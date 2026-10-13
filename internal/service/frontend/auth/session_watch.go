// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	"github.com/dagucloud/dagu/v2/internal/service/oidcsession"
)

const (
	// sessionWatchPoll is the longest a watched connection goes without its
	// token being checked again. It bounds how long a connection stays open
	// after its session ended in a way the window does not show, a sign-out
	// above all.
	sessionWatchPoll = 15 * time.Second

	// sessionWatchRetry is the longest until the token is checked again once
	// the session is due at the provider and the last check did not move its
	// window: the provider gave nothing usable, or another hub process is
	// asking. It is the session manager's own least time between two
	// provider calls.
	sessionWatchRetry = 5 * time.Second

	// sessionWatchFirstRead is how long the first read of a session's window
	// may take, when a connection is opened. A connection whose session
	// cannot be read in that time is closed.
	sessionWatchFirstRead = 5 * time.Second

	// sessionWatchMinStep is the least time between two checks, whatever the
	// configuration, so that a watch never spins. Only a session configured
	// with a limit shorter than this can reach it with no check made.
	sessionWatchMinStep = 100 * time.Millisecond
)

// ErrSessionWatchClosed is the cause a watched context is cancelled with
// when its OIDC session stopped letting the user in. The reason is wrapped
// with it.
var ErrSessionWatchClosed = errors.New("the OIDC session no longer lets this connection be served")

// errSessionWatchUnread is the reason for a connection closed because its
// session could not be read in sessionWatchFirstRead when it was opened.
var errSessionWatchUnread = errors.New("the session could not be read when the connection was opened")

// errSessionWatchPastLimit is the reason for a connection closed because its
// session reached the time a new request would be refused, with no
// confirmation from the provider by then.
var errSessionWatchPastLimit = errors.New("the session was not confirmed by its limit")

// SessionTokens is what a watch asks about a hub token. The auth service is
// the implementation: GetUserFromToken is the check every request gets.
type SessionTokens interface {
	ValidateToken(token string) (*authservice.Claims, error)
	GetUserFromToken(ctx context.Context, token string) (*authmodel.User, error)
}

// SessionWindows reports when a session next needs the identity provider.
// The session manager is the implementation.
type SessionWindows interface {
	Window(ctx context.Context, sessionID string) (oidcsession.Window, error)
}

// SessionWatchClock is the clock a watch runs on.
type SessionWatchClock interface {
	Now() time.Time
	// After returns a channel that receives once d has passed, and a
	// function that releases the timer behind it.
	After(d time.Duration) (<-chan time.Time, func())
}

type systemWatchClock struct{}

func (systemWatchClock) Now() time.Time { return time.Now() }

func (systemWatchClock) After(d time.Duration) (<-chan time.Time, func()) {
	timer := time.NewTimer(d)
	return timer.C, func() { timer.Stop() }
}

// SessionWatch closes connections that were opened with an OIDC session's
// hub token once that session stops letting its user in.
//
// A request is checked when it arrives, and that is all a request needs. A
// connection that stays open, an event stream, an MCP stream or a terminal,
// would go on being served after its session ended. A watch gives such a
// connection a context that is cancelled:
//
//   - when the token is checked again and is refused, for any reason a new
//     request would be refused for, including a session that could not be
//     confirmed or read;
//   - at the time the session manager would refuse a new request unless the
//     provider confirms the session first (oidcsession.Window.ServedUntil),
//     if no check has moved that time by then. This is a timer, not a poll:
//     a check or a read of the session that is slow or stuck does not hold
//     the connection open.
//
// The token is checked again every sessionWatchPoll at the latest, and at
// the time the session is next due at the provider, so that a connection
// with no other traffic keeps its own session confirmed.
//
// A nil *SessionWatch watches nothing. That is what a hub without OIDC
// sessions has.
type SessionWatch struct {
	tokens  SessionTokens
	windows SessionWindows
	clock   SessionWatchClock
}

// NewSessionWatch returns a watch over the sessions of windows. A nil clock
// is the system clock.
func NewSessionWatch(tokens SessionTokens, windows SessionWindows, clock SessionWatchClock) *SessionWatch {
	if clock == nil {
		clock = systemWatchClock{}
	}
	return &SessionWatch{tokens: tokens, windows: windows, clock: clock}
}

// Watch returns a context for a connection opened with token, and a function
// the caller must call when the connection is over.
//
// A token that carries no OIDC session, an API key, or no token at all is
// not watched: ctx is returned as it is, and nothing is started. Otherwise
// the context returned is cancelled, with a cause that is
// ErrSessionWatchClosed, as described on SessionWatch.
//
// The caller has already authenticated the request. Watch does not.
func (w *SessionWatch) Watch(ctx context.Context, token string) (context.Context, context.CancelFunc) {
	if w == nil || token == "" {
		return ctx, func() {}
	}
	claims, err := w.tokens.ValidateToken(token)
	if err != nil || claims.SessionID == "" {
		return ctx, func() {}
	}
	watched, cancel := context.WithCancelCause(ctx)
	go w.run(watched, cancel, token, claims.SessionID)
	return watched, func() { cancel(context.Canceled) }
}

// Middleware watches every request it serves that was made with an OIDC
// session's hub token in the Authorization header. It goes after the
// middleware that authenticates the request.
func (w *SessionWatch) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if w == nil {
			return next
		}
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			ctx, stop := w.Watch(r.Context(), extractBearerToken(r))
			defer stop()
			if ctx != r.Context() {
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(rw, r)
		})
	}
}

// SessionWatchClosed reports whether ctx was cancelled by a watch.
func SessionWatchClosed(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), ErrSessionWatchClosed)
}

func (w *SessionWatch) run(ctx context.Context, cancel context.CancelCauseFunc, token, sessionID string) {
	closeFor := func(reason error) {
		if ctx.Err() != nil {
			// The connection was over first.
			return
		}
		cancel(fmt.Errorf("%w: %w", ErrSessionWatchClosed, reason))
		logger.Info(ctx, "Closed an open connection: its OIDC session no longer lets it be served", tag.Error(reason))
	}

	// read asks for the session's window, after checking the token again
	// when check is set. It runs beside the timer that bounds it, so that a
	// check or a read that does not come back cannot keep the connection
	// open.
	type reading struct {
		window oidcsession.Window
		err    error
	}
	read := func(check bool) <-chan reading {
		out := make(chan reading, 1)
		go func() {
			if check {
				if _, err := w.tokens.GetUserFromToken(ctx, token); err != nil {
					out <- reading{err: err}
					return
				}
			}
			window, err := w.windows.Window(ctx, sessionID)
			out <- reading{window: window, err: err}
		}()
		return out
	}

	// The request that opened the connection was checked just now. Until the
	// session's window has been read once, nothing says how long it may be
	// served, so that first read is given a short time of its own.
	lastCheck := w.clock.Now()
	pending := read(false)
	limit, stopLimit := w.clock.After(sessionWatchFirstRead)
	pastLimit := errSessionWatchUnread
	for {
		var got reading
		select {
		case <-ctx.Done():
			stopLimit()
			return
		case <-limit:
			closeFor(pastLimit)
			return
		case got = <-pending:
		}
		stopLimit()
		if got.err != nil {
			closeFor(got.err)
			return
		}

		// From here the limit is the session's own, as stored: a check that
		// succeeded without a new confirmation has not moved it.
		pastLimit = errSessionWatchPastLimit
		now := w.clock.Now()
		left := got.window.ServedUntil.Sub(now)
		if left <= 0 {
			closeFor(pastLimit)
			return
		}
		limit, stopLimit = w.clock.After(left)

		wait := max(untilNextCheck(now, got.window), lastCheck.Add(sessionWatchMinStep).Sub(now))
		if wait >= left {
			// No check fits before the limit. The last one did not move it,
			// so the connection is over when it comes.
			select {
			case <-ctx.Done():
				stopLimit()
			case <-limit:
				closeFor(pastLimit)
			}
			return
		}
		due, stopDue := w.clock.After(wait)
		select {
		case <-ctx.Done():
			stopDue()
			stopLimit()
			return
		case <-limit:
			stopDue()
			closeFor(pastLimit)
			return
		case <-due:
		}
		stopDue()

		// The limit stays set while the token is checked and the window read
		// again.
		lastCheck = w.clock.Now()
		pending = read(true)
	}
}

// untilNextCheck is how long after now a watch checks the token again, before
// sessionWatchMinStep is applied. It is positive and at most sessionWatchPoll.
func untilNextCheck(now time.Time, window oidcsession.Window) time.Duration {
	if untilDue := window.RevalidateAt.Sub(now); untilDue > 0 {
		// The check that falls due is the one that has the provider asked.
		return min(sessionWatchPoll, untilDue)
	}
	// The session is due and the last check did not move its window. What
	// is left is halved each time, so that a short one still gets a check.
	return min(sessionWatchPoll, sessionWatchRetry, max(window.ServedUntil.Sub(now)/2, time.Nanosecond))
}
