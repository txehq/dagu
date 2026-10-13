// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

	// sessionWatchMinStep is the least time between two checks, whatever the
	// configuration, so that a watch never spins. It can put a check off
	// past the limit only for a session that falls due at the provider less
	// than this before its limit, on a connection opened less than this
	// before it falls due. That connection is closed at the limit.
	sessionWatchMinStep = 100 * time.Millisecond
)

// ErrSessionWatchClosed is the cause a watched context is cancelled with
// when its OIDC session stopped letting the user in. The reason is wrapped
// with it.
var ErrSessionWatchClosed = errors.New("the OIDC session no longer lets this connection be served")

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
// The limit is a time on the wall clock, and the timer that enforces it runs
// for the time that was left when it was set. If the hub's clock is stepped
// while a connection is open, the timer is off by the step until the next
// check, which reads the clock again. Hub processes are already required to
// keep their clocks together (see package oidcsession).
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
// ErrSessionWatchClosed, as described on SessionWatch. It may be cancelled
// already when Watch returns.
//
// The caller has already authenticated the request. Watch does not. It reads
// the session once before it returns, so that the connection is never served
// without its limit set.
func (w *SessionWatch) Watch(ctx context.Context, token string) (context.Context, context.CancelFunc) {
	if w == nil || token == "" {
		return ctx, func() {}
	}
	claims, err := w.tokens.ValidateToken(token)
	if errors.Is(err, authservice.ErrTokenExpired) && namesASession(token) {
		// It was good when the request was authenticated and has expired
		// since. It is a session's token all the same, and the connection
		// is over.
		watched, cancel := context.WithCancelCause(ctx)
		w.close(watched, cancel, err)
		return watched, func() { cancel(context.Canceled) }
	}
	if err != nil || claims.SessionID == "" {
		return ctx, func() {}
	}

	watched, cancel := context.WithCancelCause(ctx)
	stop := func() { cancel(context.Canceled) }
	watching := watching{token: token, sessionID: claims.SessionID}
	if claims.ExpiresAt != nil {
		// The token says when it expires to the second, which can be before
		// the time the session has stored for it.
		watching.tokenExpires = claims.ExpiresAt.Time
	}
	window, err := w.windows.Window(ctx, claims.SessionID)
	if err != nil {
		w.close(watched, cancel, err)
		return watched, stop
	}
	if !w.clock.Now().Before(watching.limit(window)) {
		w.close(watched, cancel, errSessionWatchPastLimit)
		return watched, stop
	}
	go w.run(watched, cancel, watching, window)
	return watched, stop
}

// watching is one connection being watched.
type watching struct {
	token        string
	sessionID    string
	tokenExpires time.Time
}

// limit is the time from which the connection is not served on this window.
func (c watching) limit(window oidcsession.Window) time.Time {
	if !c.tokenExpires.IsZero() && c.tokenExpires.Before(window.ServedUntil) {
		return c.tokenExpires
	}
	return window.ServedUntil
}

// namesASession reports whether a hub token names an OIDC session, without
// verifying it. It is asked only about a token that was verified a moment
// ago and has expired since.
func namesASession(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		SessionID string `json:"sid"`
	}
	return json.Unmarshal(payload, &claims) == nil && claims.SessionID != ""
}

// Middleware watches every request it serves that was made with an OIDC
// session's hub token in the Authorization header. It goes after the
// middleware that authenticates the request.
//
// A handler is expected to end when its request's context does. One that is
// held in a write to a client that does not read, or in a read of the
// request, would not see that, so when the watch closes a request its
// connection's deadlines are set to now as well.
func (w *SessionWatch) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if w == nil {
			return next
		}
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			ctx, stop := w.Watch(r.Context(), extractBearerToken(r))
			defer stop()
			if ctx == r.Context() {
				next.ServeHTTP(rw, r)
				return
			}
			controller := http.NewResponseController(rw)
			stopInterrupt := context.AfterFunc(ctx, func() {
				if SessionWatchClosed(ctx) {
					now := time.Now()
					_ = controller.SetWriteDeadline(now)
					_ = controller.SetReadDeadline(now)
				}
			})
			defer stopInterrupt()
			next.ServeHTTP(rw, r.WithContext(ctx))
		})
	}
}

// SessionWatchClosed reports whether ctx was cancelled by a watch.
func SessionWatchClosed(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), ErrSessionWatchClosed)
}

// close ends a watched connection for a reason, unless it is over already.
func (w *SessionWatch) close(ctx context.Context, cancel context.CancelCauseFunc, reason error) {
	if ctx.Err() != nil {
		return
	}
	cancel(fmt.Errorf("%w: %w", ErrSessionWatchClosed, reason))
	logger.Info(ctx, "Closed an open connection: its OIDC session no longer lets it be served", tag.Error(reason))
}

// run watches one connection from the window that was read when it was
// opened.
func (w *SessionWatch) run(ctx context.Context, cancel context.CancelCauseFunc, conn watching, window oidcsession.Window) {
	// read checks the token again and then reads the session's window. It
	// runs beside the limit, so that a check or a read that does not come
	// back cannot keep the connection open.
	type reading struct {
		window oidcsession.Window
		err    error
	}
	read := func() <-chan reading {
		out := make(chan reading, 1)
		go func() {
			if _, err := w.tokens.GetUserFromToken(ctx, conn.token); err != nil {
				out <- reading{err: err}
				return
			}
			window, err := w.windows.Window(ctx, conn.sessionID)
			out <- reading{window: window, err: err}
		}()
		return out
	}

	// The request that opened the connection was checked just now.
	lastCheck := w.clock.Now()
	for {
		// The limit is the session's own, as stored: a check that succeeded
		// without a new confirmation has not moved it.
		now := w.clock.Now()
		until := conn.limit(window)
		left := until.Sub(now)
		if left <= 0 {
			w.close(ctx, cancel, errSessionWatchPastLimit)
			return
		}
		limit, stopLimit := w.clock.After(left)

		wait := max(untilNextCheck(now, window), lastCheck.Add(sessionWatchMinStep).Sub(now))
		if wait >= left {
			// No check fits before the limit. The last one did not move it,
			// so the connection is over when it comes.
			select {
			case <-ctx.Done():
				stopLimit()
			case <-limit:
				w.close(ctx, cancel, errSessionWatchPastLimit)
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
			w.close(ctx, cancel, errSessionWatchPastLimit)
			return
		case <-due:
		}
		stopDue()

		// The limit stays set while the token is checked and the window read
		// again.
		lastCheck = w.clock.Now()
		var got reading
		select {
		case <-ctx.Done():
			stopLimit()
			return
		case <-limit:
			w.close(ctx, cancel, errSessionWatchPastLimit)
			return
		case got = <-read():
		}
		stopLimit()
		if got.err != nil {
			w.close(ctx, cancel, got.err)
			return
		}
		if !w.clock.Now().Before(until) {
			// The answer came with the limit, or after it and before this
			// goroutine ran. A confirmation that late does not undo it.
			w.close(ctx, cancel, errSessionWatchPastLimit)
			return
		}
		window = got.window
	}
}

// untilNextCheck is how long after now a watch checks the token again, before
// sessionWatchMinStep is applied. It is positive and at most sessionWatchPoll.
func untilNextCheck(now time.Time, window oidcsession.Window) time.Duration {
	untilDue := window.RevalidateAt.Sub(now)
	switch {
	case untilDue <= 0:
		// The session is due and the last check did not move its window.
		// What is left is halved each time, so that a short one still gets
		// a check.
		return min(sessionWatchPoll, sessionWatchRetry, max(window.ServedUntil.Sub(now)/2, time.Nanosecond))
	case untilDue <= sessionWatchPoll:
		// The check that falls due is the one that has the provider asked.
		return untilDue
	default:
		// An ordinary check is kept sessionWatchMinStep clear of the one
		// that falls due, which would otherwise be put off past its time.
		return min(sessionWatchPoll, untilDue-sessionWatchMinStep)
	}
}
