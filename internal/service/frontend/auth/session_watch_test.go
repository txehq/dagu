// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	persiststore "github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	"github.com/dagucloud/dagu/v2/internal/service/oidcsession"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// watchProvider is an identity provider for the watch tests: the test sets
// what a refresh answers, and can make a refresh never come back.
type watchProvider struct {
	mu    sync.Mutex
	err   error
	stuck chan struct{}
	calls int
}

func (p *watchProvider) Establish(context.Context, string) (oidcsession.ClientAuth, oidcsession.Renewal, error) {
	return oidcsession.ClientAuthHeader, oidcsession.Renewal{}, nil
}

func (p *watchProvider) Refresh(context.Context, string, oidcsession.ClientAuth) (oidcsession.Renewal, error) {
	p.mu.Lock()
	p.calls++
	n, err, stuck := p.calls, p.err, p.stuck
	p.mu.Unlock()
	if stuck != nil {
		<-stuck
	}
	return oidcsession.Renewal{RefreshToken: fmt.Sprintf("refresh-token-%d", n)}, err
}

func (p *watchProvider) Revoke(context.Context, string, oidcsession.ClientAuth) error { return nil }

func (p *watchProvider) answer(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

func (p *watchProvider) asked() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

var errProviderDown = errors.New("the identity provider did not answer")

// watchEnv is a hub with OIDC sessions on, for a test that runs in a synctest
// bubble: a real auth service and a real session manager over a fake
// provider, all on the bubble's clock.
type watchEnv struct {
	t        *testing.T
	provider *watchProvider
	store    *sessionStore
	enc      oidcsession.Encryptor
	sessions *oidcsession.Manager
	svc      *authservice.Service
	users    authmodel.UserStore
	cfg      *BuiltinOIDCConfig
	alice    *authmodel.User
	admin    *authmodel.User
	watch    *SessionWatch
}

func newWatchEnv(t *testing.T, after, limit time.Duration) *watchEnv {
	t.Helper()
	backend := testutil.NewMemoryBackend()
	users, err := persiststore.NewUserStore(backend.Collection("users"))
	require.NoError(t, err)
	secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
	require.NoError(t, err)
	svc := authservice.New(users, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4})

	env := &watchEnv{t: t, provider: &watchProvider{}, svc: svc, users: users}
	env.store = &sessionStore{Collection: backend.Collection("oidc_sessions")}
	env.enc, err = crypto.NewEncryptor("a-test-key-that-is-long-enough-for-aes")
	require.NoError(t, err)
	env.sessions = env.process(after, limit)
	svc.SetSessionChecker(OIDCSessionChecker{Manager: env.sessions})
	env.cfg = &BuiltinOIDCConfig{AuthService: svc, Sessions: env.sessions, LoginBasePath: "/"}
	env.watch = NewSessionWatch(svc, env.sessions, nil)

	ctx := context.Background()
	env.admin, err = svc.CreateUser(ctx, authservice.CreateUserInput{Username: "admin", Password: "password123", Role: authmodel.RoleAdmin})
	require.NoError(t, err)
	env.alice = authmodel.NewUser("alice", "", authmodel.RoleViewer)
	env.alice.AuthProvider = authmodel.AuthProviderOIDC
	env.alice.OIDCIssuer, env.alice.OIDCSubject = "https://issuer.example/realms/test", "subject-1"
	require.NoError(t, users.Create(ctx, env.alice))
	return env
}

// process is a hub process over the env's session store and provider.
func (e *watchEnv) process(after, limit time.Duration) *oidcsession.Manager {
	e.t.Helper()
	sessions, err := oidcsession.NewManager(oidcsession.Config{RevalidateAfter: after, RevalidateLimit: limit},
		e.store, e.enc, e.provider, nil)
	require.NoError(e.t, err)
	return sessions
}

func (e *watchEnv) signIn() string {
	e.t.Helper()
	token, err := issueHubToken(context.Background(), e.cfg, e.alice, "provider-refresh-token")
	require.NoError(e.t, err)
	return token.Token
}

func (e *watchEnv) signOut(token string) {
	e.t.Helper()
	require.Equal(e.t, http.StatusNoContent, signOutWith(e.cfg, token).Code)
}

func signOutWith(cfg *BuiltinOIDCConfig, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/oidc-logout", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	BuiltinOIDCLogoutHandler(cfg).ServeHTTP(recorder, request)
	return recorder
}

// open watches a connection opened now with token.
func (e *watchEnv) open(token string) context.Context {
	e.t.Helper()
	ctx, stop := e.watch.Watch(e.t.Context(), token)
	e.t.Cleanup(stop)
	return ctx
}

// stillOpen lets d pass and reports that the connection is open after it.
func stillOpen(t *testing.T, ctx context.Context, d time.Duration) {
	t.Helper()
	time.Sleep(d)
	synctest.Wait()
	require.NoError(t, context.Cause(ctx), "the connection was closed within %s", d)
}

// closedIn waits for the connection to be closed and returns how long that
// took on the bubble's clock, which moves only when everything is waiting.
func closedIn(t *testing.T, ctx context.Context) time.Duration {
	t.Helper()
	start := time.Now()
	<-ctx.Done()
	require.True(t, SessionWatchClosed(ctx), "closed by something else: %v", context.Cause(ctx))
	return time.Since(start)
}

// What is not an OIDC session's hub token is not watched: the context is the
// caller's own, and nothing is started.
func TestSessionWatchLeavesOtherConnectionsAlone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		adminToken, err := env.svc.GenerateToken(env.admin)
		require.NoError(t, err)
		type key struct{}
		ctx := context.WithValue(t.Context(), key{}, "the caller's context")

		for name, tc := range map[string]struct {
			watch *SessionWatch
			token string
		}{
			"SessionsOff":         {nil, env.signIn()},
			"BuiltinUsersToken":   {env.watch, adminToken.Token},
			"APIKey":              {env.watch, "dagu_0123456789abcdef"},
			"NoToken":             {env.watch, ""},
			"NotAToken":           {env.watch, "not-a-token"},
			"SessionsOffNoToken":  {nil, ""},
			"SessionsOffAPIKey":   {nil, "dagu_0123456789abcdef"},
			"SessionsOffBuiltin":  {nil, adminToken.Token},
			"SessionsOffNotToken": {nil, "not-a-token"},
		} {
			watched, stop := tc.watch.Watch(ctx, tc.token)
			assert.Equal(t, ctx, watched, name)
			stop()
		}

		// Nothing was started, so nothing happens however long this takes:
		// the bubble would not end if a watch were running.
		env.provider.answer(errProviderDown)
		time.Sleep(time.Hour)
		synctest.Wait()
		require.NoError(t, ctx.Err())
		assert.Zero(t, env.provider.asked())
	})
}

// A sign-out closes a connection that is already open, at the next check: no
// later than sessionWatchPoll after the connection was opened or last
// checked, and not before.
func TestSessionWatchClosesAnOpenConnectionAfterSignOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		other := env.open(env.signIn())
		ctx := env.open(token)

		stillOpen(t, ctx, 20*time.Second) // one check has passed
		env.signOut(token)
		stillOpen(t, ctx, 10*time.Second-time.Nanosecond)

		assert.Equal(t, time.Nanosecond, closedIn(t, ctx), "closed at the check 30 s after it was opened")
		require.ErrorIs(t, context.Cause(ctx), authservice.ErrInvalidToken)
		require.NoError(t, other.Err(), "another session's connection stays open")
	})
}

// With the provider out, a connection is closed at the session's limit: five
// minutes after the provider last confirmed it, to the nanosecond, wherever
// in that time the connection was opened.
func TestSessionWatchClosesAtTheLimitWhateverTheAlignment(t *testing.T) {
	for _, age := range []time.Duration{
		0, time.Second, 7*time.Second + 13*time.Millisecond, 3*time.Minute + 59*time.Second,
		4*time.Minute - time.Nanosecond, 4 * time.Minute, 4*time.Minute + time.Nanosecond,
		4*time.Minute + 33*time.Second, 5*time.Minute - sessionWatchMinStep, 5*time.Minute - time.Millisecond,
		5*time.Minute - time.Nanosecond,
	} {
		t.Run(age.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
				token := env.signIn()
				env.provider.answer(errProviderDown)
				time.Sleep(age)

				ctx := env.open(token)
				left := 5*time.Minute - age
				stillOpen(t, ctx, left-time.Nanosecond)
				assert.Equal(t, time.Nanosecond, closedIn(t, ctx))
				require.ErrorIs(t, context.Cause(ctx), errSessionWatchPastLimit)

				// A new request is refused from the same instant.
				_, err := env.svc.GetUserFromToken(t.Context(), token)
				require.ErrorIs(t, err, authservice.ErrSessionCheckUnavailable)
			})
		})
	}
}

// A connection opened when the session is already at its limit is closed at
// once.
func TestSessionWatchClosesAConnectionOpenedAtTheLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		env.provider.answer(errProviderDown)
		time.Sleep(5 * time.Minute)

		ctx := env.open(token)
		assert.Zero(t, closedIn(t, ctx))
	})
}

// A connection with no other traffic keeps its own session confirmed: the
// watch's check is what has the provider asked, once per revalidate_after.
func TestSessionWatchKeepsItsSessionConfirmed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		ctx := env.open(env.signIn())

		stillOpen(t, ctx, 41*time.Minute)
		assert.Equal(t, 10, env.provider.asked(), "one confirmation every four minutes")
	})
}

// An outage that ends inside the limit costs nothing: the watch asks again
// and the connection stays open. The limit then counts from the new
// confirmation, not from the check that happened to succeed.
func TestSessionWatchSurvivesAnOutageInsideTheLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		ctx := env.open(token)
		env.provider.answer(errProviderDown)

		stillOpen(t, ctx, 4*time.Minute+42*time.Second)
		require.Positive(t, env.provider.asked())
		env.provider.answer(nil)
		// The next check is within sessionWatchRetry.
		stillOpen(t, ctx, sessionWatchRetry)
		confirmed := time.Now()
		window, err := env.sessions.Window(t.Context(), claimsOf(t, env, token).SessionID)
		require.NoError(t, err)
		require.WithinDuration(t, confirmed.Add(5*time.Minute), window.ServedUntil, sessionWatchRetry)

		// The provider goes away again. Checks go on succeeding inside the
		// limit, and none of them moves it.
		env.provider.answer(errProviderDown)
		stillOpen(t, ctx, time.Until(window.ServedUntil)-time.Nanosecond)
		assert.Equal(t, time.Nanosecond, closedIn(t, ctx))
	})
}

func claimsOf(t *testing.T, env *watchEnv, token string) *authservice.Claims {
	t.Helper()
	claims, err := env.svc.ValidateToken(token)
	require.NoError(t, err)
	return claims
}

// A check that never comes back does not hold a connection open: the limit
// is a timer of its own.
func TestSessionWatchClosesAtTheLimitWhenTheCheckIsStuck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		stuck := make(chan struct{})
		env.provider.mu.Lock()
		env.provider.stuck = stuck
		env.provider.mu.Unlock()

		ctx := env.open(token)
		stillOpen(t, ctx, 5*time.Minute-time.Nanosecond)
		require.Equal(t, 1, env.provider.asked(), "the check at four minutes is still waiting for the provider")
		assert.Equal(t, time.Nanosecond, closedIn(t, ctx))
		require.ErrorIs(t, context.Cause(ctx), errSessionWatchPastLimit)

		close(stuck)
	})
}

// A checker that ignores its context and never returns is the same.
func TestSessionWatchClosesAtTheLimitWhenTheCheckerHangs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		hang := make(chan struct{})
		watch := NewSessionWatch(hangingTokens{SessionTokens: env.svc, hang: hang}, env.sessions, nil)

		ctx, stop := watch.Watch(t.Context(), token)
		defer stop()
		stillOpen(t, ctx, 5*time.Minute-time.Nanosecond)
		assert.Equal(t, time.Nanosecond, closedIn(t, ctx))

		close(hang)
	})
}

type hangingTokens struct {
	SessionTokens
	hang chan struct{}
}

func (h hangingTokens) GetUserFromToken(context.Context, string) (*authmodel.User, error) {
	<-h.hang
	return nil, errors.New("too late")
}

// A read of the session that never comes back is the same: the connection is
// closed at the limit the watch last knew.
func TestSessionWatchClosesWhenTheSessionReadHangs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		windows := &hangingWindows{SessionWindows: env.sessions, release: make(chan struct{})}
		watch := NewSessionWatch(env.svc, windows, nil)

		// Read once when it is opened and once after the check at 15 s. The
		// third read, after the check at 30 s, hangs.
		windows.hangFrom.Store(3)
		ctx, stop := watch.Watch(t.Context(), token)
		defer stop()
		stillOpen(t, ctx, 5*time.Minute-time.Nanosecond)
		assert.Equal(t, time.Nanosecond, closedIn(t, ctx))
		require.ErrorIs(t, context.Cause(ctx), errSessionWatchPastLimit)

		close(windows.release)
	})
}

// A check that comes back with a confirmation after the limit has passed,
// before the watch has seen the limit's timer, does not keep the connection:
// by then it has gone unconfirmed for the whole limit. The clock here is the
// test's own, so that the answer is certainly there first.
func TestSessionWatchClosesWhenTheConfirmationComesAfterTheLimit(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	clock := &steppedClock{now: start, timers: make(chan steppedTimer, 8)}
	late := &lateTokens{clock: clock}
	late.window.Store(&oidcsession.Window{RevalidateAt: start.Add(4 * time.Minute), ServedUntil: start.Add(5 * time.Minute)})
	watch := NewSessionWatch(late, late, clock)

	ctx, stop := watch.Watch(t.Context(), "a-session-token")
	defer stop()
	limit, due := <-clock.timers, <-clock.timers
	require.Equal(t, 5*time.Minute, limit.after)
	require.Equal(t, sessionWatchPoll, due.after)

	// The check falls due. While it runs, the limit passes and the provider
	// then confirms: the check succeeds and the new window is a fresh one.
	// The limit's timer has not been delivered.
	late.onCheck = func() {
		clock.set(start.Add(5*time.Minute + time.Second))
		late.window.Store(&oidcsession.Window{RevalidateAt: clock.Now().Add(4 * time.Minute), ServedUntil: clock.Now().Add(5 * time.Minute)})
	}
	due.fire <- clock.Now()

	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the connection was kept on a confirmation that came after its limit")
	}
	require.ErrorIs(t, context.Cause(ctx), errSessionWatchPastLimit)
}

// steppedClock is a clock whose time the test sets and whose timers the test
// fires.
type steppedClock struct {
	mu     sync.Mutex
	now    time.Time
	timers chan steppedTimer
}

type steppedTimer struct {
	after time.Duration
	fire  chan time.Time
}

func (c *steppedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *steppedClock) set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func (c *steppedClock) After(d time.Duration) (<-chan time.Time, func()) {
	timer := steppedTimer{after: d, fire: make(chan time.Time, 1)}
	c.timers <- timer
	return timer.fire, func() {}
}

// lateTokens is a token checker and a session whose window the test sets.
type lateTokens struct {
	clock   *steppedClock
	window  atomic.Pointer[oidcsession.Window]
	onCheck func()
}

func (l *lateTokens) ValidateToken(string) (*authservice.Claims, error) {
	return &authservice.Claims{SessionID: "0123456789abcdef0123456789abcdef"}, nil
}

func (l *lateTokens) GetUserFromToken(context.Context, string) (*authmodel.User, error) {
	if l.onCheck != nil {
		l.onCheck()
	}
	return &authmodel.User{}, nil
}

func (l *lateTokens) Window(context.Context, string) (oidcsession.Window, error) {
	return *l.window.Load(), nil
}

// A hub token that expired between the request being authenticated and the
// watch being asked is still a session's token: its connection is closed, not
// left unwatched. A builtin user's expired token is no business of the watch.
func TestSessionWatchClosesForATokenThatHasJustExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		adminToken, err := env.svc.GenerateToken(env.admin)
		require.NoError(t, err)
		time.Sleep(time.Hour)

		ctx, stop := env.watch.Watch(t.Context(), token)
		defer stop()
		require.True(t, SessionWatchClosed(ctx))
		require.ErrorIs(t, context.Cause(ctx), authservice.ErrTokenExpired)

		parent := t.Context()
		unwatched, stopUnwatched := env.watch.Watch(parent, adminToken.Token)
		defer stopUnwatched()
		assert.Equal(t, parent, unwatched)
	})
}

// A token says when it expires to the second, and the session stores the
// same time to the nanosecond. A request is refused from the earlier of the
// two, so the connection is closed there.
func TestSessionWatchClosesAtTheSecondTheTokenExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		time.Sleep(900 * time.Millisecond)
		token := env.signIn()
		expires := claimsOf(t, env, token).ExpiresAt.Time
		window, err := env.sessions.Window(t.Context(), claimsOf(t, env, token).SessionID)
		require.NoError(t, err)
		require.Equal(t, time.Hour-900*time.Millisecond, time.Until(expires), "the token's expiry is cut to the second")

		ctx := env.open(token)
		stillOpen(t, ctx, time.Until(expires)-time.Nanosecond)
		assert.Equal(t, time.Nanosecond, closedIn(t, ctx))
		_, err = env.svc.GetUserFromToken(t.Context(), token)
		require.ErrorIs(t, err, authservice.ErrTokenExpired)
		_ = window
	})
}

// hangingWindows reads a session's window until its hangFrom-th call, and
// from then on does not come back until it is released.
type hangingWindows struct {
	SessionWindows
	calls    atomic.Int64
	hangFrom atomic.Int64
	release  chan struct{}
}

func (h *hangingWindows) Window(ctx context.Context, sessionID string) (oidcsession.Window, error) {
	if h.calls.Add(1) >= h.hangFrom.Load() {
		<-h.release
		return oidcsession.Window{}, errors.New("too late")
	}
	return h.SessionWindows.Window(ctx, sessionID)
}

// A session configured to be due at the provider very shortly before its
// limit is still asked about in time, and its connections stay open while
// the provider confirms; when it does not, they close at the limit.
func TestSessionWatchWithASmallGap(t *testing.T) {
	for name, tc := range map[string]struct{ after, limit time.Duration }{
		"OneSecond": {4*time.Minute + 59*time.Second, 5 * time.Minute},
		// Due just after an ordinary check would be made.
		"AfterAPoll":      {15*time.Second + 50*time.Millisecond, 15*time.Second + 60*time.Millisecond},
		"AfterTwoPolls":   {30*time.Second + 99*time.Millisecond, 30*time.Second + 100*time.Millisecond},
		"OneMillisecond":  {5*time.Minute - time.Millisecond, 5 * time.Minute},
		"ShortEverything": {300 * time.Millisecond, 400 * time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := newWatchEnv(t, tc.after, tc.limit)
				token := env.signIn()
				ctx := env.open(token)

				stillOpen(t, ctx, 10*tc.limit)
				asked := env.provider.asked()
				assert.GreaterOrEqual(t, asked, 10, "the session was confirmed in every limit")
				assert.LessOrEqual(t, asked, int(10*tc.limit/sessionWatchMinStep), "and the watch did not spin")

				env.provider.answer(errProviderDown)
				window, err := env.sessions.Window(t.Context(), claimsOf(t, env, token).SessionID)
				require.NoError(t, err)
				stillOpen(t, ctx, time.Until(window.ServedUntil)-time.Nanosecond)
				assert.Equal(t, time.Nanosecond, closedIn(t, ctx))
			})
		})
	}
}

// A session store that cannot be read closes the connection at the next
// check, as a request would be refused: it is not known to be allowed.
func TestSessionWatchClosesWhenTheStoreCannotBeRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		ctx := env.open(env.signIn())
		stillOpen(t, ctx, 20*time.Second)

		env.store.unreadable.Store(true)
		assert.Equal(t, 10*time.Second, closedIn(t, ctx))
		require.ErrorIs(t, context.Cause(ctx), authservice.ErrSessionCheckUnavailable)

		// And one opened while it cannot be read is closed at once.
		opened := env.open(env.signInWhileUnreadable())
		assert.Zero(t, closedIn(t, opened))
	})
}

// signInWhileUnreadable issues a token with the store readable, and leaves
// the store unreadable again.
func (e *watchEnv) signInWhileUnreadable() string {
	e.t.Helper()
	e.store.unreadable.Store(false)
	token := e.signIn()
	e.store.unreadable.Store(true)
	return token
}

// A user disabled on the hub loses an open connection at the next check.
func TestSessionWatchClosesWhenTheUserIsDisabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		ctx := env.open(env.signIn())

		env.alice.IsDisabled = true
		require.NoError(t, env.users.Update(t.Context(), env.alice))
		assert.Equal(t, sessionWatchPoll, closedIn(t, ctx))
		require.ErrorIs(t, context.Cause(ctx), authservice.ErrUserDisabled)
	})
}

// A connection does not outlive its hub token, whatever the provider says.
func TestSessionWatchClosesWhenTheHubTokenExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		ctx := env.open(env.signIn())

		// The token lives an hour. The session is confirmed all along.
		stillOpen(t, ctx, time.Hour-time.Nanosecond)
		assert.Equal(t, time.Nanosecond, closedIn(t, ctx))
	})
}

// On a hub of two processes over one store, a sign-out one process takes
// closes a connection the other holds at that one's next check: the end is in
// the session's record, which every check reads.
func TestSessionWatchSeesASignOutTakenByAnotherProcess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		other := env.otherProcess()

		ctx, stop := other.watch.Watch(t.Context(), token)
		defer stop()
		stillOpen(t, ctx, 20*time.Second)

		env.signOut(token)
		assert.Equal(t, 10*time.Second, closedIn(t, ctx))
		require.ErrorIs(t, context.Cause(ctx), authservice.ErrInvalidToken)
	})
}

// When the process that takes the sign-out cannot change the session's
// record, it writes the end beside the record. Another process applies that
// in a round over what is left over, which a check starts at most once a
// minute and which runs beside the check that started it. So the connection
// the other process holds is closed by the check after the one that started
// the round at the latest: within a minute and two polls of that process's
// last round. Measured here, for one end left over: 55 s or 70 s after the
// sign-out. A round deals with a limited number of ends, so a process with
// many left over can take further rounds to reach one.
func TestSessionWatchSeesAnEndWrittenBesideTheRecord(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		other := env.otherProcess()

		ctx, stop := other.watch.Watch(t.Context(), token)
		defer stop()
		// The other process's first check, and with it its first round, is
		// at 15 s.
		stillOpen(t, ctx, 20*time.Second)

		env.store.unchangeable.Store(true)
		env.signOut(token)
		_, err := env.svc.GetUserFromToken(t.Context(), token)
		require.ErrorIs(t, err, authservice.ErrInvalidToken, "the process that took the sign-out refuses at once")

		// The round at 15 s was before the sign-out at 20 s. The check at
		// 75 s is the first a minute after it and starts the next round
		// beside itself: it refuses if the round got there first, and
		// otherwise the check at 90 s does.
		took := closedIn(t, ctx)
		assert.Contains(t, []time.Duration{55 * time.Second, 70 * time.Second}, took)
		require.ErrorIs(t, context.Cause(ctx), authservice.ErrInvalidToken)
	})
}

// otherProcess is a second hub process over the same stores: its own session
// manager, auth service and watch.
func (e *watchEnv) otherProcess() *watchEnv {
	e.t.Helper()
	secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
	require.NoError(e.t, err)
	svc := authservice.New(e.users, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4})
	sessions := e.process(4*time.Minute, 5*time.Minute)
	svc.SetSessionChecker(OIDCSessionChecker{Manager: sessions})
	return &watchEnv{
		t: e.t, provider: e.provider, store: e.store, enc: e.enc, sessions: sessions, svc: svc, users: e.users,
		cfg:   &BuiltinOIDCConfig{AuthService: svc, Sessions: sessions, LoginBasePath: "/"},
		alice: e.alice, admin: e.admin, watch: NewSessionWatch(svc, sessions, nil),
	}
}

// When the connection is over first, the watch stops and closes nothing.
func TestSessionWatchStopsWithTheConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()

		ctx, stop := env.watch.Watch(t.Context(), token)
		stillOpen(t, ctx, time.Minute)
		stop()
		synctest.Wait()
		require.ErrorIs(t, context.Cause(ctx), context.Canceled)
		assert.False(t, SessionWatchClosed(ctx))

		parent, cancel := context.WithCancel(t.Context())
		ctx, stop = env.watch.Watch(parent, token)
		defer stop()
		cancel()
		synctest.Wait()
		assert.False(t, SessionWatchClosed(ctx))
		// The bubble ends only if both watches have stopped.
	})
}

// The middleware hands the handler a context that the watch closes, for a
// session's token, and the request's own context for anything else.
func TestSessionWatchMiddleware(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		adminToken, err := env.svc.GenerateToken(env.admin)
		require.NoError(t, err)

		serve := func(watch *SessionWatch, bearer string) (ctx context.Context, same bool, served chan struct{}) {
			type key struct{}
			request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil)
			request = request.WithContext(context.WithValue(t.Context(), key{}, "the request's context"))
			if bearer != "" {
				request.Header.Set("Authorization", "Bearer "+bearer)
			}
			got := make(chan context.Context, 1)
			served = make(chan struct{})
			handler := watch.Middleware(Options{})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got <- r.Context()
				// A stream: it ends when its context does.
				<-r.Context().Done()
			}))
			requestCtx, cancel := context.WithCancel(request.Context())
			t.Cleanup(cancel)
			request = request.WithContext(requestCtx)
			go func() {
				defer close(served)
				handler.ServeHTTP(httptest.NewRecorder(), request)
			}()
			ctx = <-got
			return ctx, ctx == requestCtx, served
		}

		for name, tc := range map[string]struct {
			watch *SessionWatch
			token string
		}{
			"SessionsOff": {nil, token}, "Builtin": {env.watch, adminToken.Token}, "NoToken": {env.watch, ""},
		} {
			_, same, _ := serve(tc.watch, tc.token)
			assert.True(t, same, name)
		}

		ctx, same, served := serve(env.watch, token)
		require.False(t, same)
		stillOpen(t, ctx, time.Minute)
		env.signOut(token)
		closedIn(t, ctx)
		<-served
		synctest.Wait()

		// When the handler returns, the watch it started is stopped: the
		// bubble would not end otherwise.
	})
}

// The time to the next check is always positive and never more than
// sessionWatchPoll, whatever the window.
func TestUntilNextCheckIsBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	for _, due := range []time.Duration{-time.Hour, -time.Second, -time.Nanosecond, 0, time.Nanosecond, time.Second, 4 * time.Minute, time.Hour} {
		for _, until := range []time.Duration{-time.Hour, -time.Nanosecond, 0, time.Nanosecond, time.Millisecond, time.Second, 5 * time.Minute, time.Hour} {
			wait := untilNextCheck(now, oidcsession.Window{RevalidateAt: now.Add(due), ServedUntil: now.Add(until)})
			assert.Positive(t, wait, "due %s, served until %s", due, until)
			assert.LessOrEqual(t, wait, sessionWatchPoll, "due %s, served until %s", due, until)
		}
	}
}

// fixedWindows answers every read of a session's window the same way.
type fixedWindows struct {
	window oidcsession.Window
	err    error
}

func (f fixedWindows) Window(context.Context, string) (oidcsession.Window, error) {
	return f.window, f.err
}

// A request whose session stopped letting it be served between its
// authentication and the watch is refused, and its handler is not run: 401
// when the session has ended, 503 when it could not be read or confirmed,
// each as the authentication middleware answers.
func TestSessionWatchMiddlewareRefusesWhatIsAlreadyOver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		now := time.Now()

		for name, tc := range map[string]struct {
			windows    SessionWindows
			status     int
			retryAfter string
		}{
			"Ended":      {fixedWindows{err: oidcsession.ErrSessionEnded}, http.StatusUnauthorized, ""},
			"Unreadable": {fixedWindows{err: errors.New("disk unavailable")}, http.StatusServiceUnavailable, "5"},
			"AtItsLimit": {fixedWindows{window: oidcsession.Window{RevalidateAt: now.Add(-time.Minute), ServedUntil: now}}, http.StatusServiceUnavailable, "5"},
		} {
			ran := false
			var denied []string
			opts := Options{Realm: "Dagu MCP", OnDenied: func(_ *http.Request, reason string, apiKey *authmodel.APIKey) {
				assert.Nil(t, apiKey)
				denied = append(denied, reason)
			}}
			handler := NewSessionWatch(env.svc, tc.windows, nil).Middleware(opts)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				ran = true
			}))
			request := httptest.NewRequest(http.MethodPost, "/mcp", nil).WithContext(t.Context())
			request.Header.Set("Authorization", "Bearer "+token)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			assert.False(t, ran, name)
			assert.Equal(t, tc.status, recorder.Code, name)
			assert.Equal(t, tc.retryAfter, recorder.Header().Get("Retry-After"), name)
			// A 401 is the authentication middleware's own: the challenge
			// for the route's realm, and reported as a denial. A 503 is not
			// a denial there either.
			if tc.status == http.StatusUnauthorized {
				assert.Equal(t, `Bearer realm="Dagu MCP"`, recorder.Header().Get("WWW-Authenticate"), name)
				assert.Equal(t, []string{DenialReasonAuthFailed}, denied, name)
			} else {
				assert.Empty(t, recorder.Header().Get("WWW-Authenticate"), name)
				assert.Empty(t, denied, name)
			}
		}
	})
}

// deadlineRecorder is a response writer that records the deadlines set on it.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	mu     sync.Mutex
	writes []time.Time
	reads  []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writes = append(d.writes, deadline)
	return nil
}

func (d *deadlineRecorder) SetReadDeadline(deadline time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reads = append(d.reads, deadline)
	return nil
}

// When the watch closes a request, the deadlines of its connection are set
// to now, and a handler cannot move them again: a stream that gives each
// write a deadline of its own, as the event stream does, gets now. The
// handler's stream interfaces still work through the watched writer.
func TestSessionWatchMiddlewareInterruptionCannotBeUndone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newWatchEnv(t, 4*time.Minute, 5*time.Minute)
		token := env.signIn()
		writer := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}

		closed, extended := make(chan struct{}), make(chan struct{})
		handler := env.watch.Middleware(Options{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			controller := http.NewResponseController(w)
			// Before: the handler's own deadlines are the handler's.
			assert.NoError(t, controller.SetWriteDeadline(time.Now().Add(time.Hour)))
			_, flushes := w.(http.Flusher)
			assert.True(t, flushes)
			assert.NoError(t, controller.Flush())

			<-r.Context().Done()
			close(closed)
			<-extended
			// After: it asks for another hour and gets none.
			assert.NoError(t, controller.SetWriteDeadline(time.Now().Add(time.Hour)))
			assert.NoError(t, controller.SetReadDeadline(time.Time{}))
		}))
		request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil).WithContext(t.Context())
		request.Header.Set("Authorization", "Bearer "+token)
		served := make(chan struct{})
		go func() {
			defer close(served)
			handler.ServeHTTP(writer, request)
		}()

		synctest.Wait()
		opened := time.Now()
		env.signOut(token)
		<-closed
		synctest.Wait() // the interruption has been made
		closedAt := time.Now()
		require.Equal(t, sessionWatchPoll, closedAt.Sub(opened))
		close(extended)
		<-served

		writer.mu.Lock()
		defer writer.mu.Unlock()
		require.Equal(t, []time.Time{opened.Add(time.Hour), closedAt, closedAt}, writer.writes)
		require.Equal(t, []time.Time{closedAt, closedAt}, writer.reads)
		assert.True(t, writer.Flushed)
	})
}
