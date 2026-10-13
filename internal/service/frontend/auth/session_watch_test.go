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

// A session configured to be due at the provider very shortly before its
// limit is still asked about in time, and its connections stay open while
// the provider confirms; when it does not, they close at the limit.
func TestSessionWatchWithASmallGap(t *testing.T) {
	for name, tc := range map[string]struct{ after, limit time.Duration }{
		"OneSecond":       {4*time.Minute + 59*time.Second, 5 * time.Minute},
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
// the round: within a minute and two polls of that process's last round.
// Measured here: 70 s after the sign-out.
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
		// 75 s is the first a minute after it and starts the next round; the
		// check at 90 s reads what that round did.
		assert.Equal(t, 70*time.Second, closedIn(t, ctx))
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
			handler := watch.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
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
