// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
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

// sessionProvider is an identity provider whose answer to a refresh the test
// sets.
type sessionProvider struct {
	mu      sync.Mutex
	err     error
	calls   int
	revoked []string
}

func (p *sessionProvider) Refresh(context.Context, string) (oidcsession.Renewal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return oidcsession.Renewal{RefreshToken: "next-refresh-token"}, p.err
}

func (p *sessionProvider) Revoke(_ context.Context, token string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked = append(p.revoked, token)
	return nil
}

func (p *sessionProvider) answer(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

type sessionEnv struct {
	t        *testing.T
	now      time.Time
	mu       sync.Mutex
	provider *sessionProvider
	sessions *oidcsession.Manager
	svc      *authservice.Service
	cfg      *BuiltinOIDCConfig
	alice    *authmodel.User
	admin    *authmodel.User
}

func (e *sessionEnv) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *sessionEnv) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = e.now.Add(d)
}

// newSessionEnv is a hub with OIDC sessions on: a real auth service, a real
// session manager over a fake provider, and a clock the test moves. The hub
// tokens it issues are signed with the real clock, so they stay valid.
func newSessionEnv(t *testing.T) *sessionEnv {
	t.Helper()
	backend := testutil.NewMemoryBackend()
	store, err := persiststore.NewUserStore(backend.Collection("users"))
	require.NoError(t, err)
	secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
	require.NoError(t, err)
	svc := authservice.New(store, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4})

	env := &sessionEnv{t: t, now: time.Now(), provider: &sessionProvider{}, svc: svc}
	enc, err := crypto.NewEncryptor("a-test-key-that-is-long-enough-for-aes")
	require.NoError(t, err)
	env.sessions, err = oidcsession.NewManager(oidcsession.Config{
		RevalidateAfter: 4 * time.Minute, RevalidateLimit: 5 * time.Minute, Now: env.clock,
	}, backend.Collection("oidc_sessions"), enc, env.provider, nil)
	require.NoError(t, err)
	svc.SetSessionChecker(OIDCSessionChecker{Manager: env.sessions})
	env.cfg = &BuiltinOIDCConfig{AuthService: svc, Sessions: env.sessions, LoginBasePath: "/"}

	ctx := context.Background()
	env.admin, err = svc.CreateUser(ctx, authservice.CreateUserInput{Username: "admin", Password: "password123", Role: authmodel.RoleAdmin})
	require.NoError(t, err)
	env.alice = authmodel.NewUser("alice", "", authmodel.RoleViewer)
	env.alice.AuthProvider = authmodel.AuthProviderOIDC
	env.alice.OIDCIssuer, env.alice.OIDCSubject = "https://issuer.example/realms/test", "subject-1"
	require.NoError(t, store.Create(ctx, env.alice))
	return env
}

// signIn issues the hub token the callback would, with its session.
func (e *sessionEnv) signIn() string {
	e.t.Helper()
	token, err := issueHubToken(context.Background(), e.cfg, e.alice, "provider-refresh-token")
	require.NoError(e.t, err)
	return token.Token
}

// get sends a request with the token through the real authentication
// middleware and returns the response.
func (e *sessionEnv) get(token string) *httptest.ResponseRecorder {
	handler := Middleware(Options{AuthRequired: true, JWTValidator: e.svc, Realm: "restricted"})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/dags", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// A refusal by the provider is a 401: sign in again. An outage is a 503 with
// Retry-After, however long it lasts, and never a 401. The same token works
// again when the provider answers.
func TestRefusalIs401AndOutageIs503(t *testing.T) {
	t.Parallel()

	t.Run("Outage", func(t *testing.T) {
		t.Parallel()
		env := newSessionEnv(t)
		token := env.signIn()
		assert.Equal(t, http.StatusOK, env.get(token).Code)

		env.provider.answer(errors.New("no answer"))
		env.advance(4 * time.Minute)
		assert.Equal(t, http.StatusOK, env.get(token).Code, "inside the limit an outage costs nothing")

		env.advance(time.Minute)
		for range 3 {
			response := env.get(token)
			require.Equal(t, http.StatusServiceUnavailable, response.Code)
			assert.Equal(t, "5", response.Header().Get("Retry-After"))
			assert.Empty(t, response.Header().Get("WWW-Authenticate"), "the user is not told to sign in")
			env.advance(10 * time.Minute)
		}

		env.provider.answer(nil)
		assert.Equal(t, http.StatusOK, env.get(token).Code, "the provider is back; the same token works")
	})

	for _, code := range []string{"invalid_grant", "not_allowed", "invalid_client"} {
		t.Run("Refused_"+code, func(t *testing.T) {
			t.Parallel()
			env := newSessionEnv(t)
			token := env.signIn()
			env.provider.answer(&oidcsession.RefusedError{Status: 400, Code: code})
			env.advance(4 * time.Minute)

			response := env.get(token)
			require.Equal(t, http.StatusUnauthorized, response.Code)
			assert.NotEmpty(t, response.Header().Get("WWW-Authenticate"))
			assert.Empty(t, response.Header().Get("Retry-After"))

			env.provider.answer(nil)
			assert.Equal(t, http.StatusUnauthorized, env.get(token).Code, "a refused session does not come back")
		})
	}
}

// The builtin administrator and its password sign-in are not subject to any
// of this, whatever the provider does.
func TestBuiltinUsersAreUntouchedBySessions(t *testing.T) {
	t.Parallel()
	env := newSessionEnv(t)
	adminToken, err := env.svc.GenerateToken(env.admin)
	require.NoError(t, err)
	env.provider.answer(&oidcsession.RefusedError{Status: 400, Code: "invalid_grant"})

	for range 4 {
		env.advance(time.Hour)
		assert.Equal(t, http.StatusOK, env.get(adminToken.Token).Code)
	}
	env.provider.mu.Lock()
	assert.Zero(t, env.provider.calls, "the provider is never asked about a builtin user")
	env.provider.mu.Unlock()

	// An OIDC user's token from before sessions were turned on is refused.
	old, err := env.svc.GenerateToken(env.alice)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, env.get(old.Token).Code)
}

// The token the callback issues is tied to a new session and expires with
// it. Without a refresh token from the provider there is no sign-in.
func TestIssueHubToken(t *testing.T) {
	t.Parallel()
	env := newSessionEnv(t)

	token, err := issueHubToken(context.Background(), env.cfg, env.alice, "provider-refresh-token")
	require.NoError(t, err)
	claims, err := env.svc.ValidateToken(token.Token)
	require.NoError(t, err)
	require.Len(t, claims.SessionID, 32)
	require.NoError(t, env.sessions.Check(context.Background(), claims.SessionID, oidcSessionIdentity(env.alice)))
	assert.WithinDuration(t, time.Now().Add(time.Hour), token.ExpiresAt, 5*time.Second)

	_, err = issueHubToken(context.Background(), env.cfg, env.alice, "")
	require.ErrorContains(t, err, "no refresh token")

	// With sessions off the token is the ordinary one.
	plainCfg := &BuiltinOIDCConfig{AuthService: env.svc}
	plain, err := issueHubToken(context.Background(), plainCfg, env.alice, "")
	require.NoError(t, err)
	claims, err = env.svc.ValidateToken(plain.Token)
	require.NoError(t, err)
	assert.Empty(t, claims.SessionID)
}

func signOut(env *sessionEnv, method, authorization, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	BuiltinOIDCLogoutHandler(env.cfg).ServeHTTP(recorder, request)
	return recorder
}

// Sign-out ends the session for the very next request and revokes the
// refresh token at the provider.
func TestSignOutEndsTheSession(t *testing.T) {
	t.Parallel()
	env := newSessionEnv(t)
	token := env.signIn()
	other := env.signIn()
	require.Equal(t, http.StatusOK, env.get(token).Code)

	response := signOut(env, http.MethodPost, "Bearer "+token, "/oidc-logout")
	require.Equal(t, http.StatusNoContent, response.Code)
	assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))

	assert.Equal(t, http.StatusUnauthorized, env.get(token).Code)
	assert.Equal(t, http.StatusOK, env.get(other).Code, "another session of the same user is not ended")
	env.provider.mu.Lock()
	assert.Equal(t, []string{"provider-refresh-token"}, env.provider.revoked)
	assert.Zero(t, env.provider.calls)
	env.provider.mu.Unlock()

	// Signing out again, and signing out with a token that has no session,
	// have nothing left to end and say so the same way.
	assert.Equal(t, http.StatusNoContent, signOut(env, http.MethodPost, "Bearer "+token, "/oidc-logout").Code)
	adminToken, err := env.svc.GenerateToken(env.admin)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, signOut(env, http.MethodPost, "Bearer "+adminToken.Token, "/oidc-logout").Code)
	assert.Equal(t, http.StatusOK, env.get(adminToken.Token).Code, "the administrator's token is not affected")
}

// Sign-out cannot be triggered from another site: it takes a POST with the
// hub token in the Authorization header, and a token anywhere else is not
// one.
func TestSignOutNeedsAPostWithTheTokenInTheHeader(t *testing.T) {
	t.Parallel()
	env := newSessionEnv(t)
	token := env.signIn()

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodDelete, http.MethodPut} {
		response := signOut(env, method, "Bearer "+token, "/oidc-logout")
		assert.Equal(t, http.StatusMethodNotAllowed, response.Code, method)
		assert.Equal(t, http.MethodPost, response.Header().Get("Allow"), method)
	}
	for name, attempt := range map[string]*httptest.ResponseRecorder{
		"NoToken":            signOut(env, http.MethodPost, "", "/oidc-logout"),
		"TokenInTheQuery":    signOut(env, http.MethodPost, "", "/oidc-logout?token="+token),
		"NotABearer":         signOut(env, http.MethodPost, "Basic "+token, "/oidc-logout"),
		"BearerWithoutToken": signOut(env, http.MethodPost, "Bearer ", "/oidc-logout"),
		"ForgedToken":        signOut(env, http.MethodPost, "Bearer "+token+"x", "/oidc-logout"),
	} {
		assert.Equal(t, http.StatusUnauthorized, attempt.Code, name)
	}
	cookie := httptest.NewRequest(http.MethodPost, "/oidc-logout", nil)
	cookie.AddCookie(&http.Cookie{Name: "token", Value: token})
	recorder := httptest.NewRecorder()
	BuiltinOIDCLogoutHandler(env.cfg).ServeHTTP(recorder, cookie)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code, "a cookie is not a credential here")

	assert.Equal(t, http.StatusOK, env.get(token).Code, "none of those ended the session")
	env.provider.mu.Lock()
	assert.Empty(t, env.provider.revoked)
	env.provider.mu.Unlock()
}

// The session's answers reach the auth service as the errors it knows.
func TestOIDCSessionCheckerMapsTheAnswers(t *testing.T) {
	t.Parallel()
	env := newSessionEnv(t)
	checker := OIDCSessionChecker{Manager: env.sessions}
	ctx := context.Background()
	token := env.signIn()
	claims, err := env.svc.ValidateToken(token)
	require.NoError(t, err)

	require.NoError(t, checker.CheckSession(ctx, claims.SessionID, env.alice))
	require.ErrorIs(t, checker.CheckSession(ctx, "0123456789abcdef0123456789abcdef", env.alice), authservice.ErrInvalidToken)
	require.ErrorIs(t, checker.CheckSession(ctx, claims.SessionID, env.admin), authservice.ErrInvalidToken, "another user's session")

	env.provider.answer(errors.New("no answer"))
	env.advance(5 * time.Minute)
	require.ErrorIs(t, checker.CheckSession(ctx, claims.SessionID, env.alice), authservice.ErrIdentityProviderUnavailable)
}

// Requests that race with a sign-out are each either served or refused, and
// once the sign-out has returned every one is refused.
func TestRequestsRacingASignOut(t *testing.T) {
	t.Parallel()
	env := newSessionEnv(t)
	token := env.signIn()
	env.advance(4 * time.Minute)

	var wg sync.WaitGroup
	codes := make([]int, 40)
	for i := range codes {
		wg.Go(func() { codes[i] = env.get(token).Code })
	}
	wg.Go(func() { signOut(env, http.MethodPost, "Bearer "+token, "/oidc-logout") })
	wg.Wait()

	for _, code := range codes {
		assert.Contains(t, []int{http.StatusOK, http.StatusUnauthorized}, code)
	}
	for range 5 {
		assert.Equal(t, http.StatusUnauthorized, env.get(token).Code)
	}
}
