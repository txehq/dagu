// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// fakeProviderTokens verifies tokens from a table and counts the calls.
type fakeProviderTokens struct {
	principals map[string]authn.Principal
	refusals   map[string]authn.Reason
	calls      int
}

func (f *fakeProviderTokens) Verify(_ context.Context, token string) (authn.Principal, error) {
	f.calls++
	if p, ok := f.principals[token]; ok {
		return p, nil
	}
	if reason, ok := f.refusals[token]; ok {
		return authn.Principal{}, &authn.Error{Reason: reason}
	}
	return authn.Principal{}, &authn.Error{Reason: authn.ReasonMalformed}
}

var cliPrincipal = authn.Principal{
	Identity: authn.Identity{Issuer: "https://issuer.example/realms/test", Subject: "s"},
	Class:    authn.ClassCLI,
	ClientID: "dagu-cli",
}

type seen struct {
	called bool
	token  authn.Principal
	tokOK  bool
	userOK bool
}

func providerSetup() (*fakeProviderTokens, Options) {
	tokens := &fakeProviderTokens{
		principals: map[string]authn.Principal{"provider-ok": cliPrincipal},
		refusals: map[string]authn.Reason{
			"provider-expired":  authn.ReasonExpired,
			"provider-lifetime": authn.ReasonLifetime,
			"provider-audience": authn.ReasonAudience,
			"provider-down":     authn.ReasonKeysUnavailable,
			"other-issuer":      authn.ReasonIssuer,
		},
	}
	jwt := newMockTokenValidator()
	jwt.AddUser("hub-jwt", &auth.User{ID: "u", Username: "admin", Role: auth.RoleAdmin})
	keys := newMockAPIKeyValidator()
	keys.AddKey("dagu_key", &auth.APIKey{ID: "k", Name: "cli", Role: auth.RoleDeveloper})
	opts := Options{
		Realm:           "restricted",
		AuthRequired:    true,
		JWTValidator:    jwt,
		APIKeyValidator: keys,
		ProviderTokens:  tokens,
		ProviderTokenRoute: func(r *http.Request) bool {
			return r.Method == http.MethodGet && r.URL.Path == "/api/v1/txe/identity"
		},
	}
	return tokens, opts
}

func serveWith(t *testing.T, opts Options, method, path, bearer string) (*httptest.ResponseRecorder, *seen) {
	t.Helper()
	s := &seen{}
	h := Middleware(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.called = true
		s.token, s.tokOK = txeauth.Token(r.Context())
		_, s.userOK = auth.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, s
}

func detailCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Details map[string]string `json:"details"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body.Details["code"]
}

func TestMiddleware_ProviderTokenOnAnAdmittedRouteCarriesOnlyItsPrincipal(t *testing.T) {
	_, opts := providerSetup()
	rec, s := serveWith(t, opts, http.MethodGet, "/api/v1/txe/identity", "provider-ok")
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, s.called)
	require.True(t, s.tokOK)
	require.Equal(t, cliPrincipal, s.token)
	// No hub user, so no role and no workspace access reaches the handler.
	require.False(t, s.userOK)
}

func TestMiddleware_ProviderTokenIsRefusedOnEveryOtherRoute(t *testing.T) {
	_, opts := providerSetup()
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/txe/jobs"},
		{http.MethodPost, "/api/v1/txe/identity"},
		{http.MethodGet, "/api/v1/dags"},
		{http.MethodGet, "/api/v1/txe/identity/x"},
	} {
		rec, s := serveWith(t, opts, tc.method, tc.path, "provider-ok")
		require.Equal(t, http.StatusForbidden, rec.Code, tc.path)
		require.False(t, s.called, tc.path)
		require.Equal(t, "forbidden", detailCode(t, rec))
	}

	opts.ProviderTokenRoute = nil
	rec, s := serveWith(t, opts, http.MethodGet, "/api/v1/txe/identity", "provider-ok")
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.False(t, s.called)
}

func TestMiddleware_ProviderTokenRefusedIsInvalidTokenWithNoGrace(t *testing.T) {
	_, opts := providerSetup()
	for _, token := range []string{"provider-expired", "provider-lifetime", "provider-audience"} {
		rec, s := serveWith(t, opts, http.MethodGet, "/api/v1/txe/identity", token)
		require.Equal(t, http.StatusUnauthorized, rec.Code, token)
		require.False(t, s.called, token)
		require.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`, token)
		require.Equal(t, "invalid_token", detailCode(t, rec), token)
	}
}

func TestMiddleware_ProviderKeysUnavailableIs503NotSignOut(t *testing.T) {
	_, opts := providerSetup()
	rec, s := serveWith(t, opts, http.MethodGet, "/api/v1/txe/identity", "provider-down")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.False(t, s.called)
	require.NotEmpty(t, rec.Header().Get("Retry-After"))
	require.Equal(t, "provider_unavailable", detailCode(t, rec))
}

func TestMiddleware_NotAProviderTokenFallsThroughToTheUsualChallenge(t *testing.T) {
	_, opts := providerSetup()
	for _, token := range []string{"garbage", "other-issuer"} {
		rec, s := serveWith(t, opts, http.MethodGet, "/api/v1/txe/identity", token)
		require.Equal(t, http.StatusUnauthorized, rec.Code, token)
		require.False(t, s.called, token)
		require.Equal(t, `Bearer realm="restricted"`, rec.Header().Get("WWW-Authenticate"), token)
	}
}

func TestMiddleware_HubTokensAndAPIKeysNeverReachTheProviderVerifier(t *testing.T) {
	tokens, opts := providerSetup()

	rec, s := serveWith(t, opts, http.MethodGet, "/api/v1/dags", "hub-jwt")
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, s.userOK)
	require.False(t, s.tokOK)

	rec, s = serveWith(t, opts, http.MethodGet, "/api/v1/dags", "dagu_key")
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, s.userOK)
	require.False(t, s.tokOK)

	// An unknown API key is not sent to the provider either.
	rec, _ = serveWith(t, opts, http.MethodGet, "/api/v1/dags", "dagu_unknown")
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	require.Zero(t, tokens.calls)
}

func TestMiddleware_WithoutProviderTokensAProviderTokenIsJustUnknown(t *testing.T) {
	tokens, opts := providerSetup()
	opts.ProviderTokens = nil
	rec, s := serveWith(t, opts, http.MethodGet, "/api/v1/txe/identity", "provider-ok")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.False(t, s.called)
	require.Zero(t, tokens.calls)
}
