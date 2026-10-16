// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_PasswordDisabled(t *testing.T) {
	tokens := newMockTokenValidator()
	tokens.AddUser("builtin-token", &auth.User{ID: "u1", Username: "admin", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderBuiltin})
	tokens.AddUser("legacy-token", &auth.User{ID: "u2", Username: "old", Role: auth.RoleAdmin}) // no provider: a password user
	tokens.AddUser("oidc-token", &auth.User{ID: "u3", Username: "connor", Role: auth.RoleViewer, AuthProvider: auth.AuthProviderOIDC})
	keys := newMockAPIKeyValidator()
	keys.AddKey("dagu_workerkey12345678", &auth.APIKey{ID: "k1", Name: "worker", Role: auth.RoleOperator})

	opts := Options{AuthRequired: true, JWTValidator: tokens, APIKeyValidator: keys,
		BasicAuthEnabled: true, Creds: map[string]string{"basic": "secret"}, PasswordDisabled: true}
	send := func(o Options, set func(*http.Request)) (*httptest.ResponseRecorder, *testHandler) {
		h := &testHandler{}
		r := httptest.NewRequest(http.MethodGet, "/api/v1/dags", nil)
		r.RemoteAddr = "127.0.0.1:51234" // the port-forward is no exception
		set(r)
		w := httptest.NewRecorder()
		Middleware(o)(h).ServeHTTP(w, r)
		return w, h
	}
	bearer := func(v string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+v) }
	}

	for name, set := range map[string]func(*http.Request){
		"a builtin user's token":             bearer("builtin-token"),
		"a token of a user with no provider": bearer("legacy-token"),
		"basic auth with the right password": func(r *http.Request) { r.SetBasicAuth("basic", "secret") },
		"basic auth with a wrong password":   func(r *http.Request) { r.SetBasicAuth("basic", "guess") },
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			w, h := send(opts, set)
			assert.Equal(t, http.StatusForbidden, w.Code)
			assert.Contains(t, w.Body.String(), "auth.password_disabled")
			assert.Nil(t, h.user, "the handler must not run")
		})
	}

	t.Run("an identity provider session is accepted", func(t *testing.T) {
		w, h := send(opts, bearer("oidc-token"))
		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, h.user)
	})
	t.Run("an API key is accepted", func(t *testing.T) {
		w, h := send(opts, bearer("dagu_workerkey12345678"))
		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, h.apiKey)
	})
	t.Run("the refusal is reported", func(t *testing.T) {
		var reason string
		o := opts
		o.OnDenied = func(_ *http.Request, r string, _ *auth.APIKey) { reason = r }
		send(o, bearer("builtin-token"))
		assert.Equal(t, DenialReasonPasswordDisabled, reason)
	})
	t.Run("off, a builtin token is accepted", func(t *testing.T) {
		o := opts
		o.PasswordDisabled = false
		w, _ := send(o, bearer("builtin-token"))
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
