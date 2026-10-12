// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// tokenEndpoint is a provider token endpoint that records what it is sent
// and answers with a token response that carries no ID token, so a callback
// stops right after the exchange.
type tokenEndpoint struct {
	server *httptest.Server

	mu    sync.Mutex
	forms []url.Values
}

func newTokenEndpoint(t *testing.T) *tokenEndpoint {
	t.Helper()
	endpoint := &tokenEndpoint{}
	endpoint.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		endpoint.mu.Lock()
		endpoint.forms = append(endpoint.forms, r.PostForm)
		endpoint.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":300}`))
	}))
	t.Cleanup(endpoint.server.Close)
	return endpoint
}

func (e *tokenEndpoint) requests() []url.Values {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]url.Values(nil), e.forms...)
}

func pkceTestConfig(endpoint *tokenEndpoint, pkce bool) *BuiltinOIDCConfig {
	tokenURL := "https://idp.example.com/token"
	if endpoint != nil {
		tokenURL = endpoint.server.URL
	}
	return &BuiltinOIDCConfig{
		OAuth2Config: &oauth2.Config{
			ClientID:    "dagu-web",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.example.com/authorize", TokenURL: tokenURL},
			RedirectURL: "https://dagu.example.com/oidc-callback",
		},
		LoginBasePath:        "/",
		InitialSetupComplete: func(context.Context) (bool, error) { return true, nil },
		PKCE:                 pkce,
	}
}

func cookieNamed(t *testing.T, recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

// signIn runs the sign-in handler and returns the redirect it sent and the
// cookies it set.
func signIn(t *testing.T, cfg *BuiltinOIDCConfig) (*url.URL, *httptest.ResponseRecorder) {
	t.Helper()
	recorder := httptest.NewRecorder()
	BuiltinOIDCLoginHandler(cfg).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oidc-login", nil))
	require.Equal(t, http.StatusFound, recorder.Code)
	location, err := url.Parse(recorder.Header().Get("Location"))
	require.NoError(t, err)
	return location, recorder
}

// With PKCE on, the sign-in sends the S256 digest of a verifier that stays in
// the browser.
func TestOIDCLoginSendsAPKCEChallenge(t *testing.T) {
	t.Parallel()
	location, recorder := signIn(t, pkceTestConfig(nil, true))

	query := location.Query()
	assert.Equal(t, "S256", query.Get("code_challenge_method"))
	challenge := query.Get("code_challenge")
	require.NotEmpty(t, challenge)

	verifier := cookieNamed(t, recorder, cookiePKCEVerifier)
	require.NotNil(t, verifier, "the verifier is kept in a cookie")
	assert.True(t, verifier.HttpOnly)
	assert.True(t, verifier.Secure)
	assert.Equal(t, http.SameSiteLaxMode, verifier.SameSite)
	assert.Equal(t, stateCookieExpiry, verifier.MaxAge)
	assert.GreaterOrEqual(t, len(verifier.Value), minPKCEVerifierLength)
	assert.LessOrEqual(t, len(verifier.Value), maxPKCEVerifierLength)

	digest := sha256.Sum256([]byte(verifier.Value))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(digest[:]), challenge, "the challenge is the digest of the verifier")
	assert.NotContains(t, location.String(), verifier.Value, "the verifier itself is not sent to the provider at sign-in")

	// Each sign-in has its own verifier.
	_, second := signIn(t, pkceTestConfig(nil, true))
	assert.NotEqual(t, verifier.Value, cookieNamed(t, second, cookiePKCEVerifier).Value)
}

// With PKCE off, which is the default, the sign-in is as it was.
func TestOIDCLoginSendsNoChallengeByDefault(t *testing.T) {
	t.Parallel()
	location, recorder := signIn(t, pkceTestConfig(nil, false))

	query := location.Query()
	assert.Empty(t, query.Get("code_challenge"))
	assert.Empty(t, query.Get("code_challenge_method"))
	assert.Nil(t, cookieNamed(t, recorder, cookiePKCEVerifier))
	assert.NotEmpty(t, query.Get("state"))
	assert.NotEmpty(t, query.Get("nonce"))
	assert.NotNil(t, cookieNamed(t, recorder, cookieState))
	assert.NotNil(t, cookieNamed(t, recorder, cookieNonce))
}

func callback(cfg *BuiltinOIDCConfig, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/oidc-callback?state=the-state&code=the-code", nil)
	request.AddCookie(&http.Cookie{Name: cookieState, Value: "the-state"})
	request.AddCookie(&http.Cookie{Name: cookieNonce, Value: "the-nonce"})
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	BuiltinOIDCCallbackHandler(cfg).ServeHTTP(recorder, request)
	return recorder
}

// The exchange carries the verifier from this browser's cookie.
func TestOIDCCallbackSendsThePKCEVerifier(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t)
	verifier := strings.Repeat("v", minPKCEVerifierLength)

	recorder := callback(pkceTestConfig(endpoint, true), &http.Cookie{Name: cookiePKCEVerifier, Value: verifier})

	requests := endpoint.requests()
	require.Len(t, requests, 1)
	assert.Equal(t, verifier, requests[0].Get("code_verifier"))
	assert.Equal(t, "the-code", requests[0].Get("code"))
	assert.Equal(t, "authorization_code", requests[0].Get("grant_type"))
	// The fake provider returns no ID token, so the callback stops there.
	assert.Contains(t, recorder.Header().Get("Location"), "no+ID+token")
	cleared := cookieNamed(t, recorder, cookiePKCEVerifier)
	require.NotNil(t, cleared)
	assert.Negative(t, cleared.MaxAge, "the verifier cookie is cleared when the callback ends")
}

// A callback without a usable verifier is refused before the code is sent to
// the provider.
func TestOIDCCallbackWithoutAPKCEVerifierIsRefused(t *testing.T) {
	t.Parallel()

	for name, cookies := range map[string][]*http.Cookie{
		"NoCookie": nil,
		"Empty":    {{Name: cookiePKCEVerifier, Value: ""}},
		"TooShort": {{Name: cookiePKCEVerifier, Value: strings.Repeat("v", minPKCEVerifierLength-1)}},
		"TooLong":  {{Name: cookiePKCEVerifier, Value: strings.Repeat("v", maxPKCEVerifierLength+1)}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			endpoint := newTokenEndpoint(t)

			recorder := callback(pkceTestConfig(endpoint, true), cookies...)

			assert.Equal(t, http.StatusFound, recorder.Code)
			assert.Contains(t, recorder.Header().Get("Location"), "/login?error=")
			assert.Contains(t, recorder.Header().Get("Location"), "PKCE+verifier+not+found")
			assert.Empty(t, endpoint.requests(), "the code was not sent to the provider")
		})
	}
}

// With PKCE off the exchange carries no verifier, even if a cookie of that
// name is present.
func TestOIDCCallbackSendsNoVerifierByDefault(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t)

	callback(pkceTestConfig(endpoint, false), &http.Cookie{Name: cookiePKCEVerifier, Value: strings.Repeat("v", minPKCEVerifierLength)})

	requests := endpoint.requests()
	require.Len(t, requests, 1)
	_, sent := requests[0]["code_verifier"]
	assert.False(t, sent)
}

// The state is still checked first: a forged callback does not reach the
// verifier check or the provider.
func TestOIDCCallbackChecksStateBeforePKCE(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t)
	request := httptest.NewRequest(http.MethodGet, "/oidc-callback?state=forged&code=the-code", nil)
	request.AddCookie(&http.Cookie{Name: cookieState, Value: "the-state"})
	request.AddCookie(&http.Cookie{Name: cookiePKCEVerifier, Value: strings.Repeat("v", minPKCEVerifierLength)})
	recorder := httptest.NewRecorder()

	BuiltinOIDCCallbackHandler(pkceTestConfig(endpoint, true)).ServeHTTP(recorder, request)

	assert.Contains(t, recorder.Header().Get("Location"), "state+mismatch")
	assert.Empty(t, endpoint.requests())
}
