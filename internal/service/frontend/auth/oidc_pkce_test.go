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
		// Long enough, and not characters a verifier may have.
		"NotVerifierCharacters": {{Name: cookiePKCEVerifier, Value: strings.Repeat("!", minPKCEVerifierLength)}},
		"WithASpace":            {{Name: cookiePKCEVerifier, Value: strings.Repeat("v", minPKCEVerifierLength) + " x"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			endpoint := newTokenEndpoint(t)

			recorder := callback(pkceTestConfig(endpoint, true), cookies...)

			assert.Equal(t, http.StatusFound, recorder.Code)
			assert.Contains(t, recorder.Header().Get("Location"), "/login?error=")
			assert.Contains(t, recorder.Header().Get("Location"), "PKCE+verifier+not+found")
			assert.Empty(t, endpoint.requests(), "the code was not sent to the provider")
			cleared := cookieNamed(t, recorder, cookiePKCEVerifier)
			require.NotNil(t, cleared, "the verifier cookie is cleared on this way out too")
			assert.Negative(t, cleared.MaxAge)
		})
	}
}

func TestValidPKCEVerifier(t *testing.T) {
	t.Parallel()
	all := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	assert.True(t, validPKCEVerifier(all))
	assert.True(t, validPKCEVerifier(oauth2.GenerateVerifier()))
	assert.True(t, validPKCEVerifier(strings.Repeat("a", minPKCEVerifierLength)))
	assert.True(t, validPKCEVerifier(strings.Repeat("a", maxPKCEVerifierLength)))
	for _, bad := range []string{
		"", strings.Repeat("a", minPKCEVerifierLength-1), strings.Repeat("a", maxPKCEVerifierLength+1),
		strings.Repeat("a", minPKCEVerifierLength) + "+", strings.Repeat("a", minPKCEVerifierLength) + "/",
		strings.Repeat("a", minPKCEVerifierLength) + "=", strings.Repeat("a", minPKCEVerifierLength) + "\u00e9",
		strings.Repeat("a", minPKCEVerifierLength) + "\x00",
	} {
		assert.False(t, validPKCEVerifier(bad), "%q", bad)
	}
}

// A failed exchange is described for the log without anything the provider
// chose to say, because a provider can repeat the verifier it was sent.
func TestTokenExchangeFailureCarriesNoProviderText(t *testing.T) {
	t.Parallel()
	verifier := strings.Repeat("s3cr3t-verifier-", 4)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"invalid code_verifier: ` + verifier + `","error_uri":"https://idp.example.com/` + verifier + `"}`))
	}))
	t.Cleanup(endpoint.Close)
	cfg := &oauth2.Config{ClientID: "dagu-web", Endpoint: oauth2.Endpoint{TokenURL: endpoint.URL}}

	_, err := cfg.Exchange(context.Background(), "the-code", oauth2.VerifierOption(verifier))
	require.Error(t, err)
	require.Contains(t, err.Error(), verifier, "the library's own error text does repeat it")

	describe := func(err error) string {
		var out strings.Builder
		for _, attr := range tokenExchangeFailure(err) {
			out.WriteString(attr.String() + " ")
		}
		return out.String()
	}
	described := describe(err)
	assert.NotContains(t, described, verifier)
	assert.Contains(t, described, "status=400")
	assert.Contains(t, described, "oauth_error=invalid_grant")

	// An error code that is not one RFC 6749 defines is not repeated either.
	odd := &oauth2.RetrieveError{Response: &http.Response{StatusCode: http.StatusBadRequest}, ErrorCode: verifier}
	assert.NotContains(t, describe(odd), verifier)
	assert.Contains(t, describe(odd), "oauth_error=other")

	// No response at all.
	unreachable := &oauth2.Config{ClientID: "dagu-web", Endpoint: oauth2.Endpoint{TokenURL: "http://127.0.0.1:1/token"}}
	_, err = unreachable.Exchange(context.Background(), "the-code", oauth2.VerifierOption(verifier))
	require.Error(t, err)
	assert.NotContains(t, describe(err), verifier)
	assert.Contains(t, describe(err), "no usable response")
}

// With PKCE off the exchange carries no verifier, even if a cookie of that
// name is present, and the response sets exactly the cookies it always did.
func TestOIDCCallbackIsUnchangedByDefault(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t)

	recorder := callback(pkceTestConfig(endpoint, false), &http.Cookie{Name: cookiePKCEVerifier, Value: strings.Repeat("v", minPKCEVerifierLength)})

	requests := endpoint.requests()
	require.Len(t, requests, 1)
	_, sent := requests[0]["code_verifier"]
	assert.False(t, sent)
	assert.Equal(t, []string{cookieState, cookieNonce, cookieOriginalURL}, cookieNames(recorder))
}

// With PKCE off, every way out of the handlers sets exactly the cookies it
// set before this setting existed.
func TestOIDCDefaultResponsesSetNoNewCookie(t *testing.T) {
	t.Parallel()
	incomplete := func(cfg *BuiltinOIDCConfig) *BuiltinOIDCConfig {
		cfg.InitialSetupComplete = func(context.Context) (bool, error) { return false, nil }
		return cfg
	}

	_, signedIn := signIn(t, pkceTestConfig(nil, false))
	assert.Equal(t, []string{cookieState, cookieNonce, cookieOriginalURL}, cookieNames(signedIn))

	for name, recorder := range map[string]*httptest.ResponseRecorder{
		"CallbackStateMismatch": func() *httptest.ResponseRecorder {
			request := httptest.NewRequest(http.MethodGet, "/oidc-callback?state=forged&code=c", nil)
			request.AddCookie(&http.Cookie{Name: cookieState, Value: "the-state"})
			recorder := httptest.NewRecorder()
			BuiltinOIDCCallbackHandler(pkceTestConfig(nil, false)).ServeHTTP(recorder, request)
			return recorder
		}(),
		"CallbackSetupIncomplete": func() *httptest.ResponseRecorder {
			recorder := httptest.NewRecorder()
			BuiltinOIDCCallbackHandler(incomplete(pkceTestConfig(nil, false))).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oidc-callback", nil))
			return recorder
		}(),
		"SignInSetupIncomplete": func() *httptest.ResponseRecorder {
			recorder := httptest.NewRecorder()
			BuiltinOIDCLoginHandler(incomplete(pkceTestConfig(nil, false))).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oidc-login", nil))
			return recorder
		}(),
	} {
		assert.Equal(t, []string{cookieState, cookieNonce, cookieOriginalURL}, cookieNames(recorder), name)
	}
}

func cookieNames(recorder *httptest.ResponseRecorder) []string {
	var names []string
	for _, cookie := range recorder.Result().Cookies() {
		names = append(names, cookie.Name)
	}
	return names
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

// A sign-in may ask the provider to show its sign-in page, so a person can
// switch accounts; only the prompts that do that are passed on.
func TestOIDCLoginPassesOnlyAccountSwitchPrompts(t *testing.T) {
	t.Parallel()
	for _, prompt := range []string{"login", "select_account"} {
		recorder := httptest.NewRecorder()
		BuiltinOIDCLoginHandler(pkceTestConfig(nil, false)).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oidc-login?prompt="+prompt, nil))
		require.Equal(t, http.StatusFound, recorder.Code)
		location, err := url.Parse(recorder.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "idp.example.com", location.Host)
		assert.Equal(t, prompt, location.Query().Get("prompt"))
	}

	location, _ := signIn(t, pkceTestConfig(nil, false))
	assert.False(t, location.Query().Has("prompt"), "no prompt unless asked")

	for _, prompt := range []string{"none", "consent", "login consent"} {
		recorder := httptest.NewRecorder()
		BuiltinOIDCLoginHandler(pkceTestConfig(nil, false)).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oidc-login?prompt="+url.QueryEscape(prompt), nil))
		require.Equal(t, http.StatusFound, recorder.Code)
		location, err := url.Parse(recorder.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "/login", location.Path, prompt)
		assert.Equal(t, "unsupported sign-in prompt", location.Query().Get("error"), prompt)
		state := cookieNamed(t, recorder, cookieState)
		assert.True(t, state == nil || state.Value == "" || state.MaxAge < 0, "no sign-in state is left: %s", prompt)
	}
}
