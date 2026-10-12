// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package oidcsession

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secretRefreshToken = "s3cr3t-refresh-token-value"

// endpoint is a token and revocation endpoint whose answer the test chooses.
type endpoint struct {
	server *httptest.Server
	mu     sync.Mutex
	status int
	body   string
	forms  []url.Values
	auths  []string
}

func newEndpoint(t *testing.T) *endpoint {
	t.Helper()
	e := &endpoint{status: http.StatusOK, body: `{"access_token":"a","refresh_token":"next","id_token":"id"}`}
	e.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		e.mu.Lock()
		e.forms = append(e.forms, r.PostForm)
		e.auths = append(e.auths, r.Header.Get("Authorization"))
		status, body := e.status, e.body
		e.mu.Unlock()
		// A provider that repeats what it was sent.
		body = strings.ReplaceAll(body, "{{token}}", r.PostForm.Get("refresh_token")+r.PostForm.Get("token"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(e.server.Close)
	return e
}

func (e *endpoint) answer(status int, body string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status, e.body = status, body
}

func (e *endpoint) provider(t *testing.T, secret string) *HTTPProvider {
	t.Helper()
	p, err := NewHTTPProvider(HTTPProviderConfig{
		TokenURL: e.server.URL + "/token", RevocationURL: e.server.URL + "/revoke", ClientID: "dagu-web", ClientSecret: secret,
	})
	require.NoError(t, err)
	return p
}

func TestHTTPProviderGrantedRefresh(t *testing.T) {
	t.Parallel()
	e := newEndpoint(t)

	renewal, err := e.provider(t, "client-secret").Refresh(context.Background(), secretRefreshToken)
	require.NoError(t, err)
	assert.Equal(t, Renewal{RefreshToken: "next", IDToken: "id"}, renewal)

	require.Len(t, e.forms, 1)
	assert.Equal(t, "refresh_token", e.forms[0].Get("grant_type"))
	assert.Equal(t, secretRefreshToken, e.forms[0].Get("refresh_token"))
	assert.True(t, strings.HasPrefix(e.auths[0], "Basic "), "a confidential client authenticates in the header")
	assert.Empty(t, e.forms[0].Get("client_secret"), "and not in the body")

	// A public client names itself in the body and sends no secret.
	public := newEndpoint(t)
	_, err = public.provider(t, "").Refresh(context.Background(), secretRefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "dagu-web", public.forms[0].Get("client_id"))
	assert.Empty(t, public.auths[0])
}

// The three outcomes of a refresh, by what the token endpoint answered.
// Refused is a 400 or 401 with a JSON OAuth error and nothing else.
func TestHTTPProviderClassifiesTheAnswer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		status  int
		body    string
		refused string // the refusal code, or "" when it is not a refusal
		granted bool
	}{
		// Measured on the provider: a disabled or deleted user, an ended
		// session, an invalid token.
		{"InvalidGrant", 400, `{"error":"invalid_grant","error_description":"User disabled"}`, "invalid_grant", false},
		// Measured: the user lost the offline_access role.
		{"NotAllowed", 400, `{"error":"not_allowed","error_description":"Offline tokens not allowed"}`, "not_allowed", false},
		// Measured: the client was disabled.
		{"InvalidClient", 401, `{"error":"invalid_client"}`, "invalid_client", false},
		{"UnauthorizedClient", 400, `{"error":"unauthorized_client"}`, "unauthorized_client", false},
		{"ACodeNobodyListed", 400, `{"error":"{{token}}"}`, "other", false},

		{"BadRequestFromAProxy", 400, `<html>Bad Request</html>`, "", false},
		{"BadRequestWithEmptyError", 400, `{"error":""}`, "", false},
		{"BadRequestWithOtherJSON", 400, `{"message":"no"}`, "", false},
		{"UnauthorizedWithNoBody", 401, ``, "", false},
		{"Forbidden", 403, `{"error":"access_denied"}`, "", false},
		{"NotFound", 404, `{"error":"invalid_grant"}`, "", false},
		{"TooManyRequests", 429, `{"error":"invalid_grant"}`, "", false},
		{"ServerError", 500, `{"error":"invalid_grant"}`, "", false},
		{"BadGateway", 502, `<html>`, "", false},
		{"Unavailable", 503, `starting`, "", false},
		{"Redirect", 302, ``, "", false},
		{"OKWithoutAToken", 200, `{}`, "", false},
		{"OKNotJSON", 200, `<html>`, "", false},
		{"OKWithAnError", 200, `{"error":"invalid_grant"}`, "", false},

		{"Granted", 200, `{"access_token":"a"}`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEndpoint(t)
			e.answer(tt.status, tt.body)

			_, err := e.provider(t, "client-secret").Refresh(context.Background(), secretRefreshToken)

			var refused *RefusedError
			switch {
			case tt.granted:
				require.NoError(t, err)
			case tt.refused != "":
				require.ErrorAs(t, err, &refused)
				assert.Equal(t, tt.refused, refused.Code)
				assert.Equal(t, tt.status, refused.Status)
			default:
				require.Error(t, err)
				assert.False(t, errors.As(err, &refused), "this is not a refusal: %v", err)
			}
			if err != nil {
				assert.NotContains(t, err.Error(), secretRefreshToken)
			}
		})
	}
}

// No answer at all is not a refusal either, and the error says nothing the
// request carried.
func TestHTTPProviderNoAnswer(t *testing.T) {
	t.Parallel()
	var refused *RefusedError

	down := newEndpoint(t)
	provider := down.provider(t, "client-secret")
	down.server.Close()
	_, err := provider.Refresh(context.Background(), secretRefreshToken)
	require.Error(t, err)
	assert.False(t, errors.As(err, &refused))
	assert.NotContains(t, err.Error(), secretRefreshToken)
	assert.NotContains(t, err.Error(), "client-secret")

	// The handler is held until the test ends. The server does not notice a
	// client that gave up while a request body is still unread, so it must
	// be let go by hand or closing the server would wait for ever.
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })
	timedOut, err := NewHTTPProvider(HTTPProviderConfig{
		TokenURL: slow.URL, ClientID: "dagu-web", HTTPClient: &http.Client{Timeout: 50 * time.Millisecond},
	})
	require.NoError(t, err)
	_, err = timedOut.Refresh(context.Background(), secretRefreshToken)
	require.Error(t, err)
	assert.False(t, errors.As(err, &refused))
	assert.NotContains(t, err.Error(), secretRefreshToken)
}

// A redirect is never followed, whatever client the caller supplies: it could
// carry the refresh token to another host.
func TestHTTPProviderFollowsNoRedirect(t *testing.T) {
	t.Parallel()
	elsewhere := newEndpoint(t)
	redirecting := httptest.NewServer(http.RedirectHandler(elsewhere.server.URL, http.StatusTemporaryRedirect))
	t.Cleanup(redirecting.Close)

	for _, client := range []*http.Client{nil, {}} {
		provider, err := NewHTTPProvider(HTTPProviderConfig{TokenURL: redirecting.URL, ClientID: "dagu-web", HTTPClient: client})
		require.NoError(t, err)
		_, err = provider.Refresh(context.Background(), secretRefreshToken)
		require.Error(t, err)
	}
	assert.Empty(t, elsewhere.forms, "the refresh token was not sent on")
}

func TestHTTPProviderRevoke(t *testing.T) {
	t.Parallel()
	e := newEndpoint(t)
	provider := e.provider(t, "client-secret")

	require.NoError(t, provider.Revoke(context.Background(), secretRefreshToken))
	require.Len(t, e.forms, 1)
	assert.Equal(t, secretRefreshToken, e.forms[0].Get("token"))
	assert.Equal(t, "refresh_token", e.forms[0].Get("token_type_hint"))

	e.answer(http.StatusServiceUnavailable, `{{token}}`)
	err := provider.Revoke(context.Background(), secretRefreshToken)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretRefreshToken)

	none, err := NewHTTPProvider(HTTPProviderConfig{TokenURL: e.server.URL, ClientID: "dagu-web"})
	require.NoError(t, err)
	require.Error(t, none.Revoke(context.Background(), secretRefreshToken), "a provider with no revocation endpoint")

	_, err = NewHTTPProvider(HTTPProviderConfig{ClientID: "dagu-web"})
	require.Error(t, err)
	_, err = NewHTTPProvider(HTTPProviderConfig{TokenURL: e.server.URL})
	require.Error(t, err)
}

// pickyEndpoint is a token and revocation endpoint that takes the client
// secret one way only, and answers the other way as the test says.
type pickyEndpoint struct {
	server *httptest.Server
	mu     sync.Mutex
	// wrongWay is the answer to a request that sent the secret the way this
	// provider does not take it.
	wrongWayStatus int
	wrongWayBody   string
	// rightWay is the answer to one that sent it the way it does.
	rightWayStatus int
	rightWayBody   string
	// ways lists how each request sent the secret: "header" or "form".
	ways []string
}

func newPickyEndpoint(t *testing.T, takes string) *pickyEndpoint {
	t.Helper()
	e := &pickyEndpoint{
		wrongWayStatus: http.StatusUnauthorized, wrongWayBody: `{"error":"invalid_client"}`,
		rightWayStatus: http.StatusOK, rightWayBody: `{"access_token":"a","refresh_token":"next"}`,
	}
	e.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		way := "form"
		if r.Header.Get("Authorization") != "" {
			way = "header"
		}
		e.mu.Lock()
		e.ways = append(e.ways, way)
		status, body := e.wrongWayStatus, e.wrongWayBody
		if way == takes && (way == "header" || r.PostForm.Get("client_secret") == "client-secret") {
			status, body = e.rightWayStatus, e.rightWayBody
		}
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(e.server.Close)
	return e
}

func (e *pickyEndpoint) provider(t *testing.T, auth ClientAuth) *HTTPProvider {
	t.Helper()
	p, err := NewHTTPProvider(HTTPProviderConfig{
		TokenURL: e.server.URL + "/token", RevocationURL: e.server.URL + "/revoke",
		ClientID: "dagu-web", ClientSecret: "client-secret", ClientAuth: auth,
	})
	require.NoError(t, err)
	return p
}

func (e *pickyEndpoint) sent() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.ways...)
}

// A provider that takes the client secret only in the form accepts the
// sign-in, whose exchange finds that out by itself. The refresh must find it
// out too, or the first refresh would be refused as invalid_client and end
// every session.
func TestHTTPProviderFindsHowTheProviderTakesTheSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("FormOnly", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "form")
		provider := e.provider(t, ClientAuthDetect)

		renewal, err := provider.Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		assert.Equal(t, "next", renewal.RefreshToken)
		assert.Equal(t, []string{"header", "form"}, e.sent())

		_, err = provider.Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		require.NoError(t, provider.Revoke(ctx, secretRefreshToken))
		assert.Equal(t, []string{"header", "form", "form", "form"}, e.sent(), "what worked is used from then on")
	})

	t.Run("HeaderOnly", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "header")
		provider := e.provider(t, ClientAuthDetect)
		_, err := provider.Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		_, err = provider.Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		assert.Equal(t, []string{"header", "header"}, e.sent())
	})

	t.Run("Configured", func(t *testing.T) {
		t.Parallel()
		var refused *RefusedError
		e := newPickyEndpoint(t, "form")
		_, err := e.provider(t, ClientAuthForm).Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		_, err = e.provider(t, ClientAuthHeader).Refresh(ctx, secretRefreshToken)
		require.ErrorAs(t, err, &refused, "a configured way is not second-guessed")
		assert.Equal(t, []string{"form", "header"}, e.sent())
	})

	// The refresh token itself is refused. The way the secret is sent is not
	// yet known, so both are tried, and the answer about the token is kept.
	t.Run("RefusedBothWays", func(t *testing.T) {
		t.Parallel()
		var refused *RefusedError
		for _, takes := range []string{"header", "form"} {
			e := newPickyEndpoint(t, takes)
			e.rightWayStatus, e.rightWayBody = http.StatusBadRequest, `{"error":"invalid_grant"}`
			_, err := e.provider(t, ClientAuthDetect).Refresh(ctx, secretRefreshToken)
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, "invalid_grant", refused.Code, "a provider that takes the secret in the %s", takes)
			assert.Equal(t, []string{"header", "form"}, e.sent())
		}
	})

	// Refused one way and no answer the other: nothing is known.
	t.Run("RefusedThenNoAnswer", func(t *testing.T) {
		t.Parallel()
		var refused *RefusedError
		e := newPickyEndpoint(t, "form")
		e.rightWayStatus, e.rightWayBody = http.StatusBadGateway, `<html>`
		_, err := e.provider(t, ClientAuthDetect).Refresh(ctx, secretRefreshToken)
		require.Error(t, err)
		assert.False(t, errors.As(err, &refused), "this is not a refusal: %v", err)
	})

	t.Run("RevokeBeforeAnyRefresh", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "form")
		require.NoError(t, e.provider(t, ClientAuthDetect).Revoke(ctx, secretRefreshToken))
		assert.Equal(t, []string{"header", "form"}, e.sent())
	})

	_, err := NewHTTPProvider(HTTPProviderConfig{TokenURL: "https://issuer.example/token", ClientID: "dagu-web", ClientAuth: 7})
	require.Error(t, err)
}
