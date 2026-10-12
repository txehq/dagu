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
	// The way the secret is sent is configured here, so that these tests see
	// the one request they are about. Finding the way out is tested apart.
	p, err := NewHTTPProvider(HTTPProviderConfig{
		TokenURL: e.server.URL + "/token", RevocationURL: e.server.URL + "/revoke", ClientID: "dagu-web", ClientSecret: secret,
		ClientAuth: ClientAuthHeader,
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

// pickyEndpoint is a token and revocation endpoint that accepts the client
// only when the secret is sent the way it takes, and answers an accepted
// client as the test says.
type pickyEndpoint struct {
	server *httptest.Server
	mu     sync.Mutex
	// takes is "header", "form", or "" for a provider that accepts the
	// client neither way.
	takes string
	// notAccepted is the answer to a client that is not accepted.
	notAcceptedStatus int
	notAcceptedBody   string
	// probed is the answer to an accepted client that presents a refresh
	// token the provider never issued.
	probedStatus int
	probedBody   string
	// answer is the answer to an accepted client that presents secretRefreshToken.
	answerStatus int
	answerBody   string
	// sent lists each request: the way the secret came, and what it carried.
	sent []string
}

func newPickyEndpoint(t *testing.T, takes string) *pickyEndpoint {
	t.Helper()
	e := &pickyEndpoint{
		takes:             takes,
		notAcceptedStatus: http.StatusUnauthorized, notAcceptedBody: `{"error":"invalid_client"}`,
		probedStatus: http.StatusBadRequest, probedBody: `{"error":"invalid_grant"}`,
		answerStatus: http.StatusOK, answerBody: `{"access_token":"a","refresh_token":"next"}`,
	}
	e.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		way := "form"
		if r.Header.Get("Authorization") != "" {
			way = "header"
		}
		what := "probe"
		switch {
		case r.URL.Path == "/revoke":
			what = "revoke"
		case r.PostForm.Get("refresh_token") == secretRefreshToken:
			what = "refresh"
		}
		e.mu.Lock()
		e.sent = append(e.sent, way+" "+what)
		status, body := e.notAcceptedStatus, e.notAcceptedBody
		if way == e.takes && (way == "header" || r.PostForm.Get("client_secret") == "client-secret") {
			switch what {
			case "refresh":
				status, body = e.answerStatus, e.answerBody
			case "revoke":
				status, body = http.StatusOK, ``
			default:
				status, body = e.probedStatus, e.probedBody
			}
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

func (e *pickyEndpoint) requests() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.sent...)
}

// A provider refuses a client that sent its secret the wrong way, and a
// refusal of a refresh must be about the refresh token alone. So the way is
// found out first, with a refresh token that is not one, and a session's
// token is sent only once it is known.
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
		assert.Equal(t, []string{"header probe", "form probe", "form refresh"}, e.requests())

		_, err = provider.Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		require.NoError(t, provider.Revoke(ctx, secretRefreshToken))
		assert.Equal(t, []string{"header probe", "form probe", "form refresh", "form refresh", "form revoke"}, e.requests(),
			"what was found is used from then on")
	})

	t.Run("HeaderOnly", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "header")
		provider := e.provider(t, ClientAuthDetect)
		_, err := provider.Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		_, err = provider.Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		assert.Equal(t, []string{"header probe", "header refresh", "header refresh"}, e.requests())
	})

	t.Run("Configured", func(t *testing.T) {
		t.Parallel()
		var refused *RefusedError
		e := newPickyEndpoint(t, "form")
		_, err := e.provider(t, ClientAuthForm).Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		_, err = e.provider(t, ClientAuthHeader).Refresh(ctx, secretRefreshToken)
		require.ErrorAs(t, err, &refused, "a configured way is not second-guessed")
		assert.Equal(t, []string{"form refresh", "header refresh"}, e.requests())
	})

	// Once the way is known, a refusal of a session's token is the answer
	// whatever its code, and the token is sent once: there is no second
	// request whose failure could take the refusal back.
	t.Run("ARefusalIsTheAnswerWhateverItsCode", func(t *testing.T) {
		t.Parallel()
		for _, takes := range []string{"header", "form"} {
			for body, code := range map[string]string{
				`{"error":"invalid_grant"}`:   "invalid_grant",
				`{"error":"not_allowed"}`:     "not_allowed",
				`{"error":"invalid_client"}`:  "invalid_client",
				`{"error":"session_revoked"}`: "other",
			} {
				var refused *RefusedError
				e := newPickyEndpoint(t, takes)
				e.answerStatus, e.answerBody = http.StatusBadRequest, body
				_, err := e.provider(t, ClientAuthDetect).Refresh(ctx, secretRefreshToken)
				require.ErrorAs(t, err, &refused, "%s by a provider that takes the %s", body, takes)
				assert.Equal(t, code, refused.Code)
				requests := e.requests()
				assert.Equal(t, takes+" refresh", requests[len(requests)-1])
				assert.Equal(t, 1, strings.Count(strings.Join(requests, ","), "refresh"), "the session's token is sent once: %v", requests)
			}
		}
	})

	// The way cannot be found out now. No session's token is sent, and
	// nothing is concluded about any session.
	t.Run("NotFoundOutNow", func(t *testing.T) {
		t.Parallel()
		for name, arrange := range map[string]func(*pickyEndpoint){
			"NoAnswerToTheHeader": func(e *pickyEndpoint) {
				e.takes = "header"
				e.probedStatus, e.probedBody = http.StatusBadGateway, `<html>`
			},
			"TheHeaderIsRefusedAndTheFormGetsNoAnswer": func(e *pickyEndpoint) {
				e.takes = "form"
				e.probedStatus, e.probedBody = http.StatusBadGateway, `<html>`
			},
		} {
			var refused *RefusedError
			e := newPickyEndpoint(t, "")
			arrange(e)
			provider := e.provider(t, ClientAuthDetect)
			_, err := provider.Refresh(ctx, secretRefreshToken)
			require.Error(t, err, name)
			assert.False(t, errors.As(err, &refused), "%s is not a refusal: %v", name, err)
			require.Error(t, provider.Revoke(ctx, secretRefreshToken), name)
			assert.NotContains(t, strings.Join(e.requests(), ","), "refresh", name)
			assert.NotContains(t, strings.Join(e.requests(), ","), "revoke", name)

			// When the provider answers again, the way is found and used.
			e.mu.Lock()
			e.probedStatus, e.probedBody = http.StatusBadRequest, `{"error":"invalid_grant"}`
			e.mu.Unlock()
			_, err = provider.Refresh(ctx, secretRefreshToken)
			require.NoError(t, err, name)
		}
	})

	// The provider accepts this client neither way, as it does for a client
	// that has been disabled. That is not about the way, and the refusal of
	// the session's token that follows is the provider's answer.
	t.Run("TheClientIsRefusedBothWays", func(t *testing.T) {
		t.Parallel()
		var refused *RefusedError
		e := newPickyEndpoint(t, "")
		_, err := e.provider(t, ClientAuthDetect).Refresh(ctx, secretRefreshToken)
		require.ErrorAs(t, err, &refused)
		assert.Equal(t, "invalid_client", refused.Code)
		assert.Equal(t, []string{"header probe", "form probe", "header refresh"}, e.requests())
	})

	// A provider that answers a token it never issued with a code of its own
	// has still accepted the client.
	t.Run("AProviderWithItsOwnCodeForAnUnknownToken", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "header")
		e.probedStatus, e.probedBody = http.StatusBadRequest, `{"error":"token_not_found"}`
		_, err := e.provider(t, ClientAuthDetect).Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		assert.Equal(t, []string{"header probe", "header refresh"}, e.requests())
	})

	t.Run("RevokeBeforeAnyRefresh", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "form")
		require.NoError(t, e.provider(t, ClientAuthDetect).Revoke(ctx, secretRefreshToken))
		assert.Equal(t, []string{"header probe", "form probe", "form revoke"}, e.requests())
	})

	// Many refreshes at once find the way out once.
	t.Run("FoundOutOnce", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "form")
		provider := e.provider(t, ClientAuthDetect)
		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() {
				_, err := provider.Refresh(ctx, secretRefreshToken)
				assert.NoError(t, err)
			})
		}
		wg.Wait()
		assert.Equal(t, 2, strings.Count(strings.Join(e.requests(), ","), "probe"))
	})

	// The probe carries nothing of a session, and a public client needs none.
	t.Run("WhatTheProbeCarries", func(t *testing.T) {
		t.Parallel()
		e := newEndpoint(t)
		detecting, err := NewHTTPProvider(HTTPProviderConfig{TokenURL: e.server.URL, ClientID: "dagu-web", ClientSecret: "client-secret"})
		require.NoError(t, err)
		_, err = detecting.Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		require.Len(t, e.forms, 2)
		assert.Equal(t, probeRefreshToken, e.forms[0].Get("refresh_token"))
		assert.NotContains(t, e.forms[0].Encode(), secretRefreshToken)

		public := newEndpoint(t)
		noSecret, err := NewHTTPProvider(HTTPProviderConfig{TokenURL: public.server.URL, ClientID: "dagu-web"})
		require.NoError(t, err)
		_, err = noSecret.Refresh(ctx, secretRefreshToken)
		require.NoError(t, err)
		require.Len(t, public.forms, 1)
	})

	_, err := NewHTTPProvider(HTTPProviderConfig{TokenURL: "https://issuer.example/token", ClientID: "dagu-web", ClientAuth: 7})
	require.Error(t, err)
}
