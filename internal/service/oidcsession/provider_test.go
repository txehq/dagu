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

	renewal, err := e.provider(t, "client-secret").Refresh(context.Background(), secretRefreshToken, ClientAuthHeader)
	require.NoError(t, err)
	assert.Equal(t, Renewal{RefreshToken: "next", IDToken: "id"}, renewal)

	require.Len(t, e.forms, 1)
	assert.Equal(t, "refresh_token", e.forms[0].Get("grant_type"))
	assert.Equal(t, secretRefreshToken, e.forms[0].Get("refresh_token"))
	assert.True(t, strings.HasPrefix(e.auths[0], "Basic "), "a confidential client authenticates in the header")
	assert.Empty(t, e.forms[0].Get("client_secret"), "and not in the body")

	// A public client names itself in the body and sends no secret.
	public := newEndpoint(t)
	_, err = public.provider(t, "").Refresh(context.Background(), secretRefreshToken, ClientAuthHeader)
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

			_, err := e.provider(t, "client-secret").Refresh(context.Background(), secretRefreshToken, ClientAuthHeader)

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
	_, err := provider.Refresh(context.Background(), secretRefreshToken, ClientAuthHeader)
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
	_, err = timedOut.Refresh(context.Background(), secretRefreshToken, ClientAuthHeader)
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
		_, err = provider.Refresh(context.Background(), secretRefreshToken, ClientAuthHeader)
		require.Error(t, err)
	}
	assert.Empty(t, elsewhere.forms, "the refresh token was not sent on")
}

func TestHTTPProviderRevoke(t *testing.T) {
	t.Parallel()
	e := newEndpoint(t)
	provider := e.provider(t, "client-secret")

	require.NoError(t, provider.Revoke(context.Background(), secretRefreshToken, ClientAuthHeader))
	require.Len(t, e.forms, 1)
	assert.Equal(t, secretRefreshToken, e.forms[0].Get("token"))
	assert.Equal(t, "refresh_token", e.forms[0].Get("token_type_hint"))

	e.answer(http.StatusServiceUnavailable, `{{token}}`)
	err := provider.Revoke(context.Background(), secretRefreshToken, ClientAuthHeader)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretRefreshToken)

	none, err := NewHTTPProvider(HTTPProviderConfig{TokenURL: e.server.URL, ClientID: "dagu-web"})
	require.NoError(t, err)
	require.ErrorIs(t, none.Revoke(context.Background(), secretRefreshToken, ClientAuthHeader), ErrRevocationUnsupported)

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
	// answer is the answer to a refresh by an accepted client.
	answerStatus int
	answerBody   string
	// sent lists each request: the way the secret came, and what it was.
	sent []string
}

func newPickyEndpoint(t *testing.T, takes string) *pickyEndpoint {
	t.Helper()
	e := &pickyEndpoint{
		takes:             takes,
		notAcceptedStatus: http.StatusUnauthorized, notAcceptedBody: `{"error":"invalid_client"}`,
		answerStatus: http.StatusOK, answerBody: `{"access_token":"a","refresh_token":"next"}`,
	}
	e.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		way, what := "form", "refresh"
		if r.Header.Get("Authorization") != "" {
			way = "header"
		}
		if r.URL.Path == "/revoke" {
			what = "revoke"
		}
		e.mu.Lock()
		e.sent = append(e.sent, way+" "+what)
		status, body := e.notAcceptedStatus, e.notAcceptedBody
		if way == e.takes && (way == "header" || r.PostForm.Get("client_secret") == "client-secret") {
			status, body = e.answerStatus, e.answerBody
			if what == "revoke" {
				status, body = http.StatusOK, ``
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

func (e *pickyEndpoint) set(change func(*pickyEndpoint)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	change(e)
}

// The way the provider takes the client secret is established at sign-in,
// with the refresh token the provider has just issued: a refusal of that
// token can only be about the client. The way a refresh is granted by is the
// provider's.
func TestHTTPProviderEstablishesTheWayAtSignIn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("HeaderOnly", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "header")
		auth, renewal, err := e.provider(t, ClientAuthDetect).Establish(ctx, secretRefreshToken)
		require.NoError(t, err)
		assert.Equal(t, ClientAuthHeader, auth)
		assert.Equal(t, "next", renewal.RefreshToken, "establishing exchanged the token, and the new one is the session's")
		assert.Equal(t, []string{"header refresh"}, e.requests())
	})

	t.Run("FormOnly", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "form")
		provider := e.provider(t, ClientAuthDetect)
		auth, renewal, err := provider.Establish(ctx, secretRefreshToken)
		require.NoError(t, err)
		assert.Equal(t, ClientAuthForm, auth)
		assert.Equal(t, "next", renewal.RefreshToken)
		assert.Equal(t, []string{"header refresh", "form refresh"}, e.requests())

		// The next sign-in tries first the way that grant showed. It still
		// asks: its own token has to be granted that way.
		auth, renewal, err = provider.Establish(ctx, "another-users-token")
		require.NoError(t, err)
		assert.Equal(t, ClientAuthForm, auth)
		assert.Equal(t, "next", renewal.RefreshToken)
		assert.Equal(t, []string{"header refresh", "form refresh", "form refresh"}, e.requests())
	})

	// The provider is changed to take the secret another way, and a user
	// signs in before any session has met the change. What the last grant
	// showed is tried first and refused, and the session is established with
	// the way that is granted now.
	t.Run("TheProviderWasChangedSinceTheLastGrant", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "form")
		provider := e.provider(t, ClientAuthDetect)
		auth, _, err := provider.Establish(ctx, secretRefreshToken)
		require.NoError(t, err)
		require.Equal(t, ClientAuthForm, auth)

		e.set(func(e *pickyEndpoint) { e.takes = "header" })
		auth, renewal, err := provider.Establish(ctx, "the-next-sign-ins-token")
		require.NoError(t, err)
		assert.Equal(t, ClientAuthHeader, auth)
		assert.Equal(t, "next", renewal.RefreshToken)
		assert.Equal(t, []string{"form refresh", "header refresh"}, e.requests()[2:])
	})

	// A provider that refuses the wrong way with a code of its own choosing
	// is no different: what counts is which way is granted.
	t.Run("WhateverTheRefusalOfTheWrongWayIsCalled", func(t *testing.T) {
		t.Parallel()
		for _, body := range []string{`{"error":"invalid_request"}`, `{"error":"unauthorized_client"}`, `{"error":"invalid_grant"}`, `{"error":"no_client_id"}`} {
			e := newPickyEndpoint(t, "form")
			e.notAcceptedStatus, e.notAcceptedBody = http.StatusBadRequest, body
			auth, _, err := e.provider(t, ClientAuthDetect).Establish(ctx, secretRefreshToken)
			require.NoError(t, err, body)
			assert.Equal(t, ClientAuthForm, auth, body)
		}
	})

	t.Run("ConfiguredOrNotNeeded", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "form")
		for _, configured := range []ClientAuth{ClientAuthForm, ClientAuthHeader} {
			auth, renewal, err := e.provider(t, configured).Establish(ctx, secretRefreshToken)
			require.NoError(t, err)
			assert.Equal(t, configured, auth, "a configured way is not second-guessed")
			assert.Empty(t, renewal.RefreshToken)
		}
		public, err := NewHTTPProvider(HTTPProviderConfig{TokenURL: e.server.URL + "/token", ClientID: "dagu-web"})
		require.NoError(t, err)
		auth, _, err := public.Establish(ctx, secretRefreshToken)
		require.NoError(t, err)
		assert.Equal(t, ClientAuthForm, auth, "a public client has no secret; it names itself in the form")
		assert.Empty(t, e.requests())
	})

	// The provider will not refresh the token it has just issued, whichever
	// way it is asked. A session could never be revalidated.
	t.Run("RefusedBothWays", func(t *testing.T) {
		t.Parallel()
		var refused *RefusedError
		e := newPickyEndpoint(t, "")
		_, _, err := e.provider(t, ClientAuthDetect).Establish(ctx, secretRefreshToken)
		require.ErrorAs(t, err, &refused)
		assert.Equal(t, []string{"header refresh", "form refresh"}, e.requests())
	})

	t.Run("NoAnswer", func(t *testing.T) {
		t.Parallel()
		for takes, want := range map[string][]string{"header": {"header refresh"}, "form": {"header refresh", "form refresh"}} {
			var refused *RefusedError
			e := newPickyEndpoint(t, takes)
			e.answerStatus, e.answerBody = http.StatusBadGateway, `<html>`
			_, _, err := e.provider(t, ClientAuthDetect).Establish(ctx, secretRefreshToken)
			require.Error(t, err)
			assert.False(t, errors.As(err, &refused), "no answer is not a refusal: %v", err)
			assert.Equal(t, want, e.requests())
		}
	})
}

// A refresh for a session is sent once, the way the session was established
// with. A refusal is then the answer whatever its code: there is no second
// request whose failure could take it back, and no list of codes to be on.
func TestHTTPProviderRefreshesTheWayItIsTold(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, takes := range []string{"header", "form"} {
		auth := map[string]ClientAuth{"header": ClientAuthHeader, "form": ClientAuthForm}[takes]
		for body, code := range map[string]string{
			`{"error":"invalid_grant"}`:   "invalid_grant",
			`{"error":"not_allowed"}`:     "not_allowed",
			`{"error":"invalid_client"}`:  "invalid_client",
			`{"error":"invalid_request"}`: "invalid_request",
			`{"error":"session_revoked"}`: "other",
		} {
			var refused *RefusedError
			e := newPickyEndpoint(t, takes)
			e.answerStatus, e.answerBody = http.StatusBadRequest, body
			_, err := e.provider(t, ClientAuthDetect).Refresh(ctx, secretRefreshToken, auth)
			require.ErrorAs(t, err, &refused, "%s by a provider that takes the %s", body, takes)
			assert.Equal(t, code, refused.Code)
			assert.Equal(t, []string{takes + " refresh"}, e.requests())
		}
	}

	// The way a session was established with is used even if it is refused:
	// the provider changed, the session ends, and the next sign-in
	// establishes the way again.
	t.Run("TheProviderChangesItsWay", func(t *testing.T) {
		t.Parallel()
		var refused *RefusedError
		e := newPickyEndpoint(t, "header")
		provider := e.provider(t, ClientAuthDetect)
		auth, _, err := provider.Establish(ctx, secretRefreshToken)
		require.NoError(t, err)
		require.Equal(t, ClientAuthHeader, auth)

		e.set(func(e *pickyEndpoint) { e.takes = "form" })
		_, err = provider.Refresh(ctx, secretRefreshToken, auth)
		require.ErrorAs(t, err, &refused)
		assert.Equal(t, []string{"header refresh", "header refresh"}, e.requests(), "the form is not tried for a session established with the header")

		auth, _, err = provider.Establish(ctx, "the-next-sign-ins-token")
		require.NoError(t, err)
		assert.Equal(t, ClientAuthForm, auth, "the next sign-in is established with the way that is granted now")
		assert.Equal(t, []string{"header refresh", "form refresh"}, e.requests()[2:])
	})

	t.Run("Revoke", func(t *testing.T) {
		t.Parallel()
		e := newPickyEndpoint(t, "form")
		provider := e.provider(t, ClientAuthDetect)
		require.NoError(t, provider.Revoke(ctx, secretRefreshToken, ClientAuthForm))
		require.ErrorIs(t, provider.Revoke(ctx, secretRefreshToken, ClientAuthHeader), ErrRevocationRefused,
			"a 4xx is the provider's answer, and it is no")
		assert.Equal(t, []string{"form revoke", "header revoke"}, e.requests(), "a revocation needs nothing found out first")

		// A 5xx is not an answer, and neither is a 4xx that says to come
		// back later: the revocation is tried again, not given up.
		var err error
		for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusRequestTimeout, http.StatusTooEarly} {
			unwell := newPickyEndpoint(t, "")
			unwell.notAcceptedStatus, unwell.notAcceptedBody = status, `later`
			err = unwell.provider(t, ClientAuthDetect).Revoke(ctx, secretRefreshToken, ClientAuthHeader)
			require.Error(t, err, status)
			require.NotErrorIs(t, err, ErrRevocationRefused, "%d", status)
		}

		// A token whose session was never established has no way. It is
		// asked both ways.
		require.NoError(t, provider.Revoke(ctx, secretRefreshToken, ClientAuthDetect))
		assert.Equal(t, []string{"header revoke", "form revoke"}, e.requests()[2:])
		neither := newPickyEndpoint(t, "")
		require.ErrorIs(t, neither.provider(t, ClientAuthDetect).Revoke(ctx, secretRefreshToken, ClientAuthDetect), ErrRevocationRefused,
			"no both ways is the provider's no")
		assert.Equal(t, []string{"header revoke", "form revoke"}, neither.requests())

		// No answer to the header is not a no. The form is not then tried:
		// its answer could only hide that the header got none.
		silent := newPickyEndpoint(t, "")
		silent.notAcceptedStatus, silent.notAcceptedBody = http.StatusBadGateway, `<html>`
		err = silent.provider(t, ClientAuthDetect).Revoke(ctx, secretRefreshToken, ClientAuthDetect)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrRevocationRefused)
		assert.Equal(t, []string{"header revoke"}, silent.requests())
	})

	_, err := NewHTTPProvider(HTTPProviderConfig{TokenURL: "https://issuer.example/token", ClientID: "dagu-web", ClientAuth: 7})
	require.Error(t, err)
}
