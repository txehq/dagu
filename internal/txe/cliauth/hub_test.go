// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cliauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
)

// hubFixture is a signed-in store and a hub client that sends the sign-in.
type hubFixture struct {
	provider *cliauthtest.Provider
	hub      *cliauthtest.Hub
	store    *Store
	client   *http.Client
	first    *Tokens
}

func newHubFixture(t *testing.T) *hubFixture {
	t.Helper()
	f := &hubFixture{provider: cliauthtest.New(t), hub: cliauthtest.NewHub(t), store: newTestStore(t)}
	f.provider.Rotate = true
	f.first = signIn(t, f.provider)
	e := entryFor(f.provider, f.first)
	e.Hub = f.hub.API()
	_, err := f.store.Replace(context.Background(), e)
	require.NoError(t, err)
	f.client = &http.Client{Transport: &BearerTransport{Store: f.store, Hub: f.hub.API()}}
	return f
}

func (f *hubFixture) post(t *testing.T, path, body string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.hub.API()+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer dagu_api_key_must_not_be_sent")
	return f.client.Do(req)
}

func TestBearerTransportSendsTheSignInOnly(t *testing.T) {
	f := newHubFixture(t)
	resp, err := f.post(t, "/txe/jobs", `{"x":1}`)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	reqs := f.hub.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "Bearer "+f.first.AccessToken, reqs[0].Authorization)
	assert.Equal(t, `{"x":1}`, reqs[0].Body)
	assert.Equal(t, 0, f.provider.Refreshes())
}

func TestBearerTransportRenewsOnceOnInvalidToken(t *testing.T) {
	f := newHubFixture(t)
	f.hub.Decide = func(_ *http.Request, call int) int {
		if call == 1 {
			return http.StatusUnauthorized
		}
		return 0
	}
	resp, err := f.post(t, "/txe/jobs", `{"request_id":"req_1"}`)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	reqs := f.hub.Requests()
	require.Len(t, reqs, 2)
	assert.Equal(t, "Bearer "+f.first.AccessToken, reqs[0].Authorization)
	assert.NotEqual(t, reqs[0].Authorization, reqs[1].Authorization, "the second attempt carries the renewed token")
	assert.Equal(t, reqs[0].Body, reqs[1].Body, "the same body is sent again")
	assert.Equal(t, 1, f.provider.Refreshes())

	stored, err := f.store.Load(f.hub.API())
	require.NoError(t, err)
	assert.Equal(t, "Bearer "+stored.AccessToken, reqs[1].Authorization)
}

func TestBearerTransportGivesUpAfterOneRenewal(t *testing.T) {
	f := newHubFixture(t)
	f.hub.Decide = func(*http.Request, int) int { return http.StatusUnauthorized }
	_, err := f.post(t, "/txe/jobs", `{}`)
	require.ErrorIs(t, err, ErrHubRefusedSignIn)
	assert.Len(t, f.hub.Requests(), 2, "one attempt and one retry, no more")
	assert.Equal(t, 1, f.provider.Refreshes(), "one renewal, no more")
}

func TestBearerTransportDoesNotRenewOnOtherRefusals(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newHubFixture(t)
			f.hub.Decide = func(*http.Request, int) int { return status }
			resp, err := f.post(t, "/txe/jobs", `{}`)
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, status, resp.StatusCode)
			assert.Len(t, f.hub.Requests(), 1)
			assert.Equal(t, 0, f.provider.Refreshes())
		})
	}
}

func TestBearerTransportPlain401IsNotRenewed(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="dagu"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(hub.Close)
	p := cliauthtest.New(t)
	s := newTestStore(t)
	e := entryFor(p, signIn(t, p))
	e.Hub = hub.URL
	_, err := s.Replace(context.Background(), e)
	require.NoError(t, err)
	client := &http.Client{Transport: &BearerTransport{Store: s, Hub: hub.URL}}
	resp, err := client.Get(hub.URL + "/x") //nolint:noctx // test
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, 0, p.Refreshes())
}

func TestBearerTransportProviderUnavailableIsDistinct(t *testing.T) {
	f := newHubFixture(t)
	f.hub.Decide = func(*http.Request, int) int { return http.StatusServiceUnavailable }
	_, err := f.post(t, "/txe/jobs", `{}`)
	var unavailable *HubProviderUnavailableError
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, "5", unavailable.RetryAfter)
	assert.Contains(t, err.Error(), "identity provider did not answer")
	assert.NotErrorIs(t, err, ErrHubRefusedSignIn)
	assert.Len(t, f.hub.Requests(), 1, "not retried")
	assert.Equal(t, 0, f.provider.Refreshes())
}

func TestBearerTransportKeepsOther503(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"code":"busy","message":"try later"}`)
	}))
	t.Cleanup(hub.Close)
	p := cliauthtest.New(t)
	s := newTestStore(t)
	e := entryFor(p, signIn(t, p))
	e.Hub = hub.URL
	_, err := s.Replace(context.Background(), e)
	require.NoError(t, err)
	client := &http.Client{Transport: &BearerTransport{Store: s, Hub: hub.URL}}
	resp, err := client.Get(hub.URL + "/x") //nolint:noctx // test
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Contains(t, string(body), "try later", "the body reaches the caller intact")
}

func TestBearerTransportDoesNotResendAnUnreadableBody(t *testing.T) {
	f := newHubFixture(t)
	f.hub.Decide = func(*http.Request, int) int { return http.StatusUnauthorized }
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.hub.API()+"/txe/jobs", io.NopCloser(bytes.NewReader([]byte("{}"))))
	require.NoError(t, err)
	req.GetBody = nil
	resp, err := f.client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Len(t, f.hub.Requests(), 1)
	assert.Equal(t, 0, f.provider.Refreshes())
}

func TestBearerTransportRefusesAnotherHost(t *testing.T) {
	f := newHubFixture(t)
	other := cliauthtest.NewHub(t)
	_, err := f.client.Get(other.API() + "/txe/jobs") //nolint:noctx // test
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to send")
	assert.Empty(t, other.Requests())

	// A redirect off the hub is refused the same way.
	redirector := httptest.NewServer(http.RedirectHandler(other.API()+"/stolen", http.StatusFound))
	t.Cleanup(redirector.Close)
	e, err := f.store.Load(f.hub.API())
	require.NoError(t, err)
	e.Hub = redirector.URL
	_, err = f.store.Replace(context.Background(), e)
	require.NoError(t, err)
	client := &http.Client{Transport: &BearerTransport{Store: f.store, Hub: redirector.URL}}
	_, err = client.Get(redirector.URL + "/x") //nolint:noctx // test
	require.Error(t, err)
	assert.Empty(t, other.Requests())
}

func TestBearerTransportRenewalRefusedEndsSignIn(t *testing.T) {
	f := newHubFixture(t)
	f.hub.Decide = func(*http.Request, int) int { return http.StatusUnauthorized }
	f.provider.RefreshHandler = func(w http.ResponseWriter) bool {
		cliauthtest.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return true
	}
	_, err := f.post(t, "/txe/jobs", `{}`)
	var refused *RefusedError
	require.ErrorAs(t, err, &refused)
	assert.Contains(t, err.Error(), "dagu txe login")
	_, err = f.store.Load(f.hub.API())
	assert.ErrorIs(t, err, ErrNotSignedIn)
	assert.Len(t, f.hub.Requests(), 1)
}

func TestBearerTransportNotSignedIn(t *testing.T) {
	hub := cliauthtest.NewHub(t)
	client := &http.Client{Transport: &BearerTransport{Store: newTestStore(t), Hub: hub.API()}}
	_, err := client.Get(hub.API() + "/txe/jobs") //nolint:noctx // test
	require.ErrorIs(t, err, ErrNotSignedIn)
	assert.Empty(t, hub.Requests())
}

func TestDiscoverHub(t *testing.T) {
	ctx := context.Background()
	hub := cliauthtest.NewHub(t)
	_, err := DiscoverHub(ctx, hub.API(), nil)
	require.ErrorIs(t, err, ErrHubNoSignIn)

	hub.Publish("https://idp.example/realms/r", "dagu-cli", HubUseAll)
	cfg, err := DiscoverHub(ctx, hub.API(), nil)
	require.NoError(t, err)
	assert.Equal(t, HubConfig{Contract: 1, Issuer: "https://idp.example/realms/r", ClientID: "dagu-cli", Scopes: []string{"openid"}, Use: HubUseAll}, *cfg)
	for _, r := range hub.Requests() {
		assert.Empty(t, r.Authorization, "discovery sends no credential")
	}

	bad := map[string]map[string]any{
		"unknown use":       {"contract": 1, "issuer": "https://idp.example", "client_id": "c", "use": "some"},
		"newer contract":    {"contract": 2, "issuer": "https://idp.example", "client_id": "c", "use": "all"},
		"plain http issuer": {"contract": 1, "issuer": "http://idp.example", "client_id": "c", "use": "all"},
		"no client":         {"contract": 1, "issuer": "https://idp.example", "use": "all"},
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			hub.Advertise = doc
			_, err := DiscoverHub(ctx, hub.API(), nil)
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrHubNoSignIn)
		})
	}
}

func TestDiscoverHubOlderHubs(t *testing.T) {
	ctx := context.Background()
	cases := map[string]http.HandlerFunc{
		"401 from auth": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
		"403":           func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) },
		"405":           func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusMethodNotAllowed) },
		"web UI": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<!doctype html>")
		},
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)
			_, err := DiscoverHub(ctx, srv.URL+"/api/v1", nil)
			assert.ErrorIs(t, err, ErrHubNoSignIn)
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	t.Cleanup(srv.Close)
	_, err := DiscoverHub(ctx, srv.URL+"/api/v1", nil)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrHubNoSignIn), "a failing hub is not a hub without sign-in")
}

func TestRefreshAtAndDiscover(t *testing.T) {
	ctx := context.Background()
	p := cliauthtest.New(t)
	p.Rotate = true
	tokens := signIn(t, p)
	endpoints, err := Discover(ctx, providerOf(p), nil)
	require.NoError(t, err)
	assert.Equal(t, p.Issuer()+"/token", endpoints.Token)
	assert.Equal(t, p.Issuer()+"/revoke", endpoints.Revocation)

	renewed, err := RefreshAt(ctx, endpoints.Token, providerOf(p), tokens.Identity, tokens.RefreshToken, nil)
	require.NoError(t, err)
	assert.NotEqual(t, tokens.RefreshToken, renewed.RefreshToken)
	assert.WithinDuration(t, time.Now().Add(5*time.Minute), renewed.Expiry, 5*time.Second)

	// The old refresh token was rotated away: a verdict.
	_, err = RefreshAt(ctx, endpoints.Token, providerOf(p), tokens.Identity, tokens.RefreshToken, nil)
	var refused *RefusedError
	require.ErrorAs(t, err, &refused)

	p.AccessSubject = "someone-else"
	_, err = RefreshAt(ctx, endpoints.Token, providerOf(p), tokens.Identity, renewed.RefreshToken, nil)
	require.ErrorIs(t, err, ErrIdentityChanged)

	_, err = RefreshAt(ctx, "http://idp.example/token", providerOf(p), tokens.Identity, "rt", nil)
	assert.ErrorContains(t, err, "https")
}
