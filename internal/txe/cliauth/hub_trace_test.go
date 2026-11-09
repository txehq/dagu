// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cliauth

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BearerTransport's renewal, discovery, the token request and whatever else
// the provider is asked, is made on the hub request's behalf: a trace on the
// hub request's context sees the hub request's own attempts and nothing of
// the renewal (TXE-6352). The provider here is at the hub's own origin, the
// case an address cannot tell apart.

// sameOriginHub is an identity provider and a hub on one server. The hub
// refuses the first bearer it sees as invalid_token, unless told to accept
// every bearer, and accepts the rest.
type sameOriginHub struct {
	server    *httptest.Server
	acceptAll bool
	mu        sync.Mutex
	hub       []string // Authorization header of each hub request
	tokens    int
	disc      int
}

func newSameOriginHub(t *testing.T) *sameOriginHub {
	t.Helper()
	h := &sameOriginHub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		h.mu.Lock()
		h.disc++
		h.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 h.server.URL,
			"authorization_endpoint": h.server.URL + "/auth",
			"token_endpoint":         h.server.URL + "/token",
			"jwks_uri":               h.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.tokens++
		h.mu.Unlock()
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "refresh-1" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "access-2", "token_type": "Bearer", "expires_in": 300, "refresh_token": "refresh-2"})
	})
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.hub = append(h.hub, r.Header.Get("Authorization"))
		refuse := len(h.hub) == 1 && !h.acceptAll
		h.mu.Unlock()
		if refuse {
			w.Header().Set("WWW-Authenticate", `Bearer realm="dagu", error="invalid_token"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthorized", "message": "refused"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	h.server = httptest.NewServer(mux)
	t.Cleanup(h.server.Close)
	return h
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *sameOriginHub) counts() (hub []string, tokens, discoveries int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.hub...), h.tokens, h.disc
}

// signedInAt stores a sign-in for the hub at the same origin, with an access
// token the hub will refuse once.
func (h *sameOriginHub) signedInAt(t *testing.T, expiry time.Time) *Store {
	t.Helper()
	store := newTestStore(t)
	_, err := store.Replace(context.Background(), &Entry{
		Hub:      h.server.URL + "/api/v1",
		Provider: Provider{Issuer: h.server.URL, ClientID: "dagu-cli"},
		Identity: Identity{Issuer: h.server.URL, Subject: "person-1"},
		// Synthetic tokens: not a JWT, so no identity is read from them.
		AccessToken: "access-1", RefreshToken: "refresh-1", Expiry: expiry, SignedInAt: time.Now(),
	})
	require.NoError(t, err)
	return store
}

// hubTrace counts a hub request's connection events by the address asked for.
type hubTrace struct {
	mu      sync.Mutex
	getConn map[string]int
	wrote   atomic.Int32
}

func newHubTrace() *hubTrace { return &hubTrace{getConn: map[string]int{}} }

func (tr *hubTrace) context() context.Context {
	return httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			tr.mu.Lock()
			tr.getConn[hostPort]++
			tr.mu.Unlock()
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { tr.wrote.Add(1) },
	})
}

func (tr *hubTrace) connections() map[string]int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	out := map[string]int{}
	maps.Copy(out, tr.getConn)
	return out
}

func sendTraced(t *testing.T, client *http.Client, tr *hubTrace, url string) {
	t.Helper()
	req, err := http.NewRequestWithContext(tr.context(), http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// A renewal after the hub's 401, at the hub's own origin: the hub request's
// trace counts its two attempts, not the discovery and token requests.
func TestBearerTransportRenewalStaysOffTheHubRequestsTrace(t *testing.T) {
	h := newSameOriginHub(t)
	store := h.signedInAt(t, time.Now().Add(time.Hour))
	// Transports of this test's own, so no idle connection is reused and
	// every attempt asks for a connection.
	client := &http.Client{Transport: &BearerTransport{
		Base: &http.Transport{}, Store: store, Hub: h.server.URL + "/api/v1", Use: HubUseTxe,
		Provider: &http.Client{Transport: &http.Transport{}},
	}}
	tr := newHubTrace()
	sendTraced(t, client, tr, h.server.URL+"/api/v1/txe/jobs")

	hub, tokens, discoveries := h.counts()
	assert.Equal(t, []string{"Bearer access-1", "Bearer access-2"}, hub, "the hub saw the stale token, then the renewed one")
	assert.Equal(t, 1, tokens)
	assert.Equal(t, 1, discoveries)
	origin := strings.TrimPrefix(h.server.URL, "http://")
	assert.Equal(t, map[string]int{origin: 2}, tr.connections(), "the two hub attempts, and nothing of the renewal, at one address")
	assert.Equal(t, int32(2), tr.wrote.Load())
}

// A renewal before the first attempt, for an expired sign-in: the trace sees
// the one hub attempt only.
func TestBearerTransportRenewalBeforeSendingStaysOffTheTrace(t *testing.T) {
	h := newSameOriginHub(t)
	h.acceptAll = true
	store := h.signedInAt(t, time.Now().Add(-time.Minute))
	client := &http.Client{Transport: &BearerTransport{
		Base: &http.Transport{}, Store: store, Hub: h.server.URL + "/api/v1", Use: HubUseTxe,
		Provider: &http.Client{Transport: &http.Transport{}},
	}}
	tr := newHubTrace()
	sendTraced(t, client, tr, h.server.URL+"/api/v1/txe/jobs")

	hub, tokens, _ := h.counts()
	assert.Equal(t, []string{"Bearer access-2"}, hub, "renewed before the one attempt")
	assert.Equal(t, 1, tokens)
	assert.Equal(t, map[string]int{strings.TrimPrefix(h.server.URL, "http://"): 1}, tr.connections())
}

// Through one proxy, both for the hub and for the provider, the trace counts
// the hub attempts by the proxy's address, and still nothing of the renewal.
func TestBearerTransportRenewalThroughTheSameProxyStaysOffTheTrace(t *testing.T) {
	h := newSameOriginHub(t)
	store := h.signedInAt(t, time.Now().Add(time.Hour))
	proxy, carried := testForwardProxy(t)
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	client := &http.Client{Transport: &BearerTransport{
		Base: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Store: store, Hub: h.server.URL + "/api/v1", Use: HubUseTxe,
		Provider: &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}},
	}}
	tr := newHubTrace()
	sendTraced(t, client, tr, h.server.URL+"/api/v1/txe/jobs")

	hub, tokens, discoveries := h.counts()
	assert.Len(t, hub, 2)
	assert.Equal(t, 1, tokens)
	assert.Equal(t, 1, discoveries)
	assert.Equal(t, 4, carried(), "two hub attempts, the discovery and the token request went through the proxy")
	assert.Equal(t, map[string]int{strings.TrimPrefix(proxy.URL, "http://"): 2}, tr.connections())
}

// testForwardProxy is a plain HTTP forward proxy on loopback that counts the
// requests it carried.
func testForwardProxy(t *testing.T) (*httptest.Server, func() int) {
	t.Helper()
	var carried atomic.Int32
	upstream := &http.Transport{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		carried.Add(1)
		out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		out.Header = r.Header.Clone()
		resp, err := upstream.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		maps.Copy(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(func() { proxy.Close(); upstream.CloseIdleConnections() })
	return proxy, func() int { return int(carried.Load()) }
}
