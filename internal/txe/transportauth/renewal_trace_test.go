// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth_test

import (
	"context"
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

	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

// A renewal is made on behalf of the request that needed the token, so the
// hooks of a trace on that request's context do not fire for it (TXE-6352).
// The provider here is at the hub's own origin, and in one case both are
// behind one proxy: the two cases an address cannot tell apart.

// callerHooks counts what a caller's trace saw, by the address asked for.
type callerHooks struct {
	mu      sync.Mutex
	getConn map[string]int
	other   atomic.Int32
}

func newCallerHooks() *callerHooks { return &callerHooks{getConn: map[string]int{}} }

func (h *callerHooks) context(parent context.Context) context.Context {
	return httptrace.WithClientTrace(parent, &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			h.mu.Lock()
			h.getConn[hostPort]++
			h.mu.Unlock()
		},
		GotConn:              func(httptrace.GotConnInfo) { h.other.Add(1) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { h.other.Add(1) },
		GotFirstResponseByte: func() { h.other.Add(1) },
		ConnectStart:         func(string, string) { h.other.Add(1) },
		ConnectDone:          func(string, string, error) { h.other.Add(1) },
	})
}

func (h *callerHooks) connections() map[string]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]int{}
	maps.Copy(out, h.getConn)
	return out
}

// sameOrigin serves the token endpoint and a hub route from one server.
func sameOrigin(t *testing.T, endpoint *tokenEndpoint) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/token", endpoint)
	mux.HandleFunc("/api/v1/ping", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) })
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func sourceAt(t *testing.T, server *httptest.Server, opts ...transportauth.SourceOption) *transportauth.RefreshingSource {
	t.Helper()
	path := writeCredential(t, t.TempDir(), server.URL+"/token")
	source, err := transportauth.NewRefreshingSource(path, opts...)
	require.NoError(t, err)
	return source
}

// get sends a request of the caller's own on ctx through rt.
func get(t *testing.T, ctx context.Context, rt http.RoundTripper, url string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func TestRenewalFiresNoneOfTheCallersHooksAtTheHubsOrigin(t *testing.T) {
	endpoint := &tokenEndpoint{}
	server := sameOrigin(t, endpoint)
	source := sourceAt(t, server)
	hooks := newCallerHooks()
	ctx := hooks.context(context.Background())

	token, err := source.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "access-token", token)
	assert.Equal(t, 1, endpoint.callCount(), "the provider was asked")
	assert.Empty(t, hooks.connections(), "the renewal fired the caller's GetConn")
	assert.Zero(t, hooks.other.Load(), "the renewal fired the caller's hooks")

	// Control: the caller's own request to the same origin is traced.
	get(t, ctx, &http.Transport{}, server.URL+"/api/v1/ping")
	assert.Equal(t, map[string]int{strings.TrimPrefix(server.URL, "http://"): 1}, hooks.connections())
	assert.Positive(t, hooks.other.Load())
}

// forwardProxy is a plain HTTP forward proxy on loopback. It counts what it
// carried, by destination host.
func forwardProxy(t *testing.T) (*httptest.Server, func() map[string]int) {
	t.Helper()
	var mu sync.Mutex
	carried := map[string]int{}
	upstream := &http.Transport{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		carried[r.URL.Host]++
		mu.Unlock()
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
	return proxy, func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		maps.Copy(out, carried)
		return out
	}
}

func TestRenewalFiresNoneOfTheCallersHooksThroughTheSameProxy(t *testing.T) {
	endpoint := &tokenEndpoint{}
	server := sameOrigin(t, endpoint)
	proxy, carried := forwardProxy(t)
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	viaProxy := func() *http.Transport { return &http.Transport{Proxy: http.ProxyURL(proxyURL)} }
	source := sourceAt(t, server, transportauth.WithHTTPClient(&http.Client{Transport: viaProxy()}))
	hooks := newCallerHooks()
	ctx := hooks.context(context.Background())

	_, err = source.Token(ctx)
	require.NoError(t, err)
	origin := strings.TrimPrefix(server.URL, "http://")
	assert.Equal(t, map[string]int{origin: 1}, carried(), "the renewal went through the proxy")
	assert.Empty(t, hooks.connections())
	assert.Zero(t, hooks.other.Load())

	// Control: the caller's own request through the same proxy is traced, by
	// the proxy's address.
	get(t, ctx, viaProxy(), server.URL+"/api/v1/ping")
	assert.Equal(t, map[string]int{strings.TrimPrefix(proxy.URL, "http://"): 1}, hooks.connections())
	assert.Equal(t, map[string]int{origin: 2}, carried())
}

// The renewal keeps the caller's deadline and cancellation, and its errors
// are what they were.
func TestRenewalKeepsTheCallersDeadlineAndCancellation(t *testing.T) {
	endpoint := &tokenEndpoint{}
	server := sameOrigin(t, endpoint)
	// The held requests are released before the server closes: cleanups run
	// last first, and the server's close waits for its handlers.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	endpoint.set(func(e *tokenEndpoint) { e.during = func() { <-release } })
	hooks := newCallerHooks()

	t.Run("deadline", func(t *testing.T) {
		source := sourceAt(t, server)
		ctx, cancel := context.WithTimeout(hooks.context(context.Background()), 200*time.Millisecond)
		defer cancel()
		started := time.Now()
		_, err := source.Token(ctx)
		assert.ErrorIs(t, err, transportauth.ErrProviderUnavailable)
		assert.Less(t, time.Since(started), 10*time.Second, "the caller's deadline, not the client's own timeout, ended the request")
	})
	t.Run("cancel while the provider holds the request", func(t *testing.T) {
		source := sourceAt(t, server)
		ctx, cancel := context.WithCancel(hooks.context(context.Background()))
		defer cancel()
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()
		started := time.Now()
		_, err := source.Token(ctx)
		assert.ErrorIs(t, err, transportauth.ErrProviderUnavailable)
		assert.Less(t, time.Since(started), 10*time.Second)
	})
	t.Run("cancelled before", func(t *testing.T) {
		source := sourceAt(t, server)
		ctx, cancel := context.WithCancel(hooks.context(context.Background()))
		cancel()
		_, err := source.Token(ctx)
		assert.ErrorIs(t, err, context.Canceled)
	})
	assert.Empty(t, hooks.connections(), "no attempt fired the caller's hooks")
}

type renewalKey struct{}

// The renewal's request carries the caller's other values and a context
// with none of its hooks, as its transport sees it.
func TestRenewalKeepsTheCallersValues(t *testing.T) {
	endpoint := &tokenEndpoint{}
	server := sameOrigin(t, endpoint)
	var seen atomic.Int32
	inspect := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen.Add(1)
		assert.Equal(t, "kept", req.Context().Value(renewalKey{}), "a value of the caller's")
		if trace := httptrace.ContextClientTrace(req.Context()); trace != nil {
			assert.Nil(t, trace.GetConn, "a hook of the caller's")
			assert.Nil(t, trace.GotFirstResponseByte)
		}
		return http.DefaultTransport.RoundTrip(req)
	})
	source := sourceAt(t, server, transportauth.WithHTTPClient(&http.Client{Transport: inspect}))
	hooks := newCallerHooks()
	ctx := hooks.context(context.WithValue(context.Background(), renewalKey{}, "kept"))
	_, err := source.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(1), seen.Load())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// Renewals for several requests at once each stay off their caller's trace.
func TestConcurrentRenewalsStayOffEveryCallersTrace(t *testing.T) {
	endpoint := &tokenEndpoint{}
	server := sameOrigin(t, endpoint)
	const n = 8
	sources := make([]*transportauth.RefreshingSource, n)
	for i := range sources {
		sources[i] = sourceAt(t, server)
	}
	hooks := make([]*callerHooks, n)
	var wg sync.WaitGroup
	for i := range sources {
		hooks[i] = newCallerHooks()
		wg.Go(func() {
			token, err := sources[i].Token(hooks[i].context(context.Background()))
			assert.NoError(t, err)
			assert.Equal(t, "access-token", token)
		})
	}
	wg.Wait()
	assert.Equal(t, n, endpoint.callCount())
	for i, h := range hooks {
		assert.Empty(t, h.connections(), "caller %d", i)
		assert.Zero(t, h.other.Load(), "caller %d", i)
	}
}
