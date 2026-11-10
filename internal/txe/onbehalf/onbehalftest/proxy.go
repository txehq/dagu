// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package onbehalftest has test servers for the packages that make requests
// on another request's behalf.
package onbehalftest

import (
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Proxy is a plain HTTP forward proxy on loopback. It counts the requests
// it carried, by destination host.
type Proxy struct {
	// URL is the proxy's address, for http.ProxyURL.
	URL string

	mu      sync.Mutex
	carried map[string]int
}

// NewProxy starts a proxy that is closed when the test ends.
func NewProxy(t *testing.T) *Proxy {
	t.Helper()
	p := &Proxy{carried: map[string]int{}}
	upstream := &http.Transport{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		p.carried[r.URL.Host]++
		p.mu.Unlock()
		// A forward proxy sends to whatever URL it is asked for; this one
		// serves tests on loopback only.
		out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body) //nolint:gosec
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
	t.Cleanup(func() { server.Close(); upstream.CloseIdleConnections() })
	p.URL = server.URL
	return p
}

// Carried returns how many requests went to each destination host.
func (p *Proxy) Carried() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]int{}
	maps.Copy(out, p.carried)
	return out
}

// Total returns how many requests the proxy carried.
func (p *Proxy) Total() int {
	n := 0
	for _, v := range p.Carried() {
		n += v
	}
	return n
}
