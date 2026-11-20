// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real Chrome behind the gate, with every request going to the gate's
// configured proxy: an owned loopback proxy that carries only an owned
// loopback site (proxyauth_chrome_test.go). Nothing here reaches beyond the
// host's loopback.

// countingListener is an owned loopback listener that counts every request
// it gets, standing for a proxy the gate did not configure.
type countingListener struct {
	server *httptest.Server
	mu     sync.Mutex
	count  int
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	l := &countingListener{}
	l.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		l.mu.Lock()
		l.count++
		l.mu.Unlock()
		http.Error(w, "not the gate's proxy", http.StatusForbidden)
	}))
	t.Cleanup(l.server.Close)
	return l
}

func (l *countingListener) requests() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

// A page reaches the site through the gate's configured proxy, and the
// Target params that would set a context's networking apart from the
// browser's never reach the browser: the gate refuses them, and the other
// listener they name is never contacted.
func TestRealChromeKeepsEveryPageOnTheGatesProxy(t *testing.T) {
	site := newTestSite(t)
	proxy := newCredentialProxy(t, site)
	other := newCountingListener(t)
	_, c := startProxiedChrome(t, proxy)

	_, session := c.createPage(site.server.URL + "/through-the-gate")
	eventually(t, 30*time.Second, func() bool { return strings.Contains(c.bodyText(session), "reached through the proxy") }, "the page loads through the proxy")
	_, authorized := proxy.counts("/through-the-gate")
	assert.Positive(t, authorized, "the page reached the site through the gate's proxy")

	for _, params := range []map[string]any{
		{"proxyServer": other.server.Listener.Addr().String()},
		{"proxyServer": other.server.Listener.Addr().String(), "proxyBypassList": "<-loopback>"},
		{},
	} {
		_, err := c.call("", "Target.createBrowserContext", params)
		assert.ErrorContains(t, err, "the gate does not pass on Target.createBrowserContext")
	}
	_, err := c.call("", "Target.createTarget", map[string]any{"url": site.server.URL + "/other-context", "browserContextId": "not-the-browsers-own"})
	assert.ErrorContains(t, err, "the gate serves only targets in the browser's own context")
	var contexts struct {
		IDs []string `json:"browserContextIds"`
	}
	require.NoError(t, json.Unmarshal(c.mustCall("", "Target.getBrowserContexts", map[string]any{}), &contexts))
	assert.Empty(t, contexts.IDs, "the browser holds no context but its own")

	_, session = c.createPage(site.server.URL + "/after")
	eventually(t, 30*time.Second, func() bool { return strings.Contains(c.bodyText(session), "reached through the proxy") }, "a later page loads through the proxy")
	assert.Zero(t, other.requests(), "the other listener was never contacted")
	assert.Zero(t, site.hitsOf("/other-context"))
}
