// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/procutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The gate gives the proxy's credential only to the proxy's own challenge,
// once per request, and leaves every other challenge, such as a site's or
// another proxy's, to the browser.
func TestProxyResponderAnswersOnlyItsProxy(t *testing.T) {
	t.Parallel()
	r := newProxyResponder(nil, ProxyAuth{Addresses: []string{"127.0.0.1:41234", "127.0.0.1:41235"}, Username: "dagu", Password: "secret"})

	assert.Equal(t, authProvide, r.answer("job-1", "Proxy", "http://127.0.0.1:41234"))
	assert.Equal(t, authCancel, r.answer("job-1", "Proxy", "http://127.0.0.1:41234"), "a refused credential is not given again")
	assert.Equal(t, authProvide, r.answer("job-2", "Proxy", "127.0.0.1:41235"), "the guard's port is the proxy's too")
	for name, challenge := range map[string][2]string{
		"Site":         {"Server", "http://127.0.0.1:41234"},
		"OtherProxy":   {"Proxy", "http://127.0.0.1:9999"},
		"OtherHost":    {"Proxy", "http://localhost:41234"},
		"NoPort":       {"Proxy", "http://127.0.0.1"},
		"Unparseable":  {"Proxy", "::"},
		"EmptyOrigin":  {"Proxy", ""},
		"EmptySource":  {"", "http://127.0.0.1:41234"},
		"LookalikeURL": {"Proxy", "http://127.0.0.1:41234.example.com"},
	} {
		assert.Equal(t, authDefault, r.answer("job-"+name, challenge[0], challenge[1]), name)
	}
}

// The responder bounds what it remembers.
func TestProxyResponderForgetsOldRequests(t *testing.T) {
	t.Parallel()
	r := newProxyResponder(nil, ProxyAuth{Addresses: []string{"127.0.0.1:1"}, Username: "u", Password: "p"})
	for i := range maxAnsweredChallenges + 10 {
		r.answer(strings.Repeat("x", i+1), "Proxy", "127.0.0.1:1")
	}
	assert.LessOrEqual(t, len(r.answered), maxAnsweredChallenges)
}

// A new target is held until the gate's interception and auto-attach
// beneath it are in place, and its interception lives on the gate's own
// session.
func TestProxyResponderHoldsNewTargets(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	tg.mux.mu.Lock()
	newProxyResponder(tg.mux, ProxyAuth{Addresses: []string{"127.0.0.1:1"}, Username: "u", Password: "p"}).install()
	tg.mux.mu.Unlock()

	a := tg.dial("")
	a.mustCall("", "Target.setAutoAttach", autoAttach(false))
	a.waitEvent("Target.attachedToTarget", nil)
	created := a.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"})
	var child struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(created, &child))
	eventually(t, 5*time.Second, func() bool {
		return slices.Contains(tg.state(a).Resumed, child.TargetID)
	}, "the target resumes once the gate's setup is in place")

	tg.mux.mu.Lock()
	var gateSession string
	for _, target := range tg.mux.targets {
		if target.id == child.TargetID {
			gateSession = target.gateSession
			assert.True(t, target.nestedAutoAttach, "the target's own children are held too")
		}
	}
	tg.mux.mu.Unlock()
	require.NotEmpty(t, gateSession)
	for _, s := range tg.state(a).Sessions {
		if s.ID == gateSession {
			assert.True(t, s.FetchAuth, "the gate intercepts on its own session")
		}
	}
}

// A target that takes neither interception nor auto-attach is not held
// for ever: the gate lets it run once both refusals are in, and what it
// sends without the credential the proxy refuses.
func TestProxyResponderReleasesATargetThatRefusesSetup(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	tg.fake.mu.Lock()
	tg.fake.refuseTargetSetup = true
	tg.fake.mu.Unlock()
	tg.mux.mu.Lock()
	newProxyResponder(tg.mux, ProxyAuth{Addresses: []string{"127.0.0.1:1"}, Username: "u", Password: "p"}).install()
	tg.mux.mu.Unlock()

	a := tg.dial("")
	a.mustCall("", "Target.setAutoAttach", autoAttach(false))
	a.waitEvent("Target.attachedToTarget", nil)
	created := a.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"})
	var child struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(created, &child))
	eventually(t, 5*time.Second, func() bool {
		return slices.Contains(tg.state(a).Resumed, child.TargetID)
	}, "the target runs once its setup was refused")
	tg.mux.mu.Lock()
	defer tg.mux.mu.Unlock()
	for _, target := range tg.mux.targets {
		if target.id == child.TargetID {
			assert.False(t, target.nestedAutoAttach, "a refused auto-attach is not taken as in place")
			assert.Zero(t, target.holds)
		}
	}
}

// Real Chrome, behind the gate, reaches a page through a proxy that
// requires a credential: the gate answers the proxy's challenge, and gives
// that credential to nobody else, such as a site asking for a password.
func TestRealChromeAnswersProxyChallenge(t *testing.T) {
	chrome := requireChrome(t)
	self, err := os.Executable()
	require.NoError(t, err)

	var mu sync.Mutex
	var siteAuthorizations []string
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/private" {
			mu.Lock()
			siteAuthorizations = append(siteAuthorizations, r.Header.Get("Authorization"))
			mu.Unlock()
			w.Header().Set("WWW-Authenticate", `Basic realm="site"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "reached through the proxy")
	}))
	t.Cleanup(site.Close)
	const wantAuthorization = "Basic ZGFndTpwcm94eS1zZWNyZXQ=" // dagu:proxy-secret
	var challenged, authorized int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.String(), site.URL) {
			http.Error(w, "this proxy carries only the test site", http.StatusForbidden)
			return
		}
		mu.Lock()
		if r.Header.Get("Proxy-Authorization") != wantAuthorization {
			challenged++
			mu.Unlock()
			w.Header().Set("Proxy-Authenticate", `Basic realm="dagu"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		authorized++
		mu.Unlock()
		outbound, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		outbound.Header = r.Header.Clone()
		outbound.Header.Del("Proxy-Authorization")
		response, err := http.DefaultTransport.RoundTrip(outbound)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()
		maps.Copy(w.Header(), response.Header)
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	t.Cleanup(proxy.Close)
	proxyAddress := proxy.Listener.Addr().String()

	profile, err := os.MkdirTemp("", "dagu-gate-proxy-auth-")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	handle, err := Start(ctx, self, Config{
		Token:      NewToken(),
		Executable: chrome,
		Args: ChromeArgs(LaunchOptions{
			UserDataDir: profile,
			Headless:    true,
			NoSandbox:   os.Getenv("CI") != "" || (runtime.GOOS == "linux" && os.Geteuid() == 0),
			Extra:       []string{"--proxy-server=" + proxyAddress, "--proxy-bypass-list=<-loopback>"},
		}),
		ProxyAuth: &ProxyAuth{Addresses: []string{proxyAddress}, Username: "dagu", Password: "proxy-secret"},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = handle.Kill()
		// Chrome's last processes may still be writing as it exits.
		eventually(t, 15*time.Second, func() bool {
			return !procutil.IsAlive(handle.BrowserPID) && os.RemoveAll(profile) == nil
		}, "the browser exits and its profile is removed")
	})

	_, body := get(t, handle.URL+"/json/version")
	var version map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &version))
	c := dialWS(t, version["webSocketDebuggerUrl"], nil)
	created := c.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"})
	var page struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(created, &page))
	attached := c.mustCall("", "Target.attachToTarget", map[string]any{"targetId": page.TargetID, "flatten": true})
	var session struct {
		SessionID string `json:"sessionId"`
	}
	require.NoError(t, json.Unmarshal(attached, &session))

	text := func() string {
		result := c.mustCall(session.SessionID, "Runtime.evaluate", map[string]any{"expression": "document.body ? document.body.innerText : ''", "returnByValue": true})
		var evaluated struct {
			Result struct {
				Value string `json:"value"`
			} `json:"result"`
		}
		_ = json.Unmarshal(result, &evaluated)
		return evaluated.Result.Value
	}
	c.mustCall(session.SessionID, "Page.navigate", map[string]any{"url": site.URL + "/"})
	eventually(t, 30*time.Second, func() bool { return strings.Contains(text(), "reached through the proxy") }, "the page loads through the proxy")
	mu.Lock()
	assert.Positive(t, challenged, "the proxy challenged the browser")
	assert.Positive(t, authorized, "the browser answered with the gate's credential")
	mu.Unlock()

	// A site asking for a password gets nothing from the gate.
	c.mustCall(session.SessionID, "Page.navigate", map[string]any{"url": site.URL + "/private"})
	eventually(t, 30*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(siteAuthorizations) > 0
	}, "the site's challenge was reached")
	time.Sleep(time.Second)
	mu.Lock()
	defer mu.Unlock()
	for _, authorization := range siteAuthorizations {
		assert.Empty(t, authorization, "the proxy's credential is never given to a site")
	}
}

// A service worker's own requests reach the site through a proxy that
// requires a credential: the gate holds the worker's target and answers the
// proxy's challenge on it. The proxy challenges the worker's request with a
// realm of its own, so a credential Chrome kept from the page's requests
// does not answer it: only the gate's answer on the worker's target does.
func TestRealChromeAnswersProxyChallengeForAServiceWorker(t *testing.T) {
	chrome := requireChrome(t)
	self, err := os.Executable()
	require.NoError(t, err)

	var mu sync.Mutex
	var fromWorker int
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sw.js":
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = io.WriteString(w, `self.addEventListener('install', event => event.waitUntil(fetch('/from-sw').then(r => { if (!r.ok) throw new Error(r.status); })));`)
		case "/from-sw":
			mu.Lock()
			fromWorker++
			mu.Unlock()
			_, _ = io.WriteString(w, "worker")
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<p id="state">registering</p><script>
navigator.serviceWorker.register('/sw.js')
  .then(reg => new Promise((resolve, reject) => {
    const worker = reg.installing || reg.waiting || reg.active;
    if (worker.state === 'activated' || worker.state === 'installed') return resolve(worker.state);
    worker.addEventListener('statechange', () => {
      if (worker.state === 'installed' || worker.state === 'activated') resolve(worker.state);
      if (worker.state === 'redundant') reject(new Error('the worker did not install'));
    });
  }))
  .then(state => { document.getElementById('state').textContent = 'installed'; })
  .catch(err => { document.getElementById('state').textContent = 'failed: ' + err.message; });
</script>`)
		}
	}))
	t.Cleanup(site.Close)

	const wantAuthorization = "Basic ZGFndTpwcm94eS1zZWNyZXQ=" // dagu:proxy-secret
	challengedWorker := false
	var workerChallenges, workerAuthorized int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.String(), site.URL) {
			http.Error(w, "this proxy carries only the test site", http.StatusForbidden)
			return
		}
		mu.Lock()
		worker := r.URL.Path == "/from-sw"
		authorized := r.Header.Get("Proxy-Authorization") == wantAuthorization
		switch {
		case worker && !challengedWorker:
			// A realm Chrome holds no credential for yet.
			challengedWorker = true
			workerChallenges++
			mu.Unlock()
			w.Header().Set("Proxy-Authenticate", `Basic realm="worker"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		case !authorized:
			if worker {
				workerChallenges++
			}
			mu.Unlock()
			w.Header().Set("Proxy-Authenticate", `Basic realm="dagu"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		if worker {
			workerAuthorized++
		}
		mu.Unlock()
		outbound, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		outbound.Header = r.Header.Clone()
		outbound.Header.Del("Proxy-Authorization")
		response, err := http.DefaultTransport.RoundTrip(outbound)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()
		maps.Copy(w.Header(), response.Header)
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	t.Cleanup(proxy.Close)
	proxyAddress := proxy.Listener.Addr().String()

	profile, err := os.MkdirTemp("", "dagu-gate-proxy-worker-")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	handle, err := Start(ctx, self, Config{
		Token:      NewToken(),
		Executable: chrome,
		Args: ChromeArgs(LaunchOptions{
			UserDataDir: profile,
			Headless:    true,
			NoSandbox:   os.Getenv("CI") != "" || (runtime.GOOS == "linux" && os.Geteuid() == 0),
			Extra:       []string{"--proxy-server=" + proxyAddress, "--proxy-bypass-list=<-loopback>"},
		}),
		ProxyAuth: &ProxyAuth{Addresses: []string{proxyAddress}, Username: "dagu", Password: "proxy-secret"},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = handle.Kill()
		eventually(t, 15*time.Second, func() bool {
			return !procutil.IsAlive(handle.BrowserPID) && os.RemoveAll(profile) == nil
		}, "the browser exits and its profile is removed")
	})

	_, body := get(t, handle.URL+"/json/version")
	var version map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &version))
	c := dialWS(t, version["webSocketDebuggerUrl"], nil)
	created := c.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"})
	var page struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(created, &page))
	attached := c.mustCall("", "Target.attachToTarget", map[string]any{"targetId": page.TargetID, "flatten": true})
	var session struct {
		SessionID string `json:"sessionId"`
	}
	require.NoError(t, json.Unmarshal(attached, &session))
	c.mustCall(session.SessionID, "Page.navigate", map[string]any{"url": site.URL + "/"})

	state := func() string {
		result := c.mustCall(session.SessionID, "Runtime.evaluate", map[string]any{"expression": "document.getElementById('state') ? document.getElementById('state').textContent : ''", "returnByValue": true})
		var evaluated struct {
			Result struct {
				Value string `json:"value"`
			} `json:"result"`
		}
		_ = json.Unmarshal(result, &evaluated)
		return evaluated.Result.Value
	}
	eventually(t, 45*time.Second, func() bool {
		settled := state()
		return settled != "" && settled != "registering"
	}, "the worker settles")
	assert.Equal(t, "installed", state(), "the worker's own request through the proxy succeeded")
	mu.Lock()
	defer mu.Unlock()
	assert.Positive(t, workerChallenges, "the proxy challenged the worker's request")
	assert.Positive(t, workerAuthorized, "the worker's request carried the gate's credential")
	assert.Positive(t, fromWorker, "the worker's request reached the site")
}
