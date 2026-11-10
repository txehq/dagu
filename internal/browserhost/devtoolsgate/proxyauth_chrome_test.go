// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/procutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real Chrome behind the gate, sending every request to a proxy that carries
// nothing without its credential. The gate answers the proxy's challenge for
// every target the browser makes, whatever made it and however early its
// first request leaves, and gives the credential to nobody else.

const (
	proxyCredentialUser     = "dagu"
	proxyCredentialPassword = "proxy-secret"
)

// testSite serves the pages the real-Chrome tests load through the proxy.
type testSite struct {
	server *httptest.Server
	mu     sync.Mutex
	// privateAuthorizations are the Authorization headers /private was asked
	// with: a site's own challenge must get no credential from the gate.
	privateAuthorizations []string
	// fromWorker counts the requests the service worker made.
	fromWorker int
}

func newTestSite(t *testing.T) *testSite {
	t.Helper()
	s := &testSite{}
	s.server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	return s
}

// host is the site's authority, as a request through the proxy names it.
func (s *testSite) host() string { return s.server.Listener.Addr().String() }

// crossSiteHost is the site under another name, so a frame from it is
// another site to the browser and runs in a process of its own.
func (s *testSite) crossSiteHost() string {
	_, port, _ := strings.Cut(s.host(), ":")
	return "localhost:" + port
}

func (s *testSite) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/private":
		s.mu.Lock()
		s.privateAuthorizations = append(s.privateAuthorizations, r.Header.Get("Authorization"))
		s.mu.Unlock()
		w.Header().Set("WWW-Authenticate", `Basic realm="site"`)
		w.WriteHeader(http.StatusUnauthorized)
	case "/sw.js":
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = io.WriteString(w, `self.addEventListener('install', event => event.waitUntil(fetch('/from-sw').then(r => { if (!r.ok) throw new Error(r.status); })));`)
	case "/from-sw":
		s.mu.Lock()
		s.fromWorker++
		s.mu.Unlock()
		_, _ = io.WriteString(w, "worker")
	case "/register-worker":
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
	case "/embed":
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<p>embedding</p><iframe src="http://`+r.URL.Query().Get("frame")+`/frame"></iframe>`)
	case "/frame":
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<p>framed through the proxy</p>`)
	default:
		_, _ = io.WriteString(w, "reached through the proxy")
	}
}

// credentialProxy is a forward proxy that carries only the test site, and
// nothing without the gate's credential: a request without it is refused
// with a 407 challenge and reaches no site. A path can be given a realm of
// its own, challenged once whatever credential the request carries, so a
// credential the browser kept from earlier requests cannot answer it and
// only the gate's answer for that request can.
type credentialProxy struct {
	server *httptest.Server
	hosts  map[string]bool

	mu              sync.Mutex
	realms          map[string]string
	realmChallenged map[string]bool
	// challenged and authorized count, by path, the 407s sent and the
	// requests carried with the credential.
	challenged map[string]int
	authorized map[string]int
	// refused are the requests to a site the proxy does not carry.
	refused []string
}

func newCredentialProxy(t *testing.T, site *testSite) *credentialProxy {
	t.Helper()
	p := &credentialProxy{
		hosts:           map[string]bool{site.host(): true, site.crossSiteHost(): true},
		realms:          map[string]string{},
		realmChallenged: map[string]bool{},
		challenged:      map[string]int{},
		authorized:      map[string]int{},
	}
	p.server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	return p
}

func (p *credentialProxy) address() string { return p.server.Listener.Addr().String() }

// auth is the credential the gate holds for this proxy.
func (p *credentialProxy) auth() *ProxyAuth {
	return &ProxyAuth{Addresses: []string{p.address()}, Username: proxyCredentialUser, Password: proxyCredentialPassword}
}

// chromeArgs sends every request of the browser, loopback included, to the
// proxy.
func (p *credentialProxy) chromeArgs() []string {
	return []string{"--proxy-server=" + p.address(), "--proxy-bypass-list=<-loopback>"}
}

// challengeOnceWithRealm makes the first request for path answer a challenge
// of realm, whatever it carries.
func (p *credentialProxy) challengeOnceWithRealm(path, realm string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.realms[path] = realm
}

// counts returns how often path was challenged and how often it was carried
// with the credential.
func (p *credentialProxy) counts(path string) (challenged, authorized int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.challenged[path], p.authorized[path]
}

func (p *credentialProxy) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect || !p.hosts[r.URL.Host] {
		p.mu.Lock()
		p.refused = append(p.refused, r.Method+" "+r.URL.Host)
		p.mu.Unlock()
		http.Error(w, "this proxy carries only the test site", http.StatusForbidden)
		return
	}
	path := r.URL.Path
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyCredentialUser+":"+proxyCredentialPassword))
	authorized := r.Header.Get("Proxy-Authorization") == want
	p.mu.Lock()
	realm := "dagu"
	if own, ok := p.realms[path]; ok && !p.realmChallenged[path] {
		// A realm the browser holds no credential for yet.
		p.realmChallenged[path] = true
		realm, authorized = own, false
	}
	if !authorized {
		p.challenged[path]++
		p.mu.Unlock()
		w.Header().Set("Proxy-Authenticate", `Basic realm="`+realm+`"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	p.authorized[path]++
	p.mu.Unlock()
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
}

// startProxiedChrome starts real Chrome behind the gate, on a profile of its
// own that is removed at the end, with every request going to proxy and the
// gate holding the proxy's credential. It returns a browser-level client.
func startProxiedChrome(t *testing.T, proxy *credentialProxy) (*Handle, *cdpConn) {
	t.Helper()
	chrome := requireChrome(t)
	self, err := os.Executable()
	require.NoError(t, err)
	profile, err := os.MkdirTemp("", "dagu-gate-proxy-auth-")
	require.NoError(t, err)
	// Registered first, so it runs last: the profile goes whether or not the
	// browser started. Chrome's last processes may still be writing as it
	// exits.
	t.Cleanup(func() {
		eventually(t, 15*time.Second, func() bool { return os.RemoveAll(profile) == nil }, "the profile is removed")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	handle, err := Start(ctx, self, Config{
		Token:      NewToken(),
		Executable: chrome,
		Args: ChromeArgs(LaunchOptions{
			UserDataDir: profile,
			Headless:    true,
			NoSandbox:   os.Getenv("CI") != "" || (runtime.GOOS == "linux" && os.Geteuid() == 0),
			Extra:       proxy.chromeArgs(),
		}),
		ProxyAuth: proxy.auth(),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = handle.Kill()
		eventually(t, 15*time.Second, func() bool { return !procutil.IsAlive(handle.BrowserPID) }, "the browser exits")
	})
	_, body := get(t, handle.URL+"/json/version")
	var version map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &version))
	return handle, dialWS(t, version["webSocketDebuggerUrl"], nil)
}

// createPage creates a page target on url and returns its id and a session
// of the client's own on it.
func (c *cdpConn) createPage(url string) (targetID, session string) {
	c.t.Helper()
	created := c.mustCall("", "Target.createTarget", map[string]any{"url": url})
	var page struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(c.t, json.Unmarshal(created, &page))
	return page.TargetID, c.attach(page.TargetID)
}

// attach attaches a session on targetID.
func (c *cdpConn) attach(targetID string) string {
	c.t.Helper()
	session := sessionOf(c.mustCall("", "Target.attachToTarget", map[string]any{"targetId": targetID, "flatten": true}))
	require.NotEmpty(c.t, session)
	return session
}

// evaluateString evaluates expression on session and returns its string
// value, or "" when it has none.
func (c *cdpConn) evaluateString(session, expression string, userGesture bool) string {
	c.t.Helper()
	result, err := c.call(session, "Runtime.evaluate", map[string]any{"expression": expression, "returnByValue": true, "userGesture": userGesture})
	if err != nil {
		return ""
	}
	var evaluated struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	_ = json.Unmarshal(result, &evaluated)
	return evaluated.Result.Value
}

// bodyText is the text of the document on session.
func (c *cdpConn) bodyText(session string) string {
	c.t.Helper()
	return c.evaluateString(session, "document.body ? document.body.innerText : ''", false)
}

// targetsOfType lists the ids of the browser's targets of typ whose URL
// contains urlPart.
func (c *cdpConn) targetsOfType(typ, urlPart string) []string {
	c.t.Helper()
	var targets struct {
		TargetInfos []struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
			URL      string `json:"url"`
		} `json:"targetInfos"`
	}
	require.NoError(c.t, json.Unmarshal(c.mustCall("", "Target.getTargets", map[string]any{}), &targets))
	var ids []string
	for _, info := range targets.TargetInfos {
		if info.Type == typ && strings.Contains(info.URL, urlPart) {
			ids = append(ids, info.TargetID)
		}
	}
	return ids
}

// A page the client created blank and navigated reaches the site through
// the proxy: the gate answers the proxy's challenge, and gives the
// credential to nobody else, such as a site asking for a password.
func TestRealChromeAnswersProxyChallenge(t *testing.T) {
	site := newTestSite(t)
	proxy := newCredentialProxy(t, site)
	_, c := startProxiedChrome(t, proxy)
	_, session := c.createPage("about:blank")

	c.mustCall(session, "Page.navigate", map[string]any{"url": site.server.URL + "/"})
	eventually(t, 30*time.Second, func() bool { return strings.Contains(c.bodyText(session), "reached through the proxy") }, "the page loads through the proxy")
	challenged, authorized := proxy.counts("/")
	assert.Positive(t, challenged, "the proxy challenged the browser")
	assert.Positive(t, authorized, "the browser answered with the gate's credential")

	// A site asking for a password gets nothing from the gate.
	c.mustCall(session, "Page.navigate", map[string]any{"url": site.server.URL + "/private"})
	eventually(t, 30*time.Second, func() bool {
		site.mu.Lock()
		defer site.mu.Unlock()
		return len(site.privateAuthorizations) > 0
	}, "the site's challenge was reached")
	time.Sleep(time.Second)
	site.mu.Lock()
	defer site.mu.Unlock()
	for _, authorization := range site.privateAuthorizations {
		assert.Empty(t, authorization, "the proxy's credential is never given to a site")
	}
}

// The browser's very first proxied request is a target's created with a
// URL: the browser process starts its request before the target can be
// held, so the challenge is answered from the gate's browser-level
// interception, in place before any target exists (TXE-6197; on the
// per-target answer this request failed). A client's own browser-level
// interception, as the write gate's, runs beside it and sees no challenge.
func TestRealChromeAnswersProxyChallengeForATargetCreatedNavigating(t *testing.T) {
	site := newTestSite(t)
	proxy := newCredentialProxy(t, site)
	handle, c := startProxiedChrome(t, proxy)

	_, body := get(t, handle.URL+"/json/version")
	var version map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &version))
	helper := dialWS(t, version["webSocketDebuggerUrl"], HelperHandshake())
	helper.mustCall("", "Fetch.enable", map[string]any{"patterns": []map[string]any{{"urlPattern": "*", "requestStage": "Request"}}})
	var helperMu sync.Mutex
	var helperPaused, helperChallenged int
	go func() {
		for {
			select {
			case event := <-helper.events:
				switch event.Method {
				case "Fetch.requestPaused":
					var params struct {
						RequestID string `json:"requestId"`
					}
					_ = json.Unmarshal(event.Params, &params)
					helperMu.Lock()
					helperPaused++
					helperMu.Unlock()
					helper.send("", "Fetch.continueRequest", map[string]any{"requestId": params.RequestID})
				case "Fetch.authRequired":
					helperMu.Lock()
					helperChallenged++
					helperMu.Unlock()
				}
			case <-helper.done:
				return
			}
		}
	}()

	_, session := c.createPage(site.server.URL + "/first")
	eventually(t, 30*time.Second, func() bool { return strings.Contains(c.bodyText(session), "reached through the proxy") }, "the target's first request loads through the proxy")
	challenged, authorized := proxy.counts("/first")
	assert.Positive(t, challenged, "the proxy challenged the target's first request")
	assert.Positive(t, authorized, "the first request was answered with the gate's credential")
	helperMu.Lock()
	defer helperMu.Unlock()
	assert.Positive(t, helperPaused, "the client's own browser-level interception saw the requests")
	assert.Zero(t, helperChallenged, "the proxy's challenge is the gate's to answer, not a client's")
}

// The browser's first page exists before the gate's interception, with
// request loaders built without it; the gate has the browser build them
// again. A fetch from that page, as the browser's very first proxied
// request, is answered for. (Measured without the rebuild: it met the
// challenge and hung, nobody answering.)
func TestRealChromeAnswersProxyChallengeForTheFirstPage(t *testing.T) {
	site := newTestSite(t)
	proxy := newCredentialProxy(t, site)
	_, c := startProxiedChrome(t, proxy)
	var first []string
	eventually(t, 10*time.Second, func() bool {
		first = c.targetsOfType("page", "about:blank")
		return len(first) == 1
	}, "the browser's first page")
	session := c.attach(first[0])
	started := c.evaluateString(session, "window.outcome = 'pending'; fetch('"+site.server.URL+"/first-page', {mode: 'no-cors'})"+
		".then(r => { window.outcome = 'answered ' + r.type; }).catch(e => { window.outcome = 'failed ' + e.message; }); 'started'", false)
	require.Equal(t, "started", started)
	eventually(t, 30*time.Second, func() bool { return c.evaluateString(session, "window.outcome", false) != "pending" }, "the fetch settles")
	assert.Equal(t, "answered opaque", c.evaluateString(session, "window.outcome", false), "the fetch got the site's answer")
	challenged, authorized := proxy.counts("/first-page")
	assert.Positive(t, challenged, "the proxy challenged the first page's request")
	assert.Positive(t, authorized, "the first page's request was answered with the gate's credential")
}

// A popup opened with an address is a new target created already
// navigating. The proxy challenges its request with a realm of its own, so
// the credential the browser kept from the opener's requests cannot answer
// it: only the gate's answer for the popup's request does.
func TestRealChromeAnswersProxyChallengeForAPopup(t *testing.T) {
	site := newTestSite(t)
	proxy := newCredentialProxy(t, site)
	proxy.challengeOnceWithRealm("/popup", "popup")
	_, c := startProxiedChrome(t, proxy)
	// The opener is created blank and navigated, the path the runtime's own
	// pages take, so the popup's is the first request of a target created
	// already navigating.
	_, session := c.createPage("about:blank")
	c.mustCall(session, "Page.navigate", map[string]any{"url": site.server.URL + "/"})
	eventually(t, 30*time.Second, func() bool { return strings.Contains(c.bodyText(session), "reached through the proxy") }, "the opener loads through the proxy")

	opened := c.evaluateString(session, "window.popup = window.open('"+site.server.URL+"/popup'); String(window.popup)", true)
	require.Equal(t, "[object Window]", opened, "the page opened a popup")
	eventually(t, 30*time.Second, func() bool {
		return strings.Contains(c.evaluateString(session, "window.popup.document.body ? window.popup.document.body.innerText : ''", false), "reached through the proxy")
	}, "the popup loads through the proxy")
	assert.Len(t, c.targetsOfType("page", "/popup"), 1, "the popup is a target of its own")
	challenged, authorized := proxy.counts("/popup")
	assert.Positive(t, challenged, "the proxy challenged the popup's request with its own realm")
	assert.Positive(t, authorized, "the popup's request was answered with the gate's credential")
}

// A frame from another site runs in a process of its own, as a target of
// type iframe. Its request is challenged with a realm of its own, so only
// the gate's answer for the frame's request carries it.
func TestRealChromeAnswersProxyChallengeForACrossSiteFrame(t *testing.T) {
	site := newTestSite(t)
	proxy := newCredentialProxy(t, site)
	proxy.challengeOnceWithRealm("/frame", "frame")
	_, c := startProxiedChrome(t, proxy)
	_, session := c.createPage("about:blank")
	c.mustCall(session, "Page.navigate", map[string]any{"url": site.server.URL + "/embed?frame=" + site.crossSiteHost()})
	eventually(t, 30*time.Second, func() bool { return strings.Contains(c.bodyText(session), "embedding") }, "the page loads through the proxy")

	var frames []string
	eventually(t, 30*time.Second, func() bool {
		frames = c.targetsOfType("iframe", "/frame")
		return len(frames) == 1
	}, "the frame is a target of its own, in a process of its own")
	frameSession := c.attach(frames[0])
	eventually(t, 30*time.Second, func() bool { return strings.Contains(c.bodyText(frameSession), "framed through the proxy") }, "the frame loads through the proxy")
	challenged, authorized := proxy.counts("/frame")
	assert.Positive(t, challenged, "the proxy challenged the frame's request with its own realm")
	assert.Positive(t, authorized, "the frame's request was answered with the gate's credential")
}

// A service worker's own requests reach the site through the proxy: the
// proxy challenges the worker's request with a realm of its own, so only
// the gate's answer for the worker's request carries it.
func TestRealChromeAnswersProxyChallengeForAServiceWorker(t *testing.T) {
	site := newTestSite(t)
	proxy := newCredentialProxy(t, site)
	proxy.challengeOnceWithRealm("/from-sw", "worker")
	_, c := startProxiedChrome(t, proxy)
	_, session := c.createPage("about:blank")
	c.mustCall(session, "Page.navigate", map[string]any{"url": site.server.URL + "/register-worker"})

	state := func() string {
		return c.evaluateString(session, "document.getElementById('state') ? document.getElementById('state').textContent : ''", false)
	}
	eventually(t, 45*time.Second, func() bool {
		settled := state()
		return settled != "" && settled != "registering"
	}, "the worker settles")
	assert.Equal(t, "installed", state(), "the worker's own request through the proxy succeeded")
	challenged, authorized := proxy.counts("/from-sw")
	assert.Positive(t, challenged, "the proxy challenged the worker's request")
	assert.Positive(t, authorized, "the worker's request carried the gate's credential")
	site.mu.Lock()
	defer site.mu.Unlock()
	assert.Positive(t, site.fromWorker, "the worker's request reached the site")
}
