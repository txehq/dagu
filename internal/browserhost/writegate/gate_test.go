// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package writegate_test

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/dagucloud/dagu/v2/internal/browserhost"
	"github.com/dagucloud/dagu/v2/internal/browserhost/devtoolsgate"
	"github.com/dagucloud/dagu/v2/internal/browserhost/writegate"
	"github.com/dagucloud/dagu/v2/internal/cmn/procutil"
	"github.com/dagucloud/dagu/v2/internal/test/chrometest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// site serves the pages the tests drive and counts the writes it receives
// by path.
type site struct {
	URL    string
	mu     sync.Mutex
	writes map[string]int
	reads  map[string]int
	socket atomic.Int64
	// startSocket counts the sockets a worker's first statement opened that
	// reached the site, apart from what the gate records.
	startSocket atomic.Int64
}

const sitePage = `<!doctype html><html><head><title>Ledger</title><script>
function post(path, opts) { return fetch(path, Object.assign({method: 'POST', body: 'amount=1000'}, opts || {})).then(r => 'ok ' + r.status, e => 'error ' + e); }
function socket() { return new Promise(res => { const s = new WebSocket(location.origin.replace('http', 'ws') + '/ws'); s.onopen = () => res('open'); s.onerror = () => res('error'); setTimeout(() => res('timeout'), 3000); }); }
</script></head><body><h1>Ledger</h1>
<form id="form" method="post" action="/w/form"><input name="title" value="hello"></form></body></html>`

// siteFrames shows a menu frame whose forms load the body frame, as a
// frameset site moves between its pages.
const siteFrames = `<!doctype html><html><head><title>Frames</title></head>
<frameset cols="30%,70%"><frame name="menu" src="/menu"><frame name="body" src="/"></frameset></html>`

const siteMenu = `<!doctype html><html><head><title>Menu</title></head><body>
<form id="form" method="post" action="/w/frame" target="body"><input name="title" value="next"></form>
<form id="read" method="get" action="/w/menu" target="body"><input name="title" value="next"></form></body></html>`

const siteIframe = `<!doctype html><html><head><title>Outer</title></head><body><iframe name="inner" src="/"></iframe></body></html>`

const siteWorker = `fetch('/w/worker', {method: 'POST', body: 'x'}).then(r => postMessage('ok ' + r.status), e => postMessage('error ' + e));`

// siteStartWorker opens a socket in its first statement.
const siteStartWorker = `new WebSocket(location.origin.replace('http', 'ws') + '/ws?from=start');
self.addEventListener('install', () => self.skipWaiting());`

const siteServiceWorker = `self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(clients.claim()));
self.addEventListener('message', e => e.waitUntil((async () => {
  const s = new WebSocket(location.origin.replace('http', 'ws') + '/ws?from=sw');
  const opened = await new Promise(res => { s.onopen = () => res('open'); s.onerror = () => res('error'); setTimeout(() => res('timeout'), 3000); });
  const write = await fetch('/w/service-worker', {method: 'POST', body: 'x'}).then(r => 'ok ' + r.status, e => 'error ' + e);
  e.source.postMessage(opened + ' ' + write);
})()));`

func startSite(t *testing.T) *site {
	t.Helper()
	s := &site{writes: map[string]int{}, reads: map[string]int{}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s.URL = "http://" + listener.Addr().String()
	server := &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return s
}

func (s *site) serve(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	switch {
	case r.URL.Path == "/ws":
		if r.URL.Query().Get("from") == "start" {
			s.startSocket.Add(1)
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		s.socket.Add(1)
		_ = conn.CloseNow()
		return
	case strings.HasPrefix(r.URL.Path, "/w/"):
		s.mu.Lock()
		if writegate.IsWrite(r.Method) {
			s.writes[r.URL.Path]++
		} else {
			s.reads[r.URL.Path]++
		}
		s.mu.Unlock()
		if r.URL.Path == "/w/stream" {
			// The stream stays open until the site closes, as a page's event
			// stream does.
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: hi\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	case r.URL.Path == "/worker.js":
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, siteWorker)
	case r.URL.Path == "/sw.js":
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, siteServiceWorker)
	case r.URL.Path == "/sw-start.js":
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, siteStartWorker)
	default:
		page, ok := map[string]string{"/frames": siteFrames, "/menu": siteMenu, "/iframe": siteIframe}[r.URL.Path]
		if !ok {
			page = sitePage
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page)
	}
}

func (s *site) written() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	maps.Copy(out, s.writes)
	return out
}

// browser is a headless Chrome started for a test, as the browser runtime
// starts one: behind its DevTools gate, where unpacked extensions may be
// loaded over DevTools.
type browser struct {
	gate    *devtoolsgate.Handle
	cdpURL  string
	profile string
}

// waitExited waits for the browser's process to exit.
func (b *browser) waitExited(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool { return !procutil.IsAlive(b.gate.BrowserPID) },
		30*time.Second, 50*time.Millisecond, "the browser did not exit")
}

func startBrowser(t *testing.T) *browser {
	t.Helper()
	return startBrowserOn(t, profileDir(t))
}

// profileDir returns a new browser profile directory. The browser's helper
// processes can write to it for a moment after the browser is ended, so it
// is removed with retries; call it before starting the browser, so it is
// removed after.
func profileDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "writegate-profile-")
	require.NoError(t, err)
	t.Cleanup(func() {
		for range 50 {
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
	return dir
}

// startupSlot lets one test browser start at a time: parallel Chrome
// startups on a loaded CI host can together outlast the wait for DevTools.
var startupSlot = make(chan struct{}, 1)

// browserSlots bounds how many tests drive a browser at once. Every running
// browser competes for the host's CPU, and on a small CI host enough of them
// together slow a gate's startup past its deadline.
var browserSlots = make(chan struct{}, 2)

// slotHolders records the tests that hold a browser slot, so a test that
// starts another browser after closing its first does not wait on itself.
var slotHolders sync.Map

// holdBrowserSlot takes a browser slot for the test until it ends.
func holdBrowserSlot(t *testing.T) {
	t.Helper()
	if _, held := slotHolders.LoadOrStore(t, struct{}{}); held {
		return
	}
	browserSlots <- struct{}{}
	t.Cleanup(func() {
		<-browserSlots
		slotHolders.Delete(t)
	})
}

// startBrowserOn starts the browser on the profile directory, behind a
// DevTools gate this test binary serves, as dagu does.
func startBrowserOn(t *testing.T, profile string) *browser {
	t.Helper()
	return startBrowserFor(t, profile, 0)
}

// startBrowserFor is startBrowserOn with the gate's unattended cap; zero is
// the gate's default.
func startBrowserFor(t *testing.T, profile string, maxUnattended time.Duration) *browser {
	t.Helper()
	path := chrometest.Require(t)
	holdBrowserSlot(t)
	startupSlot <- struct{}{}
	defer func() { <-startupSlot }()
	self, err := os.Executable()
	require.NoError(t, err)
	gate, err := devtoolsgate.Start(t.Context(), self, devtoolsgate.Config{
		Token:         devtoolsgate.NewToken(),
		Executable:    path,
		Args:          devtoolsgate.ChromeArgs(devtoolsgate.LaunchOptions{UserDataDir: profile, Headless: true, NoSandbox: true}),
		MaxUnattended: maxUnattended,
	})
	require.NoError(t, err, "the browser did not start behind its gate")
	b := &browser{gate: gate, cdpURL: gate.URL, profile: profile}
	t.Cleanup(func() {
		_ = gate.Kill()
		for range 300 {
			if !procutil.IsAlive(gate.BrowserPID) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
	return b
}

// guard runs a gate in mode rehearse on the browser until the test ends,
// and returns where its controls are.
func guard(t *testing.T, b *browser, policy writegate.Policy, secrets map[string]string) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	return guardIn(t, b, writegate.ModeRehearse, policy, secrets)
}

// guardIn runs a gate in mode on the browser until the test ends.
func guardIn(t *testing.T, b *browser, mode string, policy writegate.Policy, secrets map[string]string) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	g := guardRecorded(t, b, mode, policy, secrets)
	return g.controls, g.stop, g.done
}

// guarded is a gate a test runs: where its controls are, how to stop it,
// what it returned, and the timeline of its DevTools traffic, which is nil
// when the gate runs without the relay.
type guarded struct {
	controls string
	stop     context.CancelFunc
	done     <-chan error
	timeline *timeline
}

// guardRecorded is guardIn, also giving the gate's timeline.
func guardRecorded(t *testing.T, b *browser, mode string, policy writegate.Policy, secrets map[string]string) guarded {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	readyCh := make(chan writegate.Ready, 1)
	done := make(chan error, 1)
	served := make(chan struct{})
	token := "test-token"
	// The gate reaches the browser through a relay that records its traffic
	// as metadata, printed if the test fails (TXE-6223).
	cdpURL, tl := relayDevTools(t, b.cdpURL, served)
	go func() {
		err := writegate.Serve(ctx, writegate.Config{
			Token: token, CDPURL: cdpURL, Mode: mode, Policy: policy, Secrets: secrets,
			ExtensionDir: filepath.Join(b.profile, "DaguWriteGate"),
		}, func(r writegate.Ready) { readyCh <- r })
		close(served)
		done <- err
	}()
	t.Cleanup(cancel)
	// The gate bounds its own startup, waiting up to 30 seconds for the
	// browser to apply its socket rule, and reports why it failed. This
	// longer wait only guards against a hang, so the gate's own error is
	// what a slow start shows.
	select {
	case r := <-readyCh:
		return guarded{controls: fmt.Sprintf("http://127.0.0.1:%d/%s", r.Port, token), stop: cancel, done: done, timeline: tl}
	case err := <-done:
		t.Fatalf("the gate did not start: %v", err)
	case <-time.After(2 * time.Minute):
		t.Fatal("the gate did not start in time")
	}
	return guarded{stop: cancel, done: done, timeline: tl}
}

// page is a DevTools session on the browser's first page.
type page struct {
	t    *testing.T
	conn *websocket.Conn
	sid  string
	next int64
	mu   sync.Mutex
	// seen are the methods of the page's events read while waiting for a
	// reply, so a wait for an event that came first still sees it.
	seen []string
}

func openPage(t *testing.T, b *browser) *page {
	t.Helper()
	wsURL, err := browserhost.BrowserID(t.Context(), b.cdpURL)
	require.NoError(t, err)
	conn, response, err := websocket.Dial(t.Context(), wsURL, nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	require.NoError(t, err)
	conn.SetReadLimit(-1)
	t.Cleanup(func() { _ = conn.CloseNow() })
	p := &page{t: t, conn: conn}
	// The test opens a page of its own: a blank page the browser started
	// with can still be replaced while the browser starts.
	var created struct {
		TargetID string `json:"targetId"`
	}
	p.call("", "Target.createTarget", map[string]any{"url": "about:blank"}, &created)
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	p.call("", "Target.attachToTarget", map[string]any{"targetId": created.TargetID, "flatten": true}, &attached)
	p.sid = attached.SessionID
	return p
}

func (p *page) call(sid, method string, params map[string]any, result any) {
	p.t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next++
	command := map[string]any{"id": p.next, "method": method, "params": params}
	if params == nil {
		command["params"] = map[string]any{}
	}
	if sid != "" {
		command["sessionId"] = sid
	}
	data, _ := json.Marshal(command)
	ctx, cancel := context.WithTimeout(p.t.Context(), time.Minute)
	defer cancel()
	require.NoError(p.t, p.conn.Write(ctx, websocket.MessageText, data))
	for {
		_, data, err := p.conn.Read(ctx)
		require.NoError(p.t, err, method)
		var m struct {
			ID        int64           `json:"id"`
			Method    string          `json:"method"`
			SessionID string          `json:"sessionId"`
			Result    json.RawMessage `json:"result"`
			Error     *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if m.Method != "" && m.SessionID == p.sid {
			p.seen = append(p.seen, m.Method)
		}
		if m.ID != p.next {
			continue
		}
		require.Nil(p.t, m.Error, "%s: %v", method, m.Error)
		if result != nil {
			require.NoError(p.t, json.Unmarshal(m.Result, result))
		}
		return
	}
}

// eval runs an expression in the page and returns its value as text.
func (p *page) eval(expression string) string {
	p.t.Helper()
	var r struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
	}
	p.call(p.sid, "Runtime.evaluate", map[string]any{"expression": expression, "awaitPromise": true, "returnByValue": true}, &r)
	return fmt.Sprint(r.Result.Value)
}

// goTo loads url and waits until its document is ready.
func (p *page) goTo(url string) {
	p.t.Helper()
	p.call(p.sid, "Page.navigate", map[string]any{"url": url}, nil)
	require.Eventually(p.t, func() bool {
		return p.eval(`location.href === `+quote(url)+` && document.readyState === 'complete'`) == "true"
	}, 30*time.Second, 50*time.Millisecond)
}

// load runs statement, which starts a page load in the page or one of its
// frames, and returns once the load ended, whether or not a document
// loaded.
func (p *page) load(statement string) {
	p.t.Helper()
	p.awaitLoad(func() { p.eval(statement + `; 1`) })
}

// navigate asks the browser to load url in the page, as a goto does, and
// returns once the load ended, whether or not a document loaded.
func (p *page) navigate(url string) {
	p.t.Helper()
	p.awaitLoad(func() { p.call(p.sid, "Page.navigate", map[string]any{"url": url}, nil) })
}

// awaitLoad runs start, which starts a page load, and returns once the load
// ended.
func (p *page) awaitLoad(start func()) {
	p.t.Helper()
	p.call(p.sid, "Page.enable", nil, nil)
	p.mu.Lock()
	p.seen = nil
	p.mu.Unlock()
	start()
	p.await("Page.frameStoppedLoading")
}

// submit submits the form with ID form that frame, an expression such as
// window or frames.menu, shows, and returns once the load it started
// ended.
func (p *page) submit(frame, form string) {
	p.t.Helper()
	p.load(frame + `.document.getElementById(` + quote(form) + `).submit()`)
}

// await returns once the page sent an event of method.
func (p *page) await(method string) {
	p.t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithTimeout(p.t.Context(), 30*time.Second)
	defer cancel()
	for !slices.Contains(p.seen, method) {
		_, data, err := p.conn.Read(ctx)
		require.NoError(p.t, err, "waiting for %s", method)
		var m struct {
			Method    string `json:"method"`
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(data, &m) == nil && m.Method != "" && m.SessionID == p.sid {
			p.seen = append(p.seen, m.Method)
		}
	}
}

func quote(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

func events(t *testing.T, controls string) []writegate.Event {
	t.Helper()
	list, err := writegate.Events(t.Context(), controls, 0)
	require.NoError(t, err)
	return list
}

func find(list []writegate.Event, path string) (writegate.Event, bool) {
	for _, e := range list {
		if strings.Contains(e.URL, path) {
			return e, true
		}
	}
	return writegate.Event{}, false
}

func TestGateBlocksWritesItRehearses(t *testing.T) {
	t.Parallel()

	s := startSite(t)
	b := startBrowser(t)
	controls, _, _ := guard(t, b, writegate.Policy{}, nil)
	p := openPage(t, b)
	p.goTo(s.URL + "/")

	assert.Contains(t, p.eval(`post('/w/fetch', {headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'amount=1000&password=hunter2'})`), "error")
	assert.Equal(t, "ok 200", p.eval(`fetch('/w/read').then(r => 'ok ' + r.status)`))
	assert.Equal(t, "true", p.eval(`navigator.sendBeacon('/w/beacon', 'x')`))
	assert.Contains(t, p.eval(`new Promise(res => { const w = new Worker('/worker.js'); w.onmessage = e => res(e.data); })`), "error")
	p.submit("window", "form")

	assert.Empty(t, s.written(), "no write reaches the site")
	list := events(t, controls)
	fetchWrite, ok := find(list, "/w/fetch")
	require.True(t, ok, "%+v", list)
	assert.Equal(t, writegate.ClassWrite, fetchWrite.Class)
	assert.Equal(t, writegate.OutcomeBlocked, fetchWrite.Outcome)
	assert.True(t, fetchWrite.Consequential())
	assert.Equal(t, []string{"amount", "password"}, fetchWrite.Fields)
	assert.NotContains(t, fetchWrite.Body, "hunter2")
	assert.Contains(t, fetchWrite.Body, "amount=1000")
	assert.Equal(t, "POST "+s.URL+"/w/fetch? {amount,password}", fetchWrite.Signature)
	beacon, ok := find(list, "/w/beacon")
	require.True(t, ok)
	assert.Equal(t, writegate.ClassNoise, beacon.Class)
	assert.False(t, beacon.Consequential())
	worker, ok := find(list, "/w/worker")
	require.True(t, ok)
	assert.True(t, worker.Consequential())
	form, ok := find(list, "/w/form")
	require.True(t, ok)
	assert.Equal(t, "Document", form.ResourceType)
	_, read := find(list, "/w/read")
	assert.False(t, read, "a read is not an event")
}

// A form the gate holds leaves the page as the person filled it in,
// whichever frame the form loads, so the page shows what waits to be sent
// and the same form can send it once allowed.
func TestGateHoldsAFormOnItsPage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, path string
		// form is the frame the form is in, shown the frame it loads, and
		// write the path it posts to.
		form, shown, write string
	}{
		{name: "page", path: "/", form: "window", shown: "window", write: "/w/form"},
		{name: "frameset", path: "/frames", form: "frames.menu", shown: "frames.body", write: "/w/frame"},
		{name: "iframe", path: "/iframe", form: "frames.inner", shown: "frames.inner", write: "/w/form"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := startSite(t)
			b := startBrowser(t)
			controls, _, _ := guard(t, b, writegate.Policy{}, nil)
			p := openPage(t, b)
			p.goTo(s.URL + tc.path)
			// The form and the frame it loads are both filled in, and both
			// stay so.
			frames := []string{tc.form, tc.shown}
			field := func(frame string) string { return frame + `.document.querySelector('[name=title]').value` }
			for _, frame := range frames {
				p.eval(field(frame) + ` = 'filled in'; 1`)
			}
			p.submit(tc.form, "form")

			assert.Equal(t, s.URL+"/", p.eval(tc.shown+`.location.href`))
			for _, frame := range frames {
				assert.Equal(t, "filled in", p.eval(field(frame)), frame)
			}
			assert.Empty(t, s.written())
			held, ok := find(events(t, controls), tc.write)
			require.True(t, ok)
			assert.Equal(t, writegate.OutcomeBlocked, held.Outcome)
			assert.Equal(t, "Document", held.ResourceType)
		})
	}
}

// A form that reads loads its page in the frame it names, as any read does.
func TestGateLoadsAFormThatReads(t *testing.T) {
	t.Parallel()

	s := startSite(t)
	b := startBrowser(t)
	controls, _, _ := guard(t, b, writegate.Policy{}, nil)
	p := openPage(t, b)
	p.goTo(s.URL + "/frames")
	p.submit("frames.menu", "read")

	assert.Equal(t, s.URL+"/w/menu?title=next", p.eval(`frames.body.location.href`))
	_, ok := find(events(t, controls), "/w/menu")
	assert.False(t, ok, "a read is not an event")
}

// A load of an address the policy declares a write keeps the page, as a
// form does, whoever starts it: a link the page follows, with or without
// the page's address as its Referer, or the browser asked for the address,
// as a goto does.
func TestGateHoldsALoadWhoeverStartsIt(t *testing.T) {
	t.Parallel()

	s := startSite(t)
	b := startBrowser(t)
	policy := writegate.Policy{Writes: []writegate.Rule{{Host: "127.0.0.1", Path: "/w/delete"}}}
	controls, _, _ := guard(t, b, policy, nil)
	p := openPage(t, b)
	p.goTo(s.URL + "/")

	p.load(`location.href = '/w/delete'`)
	assert.Equal(t, s.URL+"/", p.eval(`location.href`))
	// A link that withholds the page's address names no Referer.
	p.load(`const a = document.createElement('a'); a.href = '/w/delete'; a.rel = 'noreferrer'; document.body.append(a); a.click()`)
	assert.Equal(t, s.URL+"/", p.eval(`location.href`))
	p.navigate(s.URL + "/w/delete")
	assert.Equal(t, s.URL+"/", p.eval(`location.href`))

	var outcomes []string
	for _, e := range events(t, controls) {
		outcomes = append(outcomes, strings.TrimPrefix(e.URL, s.URL)+" "+e.Outcome)
	}
	assert.Equal(t, []string{"/w/delete blocked", "/w/delete blocked", "/w/delete blocked"}, outcomes)
}

// A page loaded before the gate started is paused at its own target, so
// its writes are decided too.
func TestGateCoversAPageLoadedBeforeIt(t *testing.T) {
	t.Parallel()

	s := startSite(t)
	b := startBrowser(t)
	p := openPage(t, b)
	p.goTo(s.URL + "/")
	controls, _, _ := guard(t, b, writegate.Policy{}, nil)

	assert.Contains(t, p.eval(`post('/w/loaded-before')`), "error")
	assert.Equal(t, "ok 200", p.eval(`fetch('/w/read').then(r => 'ok ' + r.status)`))
	assert.Empty(t, s.written())
	list := events(t, controls)
	require.Len(t, list, 1, "%+v", list)
	assert.True(t, list[0].Consequential())
}

func TestGateSendsSignInAndWhatAPersonDoes(t *testing.T) {
	t.Parallel()

	s := startSite(t)
	b := startBrowser(t)
	policy := writegate.Policy{SignIn: []writegate.Rule{{Host: "127.0.0.1", Path: "/w/session", Secret: "PORTAL_PASSWORD"}}}
	controls, _, _ := guard(t, b, policy, map[string]string{"PORTAL_PASSWORD": "s3cret pw"})
	p := openPage(t, b)
	p.goTo(s.URL + "/")

	assert.Equal(t, "ok 200", p.eval(`post('/w/session', {body: 'user=a&password=s3cret+pw'})`))
	assert.Contains(t, p.eval(`post('/w/session', {body: 'user=a&password=guess'})`), "error", "a sign-in without the secret is a write")
	require.NoError(t, writegate.SetPerson(t.Context(), controls, true))
	assert.Equal(t, "ok 200", p.eval(`post('/w/person')`))
	require.NoError(t, writegate.SetPerson(t.Context(), controls, false))
	assert.Contains(t, p.eval(`post('/w/after')`), "error")

	assert.Equal(t, map[string]int{"/w/session": 1, "/w/person": 1}, s.written())
	var classes []string
	for _, e := range events(t, controls) {
		classes = append(classes, e.Class+" "+e.Outcome)
		assert.NotContains(t, e.Body, "s3cret")
	}
	assert.Equal(t, []string{"sign_in sent", "write blocked", "person sent", "write blocked"}, classes)
}

func TestGateRefusesSockets(t *testing.T) {
	t.Parallel()

	s := startSite(t)
	b := startBrowser(t)
	controls, _, _ := guard(t, b, writegate.Policy{}, nil)
	p := openPage(t, b)
	p.goTo(s.URL + "/")

	assert.Equal(t, "error", p.eval(`socket()`))
	assert.Zero(t, s.socket.Load(), "a page's socket is refused")

	// A service worker opens its socket past the extension's rule, so the
	// gate reports it.
	reply := p.eval(`(async () => {
  await navigator.serviceWorker.register('/sw.js');
  await navigator.serviceWorker.ready;
  if (!navigator.serviceWorker.controller) await new Promise(res => navigator.serviceWorker.addEventListener('controllerchange', res, {once: true}));
  return await new Promise(res => { navigator.serviceWorker.addEventListener('message', e => res(e.data), {once: true}); navigator.serviceWorker.controller.postMessage('go'); });
})()`)
	assert.Contains(t, reply, "error", "the service worker's write is blocked: %s", reply)
	assert.Empty(t, s.written())
	require.Eventually(t, func() bool {
		_, ok := find(events(t, controls), "/ws?from=sw")
		return ok
	}, 5*time.Second, 50*time.Millisecond)
	socket, _ := find(events(t, controls), "/ws?from=sw")
	assert.Equal(t, writegate.KindSocket, socket.Kind)
	assert.Equal(t, "service_worker", socket.Target)
}

// A service worker waits for the gate to watch it, so a socket it opens in
// its first statement is reported.
func TestGateSeesASocketAWorkerOpensAtStart(t *testing.T) {
	t.Parallel()

	s := startSite(t)
	b := startBrowser(t)
	controls, _, _ := guard(t, b, writegate.Policy{}, nil)
	p := openPage(t, b)
	p.goTo(s.URL + "/")

	p.eval(`navigator.serviceWorker.register('/sw-start.js').then(() => navigator.serviceWorker.ready).then(() => 'ready')`)
	if !assert.Eventually(t, func() bool {
		_, ok := find(events(t, controls), "/ws?from=start")
		return ok
	}, 10*time.Second, 50*time.Millisecond) {
		// The site counts the worker's socket itself, so a failure tells a
		// worker that ran unwatched from one whose socket never left it.
		arrived := s.startSocket.Load()
		verdict := "the worker ran unwatched, or the gate never got its event"
		if arrived == 0 {
			verdict = "the worker's socket did not reach the site either"
		}
		t.Fatalf("the gate recorded no socket from the worker's first statement; the site received %d: %s", arrived, verdict)
	}
	socket, _ := find(events(t, controls), "/ws?from=start")
	assert.Equal(t, writegate.KindSocket, socket.Kind)
}

func TestGateCutsLargeBodies(t *testing.T) {
	t.Parallel()

	s := startSite(t)
	b := startBrowser(t)
	controls, _, _ := guard(t, b, writegate.Policy{}, nil)
	p := openPage(t, b)
	p.goTo(s.URL + "/")

	// Its message is several times the 16 MiB a capped connection reads.
	assert.Contains(t, p.eval(`post('/w/large', {body: new Blob(['x'.repeat(20 << 20)])})`), "error")
	assert.Contains(t, p.eval(`post('/w/next')`), "error", "the gate still decides after a large body")
	assert.Empty(t, s.written())
	large, ok := find(events(t, controls), "/w/large")
	require.True(t, ok)
	assert.Equal(t, int64(20<<20), large.BodyBytes)
	assert.LessOrEqual(t, len(large.Body), 3*writegate.DefaultBodyLimit)
}

func TestGateClosesTheBrowserItLoses(t *testing.T) {
	t.Parallel()

	b := startBrowser(t)
	_, stop, done := guard(t, b, writegate.Policy{}, nil)
	stop()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("the gate did not end")
	}
	assert.ErrorIs(t, browserhost.Probe(context.Background(), b.cdpURL), browserhost.ErrUnreachable)
}

// The extension is loaded for one browser; a browser started later on the
// same profile without a gate keeps its sockets.
func TestGateExtensionLeavesTheProfileAsItWas(t *testing.T) {
	t.Parallel()

	profile := profileDir(t)
	b := startBrowserOn(t, profile)
	_, _, _ = guard(t, b, writegate.Policy{}, nil)
	require.Contains(t, extensionNames(t, b), "Dagu write gate")
	require.NoError(t, browserhost.CloseBrowser(t.Context(), b.cdpURL))
	b.waitExited(t)

	again := startBrowserOn(t, profile)
	assert.NotContains(t, extensionNames(t, again), "Dagu write gate")
}

func extensionNames(t *testing.T, b *browser) []string {
	t.Helper()
	var listed struct {
		Extensions []struct {
			Name string `json:"name"`
		} `json:"extensions"`
	}
	openPage(t, b).call("", "Extensions.getExtensions", nil, &listed)
	names := []string{}
	for _, e := range listed.Extensions {
		names = append(names, e.Name)
	}
	return names
}

// In record mode the gate sends only the writes the operation running may
// send, while it runs, and keeps each with its answer.
func TestGateRecordSendsWhatTheOperationMay(t *testing.T) {
	t.Parallel()

	s := startSite(t)
	b := startBrowser(t)
	controls, _, _ := guardIn(t, b, writegate.ModeRecord, writegate.Policy{}, nil)
	p := openPage(t, b)
	p.goTo(s.URL + "/")

	assert.Contains(t, p.eval(`post('/w/save')`), "error", "no operation runs, so nothing is sent")
	blocked, ok := find(events(t, controls), "/w/save")
	require.True(t, ok)
	require.NoError(t, writegate.Begin(t.Context(), controls, []string{blocked.Signature}, time.Minute))
	assert.Equal(t, "ok 200", p.eval(`post('/w/save')`))
	assert.Contains(t, p.eval(`post('/w/other')`), "error", "a write the operation may not send is blocked")
	require.NoError(t, writegate.End(t.Context(), controls))
	assert.Contains(t, p.eval(`post('/w/save')`), "error", "the operation ended")
	require.NoError(t, writegate.Begin(t.Context(), controls, []string{blocked.Signature}, time.Second))
	time.Sleep(1500 * time.Millisecond)
	assert.Contains(t, p.eval(`post('/w/save')`), "error", "the lease ended")

	assert.Equal(t, map[string]int{"/w/save": 1}, s.written())
	var outcomes []string
	var sent writegate.Event
	for _, e := range events(t, controls) {
		outcomes = append(outcomes, strings.TrimPrefix(e.URL, s.URL)+" "+e.Class+" "+e.Outcome)
		if e.Outcome == writegate.OutcomeSent {
			sent = e
		}
	}
	assert.Equal(t, []string{
		"/w/save write blocked", "/w/save approved sent", "/w/other write blocked", "/w/save write blocked", "/w/save write blocked",
	}, outcomes)
	assert.Equal(t, 200, sent.Status)
	assert.Equal(t, `{"ok":true}`, sent.Response)
}

// A sent write answered with a stream reaches the page as the stream
// begins, not when it ends.
func TestGateLetsAStreamedAnswerThrough(t *testing.T) {
	t.Parallel()

	s := startSite(t)
	b := startBrowser(t)
	controls, _, _ := guard(t, b, writegate.Policy{}, nil)
	p := openPage(t, b)
	p.goTo(s.URL + "/")
	require.NoError(t, writegate.SetPerson(t.Context(), controls, true))

	read := `fetch('/w/stream', {method: 'POST', body: 'x'}).then(r => r.body.getReader().read()).then(c => new TextDecoder().decode(c.value))`
	assert.Equal(t, "data: hi\n\n", p.eval(read))
	var sent writegate.Event
	require.Eventually(t, func() bool {
		var ok bool
		sent, ok = find(events(t, controls), "/w/stream")
		return ok
	}, 5*time.Second, 50*time.Millisecond)
	assert.Equal(t, writegate.OutcomeSent, sent.Outcome)
	assert.Equal(t, 200, sent.Status)
	assert.Empty(t, sent.Response)
}

// A page armed on its own target, and then on the browser target once it
// loads another document, has each write kept once.
func TestGateKeepsEachWriteOnce(t *testing.T) {
	t.Parallel()

	s := startSite(t)
	b := startBrowser(t)
	p := openPage(t, b)
	p.goTo(s.URL + "/")
	policy := writegate.Policy{SignIn: []writegate.Rule{{Host: "127.0.0.1", Path: "/w/session"}}}
	controls, _, _ := guard(t, b, policy, nil)
	p.goTo(s.URL + "/?again")

	assert.Equal(t, "ok 200", p.eval(`post('/w/session')`))
	assert.Contains(t, p.eval(`post('/w/save')`), "error")
	require.Eventually(t, func() bool { return len(events(t, controls)) >= 2 }, 5*time.Second, 50*time.Millisecond)
	time.Sleep(300 * time.Millisecond)
	list := events(t, controls)
	require.Len(t, list, 2, "%+v", list)
	assert.Equal(t, writegate.ClassSignIn, list[0].Class)
	assert.Equal(t, 200, list[0].Status)
	assert.True(t, list[1].Consequential())
}

// shortUnattended is an unattended cap a test can wait out: long enough for
// the write gate to start on a loaded host, since the gate's clock runs from
// launch.
const shortUnattended = 10 * time.Second

// The write gate's connection lasts the browser's whole life, and is marked
// a helper (TXE-6201): a browser whose only client is the write gate is
// unattended, and its gate ends it at the cap, as a parked session's is.
func TestBrowserWithOnlyItsWriteGateEndsWhenUnattended(t *testing.T) {
	t.Parallel()

	b := startBrowserFor(t, profileDir(t), shortUnattended)
	_, _, done := guard(t, b, writegate.Policy{}, nil)
	require.Eventually(t, func() bool {
		return errors.Is(browserhost.Probe(context.Background(), b.cdpURL), browserhost.ErrUnreachable)
	}, shortUnattended+30*time.Second, 200*time.Millisecond, "the gate ends a browser only its write gate attends")
	b.waitExited(t)
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the write gate did not end with its browser")
	}
}

// A browser a client attends is never ended by the unattended cap, however
// long the client stays; the clock starts when the last one leaves.
func TestAttendedBrowserOutlivesTheUnattendedCap(t *testing.T) {
	t.Parallel()

	b := startBrowserFor(t, profileDir(t), shortUnattended)
	_, _, _ = guard(t, b, writegate.Policy{}, nil)
	wsURL, err := browserhost.BrowserID(t.Context(), b.cdpURL)
	require.NoError(t, err)
	conn, response, err := websocket.Dial(t.Context(), wsURL, nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	require.NoError(t, err)

	time.Sleep(shortUnattended + 5*time.Second)
	require.NoError(t, browserhost.Probe(context.Background(), b.cdpURL), "an attended browser outlives the cap")

	_ = conn.Close(websocket.StatusNormalClosure, "")
	require.Eventually(t, func() bool {
		return errors.Is(browserhost.Probe(context.Background(), b.cdpURL), browserhost.ErrUnreachable)
	}, shortUnattended+30*time.Second, 200*time.Millisecond, "the cap runs once the last client left")
}

// ---- the DevTools timeline printed when a test fails (TXE-6223) ----
//
// A writegate test that times out on a loaded host says only that a
// condition was never met. The relay below sits between the gate and the
// browser's DevTools gate, passes every message on unchanged and in order,
// and records each one in a timeline that is printed when the test fails.
// The timeline keeps metadata only, by allowlist: the fields of
// timelineEntry. Params, results, URLs, headers, bodies and error text never
// enter it, since they carry what a page sent. Method names are written by
// the gate and Chrome, never by a page, and one not shaped like a DevTools
// method is kept as "?".

const (
	// timelineEntries bounds the messages a timeline keeps; older ones are
	// dropped first.
	timelineEntries = 1024
	// timelineSessions bounds the sessions given a pseudonym; later ones
	// share the pseudonym s0.
	timelineSessions = 4096
	// timelineMaxBytes bounds the printed timeline.
	timelineMaxBytes = 160 << 10
	// relayDrain bounds how long the relay outlives the test, so the gate
	// can still close its browser through it as it would directly.
	relayDrain = 20 * time.Second
)

// relayOffEnv set to "off" runs the gates without the relay, to measure what
// it costs.
const relayOffEnv = "DAGU_WRITEGATE_TEST_RELAY"

// timelineMethod is the shape of a DevTools method name.
var timelineMethod = regexp.MustCompile(`^[A-Z][A-Za-z]{0,31}\.[a-z][A-Za-z]{0,31}$`)

// timelineEntry is one message, as metadata.
type timelineEntry struct {
	at        time.Duration
	conn      int
	toBrowser bool
	// kind is 'c' for a command, 'r' for a reply, 'e' for an event and '?'
	// for a message that could not be read.
	kind     byte
	id       int64
	method   string
	session  int
	attached int
	errCode  int
	failed   bool
	took     time.Duration
}

type sentCommand struct {
	at      time.Duration
	method  string
	session int
}

// timeline is a bounded, metadata-only record of DevTools messages.
type timeline struct {
	start time.Time

	mu       sync.Mutex
	ring     [timelineEntries]timelineEntry
	recorded int
	conns    int
	sessions map[string]int
	sent     map[[2]int64]sentCommand
	unsent   int
}

func newTimeline() *timeline {
	return &timeline{start: time.Now(), sessions: map[string]int{}, sent: map[[2]int64]sentCommand{}}
}

// newConn numbers a relayed connection.
func (tl *timeline) newConn() int {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.conns++
	return tl.conns
}

// pseudonym returns the session's pseudonym; tl.mu is held.
func (tl *timeline) pseudonym(session string) int {
	if session == "" {
		return 0
	}
	if n, ok := tl.sessions[session]; ok {
		return n
	}
	if len(tl.sessions) >= timelineSessions {
		return 0
	}
	n := len(tl.sessions) + 1
	tl.sessions[session] = n
	return n
}

// record keeps the metadata of one message on connection conn.
func (tl *timeline) record(conn int, toBrowser bool, data []byte) {
	var m struct {
		ID        *int64          `json:"id"`
		Method    string          `json:"method"`
		SessionID string          `json:"sessionId"`
		Params    json.RawMessage `json:"params"`
		Error     *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	readable := json.Unmarshal(data, &m) == nil
	at := time.Since(tl.start)
	tl.mu.Lock()
	defer tl.mu.Unlock()
	e := timelineEntry{at: at, conn: conn, toBrowser: toBrowser, kind: '?'}
	if readable {
		e.session = tl.pseudonym(m.SessionID)
		e.method = "?"
		if timelineMethod.MatchString(m.Method) {
			e.method = m.Method
		}
		switch {
		case m.ID != nil && m.Method != "":
			e.kind, e.id = 'c', *m.ID
			key := [2]int64{int64(conn), *m.ID}
			if len(tl.sent) < timelineEntries {
				tl.sent[key] = sentCommand{at: at, method: e.method, session: e.session}
			} else {
				tl.unsent++
			}
		case m.ID != nil:
			e.kind, e.id, e.method = 'r', *m.ID, ""
			key := [2]int64{int64(conn), *m.ID}
			if sent, ok := tl.sent[key]; ok {
				e.took = at - sent.at
				e.method = sent.method
				delete(tl.sent, key)
			}
			if m.Error != nil {
				e.failed, e.errCode = true, m.Error.Code
			}
		case m.Method != "":
			e.kind = 'e'
			if m.Method == "Target.attachedToTarget" || m.Method == "Target.detachedFromTarget" {
				var p struct {
					SessionID string `json:"sessionId"`
				}
				if json.Unmarshal(m.Params, &p) == nil {
					e.attached = tl.pseudonym(p.SessionID)
				}
			}
		default:
			e.kind, e.method = '?', ""
		}
	}
	tl.ring[tl.recorded%timelineEntries] = e
	tl.recorded++
}

// render prints the timeline, oldest first, then the commands that never got
// a reply.
func (tl *timeline) render() string {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	var b strings.Builder
	kept := min(tl.recorded, timelineEntries)
	fmt.Fprintf(&b, "DevTools timeline of the write gate (metadata only): %d messages, %d dropped, %d connections\n",
		tl.recorded, tl.recorded-kept, tl.conns)
	session := func(n int) string {
		if n == 0 {
			return ""
		}
		return fmt.Sprintf(" s%d", n)
	}
	for i := tl.recorded - kept; i < tl.recorded; i++ {
		if b.Len() > timelineMaxBytes {
			fmt.Fprintf(&b, "... cut at %d bytes\n", timelineMaxBytes)
			break
		}
		e := tl.ring[i%timelineEntries]
		arrow := "<-"
		if e.toBrowser {
			arrow = "->"
		}
		fmt.Fprintf(&b, "%9.3fs c%d %s ", e.at.Seconds(), e.conn, arrow)
		switch e.kind {
		case 'c':
			fmt.Fprintf(&b, "#%d %s%s\n", e.id, e.method, session(e.session))
		case 'r':
			outcome := "ok"
			if e.failed {
				outcome = fmt.Sprintf("error %d", e.errCode)
			}
			fmt.Fprintf(&b, "#%d %s %s after %.3fs%s\n", e.id, e.method, outcome, e.took.Seconds(), session(e.session))
		case 'e':
			fmt.Fprintf(&b, "%s%s", e.method, session(e.session))
			if e.attached != 0 {
				fmt.Fprintf(&b, " names s%d", e.attached)
			}
			b.WriteString("\n")
		default:
			b.WriteString("unreadable message\n")
		}
	}
	waiting := slices.Collect(maps.Keys(tl.sent))
	slices.SortFunc(waiting, func(a, c [2]int64) int { return cmp.Compare(tl.sent[a].at, tl.sent[c].at) })
	fmt.Fprintf(&b, "waiting for a reply: %d command(s)", len(waiting))
	if tl.unsent > 0 {
		fmt.Fprintf(&b, ", %d more not tracked", tl.unsent)
	}
	b.WriteString("\n")
	for _, key := range waiting {
		if b.Len() > timelineMaxBytes {
			break
		}
		sent := tl.sent[key]
		fmt.Fprintf(&b, "  c%d #%d %s%s sent at %.3fs\n", key[0], key[1], sent.method, session(sent.session), sent.at.Seconds())
	}
	return b.String()
}

// relayDevTools starts a relay to the DevTools gate at cdpURL for the test
// and returns the address the write gate should use, with the timeline the
// relay records; the timeline is printed if the test fails. The relay closes
// once served is closed, or relayDrain after the test ends. A relay that
// cannot start leaves the gate on cdpURL itself, with no timeline.
func relayDevTools(t *testing.T, cdpURL string, served <-chan struct{}) (string, *timeline) {
	t.Helper()
	if os.Getenv(relayOffEnv) == "off" {
		return cdpURL, nil
	}
	upstream, err := url.Parse(cdpURL)
	if err != nil {
		t.Logf("no DevTools timeline: %v", err)
		return cdpURL, nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Logf("no DevTools timeline: %v", err)
		return cdpURL, nil
	}
	tl := newTimeline()
	r := &devToolsRelay{upstream: upstream, own: listener.Addr().String(), listener: listener, tl: tl, stops: map[*context.CancelFunc]struct{}{}}
	r.proxy = &httputil.ReverseProxy{
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) { r.unreachable(w, err) },
		Rewrite:      func(pr *httputil.ProxyRequest) { pr.SetURL(&url.URL{Scheme: upstream.Scheme, Host: upstream.Host}) },
		// The browser's address in the DevTools gate's answers becomes the
		// relay's, so the write gate's sockets come through the relay too.
		ModifyResponse: func(response *http.Response) error {
			data, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				return err
			}
			data = bytes.ReplaceAll(data, []byte("//"+upstream.Host+"/"), []byte("//"+r.own+"/"))
			response.Body = io.NopCloser(bytes.NewReader(data))
			response.ContentLength = int64(len(data))
			response.Header.Del("Content-Length")
			return nil
		},
	}
	server := &http.Server{Handler: r, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	// Registered first, so it runs last: printing reads only the timeline.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		defer func() {
			if p := recover(); p != nil {
				t.Logf("the DevTools timeline could not be printed: %v", p)
			}
		}()
		t.Log(tl.render())
	})
	t.Cleanup(func() {
		select {
		case <-served:
		case <-time.After(relayDrain):
		}
		_ = server.Close()
		r.stopAll()
	})
	return "http://" + r.own + upstream.Path, tl
}

// devToolsRelay passes HTTP requests and WebSockets to the DevTools gate
// unchanged. Paths and the helper handshake go through as they are, so the
// DevTools gate checks the token and counts attendance as it would.
type devToolsRelay struct {
	upstream *url.URL
	own      string
	listener net.Listener
	tl       *timeline
	proxy    *httputil.ReverseProxy

	mu    sync.Mutex
	stops map[*context.CancelFunc]struct{}
}

func (r *devToolsRelay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		r.proxy.ServeHTTP(w, req)
		return
	}
	header := http.Header{}
	if value := req.Header.Get(devtoolsgate.HelperHeader); value != "" {
		header.Set(devtoolsgate.HelperHeader, value)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The browser side first: a socket the DevTools gate refuses is refused
	// to the write gate with the same status.
	up, response, err := websocket.Dial(ctx, "ws://"+r.upstream.Host+req.URL.RequestURI(), &websocket.DialOptions{HTTPHeader: header})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		if response != nil {
			http.Error(w, http.StatusText(response.StatusCode), response.StatusCode)
			return
		}
		r.unreachable(w, err)
		return
	}
	down, err := websocket.Accept(w, req, nil)
	if err != nil {
		_ = up.CloseNow()
		return
	}
	r.mu.Lock()
	r.stops[&cancel] = struct{}{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.stops, &cancel)
		r.mu.Unlock()
	}()
	up.SetReadLimit(-1)
	down.SetReadLimit(-1)
	conn := r.tl.newConn()
	var wg sync.WaitGroup
	pump := func(from, to *websocket.Conn, toBrowser bool) {
		defer wg.Done()
		defer cancel()
		for {
			kind, data, err := from.Read(ctx)
			if err != nil {
				return
			}
			r.tl.record(conn, toBrowser, data)
			if err := to.Write(ctx, kind, data); err != nil {
				return
			}
		}
	}
	wg.Add(2)
	go pump(down, up, true)
	go pump(up, down, false)
	wg.Wait()
	_ = up.CloseNow()
	_ = down.CloseNow()
}

// unreachable fails a request the DevTools gate could not be reached for as
// it would fail without the relay: the connection is dropped without an
// answer, and once the DevTools gate refuses connections the relay stops
// listening too, so the write gate sees its browser gone as it would.
func (r *devToolsRelay) unreachable(w http.ResponseWriter, err error) {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		_ = r.listener.Close()
	}
	if hijacker, ok := w.(http.Hijacker); ok {
		if conn, _, hijackErr := hijacker.Hijack(); hijackErr == nil {
			_ = conn.Close()
			return
		}
	}
	w.WriteHeader(http.StatusBadGateway)
}

// stopAll ends the sockets still relayed.
func (r *devToolsRelay) stopAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for stop := range r.stops {
		(*stop)()
	}
}

// The timeline keeps metadata only: a canary in a command's params, a
// reply's result, an error's text, an event's params, a session id, a
// method name or a frame that is not JSON never appears in what it prints,
// and it stays bounded however much it is given.
func TestTimelineKeepsOnlyMetadata(t *testing.T) {
	t.Parallel()

	canary := "canary-" + rand.Text()
	tl := newTimeline()
	conn := tl.newConn()
	messages := []struct {
		toBrowser bool
		data      string
	}{
		{true, `{"id":1,"method":"Runtime.evaluate","sessionId":"` + canary + `","params":{"expression":"` + canary + `"}}`},
		{false, `{"id":1,"sessionId":"` + canary + `","result":{"result":{"value":"` + canary + `"}}}`},
		{true, `{"id":2,"method":"Fetch.continueRequest","params":{"requestId":"` + canary + `","url":"https://example.test/` + canary + `","headers":[{"name":"Cookie","value":"` + canary + `"}],"postData":"` + canary + `"}}`},
		{false, `{"id":2,"error":{"code":-32000,"message":"` + canary + `"}}`},
		{false, `{"method":"Target.attachedToTarget","params":{"sessionId":"` + canary + `-worker","targetInfo":{"url":"https://example.test/` + canary + `"}}}`},
		{false, `{"method":"Fetch.requestPaused","sessionId":"` + canary + `-worker","params":{"request":{"url":"https://example.test/` + canary + `","postData":"` + canary + `"}}}`},
		{true, `{"id":3,"method":"` + canary + `.evaluate","params":{}}`},
		{true, `{"id":4,"method":"Network.enable` + strings.Repeat("x", 64) + `"}`},
		{false, `not json ` + canary},
		{true, `{"id":"` + canary + `","method":"Page.navigate"}`},
	}
	for _, m := range messages {
		tl.record(conn, m.toBrowser, []byte(m.data))
	}
	printed := tl.render()
	assert.NotContains(t, printed, canary)
	for _, want := range []string{
		"-> #1 Runtime.evaluate s1", "<- #1 Runtime.evaluate ok", "-> #2 Fetch.continueRequest",
		"<- #2 Fetch.continueRequest error -32000", "Target.attachedToTarget names s2", "Fetch.requestPaused s2",
		"-> #3 ?", "-> #4 ?", "unreadable message", "waiting for a reply: 2 command(s)",
	} {
		assert.Contains(t, printed, want)
	}

	// However much it is given, it keeps the last entries and stays small.
	for i := range 20 * timelineEntries {
		tl.record(conn, true, fmt.Appendf(nil, `{"id":%d,"method":"Fetch.continueRequest","params":{"requestId":"%s"}}`, 100+i, canary))
	}
	printed = tl.render()
	assert.NotContains(t, printed, canary)
	assert.LessOrEqual(t, len(printed), timelineMaxBytes+4096)
	assert.Contains(t, printed, fmt.Sprintf("%d dropped", 20*timelineEntries+len(messages)-timelineEntries))
	assert.Contains(t, printed, "more not tracked")
}

// Through a real browser, a canary a page sends in a write's address, body
// and header reaches the gate, which records the write, and is nowhere in
// the timeline of the gate's DevTools traffic.
func TestGateTimelineKeepsNoPayload(t *testing.T) {
	t.Parallel()
	if os.Getenv(relayOffEnv) == "off" {
		t.Skip("the relay is off")
	}

	canary := "canary" + strings.ToLower(rand.Text())
	s := startSite(t)
	b := startBrowser(t)
	g := guardRecorded(t, b, writegate.ModeRehearse, writegate.Policy{}, nil)
	controls, tl := g.controls, g.timeline
	require.NotNil(t, tl, "the gate runs through the relay")
	p := openPage(t, b)
	p.goTo(s.URL + "/")

	reply := p.eval(fmt.Sprintf(`post('/w/%s?q=%s', {body: %s, headers: {'X-Canary': %s}})`, canary, canary, quote(canary), quote(canary)))
	assert.Contains(t, reply, "error", "the write is blocked: %s", reply)
	require.Eventually(t, func() bool {
		_, ok := find(events(t, controls), canary)
		return ok
	}, 5*time.Second, 50*time.Millisecond, "the canary reached the gate through the relay")

	printed := tl.render()
	assert.NotContains(t, printed, canary)
	assert.Contains(t, printed, "Fetch.requestPaused")
	assert.Contains(t, printed, "Fetch.failRequest")
}
