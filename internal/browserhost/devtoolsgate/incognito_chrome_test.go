// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The browser the gate starts opens no window off the record, outside its
// own context, whatever asks for one: here a privileged extension worker a
// client reaches through the gate. The browser refuses it, so it never runs
// and never sends a request: neither the proxy nor the site sees one, while
// a window opened in the browser's own context right after it loads. No
// client hears of it, not one auto-attached to every target nor one
// discovering targets, and getTargets does not list it.
func TestRealChromeOpensNoWindowOffTheRecord(t *testing.T) {
	site := newTestSite(t)
	proxy := newCredentialProxy(t, site)
	handle, c := startProxiedChrome(t, proxy)
	_, body := get(t, handle.URL+"/json/version")
	var version map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &version))
	// A client auto-attached to every target and discovering every target,
	// subscribed before the window opens, so it would see it at once.
	watcher := dialWS(t, version["webSocketDebuggerUrl"], nil)
	watcher.mustCall("", "Target.setAutoAttach", map[string]any{"autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true})
	watcher.mustCall("", "Target.setDiscoverTargets", map[string]any{"discover": true})

	worker := loadWindowExtension(t, c)
	opened := evaluateAwait(t, c, worker, `chrome.windows.create({incognito: true, url: "`+site.server.URL+`/off-the-record"})
  .then(w => "opened " + JSON.stringify(w ?? null), e => "refused " + e.message)`)
	require.Equal(t, "refused Incognito mode is disabled.", opened)
	ownContext := evaluateAwait(t, c, worker, `chrome.windows.create({url: "`+site.server.URL+`/own-context"})
  .then(w => "opened " + (w ? "window" : "nothing"), e => "refused " + e.message)`)
	require.Equal(t, "opened window", ownContext)
	eventually(t, 30*time.Second, func() bool { return site.hitsOf("/own-context") > 0 }, "the window in the browser's own context loads")
	// A bounded margin for a request the browser would have sent for a
	// window off the record, asked for before the one that loaded.
	time.Sleep(2 * time.Second)

	challenged, authorized := proxy.counts("/off-the-record")
	assert.Zero(t, challenged+authorized, "the page off the record sent nothing to the proxy")
	assert.Zero(t, site.hitsOf("/off-the-record"), "nor reached the site")
	for _, id := range c.targetsOfType("page", "/off-the-record") {
		t.Errorf("getTargets lists the page off the record: %s", id)
	}
	sawOwnContext := false
	for drained := false; !drained; {
		select {
		case event := <-watcher.events:
			if strings.Contains(string(event.Params), "/off-the-record") {
				t.Errorf("a client heard of the page off the record: %s %s", event.Method, event.Params)
			}
			if strings.Contains(string(event.Params), "/own-context") {
				sawOwnContext = true
			}
		default:
			drained = true
		}
	}
	assert.True(t, sawOwnContext, "the client heard of the window in the browser's own context")
}

// loadWindowExtension loads an extension through the gate whose worker can
// open windows, and returns a client session on its worker once the
// extension API is up.
func loadWindowExtension(t *testing.T, c *cdpConn) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"),
		[]byte(`{"manifest_version": 3, "name": "dagu gate test", "version": "1.0", "background": {"service_worker": "worker.js"}}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "worker.js"), []byte("// the test drives the worker over DevTools\n"), 0o600))
	var loaded struct {
		ID string `json:"id"`
	}
	result, err := c.call("", "Extensions.loadUnpacked", map[string]any{"path": dir})
	if err != nil && strings.Contains(err.Error(), "wasn't found") {
		// Chrome's headless shell runs no extensions, so none can open a
		// window there; Dagu's browser step needs a full Chrome.
		t.Skip("this browser runs no extensions: " + err.Error())
	}
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(result, &loaded))
	var worker string
	eventually(t, 30*time.Second, func() bool {
		ids := c.targetsOfType("service_worker", "chrome-extension://"+loaded.ID+"/")
		if len(ids) == 0 {
			return false
		}
		worker = ids[0]
		return true
	}, "the extension's worker starts")
	session := c.attach(worker)
	eventually(t, 30*time.Second, func() bool {
		return c.evaluateString(session, "typeof chrome === 'object' && chrome.windows ? 'up' : 'down'", false) == "up"
	}, "the extension API is up")
	return session
}

// evaluateAwait evaluates expression on session, awaits the promise it
// returns, and returns its string value.
func evaluateAwait(t *testing.T, c *cdpConn, session, expression string) string {
	t.Helper()
	var evaluated struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(c.mustCall(session, "Runtime.evaluate", map[string]any{
		"expression": expression, "awaitPromise": true, "returnByValue": true,
	}), &evaluated))
	return evaluated.Result.Value
}
