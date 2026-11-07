// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func get(t *testing.T, rawURL string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return response.StatusCode, string(body)
}

func TestGateRefusesWithoutToken(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	host := fmt.Sprintf("http://127.0.0.1:%d", tg.gate.port())
	wrong := host + "/" + NewToken()

	var bodies []string
	for _, path := range []string{"", "/", "/json/version", "/json", "/json/list", "/devtools/browser/" + tg.gate.browserID, "/devtools/page/T1"} {
		for _, base := range []string{host, wrong} {
			status, body := get(t, base+path)
			assert.Equal(t, http.StatusNotFound, status, "%s%s", base, path)
			bodies = append(bodies, body)
		}
	}
	for _, body := range bodies[1:] {
		assert.Equal(t, bodies[0], body, "every refusal looks the same")
	}
	// A token that is a prefix or an extension of the real one is not it.
	status, _ := get(t, host+"/"+tg.token[:len(tg.token)-1]+"/json/version")
	assert.Equal(t, http.StatusNotFound, status)
	status, _ = get(t, host+"/"+tg.token+"x/json/version")
	assert.Equal(t, http.StatusNotFound, status)

	// A websocket upgrade without the token is refused too.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, response, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(host, "http")+"/devtools/browser/"+tg.gate.browserID, nil)
	require.Error(t, err)
	if response != nil {
		assert.Equal(t, http.StatusNotFound, response.StatusCode)
		_ = response.Body.Close()
	}
}

func TestGateServesVersionAndList(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)

	status, body := get(t, tg.baseURL()+"/json/version")
	require.Equal(t, http.StatusOK, status)
	var version map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &version))
	assert.Equal(t, "FakeBrowser/1.0", version["Browser"])
	assert.Equal(t, "FakeBrowser UA", version["User-Agent"])
	assert.Equal(t, "1.3", version["Protocol-Version"])
	assert.Equal(t, tg.gate.browserWSURL(), version["webSocketDebuggerUrl"])
	assert.Contains(t, version["webSocketDebuggerUrl"], "/"+tg.token+"/devtools/browser/")

	for _, path := range []string{"/json", "/json/list"} {
		status, body = get(t, tg.baseURL()+path)
		require.Equal(t, http.StatusOK, status, path)
		var entries []listEntry
		require.NoError(t, json.Unmarshal([]byte(body), &entries))
		require.Len(t, entries, 1)
		assert.Equal(t, "T1", entries[0].ID)
		assert.Equal(t, "page", entries[0].Type)
		assert.Equal(t, tg.gate.wsBase()+"/devtools/page/T1", entries[0].WebSocketDebuggerURL)
	}
	status, _ = get(t, tg.baseURL()+"/json/protocol")
	assert.Equal(t, http.StatusNotFound, status, "routes the gate does not serve are refused like a wrong token")
}

func TestGateOrigin(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, origin := range []string{"http://127.0.0.1:8080", "https://example.com", "null", "file://"} {
		header := http.Header{"Origin": {origin}}
		_, response, err := websocket.Dial(ctx, tg.gate.browserWSURL(), &websocket.DialOptions{HTTPHeader: header})
		require.Error(t, err, origin)
		if response != nil {
			assert.Equal(t, http.StatusForbidden, response.StatusCode, origin)
			_ = response.Body.Close()
		}
	}
	// The browser's own extension connects with its Origin; libraries send
	// none.
	ext := dialWS(t, tg.gate.browserWSURL(), http.Header{"Origin": {"chrome-extension://abcdefghijklmnop"}})
	ext.mustCall("", "Browser.getVersion", nil)
	plain := tg.dial("")
	plain.mustCall("", "Browser.getVersion", nil)
}

func TestGatePageEndpoint(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	page := tg.dial("T1")
	// Commands without a session go to the page; the reply comes back
	// without one.
	result := page.mustCall("", "Runtime.evaluate", map[string]any{"expression": "1"})
	assert.Contains(t, string(result), `"value":1`)
	browser := tg.dial("")
	state := tg.state(browser)
	var pageSessions int
	for _, s := range state.Sessions {
		if s.TargetID == "T1" && !s.Auto {
			pageSessions++
		}
	}
	assert.Equal(t, 1, pageSessions, "the page client holds one explicit session on its target")

	// A page that does not exist refuses the client.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, response, err := websocket.Dial(ctx, tg.wsURL("nope"), nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	require.NoError(t, err)
	_, _, err = conn.Read(ctx)
	require.Error(t, err)
	var closeErr websocket.CloseError
	if assert.ErrorAs(t, err, &closeErr) {
		assert.Equal(t, websocket.StatusPolicyViolation, closeErr.Code)
	}
}

// A browser that agreed to close is not served any more, as Chrome stops
// answering on a port as soon as it starts to exit, though it can take
// seconds more to finish writing its profile: a client that closed the
// browser sees it gone at once, and nothing reaches it meanwhile.
func TestGateStopsServingABrowserThatIsClosing(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	tg.fake.mu.Lock()
	tg.fake.exitsSlowly = true
	tg.fake.mu.Unlock()
	tg.mux.mu.Lock()
	tg.mux.onBrowserClosing = tg.gate.stopServing
	tg.mux.mu.Unlock()

	status, _ := get(t, tg.baseURL()+"/json/version")
	require.Equal(t, http.StatusOK, status)
	a := tg.dial("")
	a.mustCall("", "Browser.close", map[string]any{})
	eventually(t, 5*time.Second, func() bool {
		response, err := http.Get(tg.baseURL() + "/json/version") //nolint:noctx // a test probe
		if err == nil {
			_ = response.Body.Close()
		}
		return err != nil
	}, "the gate refuses connections once the browser is closing")
}
