// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

// The proxy of the fake-browser tests, and the credential the gate holds
// for it.
const (
	fakeProxyOrigin = "http://127.0.0.1:41234"
	fakeProxyUser   = "dagu"
	fakeProxySecret = "proxy-secret"
)

// startTestGateWithProxy starts a test gate whose browser sends every
// request to a proxy that challenges, with the gate holding the credential,
// as run does when Config.ProxyAuth is set.
func startTestGateWithProxy(t *testing.T) *testGate {
	t.Helper()
	return startTestGateWith(t, func(m *mux, f *fakeBrowser) {
		f.mu.Lock()
		f.proxyOrigin = fakeProxyOrigin
		f.mu.Unlock()
		newProxyResponder(m, ProxyAuth{Addresses: []string{"127.0.0.1:41234"}, Username: fakeProxyUser, Password: fakeProxySecret}).install()
	})
}

// browserSessionOf reads the gate's own browser-level session id.
func (tg *testGate) browserSession() string {
	tg.mux.mu.Lock()
	defer tg.mux.mu.Unlock()
	return tg.mux.browserSession
}

// The responder's interception is on a session of the gate's own on the
// browser target, in place before the gate asks for its auto-attach, so no
// target can exist, let alone run, before it; and it is the only
// interception the gate holds: none on the targets themselves.
func TestProxyResponderInterceptsBeforeAnyTargetCanRun(t *testing.T) {
	t.Parallel()
	tg := startTestGateWithProxy(t)
	a := tg.dial("")
	state := tg.state(a)

	indexOfLog := func(prefix string) int {
		return slices.IndexFunc(state.Log, func(entry string) bool { return strings.HasPrefix(entry, prefix) })
	}
	attach, enable, autoAttach := indexOfLog("Target.attachToBrowserTarget"), indexOfLog("Fetch.enable"), indexOfLog("Target.setAutoAttach")
	require.True(t, attach >= 0 && enable >= 0 && autoAttach >= 0, "the setup and the auto-attach are all in the log: %v", state.Log)
	assert.Less(t, attach, enable, "the session comes before its interception: %v", state.Log)
	assert.Less(t, enable, autoAttach, "the interception comes before the auto-attach: %v", state.Log)
	assert.Contains(t, state.Log[enable], "auth=true", "the interception handles the proxy's challenges")

	browserSession := tg.browserSession()
	require.NotEmpty(t, browserSession)
	var browserSessions int
	for _, s := range state.Sessions {
		if s.Browser {
			browserSessions++
			assert.Equal(t, browserSession, s.ID, "the gate knows its session")
			assert.True(t, s.FetchOn && s.FetchAuth, "the gate's session intercepts and handles auth")
			continue
		}
		assert.False(t, s.FetchOn, "no target of its own is intercepted by the gate: %+v", s)
	}
	assert.Equal(t, 1, browserSessions, "one browser-level session of the gate's own")
}

// A target created with a URL starts its first request before any session
// on it exists, as the browser process does: the request is paused by the
// gate's browser-level interception alone, the proxy's challenge is answered
// with the credential, and the target then runs. No client hears of the
// request or the challenge.
func TestProxyResponderAnswersTheFirstRequestOfATargetCreatedNavigating(t *testing.T) {
	t.Parallel()
	tg := startTestGateWithProxy(t)
	a := tg.dial("")
	a.mustCall("", "Target.setAutoAttach", autoAttach(false))
	a.waitEvent("Target.attachedToTarget", nil)
	created := a.mustCall("", "Target.createTarget", map[string]any{"url": "https://site.test/first"})
	var child struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(created, &child))
	request := "nav:" + child.TargetID

	eventually(t, 5*time.Second, func() bool {
		state := tg.state(a)
		return slices.Contains(state.Completed, request) && slices.Contains(state.Resumed, child.TargetID)
	}, "the first request completes and the target resumes")
	state := tg.state(a)
	assert.Equal(t, fakeProxyUser+":"+fakeProxySecret, state.Credentials[request], "the proxy's challenge was answered with the gate's credential")
	assert.Empty(t, state.Refused, "nothing was refused")
	requested, resumed := slices.Index(state.Log, "request "+request), slices.Index(state.Log, "resume "+child.TargetID)
	assert.Less(t, requested, resumed, "the request left before the target could be held, and was answered all the same: %v", state.Log)
	a.noEvent("Fetch.requestPaused", 200*time.Millisecond)
	a.noEvent("Fetch.authRequired", 200*time.Millisecond)
}

// Through the browser, as in the unit test: a site's own challenge, or
// another proxy's, gets the browser's default handling and no credential,
// so the request fails rather than carry the credential anywhere else.
func TestProxyResponderGivesTheCredentialToNoOtherChallenge(t *testing.T) {
	t.Parallel()
	tg := startTestGateWithProxy(t)
	a := tg.dial("")
	a.mustCall("", "Fake.request", map[string]any{"targetId": "T1", "requestId": "site", "url": "https://site.test/private",
		"challenge": map[string]any{"source": "Server", "origin": "https://site.test"}})
	a.mustCall("", "Fake.request", map[string]any{"targetId": "T1", "requestId": "other", "url": "https://site.test/",
		"challenge": map[string]any{"source": "Proxy", "origin": "http://127.0.0.1:9999"}})
	a.mustCall("", "Fake.request", map[string]any{"targetId": "T1", "requestId": "own", "url": "https://site.test/"})
	eventually(t, 5*time.Second, func() bool {
		state := tg.state(a)
		return len(state.Refused) == 2 && len(state.Completed) == 1
	}, "the three requests settle")
	state := tg.state(a)
	assert.ElementsMatch(t, []string{"site", "other"}, state.Refused)
	assert.Equal(t, map[string]string{"own": fakeProxyUser + ":" + fakeProxySecret}, state.Credentials, "only the proxy's own challenge got the credential")
}

// A client's own browser-level interception, as the write gate's on the
// shared browser session, runs beside the gate's: both see each request, the
// client decides its part, the gate answers the proxy, the client never
// sees the challenge, and the client turning its interception off leaves
// the gate's in place.
func TestProxyResponderCoexistsWithAClientsBrowserLevelFetch(t *testing.T) {
	t.Parallel()
	tg := startTestGateWithProxy(t)
	b := tg.dial("")
	b.mustCall("", "Fetch.enable", map[string]any{"patterns": []map[string]any{{"urlPattern": "*", "requestStage": "Request"}}})
	result := b.mustCall("", "Fake.request", map[string]any{"targetId": "T1", "requestId": "R1", "url": "https://site.test/"})
	assert.Contains(t, string(result), `"delivered":2`, "the request paused on the client's interception and the gate's")
	paused := b.waitEvent("Fetch.requestPaused", nil)
	assert.Equal(t, "", paused.SessionID, "the client's interception is on the browser session")
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, tg.state(b).Completed, "the request waits for the client's decision")
	b.mustCall("", "Fetch.continueRequest", map[string]any{"requestId": "R1"})
	eventually(t, 5*time.Second, func() bool { return slices.Contains(tg.state(b).Completed, "R1") }, "the request completes")
	state := tg.state(b)
	assert.Equal(t, fakeProxyUser+":"+fakeProxySecret, state.Credentials["R1"], "the gate answered the proxy")
	b.noEvent("Fetch.authRequired", 200*time.Millisecond)

	b.mustCall("", "Fetch.disable", nil)
	for _, s := range tg.state(b).Sessions {
		if s.Browser {
			assert.True(t, s.FetchOn && s.FetchAuth, "the gate's interception survives the client's Fetch.disable")
		}
	}
	b.mustCall("", "Fake.request", map[string]any{"targetId": "T1", "requestId": "R2", "url": "https://site.test/2"})
	eventually(t, 5*time.Second, func() bool { return slices.Contains(tg.state(b).Completed, "R2") }, "the next request is still answered for")
}

// The gate's session is the gate's alone: a client cannot address it, turn
// its interception off or detach it, however it learned the id.
func TestProxyResponderSessionIsNotAClients(t *testing.T) {
	t.Parallel()
	tg := startTestGateWithProxy(t)
	browserSession := tg.browserSession()
	require.NotEmpty(t, browserSession)
	a := tg.dial("")
	_, err := a.call(browserSession, "Fetch.disable", nil)
	assert.ErrorContains(t, err, "Session with given id not found")
	_, err = a.call("", "Target.detachFromTarget", map[string]any{"sessionId": browserSession})
	assert.ErrorContains(t, err, "no session with the given id")
	for _, s := range tg.state(a).Sessions {
		if s.ID == browserSession {
			assert.True(t, s.FetchOn && s.FetchAuth, "the gate's interception is untouched")
		}
	}
}

// A browser that lets go of the gate's session has nothing answering for
// its requests any more: the gate closes, and the browser with it, rather
// than serve a browser whose every proxied request would fail.
func TestProxyResponderEndsWithItsSession(t *testing.T) {
	t.Parallel()
	tg := startTestGateWithProxy(t)
	a := tg.dial("")
	a.mustCall("", "Browser.getVersion", nil)
	// The browser's own doing, not a command's: the gate closes on the
	// event, so no reply could reach a client anyway.
	tg.fake.event("", "Target.detachedFromTarget", map[string]any{"sessionId": tg.browserSession(), "targetId": ""})
	select {
	case <-tg.mux.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the gate did not close after losing its session")
	}
	select {
	case <-a.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the client was not disconnected")
	}
}

// A browser that refuses the gate's browser-level interception is not
// served: the helper reports the refusal and ends the browser, and no
// address is ever handed out, so nothing runs with the proxy's challenges
// unanswered.
func TestProxyResponderFailsClosedWhenTheBrowserRefusesInterception(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	require.NoError(t, err)
	marker := filepath.Join(t.TempDir(), "exit")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	token := NewToken()
	_, err = Start(ctx, self, Config{
		Token:      token,
		Executable: self,
		Args:       fakeBrowserArgs("--refuse-browser-fetch", "--exit-marker="+marker),
		ProxyAuth:  &ProxyAuth{Addresses: []string{"127.0.0.1:41234"}, Username: fakeProxyUser, Password: fakeProxySecret},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "turn on the proxy's answer for the browser")
	assert.Contains(t, err.Error(), "Fetch.enable")
	assert.NotContains(t, err.Error(), token)
	assert.NotContains(t, err.Error(), fakeProxySecret)
	eventually(t, 15*time.Second, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}, "the browser's exit on end-of-file")
}
