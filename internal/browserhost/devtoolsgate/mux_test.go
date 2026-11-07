// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func autoAttach(wait bool) map[string]any {
	return map[string]any{"autoAttach": true, "waitForDebuggerOnStart": wait, "flatten": true}
}

// TestMuxPrivateSessionsPerClient is the case #230 needs: two clients each
// enable Fetch on the same page and each sees its own requestPaused, each
// continue is applied once, and one client's Fetch.disable leaves the other
// intercepting.
func TestMuxPrivateSessionsPerClient(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	a, b := tg.dial(""), tg.dial("")

	a.mustCall("", "Target.setAutoAttach", autoAttach(false))
	sessionA := decodeAttached(t, a.waitEvent("Target.attachedToTarget", nil)).SessionID
	b.mustCall("", "Target.setAutoAttach", autoAttach(false))
	sessionB := decodeAttached(t, b.waitEvent("Target.attachedToTarget", nil)).SessionID
	require.NotEqual(t, sessionA, sessionB, "each client has a session of its own on the target")

	a.mustCall(sessionA, "Fetch.enable", map[string]any{"patterns": []map[string]any{{"urlPattern": "*"}}})
	b.mustCall(sessionB, "Fetch.enable", map[string]any{"handleAuthRequests": true})
	state := tg.state(a)
	fetchOn := map[string]bool{}
	for _, s := range state.Sessions {
		fetchOn[s.ID] = s.FetchOn
	}
	assert.True(t, fetchOn[sessionA] && fetchOn[sessionB], "both sessions intercept: %+v", state.Sessions)

	a.mustCall("", "Fake.request", map[string]any{"targetId": "T1", "requestId": "R1", "url": "https://example.test/"})
	pausedA := a.waitEvent("Fetch.requestPaused", nil)
	pausedB := b.waitEvent("Fetch.requestPaused", nil)
	assert.Equal(t, sessionA, pausedA.SessionID)
	assert.Equal(t, sessionB, pausedB.SessionID)
	a.mustCall(sessionA, "Fetch.continueRequest", map[string]any{"requestId": "R1"})
	b.mustCall(sessionB, "Fetch.continueRequest", map[string]any{"requestId": "R1"})
	_, err := a.call(sessionA, "Fetch.continueRequest", map[string]any{"requestId": "R1"})
	assert.Error(t, err, "a request is continued once per session")

	a.mustCall(sessionA, "Fetch.disable", nil)
	result := b.mustCall("", "Fake.request", map[string]any{"targetId": "T1", "requestId": "R2", "url": "https://example.test/2"})
	assert.Contains(t, string(result), `"delivered":1`)
	b.waitEvent("Fetch.requestPaused", func(m message) bool { return m.SessionID == sessionB })
	a.noEvent("Fetch.requestPaused", 200*time.Millisecond)
	state = tg.state(a)
	assert.Equal(t, map[string]int{sessionA: 1, sessionB: 1}, state.Continues)
}

func TestMuxWaitForDebuggerGatesResume(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	waiter, other, late := tg.dial(""), tg.dial(""), tg.dial("")
	waiter.mustCall("", "Target.setAutoAttach", autoAttach(true))
	waiter.waitEvent("Target.attachedToTarget", nil)
	other.mustCall("", "Target.setAutoAttach", autoAttach(false))
	other.waitEvent("Target.attachedToTarget", nil)

	created := other.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"})
	var target struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(created, &target))

	held := decodeAttached(t, waiter.waitEvent("Target.attachedToTarget", func(m message) bool {
		return decodeAttached(t, m).TargetInfo.TargetID == target.TargetID
	}))
	assert.True(t, held.WaitingForDebugger, "the client that asked to wait sees the target held")
	free := decodeAttached(t, other.waitEvent("Target.attachedToTarget", func(m message) bool {
		return decodeAttached(t, m).TargetInfo.TargetID == target.TargetID
	}))
	assert.False(t, free.WaitingForDebugger, "a client that did not ask to wait is not told to")

	time.Sleep(100 * time.Millisecond)
	state := tg.state(other)
	assert.Contains(t, state.Paused, target.TargetID, "the target stays held while the waiting client has not resumed it")

	// A late subscriber that asks to wait joins the hold.
	late.mustCall("", "Target.setAutoAttach", autoAttach(true))
	lateHeld := decodeAttached(t, late.waitEvent("Target.attachedToTarget", func(m message) bool {
		return decodeAttached(t, m).TargetInfo.TargetID == target.TargetID
	}))
	assert.True(t, lateHeld.WaitingForDebugger)

	waiter.mustCall(held.SessionID, "Runtime.runIfWaitingForDebugger", nil)
	time.Sleep(100 * time.Millisecond)
	assert.Contains(t, tg.state(other).Paused, target.TargetID, "one of two waiting clients is not enough")
	late.mustCall(lateHeld.SessionID, "Runtime.runIfWaitingForDebugger", nil)
	eventually(t, 5*time.Second, func() bool {
		state := tg.state(other)
		for _, id := range state.Resumed {
			if id == target.TargetID {
				return true
			}
		}
		return false
	}, "the resume after every waiting client resumed")
}

func TestMuxDisconnectReleasesHoldAndSessions(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	waiter, other := tg.dial(""), tg.dial("")
	waiter.mustCall("", "Target.setAutoAttach", autoAttach(true))
	waiter.waitEvent("Target.attachedToTarget", nil)
	other.mustCall("", "Target.setAutoAttach", autoAttach(false))
	other.waitEvent("Target.attachedToTarget", nil)
	created := other.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"})
	var target struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(created, &target))
	waiter.waitEvent("Target.attachedToTarget", func(m message) bool {
		return decodeAttached(t, m).TargetInfo.TargetID == target.TargetID
	})
	otherSession := decodeAttached(t, other.waitEvent("Target.attachedToTarget", func(m message) bool {
		return decodeAttached(t, m).TargetInfo.TargetID == target.TargetID
	})).SessionID

	sessionsBefore := len(tg.state(other).Sessions)
	waiter.close()
	eventually(t, 5*time.Second, func() bool {
		state := tg.state(other)
		resumed := false
		for _, id := range state.Resumed {
			resumed = resumed || id == target.TargetID
		}
		return resumed && len(state.Sessions) < sessionsBefore
	}, "the hold released and the waiter's sessions detached")
	// The other client's session survives its peer.
	other.mustCall(otherSession, "Runtime.evaluate", map[string]any{"expression": "1"})
}

func TestMuxExplicitAttachBelongsToRequester(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	a, b := tg.dial(""), tg.dial("")
	result := a.mustCall("", "Target.attachToTarget", map[string]any{"targetId": "T1", "flatten": true})
	var attachedResult struct {
		SessionID string `json:"sessionId"`
	}
	require.NoError(t, json.Unmarshal(result, &attachedResult))
	event := decodeAttached(t, a.waitEvent("Target.attachedToTarget", nil))
	assert.Equal(t, attachedResult.SessionID, event.SessionID, "the attach event names the session the reply names")
	b.noEvent("Target.attachedToTarget", 200*time.Millisecond)

	// Events on the session reach its owner only.
	a.mustCall("", "Fake.event", map[string]any{"sessionId": attachedResult.SessionID, "method": "Page.loadEventFired", "params": map[string]any{"timestamp": 1}})
	a.waitEvent("Page.loadEventFired", nil)
	b.noEvent("Page.loadEventFired", 200*time.Millisecond)

	// Browser-level events reach everyone.
	a.mustCall("", "Fake.event", map[string]any{"method": "Browser.downloadProgress", "params": map[string]any{"state": "completed"}})
	a.waitEvent("Browser.downloadProgress", nil)
	b.waitEvent("Browser.downloadProgress", nil)

	_, err := b.call("", "Target.detachFromTarget", map[string]any{"sessionId": attachedResult.SessionID})
	assert.Error(t, err, "a client cannot detach another's session")
	a.mustCall("", "Target.detachFromTarget", map[string]any{"sessionId": attachedResult.SessionID})
	for _, s := range tg.state(a).Sessions {
		assert.True(t, s.Auto, "the explicit session is gone from the browser; only the gate's own remains: %+v", s)
	}

	_, err = a.call("", "Target.attachToTarget", map[string]any{"targetId": "T1", "flatten": false})
	assert.ErrorContains(t, err, "flatten")
	_, err = a.call("", "Target.setAutoAttach", map[string]any{"autoAttach": true, "flatten": false})
	assert.ErrorContains(t, err, "flatten")
}

func TestMuxDiscoveryAndIDs(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	a := tg.dial("")
	a.mustCall("", "Target.setDiscoverTargets", map[string]any{"discover": true})
	first := a.waitEvent("Target.targetCreated", nil)
	assert.Contains(t, string(first.Params), `"targetId":"T1"`)

	// A late discoverer is replayed what exists; ids are the client's own.
	b := tg.dial("")
	for i := 0; i < 3; i++ {
		b.mustCall("", "Browser.getVersion", nil)
	}
	b.mustCall("", "Target.setDiscoverTargets", map[string]any{"discover": true})
	replayed := b.waitEvent("Target.targetCreated", nil)
	assert.Contains(t, string(replayed.Params), `"targetId":"T1"`)

	a.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"})
	a.waitEvent("Target.targetCreated", func(m message) bool { return !contains(m.Params, `"targetId":"T1"`) })
	b.waitEvent("Target.targetCreated", func(m message) bool { return !contains(m.Params, `"targetId":"T1"`) })

	b.mustCall("", "Target.setDiscoverTargets", map[string]any{"discover": false})
	a.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"})
	a.waitEvent("Target.targetCreated", func(m message) bool { return contains(m.Params, `"targetId":"T3"`) })
	b.noEvent("Target.targetCreated", 200*time.Millisecond)

	// An unknown method's error comes back to the right client, as the
	// browser words it.
	_, err := b.call("", "Nope.nothing", nil)
	assert.ErrorContains(t, err, "wasn't found")
}

func TestMuxLateSubscriberReplay(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	a := tg.dial("")
	a.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"})
	b := tg.dial("")
	b.mustCall("", "Target.setAutoAttach", autoAttach(false))
	seen := map[string]bool{}
	for len(seen) < 2 {
		seen[decodeAttached(t, b.waitEvent("Target.attachedToTarget", nil)).TargetInfo.TargetID] = true
	}
	assert.Equal(t, map[string]bool{"T1": true, "T2": true}, seen, "existing targets are replayed to a late subscriber")

	// Turning auto-attach off detaches the client's private sessions.
	b.mustCall("", "Target.setAutoAttach", map[string]any{"autoAttach": false})
	eventually(t, 5*time.Second, func() bool {
		for _, s := range tg.state(a).Sessions {
			if !s.Auto {
				return false
			}
		}
		return true
	}, "the private sessions detached")
}

func contains(raw json.RawMessage, needle string) bool {
	return len(raw) > 0 && string(raw) != "" && indexOf(string(raw), needle) >= 0
}

func indexOf(s, needle string) int {
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
