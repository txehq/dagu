// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fake browser starts these workers as Chrome starts a service worker,
// and applies a worker's commands across its sessions in the worst order
// the browser may (fakeWorker). TXE-6223.

// createWorker has the page targetID start a service worker and returns its
// id.
func createWorker(t *testing.T, c *cdpConn, targetID string) string {
	t.Helper()
	var created struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(c.mustCall("", "Fake.createWorker", map[string]any{"targetId": targetID}), &created))
	return created.TargetID
}

// workerSession waits for c's session on worker, attached under the
// session under ("" for the root).
func workerSession(t *testing.T, c *cdpConn, worker, under string) attached {
	t.Helper()
	return decodeAttached(t, c.waitEvent("Target.attachedToTarget", func(m message) bool {
		return m.SessionID == under && decodeAttached(t, m).TargetInfo.TargetID == worker
	}))
}

// waitQueued waits until the worker holds at least n commands sent on
// session.
func waitQueued(t *testing.T, tg *testGate, c *cdpConn, session string, n int) {
	t.Helper()
	eventually(t, 5*time.Second, func() bool { return tg.state(c).Queued[session] >= n }, "the commands reaching the worker")
}

// pumpUntilRunning lets the worker apply what reached it until it runs, and
// returns the fake browser's log.
func pumpUntilRunning(t *testing.T, tg *testGate, c *cdpConn, worker string) []string {
	t.Helper()
	var log []string
	eventually(t, 5*time.Second, func() bool {
		c.mustCall("", "Fake.pump", nil)
		log = tg.state(c).Log
		return slices.Contains(log, "run "+worker)
	}, "the worker's start")
	return log
}

// before reports whether first is in log ahead of then.
func before(log []string, first, then string) bool {
	i, j := slices.Index(log, first), slices.Index(log, then)
	return i >= 0 && j >= 0 && i < j
}

// A worker two clients wait for runs only once the setup each sent on its
// own session before resuming it took effect. A resume on any session of
// the worker lets it run, the other client's or the gate's own, and the
// browser keeps no order between sessions: on main the worker ran first
// and the setup came after (the write gate missed the socket the worker's
// first statement opened).
func TestMuxWorkerRunsAfterEveryWaitingClientsSetup(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	watcher, other := tg.dial(""), tg.dial("")
	watcher.mustCall("", "Target.setAutoAttach", autoAttach(true))
	other.mustCall("", "Target.setAutoAttach", autoAttach(true))

	worker := createWorker(t, other, "T1")
	watched := workerSession(t, watcher, worker, "")
	resumed := workerSession(t, other, worker, "")
	require.True(t, watched.WaitingForDebugger)

	watcher.send(watched.SessionID, "Network.enable", map[string]any{})
	watcher.send(watched.SessionID, "Runtime.runIfWaitingForDebugger", map[string]any{})
	other.send(resumed.SessionID, "Runtime.runIfWaitingForDebugger", map[string]any{})
	waitQueued(t, tg, other, watched.SessionID, 2)
	waitQueued(t, tg, other, resumed.SessionID, 1)

	log := pumpUntilRunning(t, tg, other, worker)
	assert.True(t, before(log, "Network.enable "+watched.SessionID+" on "+worker, "run "+worker),
		"the worker ran before the watcher's setup took effect: %v", log)
}

// A client auto-attached on the page that starts a worker makes the gate
// hold the worker's script fetch too, and then no session of the worker is
// answered until that hold is released. Waiting for an answer before
// releasing it waited for ever (spec079's TestSessionRehearsesEveryWrite);
// releasing it with a resume let the worker run before the other client's
// setup. The gate lets go of its page-level session instead, which releases
// the fetch and leaves the worker held at the root until every waiting
// client's setup took effect.
func TestMuxWorkerHeldBeforeItsScriptFetchStarts(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	pageClient, watcher := tg.dial(""), tg.dial("")
	pageClient.mustCall("", "Target.setAutoAttach", autoAttach(true))
	page := decodeAttached(t, pageClient.waitEvent("Target.attachedToTarget", func(m message) bool {
		return decodeAttached(t, m).TargetInfo.TargetID == "T1"
	}))
	pageClient.mustCall(page.SessionID, "Target.setAutoAttach", autoAttach(true))
	watcher.mustCall("", "Target.setAutoAttach", autoAttach(true))

	worker := createWorker(t, watcher, "T1")
	atRoot := workerSession(t, pageClient, worker, "")
	underPage := workerSession(t, pageClient, worker, page.SessionID)
	watched := workerSession(t, watcher, worker, "")
	assert.True(t, underPage.WaitingForDebugger, "the page's client sees the worker held under the page")

	watcher.send(watched.SessionID, "Network.enable", map[string]any{})
	watcher.send(watched.SessionID, "Runtime.runIfWaitingForDebugger", map[string]any{})
	pageClient.send(atRoot.SessionID, "Runtime.runIfWaitingForDebugger", map[string]any{})
	pageClient.send(underPage.SessionID, "Runtime.runIfWaitingForDebugger", map[string]any{})
	waitQueued(t, tg, watcher, watched.SessionID, 2)

	log := pumpUntilRunning(t, tg, watcher, worker)
	assert.True(t, before(log, "Network.enable "+watched.SessionID+" on "+worker, "run "+worker),
		"the worker ran before the watcher's setup took effect: %v", log)
	assert.True(t, slices.ContainsFunc(log, func(line string) bool {
		return strings.HasPrefix(line, "fetch of "+worker+" released by the detach of ")
	}), "the gate let go of its page-level session: %v", log)
	assert.False(t, slices.ContainsFunc(log, func(line string) bool {
		return strings.HasPrefix(line, "fetch of "+worker+" released by the resume on ")
	}), "no resume released the fetch: %v", log)
}

// A client that attached itself to a held worker holds nothing, and its
// resume does not let the worker run before the client the gate holds it
// for set it up. The resume is answered, as the browser answers one.
func TestMuxExplicitSessionDoesNotResumeAHeldWorker(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	watcher, other := tg.dial(""), tg.dial("")
	watcher.mustCall("", "Target.setAutoAttach", autoAttach(true))
	worker := createWorker(t, other, "T1")
	watched := workerSession(t, watcher, worker, "")

	var explicit struct {
		SessionID string `json:"sessionId"`
	}
	require.NoError(t, json.Unmarshal(other.mustCall("", "Target.attachToTarget", map[string]any{"targetId": worker, "flatten": true}), &explicit))
	other.mustCall(explicit.SessionID, "Runtime.runIfWaitingForDebugger", nil)
	other.mustCall("", "Fake.pump", nil)
	state := tg.state(other)
	assert.NotContains(t, state.Log, "run "+worker, "the explicit session's resume ran the worker")
	assert.Contains(t, state.Paused, worker)

	watcher.send(watched.SessionID, "Network.enable", map[string]any{})
	watcher.send(watched.SessionID, "Runtime.runIfWaitingForDebugger", map[string]any{})
	log := pumpUntilRunning(t, tg, other, worker)
	assert.True(t, before(log, "Network.enable "+watched.SessionID+" on "+worker, "run "+worker), "%v", log)
}

// A waiting client that goes away after resuming a worker, before the
// browser answered the barrier behind its resume, leaves nothing to wait
// for: its session and the setup on it are gone, and the barrier is never
// answered.
func TestMuxWorkerReleasedWhenAResumingClientLeaves(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	watcher, leaver := tg.dial(""), tg.dial("")
	watcher.mustCall("", "Target.setAutoAttach", autoAttach(true))
	leaver.mustCall("", "Target.setAutoAttach", autoAttach(true))
	worker := createWorker(t, watcher, "T1")
	watched := workerSession(t, watcher, worker, "")
	leaving := workerSession(t, leaver, worker, "")

	leaver.send(leaving.SessionID, "Runtime.runIfWaitingForDebugger", map[string]any{})
	waitQueued(t, tg, watcher, leaving.SessionID, 1)
	leaver.close()
	eventually(t, 5*time.Second, func() bool {
		_, queued := tg.state(watcher).Queued[leaving.SessionID]
		return !queued
	}, "the leaving client's session detached")

	watcher.send(watched.SessionID, "Network.enable", map[string]any{})
	watcher.send(watched.SessionID, "Runtime.runIfWaitingForDebugger", map[string]any{})
	log := pumpUntilRunning(t, tg, watcher, worker)
	assert.True(t, before(log, "Network.enable "+watched.SessionID+" on "+worker, "run "+worker), "%v", log)
	// The barrier the browser never answered is not kept for the browser's
	// lifetime.
	eventually(t, 5*time.Second, func() bool {
		tg.mux.mu.Lock()
		defer tg.mux.mu.Unlock()
		return len(tg.mux.pending) == 0
	}, "the unanswered barrier dropped")
}

// A client's auto-attach on a session it attached itself is the browser's,
// and so would be its hold on a worker, released by the client's resume
// alone. The gate leaves workers out of it, so the client's resume cannot
// let a worker the gate holds run before the clients it is held for set it
// up. The automated security review of this change found the gap.
func TestMuxClientAutoAttachOnItsOwnSessionHoldsNoWorker(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	pageClient, watcher := tg.dial("T1"), tg.dial("")
	pageClient.mustCall("", "Target.setAutoAttach", autoAttach(true))
	watcher.mustCall("", "Target.setAutoAttach", autoAttach(true))

	worker := createWorker(t, watcher, "T1")
	watched := workerSession(t, watcher, worker, "")
	pageClient.noEvent("Target.attachedToTarget", 300*time.Millisecond)

	watcher.send(watched.SessionID, "Network.enable", map[string]any{})
	watcher.send(watched.SessionID, "Runtime.runIfWaitingForDebugger", map[string]any{})
	log := pumpUntilRunning(t, tg, watcher, worker)
	assert.True(t, before(log, "Network.enable "+watched.SessionID+" on "+worker, "run "+worker), "%v", log)

	// Other children still reach the client as the browser gives them.
	pageClient.mustCall("", "Fake.createChild", map[string]any{"targetId": "T1", "type": "worker"})
	child := decodeAttached(t, pageClient.waitEvent("Target.attachedToTarget", nil))
	assert.Equal(t, "worker", child.TargetInfo.Type)
	assert.True(t, child.WaitingForDebugger)
}

// The Target commands the gate does not mediate are refused: each could
// change which targets are held or reach them past the gate. A client's
// Target.autoAttachRelated turns the browser connection's own auto-attach
// off, so workers would start unheld; Target.exposeDevToolsProtocol gives a
// page a DevTools connection the gate never sees; Target.sendMessageToTarget
// reaches any session by id. The gate's own auto-attach stays on.
func TestMuxRefusesTargetCommandsItDoesNotMediate(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	c := tg.dial("")
	for _, method := range []string{
		"Target.autoAttachRelated", "Target.exposeDevToolsProtocol", "Target.sendMessageToTarget",
		"Target.setRemoteLocations", "Target.openDevTools", "Target.someFutureCommand", "ServiceWorker.inspectWorker",
	} {
		_, err := c.call("", method, map[string]any{"targetId": "T1", "waitForDebuggerOnStart": false})
		assert.ErrorContains(t, err, "the gate does not pass on "+method)
	}
	_, err := c.call("", "Target.getTargets", map[string]any{})
	assert.NoError(t, err)
	_, err = c.call("", "Target.createTarget", map[string]any{"url": "about:blank"})
	assert.NoError(t, err)

	watcher := tg.dial("")
	watcher.mustCall("", "Target.setAutoAttach", autoAttach(true))
	worker := createWorker(t, c, "T1")
	assert.True(t, workerSession(t, watcher, worker, "").WaitingForDebugger, "the gate still holds new workers")
}

// The rewrite of a client's own auto-attach does not rest on how the gate
// reads the params: a repeated autoAttach, which the gate's parse and the
// browser's could read differently, reaches the browser once, and the call
// is rewritten all the same. A case variant of autoAttach, which the browser
// does not read, is a param outside the policy and refused (TXE-7856).
func TestMuxClientAutoAttachRewriteIgnoresHowTheGateParsesIt(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	pageClient, watcher := tg.dial("T1"), tg.dial("")
	_, err := pageClient.call("", "Target.setAutoAttach", map[string]any{
		"autoAttach": true, "autoattach": false, "waitForDebuggerOnStart": true, "flatten": true,
	})
	assert.ErrorContains(t, err, `the gate does not pass on Target.setAutoAttach with the param "autoattach"`)
	pageClient.mustCall("", "Target.setAutoAttach", json.RawMessage(
		`{"autoAttach":false,"autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true}`))
	watcher.mustCall("", "Target.setAutoAttach", autoAttach(true))
	createWorker(t, watcher, "T1")
	pageClient.noEvent("Target.attachedToTarget", 300*time.Millisecond)
}

// Params that are not a JSON object are refused on a client's own session,
// and the gate goes on serving: a null once crashed the rewrite of its
// filter.
func TestMuxClientAutoAttachWithParamsNotAnObjectIsRefused(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	pageClient := tg.dial("T1")
	for _, params := range []any{json.RawMessage("null"), json.RawMessage("[]"), json.RawMessage(`"x"`)} {
		_, err := pageClient.call("", "Target.setAutoAttach", params)
		assert.Error(t, err)
	}
	pageClient.mustCall("", "Target.setAutoAttach", autoAttach(true))
	tg.state(pageClient)
}
