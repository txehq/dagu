// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createOffTheRecord opens a page off the record, as a privileged page or
// worker can, and returns its id.
func createOffTheRecord(t *testing.T, c *cdpConn) string {
	t.Helper()
	return createOffTheRecordWith(t, c, map[string]any{"url": "about:blank#otr"})
}

func createOffTheRecordWith(t *testing.T, c *cdpConn, params map[string]any) string {
	t.Helper()
	var created struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(c.mustCall("", "Fake.createOffTheRecord", params), &created))
	return created.TargetID
}

// Every target runs in the browser's own context. One made in another,
// whatever made it, is closed while the gate's auto-attach holds it: it
// never runs, and no client waiting on new targets is attached to it.
func TestMuxClosesATargetOutsideTheBrowsersOwnContext(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	c, watcher := tg.dial(""), tg.dial("")
	watcher.mustCall("", "Target.setAutoAttach", autoAttach(true))
	assert.Equal(t, "T1", decodeAttached(t, watcher.waitEvent("Target.attachedToTarget", nil)).TargetInfo.TargetID, "the first page is replayed")

	foreign := createOffTheRecord(t, c)
	watcher.noEvent("Target.attachedToTarget", 300*time.Millisecond)
	eventually(t, 5*time.Second, func() bool {
		return !slices.Contains(tg.state(c).Targets, foreign)
	}, "the target off the record is closed")
	assert.NotContains(t, tg.state(c).Resumed, foreign, "it never ran")

	// A page in the browser's own context reaches the watcher as before.
	c.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"})
	assert.True(t, decodeAttached(t, watcher.waitEvent("Target.attachedToTarget", nil)).WaitingForDebugger)
}

// A target outside the browser's own context that is still there is not
// attached to, explicitly or through a page endpoint, and no target is made
// in another context.
func TestMuxAttachesNoClientToATargetOutsideTheBrowsersOwnContext(t *testing.T) {
	t.Parallel()
	tg := startTestGateWith(t, func(_ *mux, f *fakeBrowser) { f.keepsOffTheRecord = true })
	c := tg.dial("")
	foreign := createOffTheRecord(t, c)
	eventually(t, 5*time.Second, func() bool {
		return slices.Contains(sentOf(tg.state(c), "Target.closeTarget"), `Target.closeTarget {"targetId":"`+foreign+`"}`)
	}, "the gate asked to close the target off the record")

	_, err := c.call("", "Target.attachToTarget", map[string]any{"targetId": foreign, "flatten": true})
	assert.ErrorContains(t, err, "the gate serves only targets in the browser's own context")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, response, err := websocket.Dial(ctx, tg.wsURL(foreign), nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	require.NoError(t, err)
	_, _, err = conn.Read(ctx)
	assert.Equal(t, websocket.StatusPolicyViolation, websocket.CloseStatus(err), "%v", err)

	_, err = c.call("", "Target.createTarget", map[string]any{"url": "about:blank", "browserContextId": fakeOffTheRecordContext})
	assert.ErrorContains(t, err, "Target.createTarget: the gate serves only targets in the browser's own context")
	c.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank", "browserContextId": fakeOwnContext})
	assert.Equal(t, 0, countAttachSessions(tg.state(c), foreign), "no session but the gate's is on the target")
}

// A browser that does not name its own context: the gate takes it from the
// targets that exist before any client, and enforces it all the same.
func TestMuxTakesItsOwnContextFromTheFirstTargetsWhenTheBrowserNamesNone(t *testing.T) {
	t.Parallel()
	tg := startTestGateWith(t, func(_ *mux, f *fakeBrowser) { f.unnamedContext = true })
	c, watcher := tg.dial(""), tg.dial("")
	watcher.mustCall("", "Target.setAutoAttach", autoAttach(true))
	assert.Equal(t, "T1", decodeAttached(t, watcher.waitEvent("Target.attachedToTarget", nil)).TargetInfo.TargetID, "the first page is replayed")
	foreign := createOffTheRecord(t, c)
	watcher.noEvent("Target.attachedToTarget", 300*time.Millisecond)
	eventually(t, 5*time.Second, func() bool {
		return !slices.Contains(tg.state(c).Targets, foreign)
	}, "the target off the record is closed")
}

// countAttachSessions counts the sessions on targetID that are not
// auto-attached: the ones a client asked for.
func countAttachSessions(state fakeState, targetID string) int {
	n := 0
	for _, s := range state.Sessions {
		if s.TargetID == targetID && !s.Auto {
			n++
		}
	}
	return n
}

// startMux starts a mux on a fake browser set up by setup and returns the
// fake and start's outcome, for a start that may fail.
func startMux(t *testing.T, setup func(f *fakeBrowser)) (*fakeBrowser, error) {
	t.Helper()
	pair := newPipePair(t)
	fake := newFakeBrowser(pair.browserRead, pair.browserWrite)
	setup(fake)
	go func() { _ = fake.serve() }()
	m := newMux(newPipe(pair.gateRead, pair.gateWrite))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = m.run(ctx) }()
	t.Cleanup(func() {
		cancel()
		pair.close()
	})
	startCtx, cancelStart := context.WithTimeout(ctx, 10*time.Second)
	defer cancelStart()
	_, err := readVersion(startCtx, m)
	require.NoError(t, err)
	return fake, m.start(startCtx)
}

// fakeTargetState returns, under the fake's lock, whether the target
// exists and whether it was resumed.
func fakeTargetState(f *fakeBrowser, targetID string) (exists, resumed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, exists = f.targets[targetID]
	return exists, slices.Contains(f.resumed, targetID)
}

// A target outside the browser's own context that opens as the gate starts
// is held and closed like any other, never resumed. A browser that does not
// name its own context and starts with targets in two does not start, and
// nothing it held is resumed.
func TestMuxStartResumesNoTargetOutsideTheBrowsersOwnContext(t *testing.T) {
	t.Parallel()
	fake, err := startMux(t, func(f *fakeBrowser) { f.offTheRecordAtStart = true })
	require.NoError(t, err)
	foreign := "T2"
	eventually(t, 5*time.Second, func() bool {
		exists, _ := fakeTargetState(fake, foreign)
		return !exists
	}, "the target off the record is closed")
	_, resumed := fakeTargetState(fake, foreign)
	assert.False(t, resumed)

	fake, err = startMux(t, func(f *fakeBrowser) { f.offTheRecordAtStart = true; f.unnamedContext = true })
	assert.ErrorContains(t, err, "more than one context")
	time.Sleep(200 * time.Millisecond)
	exists, resumed := fakeTargetState(fake, foreign)
	assert.True(t, exists)
	assert.False(t, resumed, "nothing held is let go")
}

// A browser that does not name its own context starts only when its first
// targets prove one: each names the same context, and the browser does not
// list that context among its others. A first target that names no context
// beside one off the record, or first targets all in a context the browser
// lists as not its default, are not taken for the browser's own, and
// nothing held is let go.
func TestMuxStartTakesNoUnprovenContextForTheBrowsersOwn(t *testing.T) {
	t.Parallel()
	for name, setup := range map[string]func(f *fakeBrowser){
		"a first target names no context": func(f *fakeBrowser) {
			f.unnamedContext, f.firstPage, f.offTheRecordAtStart = true, "unnamed", true
		},
		"the one context is listed as not the default": func(f *fakeBrowser) {
			f.unnamedContext, f.firstPage, f.offTheRecordAtStart = true, "offTheRecord", true
		},
	} {
		fake, err := startMux(t, setup)
		require.Error(t, err, name)
		time.Sleep(200 * time.Millisecond)
		_, resumed := fakeTargetState(fake, "T2")
		assert.False(t, resumed, "%s: nothing held is let go", name)
	}
	_, err := startMux(t, func(f *fakeBrowser) { f.unnamedContext = true })
	assert.NoError(t, err, "first targets that agree on a context the browser does not list start")
}

// A child in another context that the browser attaches under a session a
// client attached itself reaches no client, and its session is let go of
// on the session it was attached under, where the browser keeps it.
func TestMuxClientOwnSessionChildOutsideTheBrowsersOwnContext(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	pageClient := tg.dial("T1")
	pageClient.mustCall("", "Target.setAutoAttach", autoAttach(true))
	var created struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(pageClient.mustCall("", "Fake.createChild", map[string]any{
		"targetId": "T1", "type": "iframe", "browserContextId": fakeOffTheRecordContext,
	}), &created))
	pageClient.noEvent("Target.attachedToTarget", 300*time.Millisecond)
	eventually(t, 5*time.Second, func() bool {
		for _, s := range tg.state(pageClient).Sessions {
			if s.TargetID == created.TargetID {
				return false
			}
		}
		return true
	}, "the child's session is detached")
}

// No client hears of a target outside the browser's own context: not a
// discovering client, in the same instant as the auto-attach that holds it,
// not getTargets, not getTargetInfo. A target in the browser's own context
// is reported as before.
func TestMuxHidesATargetOutsideTheBrowsersOwnContext(t *testing.T) {
	t.Parallel()
	tg := startTestGateWith(t, func(_ *mux, f *fakeBrowser) { f.keepsOffTheRecord = true })
	c, watcher := tg.dial(""), tg.dial("")
	c.mustCall("", "Target.setDiscoverTargets", map[string]any{"discover": true})
	assert.Equal(t, "T1", targetOf(t, c.waitEvent("Target.targetCreated", nil)), "the first page is replayed")
	watcher.mustCall("", "Target.setAutoAttach", autoAttach(true))
	assert.Equal(t, "T1", decodeAttached(t, watcher.waitEvent("Target.attachedToTarget", nil)).TargetInfo.TargetID)

	foreign := createOffTheRecord(t, c)
	c.noEvents(300*time.Millisecond, "Target.targetCreated", "Target.targetInfoChanged", "Target.targetDestroyed")
	watcher.noEvent("Target.attachedToTarget", 0)
	var listed struct {
		TargetInfos []struct {
			TargetID string `json:"targetId"`
		} `json:"targetInfos"`
	}
	require.NoError(t, json.Unmarshal(c.mustCall("", "Target.getTargets", map[string]any{}), &listed))
	for _, info := range listed.TargetInfos {
		assert.NotEqual(t, foreign, info.TargetID)
	}
	assert.NotEmpty(t, listed.TargetInfos, "the browser's own targets are listed")
	// A client that knows the hidden target's id can neither act on it nor
	// tell it from a target that never existed: the gate answers exactly as
	// the browser does for an unknown id, and passes nothing on.
	for _, method := range []string{"Target.getTargetInfo", "Target.activateTarget", "Target.closeTarget"} {
		hidden := c.callReply("", method, map[string]any{"targetId": foreign})
		missing := c.callReply("", method, map[string]any{"targetId": "NO-SUCH-TARGET"})
		require.NotEmpty(t, hidden.Error, method)
		assert.JSONEq(t, string(missing.Error), string(hidden.Error), method)
		assert.JSONEq(t, `{"code":-32602,"message":"No target with given id found"}`, string(hidden.Error), method)
	}
	for _, sent := range append(sentOf(tg.state(c), "Target.activateTarget"), sentOf(tg.state(c), "Target.getTargetInfo")...) {
		assert.NotContains(t, sent, foreign, "no client command on the hidden target reaches the browser")
	}
	// The gate's HTTP discovery lists the same targets a client hears of.
	for _, path := range []string{"/json", "/json/list"} {
		status, body := get(t, tg.baseURL()+path)
		require.Equal(t, http.StatusOK, status, path)
		assert.NotContains(t, body, foreign, path)
		assert.Contains(t, body, `"T1"`, "%s lists the browser's own page", path)
	}
	exists, resumed := fakeTargetState(tg.fake, foreign)
	assert.True(t, exists, "the browser refused to close it")
	assert.False(t, resumed, "it stays held")

	own := createdTarget(t, c.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"}))
	assert.Equal(t, own, targetOf(t, c.waitEvent("Target.targetCreated", nil)))
	assert.Equal(t, own, decodeAttached(t, watcher.waitEvent("Target.attachedToTarget", nil)).TargetInfo.TargetID)
}

// A target whose info names no context is not placed in the browser's own:
// it is held, closed and reported to no client, like one in another.
func TestMuxClosesATargetThatNamesNoContext(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	c, watcher := tg.dial(""), tg.dial("")
	c.mustCall("", "Target.setDiscoverTargets", map[string]any{"discover": true})
	assert.Equal(t, "T1", targetOf(t, c.waitEvent("Target.targetCreated", nil)))
	watcher.mustCall("", "Target.setAutoAttach", autoAttach(true))
	assert.Equal(t, "T1", decodeAttached(t, watcher.waitEvent("Target.attachedToTarget", nil)).TargetInfo.TargetID)

	unplaced := createOffTheRecordWith(t, c, map[string]any{"url": "about:blank#unplaced", "noContext": true})
	watcher.noEvent("Target.attachedToTarget", 300*time.Millisecond)
	c.noEvents(0, "Target.targetCreated", "Target.targetDestroyed")
	eventually(t, 5*time.Second, func() bool {
		exists, _ := fakeTargetState(tg.fake, unplaced)
		return !exists
	}, "the target that names no context is closed")
	_, resumed := fakeTargetState(tg.fake, unplaced)
	assert.False(t, resumed)
}

func targetOf(t *testing.T, event message) string {
	t.Helper()
	var params struct {
		TargetInfo struct {
			TargetID string `json:"targetId"`
		} `json:"targetInfo"`
	}
	require.NoError(t, json.Unmarshal(event.Params, &params))
	return params.TargetInfo.TargetID
}

func createdTarget(t *testing.T, result json.RawMessage) string {
	t.Helper()
	var created struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(result, &created))
	return created.TargetID
}
