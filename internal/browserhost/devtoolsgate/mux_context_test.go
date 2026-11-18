// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
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
	var created struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(c.mustCall("", "Fake.createOffTheRecord", map[string]any{"url": "about:blank#otr"}), &created))
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
