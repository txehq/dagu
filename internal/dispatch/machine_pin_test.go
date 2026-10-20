// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dispatch_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

// A machine worker is handed, in enforce, only tasks whose selector names its
// machine; in off and observe it is matched as before. A worker that is not
// a machine's is matched as before in every mode.
func TestSelectorAdmitsMachinePinning(t *testing.T) {
	machineA := map[string]string{"txe.machine": "mch_A", "txe.owner": "own_A", "os": "darwin", "arch": "arm64"}
	plain := map[string]string{"os": "linux", "arch": "amd64", "pool": "platform"}

	cases := []struct {
		name     string
		worker   map[string]string
		selector map[string]string
		off      bool
		enforce  bool
	}{
		{"empty selector on a machine", machineA, nil, true, false},
		{"platform label only on a machine", machineA, map[string]string{"os": "darwin"}, true, false},
		{"owner label only on a machine", machineA, map[string]string{"txe.owner": "own_A"}, true, false},
		{"own machine", machineA, map[string]string{"txe.machine": "mch_A"}, true, true},
		{"own machine and platform", machineA, map[string]string{"txe.machine": "mch_A", "os": "darwin"}, true, true},
		{"another machine", machineA, map[string]string{"txe.machine": "mch_B"}, false, false},
		{"own machine, conflicting label", machineA, map[string]string{"txe.machine": "mch_A", "os": "linux"}, false, false},
		{"empty selector on a plain worker", plain, nil, true, true},
		{"platform label on a plain worker", plain, map[string]string{"pool": "platform"}, true, true},
		{"a machine selector on a plain worker", plain, map[string]string{"txe.machine": "mch_A"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.off, dispatch.SelectorAdmits(tc.worker, tc.selector, dispatch.MachinePinningOff), "off")
			assert.Equal(t, tc.off, dispatch.SelectorAdmits(tc.worker, tc.selector, dispatch.MachinePinningObserve), "observe")
			assert.Equal(t, tc.enforce, dispatch.SelectorAdmits(tc.worker, tc.selector, dispatch.MachinePinningEnforce), "enforce")
			record := dispatch.WorkerHeartbeatRecord{WorkerID: "w", Labels: tc.worker}
			assert.Equal(t, tc.enforce, dispatch.WorkerHeartbeatAdmits(record, tc.selector, "", dispatch.MachinePinningEnforce), "heartbeat, enforce")
			assert.Equal(t, tc.off, dispatch.WorkerHeartbeatMatches(record, tc.selector, ""), "heartbeat, as before")
		})
	}
}

func TestMachineLabelIsTheMachineWorkersLabel(t *testing.T) {
	assert.Equal(t, txepkg.LabelMachine, dispatch.MachineLabel)
}

func TestMachinePinningFor(t *testing.T) {
	assert.Equal(t, dispatch.MachinePinningOff, dispatch.MachinePinningFor(""))
	assert.Equal(t, dispatch.MachinePinningOff, dispatch.MachinePinningFor(config.TXEAuthzModeOff))
	assert.Equal(t, dispatch.MachinePinningObserve, dispatch.MachinePinningFor(config.TXEAuthzModeObserve))
	assert.Equal(t, dispatch.MachinePinningEnforce, dispatch.MachinePinningFor(config.TXEAuthzModeEnforce))
}

func TestWorkerMachine(t *testing.T) {
	for id, want := range map[string]string{
		"mch_A": "mch_A", "mch_A@laptop": "mch_A", "mch_A@host@42": "mch_A",
		"worker-1": "", "local": "", "": "", "mch_": "", "mch_@x": "", "xmch_A": "",
	} {
		assert.Equal(t, want, dispatch.WorkerMachine(id), id)
	}
}
