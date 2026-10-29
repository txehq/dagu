// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TXE-3757: the outputs of a run a worker executed reach the hub. The worker is
// isolated, with its own data directories, so nothing it writes is in the hub's
// storage unless the coordinator put it there; its agent keeps no run directory.
// Before the fix the hub had no outputs.json for such a run and its outputs API
// returned an empty object. A declared step output stays step-scoped: it is not
// a run output, on a worker as on the hub.
func TestWorkerRunOutputsReachTheHub(t *testing.T) {
	f := newTestFixture(t, `
type: graph
name: worker-run-outputs
worker_selector:
  test: "true"
steps:
  - id: declared
    run: printf 'free_pct=15\n' >> "$DAGU_OUTPUT_FILE"
    outputs:
      - name: free_pct
  - id: stringform
    depends: declared
    run: echo 42
    output: FREE_PCT
`, withIsolatedWorker())
	defer f.cleanup()

	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(60 * time.Second)
	status := f.waitForStatus(ir.Succeeded, distrTestTimeout(30*time.Second))
	require.NotEmpty(t, status.WorkerID)
	require.NotEqual(t, "local", status.WorkerID, "the run must have been executed by the worker")

	attempt, err := f.coord.DAGRunRepository.FindAttempt(f.coord.Context, status.DAGRun())
	require.NoError(t, err)
	var outputs *ir.DAGRunOutputs
	require.Eventually(t, func() bool {
		outputs, err = attempt.ReadOutputs(f.coord.Context)
		return err == nil && outputs != nil
	}, distrTestTimeout(10*time.Second), 50*time.Millisecond, "the hub has no outputs for the worker's run")
	assert.Equal(t, map[string]string{"freePct": "42"}, outputs.Outputs)
	assert.Equal(t, status.Name, outputs.Metadata.DAGName)
	assert.Equal(t, status.DAGRunID, outputs.Metadata.DAGRunID)
	assert.Equal(t, status.AttemptID, outputs.Metadata.AttemptID)
	assert.Equal(t, "succeeded", outputs.Metadata.Status)

	// The worker's own storage holds no outputs file: only the hub has it.
	require.NotEmpty(t, f.workerDataDirs)
	for _, dir := range f.workerDataDirs {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			assert.False(t, strings.EqualFold(d.Name(), "outputs.json"), "the worker wrote %s", p)
			return nil
		})
		require.NoError(t, err)
	}
	// The hub's file is in its own storage, not in a directory it shares.
	hub := hubFilesContaining(t, f, `"freePct"`)
	require.NotEmpty(t, hub)
	for _, p := range hub {
		assert.True(t, strings.HasPrefix(p, f.coord.Config.Paths.DataDir), "outputs found outside the hub's data directory: %s", p)
	}
}
