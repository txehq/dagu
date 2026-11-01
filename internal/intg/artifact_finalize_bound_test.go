// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package intg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/runtime/agent"
	"github.com/dagucloud/dagu/v2/internal/test"
)

// selfBounded is an uploader that bounds its own finalization, as one sending
// segments does.
type selfBounded struct {
	called   bool
	deadline time.Time
	limited  bool
}

func (f *selfBounded) BoundsItsOwnFinalize() bool { return true }

func (f *selfBounded) Finalize(ctx context.Context, _, _ string) error {
	f.called = true
	f.deadline, f.limited = ctx.Deadline()
	return nil
}

func finalizeThrough(t *testing.T, yaml string, status ir.Status) *selfBounded {
	t.Helper()
	th := test.Setup(t)
	dag := th.DAG(t, yaml)
	finalizer := &selfBounded{}
	run := dag.Agent(test.WithAgentOptions(agent.Options{ArtifactDir: t.TempDir(), ArtifactFinalizer: finalizer}))
	_ = run.Run(run.Context)
	dag.AssertLatestStatus(t, status)
	require.True(t, finalizer.called)
	return finalizer
}

// A job past its timeout: the timeout lives inside the runner, so the agent's own
// context never ends, and the upload still has only the fixed time.
func TestAJobPastItsTimeoutBoundsItsFinalization(t *testing.T) {
	finalizer := finalizeThrough(t, `
timeout_sec: 1
steps:
  - name: run
    command: sleep 30
`, ir.Failed)
	require.True(t, finalizer.limited)
	assert.WithinDuration(t, time.Now().Add(3*time.Minute), finalizer.deadline, 20*time.Second)
}

// A job inside its timeout has what is left of it, if that is more.
func TestAJobInsideItsTimeoutHasWhatIsLeft(t *testing.T) {
	finalizer := finalizeThrough(t, `
timeout_sec: 3600
steps:
  - name: run
    command: "true"
`, ir.Succeeded)
	require.True(t, finalizer.limited)
	assert.WithinDuration(t, time.Now().Add(time.Hour), finalizer.deadline, 30*time.Second)
}

// A job with no timeout leaves the upload to its own bound.
func TestAJobWithNoTimeoutLeavesTheUploadToItsOwnBound(t *testing.T) {
	finalizer := finalizeThrough(t, `
steps:
  - name: run
    command: "true"
`, ir.Succeeded)
	assert.False(t, finalizer.limited)
}
