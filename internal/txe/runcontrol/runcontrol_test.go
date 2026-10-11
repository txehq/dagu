// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package runcontrol

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/testutil"
)

// A run's latest attempt is reported as preparing while the coordinator's
// preparation journal holds it, and no longer once the preparation ends.
func TestLatestAttemptReportsAPreparation(t *testing.T) {
	ctx := t.Context()
	runs := testutil.NewFileDAGRunRepository(filepath.Join(t.TempDir(), "runs"), persis.DAGRunRepositoryOptions{})
	c := &Control{Runs: runs}
	dag := &ir.DAG{Name: "job", YamlData: []byte("steps:\n  - name: s\n    run: true\n")}

	write := func(opts persis.DAGRunCreateAttemptOptions, st ir.Status) string {
		attempt, err := runs.CreateAttempt(ctx, dag, time.Now(), "run-1", opts)
		require.NoError(t, err)
		status := ir.InitialStatus(dag)
		status.DAGRunID, status.AttemptID, status.Status = "run-1", attempt.ID(), st
		require.NoError(t, attempt.Open(ctx))
		require.NoError(t, attempt.Write(ctx, status))
		require.NoError(t, attempt.Close(ctx))
		return attempt.ID()
	}
	first := write(persis.DAGRunCreateAttemptOptions{}, ir.Failed)
	latest, err := c.LatestAttempt(ctx, "job", "run-1")
	require.NoError(t, err)
	assert.Equal(t, first, latest.AttemptID)
	assert.False(t, latest.Preparing, "an attempt that was never journaled")

	prepared := write(persis.DAGRunCreateAttemptOptions{Retry: true, TrackPreparation: true}, ir.NotStarted)
	latest, err = c.LatestAttempt(ctx, "job", "run-1")
	require.NoError(t, err)
	assert.Equal(t, prepared, latest.AttemptID)
	assert.True(t, latest.Preparing, "journaled and not yet handed to a worker")

	entries, err := runs.ListAttemptPreparations(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.NoError(t, runs.EndAttemptPreparation(ctx, entries[0]))
	latest, err = c.LatestAttempt(ctx, "job", "run-1")
	require.NoError(t, err)
	assert.Equal(t, prepared, latest.AttemptID)
	assert.False(t, latest.Preparing, "handed to a worker")
}

// preparedRun is a run whose failed execution is followed by a retry
// preparation the coordinator has journaled and not yet handed to a worker.
type preparedRun struct {
	c               *Control
	runs            *persis.DAGRunRepository
	dir             string
	first, prepared string
}

func newPreparedRun(t *testing.T) preparedRun {
	t.Helper()
	ctx := t.Context()
	dir := t.TempDir()
	runs := testutil.NewFileDAGRunRepository(filepath.Join(dir, "runs"), persis.DAGRunRepositoryOptions{})
	dag := &ir.DAG{Name: "job", YamlData: []byte("steps:\n  - name: s\n    run: true\n")}
	write := func(opts persis.DAGRunCreateAttemptOptions, st ir.Status) string {
		attempt, err := runs.CreateAttempt(ctx, dag, time.Now(), "run-1", opts)
		require.NoError(t, err)
		status := ir.InitialStatus(dag)
		status.DAGRunID, status.AttemptID, status.Status = "run-1", attempt.ID(), st
		require.NoError(t, attempt.Open(ctx))
		require.NoError(t, attempt.Write(ctx, status))
		require.NoError(t, attempt.Close(ctx))
		return attempt.ID()
	}
	first := write(persis.DAGRunCreateAttemptOptions{}, ir.Failed)
	prepared := write(persis.DAGRunCreateAttemptOptions{Retry: true, TrackPreparation: true}, ir.NotStarted)
	return preparedRun{c: &Control{Runs: runs}, runs: runs, dir: dir, first: first, prepared: prepared}
}

// The coordinator abandons the preparation between the read of the latest
// execution and the journal read: it hides the attempt, then ends the entry.
// The preparation is not reported as dispatched; the restored execution is
// read again and reported.
func TestLatestAttemptNeverReportsAnAbandonedPreparationAsDispatched(t *testing.T) {
	ctx := t.Context()
	p := newPreparedRun(t)
	c, runs, first, prepared := p.c, p.runs, p.first, p.prepared
	run := ir.NewDAGRunRef("job", "run-1")
	abandoned := false
	c.afterLatestRead = func() {
		if abandoned {
			return
		}
		abandoned = true
		expected := persis.ExecutionIdentity{AttemptID: first}
		_, err := runs.AbandonAttempt(ctx, persis.AbandonAttemptRequest{DAGRun: run, Record: persis.AttemptAbandonment{
			Schema: persis.AttemptAbandonmentSchema, Run: run, RootRun: run, AbandonedAttemptID: prepared,
			AbandonedExecution: persis.ExecutionIdentity{AttemptID: prepared}, ExpectedExecution: &expected,
			Reason: persis.AbandonedRetryPreparation, DecidedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Evidence: persis.AbandonmentEvidence{
				DispatchTask: persis.EvidenceAbsent, Lease: persis.EvidenceAbsent,
				ActiveRun: persis.EvidenceAbsent, Worker: persis.EvidenceAbsent,
				ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
			},
		}})
		require.NoError(t, err)
		require.NoError(t, runs.EndAttemptPreparation(ctx, persis.AttemptPreparation{Run: run, RootRun: run, AttemptID: prepared}))
	}

	latest, err := c.LatestAttempt(ctx, "job", "run-1")
	require.NoError(t, err)
	assert.True(t, abandoned)
	assert.Equal(t, first, latest.AttemptID, "the restored execution, read again")
	assert.False(t, latest.Preparing)
}

// A journal entry that cannot be read is an error, never evidence that the
// attempt was dispatched.
func TestLatestAttemptFailsOnAnUnreadablePreparation(t *testing.T) {
	p := newPreparedRun(t)
	entries, err := filepath.Glob(filepath.Join(p.dir, "runs.preparations", "*.json"))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.NoError(t, os.WriteFile(entries[0], []byte("{"), 0o600))

	_, err = p.c.LatestAttempt(t.Context(), "job", "run-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "preparation journal")
}

// Failure and recovery: the attempt was handed to a worker and started, but
// the coordinator failed to end its journal entry. It is reported as
// preparing (uncertain), never as never-dispatched or dispatched, until the
// entry is settled; reconciliation's settle ends it because the attempt
// started, and then it is reported as dispatched.
func TestLatestAttemptStaysUncertainUntilALeftoverEntryIsSettled(t *testing.T) {
	ctx := t.Context()
	p := newPreparedRun(t)
	run := ir.NewDAGRunRef("job", "run-1")
	attempt, err := p.runs.FindAttempt(ctx, run)
	require.NoError(t, err)
	require.Equal(t, p.prepared, attempt.ID())
	status, err := attempt.ReadStatus(ctx)
	require.NoError(t, err)
	status.Status, status.WorkerID = ir.Running, "worker-1"
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, *status))
	require.NoError(t, attempt.Close(ctx))

	latest, err := p.c.LatestAttempt(ctx, "job", "run-1")
	require.NoError(t, err)
	assert.Equal(t, p.prepared, latest.AttemptID)
	assert.True(t, latest.Preparing, "the entry was left behind: uncertain")

	ended, err := p.runs.EndSettledAttemptPreparation(ctx, persis.AttemptPreparation{Run: run, RootRun: run, AttemptID: p.prepared})
	require.NoError(t, err)
	assert.True(t, ended, "it started, so the preparation is settled")
	latest, err = p.c.LatestAttempt(ctx, "job", "run-1")
	require.NoError(t, err)
	assert.False(t, latest.Preparing)
	assert.True(t, latest.Running)
}
