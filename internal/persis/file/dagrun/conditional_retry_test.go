// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/testutil"
)

// A conditional retry creates its attempt only while the run's latest
// execution is the expected one and has finished; otherwise nothing is
// created.
func TestCreateAttemptExpectsTheLatestExecution(t *testing.T) {
	ctx := context.Background()
	repo := testutil.NewFileDAGRunRepository(filepath.Join(t.TempDir(), "runs"), persis.DAGRunRepositoryOptions{})
	dag := &ir.DAG{Name: "job"}
	first, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	write := func(st ir.Status, queuedAt string) {
		status := ir.InitialStatus(dag)
		status.DAGRunID, status.AttemptID, status.Status, status.QueuedAt = "run-1", first.ID(), st, queuedAt
		require.NoError(t, first.Open(ctx))
		require.NoError(t, first.Write(ctx, status))
		require.NoError(t, first.Close(ctx))
	}
	retry := func(want persis.ExpectedExecution) error {
		_, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{Retry: true, ExpectLatest: &want})
		return err
	}
	latest := func() string {
		a, err := repo.FindAttempt(ctx, ir.NewDAGRunRef(dag.Name, "run-1"))
		require.NoError(t, err)
		return a.ID()
	}

	write(ir.Failed, "q1")
	assert.ErrorIs(t, retry(persis.ExpectedExecution{AttemptID: first.ID(), QueuedAt: "q0"}), persis.ErrLatestExecutionChanged, "another execution of the attempt")
	assert.ErrorIs(t, retry(persis.ExpectedExecution{AttemptID: "other", QueuedAt: "q1"}), persis.ErrLatestExecutionChanged, "another attempt")
	write(ir.Queued, "q1")
	assert.ErrorIs(t, retry(persis.ExpectedExecution{AttemptID: first.ID(), QueuedAt: "q1"}), persis.ErrLatestExecutionChanged, "not finished")
	assert.Equal(t, first.ID(), latest(), "nothing was created")

	write(ir.Failed, "q1")
	next, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{Retry: true,
		ExpectLatest: &persis.ExpectedExecution{AttemptID: first.ID(), QueuedAt: "q1"}})
	require.NoError(t, err, "the expected execution is retried")
	assert.NotEqual(t, first.ID(), next.ID())
}

// A conditional retry's attempt is the run's latest as soon as it is
// created, before its creator writes anything: a second conditional retry
// through another store on the same directory, and a queued retry of the old
// execution, both see that the expected execution was consumed.
func TestConditionalAttemptIsVisibleAtCreation(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "runs")
	repo := testutil.NewFileDAGRunRepository(dir, persis.DAGRunRepositoryOptions{})
	other := testutil.NewFileDAGRunRepository(dir, persis.DAGRunRepositoryOptions{})
	dag := &ir.DAG{Name: "job"}
	first, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	status := ir.InitialStatus(dag)
	status.DAGRunID, status.AttemptID, status.Status, status.QueuedAt = "run-1", first.ID(), ir.Failed, "q1"
	status.Nodes = []*ir.Node{{Step: ir.Step{Name: "build"}, Status: ir.NodeSucceeded}, {Step: ir.Step{Name: "publish"}, Status: ir.NodeFailed}}
	status.WorkerID, status.ClaimKey, status.Error = "worker-1", "claim-1", "publish failed"
	status.StartedAt, status.FinishedAt = "2026-10-09T12:00:00Z", "2026-10-09T12:01:00Z"
	require.NoError(t, first.Open(ctx))
	require.NoError(t, first.Write(ctx, status))
	require.NoError(t, first.Close(ctx))
	want := &persis.ExpectedExecution{AttemptID: first.ID(), QueuedAt: "q1"}

	// The first admission creates its attempt and pauses before writing.
	next, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{Retry: true, ExpectLatest: want})
	require.NoError(t, err)

	_, err = other.CreateAttempt(ctx, dag, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{Retry: true, ExpectLatest: want})
	assert.ErrorIs(t, err, persis.ErrLatestExecutionChanged, "a second conditional retry of the same execution")
	_, swapped, err := other.CompareAndSwapLatestAttemptStatus(ctx, ir.NewDAGRunRef(dag.Name, "run-1"), first.ID(), ir.Failed,
		func(s *ir.DAGRunStatus) error { s.Status = ir.Queued; return nil }, persis.DAGRunCompareAndSwapOptions{})
	require.NoError(t, err)
	assert.False(t, swapped, "a queued retry of the consumed execution")

	latest, err := other.FindAttempt(ctx, ir.NewDAGRunRef(dag.Name, "run-1"))
	require.NoError(t, err)
	assert.Equal(t, next.ID(), latest.ID())
	got, err := latest.ReadStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, ir.NotStarted, got.Status)
	// If the retry is never dispatched, the run still holds the retried
	// execution's checkpoint, so a later retry does not rerun finished steps.
	require.Len(t, got.Nodes, 2)
	assert.Equal(t, ir.NodeSucceeded, got.Nodes[0].Status)
	assert.Equal(t, ir.NodeFailed, got.Nodes[1].Status)
	assert.Equal(t, next.ID(), got.AttemptID)
	assert.Equal(t, "q1", got.QueuedAt, "a direct retry keeps the retried status's queued-at")
	assert.Empty(t, got.WorkerID, "the claim belongs to no worker yet")
	assert.Empty(t, got.ClaimKey, "nor to the retried execution's lease")
	assert.Empty(t, got.StartedAt, "it has not started")
	assert.Empty(t, got.FinishedAt)
	assert.Empty(t, got.Error, "the retried execution's error is not the claim's")
}
