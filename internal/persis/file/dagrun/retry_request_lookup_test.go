// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

// The execution that recorded a retry request is found wherever it now is:
// the run's current execution, a retained copy after a later queued retry
// replaced it, or an abandoned (hidden) preparation with its record. An
// unknown request is not found; an unreadable status fails closed.
func TestFindRetryRequest(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("lookup_dag").DAG
	run := ir.NewDAGRunRef(dag.Name, abandonRunID)
	first := createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	find := func(id string) (*persis.RetryRequestMatch, error) {
		return th.Repository.FindRetryRequest(th.Context, run, id)
	}
	rewrite := func(a *Attempt, mutate func(*ir.DAGRunStatus)) {
		st, err := a.ReadStatus(th.Context)
		require.NoError(t, err)
		mutate(st)
		require.NoError(t, a.Open(th.Context))
		require.NoError(t, a.Write(th.Context, *st))
		require.NoError(t, a.Close(th.Context))
	}

	// A conditional direct retry of the first execution, for request r1.
	r1, err := ir.NewRetryRequest(run, first.ID(), "", "act-1", "1", "d")
	require.NoError(t, err)
	created, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{DAG: dag, Timestamp: time.Now(),
		DAGRunID: abandonRunID, Retry: true, ExpectLatest: &persis.ExpectedExecution{AttemptID: first.ID(), Request: r1}})
	require.NoError(t, err)
	second := created.(*Attempt)
	match, err := find(r1.ID)
	require.NoError(t, err)
	assert.Equal(t, persis.RetryRequestAdmitted, match.State)
	assert.Equal(t, persis.ExecutionIdentity{AttemptID: second.ID()}, match.Execution)
	assert.False(t, match.Retained)
	assert.Equal(t, r1, match.Status.RetryRequest)

	// It fails; a queued retry for request r2 replaces it in the same attempt,
	// keeping a copy.
	rewrite(second, func(s *ir.DAGRunStatus) { s.Status = ir.Failed })
	failed, err := second.ReadStatus(th.Context)
	require.NoError(t, err)
	r2, err := ir.NewRetryRequest(run, second.ID(), "", "act-2", "1", "d")
	require.NoError(t, err)
	_, swapped, err := th.Repository.CompareAndSwapLatestAttemptStatus(th.Context, run, second.ID(), ir.Failed,
		func(s *ir.DAGRunStatus) error {
			s.Status, s.QueuedAt, s.RetryRequest = ir.Queued, "2026-10-12T00:00:00.000000001Z", r2
			return nil
		}, persis.DAGRunCompareAndSwapOptions{RetainBeforeSwap: true})
	require.NoError(t, err)
	require.True(t, swapped)
	match, err = find(r1.ID)
	require.NoError(t, err)
	assert.True(t, match.Retained, "the replaced execution's copy")
	assert.Equal(t, persis.ExecutionIdentity{AttemptID: second.ID(), QueuedAt: failed.QueuedAt}, match.Execution)
	match, err = find(r2.ID)
	require.NoError(t, err)
	assert.False(t, match.Retained)
	assert.Equal(t, "2026-10-12T00:00:00.000000001Z", match.Execution.QueuedAt)

	// The queued execution fails; a conditional retry for r3 creates a
	// preparation that is abandoned.
	rewrite(second, func(s *ir.DAGRunStatus) { s.Status = ir.Failed })
	r3, err := ir.NewRetryRequest(run, second.ID(), "2026-10-12T00:00:00.000000001Z", "act-3", "1", "d")
	require.NoError(t, err)
	prep, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{DAG: dag, Timestamp: time.Now(),
		DAGRunID: abandonRunID, Retry: true, TrackPreparation: true,
		ExpectLatest: &persis.ExpectedExecution{AttemptID: second.ID(), QueuedAt: "2026-10-12T00:00:00.000000001Z", Request: r3}})
	require.NoError(t, err)
	_, err = abandon(th, abandonRecord(dag, prep.ID(), nil))
	require.NoError(t, err)
	match, err = find(r3.ID)
	require.NoError(t, err)
	assert.Equal(t, persis.RetryRequestAbandoned, match.State)
	require.NotNil(t, match.Abandonment)
	assert.Equal(t, prep.ID(), match.Abandonment.AbandonedAttemptID)

	_, err = find("unknown")
	assert.ErrorIs(t, err, persis.ErrNotFound)

	// An unreadable status is an error, never "not found".
	require.NoError(t, os.WriteFile(first.file, []byte("{not json\n"), 0o600))
	_, err = find("unknown")
	assert.Error(t, err)
	assert.NotErrorIs(t, err, persis.ErrNotFound)
}
