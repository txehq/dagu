// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package scheduler

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// TXE-8596. The reviewer and queue dispatch, joined in queue order, against
// the real registry, run history and queue: a person approves a retry, the
// hub queues it in a global queue, the reviewer observes it queued and
// records its outcome, the review's claim ends, and only then does the queue
// dispatch it. The reviewer's registry calls are made here exactly as
// Reviewer.runJournaled makes them for a retry it saw queued: before
// TXE-8596 it recorded the retry as succeeded with the queued execution as
// the receipt, and the registry took it; dispatch then refused the retry as
// retry_not_approved, and it never ran.

// reviewerClaim is the live claim the approved retry was granted under.
func reviewerClaim(t *testing.T, f *queueFixture, j txeQueueJob) *registry.Claim {
	t.Helper()
	job, err := j.store.GetJob(f.ctx, j.job.JobID)
	require.NoError(t, err)
	require.NotNil(t, job.Claim)
	require.Equal(t, registry.ClaimLive, job.Claim.State)
	c := *job.Claim
	return &c
}

func settleRetry(t *testing.T, f *queueFixture, j txeQueueJob, approved approvedRerun, c *registry.Claim, state registry.ActionState, receipt string, outcome json.RawMessage) error {
	t.Helper()
	reviewer := registry.Actor{Kind: registry.ActorReviewer, ID: "reviewer"}
	_, err := j.store.WithJobTx(f.ctx, j.job.JobID, reviewer, func(tx *registry.JobTx) error {
		_, err := tx.SettleAction(registry.Settlement{ActionID: approved.actionID, GrantID: approved.grant.GrantID,
			ClaimID: c.ClaimID, Fence: c.Fence, State: state, Receipt: receipt, Outcome: outcome})
		return err
	})
	return err
}

func releaseClaim(t *testing.T, f *queueFixture, j txeQueueJob, c *registry.Claim) {
	t.Helper()
	reviewer := registry.Actor{Kind: registry.ActorReviewer, ID: "reviewer"}
	_, err := j.store.WithJobTx(f.ctx, j.job.JobID, reviewer, func(tx *registry.JobTx) error {
		return tx.ReleaseClaim(c.ClaimID, c.Fence)
	})
	require.NoError(t, err)
}

func admittedOutcome(t *testing.T, ref string) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(map[string]any{"detail": "queued and not yet dispatched", "admitted": true, "admitted_execution": ref})
	require.NoError(t, err)
	return out
}

// startQueued moves the queued execution to running, as dispatch to a
// worker does.
func startQueued(t *testing.T, f *queueFixture, queued *ir.DAGRunStatus) {
	t.Helper()
	_, swapped, err := f.dagRunRepository.CompareAndSwapLatestAttemptStatus(f.ctx, queued.DAGRun(), queued.AttemptID, ir.Queued,
		func(latest *ir.DAGRunStatus) error {
			latest.Status = ir.Running
			latest.WorkerID = "worker-1"
			return nil
		}, persis.DAGRunCompareAndSwapOptions{})
	require.NoError(t, err)
	require.True(t, swapped)
}

// The joined race: approve, queue, the reviewer observes the retry queued
// and records it, its claim ends, and then the queue dispatches it. The
// retry must be admitted, and be recorded as succeeded once it runs.
func TestQueueDispatch_TxeQueuedRetryObservedByTheReviewerIsStillAdmitted(t *testing.T) {
	f := newQueueFixture(t)
	j, _ := newRegistryJobWithRuns(t, f)
	approved := approveRerun(t, f, j, "run-failed")
	claim := reviewerClaim(t, f, j)
	queued := cliEnqueueRetry(t, f, j.dag, approved.failed, approved.request)
	ref := ir.ExecutionRef(queued.AttemptID, queued.QueuedAt)

	// The reviewer saw the retry queued. Before TXE-8596 it recorded it as
	// succeeded; the registry now refuses that, and the reviewer records the
	// admitted execution on the action it leaves executing.
	err := settleRetry(t, f, j, approved, claim, registry.ActionSucceeded, ref, nil)
	if err == nil {
		t.Log("the registry recorded a queued retry as succeeded before it was dispatched")
	} else {
		assert.Equal(t, registry.CodeNotReady, registry.ErrorCode(err), "a queued execution is no receipt yet")
		require.NoError(t, settleRetry(t, f, j, approved, claim, registry.ActionExecuting, "", admittedOutcome(t, ref)))
	}
	releaseClaim(t, f, j, claim)

	admitted := distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), queuedItem(t, f, j.dag), queued.AttemptID, queued, j.dag)
	if !admitted {
		attempt, err := f.dagRunRepository.FindAttempt(f.ctx, queued.DAGRun())
		require.NoError(t, err)
		status, err := attempt.ReadStatus(f.ctx)
		require.NoError(t, err)
		t.Fatalf("queue dispatch refused the approved retry the reviewer observed queued: %s", status.Error)
	}
	job, err := j.store.GetJob(f.ctx, j.job.JobID)
	require.NoError(t, err)
	assert.Equal(t, registry.ActionExecuting, job.Actions[approved.actionID].State)

	// It runs, and the next review records it as succeeded.
	startQueued(t, f, queued)
	later := acquireReviewClaim(t, f, j)
	require.NoError(t, settleRetry(t, f, j, approved, later, registry.ActionSucceeded, ref, nil))
}

func acquireReviewClaim(t *testing.T, f *queueFixture, j txeQueueJob) *registry.Claim {
	t.Helper()
	var c *registry.Claim
	reviewer := registry.Actor{Kind: registry.ActorReviewer, ID: "reviewer"}
	_, err := j.store.WithJobTx(f.ctx, j.job.JobID, reviewer, func(tx *registry.JobTx) error {
		var err error
		c, err = tx.AcquireClaim(registry.ClaimReview, registry.Reviewer{MachineID: j.machine}, time.Hour)
		return err
	})
	require.NoError(t, err)
	return c
}

// The grant ends while the retry waits: dispatch refuses it, as today, and
// withdraws it from its queue (TXE-8596). It neither marks the execution
// aborted, which would read as having run, nor records it as never
// dispatched, which only the coordinator can establish. So the retry is
// pending: the registry records it neither as succeeded nor as not applied.
// The coordinator's decision, and what follows from it, is tested in
// internal/service/coordinator (withdrawn_queued_retry_test.go).
func TestQueueDispatch_TxeRefusedQueuedRetryIsNeverASuccess(t *testing.T) {
	f := newQueueFixture(t)
	j, clock := newRegistryJobWithRuns(t, f)
	approved := approveRerun(t, f, j, "run-failed")
	claim := reviewerClaim(t, f, j)
	queued := cliEnqueueRetry(t, f, j.dag, approved.failed, approved.request)
	ref := ir.ExecutionRef(queued.AttemptID, queued.QueuedAt)
	require.NoError(t, settleRetry(t, f, j, approved, claim, registry.ActionExecuting, "", admittedOutcome(t, ref)))
	releaseClaim(t, f, j, claim)
	clock.advance(approved.grant.ExpiresAt.Sub(clock.Now()) + time.Second)

	admitted := distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), queuedItem(t, f, j.dag), queued.AttemptID, queued, j.dag)
	assertRetryWithdrawn(t, f, j, queued, admitted, registry.AdmitRetryNotApproved)

	later := acquireReviewClaim(t, f, j)
	err := settleRetry(t, f, j, approved, later, registry.ActionSucceeded, ref, nil)
	assert.Equal(t, registry.CodeNotReady, registry.ErrorCode(err), "withdrawn, journaled and still queued: no success")
	err = settleRetry(t, f, j, approved, later, registry.ActionNotApplied, "", nil)
	assert.Equal(t, registry.CodeInvalid, registry.ErrorCode(err), "and no not applied without the coordinator's record")
	job, err := j.store.GetJob(f.ctx, j.job.JobID)
	require.NoError(t, err)
	assert.Equal(t, registry.ActionUncertain, job.Actions[approved.actionID].State, "interrupted with its grant, and pending")
}

// The P1 root's review of r2 found. A queued retry was handed off earlier:
// the coordinator holds a live lease for it, and its status still reads
// queued because the worker has not reported. Its queue item outlived the
// handoff (the deletion failed, or the scheduler stopped first), and
// admission now refuses the retry. Nothing may record the execution as never
// dispatched: the scheduler cannot read the coordinator's lease, task or
// active-run stores, so it withdraws the retry and writes no record and no
// status. (r2 recorded it as abandoned here, from the queued status alone.)
func TestQueueDispatch_TxeRefusedRetryHandedOffEarlierIsNotRecordedAsNeverRun(t *testing.T) {
	f := newQueueFixture(t)
	j, clock := newRegistryJobWithRuns(t, f)
	approved := approveRerun(t, f, j, "run-failed")
	queued := cliEnqueueRetry(t, f, j.dag, approved.failed, approved.request)
	attemptKey := ir.GenerateAttemptKey(queued.Name, queued.DAGRunID, queued.Name, queued.DAGRunID, queued.AttemptID)
	leases := store.NewDAGRunLeaseStore(file.NewCollection(filepath.Join(t.TempDir(), "leases")))
	now := time.Now().UTC().UnixMilli()
	require.NoError(t, leases.Upsert(f.ctx, dispatch.DAGRunLease{
		AttemptKey: attemptKey, DAGRun: queued.DAGRun(), Root: queued.DAGRun(), AttemptID: queued.AttemptID,
		ExecutionMarker: queued.QueuedAt, WorkerID: "worker-1", ClaimedAt: now, LastHeartbeatAt: now,
	}))
	clock.advance(approved.grant.ExpiresAt.Sub(clock.Now()) + time.Second)

	admitted := distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), queuedItem(t, f, j.dag), queued.AttemptID, queued, j.dag)
	assertRetryWithdrawn(t, f, j, queued, admitted, registry.AdmitRetryNotApproved)
	_, err := leases.Get(f.ctx, attemptKey)
	require.NoError(t, err, "the coordinator's lease is untouched")
}

// assertRetryWithdrawn checks a refused queued retry that carried a retry
// request: not dispatched, its queue item gone, its status unchanged (still
// queued, no error written), the execution journaled for the coordinator to
// decide, no abandonment record, the retried execution kept, and the refusal
// noted on the job with its reason.
func assertRetryWithdrawn(t *testing.T, f *queueFixture, j txeQueueJob, queued *ir.DAGRunStatus, admitted bool, code registry.AdmitCode) {
	t.Helper()
	assert.False(t, admitted)
	items, err := f.queueStore.List(f.ctx, j.dag.ProcGroup())
	require.NoError(t, err)
	assert.Empty(t, items)
	attempt, err := f.dagRunRepository.FindAttempt(f.ctx, queued.DAGRun())
	require.NoError(t, err)
	status, err := attempt.ReadStatus(f.ctx)
	require.NoError(t, err)
	assert.Equal(t, ir.Queued, status.Status, "no status is written")
	assert.Equal(t, queued.QueuedAt, status.QueuedAt)
	assert.Empty(t, status.Error)
	prepared, err := f.dagRunRepository.AttemptPrepared(f.ctx, queued.DAGRun(), queued.DAGRun(), queued.AttemptID)
	require.NoError(t, err)
	assert.True(t, prepared, "journaled for the coordinator to decide")
	record, err := f.dagRunRepository.ReadExecutionAbandonment(f.ctx, queued.DAGRun(), queued.DAGRun(), queued.AttemptID, queued.QueuedAt)
	require.NoError(t, err)
	assert.Nil(t, record, "the scheduler never records an execution as not dispatched")
	match, err := f.dagRunRepository.FindRetryRequest(f.ctx, queued.DAGRun(), queued.RetryRequest.ID)
	require.NoError(t, err)
	assert.Equal(t, persis.RetryRequestAdmitted, match.State)
	retained, err := f.dagRunRepository.ListRetainedExecutions(f.ctx, queued.DAGRun())
	require.NoError(t, err)
	require.Len(t, retained, 1, "the retried execution is kept")
	events, err := j.store.ListEvents(f.ctx, j.job.JobID, 10)
	require.NoError(t, err)
	require.NotEmpty(t, events)
	assert.Equal(t, registry.EventRunDropped, events[0].Kind)
	assert.Equal(t, string(code), events[0].Reason)
}
