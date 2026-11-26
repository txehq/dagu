// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/queue"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// TXE-8596. When queue admission refuses a queued retry, the scheduler
// withdraws it (queue.WithdrawQueuedExecution): it journals the execution and
// removes its queue item, and asserts nothing about whether it was ever
// dispatched. This coordinator's reconciliation decides that under its own
// fence. These tests run the scheduler's withdrawal and the coordinator
// against the same real stores.

// enqueueQueued puts the run in its queue, as the queue holds a queued
// retry, and returns the queue name and the item's ID.
func (f *strandedFixture) enqueueQueued(t *testing.T) (string, string) {
	t.Helper()
	found, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	st, err := found.ReadStatus(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, st.ProcGroup)
	require.NoError(t, f.h.queueStore.Enqueue(t.Context(), st.ProcGroup, queue.QueuePriorityLow, f.ref))
	items, err := f.h.queueStore.List(t.Context(), st.ProcGroup)
	require.NoError(t, err)
	require.Len(t, items, 1)
	return st.ProcGroup, items[0].ID()
}

// withdraw is the scheduler's withdrawal of a refused queued retry.
func (f *strandedFixture) withdraw(t *testing.T, queueName, itemID, attemptID, marker string) queue.Withdrawal {
	t.Helper()
	out, err := queue.WithdrawQueuedExecution(t.Context(), f.repository, f.h.queueStore, queueName, f.ref, f.ref, attemptID, marker, itemID)
	require.NoError(t, err)
	items, err := f.h.queueStore.List(t.Context(), queueName)
	require.NoError(t, err)
	assert.Empty(t, items, "the withdrawn item is gone from its queue")
	return out
}

func (f *strandedFixture) status(t *testing.T) *ir.DAGRunStatus {
	t.Helper()
	found, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	st, err := found.ReadStatus(t.Context())
	require.NoError(t, err)
	return st
}

func (f *strandedFixture) executionRecord(t *testing.T, attemptID, marker string) *persis.AttemptAbandonment {
	t.Helper()
	record, err := f.repository.ReadExecutionAbandonment(t.Context(), f.ref, f.ref, attemptID, marker)
	require.NoError(t, err)
	return record
}

// The regression the review asked for. A queued retry was handed off: its
// task was claimed and the claim acknowledged, so a real lease and active run
// exist, and its status still reads queued (the worker has not reported). The
// queue item outlived the handoff, as after a failed deletion. Admission then
// refuses the retry and the scheduler withdraws it. Reconciliation must not
// fail the execution: it was handed to a worker. Once the worker reports, its
// entry is ended, still with no record.
func TestAWithdrawnQueuedRetryThatWasHandedOffIsNeverAbandoned(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newStrandedFixture(t, nil)
	const marker = "2026-11-26T09:00:00+08:00"
	queued := f.writeQueued(t, f.previous, marker)
	queueName, itemID := f.enqueueQueued(t)

	_, err := f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.NoError(t, err)
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: time.Minute})
	require.NoError(t, err)
	require.NotNil(t, claimed)
	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(queued),
	})
	require.NoError(t, err)
	require.True(t, resp.Accepted, resp.Error)
	_, err = f.leases.Get(t.Context(), f.attemptKey(queued))
	require.NoError(t, err, "a real lease")
	require.Equal(t, ir.Queued, f.status(t).Status, "the status still reads queued")
	require.Empty(t, f.preparationEntries(t), "the acknowledgement ended the dispatch's entry")

	// The item survived the handoff; admission refuses the retry now.
	assert.Equal(t, queue.WithdrawalJournaled, f.withdraw(t, queueName, itemID, queued, marker))
	require.Len(t, f.preparationEntries(t), 1)
	assert.Equal(t, ir.Queued, f.status(t).Status, "the withdrawal writes no status")

	for range 2 {
		f.h.reconcileAbandonedPreparations(t.Context(), later())
		assert.Nil(t, f.executionRecord(t, queued, marker), "a handed-off execution is never failed as not dispatched")
		assert.Empty(t, f.records(t))
		assert.Len(t, f.preparationEntries(t), 1, "left until it settles")
		assert.Equal(t, ir.Queued, f.status(t).Status)
	}
	_, err = f.leases.Get(t.Context(), f.attemptKey(queued))
	require.NoError(t, err, "the worker's lease is untouched")

	f.reportStatus(t, queued, ir.Running, "worker-1")
	f.h.reconcileAbandonedPreparations(t.Context(), later())
	assert.Empty(t, f.preparationEntries(t), "settled: the entry is ended")
	assert.Nil(t, f.executionRecord(t, queued, marker))
}

// A refused queued retry that was never handed off: once withdrawn, no
// queue holds it and no task, lease or active run exists, so reconciliation
// fails exactly that execution with its own record. A claim published for it
// afterwards is refused.
func TestAWithdrawnQueuedRetryNeverHandedOffIsAbandonedWithARecord(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newStrandedFixture(t, nil)
	const marker = "2026-11-26T09:10:00+08:00"
	queued := f.writeQueued(t, f.previous, marker)
	queueName, itemID := f.enqueueQueued(t)

	assert.Equal(t, queue.WithdrawalJournaled, f.withdraw(t, queueName, itemID, queued, marker))
	assert.Equal(t, queue.WithdrawalJournaled, f.withdraw(t, queueName, itemID, queued, marker), "withdrawing again changes nothing")
	require.Len(t, f.preparationEntries(t), 1)
	assert.Nil(t, f.executionRecord(t, queued, marker), "nothing is recorded before the coordinator judges it")

	f.h.reconcileAbandonedPreparations(t.Context(), later())
	record := f.executionRecord(t, queued, marker)
	require.NotNil(t, record)
	assert.Equal(t, persis.AbandonmentScopeExecution, record.Scope)
	assert.Equal(t, persis.AbandonmentMarkedFailed, record.Outcome)
	assert.Equal(t, persis.ExecutionIdentity{AttemptID: queued, QueuedAt: marker}, record.AbandonedExecution)
	assert.Equal(t, persis.EvidenceAbsent, record.Evidence.Lease)
	assert.Equal(t, "coord-a", record.CoordinatorID, "decided by the coordinator, not the scheduler")
	assert.Equal(t, abandonedPreparationDetail, record.Detail)
	assert.Equal(t, ir.Failed, f.status(t).Status)
	assert.Empty(t, f.preparationEntries(t))

	require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
		Target: strandedDAG, DAGRunID: strandedRun, AttemptID: queued, AttemptKey: f.attemptKey(queued),
		ExecutionMarker: marker, Owner: dispatch.CoordinatorEndpoint{ID: "coord-b", Host: "127.0.0.1", Port: 50056},
	}))
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: time.Minute})
	require.NoError(t, err)
	require.NotNil(t, claimed)
	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(queued),
	})
	require.NoError(t, err)
	assert.False(t, resp.Accepted, "the withdrawn execution never runs")
}

// fenceWait is how long a barrier waits to see that the other side cannot
// finish while the fence is held. Finishing within it is a failure; not
// finishing proves nothing more than the lock already does.
const fenceWait = 200 * time.Millisecond

// Abandonment first. Reconciliation has established that nothing holds the
// withdrawn execution and holds the run's write lock; at that moment a task
// for it is published elsewhere, claimed, and acknowledged. The
// acknowledgement cannot complete while the abandonment holds the lock, and
// once the record is written it is refused: no lease is recorded, so nothing
// runs after the execution was recorded as not dispatched.
func TestAnAcknowledgementDuringAWithdrawnRetrysAbandonmentIsRefused(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newStrandedFixture(t, nil)
	const marker = "2026-11-26T09:20:00+08:00"
	queued := f.writeQueued(t, f.previous, marker)
	queueName, itemID := f.enqueueQueued(t)
	f.withdraw(t, queueName, itemID, queued, marker)

	acked := make(chan *coordinatorv1.AckTaskClaimResponse, 1)
	fired := false
	abandonEvidenceCheckedHook = func(run ir.DAGRunRef, attemptID string) {
		if fired || run != f.ref || attemptID != queued {
			return
		}
		fired = true
		require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
			Target: strandedDAG, DAGRunID: strandedRun, AttemptID: queued, AttemptKey: f.attemptKey(queued),
			ExecutionMarker: marker, Owner: dispatch.CoordinatorEndpoint{ID: "coord-b", Host: "127.0.0.1", Port: 50056},
		}))
		claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: time.Minute})
		require.NoError(t, err)
		require.NotNil(t, claimed)
		go func() {
			resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
				ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(queued),
			})
			if err != nil {
				resp = &coordinatorv1.AckTaskClaimResponse{Error: err.Error()}
			}
			acked <- resp
		}()
		select {
		case <-acked:
			t.Error("the acknowledgement completed while the abandonment held the run's lock")
		case <-time.After(fenceWait):
		}
	}
	t.Cleanup(func() { abandonEvidenceCheckedHook = nil })

	f.h.reconcileAbandonedPreparations(t.Context(), later())
	require.True(t, fired)
	require.NotNil(t, f.executionRecord(t, queued, marker))
	resp := <-acked
	assert.False(t, resp.Accepted)
	assert.Equal(t, errAttemptAbandoned.Error(), resp.Error)
	_, err := f.leases.Get(t.Context(), f.attemptKey(queued))
	require.ErrorIs(t, err, dispatch.ErrDAGRunLeaseNotFound, "no later acknowledgement")
}

// Acknowledgement first. A claim of the withdrawn execution is being
// acknowledged and holds the run's write lock with its lease recorded;
// reconciliation runs at that moment. It cannot judge the execution until the
// acknowledgement is done, and then finds the lease: no record is written.
func TestAWithdrawnRetrysAbandonmentDuringAnAcknowledgementLeavesIt(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newStrandedFixture(t, nil)
	const marker = "2026-11-26T09:30:00+08:00"
	queued := f.writeQueued(t, f.previous, marker)
	queueName, itemID := f.enqueueQueued(t)
	f.withdraw(t, queueName, itemID, queued, marker)
	require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
		Target: strandedDAG, DAGRunID: strandedRun, AttemptID: queued, AttemptKey: f.attemptKey(queued),
		ExecutionMarker: marker, Owner: dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055},
	}))
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: time.Minute})
	require.NoError(t, err)
	require.NotNil(t, claimed)

	reconciled := make(chan struct{})
	fired := false
	taskClaimRecordedHook = func(run ir.DAGRunRef, attemptID string) {
		if fired || run != f.ref || attemptID != queued {
			return
		}
		fired = true
		go func() {
			f.h.reconcileAbandonedPreparations(t.Context(), later())
			close(reconciled)
		}()
		select {
		case <-reconciled:
			t.Error("reconciliation judged the execution while its acknowledgement held the run's lock")
		case <-time.After(fenceWait):
		}
	}
	t.Cleanup(func() { taskClaimRecordedHook = nil })

	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(queued),
	})
	require.NoError(t, err)
	require.True(t, fired)
	assert.True(t, resp.Accepted, resp.Error)
	<-reconciled
	assert.Nil(t, f.executionRecord(t, queued, marker), "no false abandonment")
	assert.Empty(t, f.records(t))
	_, err = f.leases.Get(t.Context(), f.attemptKey(queued))
	require.NoError(t, err)
}
