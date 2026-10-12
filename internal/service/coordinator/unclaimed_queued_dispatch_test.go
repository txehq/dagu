// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/proto/convert"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// writeQueued writes a Queued status with queuedAt, as the queue leaves a
// queued run, to a new attempt or, with attemptID, re-queues that attempt.
func (f *strandedFixture) writeQueued(t *testing.T, attemptID, queuedAt string) string {
	t.Helper()
	dag := &ir.DAG{Name: strandedDAG}
	var found dagrun.Attempt
	if attemptID == "" {
		created, err := f.repository.CreateAttempt(t.Context(), dag, time.Now(), strandedRun, persis.DAGRunCreateAttemptOptions{Retry: true})
		require.NoError(t, err)
		found, attemptID = created, created.ID()
	} else {
		latest, err := f.repository.FindAttempt(t.Context(), f.ref)
		require.NoError(t, err)
		require.Equal(t, attemptID, latest.ID())
		found = latest
	}
	require.NoError(t, found.Open(t.Context()))
	status := ir.InitialStatus(dag)
	status.DAGRunID = strandedRun
	status.AttemptID = attemptID
	status.AttemptKey = f.attemptKey(attemptID)
	status.Status = ir.Queued
	status.QueuedAt = queuedAt
	require.NoError(t, found.Write(t.Context(), status))
	require.NoError(t, found.Close(t.Context()))
	return attemptID
}

// queuedDispatch is the queue's dispatch of the run's queued execution.
func (f *strandedFixture) queuedDispatch(t *testing.T) *coordinatorv1.DispatchRequest {
	t.Helper()
	found, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	st, err := found.ReadStatus(t.Context())
	require.NoError(t, err)
	require.Equal(t, ir.Queued, st.Status)
	previous, err := convert.DAGRunStatusToProto(st)
	require.NoError(t, err)
	req := retryTask()
	req.Task.PreviousStatus = previous
	return req
}

func (f *strandedFixture) preparationEntries(t *testing.T) []persis.AttemptPreparation {
	t.Helper()
	entries, err := f.repository.ListAttemptPreparations(t.Context())
	require.NoError(t, err)
	return entries
}

// A queued run is dispatched from its queued attempt while no worker can claim
// it, and its queue item is gone. Its task expires, and the execution, journaled
// by its queued-at marker, is failed with a record of its own instead of
// staying queued with nothing left to run it. A late claim of it is refused.
func TestReconcileFailsAnUnclaimedQueuedExecution(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newShortReservationFixture(t)
	const marker = "2026-10-12T15:03:44+08:00"
	queued := f.writeQueued(t, "", marker)

	_, err := f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.NoError(t, err)
	entries := f.preparationEntries(t)
	require.Len(t, entries, 1)
	assert.Equal(t, queued, entries[0].AttemptID)
	assert.Equal(t, marker, entries[0].QueuedAt, "the execution is journaled by its marker")
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: shortReservation})
	require.NoError(t, err)
	require.NotNil(t, claimed)

	time.Sleep(3 * shortReservation)
	_, err = f.dispatches.HasOutstandingAttempt(t.Context(), f.attemptKey(queued), 0)
	require.NoError(t, err)
	time.Sleep(3 * shortReservation)
	f.h.reconcileAbandonedPreparations(t.Context(), later())

	assert.Empty(t, f.preparationEntries(t))
	assert.Equal(t, queued, f.latest(t), "the attempt stays; only its execution failed")
	found, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	st, err := found.ReadStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, ir.Failed, st.Status)
	record, err := f.repository.ReadExecutionAbandonment(t.Context(), f.ref, f.ref, queued, marker)
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, persis.AbandonmentScopeExecution, record.Scope)
	assert.Equal(t, persis.AbandonmentMarkedFailed, record.Outcome)
	assert.Equal(t, persis.ExecutionIdentity{AttemptID: queued, QueuedAt: marker}, record.AbandonedExecution)
	assert.Equal(t, abandonedPreparationDetail, record.Detail)

	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(queued),
	})
	require.NoError(t, err)
	assert.False(t, resp.Accepted, "the failed execution never runs")
}

// A queued retry re-queues the run's attempt under a new marker. When its task
// expires unclaimed, only that execution is failed; the attempt's earlier
// execution keeps its result, and the record names the new marker.
func TestReconcileFailsOnlyTheUnclaimedQueuedRetry(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newShortReservationFixture(t)
	const marker = "2026-10-12T15:10:00+08:00"
	retried := f.writeQueued(t, f.previous, marker)

	_, err := f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.NoError(t, err)
	require.Len(t, f.preparationEntries(t), 1)

	time.Sleep(3 * shortReservation)
	f.h.reconcileAbandonedPreparations(t.Context(), later())

	assert.Empty(t, f.preparationEntries(t))
	record, err := f.repository.ReadExecutionAbandonment(t.Context(), f.ref, f.ref, retried, marker)
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, persis.AbandonmentScopeExecution, record.Scope)
	assert.Equal(t, marker, record.AbandonedExecution.QueuedAt)
	other, err := f.repository.ReadExecutionAbandonment(t.Context(), f.ref, f.ref, retried, "2026-10-12T15:20:00+08:00")
	require.NoError(t, err)
	assert.Nil(t, other, "a later execution of the attempt is not covered")
}

// A queued execution whose dispatch fails stays queued, with its queue item, so
// the queue dispatches it again: its entry is ended, and reconciliation never
// fails it for the failed hand-out.
func TestAFailedQueuedDispatchEndsItsExecutionEntry(t *testing.T) {
	t.Parallel()
	registerCommandExecutorCapsForCoordinatorTest()
	f := newStrandedFixture(t, &failingDispatchTaskStore{enqueueErr: errors.New("disk full")})
	f.writeQueued(t, "", "2026-10-12T15:30:00+08:00")

	_, err := f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.Error(t, err)
	assert.Empty(t, f.preparationEntries(t))
	f.h.reconcileAbandonedPreparations(t.Context(), later())
	assert.Empty(t, f.records(t))
}

// A queued execution that a worker claims and acknowledges ends its entry and
// is never failed by reconciliation.
func TestAnAcknowledgedQueuedExecutionEndsItsEntry(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newStrandedFixture(t, nil)
	const marker = "2026-10-12T15:40:00+08:00"
	queued := f.writeQueued(t, "", marker)

	_, err := f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.NoError(t, err)
	require.Len(t, f.preparationEntries(t), 1)
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: time.Minute})
	require.NoError(t, err)
	require.NotNil(t, claimed)
	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(queued),
	})
	require.NoError(t, err)
	require.True(t, resp.Accepted, resp.Error)

	assert.Empty(t, f.preparationEntries(t))
	f.h.reconcileAbandonedPreparations(t.Context(), later())
	assert.Empty(t, f.records(t))
}

// Another coordinator publishes the queued execution's task after this one
// failed it as never dispatched. The worker's claim is live, and it is refused
// by the execution's own record, so the failed execution never runs.
func TestALiveClaimOfAFailedQueuedExecutionIsRefused(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newShortReservationFixture(t)
	const marker = "2026-10-12T16:00:00+08:00"
	queued := f.writeQueued(t, "", marker)
	_, err := f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.NoError(t, err)
	time.Sleep(3 * shortReservation)
	f.h.reconcileAbandonedPreparations(t.Context(), later())
	record, err := f.repository.ReadExecutionAbandonment(t.Context(), f.ref, f.ref, queued, marker)
	require.NoError(t, err)
	require.NotNil(t, record)

	require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
		Target: strandedDAG, DAGRunID: strandedRun, AttemptID: queued, AttemptKey: f.attemptKey(queued),
		ExecutionMarker: marker,
		Owner:           dispatch.CoordinatorEndpoint{ID: "coord-b", Host: "127.0.0.1", Port: 50056},
	}))
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: time.Minute})
	require.NoError(t, err)
	require.NotNil(t, claimed)
	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(queued),
	})
	require.NoError(t, err)
	assert.False(t, resp.Accepted)
	assert.Equal(t, errAttemptAbandoned.Error(), resp.Error)
	_, err = f.leases.Get(t.Context(), f.attemptKey(queued))
	require.ErrorIs(t, err, dispatch.ErrDAGRunLeaseNotFound, "no lease is recorded")
}
