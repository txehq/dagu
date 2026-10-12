// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/proto/convert"
	"github.com/dagucloud/dagu/v2/internal/queue"
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

// scriptedEnqueueStore fails the enqueues listed in fail (by call, from 0) and
// passes the rest to the dispatch store it wraps.
type scriptedEnqueueStore struct {
	dispatch.DispatchTaskStore
	fail  map[int]bool
	calls int
}

func (s *scriptedEnqueueStore) Enqueue(ctx context.Context, task *dispatch.DispatchTask) error {
	call := s.calls
	s.calls++
	if s.fail[call] {
		return errors.New("disk full")
	}
	return s.DispatchTaskStore.Enqueue(ctx, task)
}

// A queued execution whose dispatch fails stays queued and the queue dispatches
// it again. Both dispatches share the execution's one journal entry, which the
// failure leaves in place and the acknowledged claim ends.
func TestAFailedQueuedDispatchKeepsItsExecutionEntryForTheNextDispatch(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	dispatches := &scriptedEnqueueStore{DispatchTaskStore: newTestDispatchTaskStore(filepath.Join(t.TempDir(), "d")), fail: map[int]bool{0: true}}
	f := newStrandedFixture(t, dispatches)
	queued := f.writeQueued(t, "", "2026-10-12T15:30:00+08:00")

	_, err := f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.Error(t, err)
	before := f.preparationEntries(t)
	require.Len(t, before, 1, "a failed dispatch keeps the entry")

	_, err = f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.NoError(t, err)
	assert.Equal(t, before, f.preparationEntries(t), "the queue's next dispatch shares the entry")

	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: time.Minute})
	require.NoError(t, err)
	require.NotNil(t, claimed)
	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(queued),
	})
	require.NoError(t, err)
	require.True(t, resp.Accepted, resp.Error)
	assert.Empty(t, f.preparationEntries(t))
}

// A queued execution's task is published, then a duplicate dispatch of the
// same execution fails. The failure must not remove the entry protecting the
// published task: when that task expires unclaimed, the execution is still
// failed with a record instead of being left queued.
func TestAFailedDuplicateDispatchKeepsThePublishedExecutionsEntry(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	dispatches := &scriptedEnqueueStore{
		DispatchTaskStore: store.NewDispatchTaskStore(file.NewCollection(filepath.Join(t.TempDir(), "d")), store.WithDispatchReservationTTL(shortReservation)),
		fail:              map[int]bool{1: true},
	}
	f := newStrandedFixture(t, dispatches)
	const marker = "2026-10-12T15:35:00+08:00"
	queued := f.writeQueued(t, "", marker)

	_, err := f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.NoError(t, err)
	_, err = f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.Error(t, err)
	require.Len(t, f.preparationEntries(t), 1, "the published execution stays journaled")

	time.Sleep(3 * shortReservation)
	f.h.reconcileAbandonedPreparations(t.Context(), later())
	record, err := f.repository.ReadExecutionAbandonment(t.Context(), f.ref, f.ref, queued, marker)
	require.NoError(t, err)
	require.NotNil(t, record, "the expired execution is failed, not left queued")
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

// A queued execution's dispatch fails and the run stays in its queue, which
// will dispatch it again, possibly long after (its worker may be away). Its
// journal entry is kept, and reconciliation, however late, does not fail the
// execution while the queue still holds the run. Once the queue no longer
// holds it and nothing claimed it, the execution is failed with a record.
func TestReconcileLeavesAQueuedExecutionItsQueueStillHolds(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	dispatches := &scriptedEnqueueStore{DispatchTaskStore: newTestDispatchTaskStore(filepath.Join(t.TempDir(), "d")), fail: map[int]bool{0: true}}
	f := newStrandedFixture(t, dispatches)
	queues := store.NewQueueStore(file.NewCollection(filepath.Join(t.TempDir(), "queue")))
	f.h.queueStore = queues
	const marker = "2026-10-12T16:30:00+08:00"
	queued := f.writeQueued(t, "", marker)
	found, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	st, err := found.ReadStatus(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, st.ProcGroup)
	require.NoError(t, queues.Enqueue(t.Context(), st.ProcGroup, queue.QueuePriorityLow, f.ref))

	_, err = f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.Error(t, err)
	require.Len(t, f.preparationEntries(t), 1)

	f.h.reconcileAbandonedPreparations(t.Context(), time.Now().Add(time.Hour))
	assert.Len(t, f.preparationEntries(t), 1, "the queue still owns the execution")
	assert.Empty(t, f.records(t))
	record, err := f.repository.ReadExecutionAbandonment(t.Context(), f.ref, f.ref, queued, marker)
	require.NoError(t, err)
	assert.Nil(t, record)

	items, err := queues.List(t.Context(), st.ProcGroup)
	require.NoError(t, err)
	_, err = queues.DeleteByItemIDs(t.Context(), st.ProcGroup, []string{items[0].ID()})
	require.NoError(t, err)
	f.h.reconcileAbandonedPreparations(t.Context(), time.Now().Add(time.Hour))
	record, err = f.repository.ReadExecutionAbandonment(t.Context(), f.ref, f.ref, queued, marker)
	require.NoError(t, err)
	require.NotNil(t, record, "with the queue no longer holding it, the execution is failed")
}
