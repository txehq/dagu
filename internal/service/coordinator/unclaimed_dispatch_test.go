// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
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
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// shortReservation is the dispatch reservation time these tests run with, so
// an unclaimed task expires within the test. It leaves a test enough time to
// claim a task it has just published, even on a loaded machine.
const shortReservation = 300 * time.Millisecond

func newShortReservationFixture(t *testing.T) *strandedFixture {
	t.Helper()
	dispatches := store.NewDispatchTaskStore(file.NewCollection(filepath.Join(t.TempDir(), "distributed")),
		store.WithDispatchReservationTTL(shortReservation))
	return newStrandedFixture(t, dispatches)
}

// A retry is published while no worker can claim it. Its task expires from the
// dispatch store, and the preparation entry, kept until a claim is
// acknowledged, lets reconciliation abandon the attempt with a record instead
// of leaving it waiting for a worker that will never receive it.
func TestReconcileAbandonsAnUnclaimedDispatchOnceItExpires(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newShortReservationFixture(t)

	_, err := f.h.Dispatch(t.Context(), retryTask())
	require.NoError(t, err)
	attempt := f.latest(t)
	require.Equal(t, []string{attempt}, f.preparations(t))

	time.Sleep(3 * shortReservation)
	f.h.reconcileAbandonedPreparations(t.Context(), later())

	assert.Empty(t, f.preparations(t))
	assert.Equal(t, f.previous, f.latest(t), "the previous execution is the latest again")
	records := f.records(t)
	require.Len(t, records, 1)
	assert.Equal(t, attempt, records[0].AbandonedAttemptID)
	assert.Equal(t, persis.EvidenceAbsent, records[0].Evidence.DispatchTask)
	assert.Equal(t, abandonedPreparationDetail, records[0].Detail)

	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: time.Minute})
	require.NoError(t, err)
	assert.Nil(t, claimed, "nothing is left to hand to a worker")
}

// A worker claims the task but never acknowledges it, and comes back after the
// claim was released and the task expired. By then the attempt was abandoned:
// the late acknowledgement is refused, so the abandoned attempt never runs.
func TestALateAcknowledgementOfAnExpiredClaimIsRefused(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newShortReservationFixture(t)

	_, err := f.h.Dispatch(t.Context(), retryTask())
	require.NoError(t, err)
	attempt := f.latest(t)
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: shortReservation})
	require.NoError(t, err)
	require.NotNil(t, claimed)

	// The claim is released to pending after one reservation time and the
	// pending task expires after another.
	time.Sleep(3 * shortReservation)
	_, err = f.dispatches.HasOutstandingAttempt(t.Context(), f.attemptKey(attempt), 0)
	require.NoError(t, err)
	time.Sleep(3 * shortReservation)
	f.h.reconcileAbandonedPreparations(t.Context(), later())
	require.Len(t, f.records(t), 1)

	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(attempt),
	})
	require.NoError(t, err)
	assert.False(t, resp.Accepted)
	_, err = f.leases.Get(t.Context(), f.attemptKey(attempt))
	require.ErrorIs(t, err, dispatch.ErrDAGRunLeaseNotFound, "no lease is recorded")
}

// A coordinator stopped after an acknowledged claim wrote its lease and before
// it ended the preparation entry. Reconciliation must not abandon the attempt:
// it leaves the entry, reports that once rather than every pass, and ends it as
// settled once the worker's status shows progress.
func TestReconcileLeavesALeasedPreparationUntilItSettles(t *testing.T) {
	t.Parallel()
	f := newStrandedFixture(t, nil)
	placeholder := f.writeAttempt(t, true, ir.NotStarted, "")
	now := time.Now().UTC().UnixMilli()
	require.NoError(t, f.leases.Upsert(t.Context(), dispatch.DAGRunLease{
		AttemptKey: f.attemptKey(placeholder), DAGRun: f.ref, Root: f.ref, AttemptID: placeholder,
		WorkerID: "worker-1", ClaimedAt: now, LastHeartbeatAt: now,
	}))

	for range 3 {
		f.h.reconcileAbandonedPreparations(t.Context(), later())
		assert.Equal(t, placeholder, f.latest(t))
		assert.Empty(t, f.records(t), "a leased attempt is never abandoned")
		assert.Equal(t, []string{placeholder}, f.preparations(t), "the entry stays until the attempt settles")
	}
	entries, err := f.repository.ListAttemptPreparations(t.Context())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, f.h.wasInFlight(preparationKey(entries[0])), "reported once, then remembered")

	f.reportStatus(t, placeholder, ir.Running, "worker-1")
	f.h.reconcileAbandonedPreparations(t.Context(), later())
	assert.Empty(t, f.preparations(t), "a running attempt's entry is ended as settled")
	assert.Empty(t, f.records(t))
	assert.False(t, f.h.wasInFlight(preparationKey(entries[0])), "a settled entry is forgotten")
}

// reportStatus writes a status to an existing attempt, as its worker would.
func (f *strandedFixture) reportStatus(t *testing.T, attemptID string, st ir.Status, worker string) {
	t.Helper()
	attempt, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	require.Equal(t, attemptID, attempt.ID())
	require.NoError(t, attempt.Open(t.Context()))
	dag := &ir.DAG{Name: strandedDAG}
	status := ir.InitialStatus(dag)
	status.DAGRunID = strandedRun
	status.AttemptID = attemptID
	status.AttemptKey = f.attemptKey(attemptID)
	status.Status = st
	status.WorkerID = worker
	require.NoError(t, attempt.Write(t.Context(), status))
	require.NoError(t, attempt.Close(t.Context()))
}

// The minimum age outlasts the longest an unacknowledged dispatch can stay
// reserved, a claim released after one reservation time and then expiring
// after another, so reconciliation never judges a live reservation.
func TestAbandonedPreparationMinAgeOutlastsAnUnacknowledgedReservation(t *testing.T) {
	t.Parallel()
	assert.Greater(t, abandonedPreparationMinAge, 2*dagrun.DefaultStaleLeaseThreshold)
}

// An acknowledgement may carry a marker filled in for a legacy queued task even
// when the dispatch created the attempt, which is journaled without a marker.
// Recording the claim still ends that attempt's entry.
func TestARecordedClaimEndsTheAttemptEntryWhateverItsMarker(t *testing.T) {
	t.Parallel()
	f := newStrandedFixture(t, nil)
	placeholder := f.writeAttempt(t, true, ir.NotStarted, "")
	require.Equal(t, []string{placeholder}, f.preparations(t))

	err := f.h.recordTaskClaim(t.Context(), &coordinatorv1.Task{
		Target: strandedDAG, DagRunId: strandedRun, AttemptId: placeholder, AttemptKey: f.attemptKey(placeholder),
		ExecutionMarker: "2026-10-12T16:20:00+08:00",
	}, "worker-1")
	require.NoError(t, err)
	assert.Empty(t, f.preparations(t))
}
