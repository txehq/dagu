// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/testutil"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newHeldPreparationFixture is a coordinator that holds a dispatch no
// healthy worker matches (worker-1 carries no labels), over stores that can
// prove absence of dispatch, so a held attempt left without its task can be
// abandoned.
func newHeldPreparationFixture(t *testing.T, dispatches dispatch.DispatchTaskStore) *strandedFixture {
	t.Helper()
	registerCommandExecutorCapsForCoordinatorTest()
	dir := t.TempDir()
	repository := testutil.NewFileDAGRunRepository(filepath.Join(dir, "dag-runs"), persis.DAGRunRepositoryOptions{LatestStatusToday: true})
	if dispatches == nil {
		dispatches = newTestDispatchTaskStore(filepath.Join(dir, "distributed"))
	}
	heartbeats := newTestWorkerHeartbeatStore(filepath.Join(dir, "distributed"))
	require.NoError(t, heartbeats.Upsert(t.Context(), dispatch.WorkerHeartbeatRecord{WorkerID: "worker-1", LastHeartbeatAt: time.Now().UTC().UnixMilli()}))
	leases := newTestDAGRunLeaseStore(filepath.Join(dir, "distributed"))
	f := &strandedFixture{
		h: NewHandler(HandlerConfig{
			DAGRunRepository:          repository,
			DispatchTaskStore:         dispatches,
			DAGRunLeaseStore:          leases,
			ActiveDistributedRunStore: newTestActiveDistributedRunStore(filepath.Join(dir, "distributed")),
			WorkerHeartbeatStore:      heartbeats,
			QueueStore:                store.NewQueueStore(file.NewCollection(filepath.Join(dir, "queue"))),
			Owner:                     dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055},
			WorkerWaitTimeout:         holdWait,
		}),
		repository: repository,
		dispatches: dispatches,
		leases:     leases,
		ref:        ir.NewDAGRunRef(strandedDAG, "held-run"),
		runsDir:    filepath.Join(dir, "dag-runs"),
	}
	t.Cleanup(func() { f.h.Close(context.Background()) })
	return f
}

func heldTask(runID string) *coordinatorv1.Task {
	return &coordinatorv1.Task{
		Operation:      coordinatorv1.Operation_OPERATION_START,
		DagRunId:       runID,
		Target:         strandedDAG,
		Definition:     "name: " + strandedDAG + "\nsteps:\n  - name: step1\n    run: echo hello",
		WorkerSelector: map[string]string{"type": "cpu"},
	}
}

// A dispatch held for a worker whose task then cannot be stored is not left
// queued for ever: the failure abandons the held attempt with its record,
// as it does an attempt that never left NotStarted.
func TestHeldDispatchWhoseTaskCannotBeStoredIsAbandoned(t *testing.T) {
	t.Parallel()
	f := newHeldPreparationFixture(t, &failingDispatchTaskStore{enqueueErr: errors.New("disk full")})

	_, err := f.h.Dispatch(t.Context(), &coordinatorv1.DispatchRequest{Task: heldTask(f.ref.ID)})
	require.Error(t, err)

	attempt, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err, "the run stays visible")
	status, err := attempt.ReadStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, ir.Failed, status.Status, "a held attempt with no task is not left queued")
	assert.Contains(t, status.Error, "not dispatched")
	records, err := f.repository.ListAttemptAbandonments(t.Context(), f.ref, ir.DAGRunRef{})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, persis.AbandonmentMarkedFailed, records[0].Outcome)
	assert.Empty(t, f.preparations(t), "the journal entry ends with the record")
}

// writeHeldAttempt leaves a first attempt as a coordinator that held it and
// then stopped would: journaled as a preparation, Queued with the hold's
// conditions and its prepared, empty queuedAt.
func (f *strandedFixture) writeHeldAttempt(t *testing.T) (*ir.DAGRunStatus, string) {
	t.Helper()
	dag := &ir.DAG{Name: strandedDAG}
	attempt, err := f.repository.CreateAttempt(t.Context(), dag, time.Now(), f.ref.ID, persis.DAGRunCreateAttemptOptions{TrackPreparation: true})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(t.Context()))
	status := ir.InitialStatus(dag)
	status.DAGRunID = f.ref.ID
	status.AttemptID = attempt.ID()
	status.AttemptKey = ir.GenerateAttemptKey(strandedDAG, f.ref.ID, strandedDAG, f.ref.ID, attempt.ID())
	status.Status = ir.Queued
	status.Conditions = ir.MergeDAGRunConditions(status.Conditions, ir.NoMatchingWorkerConditions(time.Now())...)
	require.NoError(t, attempt.Write(t.Context(), status))
	require.NoError(t, attempt.Close(t.Context()))
	return &status, attempt.ID()
}

// A coordinator that stopped between holding an attempt and storing its task
// leaves the attempt queued with nothing behind it: reconciliation abandons
// it. One whose held task was stored is left for a worker, or for the hold's
// own deadline.
func TestReconcileAbandonsAHeldAttemptOnlyWithoutItsTask(t *testing.T) {
	t.Parallel()

	t.Run("task never stored", func(t *testing.T) {
		t.Parallel()
		f := newHeldPreparationFixture(t, nil)
		_, attemptID := f.writeHeldAttempt(t)

		f.h.reconcileAbandonedPreparations(t.Context(), later())

		attempt, err := f.repository.FindAttempt(t.Context(), f.ref)
		require.NoError(t, err)
		assert.Equal(t, attemptID, attempt.ID())
		status, err := attempt.ReadStatus(t.Context())
		require.NoError(t, err)
		assert.Equal(t, ir.Failed, status.Status)
		records, err := f.repository.ListAttemptAbandonments(t.Context(), f.ref, ir.DAGRunRef{})
		require.NoError(t, err)
		require.Len(t, records, 1)
		assert.Equal(t, attemptID, records[0].AbandonedAttemptID)
	})

	t.Run("held task stored", func(t *testing.T) {
		t.Parallel()
		f := newHeldPreparationFixture(t, nil)
		status, attemptID := f.writeHeldAttempt(t)
		require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
			Operation:      dispatch.DispatchOperationStart,
			DAGRunID:       f.ref.ID,
			Target:         strandedDAG,
			AttemptID:      attemptID,
			AttemptKey:     status.AttemptKey,
			RootDAGRunName: strandedDAG,
			RootDAGRunID:   f.ref.ID,
			HoldUntil:      time.Now().Add(holdWait).UTC(),
		}))

		f.h.reconcileAbandonedPreparations(t.Context(), later())

		attempt, err := f.repository.FindAttempt(t.Context(), f.ref)
		require.NoError(t, err)
		got, err := attempt.ReadStatus(t.Context())
		require.NoError(t, err)
		assert.Equal(t, ir.Queued, got.Status, "a held attempt whose task is pending is not abandoned")
		records, err := f.repository.ListAttemptAbandonments(t.Context(), f.ref, ir.DAGRunRef{})
		require.NoError(t, err)
		assert.Empty(t, records)
	})
}
