// Copyright (C) 2026 Yota Hamada
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
	"github.com/dagucloud/dagu/v2/internal/testutil"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	strandedDAG = "stranded-dag"
	strandedRun = "stranded-run"
)

type strandedFixture struct {
	h          *Handler
	repository *persis.DAGRunRepository
	dispatches dispatch.DispatchTaskStore
	leases     dispatch.DAGRunLeaseStore
	ref        ir.DAGRunRef
	previous   string
}

func newStrandedFixture(t *testing.T, dispatches dispatch.DispatchTaskStore) *strandedFixture {
	t.Helper()
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
			Owner:                     dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055},
		}),
		repository: repository,
		dispatches: dispatches,
		leases:     leases,
		ref:        ir.NewDAGRunRef(strandedDAG, strandedRun),
	}
	f.previous = f.writeAttempt(t, false, ir.Failed, "worker-1", time.Now().Add(-2*time.Hour))
	return f
}

// writeAttempt adds an attempt to the run with the given status, worker and
// creation time, as a coordinator that created it would have left it.
func (f *strandedFixture) writeAttempt(t *testing.T, retry bool, st ir.Status, worker string, createdAt time.Time) string {
	t.Helper()
	dag := &ir.DAG{Name: strandedDAG}
	attempt, err := f.repository.CreateAttempt(t.Context(), dag, time.Now(), strandedRun, persis.DAGRunCreateAttemptOptions{Retry: retry})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(t.Context()))
	status := ir.InitialStatus(dag)
	status.DAGRunID = strandedRun
	status.AttemptID = attempt.ID()
	status.AttemptKey = ir.GenerateAttemptKey(strandedDAG, strandedRun, strandedDAG, strandedRun, attempt.ID())
	status.Status = st
	status.WorkerID = worker
	status.CreatedAt = createdAt.UnixMilli()
	require.NoError(t, attempt.Write(t.Context(), status))
	require.NoError(t, attempt.Close(t.Context()))
	return attempt.ID()
}

func (f *strandedFixture) latest(t *testing.T) string {
	t.Helper()
	attempt, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	return attempt.ID()
}

func (f *strandedFixture) records(t *testing.T) []persis.AttemptAbandonment {
	t.Helper()
	records, err := f.repository.ListAttemptAbandonments(t.Context(), f.ref, ir.DAGRunRef{})
	require.NoError(t, err)
	return records
}

func (f *strandedFixture) attemptKey(attemptID string) string {
	return ir.GenerateAttemptKey(strandedDAG, strandedRun, strandedDAG, strandedRun, attemptID)
}

// A coordinator stopped after creating a retry's attempt and before
// publishing its task. Reconciliation proves nothing was dispatched, records
// that, and hides the attempt, so the previous execution is the latest again.
func TestReconcileAbandonsStrandedPlaceholder(t *testing.T) {
	t.Parallel()
	f := newStrandedFixture(t, nil)
	placeholder := f.writeAttempt(t, true, ir.NotStarted, "", time.Now().Add(-time.Hour))

	// Reconciliation runs in the coordinator's periodic zombie pass.
	f.h.detectAndCleanupZombies(t.Context())

	assert.Equal(t, f.previous, f.latest(t))
	records := f.records(t)
	require.Len(t, records, 1)
	assert.Equal(t, placeholder, records[0].AbandonedAttemptID)
	require.NotNil(t, records[0].ExpectedExecution)
	assert.Equal(t, f.previous, records[0].ExpectedExecution.AttemptID)
	assert.Equal(t, persis.EvidenceAbsent, records[0].Evidence.DispatchTask)
	assert.Equal(t, "coord-a", records[0].CoordinatorID)
}

// Anything that shows the attempt may have been dispatched, or a stranded
// attempt too young to judge, leaves it alone.
func TestReconcileLeavesPossiblyDispatchedPlaceholder(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		age     time.Duration
		arrange func(t *testing.T, f *strandedFixture, attemptID string)
	}{
		{name: "a dispatch task is pending", age: time.Hour, arrange: func(t *testing.T, f *strandedFixture, attemptID string) {
			require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
				Target: strandedDAG, DAGRunID: strandedRun, AttemptID: attemptID, AttemptKey: f.attemptKey(attemptID),
			}))
		}},
		{name: "a lease exists", age: time.Hour, arrange: func(t *testing.T, f *strandedFixture, attemptID string) {
			now := time.Now().UTC().UnixMilli()
			require.NoError(t, f.leases.Upsert(t.Context(), dispatch.DAGRunLease{
				AttemptKey: f.attemptKey(attemptID), DAGRun: f.ref, Root: f.ref, AttemptID: attemptID,
				WorkerID: "worker-1", ClaimedAt: now, LastHeartbeatAt: now,
			}))
		}},
		{name: "too young to judge", age: abandonedPreparationMinAge - time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newStrandedFixture(t, nil)
			now := time.Now()
			placeholder := f.writeAttempt(t, true, ir.NotStarted, "", now.Add(-tc.age))
			if tc.arrange != nil {
				tc.arrange(t, f, placeholder)
			}

			f.h.reconcileAbandonedPreparations(t.Context(), now)
			assert.Equal(t, placeholder, f.latest(t), "the attempt stays visible")
			assert.Empty(t, f.records(t), "no record is written")
		})
	}
}

// erroringDispatchStore fails the outstanding-dispatch lookup.
type erroringDispatchStore struct {
	dispatch.DispatchTaskStore
}

func (erroringDispatchStore) HasOutstandingAttempt(context.Context, string, time.Duration) (bool, error) {
	return false, errors.New("dispatch index unavailable")
}

// A lookup that fails is unknown, never absent.
func TestReconcileTreatsLookupErrorAsUnknown(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := newStrandedFixture(t, erroringDispatchStore{DispatchTaskStore: newTestDispatchTaskStore(filepath.Join(dir, "d"))})
	placeholder := f.writeAttempt(t, true, ir.NotStarted, "", time.Now().Add(-time.Hour))

	f.h.reconcileAbandonedPreparations(t.Context(), time.Now())

	assert.Equal(t, placeholder, f.latest(t))
	assert.Empty(t, f.records(t))
}

// Not parallel: the hook is package state. Dispatch pauses after preparing a
// retry's attempt, before publishing its task, and reconciliation runs in that
// window. It must wait for the publication and then find the task, so the
// attempt is never both hidden as undispatched and published.
func TestReconcileWaitsForAnInFlightDispatch(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newStrandedFixture(t, nil)

	reconciled := make(chan error, 1)
	completedInWindow := false
	var prepared string
	dispatchPublishHook = func(task *coordinatorv1.Task) {
		if task.GetDagRunId() != strandedRun {
			return
		}
		prepared = task.GetAttemptId()
		go func() {
			_, err := f.h.abandonNeverDispatched(context.Background(), f.ref, prepared, "test", false)
			reconciled <- err
		}()
		select {
		case err := <-reconciled:
			completedInWindow = true
			reconciled <- err
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Cleanup(func() { dispatchPublishHook = nil })

	_, err := f.h.Dispatch(t.Context(), &coordinatorv1.DispatchRequest{Task: &coordinatorv1.Task{
		DagRunId:   strandedRun,
		Target:     strandedDAG,
		Operation:  coordinatorv1.Operation_OPERATION_RETRY,
		Definition: "name: " + strandedDAG + "\nsteps:\n  - name: step1\n    run: echo hello",
		QueueName:  "q",
	}})
	require.NoError(t, err)
	require.NotEmpty(t, prepared)

	reconcileErr := <-reconciled
	assert.False(t, completedInWindow, "reconciliation must wait for the publication")
	require.Error(t, reconcileErr, "the published task must stop the abandonment")
	assert.Equal(t, prepared, f.latest(t), "the dispatched attempt stays visible")
	assert.Empty(t, f.records(t))
}

// Another coordinator publishes a task after this one proved the attempt was
// never dispatched and abandoned it. The worker's claim is refused, so the
// hidden attempt is never executed.
func TestAckRefusesAbandonedAttempt(t *testing.T) {
	t.Parallel()
	f := newStrandedFixture(t, nil)
	placeholder := f.writeAttempt(t, true, ir.NotStarted, "", time.Now().Add(-time.Hour))
	_, err := f.h.abandonNeverDispatched(t.Context(), f.ref, placeholder, "test", false)
	require.NoError(t, err)

	require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
		Target: strandedDAG, DAGRunID: strandedRun, AttemptID: placeholder, AttemptKey: f.attemptKey(placeholder),
		Owner: dispatch.CoordinatorEndpoint{ID: "coord-b", Host: "127.0.0.1", Port: 50056},
	}))
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: time.Minute})
	require.NoError(t, err)
	require.NotNil(t, claimed)

	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(placeholder),
	})
	require.NoError(t, err)
	assert.False(t, resp.Accepted)
	assert.Equal(t, errAttemptAbandoned.Error(), resp.Error)
	_, err = f.leases.Get(t.Context(), f.attemptKey(placeholder))
	require.ErrorIs(t, err, dispatch.ErrDAGRunLeaseNotFound, "no lease is recorded")
}

// When handing a retry's task to a worker fails, nothing ran: the attempt is
// abandoned rather than marked Failed like an execution.
func TestDispatchHandoffFailureAbandonsRetryAttempt(t *testing.T) {
	t.Parallel()
	registerCommandExecutorCapsForCoordinatorTest()
	f := newStrandedFixture(t, &failingDispatchTaskStore{enqueueErr: errors.New("disk full")})

	_, err := f.h.Dispatch(t.Context(), &coordinatorv1.DispatchRequest{Task: &coordinatorv1.Task{
		DagRunId:   strandedRun,
		Target:     strandedDAG,
		Operation:  coordinatorv1.Operation_OPERATION_RETRY,
		Definition: "name: " + strandedDAG + "\nsteps:\n  - name: step1\n    run: echo hello",
		QueueName:  "q",
	}})
	require.Error(t, err)

	assert.Equal(t, f.previous, f.latest(t), "the previous execution is the latest again")
	records := f.records(t)
	require.Len(t, records, 1)
	assert.Contains(t, records[0].Detail, "handing the task to a worker failed")
}
