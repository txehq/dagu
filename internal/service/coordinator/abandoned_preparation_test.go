// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/queue"
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
	runsDir    string
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
		runsDir:    filepath.Join(dir, "dag-runs"),
	}
	f.previous = f.writeAttempt(t, false, ir.Failed, "worker-1")
	return f
}

// later is a reconciliation time past the bound for any preparation journaled
// before it.
func later() time.Time { return time.Now().Add(abandonedPreparationMinAge + time.Minute) }

// writeAttempt adds an attempt to the run with the given status and worker,
// as a coordinator that created it would have left it. A not-started attempt
// is journaled as a preparation, and its status has no creation time, as the
// initial status Dispatch writes has none.
func (f *strandedFixture) writeAttempt(t *testing.T, retry bool, st ir.Status, worker string) string {
	t.Helper()
	return f.writeAttemptAt(t, time.Now(), retry, st, worker)
}

func (f *strandedFixture) writeAttemptAt(t *testing.T, ts time.Time, retry bool, st ir.Status, worker string) string {
	t.Helper()
	dag := &ir.DAG{Name: strandedDAG}
	attempt, err := f.repository.CreateAttempt(t.Context(), dag, ts, strandedRun,
		persis.DAGRunCreateAttemptOptions{Retry: retry, TrackPreparation: st == ir.NotStarted})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(t.Context()))
	status := ir.InitialStatus(dag)
	status.DAGRunID = strandedRun
	status.AttemptID = attempt.ID()
	status.AttemptKey = ir.GenerateAttemptKey(strandedDAG, strandedRun, strandedDAG, strandedRun, attempt.ID())
	status.Status = st
	status.WorkerID = worker
	require.NoError(t, attempt.Write(t.Context(), status))
	require.NoError(t, attempt.Close(t.Context()))
	return attempt.ID()
}

// preparations lists the attempts still in the preparation journal.
func (f *strandedFixture) preparations(t *testing.T) []string {
	t.Helper()
	entries, err := f.repository.ListAttemptPreparations(t.Context())
	require.NoError(t, err)
	var ids []string
	for _, e := range entries {
		ids = append(ids, e.AttemptID)
	}
	return ids
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
// publishing its task. Reconciliation finds it in the preparation journal,
// though its status has no creation time, proves nothing was dispatched,
// records that, and hides the attempt, so the previous execution is the
// latest again. The journal entry is ended.
func TestReconcileAbandonsStrandedPlaceholder(t *testing.T) {
	t.Parallel()
	f := newStrandedFixture(t, nil)
	placeholder := f.writeAttempt(t, true, ir.NotStarted, "")
	require.Equal(t, []string{placeholder}, f.preparations(t))

	f.h.reconcileAbandonedPreparations(t.Context(), later())

	assert.Empty(t, f.preparations(t))
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
			placeholder := f.writeAttempt(t, true, ir.NotStarted, "")
			if tc.arrange != nil {
				tc.arrange(t, f, placeholder)
			}

			f.h.reconcileAbandonedPreparations(t.Context(), time.Now().Add(tc.age))
			assert.Equal(t, placeholder, f.latest(t), "the attempt stays visible")
			assert.Empty(t, f.records(t), "no record is written")
			assert.Equal(t, []string{placeholder}, f.preparations(t), "the preparation stays journaled")
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
	placeholder := f.writeAttempt(t, true, ir.NotStarted, "")

	f.h.reconcileAbandonedPreparations(t.Context(), later())

	assert.Equal(t, placeholder, f.latest(t))
	assert.Empty(t, f.records(t))
	assert.Equal(t, []string{placeholder}, f.preparations(t))
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
			_, err := f.h.abandonNeverDispatched(context.Background(), f.ref, f.ref, prepared, "test")
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
	placeholder := f.writeAttempt(t, true, ir.NotStarted, "")
	_, err := f.h.abandonNeverDispatched(t.Context(), f.ref, f.ref, placeholder, "test")
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

// newFirstAttemptFixture is a fixture whose run has no earlier execution.
func newFirstAttemptFixture(t *testing.T, dispatches dispatch.DispatchTaskStore) *strandedFixture {
	t.Helper()
	f := newStrandedFixture(t, dispatches)
	f.ref = ir.NewDAGRunRef(strandedDAG, "first-run")
	return f
}

// A brand-new run whose task could not be handed to a worker stays visible,
// marked Failed with the not-dispatched reason, and its record says the
// predecessor is absent.
func TestDispatchHandoffFailureKeepsFirstAttemptVisible(t *testing.T) {
	t.Parallel()
	registerCommandExecutorCapsForCoordinatorTest()
	f := newFirstAttemptFixture(t, &failingDispatchTaskStore{enqueueErr: errors.New("disk full")})

	_, err := f.h.Dispatch(t.Context(), &coordinatorv1.DispatchRequest{Task: &coordinatorv1.Task{
		DagRunId:   f.ref.ID,
		Target:     strandedDAG,
		Definition: "name: " + strandedDAG + "\nsteps:\n  - name: step1\n    run: echo hello",
		QueueName:  "q",
	}})
	require.Error(t, err)

	attempt, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err, "the run stays visible")
	status, err := attempt.ReadStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, ir.Failed, status.Status)
	assert.Contains(t, status.Error, "not dispatched")
	records, err := f.repository.ListAttemptAbandonments(t.Context(), f.ref, ir.DAGRunRef{})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, persis.AbandonmentMarkedFailed, records[0].Outcome)
	assert.True(t, records[0].PredecessorAbsent)
	assert.Nil(t, records[0].ExpectedExecution)
}

// A stranded first attempt found by reconciliation is likewise kept visible
// and marked Failed with its record.
func TestReconcileKeepsStrandedFirstAttemptVisible(t *testing.T) {
	t.Parallel()
	f := newStrandedFixture(t, nil)
	first := ir.NewDAGRunRef(strandedDAG, "first-run")
	dag := &ir.DAG{Name: strandedDAG}
	attempt, err := f.repository.CreateAttempt(t.Context(), dag, time.Now(), first.ID, persis.DAGRunCreateAttemptOptions{TrackPreparation: true})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(t.Context()))
	status := ir.InitialStatus(dag)
	status.DAGRunID = first.ID
	status.AttemptID = attempt.ID()
	require.NoError(t, attempt.Write(t.Context(), status))
	require.NoError(t, attempt.Close(t.Context()))

	f.h.reconcileAbandonedPreparations(t.Context(), later())

	latest, err := f.repository.FindAttempt(t.Context(), first)
	require.NoError(t, err)
	assert.Equal(t, attempt.ID(), latest.ID())
	got, err := latest.ReadStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, ir.Failed, got.Status)
	records, err := f.repository.ListAttemptAbandonments(t.Context(), first, ir.DAGRunRef{})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, persis.AbandonmentMarkedFailed, records[0].Outcome)
}

// A coordinator can stop before an attempt's status is ever written: right
// after creating it, or after Open created an empty status file. The journal
// still names the attempt, and reconciliation abandons it.
func TestReconcileAbandonsStatusLessPreparation(t *testing.T) {
	t.Parallel()
	for name, open := range map[string]bool{"before Open": false, "empty status file": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newStrandedFixture(t, nil)
			attempt, err := f.repository.CreateAttempt(t.Context(), &ir.DAG{Name: strandedDAG}, time.Now(), strandedRun,
				persis.DAGRunCreateAttemptOptions{Retry: true, TrackPreparation: true})
			require.NoError(t, err)
			if open {
				require.NoError(t, attempt.Open(t.Context()))
				require.NoError(t, attempt.Close(t.Context()))
			}

			f.h.reconcileAbandonedPreparations(t.Context(), later())

			assert.Empty(t, f.preparations(t))
			assert.Equal(t, f.previous, f.latest(t))
			records := f.records(t)
			require.Len(t, records, 1)
			assert.Equal(t, attempt.ID(), records[0].AbandonedAttemptID)
		})
	}
}

// A retry of a run created long ago is judged by when the retry was prepared,
// not by the run's age.
func TestReconcileAbandonsStrandedRetryOfAnOldRun(t *testing.T) {
	t.Parallel()
	f := newStrandedFixture(t, nil)
	f.ref = ir.NewDAGRunRef(strandedDAG, strandedRun)
	old := ir.NewDAGRunRef(strandedDAG, "old-run")
	dag := &ir.DAG{Name: strandedDAG}
	write := func(retry bool, st ir.Status, worker string) string {
		attempt, err := f.repository.CreateAttempt(t.Context(), dag, time.Now().AddDate(0, -2, 0), old.ID,
			persis.DAGRunCreateAttemptOptions{Retry: retry, TrackPreparation: st == ir.NotStarted})
		require.NoError(t, err)
		require.NoError(t, attempt.Open(t.Context()))
		status := ir.InitialStatus(dag)
		status.DAGRunID = old.ID
		status.AttemptID = attempt.ID()
		status.Status = st
		status.WorkerID = worker
		require.NoError(t, attempt.Write(t.Context(), status))
		require.NoError(t, attempt.Close(t.Context()))
		return attempt.ID()
	}
	previous := write(false, ir.Failed, "worker-1")
	placeholder := write(true, ir.NotStarted, "")

	f.h.reconcileAbandonedPreparations(t.Context(), later())

	latest, err := f.repository.FindAttempt(t.Context(), old)
	require.NoError(t, err)
	assert.Equal(t, previous, latest.ID())
	records, err := f.repository.ListAttemptAbandonments(t.Context(), old, ir.DAGRunRef{})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, placeholder, records[0].AbandonedAttemptID)
}

// A journaled attempt that a worker started, or whose run is gone, is settled:
// its entry is ended and nothing is recorded. One that remains possibly
// dispatched stays journaled without holding the others back.
func TestReconcileEndsSettledPreparations(t *testing.T) {
	t.Parallel()
	f := newStrandedFixture(t, nil)
	dag := &ir.DAG{Name: strandedDAG}

	started, err := f.repository.CreateAttempt(t.Context(), dag, time.Now(), "started-run",
		persis.DAGRunCreateAttemptOptions{TrackPreparation: true})
	require.NoError(t, err)
	require.NoError(t, started.Open(t.Context()))
	status := ir.InitialStatus(dag)
	status.DAGRunID = "started-run"
	status.AttemptID = started.ID()
	status.Status = ir.Running
	status.WorkerID = "worker-1"
	require.NoError(t, started.Write(t.Context(), status))
	require.NoError(t, started.Close(t.Context()))

	gone, err := f.repository.CreateAttempt(t.Context(), dag, time.Now(), "gone-run",
		persis.DAGRunCreateAttemptOptions{TrackPreparation: true})
	require.NoError(t, err)
	require.NoError(t, f.repository.RemoveDAGRun(t.Context(), ir.NewDAGRunRef(strandedDAG, "gone-run"), persis.DAGRunRemoveOptions{}))

	pending := f.writeAttempt(t, true, ir.NotStarted, "")
	require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
		Target: strandedDAG, DAGRunID: strandedRun, AttemptID: pending, AttemptKey: f.attemptKey(pending),
	}))
	require.ElementsMatch(t, []string{started.ID(), gone.ID(), pending}, f.preparations(t))

	f.h.reconcileAbandonedPreparations(t.Context(), later())

	assert.Equal(t, []string{pending}, f.preparations(t))
	assert.Empty(t, f.records(t))
	records, err := f.repository.ListAttemptAbandonments(t.Context(), ir.NewDAGRunRef(strandedDAG, "started-run"), ir.DAGRunRef{})
	require.NoError(t, err)
	assert.Empty(t, records)
}

// A sub-DAG run's attempt that was prepared and never dispatched is abandoned
// under its root, with the child's attempt key as the evidence key. The root
// run is untouched.
func TestReconcileAbandonsStrandedSubDAGPreparation(t *testing.T) {
	t.Parallel()
	for name, pending := range map[string]bool{"never dispatched": false, "task pending": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newStrandedFixture(t, nil)
			child := ir.NewDAGRunRef("child-dag", "child-run")
			attempt, err := f.repository.CreateAttempt(t.Context(), &ir.DAG{Name: child.Name}, time.Now(), child.ID,
				persis.DAGRunCreateAttemptOptions{RootDAGRun: f.ref, TrackPreparation: true})
			require.NoError(t, err)
			require.NoError(t, attempt.Open(t.Context()))
			status := ir.InitialStatus(&ir.DAG{Name: child.Name})
			status.DAGRunID = child.ID
			status.AttemptID = attempt.ID()
			status.Root = f.ref
			status.Parent = f.ref
			require.NoError(t, attempt.Write(t.Context(), status))
			require.NoError(t, attempt.Close(t.Context()))
			key := ir.GenerateAttemptKey(f.ref.Name, f.ref.ID, child.Name, child.ID, attempt.ID())
			if pending {
				require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
					Target: child.Name, DAGRunID: child.ID, AttemptID: attempt.ID(), AttemptKey: key,
					RootDAGRunName: f.ref.Name, RootDAGRunID: f.ref.ID, ParentDAGRunName: f.ref.Name, ParentDAGRunID: f.ref.ID,
				}))
			}

			f.h.reconcileAbandonedPreparations(t.Context(), later())

			assert.Equal(t, f.previous, f.latest(t), "the root run is untouched")
			records, err := f.repository.ListAttemptAbandonments(t.Context(), child, f.ref)
			require.NoError(t, err)
			if pending {
				assert.Empty(t, records)
				assert.Equal(t, []string{attempt.ID()}, f.preparations(t))
				return
			}
			require.Len(t, records, 1)
			assert.Equal(t, f.ref, records[0].RootRun)
			assert.Equal(t, child, records[0].Run)
			assert.Equal(t, persis.AbandonmentMarkedFailed, records[0].Outcome)
			assert.Empty(t, f.preparations(t))
			latest, err := f.repository.FindSubAttempt(t.Context(), f.ref, child.ID)
			require.NoError(t, err)
			got, err := latest.ReadStatus(t.Context())
			require.NoError(t, err)
			assert.Equal(t, ir.Failed, got.Status)
		})
	}
}

// A first attempt abandoned and marked Failed can be retried: the retry
// re-queues the same attempt under a new queued-at marker. Its claim is a
// different execution and is not refused; a late claim of the abandoned
// execution still is.
func TestClaimRefusalIsScopedToTheAbandonedExecution(t *testing.T) {
	t.Parallel()
	f := newFirstAttemptFixture(t, nil)
	dag := &ir.DAG{Name: strandedDAG}
	attempt, err := f.repository.CreateAttempt(t.Context(), dag, time.Now(), f.ref.ID,
		persis.DAGRunCreateAttemptOptions{TrackPreparation: true})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(t.Context()))
	status := ir.InitialStatus(dag)
	status.DAGRunID = f.ref.ID
	status.AttemptID = attempt.ID()
	require.NoError(t, attempt.Write(t.Context(), status))
	require.NoError(t, attempt.Close(t.Context()))
	record, err := f.h.abandonNeverDispatched(t.Context(), f.ref, f.ref, attempt.ID(), "test")
	require.NoError(t, err)
	require.Equal(t, persis.AbandonmentMarkedFailed, record.Outcome)

	failed, err := attempt.ReadStatus(t.Context())
	require.NoError(t, err)
	admission, err := queue.PrepareRetry(t.Context(), f.repository, dag, failed, queue.EnqueueRetryOptions{})
	require.NoError(t, err)
	require.NotNil(t, admission)
	require.Equal(t, attempt.ID(), admission.Status.AttemptID, "the retry re-queues the same attempt")
	require.NotEmpty(t, admission.Status.QueuedAt)

	assert.NoError(t, f.h.refuseAbandonedExecution(t.Context(), f.ref, f.ref, attempt.ID(), admission.Status.QueuedAt))
	assert.ErrorIs(t, f.h.refuseAbandonedExecution(t.Context(), f.ref, f.ref, attempt.ID(), ""), errAttemptAbandoned)
}

// A record that cannot be read refuses the claim rather than letting it pass
// as though the attempt had none.
func TestClaimRefusalFailsClosedOnAnUnreadableRecord(t *testing.T) {
	t.Parallel()
	f := newStrandedFixture(t, nil)
	placeholder := f.writeAttempt(t, true, ir.NotStarted, "")
	_, err := f.h.abandonNeverDispatched(t.Context(), f.ref, f.ref, placeholder, "test")
	require.NoError(t, err)
	var record string
	require.NoError(t, filepath.WalkDir(f.runsDir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.Name() == "abandonment.json" && strings.HasSuffix(filepath.Dir(path), placeholder) {
			record = path
		}
		return err
	}))
	require.NotEmpty(t, record)
	require.NoError(t, os.WriteFile(record, []byte("{"), 0600))

	err = f.h.refuseAbandonedExecution(t.Context(), f.ref, f.ref, placeholder, "")
	require.Error(t, err)
	assert.NotErrorIs(t, err, errAttemptAbandoned)
	assert.ErrorIs(t, err, persis.ErrAttemptAbandonmentConflict)
}

// evidenceGatedDispatchStore fails enqueueing, and fails the
// outstanding-dispatch lookup while unknown is set, as an index that is
// briefly unavailable.
type evidenceGatedDispatchStore struct {
	dispatch.DispatchTaskStore
	unknown atomic.Bool
}

func (s *evidenceGatedDispatchStore) Enqueue(context.Context, *dispatch.DispatchTask) error {
	return errors.New("disk full")
}

func (s *evidenceGatedDispatchStore) HasOutstandingAttempt(ctx context.Context, key string, stale time.Duration) (bool, error) {
	if s.unknown.Load() {
		return false, errors.New("dispatch index unavailable")
	}
	return s.DispatchTaskStore.HasOutstandingAttempt(ctx, key, stale)
}

// An attempt that Dispatch prepared, whose immediate abandonment could not
// establish absence, stays journaled. Its initial status, written by the real
// preparation path, has no creation time; reconciliation still finds it and
// abandons it once the evidence can be read.
func TestDispatchPreparationLeftBehindIsReconciled(t *testing.T) {
	t.Parallel()
	registerCommandExecutorCapsForCoordinatorTest()
	dir := t.TempDir()
	gated := &evidenceGatedDispatchStore{DispatchTaskStore: newTestDispatchTaskStore(filepath.Join(dir, "d"))}
	gated.unknown.Store(true)
	f := newStrandedFixture(t, gated)

	_, err := f.h.Dispatch(t.Context(), &coordinatorv1.DispatchRequest{Task: &coordinatorv1.Task{
		DagRunId:   strandedRun,
		Target:     strandedDAG,
		Operation:  coordinatorv1.Operation_OPERATION_RETRY,
		Definition: "name: " + strandedDAG + "\nsteps:\n  - name: step1\n    run: echo hello",
		QueueName:  "q",
	}})
	require.Error(t, err)
	prepared := f.latest(t)
	require.NotEqual(t, f.previous, prepared, "the prepared attempt was left for review")
	require.Equal(t, []string{prepared}, f.preparations(t))
	attempt, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	status, err := attempt.ReadStatus(t.Context())
	require.NoError(t, err)
	require.Equal(t, ir.NotStarted, status.Status)
	require.Zero(t, status.CreatedAt, "the real initial status has no creation time")

	gated.unknown.Store(false)
	f.h.reconcileAbandonedPreparations(t.Context(), later())

	assert.Equal(t, f.previous, f.latest(t))
	assert.Empty(t, f.preparations(t))
	records := f.records(t)
	require.Len(t, records, 1)
	assert.Equal(t, prepared, records[0].AbandonedAttemptID)
}

// A successful dispatch journals its attempt while preparing it and ends the
// entry once the task is published.
func TestDispatchEndsItsPreparationOncePublished(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newStrandedFixture(t, nil)
	var during []string
	dispatchPublishHook = func(task *coordinatorv1.Task) {
		if task.GetDagRunId() == strandedRun {
			during = f.preparations(t)
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
	assert.Equal(t, []string{f.latest(t)}, during)
	assert.Empty(t, f.preparations(t))
}

// When handing a sub-DAG run's task to a worker fails, nothing ran: the
// child's attempt is abandoned under its root with a record, not marked
// Failed like an execution. The root run is untouched.
func TestDispatchHandoffFailureAbandonsSubDAGAttempt(t *testing.T) {
	t.Parallel()
	registerCommandExecutorCapsForCoordinatorTest()
	f := newStrandedFixture(t, &failingDispatchTaskStore{enqueueErr: errors.New("disk full")})
	child := ir.NewDAGRunRef("child-dag", "child-run")

	_, err := f.h.Dispatch(t.Context(), &coordinatorv1.DispatchRequest{Task: &coordinatorv1.Task{
		DagRunId:         child.ID,
		Target:           child.Name,
		RootDagRunName:   f.ref.Name,
		RootDagRunId:     f.ref.ID,
		ParentDagRunName: f.ref.Name,
		ParentDagRunId:   f.ref.ID,
		Definition:       "name: " + child.Name + "\nsteps:\n  - name: step1\n    run: echo hello",
		QueueName:        "q",
	}})
	require.Error(t, err)

	assert.Equal(t, f.previous, f.latest(t), "the root run is untouched")
	records, err := f.repository.ListAttemptAbandonments(t.Context(), child, f.ref)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, f.ref, records[0].RootRun)
	assert.Contains(t, records[0].Detail, "handing the task to a worker failed")
	assert.Empty(t, f.preparations(t))
	latest, err := f.repository.FindSubAttempt(t.Context(), f.ref, child.ID)
	require.NoError(t, err)
	status, err := latest.ReadStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, ir.Failed, status.Status)
	assert.Contains(t, status.Error, "not dispatched")
}

// A first attempt abandoned and then retried through PrepareRetry is claimed
// through the coordinator: the retry's task carries the new queued-at marker,
// and the claim is accepted.
func TestAckAcceptsRetryOfAnAbandonedFirstAttempt(t *testing.T) {
	t.Parallel()
	f := newFirstAttemptFixture(t, nil)
	dag := &ir.DAG{Name: strandedDAG}
	attempt, err := f.repository.CreateAttempt(t.Context(), dag, time.Now(), f.ref.ID,
		persis.DAGRunCreateAttemptOptions{TrackPreparation: true})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(t.Context()))
	status := ir.InitialStatus(dag)
	status.DAGRunID = f.ref.ID
	status.AttemptID = attempt.ID()
	require.NoError(t, attempt.Write(t.Context(), status))
	require.NoError(t, attempt.Close(t.Context()))
	_, err = f.h.abandonNeverDispatched(t.Context(), f.ref, f.ref, attempt.ID(), "test")
	require.NoError(t, err)
	failed, err := attempt.ReadStatus(t.Context())
	require.NoError(t, err)
	admission, err := queue.PrepareRetry(t.Context(), f.repository, dag, failed, queue.EnqueueRetryOptions{})
	require.NoError(t, err)
	require.NotNil(t, admission)

	key := ir.GenerateAttemptKey(strandedDAG, f.ref.ID, strandedDAG, f.ref.ID, attempt.ID())
	require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
		Target: strandedDAG, DAGRunID: f.ref.ID, AttemptID: attempt.ID(), AttemptKey: key,
		ExecutionMarker: admission.Status.QueuedAt,
		Owner:           dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055},
	}))
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: time.Minute})
	require.NoError(t, err)
	require.NotNil(t, claimed)

	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: key,
	})
	require.NoError(t, err)
	assert.True(t, resp.Accepted, resp.Error)
}

// A sub-DAG attempt that Dispatch prepared and could not abandon on the spot
// stays journaled under its root, and reconciliation abandons it later.
func TestDispatchSubDAGPreparationLeftBehindIsReconciled(t *testing.T) {
	t.Parallel()
	registerCommandExecutorCapsForCoordinatorTest()
	dir := t.TempDir()
	gated := &evidenceGatedDispatchStore{DispatchTaskStore: newTestDispatchTaskStore(filepath.Join(dir, "d"))}
	gated.unknown.Store(true)
	f := newStrandedFixture(t, gated)
	child := ir.NewDAGRunRef("child-dag", "child-run")

	_, err := f.h.Dispatch(t.Context(), &coordinatorv1.DispatchRequest{Task: &coordinatorv1.Task{
		DagRunId:         child.ID,
		Target:           child.Name,
		RootDagRunName:   f.ref.Name,
		RootDagRunId:     f.ref.ID,
		ParentDagRunName: f.ref.Name,
		ParentDagRunId:   f.ref.ID,
		Definition:       "name: " + child.Name + "\nsteps:\n  - name: step1\n    run: echo hello",
		QueueName:        "q",
	}})
	require.Error(t, err)
	entries, err := f.repository.ListAttemptPreparations(t.Context())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, child, entries[0].Run)
	assert.Equal(t, f.ref, entries[0].RootRun)

	gated.unknown.Store(false)
	f.h.reconcileAbandonedPreparations(t.Context(), later())

	assert.Empty(t, f.preparations(t))
	records, err := f.repository.ListAttemptAbandonments(t.Context(), child, f.ref)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, entries[0].AttemptID, records[0].AbandonedAttemptID)
}
