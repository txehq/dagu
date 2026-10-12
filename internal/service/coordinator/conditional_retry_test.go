// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	filedagrun "github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
	"github.com/dagucloud/dagu/v2/internal/proto/convert"
	"github.com/dagucloud/dagu/v2/internal/testutil"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// A conditional retry dispatch creates no attempt unless the run's latest
// execution is the previous status's: a later execution of the attempt, or
// a retry someone else already queued, is refused with ABORTED.
func TestDispatchConditionalRetryRefusesAnotherLatestExecution(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	ctx := context.Background()
	dir := t.TempDir()
	repo := testutil.NewFileDAGRunRepository(filepath.Join(dir, "runs"), persis.DAGRunRepositoryOptions{})
	dag := &ir.DAG{Name: "test-dag"}
	first, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-123", persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	write := func(st ir.Status, queuedAt string) *ir.DAGRunStatus {
		s := ir.InitialStatus(dag)
		s.DAGRunID, s.AttemptID, s.Status, s.QueuedAt = "run-123", first.ID(), st, queuedAt
		require.NoError(t, first.Open(ctx))
		require.NoError(t, first.Write(ctx, s))
		require.NoError(t, first.Close(ctx))
		return &s
	}
	approved := write(ir.Failed, "q1")
	previous, err := convert.DAGRunStatusToProto(approved)
	require.NoError(t, err)

	dispatchStore := newTestDispatchTaskStore(filepath.Join(dir, "distributed"))
	heartbeatStore := newTestWorkerHeartbeatStore(filepath.Join(dir, "distributed"))
	require.NoError(t, heartbeatStore.Upsert(ctx, dispatch.WorkerHeartbeatRecord{WorkerID: "worker-1", LastHeartbeatAt: time.Now().UTC().UnixMilli()}))
	h := NewHandler(HandlerConfig{DAGRunRepository: repo, DispatchTaskStore: dispatchStore, WorkerHeartbeatStore: heartbeatStore})
	// Release the attempts it keeps open, before the temp dir is removed
	// (Windows cannot delete an open file).
	t.Cleanup(func() { h.Close(context.Background()) })
	dispatchRetry := func() error {
		_, err := h.Dispatch(ctx, &coordinatorv1.DispatchRequest{Task: &coordinatorv1.Task{
			Operation: coordinatorv1.Operation_OPERATION_RETRY, DagRunId: "run-123", Target: "test-dag",
			Definition: "name: test-dag\nsteps:\n  - name: step1\n    run: echo hello", QueueName: "test-queue",
			PreviousStatus: previous, RequireLatestIsPrevious: true,
		}})
		return err
	}
	latestAttempt := func() string {
		a, err := repo.FindAttempt(ctx, ir.NewDAGRunRef(dag.Name, "run-123"))
		require.NoError(t, err)
		return a.ID()
	}

	for _, tc := range []struct {
		name     string
		st       ir.Status
		queuedAt string
	}{
		{"a later execution of the attempt", ir.Failed, "q2"},
		{"a retry someone else queued", ir.Queued, "q2"},
	} {
		write(tc.st, tc.queuedAt)
		err := dispatchRetry()
		st, ok := status.FromError(err)
		require.True(t, ok, tc.name)
		assert.Equal(t, codes.Aborted, st.Code(), tc.name)
		assert.Equal(t, first.ID(), latestAttempt(), "%s: no attempt was created", tc.name)
		count, err := dispatchStore.CountOutstandingByQueue(ctx, "test-queue", time.Second)
		require.NoError(t, err)
		assert.Zero(t, count, "%s: nothing was dispatched", tc.name)
	}
}

// racingCreateStore lets another retry finish a later execution of the
// attempt after the handler has read the run and just before the store takes
// the run's lock to create the retry's attempt.
type racingCreateStore struct {
	persis.DAGRunStore
	race func()
}

func (s *racingCreateStore) CreateAttempt(ctx context.Context, req persis.DAGRunCreateAttemptRequest) (dagrun.Attempt, error) {
	if s.race != nil {
		s.race()
		s.race = nil
	}
	return s.DAGRunStore.CreateAttempt(ctx, req)
}

// The expected execution is the latest when the handler reads the run, and
// another execution finishes before the attempt is created: the dispatch is
// refused with ABORTED by the check under the run's lock, and nothing is
// created or dispatched.
func TestDispatchConditionalRetryRefusesARaceBeforeCreation(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	ctx := context.Background()
	dir := t.TempDir()
	backend := &racingCreateStore{DAGRunStore: filedagrun.NewStore(filepath.Join(dir, "runs"))}
	repo := persis.NewDAGRunRepository(backend, filedagrun.NewWorkDirStore(filepath.Join(dir, "work"), filepath.Join(dir, "runs")), persis.DAGRunRepositoryOptions{})
	dag := &ir.DAG{Name: "test-dag"}
	first, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-123", persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	approved := ir.InitialStatus(dag)
	approved.DAGRunID, approved.AttemptID, approved.Status, approved.QueuedAt = "run-123", first.ID(), ir.Failed, "q1"
	require.NoError(t, first.Open(ctx))
	require.NoError(t, first.Write(ctx, approved))
	require.NoError(t, first.Close(ctx))
	previous, err := convert.DAGRunStatusToProto(&approved)
	require.NoError(t, err)
	backend.race = func() {
		_, swapped, err := repo.CompareAndSwapLatestAttemptStatus(ctx, ir.NewDAGRunRef(dag.Name, "run-123"), first.ID(), ir.Failed,
			func(s *ir.DAGRunStatus) error { s.QueuedAt = "q2"; return nil }, persis.DAGRunCompareAndSwapOptions{})
		require.NoError(t, err)
		require.True(t, swapped)
	}

	dispatchStore := newTestDispatchTaskStore(filepath.Join(dir, "distributed"))
	heartbeatStore := newTestWorkerHeartbeatStore(filepath.Join(dir, "distributed"))
	require.NoError(t, heartbeatStore.Upsert(ctx, dispatch.WorkerHeartbeatRecord{WorkerID: "worker-1", LastHeartbeatAt: time.Now().UTC().UnixMilli()}))
	h := NewHandler(HandlerConfig{DAGRunRepository: repo, DispatchTaskStore: dispatchStore, WorkerHeartbeatStore: heartbeatStore})
	// Release the attempts it keeps open, before the temp dir is removed
	// (Windows cannot delete an open file).
	t.Cleanup(func() { h.Close(context.Background()) })
	_, err = h.Dispatch(ctx, &coordinatorv1.DispatchRequest{Task: &coordinatorv1.Task{
		Operation: coordinatorv1.Operation_OPERATION_RETRY, DagRunId: "run-123", Target: "test-dag",
		Definition: "name: test-dag\nsteps:\n  - name: step1\n    run: echo hello", QueueName: "test-queue",
		PreviousStatus: previous, RequireLatestIsPrevious: true,
	}})
	require.Nil(t, backend.race, "the race ran")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Aborted, st.Code())
	assert.Contains(t, st.Message(), persis.ErrLatestExecutionChanged.Error())

	a, err := repo.FindAttempt(ctx, ir.NewDAGRunRef(dag.Name, "run-123"))
	require.NoError(t, err)
	assert.Equal(t, first.ID(), a.ID(), "no attempt was created")
	latest, err := a.ReadStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, "q2", latest.QueuedAt, "the later execution is untouched")
	count, err := dispatchStore.CountOutstandingByQueue(ctx, "test-queue", time.Second)
	require.NoError(t, err)
	assert.Zero(t, count, "nothing was dispatched")
}

// A dispatch names the attempt it prepared and the queued-at that attempt's
// statuses will carry: a direct retry keeps the retried status's queued-at
// (the run was queued before), and a run never queued has none.
func TestAdmittedResponseNamesTheSavedExecution(t *testing.T) {
	attempt := &testutil.MockAttempt{}
	attempt.On("ID").Return("attempt-2")
	prepared := &preparedDispatchAttempt{attempt: attempt}
	task := func(queuedAt string) *coordinatorv1.Task {
		prev, err := convert.DAGRunStatusToProto(&ir.DAGRunStatus{Name: "d", DAGRunID: "r", AttemptID: "attempt-1", Status: ir.Failed, QueuedAt: queuedAt})
		require.NoError(t, err)
		return &coordinatorv1.Task{Operation: coordinatorv1.Operation_OPERATION_RETRY, PreviousStatus: prev}
	}
	got := admittedResponse(task("2026-10-09T12:00:00Z"), prepared)
	assert.Equal(t, "attempt-2", got.GetAttemptId())
	assert.Equal(t, "2026-10-09T12:00:00Z", got.GetQueuedAt(), "a direct retry of a queued run keeps its queued-at")
	got = admittedResponse(task(""), prepared)
	assert.Equal(t, "attempt-2", got.GetAttemptId())
	assert.Empty(t, got.GetQueuedAt(), "never queued")
	assert.Empty(t, admittedResponse(task(""), nil).GetAttemptId(), "nothing prepared, nothing named")
}

// Through the real Dispatch and file store, the receipt names exactly the
// execution the saved statuses carry: the new attempt with the retried
// status's queued-at for a run queued before, none for a run never queued.
func TestDispatchReceiptMatchesTheSavedExecution(t *testing.T) {
	// The worker's rule (taskQueuedAt): the retried status's queued-at when it
	// has one, else the task's execution marker. A conditional retry always
	// creates a new attempt, whose marker the coordinator clears, so a marker
	// the caller sent never reaches the receipt or the saved status.
	for _, tc := range []struct{ queuedAt, marker, want string }{
		{"2026-10-09T12:00:00Z", "", "2026-10-09T12:00:00Z"},
		{"2026-10-09T12:00:00Z", "2026-10-09T13:00:00Z", "2026-10-09T12:00:00Z"},
		{"", "", ""},
		{"", "2026-10-09T13:00:00Z", ""},
	} {
		queuedAt := tc.queuedAt
		t.Run("queuedAt="+queuedAt+",marker="+tc.marker, func(t *testing.T) {
			registerCommandExecutorCapsForCoordinatorTest()
			ctx := context.Background()
			dir := t.TempDir()
			repo := testutil.NewFileDAGRunRepository(filepath.Join(dir, "runs"), persis.DAGRunRepositoryOptions{})
			dag := &ir.DAG{Name: "test-dag"}
			first, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-123", persis.DAGRunCreateAttemptOptions{})
			require.NoError(t, err)
			s := ir.InitialStatus(dag)
			s.DAGRunID, s.AttemptID, s.Status, s.QueuedAt = "run-123", first.ID(), ir.Failed, queuedAt
			require.NoError(t, first.Open(ctx))
			require.NoError(t, first.Write(ctx, s))
			require.NoError(t, first.Close(ctx))
			previous, err := convert.DAGRunStatusToProto(&s)
			require.NoError(t, err)

			dispatchStore := newTestDispatchTaskStore(filepath.Join(dir, "distributed"))
			heartbeatStore := newTestWorkerHeartbeatStore(filepath.Join(dir, "distributed"))
			require.NoError(t, heartbeatStore.Upsert(ctx, dispatch.WorkerHeartbeatRecord{WorkerID: "worker-1", LastHeartbeatAt: time.Now().UTC().UnixMilli()}))
			h := NewHandler(HandlerConfig{DAGRunRepository: repo, DispatchTaskStore: dispatchStore, WorkerHeartbeatStore: heartbeatStore})
			// Release the attempts it keeps open, before the temp dir is removed
			// (Windows cannot delete an open file).
			t.Cleanup(func() { h.Close(context.Background()) })
			resp, err := h.Dispatch(ctx, &coordinatorv1.DispatchRequest{Task: &coordinatorv1.Task{
				Operation: coordinatorv1.Operation_OPERATION_RETRY, DagRunId: "run-123", Target: "test-dag",
				Definition: "name: test-dag\nsteps:\n  - name: step1\n    run: echo hello", QueueName: "test-queue",
				PreviousStatus: previous, RequireLatestIsPrevious: true, ExecutionMarker: tc.marker,
			}})
			require.NoError(t, err)
			require.NotEqual(t, first.ID(), resp.GetAttemptId(), "a new attempt")
			assert.Equal(t, tc.want, resp.GetQueuedAt())

			latest, err := repo.FindAttempt(ctx, ir.NewDAGRunRef(dag.Name, "run-123"))
			require.NoError(t, err)
			saved, err := latest.ReadStatus(ctx)
			require.NoError(t, err)
			assert.Equal(t, resp.GetAttemptId(), saved.AttemptID)
			assert.Equal(t, resp.GetQueuedAt(), saved.QueuedAt, "the initial status names the receipt's execution")
		})
	}
}

// A conditional retry's coordinator records on the admitted execution's
// initial status the correlation it derives from the task's action attempt,
// the run and the previous execution; the caller's own ID is never used.
func TestDispatchRecordsTheDerivedRetryRequest(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	ctx := context.Background()
	dir := t.TempDir()
	repo := testutil.NewFileDAGRunRepository(filepath.Join(dir, "runs"), persis.DAGRunRepositoryOptions{})
	dag := &ir.DAG{Name: "test-dag"}
	first, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-123", persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	s := ir.InitialStatus(dag)
	s.DAGRunID, s.AttemptID, s.Status, s.QueuedAt = "run-123", first.ID(), ir.Failed, "2026-10-09T12:00:00Z"
	s.RetryRequest = &ir.RetryRequest{ID: "earlier", ActionID: "act-0", ActionAttempt: "1", BindingDigest: "d", RetryOf: "x"}
	require.NoError(t, first.Open(ctx))
	require.NoError(t, first.Write(ctx, s))
	require.NoError(t, first.Close(ctx))
	previous, err := convert.DAGRunStatusToProto(&s)
	require.NoError(t, err)

	dispatchStore := newTestDispatchTaskStore(filepath.Join(dir, "distributed"))
	heartbeatStore := newTestWorkerHeartbeatStore(filepath.Join(dir, "distributed"))
	require.NoError(t, heartbeatStore.Upsert(ctx, dispatch.WorkerHeartbeatRecord{WorkerID: "worker-1", LastHeartbeatAt: time.Now().UTC().UnixMilli()}))
	h := NewHandler(HandlerConfig{DAGRunRepository: repo, DispatchTaskStore: dispatchStore, WorkerHeartbeatStore: heartbeatStore})
	t.Cleanup(func() { h.Close(context.Background()) })
	task := &coordinatorv1.Task{
		Operation: coordinatorv1.Operation_OPERATION_RETRY, DagRunId: "run-123", Target: "test-dag",
		Definition: "name: test-dag\nsteps:\n  - name: step1\n    run: echo hello", QueueName: "test-queue",
		PreviousStatus: previous, RequireLatestIsPrevious: true,
		RetryRequest: &coordinatorv1.RetryRequestProto{ActionId: "act-1", ActionAttempt: "2", BindingDigest: "sha256:d"},
	}
	_, err = h.Dispatch(ctx, &coordinatorv1.DispatchRequest{Task: task})
	require.NoError(t, err)

	want, err := ir.NewRetryRequest(ir.NewDAGRunRef("test-dag", "run-123"), first.ID(), s.QueuedAt, "act-1", "2", "sha256:d")
	require.NoError(t, err)
	latest, err := repo.FindAttempt(ctx, ir.NewDAGRunRef(dag.Name, "run-123"))
	require.NoError(t, err)
	require.NotEqual(t, first.ID(), latest.ID())
	saved, err := latest.ReadStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, saved.RetryRequest, "the initial status records the derived request, not the retried one's")

	// A retry that is not conditional cannot name an action attempt.
	_, err = admittedRetryRequest(&coordinatorv1.Task{Operation: coordinatorv1.Operation_OPERATION_RETRY, DagRunId: "run-123", Target: "test-dag",
		RetryRequest: &coordinatorv1.RetryRequestProto{ActionId: "act-1", ActionAttempt: "2", BindingDigest: "sha256:d"}})
	assert.ErrorIs(t, err, ir.ErrInvalidRetryRequest)
}

// A reported status keeps the stored execution's retry request only when it
// reports that execution; a report never sets or changes it.
func TestKeptRetryRequest(t *testing.T) {
	request := &ir.RetryRequest{ID: "r1", ActionID: "act-1", ActionAttempt: "1", BindingDigest: "d", RetryOf: "x"}
	stored := &ir.DAGRunStatus{AttemptID: "a1", QueuedAt: "q1", RetryRequest: request}
	assert.Equal(t, request, keptRetryRequest(stored, &ir.DAGRunStatus{AttemptID: "a1", QueuedAt: "q1"}), "an empty report keeps it")
	assert.Equal(t, request, keptRetryRequest(stored, &ir.DAGRunStatus{AttemptID: "a1", QueuedAt: "q1",
		RetryRequest: &ir.RetryRequest{ID: "forged"}}), "a report cannot change it")
	assert.Nil(t, keptRetryRequest(stored, &ir.DAGRunStatus{AttemptID: "a1", QueuedAt: "q2"}), "another execution of the attempt")
	assert.Nil(t, keptRetryRequest(stored, &ir.DAGRunStatus{AttemptID: "a2", QueuedAt: "q1"}), "another attempt")
	assert.Nil(t, keptRetryRequest(&ir.DAGRunStatus{AttemptID: "a1", QueuedAt: "q1"}, &ir.DAGRunStatus{AttemptID: "a1", QueuedAt: "q1",
		RetryRequest: request}), "a report cannot set one")
}

// A task that names a retry request but is no conditional retry is refused
// before any attempt is created; the request is never silently dropped.
func TestDispatchRefusesAStrayRetryRequest(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	ctx := context.Background()
	dir := t.TempDir()
	repo := testutil.NewFileDAGRunRepository(filepath.Join(dir, "runs"), persis.DAGRunRepositoryOptions{})
	dag := &ir.DAG{Name: "test-dag"}
	first, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-123", persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	s := ir.InitialStatus(dag)
	s.DAGRunID, s.AttemptID, s.Status = "run-123", first.ID(), ir.Failed
	require.NoError(t, first.Open(ctx))
	require.NoError(t, first.Write(ctx, s))
	require.NoError(t, first.Close(ctx))
	previous, err := convert.DAGRunStatusToProto(&s)
	require.NoError(t, err)
	dispatchStore := newTestDispatchTaskStore(filepath.Join(dir, "distributed"))
	heartbeatStore := newTestWorkerHeartbeatStore(filepath.Join(dir, "distributed"))
	require.NoError(t, heartbeatStore.Upsert(ctx, dispatch.WorkerHeartbeatRecord{WorkerID: "worker-1", LastHeartbeatAt: time.Now().UTC().UnixMilli()}))
	h := NewHandler(HandlerConfig{DAGRunRepository: repo, DispatchTaskStore: dispatchStore, WorkerHeartbeatStore: heartbeatStore})
	t.Cleanup(func() { h.Close(context.Background()) })

	_, err = h.Dispatch(ctx, &coordinatorv1.DispatchRequest{Task: &coordinatorv1.Task{
		Operation: coordinatorv1.Operation_OPERATION_RETRY, DagRunId: "run-123", Target: "test-dag",
		Definition: "name: test-dag\nsteps:\n  - name: step1\n    run: echo hello", QueueName: "test-queue",
		PreviousStatus: previous,
		RetryRequest:   &coordinatorv1.RetryRequestProto{ActionId: "act-1", ActionAttempt: "1", BindingDigest: "d"},
	}})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	latest, err := repo.FindAttempt(ctx, ir.NewDAGRunRef(dag.Name, "run-123"))
	require.NoError(t, err)
	assert.Equal(t, first.ID(), latest.ID(), "no attempt was created")
}

// Without run storage, Dispatch still refuses a malformed retry request at
// entry: one on a conditional start, or on a retry with no expected attempt.
func TestDispatchRefusesAMalformedRetryRequestWithoutStorage(t *testing.T) {
	ctx := context.Background()
	failed := ir.DAGRunStatus{Name: "test-dag", DAGRunID: "run-123", AttemptID: "a1", Status: ir.Failed}
	previous, err := convert.DAGRunStatusToProto(&failed)
	require.NoError(t, err)
	noAttempt := failed
	noAttempt.AttemptID = ""
	previousNoAttempt, err := convert.DAGRunStatusToProto(&noAttempt)
	require.NoError(t, err)
	spec := &coordinatorv1.RetryRequestProto{ActionId: "act-1", ActionAttempt: "1", BindingDigest: "d"}
	for name, task := range map[string]*coordinatorv1.Task{
		"conditional start":   {Operation: coordinatorv1.Operation_OPERATION_START, PreviousStatus: previous},
		"no expected attempt": {Operation: coordinatorv1.Operation_OPERATION_RETRY, PreviousStatus: previousNoAttempt},
	} {
		t.Run(name, func(t *testing.T) {
			h := NewHandler(HandlerConfig{})
			t.Cleanup(func() { h.Close(context.Background()) })
			task.DagRunId, task.Target, task.QueueName = "run-123", "test-dag", "test-queue"
			task.Definition = "name: test-dag\nsteps:\n  - name: step1\n    run: echo hello"
			task.RequireLatestIsPrevious, task.RetryRequest = true, spec
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, err := h.Dispatch(ctx, &coordinatorv1.DispatchRequest{Task: task})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), ir.ErrInvalidRetryRequest.Error())
		})
	}
}
