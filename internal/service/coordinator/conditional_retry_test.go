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
