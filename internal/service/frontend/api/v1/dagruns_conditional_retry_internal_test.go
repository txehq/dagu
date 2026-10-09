// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	openapiv1 "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file"
	filedagrun "github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
)

// racingRunStore lets another retry finish a later execution of the attempt
// just before the caller's compare-and-swap: the interleaving a conditional
// retry must refuse.
type racingRunStore struct {
	*filedagrun.Store
	raced bool
}

func (s *racingRunStore) CompareAndSwapLatestAttemptStatus(ctx context.Context, req persis.DAGRunCompareAndSwapStatusRequest) (*ir.DAGRunStatus, bool, error) {
	if !s.raced {
		s.raced = true
		other := req
		other.Mutate = func(st *ir.DAGRunStatus) error { st.QueuedAt = "q2"; return nil }
		if _, swapped, err := s.Store.CompareAndSwapLatestAttemptStatus(ctx, other); err != nil || !swapped {
			return nil, false, fmt.Errorf("race setup: swapped=%v: %w", swapped, err)
		}
	}
	return s.Store.CompareAndSwapLatestAttemptStatus(ctx, req)
}

type conditionalRetryFixture struct {
	api      *API
	dag      *ir.DAG
	attempt  string
	queue    *store.QueueStore
	recorder *retryCoordinatorRecorder
	runs     *persis.DAGRunRepository
}

func newConditionalRetryFixture(t *testing.T, queued, racing bool) *conditionalRetryFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dag := &ir.DAG{Name: "job", YamlData: []byte("name: job\nworker_selector:\n  region: apac\nsteps:\n  - name: main\n    run: echo hi\n"),
		WorkerSelector: map[string]string{"region": "apac"}}
	var backend persis.DAGRunStore = filedagrun.NewStore(filepath.Join(dir, "runs"))
	if racing {
		backend = &racingRunStore{Store: backend.(*filedagrun.Store)}
	}
	runs := persis.NewDAGRunRepository(backend, filedagrun.NewWorkDirStore(filepath.Join(dir, "work"), filepath.Join(dir, "runs")), persis.DAGRunRepositoryOptions{})
	attempt, err := runs.CreateAttempt(ctx, dag, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	status := ir.InitialStatus(dag)
	status.DAGRunID, status.AttemptID, status.Status, status.QueuedAt = "run-1", attempt.ID(), ir.Failed, "q1"
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, status))
	require.NoError(t, attempt.Close(ctx))

	cfg := &config.Config{Server: config.Server{Permissions: map[config.Permission]bool{config.PermissionRunDAGs: true}}}
	if queued {
		cfg.Queues = config.Queues{Enabled: true, Config: []config.QueueConfig{{Name: dag.Name, MaxActiveRuns: 1}}}
	}
	f := &conditionalRetryFixture{dag: dag, attempt: attempt.ID(), queue: store.NewQueueStore(file.NewCollection(filepath.Join(dir, "queue"))),
		recorder: &retryCoordinatorRecorder{}, runs: runs}
	f.api = &API{dagRunRepository: runs, config: cfg, coordinatorCli: f.recorder, defaultExecMode: config.ExecutionModeLocal, queueStore: f.queue}
	return f
}

func (f *conditionalRetryFixture) retry(attemptID, queuedAt string) error {
	_, err := f.api.RetryDAGRun(context.Background(), openapiv1.RetryDAGRunRequestObject{Name: f.dag.Name, DagRunId: "run-1",
		Body: &openapiv1.RetryDAGRunJSONRequestBody{DagRunId: "run-1", ExpectedAttemptId: &attemptID, ExpectedQueuedAt: &queuedAt}})
	return err
}

func requireConflictCode(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr *Error
	require.True(t, errors.As(err, &apiErr), "%v", err)
	assert.Equal(t, http.StatusConflict, apiErr.HTTPStatus)
	assert.Equal(t, code, apiErr.Details["code"])
}

func TestConditionalRetryQueued(t *testing.T) {
	t.Run("expected execution is queued", func(t *testing.T) {
		f := newConditionalRetryFixture(t, true, false)
		require.NoError(t, f.retry(f.attempt, "q1"))
		items, err := f.queue.List(context.Background(), f.dag.Name)
		require.NoError(t, err)
		assert.Len(t, items, 1)
	})
	t.Run("another execution read by the handler", func(t *testing.T) {
		f := newConditionalRetryFixture(t, true, false)
		requireConflictCode(t, f.retry(f.attempt, "q0"), "execution_changed")
		items, err := f.queue.List(context.Background(), f.dag.Name)
		require.NoError(t, err)
		assert.Empty(t, items)
	})
	t.Run("another execution finished between the read and the admission", func(t *testing.T) {
		f := newConditionalRetryFixture(t, true, true)
		requireConflictCode(t, f.retry(f.attempt, "q1"), "execution_changed")
		items, err := f.queue.List(context.Background(), f.dag.Name)
		require.NoError(t, err)
		assert.Empty(t, items, "nothing was queued")
		a, err := f.runs.FindAttempt(context.Background(), ir.NewDAGRunRef(f.dag.Name, "run-1"))
		require.NoError(t, err)
		st, err := a.ReadStatus(context.Background())
		require.NoError(t, err)
		assert.Equal(t, ir.Failed, st.Status)
		assert.Equal(t, "q2", st.QueuedAt, "the later execution is untouched")
	})
}

func TestConditionalRetryDistributed(t *testing.T) {
	t.Run("the task carries the condition", func(t *testing.T) {
		f := newConditionalRetryFixture(t, false, false)
		require.NoError(t, f.retry(f.attempt, "q1"))
		require.Len(t, f.recorder.dispatched, 1)
		task := f.recorder.dispatched[0]
		assert.Equal(t, dispatch.DispatchOperationRetry, task.Operation)
		assert.True(t, task.RequireLatestIsPrevious)
		assert.Equal(t, "q1", task.PreviousStatus.QueuedAt)
	})
	t.Run("the coordinator refuses at attempt creation", func(t *testing.T) {
		f := newConditionalRetryFixture(t, false, false)
		f.recorder.dispatchErr = fmt.Errorf("dispatch: %w", persis.ErrLatestExecutionChanged)
		requireConflictCode(t, f.retry(f.attempt, "q1"), "execution_changed")
	})
	t.Run("without the condition nothing changes", func(t *testing.T) {
		f := newConditionalRetryFixture(t, false, false)
		_, err := f.api.RetryDAGRun(context.Background(), openapiv1.RetryDAGRunRequestObject{Name: f.dag.Name, DagRunId: "run-1",
			Body: &openapiv1.RetryDAGRunJSONRequestBody{DagRunId: "run-1"}})
		require.NoError(t, err)
		require.Len(t, f.recorder.dispatched, 1)
		assert.False(t, f.recorder.dispatched[0].RequireLatestIsPrevious)
	})
}

func TestConditionalRetryRefusals(t *testing.T) {
	f := newConditionalRetryFixture(t, false, false)
	f.api.coordinatorCli = nil
	requireConflictCode(t, f.retry(f.attempt, "q1"), "conditional_retry_unsupported")

	attemptID := f.attempt
	_, err := f.api.RetryDAGRun(context.Background(), openapiv1.RetryDAGRunRequestObject{Name: f.dag.Name, DagRunId: "run-1",
		Body: &openapiv1.RetryDAGRunJSONRequestBody{DagRunId: "run-1", ExpectedAttemptId: &attemptID}})
	var apiErr *Error
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusBadRequest, apiErr.HTTPStatus, "both fields or neither")
}
