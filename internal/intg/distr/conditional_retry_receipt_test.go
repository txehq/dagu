// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/runtime/executor"
)

// A conditional direct retry, through a real coordinator and an isolated
// worker, names exactly the execution the hub stores: the receipt equals the
// saved status right after admission and once the retry has ended. A retry
// that expects an execution which is no longer the latest creates nothing.
func TestConditionalDirectRetryReceiptIsTheSavedExecution(t *testing.T) {
	q := newQueuedAtFixture(t)
	f := q.f

	first := q.execution(t, 1, ir.Failed)
	require.NotEmpty(t, first.stored.QueuedAt, "the run was queued; a direct retry inherits that marker")

	require.NoError(t, os.WriteFile(filepath.Join(q.dir, "succeed"), nil, 0o600))
	dag := f.dagWrapper.DAG
	task := executor.CreateTask(dag.Name, string(dag.YamlData), dispatch.DispatchOperationRetry, first.stored.DAGRunID,
		executor.WithWorkerSelector(dag.WorkerSelector), executor.WithPreviousStatus(&first.stored),
		executor.WithRequireLatestIsPrevious(true))
	admitted := &dispatch.AdmittedExecution{}
	require.NoError(t, f.coord.GetCoordinatorClient(t).Dispatch(f.coord.Context, dispatch.DispatchRequest{Task: task, Admitted: admitted}))
	require.NotEmpty(t, admitted.AttemptID)
	assert.NotEqual(t, first.stored.AttemptID, admitted.AttemptID, "a direct retry is a new attempt")
	assert.Equal(t, first.stored.QueuedAt, admitted.QueuedAt, "it keeps the retried status's marker")

	saved, err := f.latestStatus()
	require.NoError(t, err)
	assert.Equal(t, admitted.AttemptID, saved.AttemptID, "right after admission")
	assert.Equal(t, admitted.QueuedAt, saved.QueuedAt, "right after admission")

	second := q.execution(t, 2, ir.Succeeded)
	assert.Equal(t, admitted.AttemptID, second.stored.AttemptID)
	assert.Equal(t, admitted.QueuedAt, second.stored.QueuedAt)
	assert.Equal(t, ir.ExecutionRef(admitted.AttemptID, admitted.QueuedAt), ir.ExecutionRef(second.stored.AttemptID, second.stored.QueuedAt))
	assert.Equal(t, second.stored.QueuedAt, second.inCommand, "the step saw the same execution")

	// The first execution is no longer the latest: a retry expecting it is
	// refused by the coordinator and creates nothing.
	stale := executor.CreateTask(dag.Name, string(dag.YamlData), dispatch.DispatchOperationRetry, first.stored.DAGRunID,
		executor.WithWorkerSelector(dag.WorkerSelector), executor.WithPreviousStatus(&first.stored),
		executor.WithRequireLatestIsPrevious(true))
	err = f.coord.GetCoordinatorClient(t).Dispatch(f.coord.Context, dispatch.DispatchRequest{Task: stale, Admitted: &dispatch.AdmittedExecution{}})
	require.ErrorIs(t, err, persis.ErrLatestExecutionChanged)
	after, err := f.latestStatus()
	require.NoError(t, err)
	assert.Equal(t, second.stored.AttemptID, after.AttemptID, "nothing was created")
}
