// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/proto/convert"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A queued retry reuses the attempt key, so a cancellation that names an
// execution marker must cancel only that execution. A directive without a
// marker keeps cancelling whatever runs under the key.
func TestProcessCancellationsScopesToExecutionMarker(t *testing.T) {
	t.Parallel()

	const key = "attempt-key"
	marker := func(s string) *string { return &s }

	tests := []struct {
		name      string
		running   string
		directive *coordinatorv1.CancelledRun
		cancelled bool
	}{
		{"earlier execution's directive spares the current one", "q2", &coordinatorv1.CancelledRun{AttemptKey: key, ExecutionMarker: marker("q1")}, false},
		{"matching marker cancels", "q2", &coordinatorv1.CancelledRun{AttemptKey: key, ExecutionMarker: marker("q2")}, true},
		{"empty marker names a direct start", "", &coordinatorv1.CancelledRun{AttemptKey: key, ExecutionMarker: marker("")}, true},
		{"empty marker spares a queued execution", "q2", &coordinatorv1.CancelledRun{AttemptKey: key, ExecutionMarker: marker("")}, false},
		{"no marker cancels by key", "q2", &coordinatorv1.CancelledRun{AttemptKey: key}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w := &Worker{
				runningTasks: map[string]*runningTaskState{
					key: {task: &coordinatorv1.RunningTask{AttemptKey: key, ExecutionMarker: tc.running}},
				},
				cancelFuncs: map[string]context.CancelFunc{key: cancel},
			}

			w.processCancellations(context.Background(), []*coordinatorv1.CancelledRun{tc.directive})
			assert.Equal(t, tc.cancelled, ctx.Err() != nil)
		})
	}
}

// A load or init failure is reported before the agent runs, so it must carry
// the queued-at the agent would have echoed; otherwise two failed executions
// of one attempt both report an empty queued-at and cannot be told apart.
func TestTaskQueuedAt(t *testing.T) {
	t.Parallel()

	previous, err := convert.DAGRunStatusToProto(&ir.DAGRunStatus{
		Name: "dag", DAGRunID: "run", AttemptID: "a1", Status: ir.Queued, QueuedAt: "2026-10-10T01:05:00Z",
	})
	require.NoError(t, err)
	assert.Equal(t, "2026-10-10T01:05:00Z", taskQueuedAt(&coordinatorv1.Task{PreviousStatus: previous, ExecutionMarker: "other"}))
	assert.Equal(t, "2026-10-10T01:05:00Z", taskQueuedAt(&coordinatorv1.Task{ExecutionMarker: "2026-10-10T01:05:00Z"}))
	assert.Equal(t, "", taskQueuedAt(&coordinatorv1.Task{}))
}

// Both reports sent before the agent starts carry the execution's queued-at.
func TestFailureReportsCarryQueuedAt(t *testing.T) {
	t.Parallel()

	task := &coordinatorv1.Task{
		Target: "dag", DagRunId: "run-1", AttemptId: "attempt-1", ExecutionMarker: "2026-10-10T01:05:00Z",
	}
	root := ir.NewDAGRunRef("dag", "run-1")
	loaded, err := ReportTaskLoadFailureStatusForTest(context.Background(), task, root, ir.DAGRunRef{}, errors.New("load failed"), "")
	require.NoError(t, err)
	assert.Equal(t, "2026-10-10T01:05:00Z", loaded.QueuedAt)
	initialized, err := ReportTaskInitFailureStatusForTest(context.Background(), task, root, ir.DAGRunRef{}, errors.New("init failed"), "")
	require.NoError(t, err)
	assert.Equal(t, "2026-10-10T01:05:00Z", initialized.QueuedAt)
}
