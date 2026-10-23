// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/proto/convert"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// The retried execution a worker gives its agent (TXE-5067) is the one the
// coordinator records on the execution it admitted, and only a conditional
// retry made for an action attempt has one.
func TestTaskRetryOf(t *testing.T) {
	prev, err := convert.DAGRunStatusToProto(&ir.DAGRunStatus{Name: "job_1", DAGRunID: "run-1", AttemptID: "e01fc7", QueuedAt: "", Status: ir.Failed})
	require.NoError(t, err)
	task := func(mutate func(*coordinatorv1.Task)) *coordinatorv1.Task {
		task := &coordinatorv1.Task{
			Operation: coordinatorv1.Operation_OPERATION_RETRY, Target: "job_1", DagRunId: "run-1",
			PreviousStatus: prev, RequireLatestIsPrevious: true,
			RetryRequest: &coordinatorv1.RetryRequestProto{ActionId: "act_1", ActionAttempt: "1", BindingDigest: "bd"},
		}
		if mutate != nil {
			mutate(task)
		}
		return task
	}

	recorded, err := ir.NewRetryRequest(ir.NewDAGRunRef("job_1", "run-1"), "e01fc7", "", "act_1", "1", "bd")
	require.NoError(t, err)
	assert.Equal(t, recorded.RetryOf, taskRetryOf(task(nil)))
	assert.Equal(t, ir.ExecutionRef("e01fc7", ""), taskRetryOf(task(nil)))

	for name, mutate := range map[string]func(*coordinatorv1.Task){
		"not conditional":       func(t *coordinatorv1.Task) { t.RequireLatestIsPrevious = false },
		"made for no action":    func(t *coordinatorv1.Task) { t.RetryRequest = nil },
		"a start":               func(t *coordinatorv1.Task) { t.Operation = coordinatorv1.Operation_OPERATION_START },
		"no previous execution": func(t *coordinatorv1.Task) { t.PreviousStatus = nil },
		"an incomplete request": func(t *coordinatorv1.Task) { t.RetryRequest.BindingDigest = "" },
	} {
		assert.Empty(t, taskRetryOf(task(mutate)), name)
	}
}
