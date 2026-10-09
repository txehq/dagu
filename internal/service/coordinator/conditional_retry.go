// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/proto/convert"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// expectedLatest returns the execution a conditional retry requires to be the
// run's latest: the previous status's (attempt, queue marker). It is nil for
// any other task.
func expectedLatest(task *coordinatorv1.Task) (*persis.ExpectedExecution, error) {
	if !task.RequireLatestIsPrevious {
		return nil, nil
	}
	if task.Operation != coordinatorv1.Operation_OPERATION_RETRY {
		return nil, fmt.Errorf("%w: a conditional dispatch must be a retry", persis.ErrLatestExecutionChanged)
	}
	prev, err := convert.ProtoToDAGRunStatus(task.PreviousStatus)
	if err != nil {
		return nil, err
	}
	if prev == nil || prev.AttemptID == "" {
		return nil, fmt.Errorf("%w: a conditional retry needs the previous execution", persis.ErrLatestExecutionChanged)
	}
	return &persis.ExpectedExecution{AttemptID: prev.AttemptID, QueuedAt: prev.QueuedAt}, nil
}

// admittedResponse names the execution a dispatch admitted: the prepared
// attempt and the queued-at its statuses will carry, which is what the
// registry and the publisher read back. A worker's statuses carry the
// retried status's queued-at (a direct retry of a queued run inherits it),
// else the task's own marker, empty here. Without a prepared attempt the
// response names nothing.
func admittedResponse(task *coordinatorv1.Task, prepared *preparedDispatchAttempt) *coordinatorv1.DispatchResponse {
	if prepared == nil || prepared.attempt == nil {
		return &coordinatorv1.DispatchResponse{}
	}
	return &coordinatorv1.DispatchResponse{AttemptId: prepared.attempt.ID(), QueuedAt: admittedQueuedAt(task)}
}

// admittedQueuedAt is the queued-at every status of the task's execution
// carries, the coordinator's initial one included: the retried status's
// (a direct retry of a queued run inherits it), else none on this base (on
// main: the task's execution marker, as the worker's taskQueuedAt).
func admittedQueuedAt(task *coordinatorv1.Task) string {
	if prev, err := convert.ProtoToDAGRunStatus(task.PreviousStatus); err == nil && prev != nil {
		return prev.QueuedAt
	}
	return ""
}
