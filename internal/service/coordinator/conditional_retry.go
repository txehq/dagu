// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/ir"
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
	request, err := admittedRetryRequest(task)
	if err != nil {
		return nil, err
	}
	return &persis.ExpectedExecution{AttemptID: prev.AttemptID, QueuedAt: prev.QueuedAt, Request: request}, nil
}

// admittedRetryRequest is the correlation a conditional retry's admitted
// execution records: derived here from the task's action attempt, the run
// and previous_status's execution, never taken from the caller. A task that
// is no conditional retry, or names no action attempt, records none.
func admittedRetryRequest(task *coordinatorv1.Task) (*ir.RetryRequest, error) {
	spec := task.GetRetryRequest()
	if spec == nil {
		return nil, nil
	}
	if !task.GetRequireLatestIsPrevious() || task.GetOperation() != coordinatorv1.Operation_OPERATION_RETRY {
		return nil, fmt.Errorf("%w: only a conditional retry names an action attempt", ir.ErrInvalidRetryRequest)
	}
	prev, err := convert.ProtoToDAGRunStatus(task.PreviousStatus)
	if err != nil {
		return nil, err
	}
	if prev == nil || prev.AttemptID == "" {
		return nil, fmt.Errorf("%w: no previous execution", ir.ErrInvalidRetryRequest)
	}
	return ir.NewRetryRequest(ir.NewDAGRunRef(task.GetTarget(), task.GetDagRunId()), prev.AttemptID, prev.QueuedAt,
		spec.GetActionId(), spec.GetActionAttempt(), spec.GetBindingDigest())
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
// when it has one (a direct retry of a queued run inherits it), else the
// task's execution marker. It is the worker's rule (taskQueuedAt in
// internal/service/worker), so the receipt names what the worker saves.
func admittedQueuedAt(task *coordinatorv1.Task) string {
	if prev, err := convert.ProtoToDAGRunStatus(task.PreviousStatus); err == nil && prev != nil && prev.QueuedAt != "" {
		return prev.QueuedAt
	}
	return task.GetExecutionMarker()
}

// refuseStrayRetryRequest refuses a task that names a retry request but is
// no root conditional retry, or whose request is invalid.
func refuseStrayRetryRequest(task *coordinatorv1.Task) error {
	if task.GetRetryRequest() == nil {
		return nil
	}
	isRoot := task.GetParentDagRunId() == "" && (task.GetRootDagRunId() == "" || task.GetRootDagRunId() == task.GetDagRunId())
	if !isRoot {
		return fmt.Errorf("%w: a sub-DAG run cannot name an action attempt", ir.ErrInvalidRetryRequest)
	}
	_, err := admittedRetryRequest(task)
	return err
}

// initialRetryRequest is the correlation the coordinator's initial status of
// a conditional retry records; prepareAttemptForDispatch has already refused
// a task whose request is invalid (refuseStrayRetryRequest).
func initialRetryRequest(task *coordinatorv1.Task) *ir.RetryRequest {
	request, err := admittedRetryRequest(task)
	if err != nil {
		return nil
	}
	return request
}

// keptRetryRequest is the retry request a reported status is written with:
// the stored execution's, when the report is of that execution (its attempt
// and queued-at); otherwise none. A worker's report never sets or changes it.
func keptRetryRequest(stored, reported *ir.DAGRunStatus) *ir.RetryRequest {
	if stored == nil || reported == nil || stored.AttemptID != reported.AttemptID || stored.QueuedAt != reported.QueuedAt {
		return nil
	}
	return stored.RetryRequest.Clone()
}
