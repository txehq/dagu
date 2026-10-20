// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
)

// A run the coordinator refuses for want of a worker is answered by what
// the caller can do about it, not as an internal error (TXE-4712).
//
// Where owners are enforced the answer is drawn from the caller's own DAG
// alone, whether it is pinned to a machine, and never from which workers
// the coordinator sees: those include other owners' machines, whose
// presence is not the caller's to learn.
var (
	errNoEligibleWorker = &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
		Message: "no connected worker may run this DAG: none matches its worker_selector. Connect a worker that does, " +
			"or change the selector",
		Details: map[string]any{"code": "no_eligible_worker"}}
	errNoWorkerAvailable = &Error{HTTPStatus: http.StatusServiceUnavailable, Code: api.ErrorCodeInternalError,
		Message: "no worker is connected to run this DAG; try again once one is",
		Details: map[string]any{"code": "no_worker_available"}}
	errDAGNotPinned = &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
		Message: "this DAG names no machine, and where owners are enforced a machine's worker runs only DAGs pinned to " +
			"it: pin the DAG with worker_selector txe.machine, or have a worker that is no machine's run it",
		Details: map[string]any{"code": "dag_not_pinned"}}
	errSessionWorkerUnavailable = &Error{HTTPStatus: http.StatusServiceUnavailable, Code: api.ErrorCodeInternalError,
		Message: "this retry resumes an agent session and must run on the worker that holds it, which is not connected; " +
			"reconnect that worker, or start the session again",
		Details: map[string]any{"code": "session_worker_unavailable"}}
	errMachineWorkerUnavailable = &Error{HTTPStatus: http.StatusServiceUnavailable, Code: api.ErrorCodeInternalError,
		Message: "no worker of the machine this DAG is pinned to may run it now: check that the machine's worker is " +
			"running and enrolled, and that it has every label the DAG's worker_selector names",
		Details: map[string]any{"code": "machine_worker_unavailable"}}
)

// dispatchRefusal returns the answer for the coordinator's refusal err of
// a run of dag, or nil when err is not a refusal that shows nothing was
// dispatched.
func (a *API) dispatchRefusal(err error, dag *ir.DAG) error {
	if errors.Is(err, coordinator.ErrDispatchOutcomeUnknown) || errors.Is(err, coordinator.ErrDispatchUncertain) {
		return nil
	}
	noMatch, noWorker := dispatch.IsNoMatchingWorker(err), dispatch.IsNoAvailableWorker(err)
	if !noMatch && !noWorker {
		return nil
	}
	if a.txeAuth != nil && a.txeAuth.Mode() == authz.ModeEnforce {
		if dag != nil && dag.WorkerSelector[dispatch.MachineLabel] != "" {
			return errMachineWorkerUnavailable
		}
		return errDAGNotPinned
	}
	if noMatch {
		return errNoEligibleWorker
	}
	return errNoWorkerAvailable
}

// retryDispatchRefusal is dispatchRefusal for a retry task. A retry that
// resumes an agent session must run on the worker holding the session, so
// when it is refused only that worker's return, not a selector change,
// makes it runnable.
func (a *API) retryDispatchRefusal(err error, dag *ir.DAG, task *dispatch.DispatchTask) error {
	refusal := a.dispatchRefusal(err, dag)
	if refusal != nil && task != nil && task.TargetWorkerID != "" {
		return errSessionWorkerUnavailable
	}
	return refusal
}

// errStartUnconfirmed answers a run the coordinator accepted whose start
// was not seen within timeout. It may yet start, or have started: its
// status could not be read, or a worker has not reported yet.
func errStartUnconfirmed(dagRunID string, timeout time.Duration) *Error {
	return &Error{HTTPStatus: http.StatusGatewayTimeout, Code: api.ErrorCodeTimeout,
		Message: fmt.Sprintf("the run was handed to a worker's coordinator but was not seen to start within %s; it may still "+
			"start: read run %s before starting it again", timeout, dagRunID),
		Details: map[string]any{"code": "start_unconfirmed", "dag_run_id": dagRunID}}
}
