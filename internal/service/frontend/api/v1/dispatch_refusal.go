// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"fmt"
	"net/http"
	"time"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
)

// A run handed to the coordinator that no worker can take is answered by
// what the caller can do about it, not as an internal error (TXE-4712). The
// answers name nothing but the caller's own DAG: never another owner's
// machine, or whether one exists.
var (
	errNoEligibleWorker = &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
		Message: "no connected worker may run this DAG: none matches its worker_selector. Where owners are enforced, a machine's " +
			"worker runs only DAGs pinned to that machine (worker_selector txe.machine), and a DAG pinned to a machine runs " +
			"only on that machine's enrolled worker. Pin the DAG to its machine, or start that machine's worker",
		Details: map[string]any{"code": "no_eligible_worker"}}
	errNoWorkerAvailable = &Error{HTTPStatus: http.StatusServiceUnavailable, Code: api.ErrorCodeInternalError,
		Message: "no worker is connected to run this DAG; try again once one is",
		Details: map[string]any{"code": "no_worker_available"}}
)

// dispatchRefusal returns the answer for the coordinator's refusal err, or
// nil when err is not one: nothing was dispatched.
func dispatchRefusal(err error) error {
	switch {
	case dispatch.IsNoMatchingWorker(err):
		return errNoEligibleWorker
	case dispatch.IsNoAvailableWorker(err):
		return errNoWorkerAvailable
	default:
		return nil
	}
}

// errDispatchNotStarted answers a run the coordinator accepted that no
// worker started within timeout: a worker it expected to take the run did
// not, for example one that is no longer allowed to.
func errDispatchNotStarted(timeout time.Duration) *Error {
	return &Error{HTTPStatus: http.StatusServiceUnavailable, Code: api.ErrorCodeTimeout,
		Message: fmt.Sprintf("no worker started this run within %s, so it has not run; check that a worker this DAG may run on "+
			"is connected and, where owners are enforced, enrolled", timeout),
		Details: map[string]any{"code": "dispatch_not_started"}}
}
