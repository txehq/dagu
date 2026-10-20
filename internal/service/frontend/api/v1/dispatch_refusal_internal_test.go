// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
)

var (
	errRefusedNoMatch  = fmt.Errorf("all coordinators failed: %w", status.Error(codes.FailedPrecondition, dispatch.NoMatchingWorkersMessage))
	errRefusedNoWorker = status.Error(codes.Unavailable, dispatch.NoAvailableWorkersMessage)
)

func startWith(a *API, dag *ir.DAG, dispatchErr error) error {
	a.coordinatorCli = &stubCoordinatorClient{dispatchErr: dispatchErr}
	return a.dispatchStartToCoordinator(context.Background(), dag, startDAGRunOptions{dagRunID: "r1"}, "", time.Second)
}

func requireAnswer(t *testing.T, err error, status int, code string, msgAndArgs ...any) {
	t.Helper()
	var apiErr *Error
	require.True(t, errors.As(err, &apiErr), msgAndArgs...)
	assert.Equal(t, status, apiErr.HTTPStatus, msgAndArgs...)
	assert.Equal(t, code, apiErr.Details["code"], msgAndArgs...)
}

// A start the coordinator refuses for want of a worker is answered with what
// the caller can do, by a stable code, and not as an internal error. A
// refusal that does not show nothing was dispatched, and any other failure,
// are reported as before (TXE-4712).
func TestStartRefusedForWantOfAWorker(t *testing.T) {
	a := &API{config: &config.Config{}}
	dag := &ir.DAG{Name: "nightly", WorkerSelector: map[string]string{"os": "linux"}}

	requireAnswer(t, startWith(a, dag, errRefusedNoMatch), http.StatusConflict, "no_eligible_worker", "no worker may take it")
	requireAnswer(t, startWith(a, dag, errRefusedNoWorker), http.StatusServiceUnavailable, "no_worker_available", "no worker at all")

	for name, err := range map[string]error{
		"a refusal after a call that may have dispatched": fmt.Errorf("%w: %w", coordinator.ErrDispatchOutcomeUnknown, errRefusedNoMatch),
		"another failure":                        status.Error(codes.Unavailable, "connection refused"),
		"a message that only mentions a refusal": errors.New(dispatch.NoMatchingWorkersMessage),
	} {
		err := startWith(a, dag, err)
		require.Error(t, err, name)
		var apiErr *Error
		assert.False(t, errors.As(err, &apiErr), "%s stays the error it was", name)
	}
}

// Where owners are enforced, the answer is drawn from the caller's DAG
// alone: whether it is pinned to a machine. Which workers the coordinator
// sees, other owners' machines among them, makes no difference to it.
func TestStartRefusalUnderEnforceNamesOnlyTheCallersDAG(t *testing.T) {
	w := newTwoOwners(t, "enforce")
	pinned := &ir.DAG{Name: "pinned", WorkerSelector: map[string]string{dispatch.MachineLabel: w.machineA}}
	unpinned := &ir.DAG{Name: "unpinned"}
	for _, refusal := range []error{errRefusedNoMatch, errRefusedNoWorker} {
		requireAnswer(t, startWith(w.api, pinned, refusal), http.StatusServiceUnavailable, "machine_worker_unavailable", refusal.Error())
		requireAnswer(t, startWith(w.api, unpinned, refusal), http.StatusConflict, "dag_not_pinned", refusal.Error())
	}
	var apiErr *Error
	require.True(t, errors.As(startWith(w.api, pinned, errRefusedNoMatch), &apiErr))
	assert.NotContains(t, apiErr.Message, w.machineA, "the answer names no machine")
}

// A run the coordinator accepted but that was not seen to start is not said
// to have failed: it may yet start, and its ID is given to read it by.
func TestStartUnconfirmedNamesTheRun(t *testing.T) {
	err := errStartUnconfirmed("r1", 30*time.Second)
	assert.Equal(t, http.StatusGatewayTimeout, err.HTTPStatus)
	assert.Equal(t, "start_unconfirmed", err.Details["code"])
	assert.Equal(t, "r1", err.Details["dag_run_id"])
	assert.Contains(t, err.Message, "30s")
	assert.NotContains(t, err.Message, "has not run")
}

// A start of selected steps goes to the coordinator as a seeded run, and is
// answered the same way.
func TestSeededStartRefusedForWantOfAWorker(t *testing.T) {
	a := &API{config: &config.Config{}, coordinatorCli: &stubCoordinatorClient{dispatchErr: errRefusedNoMatch}}
	dag := &ir.DAG{Name: "nightly", WorkerSelector: map[string]string{"os": "linux"}}
	err := a.dispatchSeededRun(context.Background(), dag, &ir.DAGRunStatus{Name: "nightly", DAGRunID: "r1"}, "")
	requireAnswer(t, err, http.StatusConflict, "no_eligible_worker")
}

// A retry bound to the worker holding its agent session is refused as
// waiting for that worker, not as a selector to change; one whose outcome
// is unknown stays unclassified.
func TestTargetedRetryRefusalNamesTheSessionWorker(t *testing.T) {
	a := &API{config: &config.Config{}}
	dag := &ir.DAG{Name: "agent"}
	targeted := &dispatch.DispatchTask{TargetWorkerID: "worker-1"}
	requireAnswer(t, a.retryDispatchRefusal(errRefusedNoMatch, dag, targeted), http.StatusServiceUnavailable, "session_worker_unavailable")
	requireAnswer(t, a.retryDispatchRefusal(errRefusedNoMatch, dag, &dispatch.DispatchTask{}), http.StatusConflict, "no_eligible_worker")
	assert.Nil(t, a.retryDispatchRefusal(fmt.Errorf("%w: %w", coordinator.ErrDispatchOutcomeUnknown, errRefusedNoMatch), dag, targeted))
}
