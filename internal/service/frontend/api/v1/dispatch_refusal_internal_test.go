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
)

// A start the coordinator refuses for want of a worker is answered with what
// the caller can do, by a stable code, and not as an internal error. The
// answer names nothing beyond the request. Any other failure is reported as
// before (TXE-4712).
func TestStartRefusedForWantOfAWorker(t *testing.T) {
	start := func(dispatchErr error) error {
		a := &API{config: &config.Config{}, coordinatorCli: &stubCoordinatorClient{dispatchErr: dispatchErr}}
		dag := &ir.DAG{Name: "job_A", WorkerSelector: map[string]string{dispatch.MachineLabel: "mch_A1"}}
		return a.dispatchStartToCoordinator(context.Background(), dag, startDAGRunOptions{dagRunID: "r1"}, "", time.Second)
	}
	for name, tc := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"no worker may take it": {fmt.Errorf("all coordinators failed: %w",
			status.Error(codes.FailedPrecondition, dispatch.NoMatchingWorkersMessage)), http.StatusConflict, "no_eligible_worker"},
		"no worker at all": {status.Error(codes.Unavailable, dispatch.NoAvailableWorkersMessage), http.StatusServiceUnavailable, "no_worker_available"},
	} {
		err := start(tc.err)
		var apiErr *Error
		require.True(t, errors.As(err, &apiErr), name)
		assert.Equal(t, tc.status, apiErr.HTTPStatus, name)
		assert.Equal(t, tc.code, apiErr.Details["code"], name)
		assert.NotContains(t, apiErr.Message, "mch_A1", "%s: the answer names no machine", name)
	}

	// Anything else is not taken for a refusal.
	err := start(status.Error(codes.Unavailable, "connection refused"))
	require.Error(t, err)
	var apiErr *Error
	assert.False(t, errors.As(err, &apiErr), "an unclassified failure stays the error it was")

	notStarted := errDispatchNotStarted(30 * time.Second)
	assert.Equal(t, http.StatusServiceUnavailable, notStarted.HTTPStatus)
	assert.Equal(t, "dispatch_not_started", notStarted.Details["code"])
	assert.Contains(t, notStarted.Message, "30s")
}
