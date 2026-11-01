// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
)

// A machine on the worker channel reaches the hub's REST routes with its worker
// credential. It is held to its own owner in every mode, off included: the hub's
// mode describes the private path, and this address is public.
func TestAWorkerCredentialIsHeldToItsOwnerInEveryMode(t *testing.T) {
	for _, mode := range []string{"", config.TXEAuthzModeOff, config.TXEAuthzModeObserve, config.TXEAuthzModeEnforce} {
		t.Run("mode "+mode, func(t *testing.T) {
			w := newTwoOwners(t, mode)
			require.NoError(t, w.getJob(w.workerA, w.jobA))
			require.Equal(t, http.StatusNotFound, statusOf(w.getJob(w.workerA, w.jobB)))
			require.Equal(t, []string{w.jobA}, w.listJobs(w.workerA))

			// A job's results are published by its own machine only.
			w.markReady(w.jobB, w.machineB)
			attemptID := w.addRun(w.jobB, "run-1", "production")
			_, err := w.api.RecordTxeRunArtifacts(w.workerA, apigen.RecordTxeRunArtifactsRequestObject{JobId: w.jobB, RunId: "run-1",
				Body: &apigen.RecordTxeRunArtifactsJSONRequestBody{AttemptId: attemptID, QueuedAt: "q1", JobVersion: 1}})
			require.Equal(t, http.StatusNotFound, statusOf(err))
			manifests, err := w.reg.ListArtifacts(context.Background(), w.jobB, "run-1")
			require.NoError(t, err)
			require.Empty(t, manifests)
		})
	}
}
