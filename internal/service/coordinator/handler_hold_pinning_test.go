// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// newPinnedHoldFixture is newHoldFixture under a machine pinning mode, with
// the given workers' heartbeats.
func newPinnedHoldFixture(t *testing.T, pinning dispatch.MachinePinning, workers map[string]map[string]string) *holdFixture {
	t.Helper()
	registerCommandExecutorCapsForCoordinatorTest()
	baseDir := t.TempDir()
	f := &holdFixture{
		runs:       newMockDAGRunStore(),
		heartbeats: newTestWorkerHeartbeatStore(baseDir),
		dispatches: newTestDispatchTaskStore(baseDir),
	}
	for id, labels := range workers {
		f.heartbeat(t, id, labels)
	}
	f.h = NewHandler(HandlerConfig{
		DAGRunRepository:     f.runs.repository,
		DispatchTaskStore:    f.dispatches,
		DAGRunLeaseStore:     newTestDAGRunLeaseStore(baseDir),
		WorkerHeartbeatStore: f.heartbeats,
		WorkerWaitTimeout:    time.Hour,
		MachinePinning:       pinning,
	})
	t.Cleanup(func() { f.h.Close(context.Background()) })
	return f
}

func pinnedTask(runID, machine string) *coordinatorv1.Task {
	return &coordinatorv1.Task{
		Operation:      coordinatorv1.Operation_OPERATION_START,
		DagRunId:       runID,
		Target:         "job_A",
		Definition:     "steps:\n  - name: wait\n    run: sleep 1\n",
		WorkerSelector: map[string]string{"txe.machine": machine},
	}
}

// With machines pinned, a dispatch no connected machine of its owner may take
// is refused at once even though a worker wait is configured (TXE-5923): no
// attempt is created and no task is stored. "No worker at all" and "only
// other owners' machines" get the same code and message, so the caller learns
// nothing about which other machines are connected.
func TestPinnedDispatchIsNeverHeld(t *testing.T) {
	cases := map[string]map[string]map[string]string{
		"no worker connected":     {},
		"another owner's machine": {"mch_B": {"txe.machine": "mch_B", "txe.owner": "own_B"}},
	}
	type answer struct {
		code    codes.Code
		message string
	}
	answers := map[string]answer{}
	for name, workers := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPinnedHoldFixture(t, dispatch.MachinePinningEnforce, workers)

			_, err := f.h.Dispatch(t.Context(), &coordinatorv1.DispatchRequest{Task: pinnedTask("run-1", "mch_A")})
			require.Error(t, err)
			answers[name] = answer{status.Code(err), status.Convert(err).Message()}
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.Equal(t, errNoMatchingWorkers.Error(), status.Convert(err).Message())

			assert.Nil(t, f.runs.attempts["run-1"], "no attempt is created for a refused dispatch")
			future := time.Now().Add(24 * time.Hour)
			unheld, err := f.dispatches.ListStalePending(t.Context(), future)
			require.NoError(t, err)
			held, err := f.dispatches.ListExpiredHeld(t.Context(), future)
			require.NoError(t, err)
			assert.Empty(t, unheld, "no task is stored for a refused dispatch")
			assert.Empty(t, held, "no task is held for a refused dispatch")
		})
	}
	assert.Equal(t, answers["no worker connected"], answers["another owner's machine"])
}

// In observe and off the configured wait applies: a dispatch no worker
// matches is held as Queued, and the machine that registers later takes it.
// Holding keeps the queuedAt the attempt was prepared with, so the identity
// the task carries (attempt id, execution marker) is the one its status
// names, and the claiming worker's first report is accepted.
func TestUnpinnedDispatchIsHeldWithItsIdentity(t *testing.T) {
	for _, pinning := range []dispatch.MachinePinning{dispatch.MachinePinningOff, dispatch.MachinePinningObserve} {
		t.Run(pinningName(pinning), func(t *testing.T) {
			f := newPinnedHoldFixture(t, pinning, map[string]map[string]string{
				"mch_B": {"txe.machine": "mch_B", "txe.owner": "own_B"},
			})
			ctx := t.Context()

			_, err := f.h.Dispatch(ctx, &coordinatorv1.DispatchRequest{Task: pinnedTask("run-held", "mch_A")})
			require.NoError(t, err)
			held := f.status(t, "run-held")
			assert.Equal(t, ir.Queued, held.Status)
			assert.Empty(t, held.QueuedAt, "a direct start keeps the empty queuedAt it was prepared with")

			labels := map[string]string{"txe.machine": "mch_A", "txe.owner": "own_A"}
			f.heartbeat(t, "mch_A", labels)
			pollCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			polled, err := f.h.Poll(pollCtx, &coordinatorv1.PollRequest{WorkerId: "mch_A", PollerId: "p-a", Labels: labels})
			require.NoError(t, err)
			require.NotNil(t, polled.Task)
			task := polled.Task
			assert.Equal(t, held.AttemptID, task.AttemptId)
			assert.Equal(t, held.QueuedAt, task.ExecutionMarker, "the task names the execution its status records")
		})
	}
}

func pinningName(p dispatch.MachinePinning) string {
	switch p {
	case dispatch.MachinePinningOff:
		return "off"
	case dispatch.MachinePinningObserve:
		return "observe"
	case dispatch.MachinePinningEnforce:
		return "enforce"
	default:
		return "unknown"
	}
}
