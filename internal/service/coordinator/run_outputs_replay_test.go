// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/proto/convert"
	"github.com/dagucloud/dagu/v2/internal/testutil"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

const outputsReplayDAG = "outputs-replay"

// outputsReplayFixture is a coordinator over real stores: the file run store,
// and the file-backed lease, active-run and admission stores the handler
// finalizes when a run ends. The worker is not real; its terminal report is
// delivered as the deployed worker delivers it, including its replay.
type outputsReplayFixture struct {
	h          *Handler
	repository *persis.DAGRunRepository
	admissions *store.DispatchTaskStore
	leases     *store.DAGRunLeaseStore
	active     *store.ActiveDistributedRunStore
	runsDir    string
	ref        ir.DAGRunRef
}

func newOutputsReplayFixture(t *testing.T) *outputsReplayFixture {
	t.Helper()
	dir := t.TempDir()
	admissions, leases, active := newTestDispatchAdmissionTaskStore(filepath.Join(dir, "distributed"))
	repository := testutil.NewFileDAGRunRepository(filepath.Join(dir, "dag-runs"), persis.DAGRunRepositoryOptions{LatestStatusToday: true})
	f := &outputsReplayFixture{
		h: NewHandler(HandlerConfig{
			DAGRunRepository:          repository,
			DispatchTaskStore:         admissions,
			DispatchAdmissionStore:    admissions,
			DAGRunLeaseStore:          leases,
			ActiveDistributedRunStore: active,
			Owner:                     dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055},
		}),
		repository: repository,
		admissions: admissions,
		leases:     leases,
		active:     active,
		runsDir:    filepath.Join(dir, "dag-runs"),
		ref:        ir.NewDAGRunRef(outputsReplayDAG, "run-1"),
	}
	t.Cleanup(func() { f.h.Close(context.Background()) })
	return f
}

// startExecution records an attempt as dispatched to worker w1: its running
// status with the execution's queued-at, its admission, lease and active run.
// It returns the attempt id and key.
func (f *outputsReplayFixture) startExecution(t *testing.T, retry bool, queuedAt string) (string, string) {
	t.Helper()
	ctx := t.Context()
	dag := &ir.DAG{Name: outputsReplayDAG}
	attempt, err := f.repository.CreateAttempt(ctx, dag, time.Now(), f.ref.ID, persis.DAGRunCreateAttemptOptions{Retry: retry})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(ctx))
	st := ir.InitialStatus(dag)
	st.DAGRunID = f.ref.ID
	st.AttemptID = attempt.ID()
	st.AttemptKey = ir.GenerateAttemptKey(outputsReplayDAG, f.ref.ID, outputsReplayDAG, f.ref.ID, attempt.ID())
	st.Status = ir.Running
	st.WorkerID = "w1"
	st.QueuedAt = queuedAt
	require.NoError(t, attempt.Write(ctx, st))
	require.NoError(t, attempt.Close(ctx))

	decision, err := f.admissions.ReserveAdmission(ctx, dispatch.DispatchAdmissionRequest{
		QueueName: "q", MaxConcurrency: 1, AttemptKey: st.AttemptKey, AttemptID: st.AttemptID,
		DAGRun: f.ref, StaleThreshold: time.Hour,
	})
	require.NoError(t, err)
	require.True(t, decision.Reserved, "the queue's one admission slot is taken")
	now := time.Now().UTC().UnixMilli()
	require.NoError(t, f.leases.Upsert(ctx, dispatch.DAGRunLease{
		AttemptKey: st.AttemptKey, DAGRun: f.ref, Root: f.ref, AttemptID: st.AttemptID,
		QueueName: "q", WorkerID: "w1", ClaimedAt: now, LastHeartbeatAt: now, ExecutionMarker: queuedAt,
	}))
	require.NoError(t, f.active.Upsert(ctx, dispatch.ActiveDistributedRun{
		AttemptKey: st.AttemptKey, DAGRun: f.ref, Root: f.ref, AttemptID: st.AttemptID, WorkerID: "w1", Status: ir.Running,
	}))
	return st.AttemptID, st.AttemptKey
}

// terminalReport is the worker's terminal report of one execution.
func (f *outputsReplayFixture) terminalReport(t *testing.T, attemptID, attemptKey, queuedAt string) *coordinatorv1.ReportStatusRequest {
	t.Helper()
	st := &ir.DAGRunStatus{
		Name: outputsReplayDAG, DAGRunID: f.ref.ID, AttemptID: attemptID, AttemptKey: attemptKey,
		Status: ir.Succeeded, WorkerID: "w1", QueuedAt: queuedAt, FinishedAt: "2026-10-29T17:00:00Z",
		Nodes: []*ir.Node{{Step: ir.Step{Name: "stringform", Output: "FREE_PCT"}, Status: ir.NodeSucceeded, OutputValue: new("42")}},
	}
	proto, err := convert.DAGRunStatusToProto(st)
	require.NoError(t, err)
	return &coordinatorv1.ReportStatusRequest{Status: proto, WorkerId: "w1", OwnerCoordinatorId: "coord-a", ExecutionMarker: queuedAt}
}

// attemptDir is the directory the file store keeps the attempt in.
func (f *outputsReplayFixture) attemptDir(t *testing.T, attemptID string) string {
	t.Helper()
	var found string
	require.NoError(t, filepath.WalkDir(f.runsDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && found == "" && strings.HasSuffix(d.Name(), "_"+attemptID) {
			found = p
		}
		return err
	}))
	require.NotEmpty(t, found, "no directory for attempt %s", attemptID)
	return found
}

// blockOutputs makes the attempt's outputs file unwritable: a directory where
// the file would go, so the store's atomic rename onto it fails.
func blockOutputs(t *testing.T, dir string) func() {
	t.Helper()
	blocker := filepath.Join(dir, dagrun.OutputsFile)
	require.NoError(t, os.MkdirAll(filepath.Join(blocker, "keep"), 0o750))
	return func() { require.NoError(t, os.RemoveAll(blocker)) }
}

func (f *outputsReplayFixture) latestStatus(t *testing.T) *ir.DAGRunStatus {
	t.Helper()
	attempt, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	st, err := attempt.ReadStatus(t.Context())
	require.NoError(t, err)
	return st
}

func (f *outputsReplayFixture) latest(t *testing.T) (*ir.DAGRunStatus, *ir.DAGRunOutputs) {
	t.Helper()
	attempt, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	st, err := attempt.ReadStatus(t.Context())
	require.NoError(t, err)
	out, err := attempt.ReadOutputs(t.Context())
	require.NoError(t, err)
	return st, out
}

func (f *outputsReplayFixture) requireReleased(t *testing.T, attemptKey string) {
	t.Helper()
	_, err := f.leases.Get(t.Context(), attemptKey)
	require.ErrorIs(t, err, dispatch.ErrDAGRunLeaseNotFound, "the lease is held")
	_, err = f.active.Get(t.Context(), attemptKey)
	require.ErrorIs(t, err, dispatch.ErrActiveRunNotFound, "the run is still active")
}

// slotFree reports whether the queue's one admission slot is free, which it is
// only once the ended execution's admission was finalized. The reservation it
// makes to find out is released again.
func (f *outputsReplayFixture) slotFree(t *testing.T) bool {
	t.Helper()
	decision, err := f.admissions.ReserveAdmission(t.Context(), dispatch.DispatchAdmissionRequest{
		QueueName: "q", MaxConcurrency: 1, AttemptKey: "probe-" + time.Now().Format("150405.000000000"), AttemptID: "probe",
		DAGRun: ir.NewDAGRunRef(outputsReplayDAG, "probe"), StaleThreshold: time.Hour,
	})
	require.NoError(t, err)
	if decision.Reserved {
		require.NoError(t, f.admissions.ReleaseAdmissionToken(t.Context(), decision.ReservationToken))
	}
	return decision.Reserved
}

// The deployed worker's retry path (TXE-3757 review): the hub records the
// terminal status and its bookkeeping, releasing the lease, the active run and
// the admission, but cannot write the outputs. The worker is told Unavailable,
// sends the same terminal report again, and that replay is accepted after the
// bookkeeping and writes the outputs, without reopening the execution.
func TestTerminalReportReplayRepairsOutputsAfterBookkeeping(t *testing.T) {
	f := newOutputsReplayFixture(t)
	attemptID, attemptKey := f.startExecution(t, false, "2026-10-29T16:59:00Z")
	require.False(t, f.slotFree(t), "the execution holds the queue's slot")
	unblock := blockOutputs(t, f.attemptDir(t, attemptID))
	report := f.terminalReport(t, attemptID, attemptKey, "2026-10-29T16:59:00Z")

	_, err := f.h.ReportStatus(t.Context(), report)
	require.Error(t, err)
	require.Equal(t, codes.Unavailable, grpcstatus.Code(err), "the worker retries a terminal report only on Unavailable")
	st := f.latestStatus(t)
	require.Equal(t, ir.Succeeded, st.Status, "the terminal status is recorded")
	f.requireReleased(t, attemptKey)
	require.True(t, f.slotFree(t), "the admission is finalized")

	unblock()
	_, out := f.latest(t)
	require.Nil(t, out, "no outputs before the replay")
	resp, err := f.h.ReportStatus(t.Context(), report)
	require.NoError(t, err)
	require.True(t, resp.Accepted, "the replay after bookkeeping must be accepted: %s", resp.Error)

	st, out = f.latest(t)
	require.NotNil(t, out, "the replay did not write the outputs")
	assert.Equal(t, map[string]string{"freePct": "42"}, out.Outputs)
	assert.Equal(t, attemptID, out.Metadata.AttemptID)
	assert.Equal(t, "succeeded", out.Metadata.Status)
	assert.Equal(t, ir.Succeeded, st.Status)
	assert.Equal(t, attemptID, st.AttemptID)
	f.requireReleased(t, attemptKey)
	assert.True(t, f.slotFree(t), "the replay reopened the execution's admission")
}

// A new execution starts between the failed write and the replay. The old
// execution's replay is rejected: it neither changes the new execution's
// status nor writes outputs into its attempt.
func TestTerminalReportReplayCannotReachANewerExecution(t *testing.T) {
	t.Run("the same attempt queued again", func(t *testing.T) {
		f := newOutputsReplayFixture(t)
		attemptID, attemptKey := f.startExecution(t, false, "2026-10-29T16:59:00Z")
		unblock := blockOutputs(t, f.attemptDir(t, attemptID))
		report := f.terminalReport(t, attemptID, attemptKey, "2026-10-29T16:59:00Z")
		_, err := f.h.ReportStatus(t.Context(), report)
		require.Equal(t, codes.Unavailable, grpcstatus.Code(err))

		// A retry queues the attempt again with a new queued-at, as
		// queue.EnqueueRetry does, before the old worker's replay arrives.
		_, swapped, err := f.repository.CompareAndSwapLatestAttemptStatus(t.Context(), f.ref, attemptID, ir.Succeeded,
			func(current *ir.DAGRunStatus) error {
				current.Status = ir.Queued
				current.QueuedAt = "2026-10-29T17:05:00Z"
				return nil
			}, persis.DAGRunCompareAndSwapOptions{RootDAGRun: f.ref})
		require.NoError(t, err)
		require.True(t, swapped)
		unblock()

		resp, err := f.h.ReportStatus(t.Context(), report)
		require.NoError(t, err)
		require.False(t, resp.Accepted)
		// Its lease was released with the first report, and the attempt is
		// queued for another execution: refused either way.
		assert.Contains(t, []string{remoteAttemptRejectedSuperseded, remoteAttemptRejectedLeaseInactive}, resp.Error)
		st, out := f.latest(t)
		assert.Equal(t, ir.Queued, st.Status)
		assert.Equal(t, "2026-10-29T17:05:00Z", st.QueuedAt)
		assert.Nil(t, out, "the old execution's replay wrote outputs into the queued retry")
	})

	t.Run("a newer attempt running", func(t *testing.T) {
		f := newOutputsReplayFixture(t)
		oldID, oldKey := f.startExecution(t, false, "2026-10-29T16:59:00Z")
		unblock := blockOutputs(t, f.attemptDir(t, oldID))
		report := f.terminalReport(t, oldID, oldKey, "2026-10-29T16:59:00Z")
		_, err := f.h.ReportStatus(t.Context(), report)
		require.Equal(t, codes.Unavailable, grpcstatus.Code(err))
		unblock()

		newID, _ := f.startExecution(t, true, "2026-10-29T17:05:00Z")
		require.NotEqual(t, oldID, newID)

		resp, err := f.h.ReportStatus(t.Context(), report)
		require.NoError(t, err)
		require.False(t, resp.Accepted)
		st, out := f.latest(t)
		assert.Equal(t, newID, st.AttemptID)
		assert.Equal(t, ir.Running, st.Status)
		assert.Nil(t, out, "the old execution's replay wrote outputs into the newer attempt")
	})
}
