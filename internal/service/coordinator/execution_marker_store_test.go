// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	filedagrun "github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
	"github.com/dagucloud/dagu/v2/internal/proto/convert"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingAttempt records the statuses written through it.
type recordingAttempt struct {
	dagrun.Attempt
	mu      sync.Mutex
	written []ir.Status
}

func (a *recordingAttempt) Write(ctx context.Context, s ir.DAGRunStatus) error {
	a.mu.Lock()
	a.written = append(a.written, s.Status)
	a.mu.Unlock()
	return a.Attempt.Write(ctx, s)
}

// The coordinator keeps a run's attempt open while it runs. Writing the
// terminal status through that open attempt and then closing it compacted the
// file from a read taken before a retry queued in between, which dropped the
// retry. Against the real file store, a terminal report must instead go
// through the store's compare-and-swap, which holds the lock the retry takes,
// and a retry queued afterwards must survive any later close.
func TestExecutionMarkerTerminalWriteBypassesOpenAttempt(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	baseDir := filepath.Join(t.TempDir(), "dag-runs")
	repository := persis.NewDAGRunRepository(
		filedagrun.NewStore(baseDir),
		filedagrun.NewWorkDirStore(filepath.Join(baseDir, ".dag-run-work"), baseDir),
		persis.DAGRunRepositoryOptions{LatestStatusToday: true},
	)
	ref := ir.NewDAGRunRef(markerDAG, markerRun)
	attempt, err := repository.CreateAttempt(ctx, &ir.DAG{Name: markerDAG}, time.Now(), markerRun, persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	running := ir.DAGRunStatus{
		Name: markerDAG, DAGRunID: markerRun, AttemptID: attempt.ID(),
		AttemptKey: ir.GenerateAttemptKey(markerDAG, markerRun, markerDAG, markerRun, attempt.ID()),
		Status:     ir.Running, QueuedAt: markerQ1, WorkerID: markerWorker,
	}
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, running))

	// The coordinator holds the running attempt open, as after dispatch.
	h := NewHandler(HandlerConfig{DAGRunRepository: repository})
	cached := &recordingAttempt{Attempt: attempt}
	h.attemptsMu.Lock()
	h.openAttempts[markerRun] = cached
	h.attemptsMu.Unlock()

	failed := running
	failed.Status = ir.Failed
	protoStatus, err := convert.DAGRunStatusToProto(&failed)
	require.NoError(t, err)
	resp, err := h.ReportStatus(ctx, &coordinatorv1.ReportStatusRequest{
		Status: protoStatus, WorkerId: markerWorker, ExecutionMarker: markerQ1,
	})
	require.NoError(t, err)
	require.True(t, resp.Accepted, resp.Error)

	cached.mu.Lock()
	written := append([]ir.Status(nil), cached.written...)
	cached.mu.Unlock()
	assert.Empty(t, written, "a terminal status must not be written through the open attempt")
	h.attemptsMu.RLock()
	_, stillCached := h.openAttempts[markerRun]
	h.attemptsMu.RUnlock()
	assert.False(t, stillCached, "the open attempt is closed before the store write")

	// The retry queues Q2 through the store, as PrepareRetry does; a later
	// close of anything the coordinator holds must not undo it.
	_, swapped, err := repository.CompareAndSwapLatestAttemptStatus(ctx, ref, attempt.ID(), ir.Failed,
		func(current *ir.DAGRunStatus) error {
			current.Status = ir.Queued
			current.QueuedAt = markerQ2
			return nil
		}, persis.DAGRunCompareAndSwapOptions{})
	require.NoError(t, err)
	require.True(t, swapped, "the terminal status must be stored for the retry to admit")
	h.closeCachedAttemptForRun(ctx, ctx, markerRun, "")
	_ = attempt.Close(ctx)

	latest, err := repository.LatestAttempt(ctx, markerDAG, persis.DAGRunLatestAttemptOptions{})
	require.NoError(t, err)
	stored, err := latest.ReadStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, ir.Queued, stored.Status)
	assert.Equal(t, markerQ2, stored.QueuedAt)
}

// conditionalAttempt passes conditional writes through to the real attempt,
// running before first.
type conditionalAttempt struct {
	dagrun.Attempt
	before func()
	calls  int
}

func (a *conditionalAttempt) WriteIfLatest(ctx context.Context, s ir.DAGRunStatus, check func(*ir.DAGRunStatus) error) error {
	a.calls++
	if a.before != nil {
		a.before()
	}
	return a.Attempt.(dagrun.ConditionalWriter).WriteIfLatest(ctx, s, check)
}

func newRunningRunOnFileStore(t *testing.T) (*persis.DAGRunRepository, dagrun.Attempt, ir.DAGRunStatus) {
	t.Helper()
	ctx := t.Context()
	baseDir := filepath.Join(t.TempDir(), "dag-runs")
	repository := persis.NewDAGRunRepository(
		filedagrun.NewStore(baseDir),
		filedagrun.NewWorkDirStore(filepath.Join(baseDir, ".dag-run-work"), baseDir),
		persis.DAGRunRepositoryOptions{LatestStatusToday: true},
	)
	attempt, err := repository.CreateAttempt(ctx, &ir.DAG{Name: markerDAG}, time.Now(), markerRun, persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	running := ir.DAGRunStatus{
		Name: markerDAG, DAGRunID: markerRun, AttemptID: attempt.ID(),
		AttemptKey: ir.GenerateAttemptKey(markerDAG, markerRun, markerDAG, markerRun, attempt.ID()),
		Status:     ir.Running, QueuedAt: markerQ1, WorkerID: markerWorker,
	}
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, running))
	return repository, attempt, running
}

func reportOnFileStore(t *testing.T, h *Handler, st ir.DAGRunStatus) *coordinatorv1.ReportStatusResponse {
	t.Helper()
	protoStatus, err := convert.DAGRunStatusToProto(&st)
	require.NoError(t, err)
	resp, err := h.ReportStatus(t.Context(), &coordinatorv1.ReportStatusRequest{
		Status: protoStatus, WorkerId: markerWorker, ExecutionMarker: markerQ1,
	})
	require.NoError(t, err)
	return resp
}

func storedOnFileStore(t *testing.T, repository *persis.DAGRunRepository) *ir.DAGRunStatus {
	t.Helper()
	latest, err := repository.LatestAttempt(t.Context(), markerDAG, persis.DAGRunLatestAttemptOptions{})
	require.NoError(t, err)
	st, err := latest.ReadStatus(t.Context())
	require.NoError(t, err)
	return st
}

// A nonterminal root report is appended through the cached open attempt,
// conditionally, not through a per-report compare-and-swap.
func TestExecutionMarkerRunningReportAppendsConditionally(t *testing.T) {
	t.Parallel()

	repository, attempt, running := newRunningRunOnFileStore(t)
	t.Cleanup(func() { _ = attempt.Close(t.Context()) })
	h := NewHandler(HandlerConfig{DAGRunRepository: repository})
	cached := &conditionalAttempt{Attempt: attempt}
	h.attemptsMu.Lock()
	h.openAttempts[markerRun] = cached
	h.attemptsMu.Unlock()

	next := running
	next.Nodes = []*ir.Node{{Step: ir.Step{Name: "step1"}, Status: ir.NodeRunning}}
	resp := reportOnFileStore(t, h, next)
	require.True(t, resp.Accepted, resp.Error)
	assert.Equal(t, 1, cached.calls, "the report must use the conditional append")
	stored := storedOnFileStore(t, repository)
	require.Len(t, stored.Nodes, 1)
	assert.Equal(t, ir.NodeRunning, stored.Nodes[0].Status)
}

// Another process fails the run as stale and queues a retry between the
// report's validation and its append; the append is refused and Q2 stands.
func TestExecutionMarkerRunningReportRefusedWhenRequeuedBeforeAppend(t *testing.T) {
	t.Parallel()

	repository, attempt, running := newRunningRunOnFileStore(t)
	t.Cleanup(func() { _ = attempt.Close(t.Context()) })
	h := NewHandler(HandlerConfig{DAGRunRepository: repository})
	ref := ir.NewDAGRunRef(markerDAG, markerRun)
	cached := &conditionalAttempt{Attempt: attempt}
	cached.before = func() {
		for _, step := range []func(*ir.DAGRunStatus){
			func(st *ir.DAGRunStatus) { st.Status = ir.Failed },
			func(st *ir.DAGRunStatus) { st.Status = ir.Queued; st.QueuedAt = markerQ2 },
		} {
			current := storedOnFileStore(t, repository)
			_, swapped, err := repository.CompareAndSwapLatestAttemptStatus(t.Context(), ref, attempt.ID(), current.Status,
				func(st *ir.DAGRunStatus) error { step(st); return nil }, persis.DAGRunCompareAndSwapOptions{})
			require.NoError(t, err)
			require.True(t, swapped)
		}
	}
	h.attemptsMu.Lock()
	h.openAttempts[markerRun] = cached
	h.attemptsMu.Unlock()

	next := running
	next.Nodes = []*ir.Node{{Step: ir.Step{Name: "step1"}, Status: ir.NodeRunning}}
	resp := reportOnFileStore(t, h, next)
	require.Equal(t, 1, cached.calls, "the report must reach the conditional append")
	assert.False(t, resp.Accepted)
	assert.Equal(t, remoteAttemptRejectedSuperseded, resp.Error)
	stored := storedOnFileStore(t, repository)
	assert.Equal(t, ir.Queued, stored.Status)
	assert.Equal(t, markerQ2, stored.QueuedAt)
}
