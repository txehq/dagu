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
