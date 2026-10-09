// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/proto/convert"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A queued retry reuses the attempt id, attempt key and claim key, so these
// tests run two executions of one attempt: E1 (marker q1, or "" for a direct
// start) and E2 (marker q2). Every write path must refuse E1 once E2 owns the
// attempt, and must accept E2, including a replay of the same write.

const (
	markerDAG     = "marker-dag"
	markerRun     = "marker-run"
	markerAttempt = "attempt-1"
	markerWorker  = "worker-1"
	markerQ1      = "2026-10-10T01:00:00Z"
	markerQ2      = "2026-10-10T01:05:00.000000001Z"
)

type markerFixture struct {
	h          *Handler
	store      *mockDAGRunStore
	attempt    *mockAttempt
	leaseStore *store.DAGRunLeaseStore
	ref        ir.DAGRunRef
	attemptKey string
	logDir     string
	archiveDir string
}

func newMarkerFixture(t *testing.T, stored *ir.DAGRunStatus, leaseMarker *string) *markerFixture {
	t.Helper()
	ref := ir.NewDAGRunRef(markerDAG, markerRun)
	attemptKey := ir.GenerateAttemptKey(markerDAG, markerRun, markerDAG, markerRun, markerAttempt)
	runStore := newMockDAGRunStore()
	archiveDir := t.TempDir()
	stored.Name = markerDAG
	stored.DAGRunID = markerRun
	stored.AttemptID = markerAttempt
	stored.AttemptKey = attemptKey
	stored.WorkerID = markerWorker
	stored.ArchiveDir = archiveDir
	attempt := runStore.addAttempt(ref, stored)
	leaseStore := newTestDAGRunLeaseStore(filepath.Join(t.TempDir(), "distributed"))
	if leaseMarker != nil {
		upsertMarkerLease(t, leaseStore, attemptKey, *leaseMarker)
	}
	logDir := t.TempDir()
	h := NewHandler(HandlerConfig{
		DAGRunRepository: runStore.repository,
		DAGRunLeaseStore: leaseStore,
		LogDir:           logDir,
		ArtifactDir:      archiveDir,
		Owner:            dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "coordinator", Port: 50055},
	})
	return &markerFixture{
		h:          h,
		store:      runStore,
		attempt:    attempt,
		leaseStore: leaseStore,
		ref:        ref,
		attemptKey: attemptKey,
		logDir:     logDir,
		archiveDir: archiveDir,
	}
}

// upsertMarkerLease records the lease a claim of the execution with marker
// would hold. A different execution's claim succeeds only once the earlier
// lease is gone, so any existing lease is removed first.
func upsertMarkerLease(t *testing.T, leaseStore *store.DAGRunLeaseStore, attemptKey, marker string) {
	t.Helper()
	if err := leaseStore.Delete(t.Context(), attemptKey); err != nil {
		require.ErrorIs(t, err, dispatch.ErrDAGRunLeaseNotFound)
	}
	ref := ir.NewDAGRunRef(markerDAG, markerRun)
	now := time.Now().UTC().UnixMilli()
	require.NoError(t, leaseStore.Upsert(t.Context(), dispatch.DAGRunLease{
		AttemptKey:      attemptKey,
		DAGRun:          ref,
		Root:            ref,
		AttemptID:       markerAttempt,
		QueueName:       markerDAG,
		WorkerID:        markerWorker,
		Owner:           dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "coordinator", Port: 50055},
		ExecutionMarker: marker,
		ClaimedAt:       now,
		LastHeartbeatAt: now,
	}))
}

func (f *markerFixture) report(t *testing.T, st ir.Status, queuedAt, marker string) *coordinatorv1.ReportStatusResponse {
	t.Helper()
	protoStatus, err := convert.DAGRunStatusToProto(&ir.DAGRunStatus{
		Name:       markerDAG,
		DAGRunID:   markerRun,
		AttemptID:  markerAttempt,
		AttemptKey: f.attemptKey,
		ProcGroup:  markerDAG,
		Status:     st,
		QueuedAt:   queuedAt,
		WorkerID:   markerWorker,
	})
	require.NoError(t, err)
	resp, err := f.h.ReportStatus(t.Context(), &coordinatorv1.ReportStatusRequest{
		Status:             protoStatus,
		WorkerId:           markerWorker,
		OwnerCoordinatorId: "coord-a",
		ExecutionMarker:    marker,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func (f *markerFixture) stored(t *testing.T) *ir.DAGRunStatus {
	t.Helper()
	st, err := f.attempt.ReadStatus(t.Context())
	require.NoError(t, err)
	return st
}

func TestExecutionMarkerReportStatus(t *testing.T) {
	t.Parallel()

	t.Run("StaleExecutionRefusedWhileRequeued", func(t *testing.T) {
		t.Parallel()
		// E1 failed and a retry re-queued the attempt (q2) before E1's last
		// report arrived; E1's lease has not been cleaned up yet.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Queued, QueuedAt: markerQ2}, new(markerQ1))

		resp := f.report(t, ir.Failed, markerQ1, markerQ1)
		assert.False(t, resp.Accepted)
		assert.Equal(t, remoteAttemptRejectedSuperseded, resp.Error)

		st := f.stored(t)
		assert.Equal(t, ir.Queued, st.Status, "the queued retry must survive the late report")
		assert.Equal(t, markerQ2, st.QueuedAt)
	})

	t.Run("StaleExecutionRefusedAfterLeaseReplacement", func(t *testing.T) {
		t.Parallel()
		// E2 has claimed the attempt and is running.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))

		resp := f.report(t, ir.Failed, markerQ1, markerQ1)
		assert.False(t, resp.Accepted)
		assert.Equal(t, remoteAttemptRejectedSuperseded, resp.Error)
		assert.Equal(t, ir.Running, f.stored(t).Status)
	})

	t.Run("CurrentExecutionAcceptedAndReplayAccepted", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))

		for range 2 {
			resp := f.report(t, ir.Running, markerQ2, markerQ2)
			assert.True(t, resp.Accepted, resp.Error)
		}
		assert.Equal(t, ir.Running, f.stored(t).Status)
	})

	t.Run("QueuedExecutionOwnReportAccepted", func(t *testing.T) {
		t.Parallel()
		// E2 has been claimed but its first report still finds the stored
		// status Queued; it carries the queued marker and must be accepted.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Queued, QueuedAt: markerQ2}, new(markerQ2))

		resp := f.report(t, ir.Running, markerQ2, markerQ2)
		assert.True(t, resp.Accepted, resp.Error)
		assert.Equal(t, ir.Running, f.stored(t).Status)
	})

	t.Run("StaleDirectStartRefusedAfterRequeue", func(t *testing.T) {
		t.Parallel()
		// E1 was a direct start (empty marker). Its status echoes an earlier
		// queued-at, so only the request's marker can identify it.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Queued, QueuedAt: markerQ2}, new(""))

		resp := f.report(t, ir.Failed, markerQ1, "")
		assert.False(t, resp.Accepted)
		assert.Equal(t, ir.Queued, f.stored(t).Status)
	})

	t.Run("StaleDirectStartRefusedOnceRequeuedExecutionRuns", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))

		resp := f.report(t, ir.Failed, "", "")
		assert.False(t, resp.Accepted)
		assert.Equal(t, remoteAttemptRejectedSuperseded, resp.Error)
	})

	t.Run("DirectStartAccepted", func(t *testing.T) {
		t.Parallel()
		// A direct retry's status echoes the previous attempt's queued-at
		// while its task marker is empty; that must not refuse it.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, new(""))

		resp := f.report(t, ir.Running, markerQ1, "")
		assert.True(t, resp.Accepted, resp.Error)
	})

}

func TestExecutionMarkerReportStatusAfterLeaseRetired(t *testing.T) {
	t.Parallel()

	// E2, a queued retry, has finished: its lease is gone. A delayed terminal
	// report from E1 must not replace E2's result; E2's own replay must.
	f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Succeeded, QueuedAt: markerQ2}, nil)

	resp := f.report(t, ir.Failed, markerQ1, markerQ1)
	assert.False(t, resp.Accepted)
	assert.Equal(t, remoteAttemptRejectedSuperseded, resp.Error)
	resp = f.report(t, ir.Failed, "", "")
	assert.False(t, resp.Accepted, "a direct-start E1 is refused too")
	assert.Equal(t, ir.Succeeded, f.stored(t).Status)

	resp = f.report(t, ir.Succeeded, markerQ2, markerQ2)
	assert.True(t, resp.Accepted, resp.Error)
}

// E1's terminal replay is validated against E1's terminal status, then a
// retry persists Q2 before the replay is written. The retry may run in another
// process, so only the store's compare-and-swap orders the two: the replay
// must not restore E1's status over Q2.
func TestExecutionMarkerTerminalReplayRacesRequeue(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		after func(*ir.DAGRunStatus)
	}{
		{"retry queued", func(st *ir.DAGRunStatus) { st.Status = ir.Queued; st.QueuedAt = markerQ2 }},
		{"retry already failed again", func(st *ir.DAGRunStatus) { st.Status = ir.Failed; st.QueuedAt = markerQ2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Failed, QueuedAt: markerQ1}, nil)
			f.store.beforeCompareAndSwap = func() {
				f.store.beforeCompareAndSwap = nil
				next := f.stored(t)
				tc.after(next)
				f.attempt.mu.Lock()
				f.attempt.status = next
				f.attempt.mu.Unlock()
			}

			resp := f.report(t, ir.Failed, markerQ1, markerQ1)
			assert.False(t, resp.Accepted)
			assert.Equal(t, remoteAttemptRejectedSuperseded, resp.Error)
			assert.Equal(t, markerQ2, f.stored(t).QueuedAt, "E1 must not restore its status over the retry")
		})
	}

	t.Run("replay without a requeue is accepted", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Failed, QueuedAt: markerQ1}, nil)
		resp := f.report(t, ir.Failed, markerQ1, markerQ1)
		assert.True(t, resp.Accepted, resp.Error)
	})
}

// A delayed E1 Running report reads Running(Q1); before it is written, another
// process fails the run as stale and a retry queues Q2, both through the
// store's compare-and-swap and outside this coordinator's locks. The report
// must not restore Running over the queued retry.
func TestExecutionMarkerRunningReportRacesRepairAndRequeue(t *testing.T) {
	t.Parallel()

	f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, new(markerQ1))
	fired := false
	f.store.beforeCompareAndSwap = func() {
		f.store.beforeCompareAndSwap = nil
		fired = true
		next := f.stored(t)
		next.Status = ir.Queued
		next.QueuedAt = markerQ2
		f.attempt.mu.Lock()
		f.attempt.status = next
		f.attempt.mu.Unlock()
	}

	// The mock store cannot append conditionally, so the report falls back
	// to the store's compare-and-swap; the repair and requeue land just
	// before it.
	resp := f.report(t, ir.Running, markerQ1, markerQ1)
	require.True(t, fired, "the report must reach the store write")
	assert.False(t, resp.Accepted)
	st := f.stored(t)
	assert.Equal(t, ir.Queued, st.Status, "E1 must not restore Running over the retry")
	assert.Equal(t, markerQ2, st.QueuedAt)
}

func TestExecutionMarkerReportStatusHoldsTheWriteLock(t *testing.T) {
	t.Parallel()

	// A claim of the next execution takes the run's write lock, so a report
	// must hold it from validation through the write.
	f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))
	unlock := f.h.attemptWriteLocks.lock(f.ref)
	done := make(chan *coordinatorv1.ReportStatusResponse, 1)
	go func() {
		protoStatus, err := convert.DAGRunStatusToProto(&ir.DAGRunStatus{
			Name: markerDAG, DAGRunID: markerRun, AttemptID: markerAttempt, AttemptKey: f.attemptKey,
			ProcGroup: markerDAG, Status: ir.Running, QueuedAt: markerQ2, WorkerID: markerWorker,
		})
		if err != nil {
			done <- nil
			return
		}
		resp, _ := f.h.ReportStatus(context.Background(), &coordinatorv1.ReportStatusRequest{
			Status: protoStatus, WorkerId: markerWorker, OwnerCoordinatorId: "coord-a", ExecutionMarker: markerQ2,
		})
		done <- resp
	}()
	select {
	case <-done:
		unlock()
		require.FailNow(t, "the report completed while the run's write lock was held")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	resp := <-done
	require.NotNil(t, resp)
	assert.True(t, resp.Accepted, resp.Error)
}

func TestExecutionMarkerHeartbeatCancellationIsScoped(t *testing.T) {
	t.Parallel()

	// The run was aborted while E1 ran; the directive names E1 so a delayed
	// response cannot cancel a newer execution under the same key.
	f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Aborted, QueuedAt: markerQ1}, nil)
	cancelled := f.h.getCancelledRunsForWorker(t.Context(), &coordinatorv1.WorkerStats{
		RunningTasks: []*coordinatorv1.RunningTask{{
			DagName: markerDAG, DagRunId: markerRun, AttemptKey: f.attemptKey, ExecutionMarker: markerQ1,
		}},
	})
	require.Len(t, cancelled, 1)
	require.NotNil(t, cancelled[0].ExecutionMarker)
	assert.Equal(t, markerQ1, cancelled[0].GetExecutionMarker())

	merged := appendCancelledRuns(nil, cancelled)
	require.Len(t, merged, 1)
	require.NotNil(t, merged[0].ExecutionMarker, "merging directives keeps their marker")
	assert.Equal(t, markerQ1, merged[0].GetExecutionMarker())
}

func TestFillLegacyExecutionMarker(t *testing.T) {
	t.Parallel()

	queued, err := convert.DAGRunStatusToProto(&ir.DAGRunStatus{
		Name: markerDAG, DAGRunID: markerRun, AttemptID: markerAttempt, Status: ir.Queued, QueuedAt: markerQ2,
	})
	require.NoError(t, err)
	legacy := &coordinatorv1.Task{Operation: coordinatorv1.Operation_OPERATION_RETRY, PreviousStatus: queued}
	require.NoError(t, fillLegacyExecutionMarker(legacy))
	assert.Equal(t, markerQ2, legacy.ExecutionMarker, "a pre-marker queued dispatch gets its queued-at")

	current := &coordinatorv1.Task{Operation: coordinatorv1.Operation_OPERATION_RETRY, PreviousStatus: queued, ExecutionMarker: markerQ1}
	require.NoError(t, fillLegacyExecutionMarker(current))
	assert.Equal(t, markerQ1, current.ExecutionMarker, "a stamped marker is kept")

	direct := &coordinatorv1.Task{Operation: coordinatorv1.Operation_OPERATION_START}
	require.NoError(t, fillLegacyExecutionMarker(direct))
	assert.Equal(t, "", direct.ExecutionMarker, "a direct start keeps its empty marker")
}

// A lease rebuilt from an accepted report takes the reporting execution's
// marker, never the status's queued-at: a direct retry's status echoes the
// previous attempt's queued-at while its task marker is empty. An existing
// lease keeps its own marker.
func TestExecutionMarkerSyncFromStatus(t *testing.T) {
	t.Parallel()

	f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, nil)
	ownership := f.h.attemptOwnership()
	reported := f.stored(t)

	ownership.syncFromStatus(t.Context(), markerWorker, reported, markerAttempt, "")
	lease, err := f.h.dagRunLeaseStore.Get(t.Context(), f.attemptKey)
	require.NoError(t, err)
	assert.Equal(t, "", lease.ExecutionMarker)

	ownership.syncFromStatus(t.Context(), markerWorker, reported, markerAttempt, markerQ2)
	lease, err = f.h.dagRunLeaseStore.Get(t.Context(), f.attemptKey)
	require.NoError(t, err)
	assert.Equal(t, "", lease.ExecutionMarker, "an existing lease keeps its execution")
}

// The reconciler must treat a lease of an earlier execution on a re-queued
// attempt as superseded: removing it lets the queued execution claim, and the
// queued run is not failed as a stale lease.
func TestExecutionMarkerReconcileDropsEarlierExecutionLease(t *testing.T) {
	t.Parallel()

	f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Queued, QueuedAt: markerQ2}, new(markerQ1))
	lease, err := f.h.dagRunLeaseStore.Get(t.Context(), f.attemptKey)
	require.NoError(t, err)

	f.h.reconcileLease(t.Context(), *lease, time.Now().Add(time.Hour))
	_, err = f.h.dagRunLeaseStore.Get(t.Context(), f.attemptKey)
	require.ErrorIs(t, err, dispatch.ErrDAGRunLeaseNotFound)
	st := f.stored(t)
	assert.Equal(t, ir.Queued, st.Status)
	assert.Equal(t, markerQ2, st.QueuedAt)

	// The queued execution's own lease survives reconciliation.
	upsertMarkerLease(t, f.leaseStore, f.attemptKey, markerQ2)
	lease, err = f.h.dagRunLeaseStore.Get(t.Context(), f.attemptKey)
	require.NoError(t, err)
	f.h.reconcileLease(t.Context(), *lease, time.Now())
	lease, err = f.h.dagRunLeaseStore.Get(t.Context(), f.attemptKey)
	require.NoError(t, err)
	assert.Equal(t, markerQ2, lease.ExecutionMarker)
}

func TestExecutionMarkerRunHeartbeatCancelsOnlyTheStaleExecution(t *testing.T) {
	t.Parallel()

	f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))
	running := func(marker string) *coordinatorv1.RunningTask {
		return &coordinatorv1.RunningTask{
			DagName:         markerDAG,
			DagRunId:        markerRun,
			AttemptKey:      f.attemptKey,
			ExecutionMarker: marker,
		}
	}

	resp, err := f.h.RunHeartbeat(t.Context(), &coordinatorv1.RunHeartbeatRequest{
		WorkerId:     markerWorker,
		RunningTasks: []*coordinatorv1.RunningTask{running(markerQ1)},
	})
	require.NoError(t, err)
	require.Len(t, resp.CancelledRuns, 1)
	assert.Equal(t, f.attemptKey, resp.CancelledRuns[0].AttemptKey)
	require.NotNil(t, resp.CancelledRuns[0].ExecutionMarker, "a refused execution is cancelled by marker")
	assert.Equal(t, markerQ1, resp.CancelledRuns[0].GetExecutionMarker())

	resp, err = f.h.RunHeartbeat(t.Context(), &coordinatorv1.RunHeartbeatRequest{
		WorkerId:     markerWorker,
		RunningTasks: []*coordinatorv1.RunningTask{running(markerQ2)},
	})
	require.NoError(t, err)
	assert.Empty(t, resp.CancelledRuns)
}

func markerLogChunk(marker string, data string, final bool) *coordinatorv1.LogChunk {
	return &coordinatorv1.LogChunk{
		WorkerId:           markerWorker,
		DagName:            markerDAG,
		DagRunId:           markerRun,
		AttemptId:          markerAttempt,
		StepName:           "step1",
		StreamType:         coordinatorv1.LogStreamType_LOG_STREAM_TYPE_STDOUT,
		Data:               []byte(data),
		IsFinal:            final,
		OwnerCoordinatorId: "coord-a",
		ExecutionMarker:    marker,
	}
}

func (f *markerFixture) logPath() string {
	return filepath.Join(f.logDir, markerDAG, markerRun, markerAttempt, "step1.stdout.log")
}

func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readFinalRecord(t *testing.T, logPath string) (logFinalRecord, bool) {
	t.Helper()
	data, err := os.ReadFile(logPath + logFinalRecordSuffix)
	if os.IsNotExist(err) {
		return logFinalRecord{}, false
	}
	require.NoError(t, err)
	var record logFinalRecord
	require.NoError(t, json.Unmarshal(data, &record))
	return record, true
}

func TestExecutionMarkerStreamLogs(t *testing.T) {
	t.Parallel()

	t.Run("CompleteStreamRecordsFinalization", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))

		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ2, "second\n", false),
			markerLogChunk(markerQ2, "", true),
		}}))
		content, err := os.ReadFile(f.logPath())
		require.NoError(t, err)
		assert.Equal(t, "second\n", string(content))
		record, ok := readFinalRecord(t, f.logPath())
		require.True(t, ok)
		assert.Equal(t, logFinalRecord{ExecutionMarker: markerQ2, AttemptID: markerAttempt, Size: 7, SHA256: digestOf("second\n")}, record)
	})

	t.Run("IncompleteStreamHasNoFinalization", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))

		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ2, "partial\n", false),
		}}))
		_, ok := readFinalRecord(t, f.logPath())
		assert.False(t, ok)
	})

	t.Run("ReopeningClearsAnEarlierFinalization", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, new(markerQ1))
		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ1, "first\n", false),
			markerLogChunk(markerQ1, "", true),
		}}))
		_, ok := readFinalRecord(t, f.logPath())
		require.True(t, ok)

		// E2 claims the attempt and starts writing the same file without
		// finishing; E1's record must not describe the new content.
		upsertMarkerLease(t, f.leaseStore, f.attemptKey, markerQ2)
		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ2, "second\n", false),
		}}))
		_, ok = readFinalRecord(t, f.logPath())
		assert.False(t, ok)
	})

	t.Run("FinalOnlyResumedStreamRecordsFinalization", func(t *testing.T) {
		t.Parallel()
		// The worker checkpoints by ending the RPC without a final chunk, then
		// sends the final chunk alone on a new RPC.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))
		at := func(c *coordinatorv1.LogChunk, offset uint64) *coordinatorv1.LogChunk {
			c.ByteOffset = &offset
			return c
		}
		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			at(markerLogChunk(markerQ2, "second\n", false), 0),
		}}))
		_, ok := readFinalRecord(t, f.logPath())
		require.False(t, ok)

		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			at(markerLogChunk(markerQ2, "", true), 7),
		}}))
		record, ok := readFinalRecord(t, f.logPath())
		require.True(t, ok)
		assert.Equal(t, logFinalRecord{ExecutionMarker: markerQ2, AttemptID: markerAttempt, Size: 7, SHA256: digestOf("second\n")}, record)
	})

	t.Run("DigestDescribesRewrittenBytes", func(t *testing.T) {
		t.Parallel()
		// A resumed stream rewrites earlier offsets; the record must hash the
		// file as finalized, not the bytes received on the last RPC.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))
		at := func(c *coordinatorv1.LogChunk, offset uint64) *coordinatorv1.LogChunk {
			c.ByteOffset = &offset
			return c
		}
		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			at(markerLogChunk(markerQ2, "aaaaaa\n", false), 0),
		}}))
		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			at(markerLogChunk(markerQ2, "bb", false), 0),
			at(markerLogChunk(markerQ2, "", true), 5),
		}}))
		content, err := os.ReadFile(f.logPath())
		require.NoError(t, err)
		require.Equal(t, "bbaaa", string(content))
		record, ok := readFinalRecord(t, f.logPath())
		require.True(t, ok)
		assert.Equal(t, logFinalRecord{ExecutionMarker: markerQ2, AttemptID: markerAttempt, Size: 5, SHA256: digestOf("bbaaa")}, record)
	})

	t.Run("EmptyStreamRecordsEmptyFinalization", func(t *testing.T) {
		t.Parallel()
		// A stream that wrote nothing sends only its final chunk at offset 0;
		// the log is complete and empty for this execution.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))
		offset := uint64(0)
		final := markerLogChunk(markerQ2, "", true)
		final.ByteOffset = &offset
		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{final}}))
		content, err := os.ReadFile(f.logPath())
		require.NoError(t, err)
		assert.Empty(t, content)
		record, ok := readFinalRecord(t, f.logPath())
		require.True(t, ok)
		assert.Equal(t, logFinalRecord{ExecutionMarker: markerQ2, AttemptID: markerAttempt, Size: 0, SHA256: digestOf("")}, record)
	})

	t.Run("FinalOnlyBeyondReceivedBytesStaysIncomplete", func(t *testing.T) {
		t.Parallel()
		// The earlier bytes reached another coordinator; this one cannot
		// vouch for the log, and must not fail the worker's final RPC.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))
		offset := uint64(64)
		final := markerLogChunk(markerQ2, "", true)
		final.ByteOffset = &offset
		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{final}}))
		_, ok := readFinalRecord(t, f.logPath())
		assert.False(t, ok)
	})

	t.Run("FinalOnlyUnpositionedStreamStaysIncomplete", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))
		require.NoError(t, os.MkdirAll(filepath.Dir(f.logPath()), 0o750))
		require.NoError(t, os.WriteFile(f.logPath(), []byte("earlier\n"), 0o600))
		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ2, "", true),
		}}))
		_, ok := readFinalRecord(t, f.logPath())
		assert.False(t, ok, "nothing says which bytes are this execution's")
	})

	t.Run("StaleStreamRefusedBeforeWriting", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))
		require.NoError(t, os.MkdirAll(filepath.Dir(f.logPath()), 0o750))
		require.NoError(t, os.WriteFile(f.logPath(), []byte("second\n"), 0o600))

		err := f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ1, "late first\n", false),
			markerLogChunk(markerQ1, "", true),
		}})
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		content, readErr := os.ReadFile(f.logPath())
		require.NoError(t, readErr)
		assert.Equal(t, "second\n", string(content), "a stale stream must not truncate or append")
		_, ok := readFinalRecord(t, f.logPath())
		assert.False(t, ok)
	})

	t.Run("StaleChunkAfterNewExecutionAdmittedIsRefused", func(t *testing.T) {
		t.Parallel()
		// E1's stream is open and has written. E2 is admitted and writes its
		// own output. E1's next chunk arrives at once, with no time for any
		// periodic revalidation: it must be refused, and E2's bytes kept.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, new(markerQ1))
		chunks := []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ1, "first\n", false),
			markerLogChunk(markerQ1, "late first\n", false),
			markerLogChunk(markerQ1, "", true),
		}
		stream := &hookedLogStream{mockStreamLogsServer: &mockStreamLogsServer{ctx: t.Context(), chunks: chunks}}
		stream.before = func(idx int) {
			if idx != 1 {
				return
			}
			upsertMarkerLease(t, f.leaseStore, f.attemptKey, markerQ2)
			require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
				markerLogChunk(markerQ2, "second\n", false),
			}}))
		}

		err := f.h.StreamLogs(stream)
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		content, readErr := os.ReadFile(f.logPath())
		require.NoError(t, readErr)
		assert.Equal(t, "first\nsecond\n", string(content), "E2's bytes must be unchanged")
		_, ok := readFinalRecord(t, f.logPath())
		assert.False(t, ok, "an execution that lost the attempt cannot finalize its log")
	})

	t.Run("FinalChunkRefusedAfterLeaseReplacement", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, new(markerQ1))
		chunks := []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ1, "first\n", false),
			markerLogChunk(markerQ1, "", true),
		}
		stream := &hookedLogStream{mockStreamLogsServer: &mockStreamLogsServer{ctx: t.Context(), chunks: chunks}}
		stream.before = func(idx int) {
			if idx == 1 {
				upsertMarkerLease(t, f.leaseStore, f.attemptKey, markerQ2)
			}
		}

		err := f.h.StreamLogs(stream)
		require.Error(t, err)
		_, ok := readFinalRecord(t, f.logPath())
		assert.False(t, ok)
	})

	t.Run("ClaimWaitsForAValidatedWriteInFlight", func(t *testing.T) {
		t.Parallel()
		// E1's chunk has passed validation and is about to be written when
		// E2's claim arrives. The claim must wait until the write is done,
		// and E1's next chunk must then be refused.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, new(markerQ1))
		lh := newLogHandler(f.logDir)
		lh.lockAttempt = f.h.attemptWriteLocks.lock
		defer lh.Close(t.Context())

		claimed := make(chan error, 1)
		var claimDoneDuringWrite bool
		validations := 0
		lh.attemptValidator = func(ctx context.Context, identity attemptIdentity) error {
			err := f.h.validateAttempt(ctx, identity)
			validations++
			if validations == 1 && err == nil {
				go func() {
					if err := f.leaseStore.Delete(t.Context(), f.attemptKey); err != nil {
						claimed <- err
						return
					}
					claimed <- f.h.recordTaskClaim(t.Context(), &coordinatorv1.Task{
						Target:          markerDAG,
						DagRunId:        markerRun,
						AttemptId:       markerAttempt,
						AttemptKey:      f.attemptKey,
						ExecutionMarker: markerQ2,
					}, markerWorker)
				}()
				select {
				case <-claimed:
					claimDoneDuringWrite = true
				case <-time.After(200 * time.Millisecond):
				}
			}
			return err
		}

		stream := &mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ1, "first\n", false),
			markerLogChunk(markerQ1, "late first\n", false),
		}}
		err := lh.handleStream(stream)
		require.False(t, claimDoneDuringWrite, "the claim must not complete while a validated write is in flight")
		require.NoError(t, <-claimed)
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		content, readErr := os.ReadFile(f.logPath())
		require.NoError(t, readErr)
		assert.Equal(t, "first\n", string(content))
		lease, leaseErr := f.h.dagRunLeaseStore.Get(t.Context(), f.attemptKey)
		require.NoError(t, leaseErr)
		assert.Equal(t, markerQ2, lease.ExecutionMarker)
	})
}

// The retry persists the queued status (Q2) before the next execution claims,
// so for a while E1's lease still matches. Every E1 write in that window must
// be refused, not just its status. E2 then claims and its output stands alone.
func TestExecutionMarkerRequeueWindowBeforeClaim(t *testing.T) {
	t.Parallel()

	f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, new(markerQ1))
	at := func(c *coordinatorv1.LogChunk, offset uint64) *coordinatorv1.LogChunk {
		c.ByteOffset = &offset
		return c
	}
	requeue := func() {
		queued := f.stored(t)
		queued.Status = ir.Queued
		queued.QueuedAt = markerQ2
		require.NoError(t, f.attempt.Write(t.Context(), *queued))
	}

	// E1's stream is open and has written when the retry is queued.
	stream := &hookedLogStream{mockStreamLogsServer: &mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
		at(markerLogChunk(markerQ1, "first\n", false), 0),
		at(markerLogChunk(markerQ1, "late\n", false), 6),
	}}}
	stream.before = func(idx int) {
		if idx == 1 {
			requeue()
		}
	}
	err := f.h.StreamLogs(stream)
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	// E1's final chunk and status arrive before E2 claims.
	err = f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
		at(markerLogChunk(markerQ1, "", true), 6),
	}})
	require.Error(t, err)
	resp := f.report(t, ir.Failed, markerQ1, markerQ1)
	assert.False(t, resp.Accepted)
	err = f.h.StreamArtifacts(&mockStreamArtifactsServer{ctx: t.Context(), chunks: []*coordinatorv1.ArtifactChunk{
		markerArtifactChunk(f.attemptKey, markerQ1, "late first"),
	}})
	require.Error(t, err)
	hb, err := f.h.RunHeartbeat(t.Context(), &coordinatorv1.RunHeartbeatRequest{
		WorkerId: markerWorker,
		RunningTasks: []*coordinatorv1.RunningTask{{
			DagName: markerDAG, DagRunId: markerRun, AttemptKey: f.attemptKey, ExecutionMarker: markerQ1,
		}},
	})
	require.NoError(t, err)
	require.Len(t, hb.CancelledRuns, 1)
	assert.Equal(t, markerQ1, hb.CancelledRuns[0].GetExecutionMarker())

	content, err := os.ReadFile(f.logPath())
	require.NoError(t, err)
	assert.Equal(t, "first\n", string(content))
	_, ok := readFinalRecord(t, f.logPath())
	assert.False(t, ok, "E1 must not finalize its log after the retry was queued")
	_, err = os.Stat(filepath.Join(f.archiveDir, "artifact.txt"))
	assert.True(t, os.IsNotExist(err))
	st := f.stored(t)
	assert.Equal(t, ir.Queued, st.Status)
	assert.Equal(t, markerQ2, st.QueuedAt)

	// E2 claims and writes its own output from offset zero.
	require.NoError(t, f.leaseStore.Delete(t.Context(), f.attemptKey))
	require.NoError(t, f.h.recordTaskClaim(t.Context(), &coordinatorv1.Task{
		Target: markerDAG, DagRunId: markerRun, AttemptId: markerAttempt, AttemptKey: f.attemptKey, ExecutionMarker: markerQ2,
	}, markerWorker))
	require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
		at(markerLogChunk(markerQ2, "2nd\n", false), 0),
		at(markerLogChunk(markerQ2, "", true), 4),
	}}))
	content, err = os.ReadFile(f.logPath())
	require.NoError(t, err)
	assert.Equal(t, "2nd\n", string(content))
	record, ok := readFinalRecord(t, f.logPath())
	require.True(t, ok)
	assert.Equal(t, logFinalRecord{ExecutionMarker: markerQ2, AttemptID: markerAttempt, Size: 4, SHA256: digestOf("2nd\n")}, record)
}

// A separately dispatched child holds its own claim and an empty marker. While
// the root waits in the queue its writes are judged by its own lease, not by
// the root's queued marker.
func TestExecutionMarkerRequeueCheckSparesIndependentChild(t *testing.T) {
	t.Parallel()

	f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Queued, QueuedAt: markerQ2}, new(markerQ2))
	child := ir.NewDAGRunRef("child-dag", "child-run")
	childKey := ir.GenerateAttemptKey(markerDAG, markerRun, child.Name, child.ID, "child-attempt")
	now := time.Now().UTC().UnixMilli()
	require.NoError(t, f.leaseStore.Upsert(t.Context(), dispatch.DAGRunLease{
		AttemptKey: childKey, DAGRun: child, Root: f.ref, AttemptID: "child-attempt", WorkerID: markerWorker,
		Owner:     dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "coordinator", Port: 50055},
		ClaimedAt: now, LastHeartbeatAt: now,
	}))
	chunk := func(data string, final bool) *coordinatorv1.LogChunk {
		return &coordinatorv1.LogChunk{
			WorkerId: markerWorker, DagName: child.Name, DagRunId: child.ID, AttemptId: "child-attempt",
			RootDagRunName: markerDAG, RootDagRunId: markerRun, AttemptKey: childKey,
			StepName: "step1", StreamType: coordinatorv1.LogStreamType_LOG_STREAM_TYPE_STDOUT,
			Data: []byte(data), IsFinal: final, OwnerCoordinatorId: "coord-a",
		}
	}
	require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
		chunk("child\n", false), chunk("", true),
	}}))

	// The root's own earlier execution is still refused.
	err := f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
		markerLogChunk(markerQ1, "late\n", false),
	}})
	require.Error(t, err)
}

// hookedLogStream runs before(idx) ahead of delivering chunk idx.
type hookedLogStream struct {
	*mockStreamLogsServer
	before func(int)
}

func (s *hookedLogStream) Recv() (*coordinatorv1.LogChunk, error) {
	if s.before != nil && s.idx < len(s.chunks) {
		s.before(s.idx)
	}
	return s.mockStreamLogsServer.Recv()
}

func markerArtifactChunk(attemptKey, marker, data string) *coordinatorv1.ArtifactChunk {
	return &coordinatorv1.ArtifactChunk{
		WorkerId:           markerWorker,
		DagName:            markerDAG,
		DagRunId:           markerRun,
		AttemptId:          markerAttempt,
		AttemptKey:         attemptKey,
		RelativePath:       "artifact.txt",
		Data:               []byte(data),
		IsFinal:            true,
		OwnerCoordinatorId: "coord-a",
		ExecutionMarker:    marker,
	}
}

func TestExecutionMarkerStreamArtifacts(t *testing.T) {
	t.Parallel()

	t.Run("CurrentExecutionCommits", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))

		require.NoError(t, f.h.StreamArtifacts(&mockStreamArtifactsServer{ctx: t.Context(), chunks: []*coordinatorv1.ArtifactChunk{
			markerArtifactChunk(f.attemptKey, markerQ2, "second"),
		}}))
		content, err := os.ReadFile(filepath.Join(f.archiveDir, "artifact.txt"))
		require.NoError(t, err)
		assert.Equal(t, "second", string(content))
	})

	t.Run("StaleExecutionRefused", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, new(markerQ2))
		require.NoError(t, os.WriteFile(filepath.Join(f.archiveDir, "artifact.txt"), []byte("second"), 0o600))

		err := f.h.StreamArtifacts(&mockStreamArtifactsServer{ctx: t.Context(), chunks: []*coordinatorv1.ArtifactChunk{
			markerArtifactChunk(f.attemptKey, markerQ1, "late first"),
		}})
		require.Error(t, err)
		content, readErr := os.ReadFile(filepath.Join(f.archiveDir, "artifact.txt"))
		require.NoError(t, readErr)
		assert.Equal(t, "second", string(content))
	})

	t.Run("DelayedUploadNotCommittedAfterLeaseReplacement", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, new(markerQ1))
		require.NoError(t, os.WriteFile(filepath.Join(f.archiveDir, "artifact.txt"), []byte("second"), 0o600))

		first := markerArtifactChunk(f.attemptKey, markerQ1, "late ")
		first.IsFinal = false
		stream := &mockStreamArtifactsServer{ctx: t.Context(), chunks: []*coordinatorv1.ArtifactChunk{
			first,
			markerArtifactChunk(f.attemptKey, markerQ1, "first"),
		}}
		stream.recvHook = func(idx int) {
			if idx == 1 {
				upsertMarkerLease(t, f.leaseStore, f.attemptKey, markerQ2)
			}
		}

		err := f.h.StreamArtifacts(stream)
		require.Error(t, err)
		content, readErr := os.ReadFile(filepath.Join(f.archiveDir, "artifact.txt"))
		require.NoError(t, readErr)
		assert.Equal(t, "second", string(content), "E1's upload must not replace E2's file")
	})
}
