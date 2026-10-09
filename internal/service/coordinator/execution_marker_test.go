// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
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

func strPtr(s string) *string { return &s }

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
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Queued, QueuedAt: markerQ2}, strPtr(markerQ1))

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
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, strPtr(markerQ2))

		resp := f.report(t, ir.Failed, markerQ1, markerQ1)
		assert.False(t, resp.Accepted)
		assert.Equal(t, remoteAttemptRejectedSuperseded, resp.Error)
		assert.Equal(t, ir.Running, f.stored(t).Status)
	})

	t.Run("CurrentExecutionAcceptedAndReplayAccepted", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, strPtr(markerQ2))

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
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Queued, QueuedAt: markerQ2}, strPtr(markerQ2))

		resp := f.report(t, ir.Running, markerQ2, markerQ2)
		assert.True(t, resp.Accepted, resp.Error)
		assert.Equal(t, ir.Running, f.stored(t).Status)
	})

	t.Run("StaleDirectStartRefusedAfterRequeue", func(t *testing.T) {
		t.Parallel()
		// E1 was a direct start (empty marker). Its status echoes an earlier
		// queued-at, so only the request's marker can identify it.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Queued, QueuedAt: markerQ2}, strPtr(""))

		resp := f.report(t, ir.Failed, markerQ1, "")
		assert.False(t, resp.Accepted)
		assert.Equal(t, ir.Queued, f.stored(t).Status)
	})

	t.Run("StaleDirectStartRefusedOnceRequeuedExecutionRuns", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, strPtr(markerQ2))

		resp := f.report(t, ir.Failed, "", "")
		assert.False(t, resp.Accepted)
		assert.Equal(t, remoteAttemptRejectedSuperseded, resp.Error)
	})

	t.Run("DirectStartAccepted", func(t *testing.T) {
		t.Parallel()
		// A direct retry's status echoes the previous attempt's queued-at
		// while its task marker is empty; that must not refuse it.
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, strPtr(""))

		resp := f.report(t, ir.Running, markerQ1, "")
		assert.True(t, resp.Accepted, resp.Error)
	})

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

	f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Queued, QueuedAt: markerQ2}, strPtr(markerQ1))
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

	f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, strPtr(markerQ2))
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
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, strPtr(markerQ2))

		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ2, "second\n", false),
			markerLogChunk(markerQ2, "", true),
		}}))
		content, err := os.ReadFile(f.logPath())
		require.NoError(t, err)
		assert.Equal(t, "second\n", string(content))
		record, ok := readFinalRecord(t, f.logPath())
		require.True(t, ok)
		assert.Equal(t, logFinalRecord{ExecutionMarker: markerQ2, AttemptID: markerAttempt, Size: 7}, record)
	})

	t.Run("IncompleteStreamHasNoFinalization", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, strPtr(markerQ2))

		require.NoError(t, f.h.StreamLogs(&mockStreamLogsServer{ctx: t.Context(), chunks: []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ2, "partial\n", false),
		}}))
		_, ok := readFinalRecord(t, f.logPath())
		assert.False(t, ok)
	})

	t.Run("ReopeningClearsAnEarlierFinalization", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, strPtr(markerQ1))
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

	t.Run("StaleStreamRefusedBeforeWriting", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, strPtr(markerQ2))
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

	t.Run("DelayedStreamStopsAfterLeaseReplacement", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, strPtr(markerQ1))
		clock := time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC)
		lh := newLogHandler(f.logDir)
		lh.attemptValidator = f.h.validateAttempt
		lh.now = func() time.Time { return clock }
		defer lh.Close(t.Context())

		chunks := []*coordinatorv1.LogChunk{
			markerLogChunk(markerQ1, "first\n", false),
			markerLogChunk(markerQ1, "still first\n", false),
			markerLogChunk(markerQ1, "", true),
		}
		stream := &hookedLogStream{mockStreamLogsServer: &mockStreamLogsServer{ctx: t.Context(), chunks: chunks}}
		stream.before = func(idx int) {
			if idx == 1 {
				// E2 claims the attempt between E1's chunks, and the stream
				// outlives the revalidation interval.
				upsertMarkerLease(t, f.leaseStore, f.attemptKey, markerQ2)
				clock = clock.Add(logStreamRevalidateInterval)
			}
		}

		err := lh.handleStream(stream)
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		content, readErr := os.ReadFile(f.logPath())
		require.NoError(t, readErr)
		assert.Equal(t, "first\n", string(content))
		_, ok := readFinalRecord(t, f.logPath())
		assert.False(t, ok, "an execution that lost the attempt cannot finalize its log")
	})

	t.Run("FinalChunkRevalidatesWithinInterval", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, strPtr(markerQ1))
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
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, strPtr(markerQ2))

		require.NoError(t, f.h.StreamArtifacts(&mockStreamArtifactsServer{ctx: t.Context(), chunks: []*coordinatorv1.ArtifactChunk{
			markerArtifactChunk(f.attemptKey, markerQ2, "second"),
		}}))
		content, err := os.ReadFile(filepath.Join(f.archiveDir, "artifact.txt"))
		require.NoError(t, err)
		assert.Equal(t, "second", string(content))
	})

	t.Run("StaleExecutionRefused", func(t *testing.T) {
		t.Parallel()
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ2}, strPtr(markerQ2))
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
		f := newMarkerFixture(t, &ir.DAGRunStatus{Status: ir.Running, QueuedAt: markerQ1}, strPtr(markerQ1))
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
