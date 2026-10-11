// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

type fakeRunAdmitter struct {
	mu      sync.Mutex
	adm     registry.Admission
	dropped []string
}

func (f *fakeRunAdmitter) AdmitClaim(context.Context, string, string, registry.RunRef) (registry.Admission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adm, nil
}

func (f *fakeRunAdmitter) RecordDroppedRun(_ context.Context, jobID, runID string, _ registry.Admission) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropped = append(f.dropped, jobID+"/"+runID)
	return nil
}

// A run that waited for an offline worker is re-checked when the worker
// claims it: a job retired in the meantime refuses the claim, its attempt is
// kept as aborted with the reason, and the claim is removed so it is not
// offered again.
func TestAckTaskClaimRefusesRetiredJob(t *testing.T) {
	t.Parallel()
	jobID, err := registry.NewID(registry.PrefixJob, time.Now())
	require.NoError(t, err)

	baseDir := filepath.Join(t.TempDir(), "distributed")
	dispatchStore := newTestDispatchTaskStore(baseDir)
	runs := newMockDAGRunStore()
	attempt := runs.addAttempt(ir.NewDAGRunRef(jobID, "run-1"), &ir.DAGRunStatus{Name: jobID, DAGRunID: "run-1", AttemptID: "attempt-1", Status: ir.Queued})
	admitter := &fakeRunAdmitter{adm: registry.Admission{JobID: jobID, Code: registry.AdmitRetired, Reason: "job retired: target_deleted"}}
	h := NewHandler(HandlerConfig{
		RunAdmitter:               admitter,
		DAGRunRepository:          runs.repository,
		DispatchTaskStore:         dispatchStore,
		DAGRunLeaseStore:          newTestDAGRunLeaseStore(baseDir),
		ActiveDistributedRunStore: newTestActiveDistributedRunStore(baseDir),
		Owner:                     dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055},
	})
	ctx := context.Background()
	require.NoError(t, dispatchStore.Enqueue(ctx, &dispatch.DispatchTask{
		DAGRunID: "run-1", Target: jobID, Definition: "steps: []\n",
		AttemptID: "attempt-1", AttemptKey: "attempt-key-1", RootDAGRunName: jobID, RootDAGRunID: "run-1",
	}))
	claimed, err := dispatchStore.ClaimNext(ctx, dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "poller-1",
		Owner: dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055}})
	require.NoError(t, err)
	require.NotNil(t, claimed)

	resp, err := h.AckTaskClaim(ctx, &coordinatorv1.AckTaskClaimRequest{ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: "attempt-key-1"})
	require.NoError(t, err)
	assert.False(t, resp.Accepted)
	assert.Contains(t, resp.Error, "retired")

	status, err := attempt.ReadStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, ir.Aborted, status.Status)
	assert.Equal(t, "txe: job "+jobID+" retired: job retired: target_deleted", status.Error)
	_, err = dispatchStore.GetClaim(ctx, claimed.ClaimToken)
	assert.ErrorIs(t, err, dispatch.ErrDispatchTaskNotFound, "the refused claim is not offered again")
	assert.Equal(t, []string{jobID + "/run-1"}, admitter.dropped)

	// Unregistered DAGs and admitted jobs are acknowledged as before.
	admitter.adm = registry.Admission{Admit: true, JobID: jobID}
	require.NoError(t, dispatchStore.Enqueue(ctx, &dispatch.DispatchTask{
		DAGRunID: "run-2", Target: jobID, AttemptID: "attempt-2", AttemptKey: "attempt-key-2", RootDAGRunName: jobID, RootDAGRunID: "run-2",
	}))
	claimed, err = dispatchStore.ClaimNext(ctx, dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "poller-2",
		Owner: dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055}})
	require.NoError(t, err)
	require.NotNil(t, claimed)
	resp, err = h.AckTaskClaim(ctx, &coordinatorv1.AckTaskClaimRequest{ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: "attempt-key-2"})
	require.NoError(t, err)
	assert.True(t, resp.Accepted)
}

// A registered job called as a subworkflow of an ordinary parent is admitted
// on its own identity; a retired child is refused and its sub-attempt aborted.
func TestAckTaskClaimRefusesRetiredChildJob(t *testing.T) {
	t.Parallel()
	jobID, err := registry.NewID(registry.PrefixJob, time.Now())
	require.NoError(t, err)
	baseDir := filepath.Join(t.TempDir(), "distributed")
	dispatchStore := newTestDispatchTaskStore(baseDir)
	runs := newMockDAGRunStore()
	root := ir.NewDAGRunRef("parent", "root-1")
	child := runs.addSubAttempt(root, "child-1", &ir.DAGRunStatus{Name: jobID, DAGRunID: "child-1", AttemptID: "attempt-c", Status: ir.NotStarted})
	admitter := &fakeRunAdmitter{adm: registry.Admission{JobID: jobID, Code: registry.AdmitPaused, Reason: "job is paused"}}
	h := NewHandler(HandlerConfig{
		RunAdmitter:               admitter,
		DAGRunRepository:          runs.repository,
		DispatchTaskStore:         dispatchStore,
		DAGRunLeaseStore:          newTestDAGRunLeaseStore(baseDir),
		ActiveDistributedRunStore: newTestActiveDistributedRunStore(baseDir),
		Owner:                     dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055},
	})
	ctx := context.Background()
	require.NoError(t, dispatchStore.Enqueue(ctx, &dispatch.DispatchTask{
		DAGRunID: "child-1", Target: jobID, AttemptID: "attempt-c", AttemptKey: "attempt-key-c",
		RootDAGRunName: "parent", RootDAGRunID: "root-1", ParentDAGRunName: "parent", ParentDAGRunID: "root-1",
	}))
	claimed, err := dispatchStore.ClaimNext(ctx, dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "poller-1",
		Owner: dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055}})
	require.NoError(t, err)
	require.NotNil(t, claimed)

	resp, err := h.AckTaskClaim(ctx, &coordinatorv1.AckTaskClaimRequest{ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: "attempt-key-c"})
	require.NoError(t, err)
	assert.False(t, resp.Accepted)
	status, err := child.ReadStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, ir.Aborted, status.Status)
}

// A refused claim finalizes only its own execution. When the run's visible
// attempt is another attempt, or the same attempt queued again under a new
// queued-at marker, the stale claim is removed and nothing is aborted.
func TestRefusedClaimAbortsOnlyItsOwnExecution(t *testing.T) {
	t.Parallel()
	jobID, err := registry.NewID(registry.PrefixJob, time.Now())
	require.NoError(t, err)
	for _, tc := range []struct {
		name       string
		status     ir.DAGRunStatus
		marker     string
		wantStatus ir.Status
	}{
		{"its own queued execution", ir.DAGRunStatus{AttemptID: "attempt-1", Status: ir.Queued, QueuedAt: "q1"}, "q1", ir.Aborted},
		{"queued again under a new marker", ir.DAGRunStatus{AttemptID: "attempt-1", Status: ir.Queued, QueuedAt: "q2"}, "q1", ir.Queued},
		{"another attempt", ir.DAGRunStatus{AttemptID: "attempt-2", Status: ir.NotStarted}, "", ir.NotStarted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseDir := filepath.Join(t.TempDir(), "distributed")
			dispatchStore := newTestDispatchTaskStore(baseDir)
			runs := newMockDAGRunStore()
			st := tc.status
			st.Name, st.DAGRunID = jobID, "run-1"
			attempt := runs.addAttempt(ir.NewDAGRunRef(jobID, "run-1"), &st)
			h := NewHandler(HandlerConfig{
				RunAdmitter:               &fakeRunAdmitter{adm: registry.Admission{JobID: jobID, Code: registry.AdmitRetired, Reason: "job retired"}},
				DAGRunRepository:          runs.repository,
				DispatchTaskStore:         dispatchStore,
				DAGRunLeaseStore:          newTestDAGRunLeaseStore(baseDir),
				ActiveDistributedRunStore: newTestActiveDistributedRunStore(baseDir),
				Owner:                     dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055},
			})
			ctx := context.Background()
			require.NoError(t, dispatchStore.Enqueue(ctx, &dispatch.DispatchTask{
				DAGRunID: "run-1", Target: jobID, AttemptID: "attempt-1", AttemptKey: "attempt-key-1",
				ExecutionMarker: tc.marker, RootDAGRunName: jobID, RootDAGRunID: "run-1",
			}))
			claimed, err := dispatchStore.ClaimNext(ctx, dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "poller-1",
				Owner: dispatch.CoordinatorEndpoint{ID: "coord-a", Host: "127.0.0.1", Port: 50055}})
			require.NoError(t, err)
			require.NotNil(t, claimed)

			resp, err := h.AckTaskClaim(ctx, &coordinatorv1.AckTaskClaimRequest{ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: "attempt-key-1"})
			require.NoError(t, err)
			assert.False(t, resp.Accepted)
			got, err := attempt.ReadStatus(ctx)
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, got.Status)
			_, err = dispatchStore.GetClaim(ctx, claimed.ClaimToken)
			assert.ErrorIs(t, err, dispatch.ErrDispatchTaskNotFound, "the stale claim is removed")
		})
	}
}

// A delayed claim for an abandoned execution that admission also refuses
// leaves the run's visible execution alone: only the stale claim goes.
func TestRefusedClaimOfAbandonedExecutionLeavesTheVisibleOneAlone(t *testing.T) {
	t.Parallel()
	jobID, err := registry.NewID(registry.PrefixJob, time.Now())
	require.NoError(t, err)
	f := newStrandedFixture(t, nil)
	f.h.runAdmitter = &fakeRunAdmitter{adm: registry.Admission{JobID: jobID, Code: registry.AdmitRetired, Reason: "job retired"}}
	placeholder := f.writeAttempt(t, true, ir.NotStarted, "")
	_, err = f.h.abandonNeverDispatched(t.Context(), f.ref, f.ref, placeholder, "test")
	require.NoError(t, err)
	visible := f.writeAttempt(t, true, ir.NotStarted, "")
	require.Equal(t, visible, f.latest(t))

	require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
		Target: strandedDAG, DefinitionID: jobID, DAGRunID: strandedRun, AttemptID: placeholder, AttemptKey: f.attemptKey(placeholder),
		Owner: dispatch.CoordinatorEndpoint{ID: "coord-b", Host: "127.0.0.1", Port: 50056},
	}))
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p", ClaimTimeout: time.Minute})
	require.NoError(t, err)
	require.NotNil(t, claimed)
	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(placeholder),
	})
	require.NoError(t, err)
	assert.False(t, resp.Accepted)

	attempt, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	require.Equal(t, visible, attempt.ID())
	st, err := attempt.ReadStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, ir.NotStarted, st.Status, "the visible execution is not aborted")
	_, err = f.dispatches.GetClaim(t.Context(), claimed.ClaimToken)
	assert.ErrorIs(t, err, dispatch.ErrDispatchTaskNotFound, "the stale claim is removed")
}
