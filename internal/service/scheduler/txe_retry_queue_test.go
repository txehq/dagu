// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package scheduler

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/launcher"
	"github.com/dagucloud/dagu/v2/internal/persis"
	dagstore "github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	queuedomain "github.com/dagucloud/dagu/v2/internal/queue"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// txeQueueJob is a ready registered job in a file registry of its own, and
// the job's DAG as the registry recorded it.
type txeQueueJob struct {
	store *registry.Store
	job   *registry.Job
	dag   *ir.DAG
}

func newTxeQueueJob(t *testing.T) txeQueueJob {
	t.Helper()
	ctx := context.Background()
	by := registry.Actor{Kind: registry.ActorCLI, ID: "txe-7518-test", Session: "txe-7518-test"}
	dir := t.TempDir()
	dags := registry.NewDAGStore(persis.NewDAGRepository(dagstore.NewStore(filepath.Join(dir, "dags")), persis.DAGRepositoryOptions{}))
	s, err := registry.NewFileStore(filepath.Join(dir, "data"), registry.WithDAGStore(dags))
	require.NoError(t, err)
	mint := func(p registry.Prefix) string {
		id, err := registry.NewID(p, time.Now())
		require.NoError(t, err)
		return id
	}
	owner, machine, jobID := mint(registry.PrefixOwner), mint(registry.PrefixMachine), mint(registry.PrefixJob)
	_, err = s.CreateOwner(ctx, registry.Owner{OwnerID: owner, DisplayName: "owner"}, by)
	require.NoError(t, err)
	_, err = s.CreateMachine(ctx, registry.Machine{MachineID: machine, OwnerID: owner, DisplayName: "laptop"}, by)
	require.NoError(t, err)
	project, err := s.EnsureProject(ctx, owner, "github.com/txehq/txe", "txe", by)
	require.NoError(t, err)
	spec := fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", machine)
	packagePath := "/Users/owner/.local/share/txe-dagu/packages/" + jobID + "/a"
	job, err := s.Register(ctx, registry.RegisterInput{
		JobID: jobID, RequestID: "req-" + jobID, OwnerID: owner, ProjectID: project.ProjectID, MachineID: machine,
		JobKey: "queue-retry", Version: registry.JobVersion{
			Title: "queue retry", Purpose: "Characterize a queued retry of a registered job",
			Package: registry.Package{Digest: fmt.Sprintf("sha256:%064x", 1), Path: packagePath, Entrypoint: "run.sh"},
			DAG:     registry.DAGRef{Spec: spec},
		},
	}, by)
	require.NoError(t, err)
	_, err = s.MarkReady(ctx, jobID, 0, registry.PackageEvidence{Digest: job.PackageDigest, Path: packagePath, MachineID: machine}, by)
	require.NoError(t, err)
	job, err = s.GetJob(ctx, jobID)
	require.NoError(t, err)
	dag := &ir.DAG{
		Name: jobID, YamlData: []byte(spec), MaxActiveRuns: 1,
		WorkerSelector: map[string]string{"txe.machine": machine},
		Steps:          []ir.Step{{Name: "run", Command: "/pkg/run.sh"}},
	}
	require.Equal(t, job.DAGSpecSHA256, specDigest(dag), "the DAG must be the job's current version")
	return txeQueueJob{store: s, job: job, dag: dag}
}

// finishedRun records one execution of dag's run that has ended: a sealed
// execution is one whose run step finished and whose result was written.
func finishedRun(t *testing.T, f *queueFixture, dag *ir.DAG, runID string, st ir.Status) *ir.DAGRunStatus {
	t.Helper()
	attempt, err := f.dagRunRepository.CreateAttempt(f.ctx, dag, time.Now().Add(-time.Minute), runID, persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(f.ctx))
	status := ir.InitialStatus(dag)
	status.DAGRunID, status.AttemptID, status.Status = runID, attempt.ID(), st
	status.TriggerType = ir.TriggerTypeScheduler
	status.QueuedAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	require.NoError(t, attempt.Write(f.ctx, status))
	require.NoError(t, attempt.Close(f.ctx))
	return &status
}

// cliEnqueueRetry queues a retry exactly as the local `dagu retry` command
// does for a DAG in a global queue (internal/cmd retry.go enqueueRetry): no
// retry request, the shell user as the actor.
func cliEnqueueRetry(t *testing.T, f *queueFixture, dag *ir.DAG, status *ir.DAGRunStatus, request *ir.RetryRequest) *ir.DAGRunStatus {
	t.Helper()
	actor := "shell-user"
	added, err := queuedomain.EnqueueRetry(f.ctx, f.dagRunRepository, f.queueStore, dag, status, queuedomain.EnqueueRetryOptions{
		TriggerActor: &actor, RetryRequest: request,
	})
	require.NoError(t, err)
	require.True(t, added)
	attempt, err := f.dagRunRepository.FindAttempt(f.ctx, status.DAGRun())
	require.NoError(t, err)
	queued, err := attempt.ReadStatus(f.ctx)
	require.NoError(t, err)
	require.Equal(t, ir.Queued, queued.Status)
	require.Equal(t, ir.TriggerTypeRetry, queued.TriggerType)
	return queued
}

// distributedDispatcher is a queue dispatcher for DAGs with a worker
// selector, guarded by admitter.
func distributedDispatcher(f *queueFixture, admitter RunAdmitter) *queueDispatcher {
	return &queueDispatcher{
		queueStore: f.queueStore, dagRunRepository: f.dagRunRepository, procRepository: f.procRepository,
		dagExecutor: NewDAGExecutor(&mockDispatcher{}, launcher.NewSubCmdBuilder(&config.Config{Paths: config.PathsConfig{Executable: "/usr/bin/dagu"}}),
			config.ExecutionModeLocal, ""),
		runAdmitter: admitter,
	}
}

// queuedItem is the one queue item of dag's proc group.
func queuedItem(t *testing.T, f *queueFixture, dag *ir.DAG) string {
	t.Helper()
	items, err := f.queueStore.List(f.ctx, dag.ProcGroup())
	require.NoError(t, err)
	require.Len(t, items, 1)
	return items[0].ID()
}

// assertRetryDropped checks a refused queued retry: not dispatched, its
// queue item gone, its execution aborted with the registry's reason, the
// retried execution kept, and the refusal noted on the job.
func assertRetryDropped(t *testing.T, f *queueFixture, j txeQueueJob, queued *ir.DAGRunStatus, admitted bool, code registry.AdmitCode) {
	t.Helper()
	assert.False(t, admitted)
	items, err := f.queueStore.List(f.ctx, j.dag.ProcGroup())
	require.NoError(t, err)
	assert.Empty(t, items)
	attempt, err := f.dagRunRepository.FindAttempt(f.ctx, queued.DAGRun())
	require.NoError(t, err)
	status, err := attempt.ReadStatus(f.ctx)
	require.NoError(t, err)
	assert.Equal(t, ir.Aborted, status.Status)
	assert.Contains(t, status.Error, string(code))
	retained, err := f.dagRunRepository.ListRetainedExecutions(f.ctx, queued.DAGRun())
	require.NoError(t, err)
	require.Len(t, retained, 1, "the retried execution is kept")
	assert.Equal(t, ir.Succeeded.String(), retained[0].Status)
	events, err := j.store.ListEvents(f.ctx, j.job.JobID, 10)
	require.NoError(t, err)
	require.NotEmpty(t, events)
	assert.Equal(t, registry.EventRunDropped, events[0].Kind)
	assert.Equal(t, string(code), events[0].Reason)
}

// A retry of a registered job's sealed run queued by the local CLI, which
// carries no retry request (TXE-7518 characterization on 47b89206c: queue
// dispatch admitted it on lifecycle and version alone), is refused.
func TestQueueDispatch_TxeRetryWithoutRequestIsRefused(t *testing.T) {
	j := newTxeQueueJob(t)
	f := newQueueFixture(t)
	sealed := finishedRun(t, f, j.dag, "run-sealed", ir.Succeeded)
	queued := cliEnqueueRetry(t, f, j.dag, sealed, nil)

	admitted := distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), queuedItem(t, f, j.dag), queued.AttemptID, queued, j.dag)

	assertRetryDropped(t, f, j, queued, admitted, registry.AdmitRetryUnbound)
}

// A retry request whose ID is not the one derived for the run's retried
// execution and action attempt is refused: it was edited after the hub
// derived it.
func TestQueueDispatch_TxeTamperedRetryRequestIsRefused(t *testing.T) {
	j := newTxeQueueJob(t)
	f := newQueueFixture(t)
	sealed := finishedRun(t, f, j.dag, "run-sealed", ir.Succeeded)
	request, err := ir.NewRetryRequest(sealed.DAGRun(), sealed.AttemptID, sealed.QueuedAt, "act_one", "1", "sha256:one")
	require.NoError(t, err)
	request.ActionAttempt = "2"
	queued := cliEnqueueRetry(t, f, j.dag, sealed, request)

	admitted := distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), queuedItem(t, f, j.dag), queued.AttemptID, queued, j.dag)

	assertRetryDropped(t, f, j, queued, admitted, registry.AdmitRetryMismatch)
}

// A retry request made for another execution, or another run, is refused:
// it names no execution this queued retry replaced.
func TestQueueDispatch_TxeRetryRequestForAnotherExecutionIsRefused(t *testing.T) {
	for name, retried := range map[string]func(*ir.DAGRunStatus) (ir.DAGRunRef, string, string){
		"another execution": func(s *ir.DAGRunStatus) (ir.DAGRunRef, string, string) {
			return s.DAGRun(), s.AttemptID, "2026-01-01T00:00:00Z"
		},
		"another run": func(s *ir.DAGRunStatus) (ir.DAGRunRef, string, string) {
			return ir.NewDAGRunRef(s.Name, "run-other"), s.AttemptID, s.QueuedAt
		},
	} {
		t.Run(name, func(t *testing.T) {
			j := newTxeQueueJob(t)
			f := newQueueFixture(t)
			sealed := finishedRun(t, f, j.dag, "run-sealed", ir.Succeeded)
			run, attemptID, queuedAt := retried(sealed)
			request, err := ir.NewRetryRequest(run, attemptID, queuedAt, "act_one", "1", "sha256:one")
			require.NoError(t, err)
			queued := cliEnqueueRetry(t, f, j.dag, sealed, request)

			admitted := distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), queuedItem(t, f, j.dag), queued.AttemptID, queued, j.dag)

			assertRetryDropped(t, f, j, queued, admitted, registry.AdmitRetryMismatch)
		})
	}
}

// Pending the TXE-7517 binding: a request derived correctly for the retried
// execution passes the request check, even for an action the job does not
// have. The registry binding (approved, executing under a live grant,
// current attempt, version and binding) is what refuses it; until that step
// lands, this test pins the gap.
func TestQueueDispatch_TxeUnknownActionAwaitsBinding(t *testing.T) {
	j := newTxeQueueJob(t)
	f := newQueueFixture(t)
	sealed := finishedRun(t, f, j.dag, "run-sealed", ir.Succeeded)
	forged, err := ir.NewRetryRequest(sealed.DAGRun(), sealed.AttemptID, sealed.QueuedAt, "act_forged", "1", "sha256:forged")
	require.NoError(t, err)
	queued := cliEnqueueRetry(t, f, j.dag, sealed, forged)

	admitted := distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), queuedItem(t, f, j.dag), queued.AttemptID, queued, j.dag)
	assert.True(t, admitted)
	_, has := j.job.Actions["act_forged"]
	assert.False(t, has)
}

// A registered job's first run, queued by any other trigger, is not a retry
// and needs no retry request.
func TestQueueDispatch_TxeFirstRunNeedsNoRequest(t *testing.T) {
	j := newTxeQueueJob(t)
	f := newQueueFixture(t)
	f.dag = j.dag
	f.enqueueRunWithTrigger("run-new", ir.TriggerTypeManual)
	attempt, err := f.dagRunRepository.FindAttempt(f.ctx, ir.NewDAGRunRef(j.dag.Name, "run-new"))
	require.NoError(t, err)
	queued, err := attempt.ReadStatus(f.ctx)
	require.NoError(t, err)

	assert.True(t, distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), queuedItem(t, f, j.dag), queued.AttemptID, queued, j.dag))
}

// The control: a non-TXE DAG's queued retry is outside the registry.
func TestQueueDispatch_NonTxeRetryIsUnguarded(t *testing.T) {
	j := newTxeQueueJob(t)
	f := newQueueFixture(t)
	dag := &ir.DAG{Name: "plain-dag", YamlData: []byte("steps:\n  - name: a\n    command: echo a\n"),
		WorkerSelector: map[string]string{"pool": "a"}, Steps: []ir.Step{{Name: "a", Command: "echo a"}}}
	done := finishedRun(t, f, dag, "run-1", ir.Succeeded)

	queued := cliEnqueueRetry(t, f, dag, done, nil)
	items, err := f.queueStore.List(f.ctx, dag.ProcGroup())
	require.NoError(t, err)
	require.Len(t, items, 1)

	assert.True(t, distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, dag.ProcGroup(), queued.DAGRun(), items[0].ID(), queued.AttemptID, queued, dag))
}
