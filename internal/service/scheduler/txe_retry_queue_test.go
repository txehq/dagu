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

// TXE-7518 characterization, on origin/main 47b89206c: a retry of a
// registered job's sealed run that the local CLI queued carries no retry
// request, and queue dispatch admits it because the job is active and on its
// current version. Nothing binds it to an approved dagu.retry_run action, so
// the sealed execution would run again.
func TestQueueDispatch_TxeCLIRetryOfSealedRun_Characterization(t *testing.T) {
	j := newTxeQueueJob(t)
	f := newQueueFixture(t)
	sealed := finishedRun(t, f, j.dag, "run-sealed", ir.Succeeded)

	queued := cliEnqueueRetry(t, f, j.dag, sealed, nil)
	assert.Nil(t, queued.RetryRequest, "the CLI cannot carry an approval")
	items, err := f.queueStore.List(f.ctx, j.dag.ProcGroup())
	require.NoError(t, err)
	require.Len(t, items, 1)

	admitted := distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), items[0].ID(), queued.AttemptID, queued, j.dag)
	assert.True(t, admitted, "today: only lifecycle and version are checked")
}

// TXE-7518 characterization: a queued retry whose recorded request names an
// action the job does not have is admitted the same way; the request is not
// read at dispatch.
func TestQueueDispatch_TxeForgedRetryRequest_Characterization(t *testing.T) {
	j := newTxeQueueJob(t)
	f := newQueueFixture(t)
	sealed := finishedRun(t, f, j.dag, "run-sealed", ir.Succeeded)
	forged, err := ir.NewRetryRequest(sealed.DAGRun(), sealed.AttemptID, sealed.QueuedAt, "act_forged", "1", "sha256:forged")
	require.NoError(t, err)

	queued := cliEnqueueRetry(t, f, j.dag, sealed, forged)
	items, err := f.queueStore.List(f.ctx, j.dag.ProcGroup())
	require.NoError(t, err)
	require.Len(t, items, 1)

	admitted := distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), items[0].ID(), queued.AttemptID, queued, j.dag)
	assert.True(t, admitted, "today: the recorded request is not checked")
	_, has := j.job.Actions["act_forged"]
	assert.False(t, has)
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
