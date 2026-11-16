// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/runtime/executor"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
	"github.com/dagucloud/dagu/v2/internal/txe/review/reviewtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TXE-7515: a person's decided retry of the lost execution, carried out by
// the job machine's real executor. The executor reads the seal the worker
// really wrote (the reader the reviewer command wires) and dispatches
// through the coordinator as the hub does for an approved dagu.retry_run:
// conditional on the lost execution, with the action's retry request, and
// for a republish only the publish step, accepting the failed job step.

// txeOwnerRuns is the hub's side of a retry, as review.RunRetrier, over
// the test coordinator.
type txeOwnerRuns struct {
	t    *testing.T
	lost *txeLostPublish
}

func (h txeOwnerRuns) RunState(_ context.Context, _, _ string) (review.RunState, error) {
	s, err := h.lost.run.f.latestStatus()
	if err != nil {
		return review.RunState{}, err
	}
	return review.RunState{AttemptID: s.AttemptID, QueuedAt: s.QueuedAt, Status: s.Status.String(),
		Active: s.Status.IsActive(), Succeeded: s.Status == ir.Succeeded}, nil
}

func (h txeOwnerRuns) RetryRun(_ context.Context, _, runID string, expected review.Execution, request review.RetryRequest) (review.Execution, error) {
	f := h.lost.run.f
	failed := h.lost.failed
	if failed.DAGRunID != runID || failed.AttemptID != expected.AttemptID || failed.QueuedAt != expected.QueuedAt {
		return review.Execution{}, review.ErrRunNotRetryable
	}
	dag := f.dagWrapper.DAG
	opts := []executor.TaskOption{executor.WithWorkerSelector(dag.WorkerSelector), executor.WithPreviousStatus(&failed),
		executor.WithRequireLatestIsPrevious(true), executor.WithRetryRequest(request.ActionID, request.ActionAttempt, request.BindingDigest)}
	switch {
	case request.Step == txepkg.PublishStepName:
		opts = append(opts, executor.WithStep(txepkg.PublishStepName), executor.WithAcceptFailedPrerequisites(true))
	case request.Rerun:
		// As the hub does for {stepName: run, includeDownstream: true}.
		opts = append(opts, executor.WithStep(txepkg.RunStepName), executor.WithIncludeDownstream(true))
	}
	task := executor.CreateTask(dag.Name, string(dag.YamlData), dispatch.DispatchOperationRetry, runID, opts...)
	admitted := &dispatch.AdmittedExecution{}
	if err := f.coord.GetCoordinatorClient(h.t).Dispatch(f.coord.Context, dispatch.DispatchRequest{Task: task, Admitted: admitted}); err != nil {
		return review.Execution{}, err
	}
	return review.Execution{AttemptID: admitted.AttemptID, QueuedAt: admitted.QueuedAt}, nil
}

func (txeOwnerRuns) Abandoned(context.Context, string, string, string) (bool, bool) {
	return false, true
}

func (txeOwnerRuns) Recover(context.Context, string, string, review.Execution, review.RetryRequest) review.RetryRecovery {
	return review.RetryRecovery{}
}

func (txeOwnerRuns) Republishes(context.Context) (bool, error) { return true, nil }

// txeOwnerSeals reads the worker's sealed results the way the reviewer
// command's seal reader does.
type txeOwnerSeals struct{ outputs txeclient.Outputs }

func (s txeOwnerSeals) RetriedSeal(jobID, runID string, e review.Execution) (int, error) {
	seal, err := s.outputs.RetriedSeal(jobID, runID, txeclient.Execution{AttemptID: e.AttemptID, QueuedAt: e.QueuedAt})
	if errors.Is(err, txeclient.ErrNotSealed) {
		return 0, fmt.Errorf("%w: %w", review.ErrNotSealed, err)
	}
	if err != nil {
		return 0, err
	}
	return len(seal.Files), nil
}

const txeOwnerMachine = "mch_01HZX0000000000000000000AA"

// txeOwnerRetry records a person's decided retry of the lost execution with
// the given intent parameters and has the machine's executor carry it out.
func txeOwnerRetry(t *testing.T, lost *txeLostPublish, intent map[string]string) review.Executed {
	t.Helper()
	return txeOwnerRetryWith(t, lost, intent, txeOwnerRuns{t: t, lost: lost})
}

// txeOwnerRetryWith is txeOwnerRetry through the given hub side.
func txeOwnerRetryWith(t *testing.T, lost *txeLostPublish, intent map[string]string, runs review.RunRetrier) review.Executed {
	t.Helper()
	failed := lost.failed
	reg := reviewtest.New()
	job := review.Job{
		ID: txeTestJob, OwnerID: "own_01HZX0000000000000000000AA", ProjectID: "prj_01HZX0000000000000000000AA",
		MachineID: txeOwnerMachine, Version: 1, PackageDigest: "sha256:package", DAGSpecSHA256: "sha256:spec",
		Title: "Lost publish", Purpose: "Publish what was sealed.", Lifecycle: review.LifecycleActive, Availability: review.AvailabilityReady,
		Review: review.ReviewPolicy{Brief: "Check it.", CadenceSec: 3600, MaxAttempts: 2},
	}
	require.NoError(t, reg.PutJob(job))
	params := map[string]string{
		review.RetryRunParam: failed.DAGRunID, review.RetryRunAttemptParam: failed.AttemptID, review.RetryRunQueuedParam: failed.QueuedAt,
		review.RetryRunSpecParam: job.DAGSpecSHA256, review.RetryRunPackageParam: job.PackageDigest,
	}
	maps.Copy(params, intent)
	proposal := review.Proposal{ID: "prop-owner", JobID: txeTestJob, Kind: review.ProposalAction, ActionName: review.RetryRunAction,
		Params: params, Question: "the owner's request"}
	require.NoError(t, reg.Update(func(s *reviewtest.State) error {
		proposal.State = review.ProposalOpen
		proposal.BindingDigest = reviewtest.BindingDigest(s.Jobs[txeTestJob], proposal.ActionName, proposal.TargetID, proposal.Params)
		s.Proposals[txeTestJob] = append(s.Proposals[txeTestJob], proposal)
		return nil
	}))
	decided, err := reg.Decide(txeTestJob, proposal.ID, review.VerdictRetry, "", "connor")
	require.NoError(t, err)

	r := &review.Reviewer{
		MachineID: txeOwnerMachine, Registry: reg, Holder: txeOwnerMachine + "/executor", AgentClient: "none",
		DecideDAG: review.DecideDAGName(txeOwnerMachine), ClaimTTL: 10 * time.Minute,
		Runs:         runs,
		Seals:        txeOwnerSeals{txeclient.Outputs{Home: lost.run.home}},
		RetryObserve: distrTestTimeout(30 * time.Second),
	}
	out, err := r.Execute(context.Background(), txeTestJob, proposal.ID, decided.ID)
	require.NoError(t, err)
	return out
}

// A retry that names no intent, of an execution that sealed its result, is
// not carried out: no new execution, the script does not run again, and
// nothing is published. The detail names the two explicit requests.
func TestTXEOwnerRecovery_UnspecifiedRetryOfASealedRunIsNotDispatched(t *testing.T) {
	lost := txeStartLostPublish(t)

	out := txeOwnerRetry(t, lost, nil)
	require.NotEmpty(t, out.Action.ID, "nothing was begun: %s", out.Skipped)
	assert.Equal(t, review.ActionFailed, out.Action.State)
	assert.Contains(t, out.Action.Detail, "not dispatched")
	assert.Contains(t, out.Action.Detail, "republish")
	assert.Contains(t, out.Action.Detail, "explicit rerun")

	time.Sleep(2 * time.Second)
	latest, err := lost.run.f.latestStatus()
	require.NoError(t, err)
	assert.Equal(t, lost.failed.AttemptID, latest.AttemptID, "a new execution was created")
	assert.Len(t, txeHubAttempts(t, lost.run.f, lost.failed.DAGRunID), 1)
	assert.Equal(t, 1, txeExecutions(t, lost.control), "the job's script ran again")
	assert.Empty(t, lost.run.registry.manifests, "something was published")
}

// An explicit rerun runs the job again on purpose: a second execution of
// the script, which publishes its own result; the sealed one is superseded
// and never published, and the action says so.
func TestTXEOwnerRecovery_ExplicitRerunRunsTheJobAgain(t *testing.T) {
	lost := txeStartLostPublish(t)

	out := txeOwnerRetry(t, lost, map[string]string{review.RetryRunStepParam: review.RetryStepRun})
	require.NotEmpty(t, out.Action.ID, "nothing was begun: %s", out.Skipped)
	assert.Equal(t, review.ActionSucceeded, out.Action.State, out.Action.Detail)
	assert.Contains(t, out.Action.Detail, "superseded and was not published")
	rerun := lost.nextExecution(t, "the rerun did not finish")
	assert.Equal(t, ir.Succeeded, rerun.Status)
	assert.Equal(t, 2, txeExecutions(t, lost.control), "the job's script did not run again")
	manifest, ok := lost.run.registry.execution(rerun)
	require.True(t, ok, "the rerun published nothing")
	assert.Equal(t, txeExecution(rerun), manifest.ProducedIn)
	assert.Equal(t, txeDigest(txeExecutionContent(2)), manifest.Artifacts[0].SHA256)
	_, published := lost.run.registry.execution(lost.failed)
	assert.False(t, published, "the sealed result was published")
}

// A person's republish of the sealed run, which no review packet needs to
// show, publishes what the lost execution sealed: the script does not run
// again, the manifest names the lost execution as the producer with the
// sealed bytes' digest, and the same request is not carried out twice.
func TestTXEOwnerRecovery_OwnerRepublishPublishesTheSealedResult(t *testing.T) {
	lost := txeStartLostPublish(t)

	out := txeOwnerRetry(t, lost, map[string]string{review.RetryRunStepParam: review.RetryStepPublish})
	require.NotEmpty(t, out.Action.ID, "nothing was begun: %s", out.Skipped)
	assert.Equal(t, review.ActionSucceeded, out.Action.State, out.Action.Detail)
	republished := lost.nextExecution(t, "the republish did not finish")
	assert.Equal(t, ir.Succeeded, republished.Status, "publish: %s", republished.Nodes[len(republished.Nodes)-1].Error)
	require.NotNil(t, republished.RetryRequest)
	assert.Equal(t, txeExecution(lost.failed).Ref(), republished.RetryRequest.RetryOf)
	assert.Equal(t, 1, txeExecutions(t, lost.control), "the job's script ran again")
	manifest, ok := lost.run.registry.execution(republished)
	require.True(t, ok, "the republish recorded no manifest")
	assert.Equal(t, txeExecution(lost.failed), manifest.ProducedIn)
	assert.Equal(t, txeDigest(txeExecutionContent(1)), manifest.Artifacts[0].SHA256)
	assert.Len(t, lost.run.registry.manifests, 1)

	// The same decision carried out again finds the run moved on.
	again := txeOwnerRetry(t, lost, map[string]string{review.RetryRunStepParam: review.RetryStepPublish})
	assert.Empty(t, again.Action.ID, "a republish of an execution that is no longer the latest was begun")
	assert.Contains(t, again.Skipped, "nothing is retried")
	assert.Equal(t, 1, txeExecutions(t, lost.control))
	assert.Len(t, lost.run.registry.manifests, 1)
}

// An explicit rerun of a run whose job step succeeded and sealed its result
// and whose publish failed runs the job's step again: a native retry of the
// run would keep the succeeded job step and only publish, so the result the
// person asked to supersede would be published. The rerun is a new
// execution of the script that seals and publishes its own result.
func TestTXEOwnerRecovery_ExplicitRerunRunsAJobStepThatSucceeded(t *testing.T) {
	control := t.TempDir()
	run := txeStartPublishJob(t, txeRetryScript, map[string]string{"TXE_FIXTURE_CONTROL": control},
		func(home txepkg.Home, _ string) []string { return []string{"--dagu-home", home.ClientDir()} })
	first := run.f.waitForStatus(ir.Succeeded, executionStatusTimeout())
	runID := first.DAGRunID

	// The job runs again and seals; publishing fails.
	run.registry.setDown(true)
	run.retryDirect(t, runID, txepkg.RunStepName)
	failed := run.waitFor(t, "the second execution did not fail at publish", func(s ir.DAGRunStatus) bool {
		return s.DAGRunID == runID && s.AttemptID != first.AttemptID && s.Status == ir.Failed
	})
	require.Equal(t, 2, txeExecutions(t, control))
	require.Len(t, failed.Nodes, 2)
	require.Equal(t, ir.NodeSucceeded, failed.Nodes[0].Status, "the job step succeeded")
	seal, err := txeclient.Outputs{Home: run.home}.Sealed(txeTestJob, runID)
	require.NoError(t, err)
	require.Equal(t, txeExecution(failed), seal.Execution)
	run.registry.setDown(false)

	lost := &txeLostPublish{run: run, control: control, failed: failed}
	out := txeOwnerRetry(t, lost, map[string]string{review.RetryRunStepParam: review.RetryStepRun})
	require.NotEmpty(t, out.Action.ID, "nothing was begun: %s", out.Skipped)
	assert.Equal(t, review.ActionSucceeded, out.Action.State, out.Action.Detail)
	assert.Contains(t, out.Action.Detail, "superseded and was not published")
	rerun := lost.nextExecution(t, "the rerun did not finish")
	assert.Equal(t, ir.Succeeded, rerun.Status)
	assert.Equal(t, 3, txeExecutions(t, control), "the job's step did not run again")
	manifest, ok := run.registry.execution(rerun)
	require.True(t, ok, "the rerun published nothing")
	assert.Equal(t, txeExecution(rerun), manifest.ProducedIn, "what was published is the rerun's own result")
	assert.Equal(t, txeDigest(txeExecutionContent(3)), manifest.Artifacts[0].SHA256)
	_, published := run.registry.execution(failed)
	assert.False(t, published, "the superseded sealed result was published")
}

// Root's ruling (TXE-7515): the explicit modes do not redefine an ordinary
// retry. A retry that names no intent, of a run whose job step failed and
// sealed nothing, is carried out as it always was: a native retry of the
// run (no step named, no rerun form), which runs the job's script again and
// publishes the new execution's result.
func TestTXEOwnerRecovery_UnspecifiedRetryOfAnUnsealedRunIsUnchanged(t *testing.T) {
	control := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(control, "fail-job"), nil, 0o600))
	run := txeStartPublishJob(t, txeRetryScript, map[string]string{"TXE_FIXTURE_CONTROL": control},
		func(home txepkg.Home, _ string) []string { return []string{"--dagu-home", home.ClientDir()} })
	failed := run.f.waitForStatus(ir.Failed, executionStatusTimeout())
	require.Equal(t, 1, txeExecutions(t, control))
	require.Len(t, failed.Nodes, 2)
	require.Equal(t, ir.NodeFailed, failed.Nodes[0].Status, "the job step failed")
	_, err := txeclient.Outputs{Home: run.home}.Sealed(txeTestJob, failed.DAGRunID)
	require.ErrorIs(t, err, txeclient.ErrNotSealed, "nothing was sealed")
	require.NoError(t, os.Remove(filepath.Join(control, "fail-job")))

	lost := &txeLostPublish{run: run, control: control, failed: failed}
	runs := &txeRecordingRuns{txeOwnerRuns: txeOwnerRuns{t: t, lost: lost}}
	out := txeOwnerRetryWith(t, lost, nil, runs)
	require.NotEmpty(t, out.Action.ID, "nothing was begun: %s", out.Skipped)
	assert.Equal(t, review.ActionSucceeded, out.Action.State, out.Action.Detail)
	assert.NotContains(t, out.Action.Detail, "superseded")
	require.Len(t, runs.requests, 1)
	assert.Equal(t, review.RetryRequest{ActionID: runs.requests[0].ActionID, ActionAttempt: runs.requests[0].ActionAttempt,
		BindingDigest: runs.requests[0].BindingDigest}, runs.requests[0], "a native retry of the run: no step, no rerun form")

	rerun := lost.nextExecution(t, "the retry did not finish")
	assert.Equal(t, ir.Succeeded, rerun.Status)
	assert.Equal(t, 2, txeExecutions(t, control), "the job's script ran again")
	manifest, ok := run.registry.execution(rerun)
	require.True(t, ok, "the retry published nothing")
	assert.Equal(t, txeExecution(rerun), manifest.ProducedIn)
	assert.Equal(t, txeDigest(txeExecutionContent(2)), manifest.Artifacts[0].SHA256)
}

// txeRecordingRuns is txeOwnerRuns that keeps every retry request sent.
type txeRecordingRuns struct {
	txeOwnerRuns
	requests []review.RetryRequest
}

func (h *txeRecordingRuns) RetryRun(ctx context.Context, jobID, runID string, expected review.Execution, request review.RetryRequest) (review.Execution, error) {
	h.requests = append(h.requests, request)
	return h.txeOwnerRuns.RetryRun(ctx, jobID, runID, expected, request)
}
