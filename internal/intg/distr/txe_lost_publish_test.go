// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/cmdutil"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/runtime/executor"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// txeLostPublish is a run whose worker sealed the job's result and then lost
// its coordinator before the publish step started (IT-15 I5). The hub has
// failed the run on lease expiry, and the worker is back under the same id.
type txeLostPublish struct {
	run     *txePublishRun
	control string
	failed  ir.DAGRunStatus
	// credential is the job's own credential file (FIXTURE_TOKEN), and envLog
	// what the job's variable and secret were when seal and publish ran.
	credential, envLog string
}

const txeLostWorker = "txe-mac-worker"

// txeStartLostPublish brings a run to that state. The step's dagu runs the
// real seal and then holds the step open, so the publish step cannot start
// while the worker is killed.
func txeStartLostPublish(t *testing.T) *txeLostPublish {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("job packages are shell scripts run by a Unix worker")
	}
	control := t.TempDir()
	credential := filepath.Join(control, "fixture-token")
	require.NoError(t, os.WriteFile(credential, []byte("txe-fixture-token\n"), 0o600))
	envLog := filepath.Join(control, "env.log")
	run := txeNewPublishJob(t, txeRetryScript, map[string]string{"TXE_FIXTURE_CONTROL": control, "JOB_SENTINEL": "present"},
		func(home txepkg.Home, _ string) []string { return []string{"--dagu-home", home.ClientDir()} },
		[]fixtureOption{
			withWorkerCount(0),
			withStaleThresholds(testStaleHeartbeatThreshold, testStaleLeaseThreshold),
			withZombieDetectionInterval(testZombieDetectorInterval),
		},
		func(spec *txepkg.DAGSpec, _ txepkg.Home) {
			spec.CredentialRefs = []txepkg.CredentialRef{{Name: "FIXTURE_TOKEN", Kind: txepkg.CredentialFile, Locator: credential}}
		})
	f := run.f
	t.Cleanup(f.cleanup)

	// After a successful seal, the step stays open while the hold file exists.
	hold := filepath.Join(control, "hold-after-seal")
	sealed := filepath.Join(control, "sealed")
	require.NoError(t, os.WriteFile(hold, nil, 0o600))
	wrapper := fmt.Sprintf(`#!/bin/sh
if [ "$1 $2" = "txe artifacts" ]; then
  printf '%%s job=%%s secret=%%s\n' "$3" "${JOB_SENTINEL:-}" "${FIXTURE_TOKEN:+set}" >> %q
fi
if [ "$1 $2 $3" = "txe resource check" ]; then exit 0; fi
if [ "$1 $2 $3" = "txe artifacts seal" ]; then
  %q "$@" || exit $?
  : > %q
  while [ -e %q ]; do sleep 0.2; done
  exit 0
fi
exec %q "$@"
`, envLog, f.coord.Config.Paths.Executable, sealed, hold, f.coord.Config.Paths.Executable)
	require.NoError(t, os.WriteFile(filepath.Join(run.home.Root, "bin", "dagu"), []byte(wrapper), 0o700)) //nolint:gosec // a test script

	worker, _ := startWorkerProcess(t, f, txeLostWorker, "txe.machine="+txeTestMachine)
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(90 * time.Second)

	require.Eventually(t, func() bool {
		_, err := os.Stat(sealed)
		return err == nil
	}, distrTestTimeout(45*time.Second), 100*time.Millisecond, "the job's step did not seal")
	require.Equal(t, 1, txeExecutions(t, control))
	running, err := f.latestStatus()
	require.NoError(t, err)
	seal, err := txeclient.Outputs{Home: run.home}.Sealed(txeTestJob, running.DAGRunID)
	require.NoError(t, err)
	require.Equal(t, txeExecution(running), seal.Execution, "the running execution sealed its own outputs")

	// The worker is gone: its coordinator hears nothing more from it.
	require.NoError(t, cmdutil.TerminateProcessGroup(worker, cmdutil.ForceTermination()))
	failed := f.waitForStatus(ir.Failed, 45*time.Second)
	require.Equal(t, running.DAGRunID, failed.DAGRunID)
	require.Equal(t, running.AttemptID, failed.AttemptID)
	assert.Equal(t, dispatch.DistributedLeaseExpiredReason(txeLostWorker), failed.Error)
	require.Len(t, failed.Nodes, 2)
	assert.NotEqual(t, ir.NodeSucceeded, failed.Nodes[0].Status, "the hub saw the job's step finish")
	assert.NotEqual(t, ir.NodeSucceeded, failed.Nodes[1].Status, "the hub saw publish finish")
	_, published := run.registry.execution(failed)
	assert.False(t, published, "the lost execution published")
	assert.Empty(t, run.registry.manifests, "something was published")

	// The machine comes back under the same worker id.
	require.NoError(t, os.Remove(hold))
	startWorkerProcess(t, f, txeLostWorker, "txe.machine="+txeTestMachine)
	return &txeLostPublish{run: run, control: control, failed: failed, credential: credential, envLog: envLog}
}

// IT-15 I5 (TXE-5043): a retry of the publish step alone, made once the
// worker is back, does not run publish while the hub has the job's step as
// failed, because a step retry treats a failed prerequisite as blocking. The
// retried execution must then not be a success: nothing was published, and
// the script did not run again. It used to be reported succeeded.
func TestTXELostPublish_PublishStepRetryIsBlockedByTheFailedStep(t *testing.T) {
	lost := txeStartLostPublish(t)
	run, failed := lost.run, lost.failed

	run.retryDirect(t, failed.DAGRunID, "publish")
	retried := run.waitFor(t, "the publish-only execution did not finish", func(s ir.DAGRunStatus) bool {
		return s.DAGRunID == failed.DAGRunID && s.AttemptID != failed.AttemptID && !s.Status.IsActive() && s.Status != ir.NotStarted
	})
	// Give a publish that might still start the time to record a manifest.
	time.Sleep(3 * time.Second)
	latest, err := run.f.latestStatus()
	require.NoError(t, err)
	require.Equal(t, retried.AttemptID, latest.AttemptID)
	t.Logf("publish-only retry: status %s; %s=%s %q; %s=%s %q", latest.Status,
		latest.Nodes[0].Step.Name, latest.Nodes[0].Status, latest.Nodes[0].Error,
		latest.Nodes[1].Step.Name, latest.Nodes[1].Status, latest.Nodes[1].Error)

	assert.Equal(t, ir.NodeFailed, latest.Nodes[0].Status, "the job's step keeps the hub's failure")
	assert.Equal(t, ir.NodeAborted, latest.Nodes[1].Status)
	assert.Equal(t, "upstream failed", latest.Nodes[1].Error)
	_, published := run.registry.execution(latest)
	assert.False(t, published, "publish ran")
	assert.Empty(t, run.registry.manifests)
	assert.Equal(t, 1, txeExecutions(t, lost.control))
	assert.Equal(t, ir.Failed, latest.Status, "an execution whose only selected step did not run is not a success")
}

// republish dispatches the republish of the lost execution's sealed result,
// as the hub does for an approved dagu.retry_run with step "publish": a
// conditional retry of the publish step that accepts the job's failed step.
// Without a request, nothing records which execution it retries.
func (l *txeLostPublish) republish(t *testing.T, withRequest bool) (*dispatch.AdmittedExecution, error) {
	t.Helper()
	dag := l.run.f.dagWrapper.DAG
	opts := []executor.TaskOption{executor.WithWorkerSelector(dag.WorkerSelector), executor.WithPreviousStatus(&l.failed),
		executor.WithStep(txepkg.PublishStepName), executor.WithAcceptFailedPrerequisites(true)}
	if withRequest {
		opts = append(opts, executor.WithRequireLatestIsPrevious(true), executor.WithRetryRequest("act_republish", "1", "sha256:binding"))
	}
	task := executor.CreateTask(dag.Name, string(dag.YamlData), dispatch.DispatchOperationRetry, l.failed.DAGRunID, opts...)
	admitted := &dispatch.AdmittedExecution{}
	err := l.run.f.coord.GetCoordinatorClient(t).Dispatch(l.run.f.coord.Context, dispatch.DispatchRequest{Task: task, Admitted: admitted})
	return admitted, err
}

func (l *txeLostPublish) nextExecution(t *testing.T, what string) ir.DAGRunStatus {
	t.Helper()
	return l.run.waitFor(t, what, func(s ir.DAGRunStatus) bool {
		return s.DAGRunID == l.failed.DAGRunID && s.AttemptID != l.failed.AttemptID && !s.Status.IsActive() && s.Status != ir.NotStarted
	})
}

// TXE-5067: the republish publishes what the lost execution sealed, from a
// new execution of the run. The job's script does not run again, the
// manifest names the lost execution as the producer with the sealed bytes'
// digest, and the run is a success; the job's step keeps the hub's failure,
// marked accepted.
func TestTXELostPublish_RepublishPublishesTheSealedResult(t *testing.T) {
	lost := txeStartLostPublish(t)
	run, failed := lost.run, lost.failed

	admitted, err := lost.republish(t, true)
	require.NoError(t, err)
	republished := lost.nextExecution(t, "the republish did not finish")
	require.Equal(t, admitted.AttemptID, republished.AttemptID, "the execution the coordinator admitted is the one that ran")
	assert.Equal(t, ir.Succeeded, republished.Status, "publish: %s", republished.Nodes[len(republished.Nodes)-1].Error)
	require.NotNil(t, republished.RetryRequest)
	assert.Equal(t, txeExecution(failed).Ref(), republished.RetryRequest.RetryOf, "the coordinator recorded the lost execution as the one retried")
	assert.Equal(t, 1, txeExecutions(t, lost.control), "the job's script ran again")
	require.Len(t, republished.Nodes, 2)
	assert.Equal(t, ir.NodeFailed, republished.Nodes[0].Status)
	assert.True(t, republished.Nodes[0].FailureAcceptedByRetry, "the acceptance is recorded")
	assert.Equal(t, ir.NodeSucceeded, republished.Nodes[1].Status)

	manifest, ok := run.registry.execution(republished)
	require.True(t, ok, "the republish recorded no manifest")
	assert.Equal(t, txeExecution(republished), manifest.Execution)
	assert.Equal(t, txeExecution(failed), manifest.ProducedIn)
	assert.Equal(t, txeDigest(txeExecutionContent(1)), manifest.Artifacts[0].SHA256)
	assert.Len(t, run.registry.manifests, 1)
}

// A republish that nothing records as the retry of the lost execution fails
// closed: the publish step refuses rather than publish whatever was sealed
// last, and the run is not a success.
func TestTXELostPublish_RepublishWithoutARecordedRetryFailsClosed(t *testing.T) {
	lost := txeStartLostPublish(t)

	_, err := lost.republish(t, false)
	require.NoError(t, err)
	retried := lost.nextExecution(t, "the unrecorded republish did not finish")
	assert.Equal(t, ir.Failed, retried.Status)
	require.Len(t, retried.Nodes, 2)
	assert.Equal(t, ir.NodeFailed, retried.Nodes[1].Status, "the publish step refused")
	_, published := lost.run.registry.execution(retried)
	assert.False(t, published)
	assert.Empty(t, lost.run.registry.manifests)
	assert.Equal(t, 1, txeExecutions(t, lost.control))
}

// The same republish sent again, as after a lost answer, is refused: the
// lost execution is no longer the run's latest. One execution of the job,
// one republish, one manifest.
func TestTXELostPublish_RepublishReplayIsRefused(t *testing.T) {
	lost := txeStartLostPublish(t)

	first, err := lost.republish(t, true)
	require.NoError(t, err)
	republished := lost.nextExecution(t, "the republish did not finish")
	require.Equal(t, ir.Succeeded, republished.Status)

	_, err = lost.republish(t, true)
	require.Error(t, err, "a second republish of the same execution was admitted")
	time.Sleep(2 * time.Second)
	latest, err := lost.run.f.latestStatus()
	require.NoError(t, err)
	assert.Equal(t, first.AttemptID, latest.AttemptID, "a second execution was created")
	assert.Len(t, txeHubAttempts(t, lost.run.f, lost.failed.DAGRunID), 2, "the lost execution and the one republish")
	assert.Len(t, lost.run.registry.manifests, 1)
	assert.Equal(t, 1, txeExecutions(t, lost.control))
}

// TXE-5067: a republish runs the publish step with the TXE variables alone.
// The job's own variable and secret, which every ordinary execution of the
// job gets, do not reach it, and its secrets are not resolved at all: with
// the job's credential file gone, the republish still publishes.
func TestTXELostPublish_RepublishRunsWithoutTheJobsVariablesAndSecrets(t *testing.T) {
	lost := txeStartLostPublish(t)
	run, failed := lost.run, lost.failed
	before, err := os.ReadFile(lost.envLog)
	require.NoError(t, err)
	assert.Contains(t, string(before), "begin job=present secret=set", "an ordinary execution gets the job's variable and secret")
	require.NoError(t, os.Remove(lost.credential))

	_, err = lost.republish(t, true)
	require.NoError(t, err)
	republished := lost.nextExecution(t, "the republish did not finish")
	assert.Equal(t, ir.Succeeded, republished.Status, "publish: %s", republished.Nodes[len(republished.Nodes)-1].Error)
	manifest, ok := run.registry.execution(republished)
	require.True(t, ok, "the republish recorded no manifest")
	assert.Equal(t, txeExecution(failed), manifest.ProducedIn)
	assert.Equal(t, 1, txeExecutions(t, lost.control))

	after, err := os.ReadFile(lost.envLog)
	require.NoError(t, err)
	assert.Contains(t, string(after), "publish job= secret=", "the republish's publish step got the job's variable or secret")
	assert.NotContains(t, string(after), "publish job=present")
}
