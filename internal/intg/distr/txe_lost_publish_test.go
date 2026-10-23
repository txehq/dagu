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
	run := txeNewPublishJob(t, txeRetryScript, map[string]string{"TXE_FIXTURE_CONTROL": control},
		func(home txepkg.Home, _ string) []string { return []string{"--dagu-home", home.ClientDir()} },
		[]fixtureOption{
			withWorkerCount(0),
			withStaleThresholds(testStaleHeartbeatThreshold, testStaleLeaseThreshold),
			withZombieDetectionInterval(testZombieDetectorInterval),
		})
	f := run.f
	t.Cleanup(f.cleanup)

	// After a successful seal, the step stays open while the hold file exists.
	hold := filepath.Join(control, "hold-after-seal")
	sealed := filepath.Join(control, "sealed")
	require.NoError(t, os.WriteFile(hold, nil, 0o600))
	wrapper := fmt.Sprintf(`#!/bin/sh
if [ "$1 $2 $3" = "txe resource check" ]; then exit 0; fi
if [ "$1 $2 $3" = "txe artifacts seal" ]; then
  %q "$@" || exit $?
  : > %q
  while [ -e %q ]; do sleep 0.2; done
  exit 0
fi
exec %q "$@"
`, f.coord.Config.Paths.Executable, sealed, hold, f.coord.Config.Paths.Executable)
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
	return &txeLostPublish{run: run, control: control, failed: failed}
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
