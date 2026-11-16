// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmd"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// txeJobRetryFixture is a registered job's DAG, as the TXE renderer names
// and pins it, with one finished run.
type txeJobRetryFixture struct {
	th       test.Command
	location string
	jobID    string
	runID    string
	attempt  string
}

func newTxeJobRetryFixture(t *testing.T, globalQueue bool) txeJobRetryFixture {
	t.Helper()
	jobID, err := registry.NewID(registry.PrefixJob, time.Now())
	require.NoError(t, err)
	var opts []test.HelperOption
	if globalQueue {
		opts = append(opts, test.WithConfigMutator(func(cfg *config.Config) {
			cfg.Queues = config.Queues{Enabled: true, Config: []config.QueueConfig{{Name: jobID, MaxActiveRuns: 1}}}
		}))
	}
	th := test.SetupCommand(t, opts...)
	dagFile := th.DAG(t, fmt.Sprintf(`name: %s
worker_selector:
  txe.machine: mch_test
steps:
  - name: run
    run: echo job
`, jobID))

	runID := "sealed-run"
	startedAt := time.Now().Add(-time.Minute)
	attempt, err := th.DAGRunRepository.CreateAttempt(th.Context, dagFile.DAG, startedAt, runID, persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	logPath := filepath.Join(th.Config.Paths.LogDir, "txe-job-retry.log")
	require.NoError(t, os.MkdirAll(filepath.Dir(logPath), 0o750))
	status := ir.NewStatusBuilder(dagFile.DAG).Create(runID, ir.Succeeded, 0, startedAt,
		ir.WithAttemptID(attempt.ID()), ir.WithLogFilePath(logPath))
	writeStatus(t, th.Context, attempt, status)
	return txeJobRetryFixture{th: th, location: dagFile.Location, jobID: jobID, runID: runID, attempt: attempt.ID()}
}

func (f txeJobRetryFixture) latest(t *testing.T) *ir.DAGRunStatus {
	t.Helper()
	attempt, err := f.th.DAGRunRepository.FindAttempt(f.th.Context, ir.NewDAGRunRef(f.jobID, f.runID))
	require.NoError(t, err)
	status, err := attempt.ReadStatus(f.th.Context)
	require.NoError(t, err)
	return status
}

// TXE-7518 characterization, on origin/main 47b89206c: the plain local
// `dagu retry` of a registered job's run is refused before any effect, by
// the upstream rule for DAGs with a worker selector, not by any TXE rule.
func TestRetryCommand_TxeJobLocalRetryRefusedBySelector_Characterization(t *testing.T) {
	f := newTxeJobRetryFixture(t, true)

	err := f.th.RunCommandWithError(t, cmd.Retry(), test.CmdTest{
		Args: []string{"retry", "--run-id=" + f.runID, f.location},
	})
	require.ErrorContains(t, err, "with workerSelector via CLI")

	items, err := f.th.QueueStore.List(f.th.Context, f.jobID)
	require.NoError(t, err)
	require.Empty(t, items)
	require.Equal(t, ir.Succeeded, f.latest(t).Status)
}

// TXE-7518 characterization: with --worker-id and --attempt-id, flags the
// worker sets for a dispatched task but any shell user can pass, the same
// command skips that rule. When the job's proc group has a global queue, it
// re-queues the sealed run as a retry with no retry request, checked by
// nothing TXE before queue dispatch.
func TestRetryCommand_TxeJobRetryWithWorkerFlagsIsQueued_Characterization(t *testing.T) {
	f := newTxeJobRetryFixture(t, true)

	f.th.RunCommand(t, cmd.Retry(), test.CmdTest{
		Args: []string{"retry", "--run-id=" + f.runID, "--worker-id=shell", "--attempt-id=" + f.attempt, f.location},
	})

	items, err := f.th.QueueStore.List(f.th.Context, f.jobID)
	require.NoError(t, err)
	require.Len(t, items, 1)
	queued := f.latest(t)
	require.Equal(t, ir.Queued, queued.Status)
	require.Equal(t, ir.TriggerTypeRetry, queued.TriggerType)
	require.Nil(t, queued.RetryRequest)
}

// TXE-7518 characterization: without a global queue, the same flags take
// the worker's execution path, which runs only an attempt the coordinator
// prepared; the sealed attempt is refused and keeps its status.
func TestRetryCommand_TxeJobRetryWithWorkerFlagsNoQueueRefused_Characterization(t *testing.T) {
	f := newTxeJobRetryFixture(t, false)

	err := f.th.RunCommandWithError(t, cmd.Retry(), test.CmdTest{
		Args: []string{"retry", "--run-id=" + f.runID, "--worker-id=shell", "--attempt-id=" + f.attempt, f.location},
	})
	require.ErrorContains(t, err, "already recorded status succeeded")

	items, err := f.th.QueueStore.List(f.th.Context, f.jobID)
	require.NoError(t, err)
	require.Empty(t, items)
	latest := f.latest(t)
	require.Equal(t, ir.Succeeded, latest.Status)
	require.Equal(t, f.attempt, latest.AttemptID)
}
