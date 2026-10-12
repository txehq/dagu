// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/runtime/executor"
)

// receiptFixture runs a DAG on an isolated worker (no handle on the hub's
// stores) whose step records the attempt and queue marker it sees, holds
// while a hold file exists, and fails until told to succeed.
type receiptFixture struct {
	f   *testFixture
	dir string
}

func newReceiptFixture(t *testing.T, opts ...fixtureOption) *receiptFixture {
	t.Helper()
	if goruntime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX shell script")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "record.sh"), []byte(`#!/bin/sh
# $1 attempt id, $2 queue marker, as the step's command received them
n=$(ls "$RECORDS" | grep -c '^seen\.' || true)
printf '%s|%s' "$1" "$2" > "$RECORDS/seen.$((n+1))"
while [ -e "$RECORDS/hold" ]; do sleep 0.1; done
test -e "$RECORDS/succeed"
`), 0o755)) //nolint:gosec // a test script
	f := newTestFixture(t, `
worker_selector:
  test: "true"
env:
  - RECORDS: `+dir+`
steps:
  - name: record
    command: `+dir+`/record.sh ${context.attempt.id} ${context.attempt.queued_at}
`, append([]fixtureOption{withIsolatedWorker()}, opts...)...)
	t.Cleanup(f.cleanup)
	return &receiptFixture{f: f, dir: dir}
}

func (r *receiptFixture) touch(t *testing.T, name string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(r.dir, name), nil, 0o600))
}

func (r *receiptFixture) remove(t *testing.T, name string) {
	t.Helper()
	require.NoError(t, os.Remove(filepath.Join(r.dir, name)))
}

// waitStatus waits until the hub's latest status satisfies ok.
func (r *receiptFixture) waitStatus(t *testing.T, what string, ok func(ir.DAGRunStatus) bool) ir.DAGRunStatus {
	t.Helper()
	var got ir.DAGRunStatus
	require.Eventually(t, func() bool {
		status, err := r.f.latestStatus()
		if err != nil || !ok(status) {
			return false
		}
		got = status
		return true
	}, distrTestTimeout(40*time.Second), 100*time.Millisecond, "the hub's latest status never became %s", what)
	return got
}

// startDirect starts a run through the coordinator without the queue, so its
// executions carry no queue marker.
func (r *receiptFixture) startDirect(t *testing.T) {
	t.Helper()
	runID, err := ir.NewDAGRunID()
	require.NoError(t, err)
	dag := r.f.dagWrapper.DAG
	task := executor.CreateTask(dag.Name, string(dag.YamlData), dispatch.DispatchOperationStart, runID,
		executor.WithWorkerSelector(dag.WorkerSelector))
	require.NoError(t, r.f.coord.GetCoordinatorClient(t).Dispatch(r.f.coord.Context, dispatch.DispatchRequest{Task: task}))
}

// retry dispatches a conditional direct retry of previous and returns the
// execution the coordinator admitted.
func (r *receiptFixture) retry(t *testing.T, previous ir.DAGRunStatus) (*dispatch.AdmittedExecution, error) {
	t.Helper()
	dag := r.f.dagWrapper.DAG
	task := executor.CreateTask(dag.Name, string(dag.YamlData), dispatch.DispatchOperationRetry, previous.DAGRunID,
		executor.WithWorkerSelector(dag.WorkerSelector), executor.WithPreviousStatus(&previous),
		executor.WithRequireLatestIsPrevious(true))
	admitted := &dispatch.AdmittedExecution{}
	err := r.f.coord.GetCoordinatorClient(t).Dispatch(r.f.coord.Context, dispatch.DispatchRequest{Task: task, Admitted: admitted})
	return admitted, err
}

// seen returns what the nth execution's step recorded: attempt and marker.
func (r *receiptFixture) seen(t *testing.T, n int) (string, string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(r.dir, "seen."+string(rune('0'+n))))
	require.NoError(t, err)
	parts := strings.Split(string(data), "|")
	require.Len(t, parts, 2, "record %q", data)
	return parts[0], parts[1]
}

func assertSavedIsReceipt(t *testing.T, admitted *dispatch.AdmittedExecution, saved ir.DAGRunStatus, when string) {
	t.Helper()
	assert.Equal(t, admitted.AttemptID, saved.AttemptID, when)
	assert.Equal(t, admitted.QueuedAt, saved.QueuedAt, when)
	assert.Equal(t, ir.ExecutionRef(admitted.AttemptID, admitted.QueuedAt), ir.ExecutionRef(saved.AttemptID, saved.QueuedAt), when)
}

// receiptThroughExecution retries the failed execution previous and checks
// that the receipt is the saved execution right after admission, while the
// step runs and once it has ended, and is the execution the step saw.
func receiptThroughExecution(t *testing.T, r *receiptFixture, previous ir.DAGRunStatus) {
	t.Helper()
	r.touch(t, "hold")
	r.touch(t, "succeed")
	admitted, err := r.retry(t, previous)
	require.NoError(t, err)
	require.NotEmpty(t, admitted.AttemptID)
	assert.NotEqual(t, previous.AttemptID, admitted.AttemptID, "a direct retry is a new attempt")
	assert.Equal(t, previous.QueuedAt, admitted.QueuedAt, "it keeps the retried status's marker")

	saved, err := r.f.latestStatus()
	require.NoError(t, err)
	assertSavedIsReceipt(t, admitted, saved, "right after admission")

	running := r.waitStatus(t, "running under the admitted attempt", func(s ir.DAGRunStatus) bool {
		return s.AttemptID == admitted.AttemptID && s.Status == ir.Running
	})
	assertSavedIsReceipt(t, admitted, running, "while running")

	r.remove(t, "hold")
	done := r.waitStatus(t, "succeeded", func(s ir.DAGRunStatus) bool {
		return s.AttemptID == admitted.AttemptID && s.Status == ir.Succeeded
	})
	assertSavedIsReceipt(t, admitted, done, "at the terminal status")
	attempt, marker := r.seen(t, 2)
	assert.Equal(t, admitted.AttemptID, attempt, "the step ran under the admitted attempt")
	assert.Equal(t, admitted.QueuedAt, marker, "the step saw the admitted execution's marker")

	// The retried execution is no longer the latest: a retry expecting it is
	// refused and creates nothing.
	_, err = r.retry(t, previous)
	require.ErrorIs(t, err, persis.ErrLatestExecutionChanged)
	after, err := r.f.latestStatus()
	require.NoError(t, err)
	assert.Equal(t, admitted.AttemptID, after.AttemptID, "nothing was created")
}

// A conditional direct retry of a run that went through the queue names the
// execution the hub stores, at every point: the retry inherits the queue
// marker of the execution it retries.
func TestConditionalRetryReceiptOfAQueuedRun(t *testing.T) {
	r := newReceiptFixture(t)
	require.NoError(t, r.f.enqueue())
	r.f.waitForQueued()
	r.f.startScheduler(120 * time.Second)

	first := r.waitStatus(t, "failed", func(s ir.DAGRunStatus) bool { return s.Status == ir.Failed })
	require.NotEmpty(t, first.QueuedAt, "the run went through the queue; the test proves nothing")
	receiptThroughExecution(t, r, first)
}

// The same for a run that was never queued: every execution's marker is
// empty, and the receipt says so.
func TestConditionalRetryReceiptOfANeverQueuedRun(t *testing.T) {
	r := newReceiptFixture(t)
	r.startDirect(t)

	first := r.waitStatus(t, "failed", func(s ir.DAGRunStatus) bool { return s.Status == ir.Failed })
	require.Empty(t, first.QueuedAt, "the run was never queued; the test proves nothing")
	receiptThroughExecution(t, r, first)
}

// When the worker cannot load the DAG, the status it reports instead of
// running is still the receipt's execution. The worker's own base config is
// malformed. The first execution comes from the scheduler, which embeds the
// hub's base config in its task, so it loads and runs; the retry's task
// carries none, so the worker falls back to its broken file and fails to
// load. The coordinator never reads that file and admits the retry.
func TestConditionalRetryReceiptWhenTheWorkerCannotLoad(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "base.yaml")
	require.NoError(t, os.WriteFile(broken, []byte("env: [unterminated\n"), 0o600))
	r := newReceiptFixture(t, withWorkerBaseConfigPath(broken))
	require.NoError(t, r.f.enqueue())
	r.f.waitForQueued()
	r.f.startScheduler(120 * time.Second)

	first := r.waitStatus(t, "failed", func(s ir.DAGRunStatus) bool { return s.Status == ir.Failed })
	require.NotEmpty(t, first.QueuedAt, "the run went through the queue; the test proves nothing")
	_, err := os.Stat(filepath.Join(r.dir, "seen.1"))
	require.NoError(t, err, "the first execution ran its step")

	admitted, err := r.retry(t, first)
	require.NoError(t, err)
	assert.Equal(t, first.QueuedAt, admitted.QueuedAt)
	saved, err := r.f.latestStatus()
	require.NoError(t, err)
	assertSavedIsReceipt(t, admitted, saved, "right after admission")

	failed := r.waitStatus(t, "failed under the admitted attempt", func(s ir.DAGRunStatus) bool {
		return s.AttemptID == admitted.AttemptID && s.Status == ir.Failed
	})
	assertSavedIsReceipt(t, admitted, failed, "at the load-failure status")
	_, err = os.Stat(filepath.Join(r.dir, "seen.2"))
	assert.True(t, os.IsNotExist(err), "the retry's step ran; the worker loaded the DAG and the test proves nothing")
	t.Logf("load-failure status error: %q", failed.Error)
}
