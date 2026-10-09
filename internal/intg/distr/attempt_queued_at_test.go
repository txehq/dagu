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

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/queue"
	"github.com/dagucloud/dagu/v2/internal/runtime/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// queuedAtFixture runs a DAG on a worker whose step records the attempt ID
// and the queue marker it sees, and fails until told otherwise.
type queuedAtFixture struct {
	f   *testFixture
	dir string
}

func newQueuedAtFixture(t *testing.T) *queuedAtFixture {
	t.Helper()
	if goruntime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX shell script")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "record.sh"), []byte(`#!/bin/sh
# $1 attempt id, $2 queue marker, as the step's command received them
n=$(ls "$RECORDS" | grep -c '^seen\.' || true)
printf '%s|%s|%s' "$1" "$2" "$QUEUED_AT_ENV" > "$RECORDS/seen.$((n+1))"
test -e "$RECORDS/succeed"
`), 0o755)) //nolint:gosec // a test script
	f := newTestFixture(t, `
worker_selector:
  test: "true"
env:
  - RECORDS: `+dir+`
  - QUEUED_AT_ENV: "${context.attempt.queued_at}"
steps:
  - name: record
    command: `+dir+`/record.sh ${context.attempt.id} ${context.attempt.queued_at}
`)
	t.Cleanup(f.cleanup)
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(120 * time.Second)
	return &queuedAtFixture{f: f, dir: dir}
}

// seenExecution is what one execution's step saw, and the status the hub
// stores once that execution has ended.
type seenExecution struct {
	attemptID, inCommand, inEnv string
	stored                      ir.DAGRunStatus
}

// execution waits for the nth execution of the step to end.
func (q *queuedAtFixture) execution(t *testing.T, n int, want ir.Status) seenExecution {
	t.Helper()
	var seen seenExecution
	record := filepath.Join(q.dir, "seen."+string(rune('0'+n)))
	defer func() {
		if t.Failed() {
			status, err := q.f.latestStatus()
			entries, _ := os.ReadDir(q.dir)
			t.Logf("the hub's latest status: %s, attempt %s, queuedAt %q, error %q (read error: %v); records: %v", status.Status, status.AttemptID, status.QueuedAt, status.Error, err, entries)
		}
	}()
	require.Eventually(t, func() bool {
		if _, err := os.Stat(record); err != nil {
			return false
		}
		status, err := q.f.latestStatus()
		if err != nil || status.Status != want {
			return false
		}
		seen.stored = status
		return true
	}, distrTestTimeout(40*time.Second), 200*time.Millisecond, "execution %d did not end %s", n, want)
	data, err := os.ReadFile(record)
	require.NoError(t, err)
	parts := strings.Split(string(data), "|")
	require.Len(t, parts, 3, "record %q", data)
	seen.attemptID, seen.inCommand, seen.inEnv = parts[0], parts[1], parts[2]
	return seen
}

// The queue marker a step reads is the queuedAt the hub stores for the
// execution the step belongs to.
//
// A retry through the queue executes again under the same attempt ID with a
// new marker. A retry dispatched to the coordinator directly gets a new
// attempt ID and keeps the marker of the attempt it retries. Either way the
// pair of attempt ID and marker differs from every earlier execution's.
func TestAttemptQueuedAt_QueuedRetry(t *testing.T) {
	q := newQueuedAtFixture(t)
	f := q.f

	first := q.execution(t, 1, ir.Failed)
	require.NotEmpty(t, first.stored.QueuedAt, "an enqueued run has no marker; the test proves nothing")
	assert.Equal(t, first.stored.AttemptID, first.attemptID)
	assert.Equal(t, first.stored.QueuedAt, first.inCommand, "the step's command saw another marker than the hub stores")
	assert.Equal(t, first.stored.QueuedAt, first.inEnv, "the DAG's env saw another marker than the hub stores")

	// The same attempt is queued again and executes with a new marker.
	//
	// The retry is queued only once the workers have let go of the run. The
	// hub accepts a status report by attempt alone, so a last report of the
	// failed execution that arrives after the retry was admitted puts the
	// failed status back and the queued retry is dropped. Waiting here keeps
	// that race, which is not this test's subject, out of it.
	require.NoError(t, os.WriteFile(filepath.Join(q.dir, "succeed"), nil, 0o600))
	f.waitForRunReleasedFromWorkers(first.stored.DAGRunID, distrTestTimeout(20*time.Second))
	require.Eventually(t, func() bool {
		previous, err := f.latestStatus()
		if err != nil {
			return false
		}
		added, err := queue.EnqueueRetry(f.coord.Context, f.coord.DAGRunRepository, f.coord.QueueStore, f.dagWrapper.DAG, &previous,
			queue.EnqueueRetryOptions{Processes: f.coord.ProcRepository})
		return err == nil && added
	}, distrTestTimeout(20*time.Second), 200*time.Millisecond, "the retry was not queued")

	second := q.execution(t, 2, ir.Succeeded)
	assert.Equal(t, first.attemptID, second.attemptID, "a queued retry got a new attempt; the test's premise is gone")
	assert.Equal(t, second.stored.AttemptID, second.attemptID)
	assert.NotEqual(t, first.stored.QueuedAt, second.stored.QueuedAt, "a queued retry kept the earlier execution's marker")
	assert.Equal(t, second.stored.QueuedAt, second.inCommand)
	assert.Equal(t, second.stored.QueuedAt, second.inEnv)
}

func TestAttemptQueuedAt_DirectRetry(t *testing.T) {
	q := newQueuedAtFixture(t)
	f := q.f

	first := q.execution(t, 1, ir.Failed)
	require.NotEmpty(t, first.stored.QueuedAt)
	assert.Equal(t, first.stored.QueuedAt, first.inCommand)

	require.NoError(t, os.WriteFile(filepath.Join(q.dir, "succeed"), nil, 0o600))
	dag := f.dagWrapper.DAG
	task := executor.CreateTask(dag.Name, string(dag.YamlData), dispatch.DispatchOperationRetry, first.stored.DAGRunID,
		executor.WithWorkerSelector(dag.WorkerSelector), executor.WithPreviousStatus(&first.stored))
	require.NoError(t, f.coord.GetCoordinatorClient(t).Dispatch(f.coord.Context, dispatch.DispatchRequest{Task: task}))

	second := q.execution(t, 2, ir.Succeeded)
	assert.NotEqual(t, first.attemptID, second.attemptID, "a direct retry kept the attempt; the test's premise is gone")
	assert.Equal(t, second.stored.AttemptID, second.attemptID)
	// The new attempt carries the marker of the attempt it retries, on the
	// hub and in the step alike.
	assert.Equal(t, first.stored.QueuedAt, second.stored.QueuedAt)
	assert.Equal(t, second.stored.QueuedAt, second.inCommand)
	assert.Equal(t, second.stored.QueuedAt, second.inEnv)
}
