// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/queue"
)

// A queued retry runs the same attempt again and replaces its status and
// logs. Each finished execution is copied first: after three executions of
// one attempt, the two replaced ones are retained with their own terminal
// status and their own log lines, and an earlier copy does not change when a
// later execution is copied.
func TestQueuedRetryRetainsEachExecution(t *testing.T) {
	state := t.TempDir()
	f := newTestFixture(t, fmt.Sprintf(`
type: chain
name: retained-executions
worker_selector:
  test: "true"
steps:
  - name: run
    run: |
      n=$(cat %[1]s/run 2>/dev/null || echo 0); n=$((n+1)); echo $n > %[1]s/run
      echo "run execution $n"
      test $n -ge 2
  - name: publish
    run: |
      n=$(cat %[1]s/publish 2>/dev/null || echo 0); n=$((n+1)); echo $n > %[1]s/publish
      echo "publish execution $n"
      test $n -ge 2
`, state), withLogPersistence())
	defer f.cleanup()

	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(distrTestTimeout(90 * time.Second))

	repo := f.coord.DAGRunRepository
	ref := func(s ir.DAGRunStatus) ir.DAGRunRef { return ir.NewDAGRunRef(s.Name, s.DAGRunID) }
	// finished waits for an execution of the run other than the previous
	// one to end in want, and for the worker to release the run.
	finished := func(previous string, want ir.Status) ir.DAGRunStatus {
		t.Helper()
		var got ir.DAGRunStatus
		require.Eventually(t, func() bool {
			s, err := f.latestStoredStatus()
			if err != nil || s.Status != want || s.QueuedAt == previous {
				return false
			}
			got = s
			return true
		}, distrTestTimeout(60*time.Second), 200*time.Millisecond)
		f.waitForRunReleasedFromWorkers(got.DAGRunID, distrTestTimeout(30*time.Second))
		return got
	}
	queuedRetry := func(s ir.DAGRunStatus) {
		t.Helper()
		_, err := queue.EnqueueRetry(f.coord.Context, repo, f.coord.QueueStore, f.dagWrapper.DAG, &s, queue.EnqueueRetryOptions{})
		require.NoError(t, err)
	}
	read := func(s ir.DAGRunStatus, name string) string {
		t.Helper()
		b, err := repo.ReadRetainedExecutionFile(f.coord.Context, ref(s), ir.ExecutionRef(s.AttemptID, s.QueuedAt), name)
		require.NoError(t, err, name)
		return string(b)
	}

	// Execution 1: run fails.
	e1 := finished("never", ir.Failed)
	queuedRetry(e1)
	e1Stdout := read(e1, "run.stdout.log")
	e1Status := read(e1, "status.json")

	// Execution 2, same attempt: run succeeds, publish fails.
	e2 := finished(e1.QueuedAt, ir.Failed)
	queuedRetry(e2)

	// Execution 3: publish only, succeeds.
	e3 := finished(e2.QueuedAt, ir.Succeeded)

	assert.Equal(t, e1.AttemptID, e2.AttemptID, "a queued retry runs the same attempt")
	assert.Equal(t, e1.AttemptID, e3.AttemptID)
	assert.NotEqual(t, e1.QueuedAt, e2.QueuedAt, "under a later queue marker")

	retained, err := repo.ListRetainedExecutions(f.coord.Context, ref(e3))
	require.NoError(t, err)
	require.Len(t, retained, 2, "both replaced executions are kept")
	assert.Equal(t, ir.ExecutionRef(e1.AttemptID, e1.QueuedAt), retained[0].Execution)
	assert.Equal(t, ir.ExecutionRef(e2.AttemptID, e2.QueuedAt), retained[1].Execution)
	for _, r := range retained {
		assert.Equal(t, "failed", r.Status)
		assert.True(t, r.StatusComplete)
		assert.False(t, r.LogsFinal, "logs are not claimed final until streams are fenced")
	}

	assert.Contains(t, e1Stdout, "run execution 1")
	assert.NotContains(t, e1Stdout, "execution 2")
	assert.Equal(t, e1Stdout, read(e1, "run.stdout.log"), "execution 1's copy is unchanged after execution 2")
	assert.Equal(t, e1Status, read(e1, "status.json"))
	assert.Contains(t, read(e2, "run.stdout.log"), "run execution 2")
	assert.Contains(t, read(e2, "publish.stdout.log"), "publish execution 1")
	assert.NotContains(t, read(e2, "publish.stdout.log"), "publish execution 2")
	assert.NotEqual(t, read(e1, "status.json"), read(e2, "status.json"))
}
