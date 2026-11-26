// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package queue_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/queue"
	"github.com/dagucloud/dagu/v2/internal/testutil"
)

// withdrawn is a run whose latest execution is held by one queue item.
type withdrawn struct {
	runs      *persis.DAGRunRepository
	queues    queue.QueueStore
	run       ir.DAGRunRef
	attemptID string
	itemID    string
}

// withdrawFixture is a run whose latest execution has status st and marker,
// held by one queue item.
func withdrawFixture(t *testing.T, st ir.Status, marker string) withdrawn {
	t.Helper()
	dir := t.TempDir()
	runs := testutil.NewFileDAGRunRepository(filepath.Join(dir, "runs"), persis.DAGRunRepositoryOptions{})
	queues := store.NewQueueStore(file.NewCollection(filepath.Join(dir, "queue")))
	dag := &ir.DAG{Name: "job", YamlData: []byte("steps:\n  - name: s\n    run: true\n")}
	attempt, err := runs.CreateAttempt(t.Context(), dag, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	status := ir.InitialStatus(dag)
	status.DAGRunID, status.AttemptID, status.Status, status.QueuedAt = "run-1", attempt.ID(), st, marker
	require.NoError(t, attempt.Open(t.Context()))
	require.NoError(t, attempt.Write(t.Context(), status))
	require.NoError(t, attempt.Close(t.Context()))
	run := ir.NewDAGRunRef("job", "run-1")
	require.NoError(t, queues.Enqueue(t.Context(), "job", queue.QueuePriorityLow, run))
	items, err := queues.List(t.Context(), "job")
	require.NoError(t, err)
	require.Len(t, items, 1)
	return withdrawn{runs: runs, queues: queues, run: run, attemptID: attempt.ID(), itemID: items[0].ID()}
}

// A queued execution is journaled, its item removed, and its status left
// as it is; withdrawing it again changes nothing.
func TestWithdrawQueuedExecutionJournalsAndLeavesTheStatus(t *testing.T) {
	const marker = "2026-11-26T09:00:00Z"
	w := withdrawFixture(t, ir.Queued, marker)
	runs, queues, run, attemptID, itemID := w.runs, w.queues, w.run, w.attemptID, w.itemID

	for range 2 {
		out, err := queue.WithdrawQueuedExecution(t.Context(), runs, queues, "job", run, ir.DAGRunRef{}, attemptID, marker, itemID)
		require.NoError(t, err)
		assert.Equal(t, queue.WithdrawalJournaled, out)
	}
	items, err := queues.List(t.Context(), "job")
	require.NoError(t, err)
	assert.Empty(t, items)
	entries, err := runs.ListAttemptPreparations(t.Context())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, run, entries[0].Run)
	assert.Equal(t, run, entries[0].RootRun)
	assert.Equal(t, attemptID, entries[0].AttemptID)
	assert.Equal(t, marker, entries[0].QueuedAt, "journaled by its marker")
	attempt, err := runs.FindAttempt(t.Context(), run)
	require.NoError(t, err)
	status, err := attempt.ReadStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, ir.Queued, status.Status, "no status is written")
	record, err := runs.ReadExecutionAbandonment(t.Context(), run, run, attemptID, marker)
	require.NoError(t, err)
	assert.Nil(t, record, "nothing records the execution as not dispatched")
}

// An execution that already left its queue (it runs) is not journaled; only
// the stale item is removed.
func TestWithdrawQueuedExecutionThatMovedOnRemovesOnlyTheItem(t *testing.T) {
	const marker = "2026-11-26T09:00:00Z"
	w := withdrawFixture(t, ir.Running, marker)
	runs, queues, run, attemptID, itemID := w.runs, w.queues, w.run, w.attemptID, w.itemID

	out, err := queue.WithdrawQueuedExecution(t.Context(), runs, queues, "job", run, run, attemptID, marker, itemID)
	require.NoError(t, err)
	assert.Equal(t, queue.WithdrawalStale, out)
	items, err := queues.List(t.Context(), "job")
	require.NoError(t, err)
	assert.Empty(t, items)
	entries, err := runs.ListAttemptPreparations(t.Context())
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestWithdrawQueuedExecutionNeedsItsItemAndStores(t *testing.T) {
	const marker = "2026-11-26T09:00:00Z"
	w := withdrawFixture(t, ir.Queued, marker)
	runs, queues, run, attemptID := w.runs, w.queues, w.run, w.attemptID
	_, err := queue.WithdrawQueuedExecution(t.Context(), runs, queues, "job", run, run, attemptID, marker, "")
	require.Error(t, err)
	_, err = queue.WithdrawQueuedExecution(t.Context(), nil, queues, "job", run, run, attemptID, marker, "x")
	require.Error(t, err)
	entries, err := runs.ListAttemptPreparations(t.Context())
	require.NoError(t, err)
	assert.Empty(t, entries, "a refused call journals nothing")
}
