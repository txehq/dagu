// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/testutil"
)

// A conditional retry creates its attempt only while the run's latest
// execution is the expected one and has finished; otherwise nothing is
// created.
func TestCreateAttemptExpectsTheLatestExecution(t *testing.T) {
	ctx := context.Background()
	repo := testutil.NewFileDAGRunRepository(filepath.Join(t.TempDir(), "runs"), persis.DAGRunRepositoryOptions{})
	dag := &ir.DAG{Name: "job"}
	first, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	write := func(st ir.Status, queuedAt string) {
		status := ir.InitialStatus(dag)
		status.DAGRunID, status.AttemptID, status.Status, status.QueuedAt = "run-1", first.ID(), st, queuedAt
		require.NoError(t, first.Open(ctx))
		require.NoError(t, first.Write(ctx, status))
		require.NoError(t, first.Close(ctx))
	}
	retry := func(want persis.ExpectedExecution) error {
		_, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{Retry: true, ExpectLatest: &want})
		return err
	}
	latest := func() string {
		a, err := repo.FindAttempt(ctx, ir.NewDAGRunRef(dag.Name, "run-1"))
		require.NoError(t, err)
		return a.ID()
	}

	write(ir.Failed, "q1")
	assert.ErrorIs(t, retry(persis.ExpectedExecution{AttemptID: first.ID(), QueuedAt: "q0"}), persis.ErrLatestExecutionChanged, "another execution of the attempt")
	assert.ErrorIs(t, retry(persis.ExpectedExecution{AttemptID: "other", QueuedAt: "q1"}), persis.ErrLatestExecutionChanged, "another attempt")
	write(ir.Queued, "q1")
	assert.ErrorIs(t, retry(persis.ExpectedExecution{AttemptID: first.ID(), QueuedAt: "q1"}), persis.ErrLatestExecutionChanged, "not finished")
	assert.Equal(t, first.ID(), latest(), "nothing was created")

	write(ir.Failed, "q1")
	next, err := repo.CreateAttempt(ctx, dag, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{Retry: true,
		ExpectLatest: &persis.ExpectedExecution{AttemptID: first.ID(), QueuedAt: "q1"}})
	require.NoError(t, err, "the expected execution is retried")
	assert.NotEqual(t, first.ID(), next.ID())
}
