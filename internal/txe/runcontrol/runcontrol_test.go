// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package runcontrol

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/testutil"
)

// A run's latest attempt is reported as preparing while the coordinator's
// preparation journal holds it, and no longer once the preparation ends.
func TestLatestAttemptReportsAPreparation(t *testing.T) {
	ctx := t.Context()
	runs := testutil.NewFileDAGRunRepository(filepath.Join(t.TempDir(), "runs"), persis.DAGRunRepositoryOptions{})
	c := &Control{Runs: runs}
	dag := &ir.DAG{Name: "job", YamlData: []byte("steps:\n  - name: s\n    run: true\n")}

	write := func(opts persis.DAGRunCreateAttemptOptions, st ir.Status) string {
		attempt, err := runs.CreateAttempt(ctx, dag, time.Now(), "run-1", opts)
		require.NoError(t, err)
		status := ir.InitialStatus(dag)
		status.DAGRunID, status.AttemptID, status.Status = "run-1", attempt.ID(), st
		require.NoError(t, attempt.Open(ctx))
		require.NoError(t, attempt.Write(ctx, status))
		require.NoError(t, attempt.Close(ctx))
		return attempt.ID()
	}
	first := write(persis.DAGRunCreateAttemptOptions{}, ir.Failed)
	latest, err := c.LatestAttempt(ctx, "job", "run-1")
	require.NoError(t, err)
	assert.Equal(t, first, latest.AttemptID)
	assert.False(t, latest.Preparing, "an attempt that was never journaled")

	prepared := write(persis.DAGRunCreateAttemptOptions{Retry: true, TrackPreparation: true}, ir.NotStarted)
	latest, err = c.LatestAttempt(ctx, "job", "run-1")
	require.NoError(t, err)
	assert.Equal(t, prepared, latest.AttemptID)
	assert.True(t, latest.Preparing, "journaled and not yet handed to a worker")

	entries, err := runs.ListAttemptPreparations(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.NoError(t, runs.EndAttemptPreparation(ctx, entries[0]))
	latest, err = c.LatestAttempt(ctx, "job", "run-1")
	require.NoError(t, err)
	assert.Equal(t, prepared, latest.AttemptID)
	assert.False(t, latest.Preparing, "handed to a worker")
}
