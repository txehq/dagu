// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package persis_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	filedagrun "github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The repository's attempts over the file store write conditionally: the
// check sees the latest stored status and the write lands.
func TestRepositoryAttemptWriteIfLatest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	baseDir := filepath.Join(t.TempDir(), "dag-runs")
	repository := persis.NewDAGRunRepository(
		filedagrun.NewStore(baseDir),
		filedagrun.NewWorkDirStore(filepath.Join(baseDir, ".dag-run-work"), baseDir),
		persis.DAGRunRepositoryOptions{},
	)
	attempt, err := repository.CreateAttempt(ctx, &ir.DAG{Name: "dag"}, time.Now(), "run-1", persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(ctx))
	t.Cleanup(func() { _ = attempt.Close(ctx) })
	require.NoError(t, attempt.Write(ctx, ir.DAGRunStatus{Name: "dag", DAGRunID: "run-1", AttemptID: attempt.ID(), Status: ir.Running}))

	writer, ok := attempt.(dagrun.ConditionalWriter)
	require.True(t, ok, "repository attempts expose conditional writes")
	var seen ir.Status
	require.NoError(t, writer.WriteIfLatest(ctx,
		ir.DAGRunStatus{Name: "dag", DAGRunID: "run-1", AttemptID: attempt.ID(), Status: ir.Succeeded},
		func(latest *ir.DAGRunStatus) error {
			seen = latest.Status
			return nil
		}))
	assert.Equal(t, ir.Running, seen)
	stored, err := attempt.ReadStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, ir.Succeeded, stored.Status)
}
