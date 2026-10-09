// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A tracked attempt is journaled under the ID it is created with, for a root
// run and a sub-DAG run, and ending the preparation removes the entry.
func TestCreateAttemptJournalsTrackedPreparation(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("prep_dag").DAG
	child := th.DAG("prep_child").DAG
	root := ir.NewDAGRunRef(dag.Name, "prep-run")
	before := time.Now().UTC()

	untracked, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
		DAG: dag, Timestamp: time.Now(), DAGRunID: root.ID,
	})
	require.NoError(t, err)
	preparations, err := th.Backend.ListAttemptPreparations(th.Context)
	require.NoError(t, err)
	assert.Empty(t, preparations, "an untracked attempt is not journaled")

	tracked, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
		DAG: dag, Timestamp: time.Now(), DAGRunID: root.ID, Retry: true, TrackPreparation: true,
	})
	require.NoError(t, err)
	require.NotEqual(t, untracked.ID(), tracked.ID())
	sub, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
		DAG: child, RootDAGRun: root, Timestamp: time.Now(), DAGRunID: "child-run", TrackPreparation: true,
	})
	require.NoError(t, err)

	preparations, err = th.Backend.ListAttemptPreparations(th.Context)
	require.NoError(t, err)
	require.Len(t, preparations, 2)
	byAttempt := map[string]persis.AttemptPreparation{}
	for _, p := range preparations {
		byAttempt[p.AttemptID] = p
		preparedAt, err := time.Parse(time.RFC3339Nano, p.PreparedAt)
		require.NoError(t, err)
		assert.False(t, preparedAt.Before(before.Add(-time.Second)))
	}
	assert.Equal(t, root, byAttempt[tracked.ID()].Run)
	assert.Equal(t, root, byAttempt[tracked.ID()].RootRun)
	assert.Equal(t, ir.NewDAGRunRef(child.Name, "child-run"), byAttempt[sub.ID()].Run)
	assert.Equal(t, root, byAttempt[sub.ID()].RootRun)

	require.NoError(t, th.Backend.EndAttemptPreparation(th.Context, byAttempt[tracked.ID()]))
	require.NoError(t, th.Backend.EndAttemptPreparation(th.Context, byAttempt[tracked.ID()]), "ending twice is not an error")
	preparations, err = th.Backend.ListAttemptPreparations(th.Context)
	require.NoError(t, err)
	require.Len(t, preparations, 1)
	assert.Equal(t, sub.ID(), preparations[0].AttemptID)
}

// The journal lives beside the run tree, never in it, where it would be read
// as a DAG's runs.
func TestPreparationJournalIsOutsideTheRunTree(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	_, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
		DAG: th.DAG("prep_dag").DAG, Timestamp: time.Now(), DAGRunID: "prep-run", TrackPreparation: true,
	})
	require.NoError(t, err)
	rel, err := filepath.Rel(th.TmpDir, th.Backend.preparationDir)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(rel, ".."), "journal %s is inside the run tree", rel)
	roots, err := th.Backend.listRoot(th.Context, "")
	require.NoError(t, err)
	assert.Len(t, roots, 1, "only the DAG is a root")
}

// An entry that cannot be read is skipped; the rest are still listed, oldest
// first.
func TestListAttemptPreparationsSkipsUnreadableEntries(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("prep_dag").DAG
	first, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
		DAG: dag, Timestamp: time.Now(), DAGRunID: "prep-1", TrackPreparation: true,
	})
	require.NoError(t, err)
	second, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
		DAG: dag, Timestamp: time.Now(), DAGRunID: "prep-2", TrackPreparation: true,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(th.Backend.preparationDir, "garbage.json"), []byte("{"), 0600))

	preparations, err := th.Backend.ListAttemptPreparations(th.Context)
	require.NoError(t, err)
	require.Len(t, preparations, 2)
	assert.Equal(t, first.ID(), preparations[0].AttemptID)
	assert.Equal(t, second.ID(), preparations[1].AttemptID)
}
