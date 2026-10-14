// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
	"github.com/dagucloud/dagu/v2/internal/runtime/runstate"
	"github.com/dagucloud/dagu/v2/internal/spec"
)

const retentionLine = "hist_retention_days: 36500\n"

// The job's DAG declares its run history, and that wins over what a base
// configuration sets for every DAG: a number of days, or a number of runs.
func TestRenderDAGKeepsRunHistoryOverABaseConfig(t *testing.T) {
	s := testDAGSpec()
	data, err := RenderDAG(s)
	require.NoError(t, err)
	require.Contains(t, string(data), retentionLine)

	withoutRetention := bytes.Replace(data, []byte(retentionLine), nil, 1)

	for _, tc := range []struct {
		name               string
		base               string
		baseDays, baseRuns int
	}{
		{name: "no base config"},
		{name: "base keeps days", base: "hist_retention_days: 1\n", baseDays: 1},
		{name: "base keeps runs", base: "hist_retention_runs: 2\n", baseRuns: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := []spec.LoadOption{spec.WithName(s.JobID), spec.WithoutEval()}
			if tc.base != "" {
				opts = append(opts, spec.WithBaseConfigContent([]byte(tc.base)))
			}

			// Without the line, the base configuration decides.
			inherited, err := spec.LoadYAML(context.Background(), withoutRetention, opts...)
			require.NoError(t, err)
			assert.Equal(t, tc.baseDays, inherited.HistRetentionDays)
			assert.Equal(t, tc.baseRuns, inherited.HistRetentionRuns)

			dag, err := spec.LoadYAML(context.Background(), data, opts...)
			require.NoError(t, err)
			assert.Equal(t, HistRetentionDays, dag.HistRetentionDays)
			assert.Zero(t, dag.HistRetentionRuns)
		})
	}
}

// A run started with local storage removes the DAG's older finished runs,
// with their logs and artifacts. Dagu's default removes a run whose last
// write was 40 days ago; the job's DAG keeps it.
func TestRenderedDAGKeepsOldRunsWhenARunStarts(t *testing.T) {
	s := testDAGSpec()
	rendered, err := RenderDAG(s)
	require.NoError(t, err)
	withoutRetention := bytes.Replace(rendered, []byte(retentionLine), nil, 1)
	require.NotEqual(t, rendered, withoutRetention)

	for _, tc := range []struct {
		name     string
		data     []byte
		wantKept bool
	}{
		{"rendered", rendered, true},
		{"Dagu default", withoutRetention, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			// Loaded from its file, as "dagu start" loads it, so Dagu's
			// defaults apply.
			file := filepath.Join(root, s.JobID+".yaml")
			require.NoError(t, os.WriteFile(file, tc.data, 0o600))
			dag, err := spec.Load(ctx, file, spec.WithoutEval())
			require.NoError(t, err)
			wantDays := 30
			if tc.wantKept {
				wantDays = HistRetentionDays
			}
			require.Equal(t, wantDays, dag.HistRetentionDays)

			runsDir := filepath.Join(root, "dag-runs")
			artifactsDir := filepath.Join(root, "artifacts")
			store := dagrun.NewStore(runsDir, dagrun.WithArtifactDir(artifactsDir))
			repo := persis.NewDAGRunRepository(store, nil, persis.DAGRunRepositoryOptions{})

			old := seedFinishedRun(t, repo, dag, "old-run", root, artifactsDir, 40*24*time.Hour)
			recent := seedFinishedRun(t, repo, dag, "recent-run", root, artifactsDir, time.Hour)

			_, err = persis.NewRunStateStore(repo, nil).BeginAttempt(ctx, runstate.BeginAttemptRequest{
				DAG: dag, RunID: "new-run",
			})
			require.NoError(t, err)

			recent.assertPresent(t, true)
			old.assertPresent(t, tc.wantKept)
		})
	}
}

// seededRun is the files of one finished run: its status, its log and an
// artifact.
type seededRun struct {
	runID    string
	repo     *persis.DAGRunRepository
	dagName  string
	log      string
	artifact string
}

func (r seededRun) assertPresent(t *testing.T, want bool) {
	t.Helper()
	_, err := r.repo.FindAttempt(context.Background(), ir.NewDAGRunRef(r.dagName, r.runID))
	assert.Equal(t, want, err == nil, "run %s recorded: %v", r.runID, err)
	assert.Equal(t, want, fileExists(r.log), "log of %s", r.runID)
	assert.Equal(t, want, fileExists(r.artifact), "artifact of %s", r.runID)
}

func seedFinishedRun(t *testing.T, repo *persis.DAGRunRepository, dag *ir.DAG, runID, root, artifactsDir string, age time.Duration) seededRun {
	t.Helper()
	ctx := context.Background()
	at := time.Now().Add(-age)

	log := filepath.Join(root, "logs", runID+".log")
	artifactDir := filepath.Join(artifactsDir, runID)
	artifact := filepath.Join(artifactDir, "report.txt")
	for _, file := range []string{log, artifact} {
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
		require.NoError(t, os.WriteFile(file, []byte(runID), 0o600))
	}

	attempt, err := repo.CreateAttempt(ctx, dag, at, runID, persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, ir.DAGRunStatus{
		Name: dag.Name, DAGRunID: runID, AttemptID: attempt.ID(),
		Status: ir.Succeeded, Log: log, ArchiveDir: artifactDir,
	}))
	require.NoError(t, attempt.Close(ctx))

	// Retention reads the age of a run from its status file.
	var touched int
	require.NoError(t, filepath.WalkDir(filepath.Join(root, "dag-runs"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != dagrun.JSONLStatusFile {
			return err
		}
		if !bytes.Contains([]byte(path), []byte(runID)) {
			return nil
		}
		touched++
		return os.Chtimes(path, at, at)
	}))
	require.Equal(t, 1, touched)

	return seededRun{runID: runID, repo: repo, dagName: dag.Name, log: log, artifact: artifact}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
