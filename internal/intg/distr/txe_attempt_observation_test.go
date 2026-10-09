// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/queue"
	"github.com/dagucloud/dagu/v2/internal/runtime/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type observedAttempt struct {
	dir     string
	id      string
	status  string
	archive string
	files   map[string]string
}

// hubAttempts reads every attempt directory the hub keeps for a run.
func hubAttempts(t *testing.T, f *testFixture, runID string) []observedAttempt {
	t.Helper()
	var out []observedAttempt
	require.NoError(t, filepath.WalkDir(f.coord.Config.Paths.DAGRunsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || !strings.HasPrefix(d.Name(), "a_") || !strings.Contains(filepath.Base(filepath.Dir(p)), runID) {
			return nil
		}
		o := observedAttempt{dir: d.Name(), files: map[string]string{}}
		file, err := os.Open(filepath.Join(p, "status.jsonl"))
		if err != nil {
			o.status = "unreadable: " + err.Error()
			out = append(out, o)
			return nil
		}
		defer func() { _ = file.Close() }()
		var last string
		sc := bufio.NewScanner(file)
		sc.Buffer(make([]byte, 1<<20), 1<<26)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) != "" {
				last = sc.Text()
			}
		}
		var st struct {
			AttemptID  string `json:"attemptId"`
			StartedAt  string `json:"startedAt"`
			QueuedAt   string `json:"queuedAt"`
			Status     any    `json:"status"`
			ArchiveDir string `json:"archiveDir"`
		}
		_ = json.Unmarshal([]byte(last), &st)
		o.id, o.status, o.archive = st.AttemptID, fmt.Sprint(st.Status)+" startedAt="+st.StartedAt+" queuedAt="+st.QueuedAt, st.ArchiveDir
		if st.ArchiveDir != "" {
			_ = filepath.WalkDir(st.ArchiveDir, func(ap string, ad fs.DirEntry, err error) error {
				if err == nil && !ad.IsDir() {
					b, _ := os.ReadFile(ap)
					rel, _ := filepath.Rel(st.ArchiveDir, ap)
					o.files[rel] = strings.TrimSpace(string(b))
				}
				return nil
			})
		}
		out = append(out, o)
		return nil
	}))
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out
}

// keepEvidence copies what the hub holds for the run, status files and logs,
// into TXE_EVIDENCE_DIR/<test>/<label>/ when that variable is set.
func keepEvidence(t *testing.T, label string, f *testFixture, runID, obs string) {
	t.Helper()
	base := os.Getenv("TXE_EVIDENCE_DIR")
	if base == "" {
		return
	}
	dst := filepath.Join(base, strings.TrimPrefix(t.Name(), "TestTXEObserveRetry_"), strings.NewReplacer(" ", "-", "(", "", ")", "", ",", "").Replace(label))
	for name, root := range map[string]string{"hub-run-store": f.coord.Config.Paths.DAGRunsDir, "hub-logs": f.logDir(), "hub-artifacts": f.coord.Config.Paths.ArtifactDir, "step-records": obs} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			if name != "step-records" && !strings.Contains(p, runID) && name != "hub-artifacts" {
				return nil
			}
			if name == "step-records" && !strings.HasPrefix(d.Name(), "run.") && !strings.HasPrefix(d.Name(), "publish.") {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			out := filepath.Join(dst, name, rel)
			require.NoError(t, os.MkdirAll(filepath.Dir(out), 0o755))
			require.NoError(t, os.WriteFile(out, data, 0o644))
			return nil
		})
	}
}

func logObservation(t *testing.T, label string, f *testFixture, runID, obs string) {
	t.Helper()
	keepEvidence(t, label, f, runID, obs)
	t.Logf("=== %s", label)
	for _, a := range hubAttempts(t, f, runID) {
		t.Logf("hub attempt dir=%s id=%s status=%s archive=%s files=%v", a.dir, a.id, a.status, filepath.Base(a.archive), a.files)
	}
	_ = filepath.WalkDir(f.coord.Config.Paths.DAGRunsDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Name() == "status.jsonl" && strings.Contains(p, runID) {
			b, _ := os.ReadFile(p)
			t.Logf("hub status.jsonl %s: %d line(s), %d bytes", filepath.Base(filepath.Dir(p)), strings.Count(strings.TrimSpace(string(b)), "\n")+1, len(b))
		}
		return nil
	})
	_ = filepath.WalkDir(f.logDir(), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(p, runID) {
			b, _ := os.ReadFile(p)
			var marks []string
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, "stdout of ") {
					marks = append(marks, line[strings.Index(line, "stdout of "):])
				}
			}
			rel, _ := filepath.Rel(f.logDir(), p)
			parts := strings.Split(rel, string(os.PathSeparator))
			t.Logf("hub log %s: %d bytes, marks=%v", strings.Join(parts[len(parts)-2:], "/"), len(b), marks)
		}
		return nil
	})
	entries, _ := os.ReadDir(obs)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "run.") || strings.HasPrefix(e.Name(), "publish.") {
			b, _ := os.ReadFile(filepath.Join(obs, e.Name()))
			t.Logf("step record %s: %s", e.Name(), strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", " | "))
		}
	}
}

func observeRetries(t *testing.T, queued bool) {
	obs := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(obs, "step.sh"), []byte(`#!/bin/sh
# $1 step, $2 attempt id from the command template
n=$(ls "$OBS" | grep -c "^$1\.[0-9]*$")
n=$((n+1))
printf 'env=%s arg=%s started=%s artifacts=%s\n' "$TXE_ATTEMPT_ID" "$2" "$3" "$(ls "$DAG_RUN_ARTIFACTS_DIR" | tr '\n' ',')" > "$OBS/$1.$n"
echo "stdout of $1 execution $n"
if [ "$1" = run ]; then
  printf 'bytes-%s\n' "$n" > "$DAG_RUN_ARTIFACTS_DIR/out.txt"
  printf 'only-%s\n' "$n" > "$DAG_RUN_ARTIFACTS_DIR/only-$n.txt"
fi
test -e "$OBS/allow-$1"
`), 0o755))

	queueLine := ""
	var opts []fixtureOption
	opts = append(opts, withArtifactPersistence(), withLogPersistence())
	if queued {
		queueLine = "queue: txe-obs\n"
		opts = append(opts, withConfigMutator(func(c *config.Config) {
			c.Queues.Enabled = true
			c.Queues.Config = []config.QueueConfig{{Name: "txe-obs", MaxActiveRuns: 1}}
		}))
	}
	f := newTestFixture(t, `
type: chain
`+queueLine+`worker_selector:
  test: "true"
artifacts:
  enabled: true
env:
  - TXE_ATTEMPT_ID: ${context.attempt.id}
  - OBS: `+obs+`
steps:
  - name: run
    command: `+obs+`/step.sh run ${context.attempt.id} ${context.attempt.started_at}
  - name: publish
    command: `+obs+`/step.sh publish ${context.attempt.id} ${context.attempt.started_at}
`, opts...)
	defer f.cleanup()

	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(120 * time.Second)

	status := f.waitForStatus(ir.Failed, artifactExecutionStatusTimeout())
	runID := status.DAGRunID
	logObservation(t, "after execution 1 (run fails)", f, runID, obs)

	waitFor := func(want ir.Status, records int, step string) {
		defer func() {
			if t.Failed() {
				logObservation(t, "at failure", f, runID, obs)
				if s, err := f.latestStatus(); err == nil {
					t.Logf("latest status=%s attempt=%s error=%q", s.Status, s.AttemptID, s.Error)
				}
			}
		}()
		ok := assert.Eventually(t, func() bool {
			if _, err := os.Stat(filepath.Join(obs, fmt.Sprintf("%s.%d", step, records))); err != nil {
				return false
			}
			s, err := f.latestStatus()
			return err == nil && s.Status == want && s.DAGRunID == runID
		}, distrTestTimeout(40*time.Second), 200*time.Millisecond)
		if !ok {
			t.FailNow()
		}
	}

	// The two paths the REST retry takes for a DAG a worker runs.
	retry := func() {
		prev, err := f.latestStatus()
		require.NoError(t, err)
		dag := f.dagWrapper.DAG
		if queued {
			_, err := queue.EnqueueRetry(f.coord.Context, f.coord.DAGRunRepository, f.coord.QueueStore, dag, &prev,
				queue.EnqueueRetryOptions{Processes: f.coord.ProcRepository})
			require.NoError(t, err)
			return
		}
		task := executor.CreateTask(dag.Name, string(dag.YamlData), dispatch.DispatchOperationRetry, runID,
			executor.WithWorkerSelector(dag.WorkerSelector), executor.WithPreviousStatus(&prev))
		require.NoError(t, f.coord.GetCoordinatorClient(t).Dispatch(f.coord.Context, dispatch.DispatchRequest{Task: task}))
	}

	require.NoError(t, os.WriteFile(filepath.Join(obs, "allow-run"), nil, 0o600))
	retry()
	waitFor(ir.Failed, 1, "publish")
	logObservation(t, "after execution 2 (run ok, publish fails)", f, runID, obs)

	require.NoError(t, os.WriteFile(filepath.Join(obs, "allow-publish"), nil, 0o600))
	retry()
	waitFor(ir.Succeeded, 2, "publish")
	logObservation(t, "after execution 3 (publish only)", f, runID, obs)
}

func TestTXEObserveRetry_Direct(t *testing.T) { observeRetries(t, false) }
func TestTXEObserveRetry_Queued(t *testing.T) { observeRetries(t, true) }
