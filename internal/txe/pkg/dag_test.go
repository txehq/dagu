// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"context"
	"testing"
	"time"

	_ "github.com/dagucloud/dagu/v2/internal/runtime/builtin" // the loader needs the command executor registered
	"github.com/dagucloud/dagu/v2/internal/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDAGSpec() DAGSpec {
	return DAGSpec{
		Title:         "Watch the dagu hub volume",
		ProjectName:   "txehq/txe",
		JobID:         testJob,
		OwnerID:       "own_01K7A5ZQ8M3N4P5R6S7T8V9W0A",
		ProjectID:     "prj_01K7A5ZQ8M3N4P5R6S7T8V9W0B",
		MachineID:     "mch_01K7A5ZQ8M3N4P5R6S7T8V9W0C",
		Version:       2,
		PackageDigest: testDigest,
		WorkDir:       "/Users/x/.local/share/txe-dagu/packages/" + testJob + "/sha256-0123/files",
		OutputDir:     "/Users/x/.local/share/txe-dagu/outputs/" + testJob,
		Entrypoint:    []string{"./check.sh", "--label", "it's a test"},
		Schedule: Schedule{
			Cron: "*/5 * * * *", Timezone: "Australia/Perth", TimeoutSec: 120,
			Retry: 2, RetryIntervalSec: 30, CatchupWindow: "1h",
		},
		Env: map[string]string{"TARGET_ID": "vol-uid-1", "MAX_AGE_SEC": "600"},
		CredentialRefs: []CredentialRef{
			{Name: "LINEAR_API_KEY", Kind: CredentialFile, Locator: "/Users/x/.config/txe/linear-token"},
		},
	}
}

const wantDAG = `description: "Watch the dagu hub volume"
group: "txehq/txe"
labels:
  - "txe.schema=1"
  - "txe.owner=own_01K7A5ZQ8M3N4P5R6S7T8V9W0A"
  - "txe.project=prj_01K7A5ZQ8M3N4P5R6S7T8V9W0B"
  - "txe.job=job_01K7A5ZQ8M3N4P5R6S7T8V9W0X"
  - "txe.machine=mch_01K7A5ZQ8M3N4P5R6S7T8V9W0C"
  - "txe.version=2"
  - "txe.package=sha256-0123456789abcdef0123456789abcdef"
worker_selector:
  txe.machine: "mch_01K7A5ZQ8M3N4P5R6S7T8V9W0C"
schedule: "CRON_TZ=Australia/Perth */5 * * * *"
overlap_policy: skip
catchup_window: "1h"
max_active_runs: 1
timeout_sec: 120
working_dir: "/Users/x/.local/share/txe-dagu/packages/job_01K7A5ZQ8M3N4P5R6S7T8V9W0X/sha256-0123/files"
env:
  - TXE_JOB_ID: "job_01K7A5ZQ8M3N4P5R6S7T8V9W0X"
  - TXE_JOB_VERSION: "2"
  - TXE_OUTPUT_DIR: "/Users/x/.local/share/txe-dagu/outputs/job_01K7A5ZQ8M3N4P5R6S7T8V9W0X"
  - MAX_AGE_SEC: "600"
  - TARGET_ID: "vol-uid-1"
secrets:
  - name: LINEAR_API_KEY
    provider: file
    key: "/Users/x/.config/txe/linear-token"
steps:
  - name: run
    command: "./check.sh --label 'it'\\''s a test'"
    retry_policy:
      limit: 2
      interval_sec: 30
`

// The rendered bytes are part of the registration contract: the registry
// hashes them, and a replay must send the same ones.
func TestRenderDAGBytes(t *testing.T) {
	got, err := RenderDAG(testDAGSpec())
	require.NoError(t, err)
	assert.Equal(t, wantDAG, string(got))

	again, err := RenderDAG(testDAGSpec())
	require.NoError(t, err)
	assert.Equal(t, got, again)
}

// Dagu's own loader accepts the definition and reads back what was meant.
func TestRenderDAGLoads(t *testing.T) {
	s := testDAGSpec()
	data, err := RenderDAG(s)
	require.NoError(t, err)

	dag, err := spec.LoadYAML(context.Background(), data, spec.WithName(s.JobID), spec.WithoutEval())
	require.NoError(t, err)

	assert.Equal(t, s.JobID, dag.Name)
	assert.Equal(t, s.Title, dag.Description)
	assert.Equal(t, map[string]string{LabelMachine: s.MachineID}, dag.WorkerSelector)
	assert.Equal(t, s.WorkDir, dag.WorkingDir)
	assert.Equal(t, 120*time.Second, dag.Timeout)
	assert.Equal(t, time.Hour, dag.CatchupWindow)
	assert.Equal(t, "skip", string(dag.OverlapPolicy))
	assert.Equal(t, 1, dag.MaxActiveRuns)
	require.Len(t, dag.Schedule, 1)
	assert.Equal(t, "CRON_TZ=Australia/Perth */5 * * * *", dag.Schedule[0].Expression)

	require.Len(t, dag.Secrets, 1)
	assert.Equal(t, "LINEAR_API_KEY", dag.Secrets[0].Name)
	assert.Equal(t, "file", dag.Secrets[0].Provider)
	assert.Equal(t, "/Users/x/.config/txe/linear-token", dag.Secrets[0].Key)

	require.Len(t, dag.Steps, 1)
	assert.Equal(t, 2, dag.Steps[0].RetryPolicy.Limit)
	assert.Equal(t, 30*time.Second, dag.Steps[0].RetryPolicy.Interval)
	assert.Contains(t, dag.Env, "TXE_OUTPUT_DIR="+s.OutputDir)
	assert.Contains(t, dag.Env, "TARGET_ID=vol-uid-1")

	// Labels come back lowercased, which is why no ID is ever read from one.
	assert.Contains(t, dag.Labels.Strings(), "txe.job=job_01k7a5zq8m3n4p5r6s7t8v9w0x")
}

func TestRenderDAGRefusals(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*DAGSpec)
		wantErr string
	}{
		{"NoTimezone", func(s *DAGSpec) { s.Schedule.Timezone = "" }, "schedule.timezone is required"},
		{"UnknownTimezone", func(s *DAGSpec) { s.Schedule.Timezone = "Mars/Olympus" }, "not a known time zone"},
		{"NoTimeout", func(s *DAGSpec) { s.Schedule.TimeoutSec = 0 }, "schedule.timeout_sec is required"},
		{"BadCron", func(s *DAGSpec) { s.Schedule.Cron = "@every 5m" }, "five-field cron"},
		{"UnboundedRetry", func(s *DAGSpec) { s.Schedule.Retry = 100 }, "between 0 and 5"},
		{"RetryWithoutInterval", func(s *DAGSpec) { s.Schedule.RetryIntervalSec = 0 }, "retry_interval_sec is required"},
		{"BadOverlap", func(s *DAGSpec) { s.Schedule.Overlap = "queue" }, "skip, all or latest"},
		{"BadCatchup", func(s *DAGSpec) { s.Schedule.CatchupWindow = "soon" }, "not a duration"},
		{"RelativeWorkDir", func(s *DAGSpec) { s.WorkDir = "files" }, "must be absolute"},
		{"ExpandedEnv", func(s *DAGSpec) { s.Env["WHERE"] = "${HOME}/x" }, "expands on the worker"},
		{"ExpandedArgument", func(s *DAGSpec) { s.Entrypoint = []string{"./check.sh", "`id`"} }, "expands on the worker"},
		{"ReservedEnv", func(s *DAGSpec) { s.Env["TXE_OUTPUT_DIR"] = "/elsewhere" }, "cannot be overridden"},
		{"CredentialShadowsEnv", func(s *DAGSpec) { s.Env["LINEAR_API_KEY"] = "x" }, "collides"},
		{"CredentialKind", func(s *DAGSpec) { s.CredentialRefs[0].Kind = "literal" }, "kind must be"},
		{"NoEntrypoint", func(s *DAGSpec) { s.Entrypoint = nil }, "entrypoint is required"},
		{"BadID", func(s *DAGSpec) { s.MachineID = "mch 1" }, "invalid id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testDAGSpec()
			tt.mutate(&s)
			_, err := RenderDAG(s)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestShellJoin(t *testing.T) {
	assert.Equal(t, "./run.sh --flag=x plain", ShellJoin([]string{"./run.sh", "--flag=x", "plain"}))
	assert.Equal(t, `./run.sh 'a b' '' 'it'\''s'`, ShellJoin([]string{"./run.sh", "a b", "", "it's"}))
}
