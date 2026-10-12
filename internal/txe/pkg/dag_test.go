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
		CLI: CLI{
			Dagu:       "/Users/x/.local/share/txe-dagu/bin/dagu",
			StoreFlags: []string{"--dagu-home", "/Users/x/.local/share/txe-dagu/client"},
			HomeRoot:   "/Users/x/.local/share/txe-dagu",
		},
	}
}

const wantDAG = `type: chain
description: "Watch the dagu hub volume"
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
  - TXE_ATTEMPT_ID: "${context.attempt.id}"
  - TXE_QUEUED_AT: "${context.attempt.queued_at}"
  - TXE_RUN_OUTPUT_DIR: "/Users/x/.local/share/txe-dagu/outputs/job_01K7A5ZQ8M3N4P5R6S7T8V9W0X/runs/${DAG_RUN_ID}/attempts/${context.attempt.id}"
  - TXE_DAGU_HOME: "/Users/x/.local/share/txe-dagu"
  - MAX_AGE_SEC: "600"
  - TARGET_ID: "vol-uid-1"
secrets:
  - name: LINEAR_API_KEY
    provider: file
    key: "/Users/x/.config/txe/linear-token"
steps:
  - name: run
    command:
      - "/Users/x/.local/share/txe-dagu/bin/dagu txe resource check --job job_01K7A5ZQ8M3N4P5R6S7T8V9W0X --job-version 2 --machine mch_01K7A5ZQ8M3N4P5R6S7T8V9W0C --dagu-home /Users/x/.local/share/txe-dagu/client"
      - "./check.sh --label 'it'\\''s a test'"
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

// A job's step output reaches the hub only as the worker's log stream. The
// definition never redirects it to a file or an artifact, and captures no
// output variable: those paths write through other writers and, for an
// artifact, upload the file.
func TestRenderDAGHasNoOutputRedirect(t *testing.T) {
	s := testDAGSpec()
	data, err := RenderDAG(s)
	require.NoError(t, err)
	for _, key := range []string{"stdout", "stderr", "output", "artifacts", "log_output", "dependencies"} {
		assert.NotContains(t, string(data), key+":", "the rendered DAG sets %s", key)
	}

	dag, err := spec.LoadYAML(context.Background(), data, spec.WithName(s.JobID), spec.WithoutEval())
	require.NoError(t, err)
	require.Len(t, dag.Steps, 1)
	step := dag.Steps[0]
	assert.Empty(t, step.Stdout)
	assert.Empty(t, step.Stderr)
	assert.Empty(t, step.StdoutArtifact)
	assert.Empty(t, step.StderrArtifact)
	assert.Empty(t, step.Output)
	assert.False(t, dag.ArtifactsEnabled())
	// The worker selector is what makes the run execute on a worker, where
	// step output is streamed, and never in the hub's own process.
	assert.NotEmpty(t, dag.WorkerSelector)
}

// A job with deliverables gets a second step that records them, and the
// native artifact directory only when a deliverable goes to the hub.
func TestRenderDAGPublishStep(t *testing.T) {
	s := testDAGSpec()
	s.Publish = &Publish{HubArtifacts: true}
	data, err := RenderDAG(s)
	require.NoError(t, err)
	text := string(data)
	assert.Contains(t, text, "artifacts:\n  enabled: true\n")
	assert.Contains(t, text, `  - TXE_DAGU_HOME: "/Users/x/.local/share/txe-dagu"`)
	assert.Contains(t, text, "  - name: publish\n    command: \"/Users/x/.local/share/txe-dagu/bin/dagu txe artifacts publish --dagu-home /Users/x/.local/share/txe-dagu/client\"\n")

	// The job's command runs after the resource check and between begin and
	// seal, in one step: a failed command stops the step, so the job does
	// not run unchecked, its outputs are sealed only if it succeeded, and a
	// retry of the step runs all four again.
	assert.Contains(t, text, `  - name: run
    command:
      - "/Users/x/.local/share/txe-dagu/bin/dagu txe resource check --job job_01K7A5ZQ8M3N4P5R6S7T8V9W0X --job-version 2 --machine mch_01K7A5ZQ8M3N4P5R6S7T8V9W0C --dagu-home /Users/x/.local/share/txe-dagu/client"
      - "/Users/x/.local/share/txe-dagu/bin/dagu txe artifacts begin --dagu-home /Users/x/.local/share/txe-dagu/client"
      - "./check.sh --label 'it'\\''s a test'"
      - "/Users/x/.local/share/txe-dagu/bin/dagu txe artifacts seal --dagu-home /Users/x/.local/share/txe-dagu/client"
    retry_policy:
`)

	dag, err := spec.LoadYAML(context.Background(), data, spec.WithName(s.JobID), spec.WithoutEval())
	require.NoError(t, err)
	require.Len(t, dag.Steps, 2)
	require.Len(t, dag.Steps[0].Commands, 4)
	home := []string{"--dagu-home", "/Users/x/.local/share/txe-dagu/client"}
	assert.Equal(t, append([]string{"txe", "resource", "check", "--job", s.JobID, "--job-version", "2", "--machine", s.MachineID}, home...),
		dag.Steps[0].Commands[0].Args)
	assert.Equal(t, append([]string{"txe", "artifacts", "begin"}, home...), dag.Steps[0].Commands[1].Args)
	assert.Equal(t, "./check.sh", dag.Steps[0].Commands[2].Command)
	assert.Equal(t, append([]string{"txe", "artifacts", "seal"}, home...), dag.Steps[0].Commands[3].Args)
	assert.Equal(t, "publish", dag.Steps[1].Name)
	require.Len(t, dag.Steps[1].Commands, 1)
	// The publish step waits for the job's step: the DAG is a chain, and the
	// loader records the dependency.
	assert.Equal(t, "chain", dag.Type)
	assert.Equal(t, []string{"run"}, dag.Steps[1].Depends)
	assert.True(t, dag.ArtifactsEnabled())
	// Still no redirect of step output.
	for _, step := range dag.Steps {
		assert.Empty(t, step.Stdout+step.Stderr+step.StdoutArtifact+step.StderrArtifact+step.Output)
	}

	s.Publish.HubArtifacts = false
	data, err = RenderDAG(s)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "artifacts:")

}

// Every job's DAG calls dagu before the job runs, so every job needs the
// binary, the store flags and the TXE home spelled out.
func TestRenderDAGNeedsTheCLI(t *testing.T) {
	s := testDAGSpec()
	s.CLI.Dagu = "dagu"
	_, err := RenderDAG(s)
	require.ErrorContains(t, err, "must be an absolute path")

	s = testDAGSpec()
	s.CLI.HomeRoot = ""
	_, err = RenderDAG(s)
	require.ErrorContains(t, err, "TXE home")

	// A job without deliverables has the check and its own command, and
	// nothing that seals or publishes.
	s = testDAGSpec()
	data, err := RenderDAG(s)
	require.NoError(t, err)
	dag, err := spec.LoadYAML(context.Background(), data, spec.WithName(s.JobID), spec.WithoutEval())
	require.NoError(t, err)
	require.Len(t, dag.Steps, 1)
	require.Len(t, dag.Steps[0].Commands, 2)
	assert.Equal(t, []string{"txe", "resource", "check"}, dag.Steps[0].Commands[0].Args[:3])
	assert.Equal(t, "./check.sh", dag.Steps[0].Commands[1].Command)
	assert.NotContains(t, string(data), "artifacts")
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
