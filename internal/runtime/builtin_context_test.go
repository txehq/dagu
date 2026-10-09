// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package runtime_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/cmn/runenv"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	cmnvalue "github.com/dagucloud/dagu/v2/internal/cmn/value"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveStringBuiltInRunContext(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	wikiDir := filepath.Join(tmpDir, "wiki")
	workDir := filepath.Join(tmpDir, "work")
	artifactDir := filepath.Join(tmpDir, "artifacts")
	logFile := filepath.Join(tmpDir, "dag.log")
	startedAt := "2026-03-13T10:00:01Z"
	scheduledAt := "2026-03-13T10:00:00Z"
	profileResolvedAt := "2026-03-13T09:59:00Z"

	dag := &ir.DAG{Name: "child"}
	cfg := &config.Config{}
	cfg.Paths.WikiDir = wikiDir
	ctx := config.WithConfig(context.Background(), cfg)
	ctx = runtime.NewContext(ctx, dag, "run-1", logFile,
		runtime.WithAttemptID("attempt-1"),
		runtime.WithRootDAGRun(ir.NewDAGRunRef("root", "root-run-1")),
		runtime.WithTriggerType(ir.TriggerTypeScheduler),
		runtime.WithRunStartedAt(startedAt),
		runtime.WithScheduleTime(scheduledAt),
		runtime.WithWorkDir(workDir),
		runtime.WithArtifactDir(artifactDir),
		runtime.WithRuntimeProfile("prod", profileResolvedAt, nil),
	)

	env := runtime.NewEnv(ctx, ir.Step{ID: "build-id", Name: "build"})
	env.Scope = env.Scope.WithEntries(map[string]string{
		runenv.EnvKeyDAGRunStatus:                  ir.Succeeded.String(),
		runenv.EnvKeyDAGRunStepStdoutFile:          filepath.Join(tmpDir, "stdout.log"),
		runenv.EnvKeyDAGRunStepStderrFile:          filepath.Join(tmpDir, "stderr.log"),
		runenv.EnvKeyDAGUOutputFile:                filepath.Join(tmpDir, "output.json"),
		runenv.EnvKeyDAGPushBackIteration:          "2",
		runenv.EnvKeyDAGPushBackPreviousStdoutFile: filepath.Join(tmpDir, "previous.log"),
	}, cmnvalue.EnvSourceStepEnv)
	ctx = runtime.WithEnv(ctx, env)

	got, err := runtime.ResolveString(ctx, "${context.dag.name}|${context.run.id}|${context.run.status}|${context.attempt.started_at}|${context.run.scheduled_at}|${context.run.root_name}|${context.run.root_id}|${context.attempt.id}|${context.step.id}|${context.step.name}|${context.trigger.type}|${context.paths.log_file}|${context.paths.work_dir}|${context.paths.artifacts_dir}|${context.paths.wiki_dir}|${context.paths.step_stdout_file}|${context.paths.step_stderr_file}|${context.paths.step_output_file}|${context.profile.name}|${context.profile.resolved_at}|${context.pushback.iteration}|${context.pushback.previous_stdout_file}", cmnvalue.WorkflowField("run"))
	require.NoError(t, err)

	expected := "child|run-1|succeeded|" + startedAt + "|" + scheduledAt + "|root|root-run-1|attempt-1|build-id|build|scheduler|" +
		logFile + "|" + workDir + "|" + artifactDir + "|" + filepath.Join(wikiDir, "child") + "|" +
		filepath.Join(tmpDir, "stdout.log") + "|" + filepath.Join(tmpDir, "stderr.log") + "|" +
		filepath.Join(tmpDir, "output.json") + "|prod|" + profileResolvedAt + "|2|" + filepath.Join(tmpDir, "previous.log")
	assert.Equal(t, expected, got)

	legacy, err := runtime.ResolveString(ctx, "${context.paths.docs_dir}|${paths.docs_dir}", cmnvalue.WorkflowField("run"))
	require.NoError(t, err)
	wikiPath := filepath.Join(wikiDir, "child")
	assert.Equal(t, wikiPath+"|"+wikiPath, legacy)
}

func TestResolveStringUnavailableBuiltInRunContextStaysLiteral(t *testing.T) {
	t.Parallel()

	ctx := runtime.NewContext(context.Background(), &ir.DAG{Name: "test"}, "run-1", "dag.log",
		runtime.WithWorkDir(t.TempDir()),
	)
	env := runtime.NewEnv(ctx, ir.Step{Name: "step"})
	ctx = runtime.WithEnv(ctx, env)

	input := "${context.run.status} ${context.run.root_name} ${context.run.root_id} ${context.trigger.actor} ${context.profile.name} ${context.pushback.iteration}"
	got, err := runtime.ResolveString(ctx, input, cmnvalue.WorkflowField("run"))
	require.NoError(t, err)
	assert.Equal(t, input, got)
}

func TestResolveStringLegacyBuiltInRunContextAliases(t *testing.T) {
	t.Parallel()

	ctx := runtime.NewContext(context.Background(), &ir.DAG{Name: "test"}, "run-1", "dag.log",
		runtime.WithAttemptID("attempt-1"),
		runtime.WithRunStartedAt("2026-03-13T10:00:01Z"),
		runtime.WithWorkDir(t.TempDir()),
	)
	env := runtime.NewEnv(ctx, ir.Step{Name: "step"})
	ctx = runtime.WithEnv(ctx, env)

	got, err := runtime.ResolveString(ctx, "${dag.name}|${run.id}|${run.started_at}|${attempt.id}|${step.name}", cmnvalue.WorkflowField("run"))
	require.NoError(t, err)
	assert.Equal(t, "test|run-1|2026-03-13T10:00:01Z|attempt-1|step", got)
}

// The queue marker reaches a step exactly as it is stored. It is compared for
// equality with the stored status, so neither the zone of a first enqueue nor
// the fraction a queued retry writes may be normalised away.
func TestResolveStringAttemptQueuedAt(t *testing.T) {
	t.Parallel()

	for _, queuedAt := range []string{
		"2026-10-09T23:48:55+08:00",
		"2026-10-09T15:48:58.155644Z",
		"2026-10-09T15:48:58.155644001Z",
	} {
		ctx := runtime.NewContext(context.Background(), &ir.DAG{Name: "test"}, "run-1", "dag.log",
			runtime.WithAttemptID("attempt-1"),
			runtime.WithAttemptQueuedAt(queuedAt),
			runtime.WithWorkDir(t.TempDir()),
		)
		ctx = runtime.WithEnv(ctx, runtime.NewEnv(ctx, ir.Step{Name: "step"}))

		got, err := runtime.ResolveString(ctx, "${context.attempt.id}|${context.attempt.queued_at}", cmnvalue.WorkflowField("run"))
		require.NoError(t, err)
		assert.Equal(t, "attempt-1|"+queuedAt, got)
	}
}

// A run that was never queued has no marker, and the reference is left as it
// is written, like any other unavailable field.
func TestResolveStringAttemptQueuedAtUnavailable(t *testing.T) {
	t.Parallel()

	ctx := runtime.NewContext(context.Background(), &ir.DAG{Name: "test"}, "run-1", "dag.log",
		runtime.WithAttemptID("attempt-1"),
		runtime.WithWorkDir(t.TempDir()),
	)
	ctx = runtime.WithEnv(ctx, runtime.NewEnv(ctx, ir.Step{Name: "step"}))

	got, err := runtime.ResolveString(ctx, "${context.attempt.id}|${context.attempt.queued_at}", cmnvalue.WorkflowField("run"))
	require.NoError(t, err)
	assert.Equal(t, "attempt-1|${context.attempt.queued_at}", got)
}
