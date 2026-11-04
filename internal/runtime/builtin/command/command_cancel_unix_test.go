// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package command

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/cmdutil"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/dagucloud/dagu/v2/internal/runtime/executor"
	"github.com/dagucloud/dagu/v2/internal/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cancelRun is one executor run of a shell script that reports when it is
// ready and whose process group holds the executor's stdout pipe.
type cancelRun struct {
	dir      string
	ready    string
	marker   string
	pidFile  string
	exec     executor.Executor
	cancel   context.CancelFunc
	done     chan error
	finished time.Time
}

// startCancelRun runs script in the background with the given cancellation
// grace and waits until the script has touched its ready marker. The script
// may use $READY, $MARKER and $PIDFILE.
func startCancelRun(t *testing.T, grace time.Duration, script string) *cancelRun {
	t.Helper()
	dir := t.TempDir()
	r := &cancelRun{
		dir:     dir,
		ready:   filepath.Join(dir, "ready"),
		marker:  filepath.Join(dir, "marker"),
		pidFile: filepath.Join(dir, "pid"),
		done:    make(chan error, 1),
	}
	step := ir.Step{
		Name:   "cancel-test",
		Script: script,
		Shell:  "sh",
		Dir:    dir,
	}
	dag := &ir.DAG{
		Name:           "cancel-test",
		MaxCleanUpTime: grace,
		Env: []string{
			"READY=" + r.ready,
			"MARKER=" + r.marker,
			"PIDFILE=" + r.pidFile,
		},
	}
	base := setupTestContext(t, dag, step)
	env := runtime.GetEnv(base)
	env.WorkingDir = dir
	base = runtime.WithEnv(base, env)
	ctx, cancel := context.WithCancel(base)
	r.cancel = cancel
	t.Cleanup(cancel)

	ex, err := NewCommand(ctx, step)
	require.NoError(t, err)
	// Buffers, not files: the command's stdout and stderr are pipes that every
	// process in the group inherits, so Wait only returns once they are gone.
	var stdout, stderr bytes.Buffer
	ex.SetStdout(&stdout)
	ex.SetStderr(&stderr)
	r.exec = ex
	go func() {
		err := ex.Run(ctx)
		r.finished = time.Now()
		r.done <- err
	}()
	require.Eventually(t, func() bool {
		_, err := os.Stat(r.ready)
		return err == nil
	}, 10*time.Second, 20*time.Millisecond, "script should report ready")
	return r
}

// wait returns Run's error, failing the test if Run does not return in time.
func (r *cancelRun) wait(t *testing.T, within time.Duration) error {
	t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(within):
		t.Fatalf("Run did not return within %s", within)
		return nil
	}
}

func (r *cancelRun) exitCode(t *testing.T) int {
	t.Helper()
	coder, ok := r.exec.(executor.ExitCoder)
	require.True(t, ok)
	return coder.ExitCode()
}

// backgroundPID is the pid the script wrote to $PIDFILE.
func (r *cancelRun) backgroundPID(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(r.pidFile)
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	require.NoError(t, err)
	return pid
}

func requireProcessGone(t *testing.T, pid int) {
	t.Helper()
	require.Eventually(t, func() bool {
		err := syscall.Kill(pid, 0)
		return err == syscall.ESRCH
	}, 5*time.Second, 20*time.Millisecond, "process %d should be gone", pid)
}

// The scripts run under sh (bash or dash): zsh's wait returns on an ignored
// signal, which would end the TERM-ignoring script on its own.

const trapScript = `
trap 'echo trapped >> "$MARKER"; exit 1' TERM
sleep 30 &
echo $! > "$PIDFILE"
touch "$READY"
wait
`

// ignoreTermScript ignores SIGTERM in the shell and, through inheritance, in
// its sleep; the loop keeps the shell alive for as long as the sleep lives
// whatever wait does on a signal.
const ignoreTermScript = `
trap '' TERM
sleep 30 &
bg=$!
echo "$bg" > "$PIDFILE"
touch "$READY"
while kill -0 "$bg" 2>/dev/null; do sleep 0.1; done
`

// A cancelled step gets SIGTERM and its trap completes within the grace; the
// run ends as soon as the process is gone, not when the grace is over.
func TestCommandExecutor_CancelRunsTrapWithinGrace(t *testing.T) {
	r := startCancelRun(t, 5*time.Second, trapScript)
	bg := r.backgroundPID(t)

	cancelledAt := time.Now()
	r.cancel()
	err := r.wait(t, 10*time.Second)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 124, r.exitCode(t))
	data, readErr := os.ReadFile(r.marker)
	require.NoError(t, readErr, "the TERM trap should have run")
	assert.Equal(t, "trapped\n", string(data))
	assert.Less(t, r.finished.Sub(cancelledAt), 3*time.Second, "Run should return when the process exits, well inside the grace")
	requireProcessGone(t, bg)
}

// A step that ignores SIGTERM is killed, with its process group, once the
// grace is over.
func TestCommandExecutor_CancelForcesAfterGraceWhenTermIgnored(t *testing.T) {
	const grace = 500 * time.Millisecond
	r := startCancelRun(t, grace, ignoreTermScript)
	bg := r.backgroundPID(t)

	cancelledAt := time.Now()
	r.cancel()
	err := r.wait(t, 10*time.Second)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 124, r.exitCode(t))
	elapsed := r.finished.Sub(cancelledAt)
	assert.GreaterOrEqual(t, elapsed, grace, "the forced stop waits for the grace")
	assert.Less(t, elapsed, 5*time.Second, "the forced stop is bounded by the grace")
	requireProcessGone(t, bg)
	assert.NoFileExists(t, r.marker)
}

// A zero grace, which only a DAG built in code can carry because the loader
// fills in the default, forces at once without a SIGTERM.
func TestCommandExecutor_CancelWithZeroGraceForcesAtOnce(t *testing.T) {
	r := startCancelRun(t, 0, trapScript)
	bg := r.backgroundPID(t)

	cancelledAt := time.Now()
	r.cancel()
	err := r.wait(t, 10*time.Second)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 124, r.exitCode(t))
	assert.Less(t, r.finished.Sub(cancelledAt), 2*time.Second)
	assert.NoFileExists(t, r.marker, "no SIGTERM is sent when there is no grace")
	requireProcessGone(t, bg)
}

// The agent's own stop escalation keeps its earlier deadline: a forced stop
// that arrives while the executor is still waiting out its grace ends the run
// at once.
func TestCommandExecutor_CancelGraceDoesNotExtendAnExternalForcedStop(t *testing.T) {
	r := startCancelRun(t, 20*time.Second, ignoreTermScript)
	bg := r.backgroundPID(t)

	cancelledAt := time.Now()
	r.cancel()
	time.Sleep(200 * time.Millisecond)
	stopper, ok := r.exec.(executor.Stopper)
	require.True(t, ok)
	require.NoError(t, stopper.Stop(cmdutil.ForceTermination()))
	err := r.wait(t, 10*time.Second)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 124, r.exitCode(t))
	assert.Less(t, r.finished.Sub(cancelledAt), 3*time.Second, "the external force ends the run long before the grace")
	requireProcessGone(t, bg)
}

// A child that ignores SIGTERM and holds no output pipe outlives the trap's
// exit; the group is still swept once the root is gone, as a cancellation
// killed the whole group before the graceful step.
func TestCommandExecutor_CancelSweepsGroupAfterRootExits(t *testing.T) {
	r := startCancelRun(t, 5*time.Second, `
trap 'exit 1' TERM
(trap '' TERM; exec sleep 30 >/dev/null 2>&1) &
echo $! > "$PIDFILE"
touch "$READY"
wait
`)
	bg := r.backgroundPID(t)

	cancelledAt := time.Now()
	r.cancel()
	err := r.wait(t, 10*time.Second)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 124, r.exitCode(t))
	assert.Less(t, r.finished.Sub(cancelledAt), 3*time.Second, "the root's exit ends the run")
	requireProcessGone(t, bg)
}

// A second SIGTERM during the trap, which the agent's own stop sends, does not
// stop the trap from completing or the group from ending. How the shell
// treats the second signal is its own: bash finishes the running handler,
// dash re-enters it, so the handler may run once or twice.
func TestCommandExecutor_CancelDuplicateTermStillEndsTheRun(t *testing.T) {
	r := startCancelRun(t, 5*time.Second, `
trap 'echo trapped >> "$MARKER"; sleep 0.3; exit 1' TERM
sleep 30 &
echo $! > "$PIDFILE"
touch "$READY"
wait
`)
	bg := r.backgroundPID(t)

	r.cancel()
	require.Eventually(t, func() bool {
		_, err := os.Stat(r.marker)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "the trap should start")
	require.NoError(t, r.exec.(executor.Stopper).Stop(cmdutil.GracefulTermination(syscall.SIGTERM)))
	err := r.wait(t, 10*time.Second)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 124, r.exitCode(t))
	data, readErr := os.ReadFile(r.marker)
	require.NoError(t, readErr)
	assert.GreaterOrEqual(t, strings.Count(string(data), "trapped\n"), 1, "the trap ran")
	assert.LessOrEqual(t, strings.Count(string(data), "trapped\n"), 2, "the trap ran at most once per SIGTERM")
	requireProcessGone(t, bg)
}

// A timeout keeps its immediate kill: no SIGTERM, no grace, the same error
// and exit code as before.
func TestCommandExecutor_TimeoutKillsAtOnceWithoutGrace(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	ready := filepath.Join(dir, "ready")
	pidFile := filepath.Join(dir, "pid")
	step := ir.Step{
		Name:   "timeout-test",
		Script: trapScript,
		Shell:  "sh",
		Dir:    dir,
	}
	dag := &ir.DAG{
		Name:           "timeout-test",
		MaxCleanUpTime: 20 * time.Second,
		Env:            []string{"READY=" + ready, "MARKER=" + marker, "PIDFILE=" + pidFile},
	}
	base := setupTestContext(t, dag, step)
	env := runtime.NewEnv(base, step)
	env.WorkingDir = dir
	base = runtime.WithEnv(base, env)
	runCtx, runCancel := context.WithTimeout(base, 700*time.Millisecond)
	defer runCancel()

	ex, err := NewCommand(runCtx, step)
	require.NoError(t, err)
	var stdout, stderr bytes.Buffer
	ex.SetStdout(&stdout)
	ex.SetStderr(&stderr)
	started := time.Now()
	err = ex.Run(runCtx)
	elapsed := time.Since(started)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, 124, ex.(executor.ExitCoder).ExitCode())
	assert.Less(t, elapsed, 5*time.Second, "a timeout does not wait out the grace")
	assert.NoFileExists(t, marker, "a timeout sends no SIGTERM")
	data, readErr := os.ReadFile(pidFile)
	if readErr == nil {
		pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
		require.NoError(t, convErr)
		requireProcessGone(t, pid)
	}
}

// A cancellation before the process starts never starts it; the error and
// exit code are the ones Start already reported.
func TestCommandExecutor_CancelBeforeStart(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	step := ir.Step{
		Name:   "before-start",
		Script: "touch \"$READY\"; sleep 30",
		Shell:  "sh",
		Dir:    dir,
	}
	dag := &ir.DAG{
		Name:           "before-start",
		MaxCleanUpTime: 5 * time.Second,
		Env:            []string{"READY=" + ready},
	}
	base := setupTestContext(t, dag, step)
	env := runtime.NewEnv(base, step)
	env.WorkingDir = dir
	base = runtime.WithEnv(base, env)
	ctx, cancel := context.WithCancel(base)
	cancel()

	ex, err := NewCommand(ctx, step)
	require.NoError(t, err)
	started := time.Now()
	err = ex.Run(ctx)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, ex.(executor.ExitCoder).ExitCode())
	assert.Less(t, time.Since(started), 2*time.Second)
	assert.Nil(t, ex.(*commandExecutor).process, "no process is started")
	time.Sleep(100 * time.Millisecond)
	assert.NoFileExists(t, ready)
}

// The grace is the DAG's max_clean_up_time as the executor sees it: as
// configured; the ir default of 5 s once the DAG has had its defaults applied,
// which loading from a file and rebuilding from YAML both do, for a file that
// sets none or sets 0; and zero for a DAG built in code, for a bare
// spec.LoadYAML result, or for a context without a DAG.
func TestCancelGracePeriod(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		dag := &ir.DAG{Name: "g", MaxCleanUpTime: 7 * time.Second}
		ctx := setupTestContext(t, dag, ir.Step{Name: "s"})
		assert.Equal(t, 7*time.Second, cancelGracePeriod(ctx))
	})
	t.Run("bare LoadYAML leaves zero until defaults are applied", func(t *testing.T) {
		dag, err := spec.LoadYAML(context.Background(), []byte("steps:\n  - name: s\n    command: \"true\"\n"))
		require.NoError(t, err)
		ctx := setupTestContext(t, dag, ir.Step{Name: "s"})
		assert.Equal(t, time.Duration(0), cancelGracePeriod(ctx))
		ir.InitializeDefaults(dag)
		assert.Equal(t, 5*time.Second, cancelGracePeriod(ctx))
	})
	t.Run("max_clean_up_time_sec 0 becomes the default once defaults are applied", func(t *testing.T) {
		dag, err := spec.LoadYAML(context.Background(), []byte("max_clean_up_time_sec: 0\nsteps:\n  - name: s\n    command: \"true\"\n"))
		require.NoError(t, err)
		ir.InitializeDefaults(dag)
		ctx := setupTestContext(t, dag, ir.Step{Name: "s"})
		assert.Equal(t, 5*time.Second, cancelGracePeriod(ctx))
	})
	t.Run("DAG built in code with zero", func(t *testing.T) {
		dag := &ir.DAG{Name: "g"}
		ctx := setupTestContext(t, dag, ir.Step{Name: "s"})
		assert.Equal(t, time.Duration(0), cancelGracePeriod(ctx))
	})
	t.Run("no DAG in context", func(t *testing.T) {
		assert.Equal(t, time.Duration(0), cancelGracePeriod(context.Background()))
	})
}
