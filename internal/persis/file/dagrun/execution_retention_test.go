// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	filedagrun "github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
	"github.com/dagucloud/dagu/v2/internal/testutil"
)

type retentionFixture struct {
	t       *testing.T
	ctx     context.Context
	repo    *persis.DAGRunRepository
	logDir  string
	dag     *ir.DAG
	runID   string
	attempt string
	handle  dagrun.Attempt
}

func newRetentionFixture(t *testing.T) *retentionFixture {
	t.Helper()
	dir := t.TempDir()
	f := &retentionFixture{t: t, ctx: context.Background(), logDir: filepath.Join(dir, "logs"),
		dag: &ir.DAG{Name: "job"}, runID: "run-1"}
	f.repo = testutil.NewFileDAGRunRepository(filepath.Join(dir, "runs"), persis.DAGRunRepositoryOptions{},
		filedagrun.WithLogDir(f.logDir), filedagrun.WithArtifactDir(filepath.Join(dir, "artifacts")))
	attempt, err := f.repo.CreateAttempt(f.ctx, f.dag, time.Now(), f.runID, persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	f.attempt, f.handle = attempt.ID(), attempt
	return f
}

// execution writes one finished execution of the attempt: its status and
// the logs the coordinator would have written for it.
func (f *retentionFixture) execution(queuedAt string, st ir.Status, line string) ir.DAGRunStatus {
	f.t.Helper()
	attempt := f.handle
	status := ir.InitialStatus(f.dag)
	status.DAGRunID, status.AttemptID, status.QueuedAt, status.Status = f.runID, f.attempt, queuedAt, st
	status.Error = line
	logs := filepath.Join(f.logDir, f.dag.Name, f.runID, f.attempt)
	require.NoError(f.t, os.MkdirAll(logs, 0o750))
	require.NoError(f.t, os.WriteFile(filepath.Join(logs, "scheduler.log"), []byte("scheduler "+line+"\n"), 0o600))
	require.NoError(f.t, os.WriteFile(filepath.Join(logs, "run.stdout.log"), []byte("stdout "+line+"\n"), 0o600))
	require.NoError(f.t, attempt.Open(f.ctx))
	require.NoError(f.t, attempt.Write(f.ctx, status))
	require.NoError(f.t, attempt.Close(f.ctx))
	return status
}

// requeue swaps the finished execution to queued with retention, as a queued
// retry's admission does.
func (f *retentionFixture) requeue(expected ir.Status, mutateErr error) error {
	_, _, err := f.repo.CompareAndSwapLatestAttemptStatus(f.ctx, ir.NewDAGRunRef(f.dag.Name, f.runID), f.attempt, expected,
		func(s *ir.DAGRunStatus) error {
			if mutateErr != nil {
				return mutateErr
			}
			s.Status = ir.Queued
			return nil
		}, persis.DAGRunCompareAndSwapOptions{RetainBeforeSwap: true})
	return err
}

func (f *retentionFixture) file(ref, name string) string {
	f.t.Helper()
	b, err := f.repo.ReadRetainedExecutionFile(f.ctx, ir.NewDAGRunRef(f.dag.Name, f.runID), ref, name)
	require.NoError(f.t, err)
	return string(b)
}

// A queued retry replaces the execution in place; each finished execution is
// copied first, with its whole status and its own logs, and an earlier copy
// is never changed by a later execution.
func TestRetainExecutionsBeforeQueuedRetry(t *testing.T) {
	f := newRetentionFixture(t)
	q1, q2 := "2026-10-09T12:00:00.000000001Z", "2026-10-09T12:00:01.000000001Z"
	e1 := f.execution(q1, ir.Failed, "execution 1")
	require.NoError(t, f.requeue(ir.Failed, nil))
	ref1 := ir.ExecutionRef(f.attempt, q1)
	first := f.file(ref1, "run.stdout.log")
	assert.Equal(t, "stdout execution 1\n", first)

	// The retry runs the same attempt under q2, overwriting status and logs.
	f.execution(q2, ir.Failed, "execution 2")
	require.NoError(t, f.requeue(ir.Failed, nil))
	ref2 := ir.ExecutionRef(f.attempt, q2)

	all, err := f.repo.ListRetainedExecutions(f.ctx, ir.NewDAGRunRef(f.dag.Name, f.runID))
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, []string{ref1, ref2}, []string{all[0].Execution, all[1].Execution})
	assert.True(t, all[0].StatusComplete)
	assert.False(t, all[0].LogsFinal, "logs are not claimed final until streams are fenced")
	assert.NotEmpty(t, all[0].LogsNote)

	assert.Equal(t, first, f.file(ref1, "run.stdout.log"), "the first copy is unchanged")
	assert.Equal(t, "scheduler execution 1\n", f.file(ref1, "scheduler.log"))
	assert.Equal(t, "stdout execution 2\n", f.file(ref2, "run.stdout.log"))
	assert.Contains(t, f.file(ref1, "status.json"), `"`+e1.Error+`"`, "the whole status of execution 1")
	assert.Contains(t, f.file(ref2, "status.json"), "execution 2")
}

// The first intact copy of an execution is its evidence: copying the same
// execution again keeps it even if the live files changed since (a late
// stream, a rolled-back admission), while a copy that was altered or is
// incomplete fails visibly and refuses the swap.
func TestRetainedExecutionIsImmutable(t *testing.T) {
	f := newRetentionFixture(t)
	f.execution("q1", ir.Failed, "execution 1")
	require.NoError(t, f.requeue(ir.Failed, nil))
	ref := ir.ExecutionRef(f.attempt, "q1")
	first := f.file(ref, "run.stdout.log")

	// The same execution is put back (an admission rolled back) and a late
	// chunk changes the live log.
	f.execution("q1", ir.Failed, "execution 1")
	logs := filepath.Join(f.logDir, f.dag.Name, f.runID, f.attempt)
	require.NoError(t, os.WriteFile(filepath.Join(logs, "run.stdout.log"), []byte("stdout execution 1\nlate\n"), 0o600))
	require.NoError(t, f.requeue(ir.Failed, nil), "a later retry of the same execution is not blocked")
	assert.Equal(t, first, f.file(ref, "run.stdout.log"), "the first copy stands")

	// An altered copy fails visibly.
	f.execution("q1", ir.Failed, "execution 1")
	all, err := f.repo.ListRetainedExecutions(f.ctx, ir.NewDAGRunRef(f.dag.Name, f.runID))
	require.NoError(t, err)
	require.Len(t, all, 1)
	copyDir := retainedCopyDir(t, f, ref)
	require.NoError(t, os.WriteFile(filepath.Join(copyDir, "logs", "run.stdout.log"), []byte("tampered\n"), 0o600))
	assert.ErrorIs(t, f.requeue(ir.Failed, nil), filedagrun.ErrRetainedExecutionConflict)
	got, err := f.handle.ReadStatus(f.ctx)
	require.NoError(t, err)
	assert.Equal(t, ir.Failed, got.Status, "the swap was refused")
}

// retainedCopyDir finds the directory holding the copy of ref.
func retainedCopyDir(t *testing.T, f *retentionFixture, ref string) string {
	t.Helper()
	var found string
	require.NoError(t, filepath.WalkDir(filepath.Dir(filepath.Dir(f.logDir)), func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && d.Name() == ref && filepath.Base(filepath.Dir(p)) == "executions" {
			found = p
		}
		return nil
	}))
	require.NotEmpty(t, found)
	return found
}

// Logs are copied from the configured log directory only: a symbolic link
// there, or a status path outside it, is not followed.
func TestRetainedExecutionCopiesOnlyHubLogs(t *testing.T) {
	f := newRetentionFixture(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0o600))
	logs := filepath.Join(f.logDir, f.dag.Name, f.runID, f.attempt)
	require.NoError(t, os.MkdirAll(logs, 0o750))
	require.NoError(t, os.Symlink(outside, filepath.Join(logs, "link.log")))

	attempt := f.handle
	status := ir.InitialStatus(f.dag)
	status.DAGRunID, status.AttemptID, status.Status, status.Log = f.runID, f.attempt, ir.Failed, outside
	require.NoError(t, attempt.Open(f.ctx))
	require.NoError(t, attempt.Write(f.ctx, status))
	require.NoError(t, attempt.Close(f.ctx))
	require.NoError(t, f.requeue(ir.Failed, nil))

	all, err := f.repo.ListRetainedExecutions(f.ctx, ir.NewDAGRunRef(f.dag.Name, f.runID))
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Empty(t, all[0].Files, "neither the link nor the outside path is copied")
	for _, name := range []string{"../status.json", "link.log", "secret.txt", "manifest.json"} {
		_, err := f.repo.ReadRetainedExecutionFile(f.ctx, ir.NewDAGRunRef(f.dag.Name, f.runID), all[0].Execution, name)
		assert.ErrorIs(t, err, persis.ErrNotFound, name)
	}
}

// sha256Of is the digest form the coordinator writes into .final.
func sha256Of(b string) string {
	sum := sha256.Sum256([]byte(b))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// A log is final only when the coordinator's .final record names this
// execution and the exact bytes copied (size and digest); the record itself
// is not copied as a log. A record of another execution, of other bytes of
// the same length, or without a digest proves nothing.
func TestRetainedLogsAreFinalOnlyWhenRecorded(t *testing.T) {
	f := newRetentionFixture(t)
	status := f.execution("q1", ir.Failed, "execution 1")
	logs := filepath.Join(f.logDir, f.dag.Name, f.runID, f.attempt)
	extra := map[string]string{"same-size.log": "AAAA", "no-digest.log": "CCCC", "stale.log": "DDDD"}
	for name, content := range extra {
		require.NoError(t, os.WriteFile(filepath.Join(logs, name), []byte(content), 0o600))
	}
	write := func(name, marker string, size int, digest string) {
		rec := fmt.Sprintf(`{"executionMarker":%q,"attemptId":%q,"size":%d,"sha256":%q}`, marker, status.AttemptID, size, digest)
		if digest == "" {
			rec = fmt.Sprintf(`{"executionMarker":%q,"attemptId":%q,"size":%d}`, marker, status.AttemptID, size)
		}
		require.NoError(t, os.WriteFile(filepath.Join(logs, name+".final"), []byte(rec), 0o600))
	}
	sched := "scheduler execution 1\n"
	write("scheduler.log", "q1", len(sched), sha256Of(sched))
	write("run.stdout.log", "q0", len("stdout execution 1\n"), sha256Of("stdout execution 1\n"))
	write("same-size.log", "q1", 4, sha256Of("BBBB"))
	write("no-digest.log", "q1", 4, "")
	write("stale.log", "q0", 4, sha256Of("DDDD"))
	require.NoError(t, f.requeue(ir.Failed, nil))

	all, err := f.repo.ListRetainedExecutions(f.ctx, ir.NewDAGRunRef(f.dag.Name, f.runID))
	require.NoError(t, err)
	require.Len(t, all, 1)
	final := map[string]bool{}
	for _, file := range all[0].Files {
		final[file.Name] = file.Final
	}
	assert.Equal(t, map[string]bool{"scheduler.log": true, "run.stdout.log": false, "same-size.log": false,
		"no-digest.log": false, "stale.log": false}, final)
	assert.False(t, all[0].LogsFinal, "one log not proven final keeps the execution's logs not final")
	assert.NotEmpty(t, all[0].LogsNote)
}

// The copy is fixed when it is taken: bytes or a .final record the old
// execution writes afterwards change neither the copy nor its finality.
func TestRetainedCopyIgnoresLateWrites(t *testing.T) {
	f := newRetentionFixture(t)
	status := f.execution("q1", ir.Failed, "execution 1")
	require.NoError(t, f.requeue(ir.Failed, nil))
	ref := ir.ExecutionRef(status.AttemptID, "q1")
	before := f.file(ref, "run.stdout.log")

	logs := filepath.Join(f.logDir, f.dag.Name, f.runID, f.attempt)
	late := "stdout execution 1\nlate chunk\n"
	require.NoError(t, os.WriteFile(filepath.Join(logs, "run.stdout.log"), []byte(late), 0o600))
	rec := fmt.Sprintf(`{"executionMarker":"q1","attemptId":%q,"size":%d,"sha256":%q}`, status.AttemptID, len(late), sha256Of(late))
	require.NoError(t, os.WriteFile(filepath.Join(logs, "run.stdout.log.final"), []byte(rec), 0o600))

	assert.Equal(t, before, f.file(ref, "run.stdout.log"), "the copy does not change")
	all, err := f.repo.ListRetainedExecutions(f.ctx, ir.NewDAGRunRef(f.dag.Name, f.runID))
	require.NoError(t, err)
	for _, file := range all[0].Files {
		assert.False(t, file.Final, "%s: finality is decided when the copy is taken", file.Name)
	}
}

// A swap the caller refuses (a stale retry) leaves no copy, so late bytes
// written afterwards cannot make the valid retry of that execution fail.
func TestRefusedSwapRetainsNothing(t *testing.T) {
	f := newRetentionFixture(t)
	f.execution("q1", ir.Failed, "execution 1")
	stale := errors.New("stale")
	assert.ErrorIs(t, f.requeue(ir.Failed, stale), stale)
	all, err := f.repo.ListRetainedExecutions(f.ctx, ir.NewDAGRunRef(f.dag.Name, f.runID))
	require.NoError(t, err)
	assert.Empty(t, all, "the refused swap kept nothing")

	logs := filepath.Join(f.logDir, f.dag.Name, f.runID, f.attempt)
	require.NoError(t, os.WriteFile(filepath.Join(logs, "run.stdout.log"), []byte("stdout execution 1\nlate\n"), 0o600))
	require.NoError(t, f.requeue(ir.Failed, nil), "the valid retry is not blocked by an earlier copy")
}

// A symbolic link anywhere below the attempt directory never redirects a
// copy's write or read outside it.
func TestRetainedCopiesStayInsideTheAttempt(t *testing.T) {
	f := newRetentionFixture(t)
	f.execution("q1", ir.Failed, "execution 1")
	require.NoError(t, f.requeue(ir.Failed, nil))
	ref1 := ir.ExecutionRef(f.attempt, "q1")
	copyDir := retainedCopyDir(t, f, ref1)
	execDir := filepath.Dir(copyDir)
	run := ir.NewDAGRunRef(f.dag.Name, f.runID)

	// Reading: a copy's logs directory replaced by a link to elsewhere.
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "run.stdout.log"), []byte("secret"), 0o600))
	require.NoError(t, os.RemoveAll(filepath.Join(copyDir, "logs")))
	require.NoError(t, os.Symlink(outside, filepath.Join(copyDir, "logs")))
	_, err := f.repo.ReadRetainedExecutionFile(f.ctx, run, ref1, "run.stdout.log")
	assert.ErrorIs(t, err, persis.ErrNotFound, "a linked logs directory is not read")

	// Writing: the executions directory replaced by a link to elsewhere.
	target := t.TempDir()
	require.NoError(t, os.RemoveAll(execDir))
	require.NoError(t, os.Symlink(target, execDir))
	f.execution("q2", ir.Failed, "execution 2")
	require.Error(t, f.requeue(ir.Failed, nil), "the swap is refused")
	entries, err := os.ReadDir(target)
	require.NoError(t, err)
	assert.Empty(t, entries, "nothing is written through the link")
	all, err := f.repo.ListRetainedExecutions(f.ctx, run)
	require.NoError(t, err)
	assert.Empty(t, all, "a linked executions directory is not listed")
}

// A symbolic link at any level of the log directory is not followed when
// logs are collected.
func TestRetainedLogsIgnoreLinkedDirectories(t *testing.T) {
	f := newRetentionFixture(t)
	outside := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(outside, f.attempt), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(outside, f.attempt, "secret.log"), []byte("secret"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(f.logDir, f.dag.Name), 0o750))
	require.NoError(t, os.Symlink(outside, filepath.Join(f.logDir, f.dag.Name, f.runID)))

	status := ir.InitialStatus(f.dag)
	status.DAGRunID, status.AttemptID, status.QueuedAt, status.Status = f.runID, f.attempt, "q1", ir.Failed
	status.Log = filepath.Join(f.logDir, f.dag.Name, f.runID, f.attempt, "secret.log")
	require.NoError(t, f.handle.Open(f.ctx))
	require.NoError(t, f.handle.Write(f.ctx, status))
	require.NoError(t, f.handle.Close(f.ctx))
	require.NoError(t, f.requeue(ir.Failed, nil))

	all, err := f.repo.ListRetainedExecutions(f.ctx, ir.NewDAGRunRef(f.dag.Name, f.runID))
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Empty(t, all[0].Files, "nothing behind the linked run directory is copied")
	assert.False(t, all[0].LogsFinal)
}

// writeFinal writes the coordinator's .final record for the log at p.
func writeFinal(t *testing.T, p, marker, attempt, content string) {
	t.Helper()
	rec := fmt.Sprintf(`{"executionMarker":%q,"attemptId":%q,"size":%d,"sha256":%q}`, marker, attempt, len(content), sha256Of(content))
	require.NoError(t, os.WriteFile(p+".final", []byte(rec), 0o600))
}

// The logs of an execution are final only when every stream the status says
// it produced arrived and was recorded final: a finalized stdout next to a
// stderr that never arrived is not enough. Handler logs are retained too.
func TestRetainedLogsAreFinalOnlyWhenEveryStreamArrived(t *testing.T) {
	f := newRetentionFixture(t)
	logs := filepath.Join(f.logDir, f.dag.Name, f.runID, f.attempt)
	runner := filepath.Join(f.logDir, f.dag.Name, f.runID, "20261009_120000_runner")
	require.NoError(t, os.MkdirAll(logs, 0o750))
	require.NoError(t, os.MkdirAll(runner, 0o750))

	put := func(dir, name, marker, content string, final bool) {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
		if final {
			writeFinal(t, p, marker, f.attempt, content)
		}
	}
	execution := func(marker string) {
		status := ir.InitialStatus(f.dag)
		status.DAGRunID, status.AttemptID, status.QueuedAt, status.Status = f.runID, f.attempt, marker, ir.Failed
		// The worker's own paths: the coordinator stores the streams under
		// the attempt's directory.
		status.Log = "/worker/logs/scheduler.log"
		status.Nodes = []*ir.Node{{Step: ir.Step{Name: "build"}, Status: ir.NodeFailed,
			Stdout: "/worker/logs/build.stdout.log", Stderr: "/worker/logs/build.stderr.log"}}
		// A local failure handler writes inside the log directory itself.
		status.OnFailure = &ir.Node{Step: ir.Step{Name: "onFailure"}, Status: ir.NodeSucceeded,
			Stdout: filepath.Join(runner, "onFailure.stdout.log")}
		require.NoError(t, f.handle.Open(f.ctx))
		require.NoError(t, f.handle.Write(f.ctx, status))
		require.NoError(t, f.handle.Close(f.ctx))
	}
	run := ir.NewDAGRunRef(f.dag.Name, f.runID)

	put(logs, "scheduler.log", "q1", "sched 1\n", true)
	put(logs, "build.stdout.log", "q1", "out 1\n", true)
	put(runner, "onFailure.stdout.log", "q1", "handler 1\n", true)
	execution("q1")
	require.NoError(t, f.requeue(ir.Failed, nil))
	all, err := f.repo.ListRetainedExecutions(f.ctx, run)
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "handler 1\n", f.file(all[0].Execution, "onFailure.stdout.log"), "the handler's log is retained")
	for _, file := range all[0].Files {
		assert.True(t, file.Final, file.Name)
	}
	assert.False(t, all[0].LogsFinal, "stderr never arrived")

	put(logs, "scheduler.log", "q2", "sched 2\n", true)
	put(logs, "build.stdout.log", "q2", "out 2\n", true)
	put(logs, "build.stderr.log", "q2", "err 2\n", true)
	put(runner, "onFailure.stdout.log", "q2", "handler 2\n", true)
	execution("q2")
	require.NoError(t, f.requeue(ir.Failed, nil))
	all, err = f.repo.ListRetainedExecutions(f.ctx, run)
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.True(t, all[1].LogsFinal, "every stream arrived and was recorded final")
	assert.Empty(t, all[1].LogsNote)
}

// A retained execution with no logs lists its files as an empty array.
func TestRetainedExecutionWithoutLogsListsNoFiles(t *testing.T) {
	f := newRetentionFixture(t)
	status := ir.InitialStatus(f.dag)
	status.DAGRunID, status.AttemptID, status.QueuedAt, status.Status = f.runID, f.attempt, "q1", ir.Failed
	require.NoError(t, f.handle.Open(f.ctx))
	require.NoError(t, f.handle.Write(f.ctx, status))
	require.NoError(t, f.handle.Close(f.ctx))
	require.NoError(t, f.requeue(ir.Failed, nil))
	all, err := f.repo.ListRetainedExecutions(f.ctx, ir.NewDAGRunRef(f.dag.Name, f.runID))
	require.NoError(t, err)
	require.Len(t, all, 1)
	data, err := json.Marshal(all[0])
	require.NoError(t, err)
	assert.Contains(t, string(data), `"files":[]`)
}
