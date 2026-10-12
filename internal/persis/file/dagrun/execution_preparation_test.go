// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	execQ1 = "2026-10-12T07:00:01.000000001Z"
	execQ2 = "2026-10-12T07:00:02.000000001Z"
	execQ3 = "2026-10-12T07:00:03.000000001Z"
)

// writeExecution writes the attempt's current execution.
func writeExecution(t *testing.T, th RepositoryTest, dag *ir.DAG, att *Attempt, st ir.Status, queuedAt, worker string, request *ir.RetryRequest) {
	t.Helper()
	status := ir.InitialStatus(dag)
	status.DAGRunID, status.AttemptID = abandonRunID, att.ID()
	status.Status, status.QueuedAt, status.WorkerID = st, queuedAt, worker
	status.RetryRequest = request
	require.NoError(t, att.Open(th.Context))
	require.NoError(t, att.Write(th.Context, status))
	require.NoError(t, att.Close(th.Context))
}

func executionRecord(dag *ir.DAG, attemptID, queuedAt string) persis.AttemptAbandonment {
	record := abandonRecord(dag, attemptID, nil)
	record.Scope = persis.AbandonmentScopeExecution
	record.AbandonedExecution = persis.ExecutionIdentity{AttemptID: attemptID, QueuedAt: queuedAt}
	record.Detail = "not dispatched: no worker claimed the task before it expired"
	return record
}

func runRef(dag *ir.DAG) ir.DAGRunRef { return ir.NewDAGRunRef(dag.Name, abandonRunID) }

// A reused attempt's execution is journaled under its queued-at marker, only
// while it is the run's latest, queued and not handed to a worker; each
// execution of the attempt has its own entry.
func TestBeginAttemptPreparationJournalsAQueuedExecution(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("exec_prep_dag").DAG
	att := createRunAttempt(t, th, dag, false, ir.Queued, execQ1, "")
	run := runRef(dag)

	for name, marker := range map[string]string{"no marker": "", "another marker": execQ2} {
		_, err := th.Repository.BeginAttemptPreparation(th.Context, run, ir.DAGRunRef{}, att.ID(), marker)
		require.ErrorIs(t, err, persis.ErrAttemptNotAbandonable, name)
	}
	entry, err := th.Repository.BeginAttemptPreparation(th.Context, run, ir.DAGRunRef{}, att.ID(), execQ1)
	require.NoError(t, err)
	assert.Equal(t, execQ1, entry.QueuedAt)
	assert.Equal(t, run, entry.RootRun)
	again, err := th.Repository.BeginAttemptPreparation(th.Context, run, ir.DAGRunRef{}, att.ID(), execQ1)
	require.NoError(t, err)
	assert.Equal(t, entry, again, "beginning it again returns the entry")

	prepared, err := th.Backend.AttemptPrepared(th.Context, run, run, att.ID())
	require.NoError(t, err)
	assert.True(t, prepared, "an execution's entry makes the attempt prepared")
	list, err := th.Backend.ListAttemptPreparations(th.Context)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, entry, list[0])

	// The execution is re-queued under another marker: its own entry.
	writeExecution(t, th, dag, att, ir.Queued, execQ2, "", nil)
	second, err := th.Repository.BeginAttemptPreparation(th.Context, run, ir.DAGRunRef{}, att.ID(), execQ2)
	require.NoError(t, err)
	assert.NotEqual(t, th.Backend.preparationPath(entry), th.Backend.preparationPath(second))
	list, err = th.Backend.ListAttemptPreparations(th.Context)
	require.NoError(t, err)
	assert.Len(t, list, 2)

	require.NoError(t, th.Backend.EndAttemptPreparation(th.Context, second))
	list, err = th.Backend.ListAttemptPreparations(th.Context)
	require.NoError(t, err)
	require.Len(t, list, 1, "ending one execution's entry leaves the other")
	assert.Equal(t, execQ1, list[0].QueuedAt)

	// Handed to a worker, or no longer the latest: not journaled.
	writeExecution(t, th, dag, att, ir.Queued, execQ3, "worker-1", nil)
	_, err = th.Repository.BeginAttemptPreparation(th.Context, run, ir.DAGRunRef{}, att.ID(), execQ3)
	require.ErrorIs(t, err, persis.ErrAttemptNotAbandonable, "a worker has it")
	writeExecution(t, th, dag, att, ir.Running, execQ3, "", nil)
	_, err = th.Repository.BeginAttemptPreparation(th.Context, run, ir.DAGRunRef{}, att.ID(), execQ3)
	require.ErrorIs(t, err, persis.ErrAttemptNotAbandonable, "it started")
	createRunAttempt(t, th, dag, true, ir.Queued, execQ3, "")
	_, err = th.Repository.BeginAttemptPreparation(th.Context, run, ir.DAGRunRef{}, att.ID(), execQ3)
	require.ErrorIs(t, err, persis.ErrAttemptNotAbandonable, "not the latest")
}

// An execution's entry is settled once the attempt moved on: another
// execution, a worker, or a newer attempt that is no preparation itself.
func TestEndSettledExecutionPreparation(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("exec_settle_dag").DAG
	att := createRunAttempt(t, th, dag, false, ir.Queued, execQ1, "")
	run := runRef(dag)
	entry, err := th.Repository.BeginAttemptPreparation(th.Context, run, ir.DAGRunRef{}, att.ID(), execQ1)
	require.NoError(t, err)

	settle := func() bool {
		t.Helper()
		ended, err := th.Repository.EndSettledAttemptPreparation(th.Context, entry)
		require.NoError(t, err)
		return ended
	}
	assert.False(t, settle(), "still queued under its marker, not handed to a worker")
	writeExecution(t, th, dag, att, ir.NotStarted, execQ1, "", nil)
	assert.False(t, settle(), "not started is still awaiting dispatch")
	writeExecution(t, th, dag, att, ir.Running, execQ1, "worker-1", nil)
	assert.True(t, settle(), "the execution was handed to a worker")

	writeExecution(t, th, dag, att, ir.Queued, execQ2, "", nil)
	entry, err = th.Repository.BeginAttemptPreparation(th.Context, run, ir.DAGRunRef{}, att.ID(), execQ2)
	require.NoError(t, err)
	writeExecution(t, th, dag, att, ir.Queued, execQ3, "", nil)
	assert.True(t, settle(), "the attempt carries another execution")

	entry, err = th.Repository.BeginAttemptPreparation(th.Context, run, ir.DAGRunRef{}, att.ID(), execQ3)
	require.NoError(t, err)
	newer, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
		DAG: dag, Timestamp: time.Now(), DAGRunID: abandonRunID, Retry: true, TrackPreparation: true,
	})
	require.NoError(t, err)
	newerAtt, ok := newer.(*Attempt)
	require.True(t, ok)
	writeExecution(t, th, dag, newerAtt, ir.NotStarted, "", "", nil)
	assert.False(t, settle(), "a newer preparation may be abandoned, making this execution the latest again")
	require.NoError(t, th.Backend.EndAttemptPreparation(th.Context, persis.AttemptPreparation{Run: run, RootRun: run, AttemptID: newer.ID()}))
	assert.True(t, settle(), "a newer attempt that is no preparation replaced it")
}

// Abandoning one execution of a reused attempt marks that execution Failed
// and records it under its own name; nothing is hidden, so the attempt and
// earlier records stay, and a later execution is abandoned separately.
func TestAbandonExecutionMarksOnlyThatExecutionFailed(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("exec_abandon_dag").DAG
	createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	att := createRunAttempt(t, th, dag, true, ir.Queued, execQ1, "")
	run := runRef(dag)

	record := executionRecord(dag, att.ID(), execQ2)
	_, err := abandon(th, record)
	require.ErrorIs(t, err, persis.ErrAttemptNotAbandonable, "another execution than the attempt's current one")

	record = executionRecord(dag, att.ID(), execQ1)
	got, err := abandon(th, record)
	require.NoError(t, err)
	assert.Equal(t, persis.AbandonmentScopeExecution, got.Scope)
	assert.Equal(t, persis.AbandonmentMarkedFailed, got.Outcome)
	assert.Nil(t, got.ExpectedExecution)
	assert.False(t, got.PredecessorAbsent, "the run had an earlier attempt")
	assert.Equal(t, persis.ExecutionIdentity{AttemptID: att.ID(), QueuedAt: execQ1}, got.AbandonedExecution)

	require.Equal(t, att.ID(), latestAttemptID(t, th, dag), "nothing is hidden")
	status, err := att.ReadStatusUncached(th.Context)
	require.NoError(t, err)
	assert.Equal(t, ir.Failed, status.Status)
	assert.Equal(t, execQ1, status.QueuedAt)
	assert.Equal(t, record.Detail, status.Error)

	again, err := abandon(th, record)
	require.NoError(t, err, "completing the same abandonment again")
	assert.Equal(t, got.DecidedAt, again.DecidedAt)

	own, err := th.Repository.ReadAttemptAbandonment(th.Context, run, ir.DAGRunRef{}, att.ID())
	require.NoError(t, err)
	assert.Nil(t, own, "the attempt itself was not abandoned")
	covering, err := th.Repository.ReadExecutionAbandonment(th.Context, run, ir.DAGRunRef{}, att.ID(), execQ1)
	require.NoError(t, err)
	require.NotNil(t, covering)
	assert.Equal(t, execQ1, covering.AbandonedExecution.QueuedAt)
	other, err := th.Repository.ReadExecutionAbandonment(th.Context, run, ir.DAGRunRef{}, att.ID(), execQ2)
	require.NoError(t, err)
	assert.Nil(t, other, "a later execution is not covered")

	// Re-queued and left unclaimed again: a second, separate record.
	writeExecution(t, th, dag, att, ir.Queued, execQ2, "", nil)
	_, err = abandon(th, executionRecord(dag, att.ID(), execQ2))
	require.NoError(t, err)
	results, err := th.Repository.ListAttemptAbandonmentsStrict(th.Context, run, ir.DAGRunRef{})
	require.NoError(t, err)
	require.Len(t, results, 2)
	markers := map[string]bool{}
	for _, r := range results {
		require.NoError(t, r.Err)
		markers[r.Record.AbandonedExecution.QueuedAt] = true
	}
	assert.Equal(t, map[string]bool{execQ1: true, execQ2: true}, markers)
	records, err := th.Repository.ListAttemptAbandonments(th.Context, run, ir.DAGRunRef{})
	require.NoError(t, err)
	assert.Len(t, records, 2)

	writeExecution(t, th, dag, att, ir.Running, execQ3, "worker-1", nil)
	_, err = abandon(th, executionRecord(dag, att.ID(), execQ3))
	require.ErrorIs(t, err, persis.ErrAttemptNotAbandonable, "it was handed to a worker")

	// Queued again, but a newer attempt is the run's latest now.
	writeExecution(t, th, dag, att, ir.Queued, execQ3, "", nil)
	createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")
	_, err = abandon(th, executionRecord(dag, att.ID(), execQ3))
	require.ErrorIs(t, err, persis.ErrAttemptNotAbandonable, "not the run's latest attempt")
}

// A run's only, queued execution abandoned had no predecessor.
func TestAbandonExecutionOfAQueuedFirstRun(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("exec_first_dag").DAG
	att := createRunAttempt(t, th, dag, false, ir.Queued, execQ1, "")
	got, err := abandon(th, executionRecord(dag, att.ID(), execQ1))
	require.NoError(t, err)
	assert.True(t, got.PredecessorAbsent)
	assert.Equal(t, persis.AbandonmentMarkedFailed, got.Outcome)
}

// A record that does not name its execution consistently is refused.
func TestAbandonExecutionRefusesAnIncompleteRecord(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("exec_bad_dag").DAG
	att := createRunAttempt(t, th, dag, false, ir.Queued, execQ1, "")
	record := executionRecord(dag, att.ID(), "")
	_, err := abandon(th, record)
	require.ErrorIs(t, err, persis.ErrAttemptNotAbandonable, "no marker")
	record = executionRecord(dag, att.ID(), execQ1)
	record.Scope = "attempts"
	_, err = abandon(th, record)
	require.ErrorIs(t, err, persis.ErrAttemptNotAbandonable, "unknown scope")
}

// The retry-requests lookup reports an execution abandoned under its own
// record, as the attempt's current execution and, after another queued retry
// replaced it, as a retained copy.
func TestFindRetryRequestSeesAnAbandonedExecution(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("exec_lookup_dag").DAG
	att := createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	request := &ir.RetryRequest{ID: "req-1", ActionID: "act-1", ActionAttempt: "1", BindingDigest: "d"}
	writeExecution(t, th, dag, att, ir.Queued, execQ1, "", request)
	run := runRef(dag)

	match, err := th.Backend.FindRetryRequest(th.Context, run, run, "req-1")
	require.NoError(t, err)
	assert.Equal(t, persis.RetryRequestAdmitted, match.State)

	_, err = abandon(th, executionRecord(dag, att.ID(), execQ1))
	require.NoError(t, err)
	match, err = th.Backend.FindRetryRequest(th.Context, run, run, "req-1")
	require.NoError(t, err)
	assert.Equal(t, persis.RetryRequestAbandoned, match.State)
	require.NotNil(t, match.Abandonment)
	assert.Equal(t, execQ1, match.Abandonment.AbandonedExecution.QueuedAt)

	// Another queued retry replaces it; the retained copy is still abandoned.
	_, _, err = th.Repository.CompareAndSwapLatestAttemptStatus(th.Context, run, att.ID(), ir.Failed,
		func(s *ir.DAGRunStatus) error {
			s.Status, s.QueuedAt = ir.Queued, execQ2
			s.RetryRequest = &ir.RetryRequest{ID: "req-2", ActionID: "act-1", ActionAttempt: "2", BindingDigest: "d"}
			return nil
		}, persis.DAGRunCompareAndSwapOptions{RetainBeforeSwap: true})
	require.NoError(t, err)
	match, err = th.Backend.FindRetryRequest(th.Context, run, run, "req-1")
	require.NoError(t, err)
	assert.True(t, match.Retained)
	assert.Equal(t, persis.RetryRequestAbandoned, match.State)
	match, err = th.Backend.FindRetryRequest(th.Context, run, run, "req-2")
	require.NoError(t, err)
	assert.Equal(t, persis.RetryRequestAdmitted, match.State, "the new execution is not covered")
}

// A crash after an execution's record and before its status was marked: the
// next call completes it from the record; if the execution moved on in the
// meantime, the record authorizes nothing and the call is a conflict.
func TestAbandonExecutionCompletesAfterACrash(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("exec_crash_dag").DAG
	att := createRunAttempt(t, th, dag, false, ir.Queued, execQ1, "")
	record := executionRecord(dag, att.ID(), execQ1)
	record.Outcome, record.PredecessorAbsent = persis.AbandonmentMarkedFailed, true
	require.NoError(t, writeRecordExclusive(executionRecordPath(att.file, execQ1), record))

	got, err := abandon(th, executionRecord(dag, att.ID(), execQ1))
	require.NoError(t, err)
	assert.Equal(t, record.DecidedAt, got.DecidedAt, "the record already on disk stands")
	status, err := att.ReadStatusUncached(th.Context)
	require.NoError(t, err)
	assert.Equal(t, ir.Failed, status.Status)

	moved := createRunAttempt(t, th, dag, true, ir.Queued, execQ2, "")
	require.NoError(t, writeRecordExclusive(executionRecordPath(moved.file, execQ2), func() persis.AttemptAbandonment {
		r := executionRecord(dag, moved.ID(), execQ2)
		r.Outcome = persis.AbandonmentMarkedFailed
		return r
	}()))
	writeExecution(t, th, dag, moved, ir.Running, execQ2, "worker-1", nil)
	_, err = abandon(th, executionRecord(dag, moved.ID(), execQ2))
	require.ErrorIs(t, err, persis.ErrAttemptAbandonmentConflict, "the execution was handed to a worker after the record")
}

// An entry written for one execution is not read as an attempt's entry by
// the listing of a build that keys entries by attempt only: its file name
// does not match, so such a build skips it instead of acting on it.
func TestExecutionPreparationNameDiffersFromTheAttempts(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	run := ir.NewDAGRunRef("d", "r")
	attempt := persis.AttemptPreparation{Run: run, RootRun: run, AttemptID: "a1"}
	execution := attempt
	execution.QueuedAt = execQ1
	assert.NotEqual(t, th.Backend.preparationPath(attempt), th.Backend.preparationPath(execution))
}

// A status writer cannot land between an execution abandonment's check and
// its record and Failed status: it waits for the status file's lock, so its
// write follows the abandonment's.
func TestAbandonExecutionHoldsTheStatusLock(t *testing.T) {
	th := setupTestRepository(t)
	dag := th.DAG("exec_lock_dag").DAG
	att := createRunAttempt(t, th, dag, false, ir.Queued, execQ1, "")
	writer, err := th.Repository.FindAttempt(th.Context, runRef(dag))
	require.NoError(t, err)

	done := make(chan error, 1)
	executionAbandonCheckedHook = func(string) {
		go func() {
			status := ir.InitialStatus(dag)
			status.DAGRunID, status.AttemptID, status.Status = abandonRunID, att.ID(), ir.Running
			status.QueuedAt, status.WorkerID = execQ1, "worker-1"
			if err := writer.Open(th.Context); err != nil {
				done <- err
				return
			}
			err := writer.Write(th.Context, status)
			_ = writer.Close(th.Context)
			done <- err
		}()
		select {
		case err := <-done:
			t.Errorf("a status write landed inside the abandonment: %v", err)
			done <- err
		case <-time.After(300 * time.Millisecond):
		}
	}
	t.Cleanup(func() { executionAbandonCheckedHook = nil })

	_, err = abandon(th, executionRecord(dag, att.ID(), execQ1))
	require.NoError(t, err)
	executionAbandonCheckedHook = nil
	require.NoError(t, <-done)
	records, err := th.Repository.ListAttemptAbandonments(th.Context, runRef(dag), ir.DAGRunRef{})
	require.NoError(t, err)
	require.Len(t, records, 1, "the abandonment was recorded before the late write")
}

// Records and entries are found by listing the literal directory: a path
// with pattern characters still finds them, and a directory that cannot be
// listed is an error rather than no records.
func TestExecutionRecordsAndEntriesUseLiteralPaths(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "[prod]*?")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	status := filepath.Join(dir, "status.jsonl")
	record := executionRecordPath(status, execQ1)
	require.NoError(t, os.WriteFile(record, []byte("{}"), 0o600))
	paths, err := executionRecordPaths(status)
	require.NoError(t, err)
	assert.Equal(t, []string{record}, paths)

	th := setupTestRepository(t)
	th.Backend.preparationDir = filepath.Join(t.TempDir(), "[journal]*")
	run := ir.NewDAGRunRef("d", "r")
	entry, err := th.Backend.writePreparation(run, run, "a1", execQ1)
	require.NoError(t, err)
	prepared, err := th.Backend.AttemptPrepared(th.Context, run, run, "a1")
	require.NoError(t, err)
	assert.True(t, prepared)
	assert.Equal(t, execQ1, entry.QueuedAt)

	if os.Getuid() != 0 {
		require.NoError(t, os.Chmod(dir, 0o000))
		t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })
		_, err = executionRecordPaths(status)
		require.Error(t, err, "an unreadable attempt directory is not an empty one")
	}
}

// The lookup trusts an execution record only when it is complete and names
// this run; one that is malformed, or a dangling link at its name, is an
// error for the current execution and for a retained copy alike.
func TestFindRetryRequestRefusesAnUntrustedExecutionRecord(t *testing.T) {
	t.Parallel()
	for name, corrupt := range map[string]func(t *testing.T, path string){
		"no evidence": func(t *testing.T, path string) {
			var r persis.AttemptAbandonment
			data, err := os.ReadFile(path) //nolint:gosec // test file
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(data, &r))
			r.Evidence = persis.AbandonmentEvidence{}
			data, err = json.Marshal(r)
			require.NoError(t, err)
			require.NoError(t, os.Remove(path))
			require.NoError(t, os.WriteFile(path, data, 0o600))
		},
		"dangling link": func(t *testing.T, path string) {
			require.NoError(t, os.Remove(path))
			require.NoError(t, os.Symlink(path+".missing", path))
		},
	} {
		t.Run(name, func(t *testing.T) {
			th := setupTestRepository(t)
			dag := th.DAG("exec_trust_dag").DAG
			att := createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
			writeExecution(t, th, dag, att, ir.Queued, execQ1, "", &ir.RetryRequest{ID: "req-1", ActionID: "a", ActionAttempt: "1", BindingDigest: "d"})
			run := runRef(dag)
			_, err := abandon(th, executionRecord(dag, att.ID(), execQ1))
			require.NoError(t, err)
			corrupt(t, executionRecordPath(att.file, execQ1))
			_, err = th.Backend.FindRetryRequest(th.Context, run, run, "req-1")
			require.Error(t, err, "current execution")

			_, _, err = th.Repository.CompareAndSwapLatestAttemptStatus(th.Context, run, att.ID(), ir.Failed,
				func(s *ir.DAGRunStatus) error {
					s.Status, s.QueuedAt, s.RetryRequest = ir.Queued, execQ2, nil
					return nil
				}, persis.DAGRunCompareAndSwapOptions{RetainBeforeSwap: true})
			require.NoError(t, err)
			_, err = th.Backend.FindRetryRequest(th.Context, run, run, "req-1")
			require.Error(t, err, "retained execution")
		})
	}
}
