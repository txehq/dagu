// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"context"
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

const abandonRunID = "abandon-run"

// createRunAttempt creates an attempt of the run with the given status and
// worker; retry adds an attempt to an existing run.
func createRunAttempt(t *testing.T, th RepositoryTest, dag *ir.DAG, retry bool, st ir.Status, queuedAt, worker string) *Attempt {
	t.Helper()
	attempt, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
		DAG: dag, Timestamp: time.Now(), DAGRunID: abandonRunID, Retry: retry,
	})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(th.Context))
	status := ir.InitialStatus(dag)
	status.DAGRunID = abandonRunID
	status.AttemptID = attempt.ID()
	status.Status = st
	status.QueuedAt = queuedAt
	status.WorkerID = worker
	require.NoError(t, attempt.Write(th.Context, status))
	require.NoError(t, attempt.Close(th.Context))
	concrete, ok := attempt.(*Attempt)
	require.True(t, ok)
	return concrete
}

func abandonRecord(dag *ir.DAG, attemptID string, expected *persis.ExecutionIdentity) persis.AttemptAbandonment {
	ref := ir.NewDAGRunRef(dag.Name, abandonRunID)
	return persis.AttemptAbandonment{
		Schema:             persis.AttemptAbandonmentSchema,
		Run:                ref,
		RootRun:            ref,
		AbandonedAttemptID: attemptID,
		AbandonedExecution: persis.ExecutionIdentity{AttemptID: attemptID},
		ExpectedExecution:  expected,
		Reason:             persis.AbandonedRetryPreparation,
		DecidedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		Evidence: persis.AbandonmentEvidence{
			DispatchTask: persis.EvidenceAbsent, Lease: persis.EvidenceAbsent,
			ActiveRun: persis.EvidenceAbsent, Worker: persis.EvidenceAbsent,
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		},
	}
}

func abandon(th RepositoryTest, record persis.AttemptAbandonment) (*persis.AttemptAbandonment, error) {
	return th.Repository.AbandonAttempt(th.Context, persis.AbandonAttemptRequest{DAGRun: record.Run, Record: record})
}

func latestAttemptID(t *testing.T, th RepositoryTest, dag *ir.DAG) string {
	t.Helper()
	latest, err := th.Repository.FindAttempt(th.Context, ir.NewDAGRunRef(dag.Name, abandonRunID))
	require.NoError(t, err)
	return latest.ID()
}

// A retry's placeholder that was never dispatched is recorded, then hidden:
// the previous execution is the latest again, and the record stays readable.
func TestAbandonAttemptRecordsThenHides(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	previous := createRunAttempt(t, th, dag, false, ir.Failed, "2026-10-10T01:00:00Z", "worker-1")
	placeholder := createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")
	require.Equal(t, placeholder.ID(), latestAttemptID(t, th, dag))

	expected := &persis.ExecutionIdentity{AttemptID: previous.ID(), QueuedAt: "2026-10-10T01:00:00Z"}
	got, err := abandon(th, abandonRecord(dag, placeholder.ID(), expected))
	require.NoError(t, err)
	assert.Equal(t, placeholder.ID(), got.AbandonedAttemptID)
	assert.Equal(t, persis.AbandonmentHidden, got.Outcome)
	assert.False(t, got.PredecessorAbsent)
	assert.Equal(t, previous.ID(), latestAttemptID(t, th, dag), "the previous execution is the latest again")

	records, err := th.Repository.ListAttemptAbandonments(th.Context, ir.NewDAGRunRef(dag.Name, abandonRunID), ir.DAGRunRef{})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, placeholder.ID(), records[0].AbandonedAttemptID)
	assert.Equal(t, expected, records[0].ExpectedExecution)
	assert.False(t, records[0].Attributable(), "no correlation, so not attributable")

	// The preparation's own status is kept, in the hidden directory: nothing
	// is deleted.
	_, err = os.Stat(placeholder.file)
	require.True(t, os.IsNotExist(err), "the attempt directory has moved")
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(filepath.Dir(placeholder.file)), ".*", JSONLStatusFile))
	require.NoError(t, err)
	assert.Len(t, matches, 1, "the hidden attempt keeps its status file")

	// Running it again is a no-op that returns the same record.
	again, err := abandon(th, abandonRecord(dag, placeholder.ID(), expected))
	require.NoError(t, err)
	assert.Equal(t, got.DecidedAt, again.DecidedAt)
}

// The record stays discoverable after later retries of the same run.
func TestAbandonAttemptRecordSurvivesLaterRetries(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	placeholder := createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")
	_, err := abandon(th, abandonRecord(dag, placeholder.ID(), nil))
	require.NoError(t, err)

	later := createRunAttempt(t, th, dag, true, ir.Succeeded, "", "worker-1")
	require.Equal(t, later.ID(), latestAttemptID(t, th, dag))
	records, err := th.Repository.ListAttemptAbandonments(th.Context, ir.NewDAGRunRef(dag.Name, abandonRunID), ir.DAGRunRef{})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, placeholder.ID(), records[0].AbandonedAttemptID)
}

// Anything that is not a never-dispatched latest attempt is refused and left
// untouched.
func TestAbandonAttemptRefuses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		status   ir.Status
		worker   string
		notLast  bool
		evidence func(*persis.AbandonmentEvidence)
	}{
		{name: "started", status: ir.Running},
		{name: "has a worker", status: ir.NotStarted, worker: "worker-1"},
		{name: "not the latest", status: ir.NotStarted, notLast: true},
		{name: "a lookup did not find absence", status: ir.NotStarted, evidence: func(e *persis.AbandonmentEvidence) { e.Lease = "unknown" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			th := setupTestRepository(t)
			dag := th.DAG("abandon_dag").DAG
			createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
			target := createRunAttempt(t, th, dag, true, tc.status, "", tc.worker)
			if tc.notLast {
				createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")
			}
			record := abandonRecord(dag, target.ID(), nil)
			if tc.evidence != nil {
				tc.evidence(&record.Evidence)
			}
			before := latestAttemptID(t, th, dag)

			_, err := abandon(th, record)
			require.ErrorIs(t, err, persis.ErrAttemptNotAbandonable)
			assert.Equal(t, before, latestAttemptID(t, th, dag), "nothing is hidden")
			_, statErr := os.Stat(filepath.Join(filepath.Dir(target.file), AbandonmentRecordFile))
			assert.True(t, os.IsNotExist(statErr), "no record is written")
		})
	}
}

// A crash between the record and the hide is completed by the next call, but
// only when the record on disk is intact and is this abandonment's.
func TestAbandonAttemptCompletesOnlyMatchingRecord(t *testing.T) {
	t.Parallel()

	t.Run("matching record completes the hide", func(t *testing.T) {
		t.Parallel()
		th := setupTestRepository(t)
		dag := th.DAG("abandon_dag").DAG
		previous := createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
		placeholder := createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")
		record := abandonRecord(dag, placeholder.ID(), &persis.ExecutionIdentity{AttemptID: previous.ID()})
		record.Outcome = persis.AbandonmentHidden
		require.NoError(t, writeRecordExclusive(filepath.Join(filepath.Dir(placeholder.file), AbandonmentRecordFile), record))

		got, err := abandon(th, abandonRecord(dag, placeholder.ID(), nil))
		require.NoError(t, err)
		assert.Equal(t, record.DecidedAt, got.DecidedAt, "the record on disk is kept, not rewritten")
		assert.Equal(t, previous.ID(), latestAttemptID(t, th, dag))
	})

	for name, content := range map[string]string{
		"corrupt record":      "{not json",
		"another run":         `{"schema":1,"run":{"name":"abandon_dag","id":"other"},"rootRun":{"name":"abandon_dag","id":"other"},"abandonedAttemptId":"x","reason":"retry_preparation_abandoned","decidedAt":"t","evidence":{"dispatchTask":"absent","lease":"absent","activeRun":"absent","worker":"absent","observedAt":"t"}}`,
		"incomplete evidence": "",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			th := setupTestRepository(t)
			dag := th.DAG("abandon_dag").DAG
			createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
			placeholder := createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")
			path := filepath.Join(filepath.Dir(placeholder.file), AbandonmentRecordFile)
			if content == "" {
				bad := abandonRecord(dag, placeholder.ID(), &persis.ExecutionIdentity{AttemptID: "x"})
				bad.Outcome = persis.AbandonmentHidden
				bad.Evidence.DispatchTask = "unknown"
				require.NoError(t, writeRecordExclusive(path, bad))
			} else {
				require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
			}

			_, err := abandon(th, abandonRecord(dag, placeholder.ID(), nil))
			require.ErrorIs(t, err, persis.ErrAttemptAbandonmentConflict)
			assert.Equal(t, placeholder.ID(), latestAttemptID(t, th, dag), "a conflicting record never authorizes a hide")
		})
	}
}

// Without the capability, the repository refuses rather than guessing.
func TestAbandonAttemptUnsupportedStore(t *testing.T) {
	t.Parallel()
	repository := persis.NewDAGRunRepository(nil, nil, persis.DAGRunRepositoryOptions{})
	_, err := repository.AbandonAttempt(context.Background(), persis.AbandonAttemptRequest{})
	require.ErrorIs(t, err, persis.ErrAttemptAbandonmentUnsupported)
	_, err = repository.ListAttemptAbandonmentsStrict(context.Background(), ir.NewDAGRunRef("d", "r"), ir.DAGRunRef{})
	require.ErrorIs(t, err, persis.ErrAttemptAbandonmentUnsupported)
}

// A run's only execution has nothing to fall back to: it stays visible,
// marked Failed with the not-dispatched reason, and the record says so with
// the predecessor explicitly absent. A later successful retry keeps the
// record discoverable.
func TestAbandonAttemptFirstAttemptStaysVisibleFailed(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	only := createRunAttempt(t, th, dag, false, ir.NotStarted, "", "")
	record := abandonRecord(dag, only.ID(), nil)
	record.Detail = "not dispatched: handing the task to a worker failed"

	got, err := abandon(th, record)
	require.NoError(t, err)
	assert.Equal(t, persis.AbandonmentMarkedFailed, got.Outcome)
	assert.True(t, got.PredecessorAbsent)
	assert.Nil(t, got.ExpectedExecution)

	require.Equal(t, only.ID(), latestAttemptID(t, th, dag), "the run stays visible")
	latest, err := th.Repository.FindAttempt(th.Context, ir.NewDAGRunRef(dag.Name, abandonRunID))
	require.NoError(t, err)
	status, err := latest.ReadStatus(th.Context)
	require.NoError(t, err)
	assert.Equal(t, ir.Failed, status.Status)
	assert.Equal(t, record.Detail, status.Error)

	later := createRunAttempt(t, th, dag, true, ir.Succeeded, "", "worker-1")
	require.Equal(t, later.ID(), latestAttemptID(t, th, dag))
	records, err := th.Repository.ListAttemptAbandonments(th.Context, ir.NewDAGRunRef(dag.Name, abandonRunID), ir.DAGRunRef{})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, persis.AbandonmentMarkedFailed, records[0].Outcome)
	assert.Equal(t, only.ID(), records[0].AbandonedAttemptID)
}

// A crash after the first attempt's record and before its status: the next
// call marks it Failed from the record.
func TestAbandonAttemptFirstAttemptCompletesStatusFromRecord(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	only := createRunAttempt(t, th, dag, false, ir.NotStarted, "", "")
	stored := abandonRecord(dag, only.ID(), nil)
	stored.Outcome = persis.AbandonmentMarkedFailed
	stored.PredecessorAbsent = true
	stored.Detail = "not dispatched: coordinator stopped"
	require.NoError(t, writeRecordExclusive(filepath.Join(filepath.Dir(only.file), AbandonmentRecordFile), stored))

	_, err := abandon(th, abandonRecord(dag, only.ID(), nil))
	require.NoError(t, err)
	latest, err := th.Repository.FindAttempt(th.Context, ir.NewDAGRunRef(dag.Name, abandonRunID))
	require.NoError(t, err)
	status, err := latest.ReadStatus(th.Context)
	require.NoError(t, err)
	assert.Equal(t, ir.Failed, status.Status)
	assert.Equal(t, stored.Detail, status.Error, "the stored record decides, not the retry")
}

// An attempt whose status was never written, because its first Open or write
// failed, was never dispatched and can be abandoned.
func TestAbandonAttemptWithoutStatus(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	previous := createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	empty, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
		DAG: dag, Timestamp: time.Now(), DAGRunID: abandonRunID, Retry: true,
	})
	require.NoError(t, err)

	got, err := abandon(th, abandonRecord(dag, empty.ID(), nil))
	require.NoError(t, err)
	require.NotNil(t, got.ExpectedExecution)
	assert.Equal(t, previous.ID(), got.ExpectedExecution.AttemptID)
	assert.Equal(t, previous.ID(), latestAttemptID(t, th, dag))
}

// A record whose outcome contradicts its predecessor fields is not this
// abandonment's and never authorizes the hide or the Failed mark.
func TestAbandonAttemptRefusesInconsistentOutcome(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*persis.AttemptAbandonment){
		"hidden without an expected execution": func(r *persis.AttemptAbandonment) { r.Outcome = persis.AbandonmentHidden },
		"marked failed with an expected execution": func(r *persis.AttemptAbandonment) {
			r.Outcome = persis.AbandonmentMarkedFailed
			r.ExpectedExecution = &persis.ExecutionIdentity{AttemptID: "x"}
		},
		"unknown outcome": func(r *persis.AttemptAbandonment) { r.Outcome = "deleted" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			th := setupTestRepository(t)
			dag := th.DAG("abandon_dag").DAG
			createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
			placeholder := createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")
			stored := abandonRecord(dag, placeholder.ID(), nil)
			mutate(&stored)
			require.NoError(t, writeRecordExclusive(filepath.Join(filepath.Dir(placeholder.file), AbandonmentRecordFile), stored))

			_, err := abandon(th, abandonRecord(dag, placeholder.ID(), nil))
			require.ErrorIs(t, err, persis.ErrAttemptAbandonmentConflict)
			assert.Equal(t, placeholder.ID(), latestAttemptID(t, th, dag))
		})
	}
}

// A status file that Open created and no write ever filled is a status never
// written: the attempt is abandoned, and a first attempt is marked Failed.
func TestAbandonAttemptWithEmptyStatusFile(t *testing.T) {
	t.Parallel()
	for name, withPrevious := range map[string]bool{"retry": true, "first attempt": false} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			th := setupTestRepository(t)
			dag := th.DAG("abandon_dag").DAG
			if withPrevious {
				createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
			}
			opened, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
				DAG: dag, Timestamp: time.Now(), DAGRunID: abandonRunID, Retry: withPrevious,
			})
			require.NoError(t, err)
			require.NoError(t, opened.Open(th.Context))
			require.NoError(t, opened.Close(th.Context))
			concrete, ok := opened.(*Attempt)
			require.True(t, ok)
			info, err := os.Stat(concrete.file)
			require.NoError(t, err, "Open leaves a status file")
			require.Zero(t, info.Size())

			got, err := abandon(th, abandonRecord(dag, opened.ID(), nil))
			require.NoError(t, err)
			assert.Equal(t, withPrevious, got.Outcome == persis.AbandonmentHidden)
			if !withPrevious {
				latest, err := th.Repository.FindAttempt(th.Context, ir.NewDAGRunRef(dag.Name, abandonRunID))
				require.NoError(t, err)
				status, err := latest.ReadStatus(th.Context)
				require.NoError(t, err)
				assert.Equal(t, ir.Failed, status.Status)
			}
		})
	}
}

// Status data that exists but does not parse may describe a run: nothing is
// recorded, and the refusal is not the settled kind.
func TestAbandonAttemptRefusesUnreadableStatus(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	placeholder := createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")
	require.NoError(t, os.WriteFile(placeholder.file, []byte("{not json\n"), 0600))

	_, err := abandon(th, abandonRecord(dag, placeholder.ID(), nil))
	require.Error(t, err)
	assert.NotErrorIs(t, err, persis.ErrAttemptNotAbandonable)
	_, statErr := os.Stat(filepath.Join(filepath.Dir(placeholder.file), AbandonmentRecordFile))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

// The record names the execution it abandons, with the queued-at marker its
// status carried.
func TestAbandonAttemptRecordsAbandonedExecution(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	only := createRunAttempt(t, th, dag, false, ir.NotStarted, "2026-10-10T02:00:00Z", "")

	got, err := abandon(th, abandonRecord(dag, only.ID(), nil))
	require.NoError(t, err)
	assert.Equal(t, persis.ExecutionIdentity{AttemptID: only.ID(), QueuedAt: "2026-10-10T02:00:00Z"}, got.AbandonedExecution)
	assert.True(t, got.Covers(only.ID(), "2026-10-10T02:00:00Z"))
	assert.True(t, got.Covers(only.ID(), ""), "a new attempt's task carries no marker")
	assert.False(t, got.Covers(only.ID(), "2026-10-10T03:00:00Z"), "a re-queued execution is another one")
	assert.False(t, got.Covers("other", ""))
}

// The strict read returns the attempt's record, nothing for an attempt
// without one, and an error for a record it cannot trust.
func TestReadAttemptAbandonment(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	ref := ir.NewDAGRunRef(dag.Name, abandonRunID)
	previous := createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	placeholder := createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")
	_, err := abandon(th, abandonRecord(dag, placeholder.ID(), nil))
	require.NoError(t, err)

	got, err := th.Repository.ReadAttemptAbandonment(th.Context, ref, ir.DAGRunRef{}, placeholder.ID())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, placeholder.ID(), got.AbandonedAttemptID)

	none, err := th.Repository.ReadAttemptAbandonment(th.Context, ref, ir.DAGRunRef{}, previous.ID())
	require.NoError(t, err)
	assert.Nil(t, none)

	// The placeholder was hidden, which renamed its directory.
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(filepath.Dir(placeholder.file)), "*"+placeholder.ID(), AbandonmentRecordFile))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	recordPath := matches[0]
	for name, data := range map[string]string{
		"malformed":          "{",
		"another attempt":    `{"schema":1,"run":{"name":"abandon_dag","id":"abandon-run"},"abandonedAttemptId":"other"}`,
		"unsupported schema": `{"schema":99}`,
	} {
		require.NoError(t, os.WriteFile(recordPath, []byte(data), 0600))
		_, err := th.Repository.ReadAttemptAbandonment(th.Context, ref, ir.DAGRunRef{}, placeholder.ID())
		require.ErrorIs(t, err, persis.ErrAttemptAbandonmentConflict, name)
	}
	require.NoError(t, os.Chmod(recordPath, 0))
	if _, err := os.ReadFile(recordPath); err != nil { //nolint:gosec // test path
		_, err := th.Repository.ReadAttemptAbandonment(th.Context, ref, ir.DAGRunRef{}, placeholder.ID())
		require.ErrorIs(t, err, persis.ErrAttemptAbandonmentConflict, "unreadable")
	}
}

// A record that parses but is incomplete or inconsistent authorizes nothing:
// the strict read reports a conflict.
func TestReadAttemptAbandonmentRefusesIncompleteRecords(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*persis.AttemptAbandonment){
		"no abandoned execution": func(r *persis.AttemptAbandonment) { r.AbandonedExecution = persis.ExecutionIdentity{} },
		"another execution":      func(r *persis.AttemptAbandonment) { r.AbandonedExecution.AttemptID = "other" },
		"another root":           func(r *persis.AttemptAbandonment) { r.RootRun = ir.NewDAGRunRef("other", "other") },
		"evidence not absent":    func(r *persis.AttemptAbandonment) { r.Evidence.Lease = "present" },
		"no outcome":             func(r *persis.AttemptAbandonment) { r.Outcome = "" },
		"hidden without expected execution": func(r *persis.AttemptAbandonment) {
			r.Outcome = persis.AbandonmentHidden
			r.ExpectedExecution = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			th := setupTestRepository(t)
			dag := th.DAG("abandon_dag").DAG
			ref := ir.NewDAGRunRef(dag.Name, abandonRunID)
			only := createRunAttempt(t, th, dag, false, ir.NotStarted, "", "")
			stored, err := abandon(th, abandonRecord(dag, only.ID(), nil))
			require.NoError(t, err)
			_, err = th.Repository.ReadAttemptAbandonment(th.Context, ref, ir.DAGRunRef{}, only.ID())
			require.NoError(t, err, "the intact record reads")

			mutate(stored)
			data, err := json.Marshal(stored)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(only.file), AbandonmentRecordFile), data, 0600))
			_, err = th.Repository.ReadAttemptAbandonment(th.Context, ref, ir.DAGRunRef{}, only.ID())
			require.ErrorIs(t, err, persis.ErrAttemptAbandonmentConflict)
		})
	}
}

// The strict read waits for the run's data-root lock, which abandonment holds
// from writing the record to hiding the attempt. A read that starts while an
// abandonment is in progress therefore sees the hidden attempt's record, not
// a directory that vanished.
func TestReadAttemptAbandonmentWaitsForAnAbandonmentInProgress(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	ref := ir.NewDAGRunRef(dag.Name, abandonRunID)
	createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	placeholder := createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")

	root := th.Backend.dataRoot(dag.Name)
	require.NoError(t, root.Lock(th.Context))
	type result struct {
		record *persis.AttemptAbandonment
		err    error
	}
	done := make(chan result, 1)
	go func() {
		record, err := th.Repository.ReadAttemptAbandonment(th.Context, ref, ir.DAGRunRef{}, placeholder.ID())
		done <- result{record, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("the read did not wait for the lock: %+v", r)
	case <-time.After(200 * time.Millisecond):
	}

	// What AbandonAttempt does under the lock: the record, then the hide.
	record := abandonRecord(dag, placeholder.ID(), &persis.ExecutionIdentity{AttemptID: "previous"})
	record.Outcome = persis.AbandonmentHidden
	require.NoError(t, writeRecordExclusive(filepath.Join(filepath.Dir(placeholder.file), AbandonmentRecordFile), record))
	require.NoError(t, placeholder.Hide(th.Context))
	require.NoError(t, root.Unlock())

	r := <-done
	require.NoError(t, r.err)
	require.NotNil(t, r.record, "the hidden attempt's record is found")
	assert.Equal(t, placeholder.ID(), r.record.AbandonedAttemptID)
}

// The strict listing reports every record: a trusted one as a record, one it
// cannot trust as an error beside the others, and attempts without a record
// not at all. Newest attempt first.
func TestListAttemptAbandonmentsStrict(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	ref := ir.NewDAGRunRef(dag.Name, abandonRunID)
	previous := createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	hidden := createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")
	_, err := abandon(th, abandonRecord(dag, hidden.ID(), nil))
	require.NoError(t, err)
	retried := createRunAttempt(t, th, dag, true, ir.Failed, "", "worker-1")
	corrupt := createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(corrupt.file), AbandonmentRecordFile), []byte("{"), 0600))

	results, err := th.Repository.ListAttemptAbandonmentsStrict(th.Context, ref, ir.DAGRunRef{})
	require.NoError(t, err)
	require.Len(t, results, 2, "attempts %s and %s have no record", previous.ID(), retried.ID())
	assert.Equal(t, corrupt.ID(), results[0].AttemptID, "newest first")
	assert.Nil(t, results[0].Record)
	require.ErrorIs(t, results[0].Err, persis.ErrAttemptAbandonmentConflict)
	assert.Equal(t, hidden.ID(), results[1].AttemptID)
	require.NoError(t, results[1].Err, "a bad record does not spoil the good one")
	require.NotNil(t, results[1].Record)
	assert.Equal(t, persis.AbandonmentHidden, results[1].Record.Outcome)
}

// A record that parses but is incomplete is reported as an error, under the
// same checks as the strict single read.
func TestListAttemptAbandonmentsStrictReportsIncompleteRecords(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	ref := ir.NewDAGRunRef(dag.Name, abandonRunID)
	only := createRunAttempt(t, th, dag, false, ir.NotStarted, "", "")
	stored, err := abandon(th, abandonRecord(dag, only.ID(), nil))
	require.NoError(t, err)
	stored.AbandonedExecution = persis.ExecutionIdentity{}
	data, err := json.Marshal(stored)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(only.file), AbandonmentRecordFile), data, 0600))

	results, err := th.Repository.ListAttemptAbandonmentsStrict(th.Context, ref, ir.DAGRunRef{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.ErrorIs(t, results[0].Err, persis.ErrAttemptAbandonmentConflict)
	_, readErr := th.Repository.ReadAttemptAbandonment(th.Context, ref, ir.DAGRunRef{}, only.ID())
	require.ErrorIs(t, readErr, persis.ErrAttemptAbandonmentConflict, "the single read agrees")
}

// A run without any record lists nothing; a run that does not exist is the
// call's own error.
func TestListAttemptAbandonmentsStrictEmptyAndMissingRuns(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")

	results, err := th.Repository.ListAttemptAbandonmentsStrict(th.Context, ir.NewDAGRunRef(dag.Name, abandonRunID), ir.DAGRunRef{})
	require.NoError(t, err)
	assert.Empty(t, results)

	_, err = th.Repository.ListAttemptAbandonmentsStrict(th.Context, ir.NewDAGRunRef(dag.Name, "no-such-run"), ir.DAGRunRef{})
	require.Error(t, err)
}

// The strict listing waits for an abandonment in progress, and then lists
// the hidden attempt's record.
func TestListAttemptAbandonmentsStrictWaitsForAnAbandonmentInProgress(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	ref := ir.NewDAGRunRef(dag.Name, abandonRunID)
	createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	placeholder := createRunAttempt(t, th, dag, true, ir.NotStarted, "", "")

	root := th.Backend.dataRoot(dag.Name)
	require.NoError(t, root.Lock(th.Context))
	type result struct {
		results []persis.AttemptAbandonmentResult
		err     error
	}
	done := make(chan result, 1)
	go func() {
		results, err := th.Repository.ListAttemptAbandonmentsStrict(th.Context, ref, ir.DAGRunRef{})
		done <- result{results, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("the listing did not wait for the lock: %+v", r)
	case <-time.After(200 * time.Millisecond):
	}
	record := abandonRecord(dag, placeholder.ID(), &persis.ExecutionIdentity{AttemptID: "previous"})
	record.Outcome = persis.AbandonmentHidden
	require.NoError(t, writeRecordExclusive(filepath.Join(filepath.Dir(placeholder.file), AbandonmentRecordFile), record))
	require.NoError(t, placeholder.Hide(th.Context))
	require.NoError(t, root.Unlock())

	r := <-done
	require.NoError(t, r.err)
	require.Len(t, r.results, 1)
	require.NoError(t, r.results[0].Err)
	assert.Equal(t, placeholder.ID(), r.results[0].AttemptID)
}
