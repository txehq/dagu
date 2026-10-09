// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"context"
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
		record := abandonRecord(dag, placeholder.ID(), nil)
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
				bad := abandonRecord(dag, placeholder.ID(), nil)
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
}

// A run's only execution has nothing to fall back to: it is refused unless the
// caller explicitly allows leaving the run with no visible attempt.
func TestAbandonAttemptWithoutPredecessor(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("abandon_dag").DAG
	only := createRunAttempt(t, th, dag, false, ir.NotStarted, "", "")

	_, err := abandon(th, abandonRecord(dag, only.ID(), nil))
	require.ErrorIs(t, err, persis.ErrAttemptNotAbandonable)
	assert.Equal(t, only.ID(), latestAttemptID(t, th, dag))

	record := abandonRecord(dag, only.ID(), nil)
	got, err := th.Repository.AbandonAttempt(th.Context, persis.AbandonAttemptRequest{
		DAGRun: record.Run, Record: record, AllowWithoutPredecessor: true,
	})
	require.NoError(t, err)
	assert.Nil(t, got.ExpectedExecution)
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
