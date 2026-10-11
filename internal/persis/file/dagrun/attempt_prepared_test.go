// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

// AttemptPrepared answers for one attempt strictly: absent is false, present
// is true, and an entry that cannot be read or names another attempt is an
// error rather than absent.
func TestAttemptPreparedIsStrict(t *testing.T) {
	ctx := t.Context()
	store := NewStore(t.TempDir())
	run := ir.NewDAGRunRef("dag", "run-1")

	prepared, err := store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a1")
	require.NoError(t, err)
	assert.False(t, prepared, "nothing journaled")

	entry, err := store.beginPreparation(run, ir.DAGRunRef{}, "a1")
	require.NoError(t, err)
	prepared, err = store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a1")
	require.NoError(t, err)
	assert.True(t, prepared)
	prepared, err = store.AttemptPrepared(ctx, run, run, "a1")
	require.NoError(t, err)
	assert.True(t, prepared, "a root run is its own root")
	prepared, err = store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a2")
	require.NoError(t, err)
	assert.False(t, prepared, "another attempt")

	path := store.preparationPath(entry)
	require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))
	_, err = store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a1")
	assert.Error(t, err, "an unreadable entry")

	other := persis.AttemptPreparation{Schema: persis.AttemptPreparationSchema, Run: run, RootRun: run, AttemptID: "a9",
		PreparedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	data, err := json.Marshal(other)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	_, err = store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a1")
	assert.Error(t, err, "an entry naming another attempt")

	require.NoError(t, store.EndAttemptPreparation(ctx, entry))
	prepared, err = store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a1")
	require.NoError(t, err)
	assert.False(t, prepared, "ended")
}

// createPreparedAttempt creates a journaled retry preparation of the run that
// has not started.
func createPreparedAttempt(t *testing.T, th RepositoryTest, dag *ir.DAG) *Attempt {
	t.Helper()
	attempt, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
		DAG: dag, Timestamp: time.Now(), DAGRunID: abandonRunID, Retry: true, TrackPreparation: true,
	})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(th.Context))
	status := ir.InitialStatus(dag)
	status.DAGRunID, status.AttemptID, status.Status = abandonRunID, attempt.ID(), ir.NotStarted
	require.NoError(t, attempt.Write(th.Context, status))
	require.NoError(t, attempt.Close(th.Context))
	concrete, ok := attempt.(*Attempt)
	require.True(t, ok)
	return concrete
}

// A preparation's entry is ended only once nothing of it is left to judge.
// After failed A come preparations B and C: B's entry stays while C, the
// latest, is a preparation; it still stays after C is abandoned and B is the
// latest again (the decision and the removal hold the lock abandonment
// takes); it is ended once B has started, or once the latest is an attempt
// that is no preparation.
func TestEndSettledAttemptPreparation(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("settle_dag").DAG
	run := ir.NewDAGRunRef(dag.Name, abandonRunID)
	createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	b := createPreparedAttempt(t, th, dag)
	c := createPreparedAttempt(t, th, dag)
	entry := func(a *Attempt) persis.AttemptPreparation {
		return persis.AttemptPreparation{Run: run, RootRun: run, AttemptID: a.ID()}
	}
	journaled := func(a *Attempt) bool {
		ok, err := th.Backend.AttemptPrepared(th.Context, run, run, a.ID())
		require.NoError(t, err)
		return ok
	}

	ended, err := th.Backend.EndSettledAttemptPreparation(th.Context, entry(b))
	require.NoError(t, err)
	assert.False(t, ended, "the latest, C, is a preparation")
	assert.True(t, journaled(b))

	expected := &persis.ExecutionIdentity{AttemptID: b.ID()}
	_, err = abandon(th, abandonRecord(dag, c.ID(), expected))
	require.NoError(t, err)
	require.NoError(t, th.Backend.EndAttemptPreparation(th.Context, entry(c)))
	require.Equal(t, b.ID(), latestAttemptID(t, th, dag))
	ended, err = th.Backend.EndSettledAttemptPreparation(th.Context, entry(b))
	require.NoError(t, err)
	assert.False(t, ended, "B is the latest again and has not started")
	assert.True(t, journaled(b))

	// B starts on a worker: settled.
	require.NoError(t, b.Open(th.Context))
	started := ir.InitialStatus(dag)
	started.DAGRunID, started.AttemptID, started.Status, started.WorkerID = abandonRunID, b.ID(), ir.Running, "worker-1"
	require.NoError(t, b.Write(th.Context, started))
	require.NoError(t, b.Close(th.Context))
	ended, err = th.Backend.EndSettledAttemptPreparation(th.Context, entry(b))
	require.NoError(t, err)
	assert.True(t, ended)
	assert.False(t, journaled(b))

	// An older preparation superseded by an attempt that is no preparation.
	d := createPreparedAttempt(t, th, dag)
	_ = createRunAttempt(t, th, dag, true, ir.Running, "", "worker-1")
	ended, err = th.Backend.EndSettledAttemptPreparation(th.Context, entry(d))
	require.NoError(t, err)
	assert.True(t, ended, "the latest is no preparation")
	assert.False(t, journaled(d))
}

// A preparation whose first status was never written is still present: its
// entry stays while a later preparation is the latest, and after that one is
// abandoned, until it is itself abandoned or starts.
func TestEndSettledAttemptPreparationKeepsAPreparationWithoutStatus(t *testing.T) {
	t.Parallel()
	th := setupTestRepository(t)
	dag := th.DAG("settle_nostatus_dag").DAG
	run := ir.NewDAGRunRef(dag.Name, abandonRunID)
	createRunAttempt(t, th, dag, false, ir.Failed, "", "worker-1")
	bare, err := th.Backend.CreateAttempt(th.Context, persis.DAGRunCreateAttemptRequest{
		DAG: dag, Timestamp: time.Now(), DAGRunID: abandonRunID, Retry: true, TrackPreparation: true,
	})
	require.NoError(t, err)
	c := createPreparedAttempt(t, th, dag)
	entry := persis.AttemptPreparation{Run: run, RootRun: run, AttemptID: bare.ID()}

	ended, err := th.Backend.EndSettledAttemptPreparation(th.Context, entry)
	require.NoError(t, err)
	assert.False(t, ended, "C, the latest, is a preparation")

	_, err = abandon(th, abandonRecord(dag, c.ID(), nil))
	require.NoError(t, err)
	require.NoError(t, th.Backend.EndAttemptPreparation(th.Context, persis.AttemptPreparation{Run: run, RootRun: run, AttemptID: c.ID()}))
	ended, err = th.Backend.EndSettledAttemptPreparation(th.Context, entry)
	require.NoError(t, err)
	assert.False(t, ended, "never started: still to be abandoned")
	ok, err := th.Backend.AttemptPrepared(th.Context, run, run, bare.ID())
	require.NoError(t, err)
	assert.True(t, ok)
}
