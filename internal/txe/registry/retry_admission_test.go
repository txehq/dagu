// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

// withCheckRetryRun replaces the queued-retry binding for one test.
func withCheckRetryRun(t *testing.T, check func(*Job, *Action, QueuedRetry, time.Time) error) {
	t.Helper()
	saved := checkRetryRun
	checkRetryRun = check
	t.Cleanup(func() { checkRetryRun = saved })
}

// putRetryAction stores a dagu.retry_run action with params on the job, as
// an approval would leave it executing.
func putRetryAction(t *testing.T, f *fixture, jobID, actionID string, params RetryRunParams) {
	t.Helper()
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	_, err = f.tx(jobID, agent, func(tx *JobTx) error {
		if tx.Job.Actions == nil {
			tx.Job.Actions = map[string]*Action{}
		}
		tx.Job.Actions[actionID] = &Action{ActionID: actionID, Kind: ActionApproved, State: ActionExecuting, Attempt: 1,
			JobVersion: tx.Job.Version, Spec: ActionSpec{Name: ActionRetryRun, Params: raw}}
		tx.touch()
		return nil
	})
	require.NoError(t, err)
}

func queuedRetry(actionID string) QueuedRetry {
	return QueuedRetry{RunID: "run-1", AttemptID: "a1", QueuedAt: "q1",
		Request: ir.RetryRequest{ID: "req", ActionID: actionID, ActionAttempt: "1", BindingDigest: "sha256:b", RetryOf: ir.ExecutionRef("a1", "q1")}}
}

// A queued retry only reruns the whole run. An action a person approved as a
// republish of the sealed result is refused, not carried out as a rerun,
// whatever the binding would say.
func TestAdmitQueuedRetryRefusesPublishIntent(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	putRetryAction(t, f, job.JobID, "act_publish", RetryRunParams{RunID: "run-1", AttemptID: "a1", QueuedAt: "q1", Step: RetryStepPublish})
	bound := false
	withCheckRetryRun(t, func(*Job, *Action, QueuedRetry, time.Time) error { bound = true; return nil })

	adm, err := f.store.AdmitQueuedRetry(f.ctx, job.JobID, queuedRetry("act_publish"))

	require.NoError(t, err)
	assert.False(t, adm.Admit)
	assert.Equal(t, AdmitRetryNotApproved, adm.Code)
	assert.Contains(t, adm.Reason, `step "publish"`)
	assert.False(t, bound, "a publish intent never reaches the rerun binding")
}

// The binding decides the rest, at dispatch, with the job and action as they
// are now and the queued retry's execution and request.
func TestAdmitQueuedRetryAsksTheBinding(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	putRetryAction(t, f, job.JobID, "act_rerun", RetryRunParams{RunID: "run-1", AttemptID: "a1", QueuedAt: "q1"})
	q := queuedRetry("act_rerun")

	var got QueuedRetry
	var gotAction *Action
	withCheckRetryRun(t, func(_ *Job, a *Action, q QueuedRetry, now time.Time) error {
		got, gotAction = q, a
		assert.Equal(t, f.clock(), now)
		return nil
	})
	adm, err := f.store.AdmitQueuedRetry(f.ctx, job.JobID, q)
	require.NoError(t, err)
	assert.True(t, adm.Admit)
	assert.Equal(t, q, got)
	require.NotNil(t, gotAction)
	assert.Equal(t, "act_rerun", gotAction.ActionID)

	withCheckRetryRun(t, func(*Job, *Action, QueuedRetry, time.Time) error {
		return &Error{Code: CodeStaleBinding, Message: "action act_rerun is not executing attempt 1 under a live grant"}
	})
	adm, err = f.store.AdmitQueuedRetry(f.ctx, job.JobID, q)
	require.NoError(t, err)
	assert.False(t, adm.Admit)
	assert.Equal(t, AdmitRetryNotApproved, adm.Code)
	assert.Contains(t, adm.Reason, "live grant")

	withCheckRetryRun(t, func(*Job, *Action, QueuedRetry, time.Time) error { return errors.New("disk read failed") })
	_, err = f.store.AdmitQueuedRetry(f.ctx, job.JobID, q)
	assert.Error(t, err, "an unreadable registry leaves the retry queued")
}

// Without the binding nothing is admitted, and an unknown job is refused.
func TestAdmitQueuedRetryFailsClosed(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	withCheckRetryRun(t, nil)

	adm, err := f.store.AdmitQueuedRetry(f.ctx, job.JobID, queuedRetry("act_any"))
	require.NoError(t, err)
	assert.False(t, adm.Admit)
	assert.Equal(t, AdmitRetryNotApproved, adm.Code)

	adm, err = f.store.AdmitQueuedRetry(f.ctx, f.mint(PrefixJob), queuedRetry("act_any"))
	require.NoError(t, err)
	assert.False(t, adm.Admit)
	assert.Equal(t, AdmitUnregistered, adm.Code)
}
