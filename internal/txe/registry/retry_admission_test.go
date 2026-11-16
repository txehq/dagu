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

func queuedRetry(actionID string) QueuedRetry {
	return QueuedRetry{RunID: "run-1", AttemptID: "a1", QueuedAt: "q1",
		Request: ir.RetryRequest{ID: "req", ActionID: actionID, ActionAttempt: "1", BindingDigest: "sha256:b", RetryOf: ir.ExecutionRef("a1", "q1")}}
}

// putRetryForm stores a dagu.retry_run action whose params are raw.
func putRetryForm(t *testing.T, f *fixture, jobID, actionID, raw string) {
	t.Helper()
	_, err := f.tx(jobID, agent, func(tx *JobTx) error {
		if tx.Job.Actions == nil {
			tx.Job.Actions = map[string]*Action{}
		}
		tx.Job.Actions[actionID] = &Action{ActionID: actionID, Kind: ActionApproved, State: ActionExecuting, Attempt: 1,
			JobVersion: tx.Job.Version, Spec: ActionSpec{Name: ActionRetryRun, Params: json.RawMessage(raw)}}
		tx.touch()
		return nil
	})
	require.NoError(t, err)
}

// A queued retry re-runs the whole run with no step. An approval of a
// republish, of an explicit rerun (TXE-7515's rerun, carried out only as a
// retry of step "run" with its downstream) or of any other step is refused
// as not applied, whatever the binding would say: neither is coerced into a
// whole-run retry.
func TestAdmitQueuedRetryRefusesFormsAQueueDoesNotCarry(t *testing.T) {
	for name, tc := range map[string]struct{ params, reason string }{
		"republish":      {`{"run_id":"run-1","attempt_id":"a1","queued_at":"q1","step":"publish"}`, "republish"},
		"explicit rerun": {`{"run_id":"run-1","attempt_id":"a1","queued_at":"q1","rerun":true}`, "explicit rerun"},
		"another step":   {`{"run_id":"run-1","attempt_id":"a1","queued_at":"q1","step":"run"}`, `step "run"`},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			job := f.ready("k")
			putRetryForm(t, f, job.JobID, "act_form", tc.params)
			bound := false
			withCheckRetryRun(t, func(*Job, *Action, QueuedRetry, time.Time) error { bound = true; return nil })

			adm, err := f.store.AdmitQueuedRetry(f.ctx, job.JobID, queuedRetry("act_form"))

			require.NoError(t, err)
			assert.False(t, adm.Admit)
			assert.Equal(t, AdmitRetryNotApproved, adm.Code)
			assert.Contains(t, adm.Reason, "not applied")
			assert.Contains(t, adm.Reason, tc.reason)
			assert.False(t, bound, "the form is refused before the binding")
		})
	}
}

// The legacy form, a person's retry that names no intent (no step, no
// rerun), is what a queued retry carries: it goes to the binding unchanged,
// so the explicit forms do not redefine an unspecified action.
func TestAdmitQueuedRetryLegacyUnspecifiedReachesTheBinding(t *testing.T) {
	for name, params := range map[string]string{
		"no intent fields": `{"run_id":"run-1","attempt_id":"a1","queued_at":"q1","run_spec_sha256":"sha256:s","package_digest":"sha256:p"}`,
		"rerun false":      `{"run_id":"run-1","attempt_id":"a1","queued_at":"q1","rerun":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			job := f.ready("k")
			putRetryForm(t, f, job.JobID, "act_legacy", params)
			bound := false
			withCheckRetryRun(t, func(*Job, *Action, QueuedRetry, time.Time) error { bound = true; return nil })

			adm, err := f.store.AdmitQueuedRetry(f.ctx, job.JobID, queuedRetry("act_legacy"))

			require.NoError(t, err)
			assert.True(t, adm.Admit)
			assert.True(t, bound)
		})
	}
}

// The binding decides the rest, at dispatch, with the job and action as they
// are now and the queued retry's execution and request.
func TestAdmitQueuedRetryAsksTheBinding(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	putRetryForm(t, f, job.JobID, "act_rerun", `{"run_id":"run-1","attempt_id":"a1","queued_at":"q1"}`)
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
