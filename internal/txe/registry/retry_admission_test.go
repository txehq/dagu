// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

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

// A queued retry re-runs the whole run with no step. The shared binding,
// asked for RetryFormWholeRun, refuses an approval of a republish, of an
// explicit rerun (TXE-7515's rerun, carried out only from the job's step
// with its downstream) or of any other step as not applied, before it reads
// the attempt, the run or the grant: neither is coerced into a whole-run
// retry.
func TestAdmitQueuedRetryRefusesFormsAQueueDoesNotCarry(t *testing.T) {
	for name, tc := range map[string]struct{ params, reason string }{
		"republish":      {`{"run_id":"run-1","attempt_id":"a1","queued_at":"q1","step":"publish"}`, "approved as a republish"},
		"explicit rerun": {`{"run_id":"run-1","attempt_id":"a1","queued_at":"q1","rerun":true}`, "approved as a rerun of the job"},
		"another step":   {`{"run_id":"run-1","attempt_id":"a1","queued_at":"q1","step":"run"}`, `retries step "run"`},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			job := f.ready("k")
			putRetryForm(t, f, job.JobID, "act_form", tc.params)

			adm, err := f.store.AdmitQueuedRetry(f.ctx, job.JobID, queuedRetry("act_form"))

			require.NoError(t, err)
			assert.False(t, adm.Admit)
			assert.Equal(t, AdmitRetryNotApproved, adm.Code)
			assert.Contains(t, adm.Reason, "not applied")
			assert.Contains(t, adm.Reason, tc.reason)
		})
	}
}

// The legacy form, a person's retry that names no intent (no step, no
// rerun), is the form a queued retry carries: it passes the form check and
// is judged on the rest of the binding, so the explicit forms do not
// redefine an unspecified action. (This injected action is no person's
// decision, so the binding refuses it there; the scheduler's
// TestQueueDispatch_TxeApprovedRetryIsAdmitted admits a real one.)
func TestAdmitQueuedRetryLegacyUnspecifiedPassesTheFormCheck(t *testing.T) {
	for name, params := range map[string]string{
		"no intent fields": `{"run_id":"run-1","attempt_id":"a1","queued_at":"q1","run_spec_sha256":"sha256:s","package_digest":"sha256:p"}`,
		"rerun false":      `{"run_id":"run-1","attempt_id":"a1","queued_at":"q1","rerun":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			job := f.ready("k")
			putRetryForm(t, f, job.JobID, "act_legacy", params)
			q := queuedRetry("act_legacy")
			q.Request.BindingDigest = ""

			adm, err := f.store.AdmitQueuedRetry(f.ctx, job.JobID, q)

			require.NoError(t, err)
			assert.False(t, adm.Admit)
			assert.Contains(t, adm.Reason, "is not a person's approved decision")
			assert.NotContains(t, adm.Reason, "approved as")
		})
	}
}

// The binding reads the request against the action as it is now: another
// attempt, another execution or an unknown action is refused.
func TestAdmitQueuedRetryChecksTheRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*QueuedRetry)
		reason string
	}{
		"another attempt":   {func(q *QueuedRetry) { q.Request.ActionAttempt = "2" }, "current attempt and binding"},
		"another execution": {func(q *QueuedRetry) { q.QueuedAt = "q2" }, "another run or execution"},
		"unknown action":    {func(q *QueuedRetry) { q.Request.ActionID = "act_none" }, "names no dagu.retry_run action"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			job := f.ready("k")
			putRetryForm(t, f, job.JobID, "act_req", `{"run_id":"run-1","attempt_id":"a1","queued_at":"q1"}`)
			q := queuedRetry("act_req")
			q.Request.BindingDigest = ""
			tc.mutate(&q)

			adm, err := f.store.AdmitQueuedRetry(f.ctx, job.JobID, q)

			require.NoError(t, err)
			assert.False(t, adm.Admit)
			assert.Equal(t, AdmitRetryNotApproved, adm.Code)
			assert.Contains(t, adm.Reason, tc.reason)
		})
	}
}

// An unknown job is refused as unregistered.
func TestAdmitQueuedRetryUnknownJob(t *testing.T) {
	f := newFixture(t)
	adm, err := f.store.AdmitQueuedRetry(f.ctx, f.mint(PrefixJob), queuedRetry("act_any"))
	require.NoError(t, err)
	assert.False(t, adm.Admit)
	assert.Equal(t, AdmitUnregistered, adm.Code)
}
