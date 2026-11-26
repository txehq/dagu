// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TXE-8596: queue dispatch admits an approved retry only while its action
// is executing under a live grant (CheckRetryRun). These tests hold the
// registry to the rules that keep that true until the queued execution is
// dispatched, and to the rule that a retry is recorded as succeeded only for
// an execution that ran.

// executingRetry is a person's approved retry of run-1's failed execution
// a1, executing under the execution claim it was granted under.
func (r *retryFixture) executingRetry(t *testing.T) (string, *Grant, *Claim) {
	t.Helper()
	return r.executingRetryClaimed(t, time.Hour)
}

// executingRetryClaimed is executingRetry under an execution claim of ttl.
func (r *retryFixture) executingRetryClaimed(t *testing.T, ttl time.Duration) (string, *Grant, *Claim) {
	t.Helper()
	r.rc.attempts["run-1"] = failedAttempt("a1", r.job.DAGSpecSHA256)
	p, d, err := r.propose(r.params("run-1", "a1"), "key-1")
	require.NoError(t, err)
	ec := acquire(t, r.f, r.job.JobID, ClaimExecution, ttl)
	act, g, err := r.authorize(p, d, ec)
	require.NoError(t, err)
	require.Equal(t, ActionExecuting, r.action(t, act).State)
	return act, g, ec
}

// queued records that the retry's request admitted execution ref, which
// waits in its queue.
func (r *retryFixture) queued(t *testing.T, actionID, ref string) {
	t.Helper()
	r.admit(t, actionID, r.params("run-1", "a1"), ref, false, false)
	r.rc.mu.Lock()
	defer r.rc.mu.Unlock()
	for id, e := range r.rc.retries {
		if e.Ref == ref {
			e.Queued = true
			r.rc.retries[id] = e
		}
	}
}

// dispatched records that execution ref left its queue.
func (r *retryFixture) dispatched(ref string) {
	r.rc.mu.Lock()
	defer r.rc.mu.Unlock()
	for id, e := range r.rc.retries {
		if e.Ref == ref {
			e.Queued = false
			r.rc.retries[id] = e
		}
	}
}

func (r *retryFixture) release(t *testing.T, c *Claim) {
	t.Helper()
	_, err := r.f.tx(r.job.JobID, agent, func(tx *JobTx) error { return tx.ReleaseClaim(c.ClaimID, c.Fence) })
	require.NoError(t, err)
}

// admits is queue dispatch's check of the retry, as AdmitQueuedRetry makes
// it, at the registry's time now.
func (r *retryFixture) admits(t *testing.T, actionID string) error {
	t.Helper()
	job, err := r.f.store.GetJob(r.f.ctx, r.job.JobID)
	require.NoError(t, err)
	a := job.Actions[actionID]
	require.NotNil(t, a)
	return CheckRetryRun(job, a, "run-1", RetriedExecution{AttemptID: "a1"},
		RetryActionRequest{ActionAttempt: strconv.Itoa(a.Attempt), BindingDigest: a.BindingDigest}, RetryFormWholeRun, r.f.clock())
}

// A retry is not settled as succeeded while the execution its request
// admitted is queued: the registry says not ready, with the execution, so
// every reviewer gets the same answer. Once dispatched, it is.
func TestQueuedRetryIsNotSettledSucceededUntilDispatched(t *testing.T) {
	r := newRetryFixture(t)
	act, g, ec := r.executingRetry(t)
	q := ExecutionRef("a1", "2026-10-09T12:00:01Z")
	r.queued(t, act, q)

	err := r.settle(act, g, ec, ActionSucceeded, q)
	require.Equal(t, CodeNotReady, code(t, err))
	re, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ExecutionPreparing{RunID: "run-1", Execution: q}, re.Current)
	assert.Contains(t, err.Error(), "queued and not yet dispatched")
	assert.Equal(t, ActionExecuting, r.action(t, act).State, "the refusal changes nothing")
	require.NoError(t, r.admits(t, act), "and queue dispatch still admits it")

	r.dispatched(q)
	require.NoError(t, r.settle(act, g, ec, ActionSucceeded, q))
}

// An executing retry may be settled as executing again only to record the
// execution its request admitted: once, never another, never with a
// receipt, never an abandoned one. Recording it again changes nothing.
func TestExecutingRetryRecordsItsAdmittedExecution(t *testing.T) {
	r := newRetryFixture(t)
	act, g, ec := r.executingRetry(t)
	q := ExecutionRef("a1", "2026-10-09T12:00:01Z")

	assert.Equal(t, CodeInvalid, code(t, r.settleOutcome(act, g, ec, ActionExecuting, "", admittedOutcome(q))), "no execution records the request yet")
	r.queued(t, act, q)
	assert.Equal(t, CodeInvalid, code(t, r.settleOutcome(act, g, ec, ActionExecuting, q, admittedOutcome(q))), "an executing action has no receipt")
	assert.Equal(t, CodeInvalid, code(t, r.settleOutcome(act, g, ec, ActionExecuting, "", `{"detail":"no execution"}`)), "it records only the admitted execution")
	require.NoError(t, r.settleOutcome(act, g, ec, ActionExecuting, "", admittedOutcome(q)))
	a := r.action(t, act)
	assert.Equal(t, ActionExecuting, a.State)
	assert.Empty(t, a.Receipt)
	ref, err := admittedExecutionOf(a.Outcome)
	require.NoError(t, err)
	assert.Equal(t, q, ref)
	require.NoError(t, r.settleOutcome(act, g, ec, ActionExecuting, "", admittedOutcome(q)), "again: no change")
	assert.Equal(t, CodeInvalid, code(t, r.settleOutcome(act, g, ec, ActionExecuting, "", admittedOutcome(ExecutionRef("a9", "")))), "never another")
}

// An abandoned execution is not recorded on an executing retry: nothing ran,
// and the retry is settled as not applied.
func TestExecutingRetryAbandonedIsNotAppliedNeverSucceeded(t *testing.T) {
	r := newRetryFixture(t)
	act, g, ec := r.executingRetry(t)
	q := ExecutionRef("a1", "2026-10-09T12:00:01Z")
	r.admit(t, act, r.params("run-1", "a1"), q, true, false)

	assert.Equal(t, CodeInvalid, code(t, r.settleOutcome(act, g, ec, ActionExecuting, "", admittedOutcome(q))))
	assert.Equal(t, CodeInvalid, code(t, r.settle(act, g, ec, ActionSucceeded, q)), "abandoned before dispatch: no receipt")
	require.NoError(t, r.settleOutcome(act, g, ec, ActionNotApplied, "", admittedOutcome(q)))
	assert.Equal(t, ActionNotApplied, r.action(t, act).State)
}

// The end of the claim a retry ran under does not interrupt it once it
// records its admitted execution: queue dispatch still admits it. Without
// the record, the end of the claim interrupts it as before, and dispatch
// refuses it.
func TestClaimEndKeepsAHeldRetryExecuting(t *testing.T) {
	t.Run("released, with its admitted execution recorded", func(t *testing.T) {
		r := newRetryFixture(t)
		act, g, ec := r.executingRetry(t)
		q := ExecutionRef("a1", "2026-10-09T12:00:01Z")
		r.queued(t, act, q)
		require.NoError(t, r.settleOutcome(act, g, ec, ActionExecuting, "", admittedOutcome(q)))
		r.release(t, ec)
		assert.Equal(t, ActionExecuting, r.action(t, act).State)
		require.NoError(t, r.admits(t, act))

		// A later claim, of any kind, settles it once it is dispatched.
		later := acquire(t, r.f, r.job.JobID, ClaimReview, time.Hour)
		assert.Equal(t, CodeNotReady, code(t, r.settle(act, g, later, ActionSucceeded, q)))
		r.dispatched(q)
		require.NoError(t, r.settle(act, g, later, ActionSucceeded, q))
	})
	t.Run("expired and taken over, with its admitted execution recorded", func(t *testing.T) {
		r := newRetryFixture(t)
		// A claim shorter than the grant, so that only the claim ends.
		act, g, ec := r.executingRetryClaimed(t, time.Minute)
		q := ExecutionRef("a1", "2026-10-09T12:00:01Z")
		r.queued(t, act, q)
		require.NoError(t, r.settleOutcome(act, g, ec, ActionExecuting, "", admittedOutcome(q)))
		r.f.advance(2 * time.Minute)
		require.True(t, r.f.clock().Before(g.ExpiresAt))
		acquire(t, r.f, r.job.JobID, ClaimReview, time.Hour)
		assert.Equal(t, ActionExecuting, r.action(t, act).State, "a takeover of the expired claim does not interrupt it")
		require.NoError(t, r.admits(t, act))
	})
	t.Run("released, without a recorded execution", func(t *testing.T) {
		r := newRetryFixture(t)
		act, _, ec := r.executingRetry(t)
		r.release(t, ec)
		assert.Equal(t, ActionUncertain, r.action(t, act).State, "interrupted with its claim, as before")
		assert.Equal(t, CodeStaleBinding, code(t, r.admits(t, act)))
	})
}

// The grant still bounds a held retry: once it ends, the registry
// interrupts the action as before, queue dispatch refuses the retry, and it
// is not recorded as succeeded while its execution is queued.
func TestGrantEndInterruptsAHeldRetry(t *testing.T) {
	r := newRetryFixture(t)
	act, g, ec := r.executingRetry(t)
	q := ExecutionRef("a1", "2026-10-09T12:00:01Z")
	r.queued(t, act, q)
	require.NoError(t, r.settleOutcome(act, g, ec, ActionExecuting, "", admittedOutcome(q)))
	r.release(t, ec)

	r.f.advance(g.ExpiresAt.Sub(r.f.clock()) + time.Second)
	later := acquire(t, r.f, r.job.JobID, ClaimReconcile, time.Hour)
	a := r.action(t, act)
	assert.Equal(t, ActionUncertain, a.State, "the sweep interrupted it with its grant")
	assert.Equal(t, CodeStaleBinding, code(t, r.admits(t, act)), "queue dispatch refuses it, as today")
	assert.Equal(t, CodeNotReady, code(t, r.settle(act, g, later, ActionSucceeded, q)), "and it is not a success while queued")
}
