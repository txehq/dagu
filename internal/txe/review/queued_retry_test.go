// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package review_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/review"
	"github.com/dagucloud/dagu/v2/internal/txe/review/reviewtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TXE-8596: an approved retry whose execution waits in a global queue is
// admitted at dispatch only while its action is executing under a live
// grant. The reviewer must not settle it before then, and must settle it
// from what the run then shows: dispatched is the retry; abandoned before
// dispatch, as the coordinator records a refused one the queue withdrew once
// nothing of it was handed to a worker, is not.

// dispatchRun moves the run's latest execution from its queue to running,
// as queue dispatch and a worker do.
func dispatchRun(r *runs, runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.state[runID]
	state.Status, state.Active = "running", true
	r.state[runID] = state
}

// setStatus gives the run's latest execution status.
func setStatus(r *runs, runID, status string, active bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.state[runID]
	state.Status, state.Active = status, active
	r.state[runID] = state
}

// reviewOnce advances the clock by d and runs one review of the job, which
// reconciles its open actions, and returns the retry's action as stored.
// counts, when given, are queueRule's success and refusal counters.
func reviewOnce(t *testing.T, f *retryFixture, holder string, d time.Duration, counts ...*int) review.Action {
	t.Helper()
	f.clock.Advance(d)
	r := f.executor(holder)
	rule := queueRule{Registry: f.registry, runs: f.runs}
	if len(counts) > 0 {
		rule.succeeded = counts[0]
	}
	if len(counts) > 1 {
		rule.refused = counts[1]
	}
	r.Registry = rule
	prepared, err := r.Prepare(context.Background(), jobID)
	require.NoError(t, err)
	if prepared.Skipped == "" {
		_, err = r.Apply(context.Background(), prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "waiting"})
		require.NoError(t, err)
	}
	return f.state().Actions[jobID][0]
}

// queueRule is the reference registry with the registry's TXE-8596 rule: a
// retry is not settled as succeeded while the execution named as its
// receipt is the run's latest and waits in its queue. It counts every
// success it was asked to record and every one it refused.
type queueRule struct {
	*reviewtest.Registry
	runs      *runs
	succeeded *int
	refused   *int
}

func (q queueRule) FinishAction(ctx context.Context, req review.FinishRequest) error {
	if req.State == review.ActionSucceeded {
		if q.succeeded != nil {
			*q.succeeded++
		}
		q.runs.mu.Lock()
		state := q.runs.state["run-1"]
		q.runs.mu.Unlock()
		if state.Execution().Ref() == req.Receipt && state.Status == "queued" {
			if q.refused != nil {
				*q.refused++
			}
			return fmt.Errorf("%w: execution %s of run run-1 is queued and not yet dispatched", review.ErrNotReady, req.Receipt)
		}
	}
	return q.Registry.FinishAction(ctx, req)
}

// queuedRetry executes the fixture's approved retry on the queued path and
// returns the reviewer's result and the queued execution.
func queuedRetry(t *testing.T, f *retryFixture, succeeded, refused *int) (review.Executed, string) {
	t.Helper()
	f.runs.retry = func(runID string) error {
		f.runs.requeue(runID)
		return nil
	}
	r := f.executor("executor")
	r.Registry = queueRule{Registry: f.registry, runs: f.runs, succeeded: succeeded, refused: refused}
	out, err := r.Execute(context.Background(), jobID, f.proposal.ID, f.decision.ID)
	require.NoError(t, err)
	return out, f.runs.ref("run-1")
}

// Queued by the retry and dispatched by the time the reviewer reads the
// run: the retry is recorded as succeeded with the queued execution as its
// receipt, as before. (The fixture's grant deadline is in the real past, so
// its watch reads the run once; settling across later reads is covered by
// the reviews below.)
func TestQueuedRetryDispatchedWhenObservedSucceeds(t *testing.T) {
	f := newRetryFixture(t)
	reads := 0
	armed := false
	moving := &movingRuns{runs: f.runs, onRead: func() {
		if !armed {
			return
		}
		// The retry left the execution queued; the queue dispatches it
		// before the reviewer's first read of the run.
		if reads++; reads == 1 {
			dispatchRun(f.runs, "run-1")
		}
	}}
	f.runs.retry = func(runID string) error {
		f.runs.requeue(runID)
		armed = true
		return nil
	}
	succeeded, refused := 0, 0
	r := f.executor("executor")
	r.Runs = moving
	r.Registry = queueRule{Registry: f.registry, runs: f.runs, succeeded: &succeeded, refused: &refused}
	out, err := r.Execute(context.Background(), jobID, f.proposal.ID, f.decision.ID)
	require.NoError(t, err)
	assert.Equal(t, review.ActionSucceeded, out.Action.State)
	assert.Equal(t, f.runs.ref("run-1"), out.Action.Receipt)
	assert.Contains(t, out.Action.Detail, "running")
	assert.Equal(t, 1, succeeded)
	assert.Zero(t, refused, "a dispatched execution is not refused")
}

// Still queued when the watch ends: the action is not settled. It stays
// executing with the queued execution recorded, a review while it is still
// queued leaves it so and asks the registry for no success, and the review
// after the queue dispatches it records it as succeeded, once. Reviews after
// that change nothing.
func TestQueuedRetryStillQueuedIsHeldAndSettledAfterDispatch(t *testing.T) {
	f := newRetryFixture(t)
	succeeded, refused := 0, 0
	out, queued := queuedRetry(t, f, &succeeded, &refused)
	assert.Equal(t, review.ActionExecuting, out.Action.State)
	assert.Equal(t, queued, out.Action.AdmittedRef)
	assert.Empty(t, out.Action.Receipt)
	assert.Contains(t, out.Action.Detail, "queued and not yet dispatched")
	assert.Zero(t, succeeded, "no success is asked for while the execution is queued")
	stored := f.state().Actions[jobID][0]
	assert.Equal(t, review.ActionExecuting, stored.State)
	assert.True(t, stored.Admitted)
	assert.Equal(t, queued, stored.AdmittedRef)

	still := reviewOnce(t, f, "reviewer-b", 30*time.Second, &succeeded, &refused)
	assert.Equal(t, review.ActionExecuting, still.State, "still queued: left executing under its grant")
	assert.Equal(t, queued, still.AdmittedRef)
	assert.Zero(t, succeeded)

	dispatchRun(f.runs, "run-1")
	settled := reviewOnce(t, f, "reviewer-c", 30*time.Second, &succeeded, &refused)
	assert.Equal(t, review.ActionSucceeded, settled.State)
	assert.Equal(t, queued, settled.Receipt)
	assert.Contains(t, settled.Detail, "reconciled")
	assert.Equal(t, 1, succeeded)

	// Idempotent: the settled action is not settled again, and does not
	// flip when the execution later finishes.
	setStatus(f.runs, "run-1", "failed", false)
	again := reviewOnce(t, f, "reviewer-d", 30*time.Second, &succeeded, &refused)
	assert.Equal(t, review.ActionSucceeded, again.State)
	assert.Equal(t, queued, again.Receipt)
	assert.Equal(t, 1, succeeded, "no second settlement")
	assert.Zero(t, refused)
	assert.Len(t, f.runs.retried, 1, "nothing is sent again")
}

// The service records that it abandoned the queued execution before
// dispatch, as the coordinator does for a refused retry the queue withdrew:
// the retry is settled as not applied, never as succeeded.
func TestQueuedRetryAbandonedBeforeDispatchIsNotApplied(t *testing.T) {
	f := newRetryFixture(t)
	succeeded := 0
	_, queued := queuedRetry(t, f, &succeeded, nil)
	f.runs.abandonedRefs = map[string]bool{queued: true}
	setStatus(f.runs, "run-1", "failed", false)

	settled := reviewOnce(t, f, "reviewer-b", 30*time.Second, &succeeded)
	assert.Equal(t, review.ActionNotApplied, settled.State)
	assert.Contains(t, settled.Detail, "not dispatched")
	assert.Zero(t, succeeded)
}

// An execution that the queue dispatched and that then aborted ran: it is
// recorded as the retry's effect, by its real outcome, not as not applied.
func TestQueuedRetryStartedThenAbortedIsItsOutcome(t *testing.T) {
	f := newRetryFixture(t)
	_, queued := queuedRetry(t, f, nil, nil)
	setStatus(f.runs, "run-1", "aborted", false)

	settled := reviewOnce(t, f, "reviewer-b", 30*time.Second)
	assert.Equal(t, review.ActionSucceeded, settled.State)
	assert.Equal(t, queued, settled.Receipt)
	assert.Contains(t, settled.Detail, "aborted")
}

// The grant ends while the execution still waits: the registry interrupts
// the action, as today, and queue dispatch refuses the retry. The reviewer
// never records it as succeeded: while it is queued it stays uncertain, and
// once the coordinator records that the withdrawn execution was abandoned
// before dispatch, it is not applied. (TXE-8596, the admission-aborted false
// success.)
func TestQueuedRetryGrantLapseIsNeverASuccess(t *testing.T) {
	f := newRetryFixture(t)
	succeeded, refused := 0, 0
	_, queued := queuedRetry(t, f, &succeeded, &refused)

	lapsed := reviewOnce(t, f, "reviewer-b", 10*time.Minute, &succeeded, &refused)
	assert.Equal(t, review.ActionUncertain, lapsed.State, "interrupted with its grant")
	assert.Equal(t, queued, lapsed.AdmittedRef)
	assert.Zero(t, succeeded, "a queued execution is never offered as a success")

	// Queue admission refuses and withdraws it; the coordinator, finding
	// nothing of it with a worker, records it as abandoned before dispatch,
	// marked failed.
	f.runs.abandonedRefs = map[string]bool{queued: true}
	setStatus(f.runs, "run-1", "failed", false)
	settled := reviewOnce(t, f, "reviewer-c", time.Minute, &succeeded, &refused)
	assert.Equal(t, review.ActionNotApplied, settled.State)
	assert.Zero(t, succeeded)
	assert.Zero(t, refused)
}

// The run's latest execution is no longer the one this attempt's request
// admitted (another caller's retry): nothing is settled from it while the
// grant holds, and no success is recorded.
func TestQueuedRetryAnotherExecutionIsNotThisRetry(t *testing.T) {
	f := newRetryFixture(t)
	succeeded := 0
	_, queued := queuedRetry(t, f, &succeeded, nil)
	f.runs.mu.Lock()
	f.runs.start("run-1")
	f.runs.mu.Unlock()
	require.NotEqual(t, queued, f.runs.ref("run-1"))

	held := reviewOnce(t, f, "reviewer-b", 30*time.Second, &succeeded)
	assert.Equal(t, review.ActionExecuting, held.State)
	assert.Equal(t, queued, held.AdmittedRef)
	assert.Empty(t, held.Receipt)
	assert.Zero(t, succeeded)
}

// A registry from before the rule refuses an executing outcome. The
// reviewer then records the uncertain outcome it recorded before, with the
// admitted execution, and still no success.
func TestQueuedRetryOnAnOlderRegistryIsUncertainNotSucceeded(t *testing.T) {
	f := newRetryFixture(t)
	f.runs.retry = func(runID string) error {
		f.runs.requeue(runID)
		return nil
	}
	r := f.executor("executor")
	r.Registry = noExecutingOutcome{f.registry}
	out, err := r.Execute(context.Background(), jobID, f.proposal.ID, f.decision.ID)
	require.NoError(t, err)
	assert.Equal(t, review.ActionUncertain, out.Action.State)
	assert.Equal(t, f.runs.ref("run-1"), out.Action.AdmittedRef)
	assert.Empty(t, out.Action.Receipt)
}

// noExecutingOutcome refuses an executing outcome as a registry from before
// TXE-8596 does: against the action's state.
type noExecutingOutcome struct{ *reviewtest.Registry }

func (n noExecutingOutcome) FinishAction(ctx context.Context, req review.FinishRequest) error {
	if req.State == review.ActionExecuting {
		return &review.TransportError{Status: 409, Code: "action_state", Message: "cannot settle executing action as executing"}
	}
	return n.Registry.FinishAction(ctx, req)
}
