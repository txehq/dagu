// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"strconv"
	"time"
)

// RetryIntent is what a retry of a registered job's run is carried out as.
type RetryIntent string

const (
	// RetryIntentRerun runs the whole run again: a dagu.retry_run approved
	// with no step.
	RetryIntentRerun RetryIntent = "rerun"
	// RetryIntentPublish publishes what the retried execution sealed and
	// never runs the job again: a dagu.retry_run approved with step
	// RetryStepPublish.
	RetryIntentPublish RetryIntent = "publish"
)

// RetriedExecution names the execution of a run a retry is made for, as Dagu
// stores it.
type RetriedExecution struct {
	AttemptID string
	QueuedAt  string
}

// RetryActionRequest is the action attempt a retry says it is made for: the
// attempt number, as Dagu records it, and the binding digest.
type RetryActionRequest struct {
	ActionAttempt string
	BindingDigest string
}

// CheckRetryRun decides whether a retry of runID's execution expected,
// made for request, carries out action as job holds it now (action is nil
// when the job has none by the id the request names). It is the one
// binding every admission of a registered job's retry applies (TXE-7517):
//
//   - action is a dagu.retry_run approved for intent: step RetryStepPublish
//     for RetryIntentPublish, no step for RetryIntentRerun, and never the
//     other;
//   - request names its current attempt and binding digest;
//   - it was approved for this run and this execution;
//   - it is a person's approved decision: an approved action whose
//     proposal, still on the job while the action is in flight, was decided
//     by a person with the decision the action names;
//   - it is executing that attempt now, under its live grant;
//   - it was approved for the job's current version, and its binding,
//     recomputed from the job as it is now, is the one approved.
//
// A nil result admits the retry. A refusal is an *Error with
// CodeStaleBinding whose message says which condition failed. Checks of
// the DAG the retry runs, such as a republish's generated publish step,
// are the caller's.
func CheckRetryRun(job *Job, action *Action, runID string, expected RetriedExecution, request RetryActionRequest, intent RetryIntent, now time.Time) error {
	jobID := job.JobID
	stale := func(format string, args ...any) error { return refuse(CodeStaleBinding, format, args...) }
	if action == nil || action.Spec.Name != ActionRetryRun {
		return stale("retryRequest names no %s action of job %s", ActionRetryRun, jobID)
	}
	// Not decoded strictly: a field added to the params later is part of
	// the binding the digest is recomputed over, not a reason to refuse.
	var params RetryRunParams
	if err := json.Unmarshal(action.Spec.Params, &params); err != nil {
		return stale("action %s has unreadable params", action.ActionID)
	}
	publishOnly := params.Step == RetryStepPublish
	switch {
	case params.Step != "" && !publishOnly:
		return stale("action %s retries step %q; only %q is a step a decision retries", action.ActionID, params.Step, RetryStepPublish)
	case intent != RetryIntentPublish && intent != RetryIntentRerun:
		return stale("retry intent %q is neither %q nor %q", intent, RetryIntentRerun, RetryIntentPublish)
	case publishOnly && intent != RetryIntentPublish:
		return stale("action %s was approved as a republish of the sealed result; it is carried out only as one (stepName %q, acceptFailedPrerequisites)", action.ActionID, RetryStepPublish)
	case !publishOnly && intent != RetryIntentRerun:
		return stale("action %s was approved as a retry of the run, not a republish of its sealed result", action.ActionID)
	case strconv.Itoa(action.Attempt) != request.ActionAttempt || action.BindingDigest != request.BindingDigest:
		return stale("retryRequest does not name the current attempt and binding of action %s", action.ActionID)
	case params.RunID != runID || params.AttemptID != expected.AttemptID || params.QueuedAt != expected.QueuedAt:
		return stale("action %s was approved for another run or execution", action.ActionID)
	case action.Kind != ActionApproved || !personDecided(job, action):
		return stale("action %s is not a person's approved decision", action.ActionID)
	case action.State != ActionExecuting || action.Grant == nil || action.Grant.Attempt != action.Attempt || !now.Before(action.Grant.ExpiresAt):
		return stale("action %s is not executing attempt %d under a live grant", action.ActionID, action.Attempt)
	case action.JobVersion != job.Version:
		return stale("action %s was approved for version %d of job %s, which is now at version %d", action.ActionID, action.JobVersion, jobID, job.Version)
	}
	// Recomputed as the registry computes it, so that an approval of
	// another version, package or action cannot pass as this one's.
	current, err := BindingDigest(job, action.Spec)
	if err != nil || current != action.BindingDigest {
		return stale("action %s no longer binds job %s as it is now", action.ActionID, jobID)
	}
	return nil
}

// personDecided reports whether action carries out the decision a person
// recorded on its proposal. While the action is in flight its proposal
// stays on the job (proposalInFlight), decided by the decision the action
// names, with a verdict that makes it executable (approvedAction).
func personDecided(job *Job, action *Action) bool {
	p := job.Proposals[action.ProposalID]
	if p == nil || p.Decision == nil {
		return false
	}
	d := p.Decision
	return d.DecisionID == action.DecisionID && d.Actor.Kind == ActorHuman &&
		(d.Verdict == VerdictApprove || d.Verdict == VerdictRetry)
}
