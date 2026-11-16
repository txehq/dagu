// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"strconv"
	"time"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

// RetryForm is how a retry of a registered job's run is carried out: which
// part of the run it executes again.
type RetryForm string

const (
	// RetryFormWholeRun retries the run with no step named. Dagu then keeps
	// every step that succeeded, so a run whose job step succeeded runs only
	// its publish step again.
	RetryFormWholeRun RetryForm = "whole_run"
	// RetryFormFromJobStep retries the job's step and everything after it
	// (stepName txepkg.RunStepName, includeDownstream): the job runs again
	// whatever the failed execution did.
	RetryFormFromJobStep RetryForm = "from_job_step"
	// RetryFormPublish retries the publish step alone, taking its failed
	// prerequisite as done (stepName RetryStepPublish,
	// acceptFailedPrerequisites): the sealed result is published and the job
	// is not run again.
	RetryFormPublish RetryForm = "publish"
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

// approvedRetryForm is the one form a decision with params p is carried
// out in: a republish only as the publish step alone; an explicit rerun
// only from the job's step, so the job runs again even when its step had
// succeeded (a retry with no step would keep that step and publish the old
// seal); a retry that names neither only as a retry of the whole run.
func approvedRetryForm(p RetryRunParams) RetryForm {
	switch p.Intent() {
	case RetryIntentRepublish:
		return RetryFormPublish
	case RetryIntentRerun:
		return RetryFormFromJobStep
	}
	return RetryFormWholeRun
}

// CheckRetryRun decides whether a retry of runID's execution expected,
// made for request and carried out in form, carries out action as job
// holds it now (action is nil when the job has none by the id the request
// names). It is the one binding every admission of a registered job's retry
// applies (TXE-7517):
//
//   - action is a dagu.retry_run, carried out in the one form its params
//     approve (approvedRetryForm), never another;
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
func CheckRetryRun(job *Job, action *Action, runID string, expected RetriedExecution, request RetryActionRequest, form RetryForm, now time.Time) error {
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
	switch form {
	case RetryFormWholeRun, RetryFormFromJobStep, RetryFormPublish:
	default:
		return stale("retry form %q is not one a decision is carried out in", form)
	}
	approved := approvedRetryForm(params)
	switch {
	case params.Step != "" && params.Step != RetryStepPublish:
		return stale("action %s retries step %q; only %q is a step a decision retries", action.ActionID, params.Step, RetryStepPublish)
	case params.Step != "" && params.Rerun:
		return stale("action %s both republishes and runs the job again; it is carried out as neither", action.ActionID)
	case approved != form:
		return stale("action %s was approved as %s; it is carried out only as one (%s), not as %s", action.ActionID, approved.describe(), approved.request(), form.describe())
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

func (f RetryForm) describe() string {
	switch f {
	case RetryFormPublish:
		return "a republish of the sealed result"
	case RetryFormFromJobStep:
		return "a rerun of the job"
	case RetryFormWholeRun:
		return "a retry of the run"
	}
	return string(f)
}

// request is how a retry in form f is asked of Dagu.
func (f RetryForm) request() string {
	switch f {
	case RetryFormPublish:
		return "stepName " + strconv.Quote(RetryStepPublish) + ", acceptFailedPrerequisites"
	case RetryFormFromJobStep:
		return "stepName " + strconv.Quote(txepkg.RunStepName) + ", includeDownstream"
	case RetryFormWholeRun:
		return "no stepName"
	}
	return string(f)
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
