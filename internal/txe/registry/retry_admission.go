// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

// Refusals of a queued retry of a registered job's run (TXE-7518). A queued
// retry runs an execution of the job again; it starts only for the retry
// request of a person's approved dagu.retry_run decision, recorded on the
// queued status by the hub that admitted it, and only while that decision
// still binds when the queue dispatches it.
const (
	// AdmitRetryUnbound refuses a queued retry that carries no retry request:
	// nothing approved it. The local CLI cannot carry one.
	AdmitRetryUnbound AdmitCode = "retry_unbound"
	// AdmitRetryMismatch refuses a queued retry whose retry request was not
	// made for this run's retried execution: it names no execution of the
	// run, or its ID is not the one the hub derives for it.
	AdmitRetryMismatch AdmitCode = "retry_request_mismatch"
	// AdmitRetryNotApproved refuses a queued retry whose request no longer
	// binds an approved dagu.retry_run action to rerun this execution: the
	// action is unknown, another attempt, for another version, run or
	// execution, not executing under a live grant (it may have expired while
	// the retry waited), or approved for another intent.
	AdmitRetryNotApproved AdmitCode = "retry_not_approved"
)

// QueuedRetry is a queued retry of a registered job's run as queue dispatch
// found it: the run, the execution the retry replaced (AttemptID and
// QueuedAt, which the action's params must name), and the retry request the
// queued status records, already checked to be the one derived for that
// execution (ir.NewRetryRequest).
type QueuedRetry struct {
	RunID     string
	AttemptID string
	QueuedAt  string
	Request   ir.RetryRequest
}

// AdmitQueuedRetry decides, when the queue dispatches it, whether a queued
// retry of job jobID's run may run that execution again. It applies the one
// binding every admission of a registered job's retry applies,
// CheckRetryRun, to the job and action as they are now, not as they were
// when the retry was queued. A queued retry is always a retry of the whole
// run with no step (Dagu queues no step retry), so it is checked as
// RetryFormWholeRun: an approval of a republish or of an explicit rerun is
// refused, not applied, and never coerced into a whole-run retry, and a
// grant that lapsed while the retry waited refuses it. An error is returned
// only when the registry cannot be read; callers must then leave the retry
// queued.
func (s *Store) AdmitQueuedRetry(ctx context.Context, jobID string, q QueuedRetry) (Admission, error) {
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		if ErrorCode(err) == CodeNotFound {
			return refuseRun(jobID, AdmitUnregistered, "job is not registered"), nil
		}
		return Admission{}, err
	}
	err = CheckRetryRun(job, job.Actions[q.Request.ActionID], q.RunID,
		RetriedExecution{AttemptID: q.AttemptID, QueuedAt: q.QueuedAt},
		RetryActionRequest{ActionAttempt: q.Request.ActionAttempt, BindingDigest: q.Request.BindingDigest},
		RetryFormWholeRun, s.clock())
	if err != nil {
		return refuseRun(jobID, AdmitRetryNotApproved, "not applied: "+err.Error()), nil
	}
	return Admission{Admit: true, JobID: jobID}, nil
}
