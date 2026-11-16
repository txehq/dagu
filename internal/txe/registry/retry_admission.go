// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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

// checkRetryRun binds a queued retry to its action as the hub binds a retry
// it admits: the one validator TXE-7517 exports, CheckRetryRun, called with
// the only intent a queued retry can carry, an unspecified (whole-run) retry.
// Until it is wired, it is nil and every queued retry of a registered job is
// refused.
var checkRetryRun func(job *Job, action *Action, q QueuedRetry, now time.Time) error

// queuedRetryForm is the part of a dagu.retry_run action's params that names
// its intent (RetryRunParams Step, and Rerun from TXE-7515): read apart so
// that a field this version does not know cannot be dropped silently.
type queuedRetryForm struct {
	Step  string `json:"step"`
	Rerun bool   `json:"rerun"`
}

// AdmitQueuedRetry decides, when the queue dispatches it, whether a queued
// retry of job jobID's run may run that execution again. A queued retry is
// always a retry of the whole run with no step: Dagu queues no step retry.
// So it carries out only an unspecified dagu.retry_run, the form a person's
// retry has always had. An approval of a republish (step "publish", which
// the hub sends as a retry of that step accepting failed prerequisites) or
// of an explicit rerun (rerun, which the hub sends as a retry of step "run"
// with its downstream) is never carried out as a queued whole-run retry: it
// is refused, not applied, before anything runs. The rest of the binding
// (attempt, binding digest, run and execution, approval, live grant,
// version) is checkRetryRun's, read now rather than when the retry was
// queued. An error is returned only when the registry cannot be read;
// callers must then leave the retry queued.
func (s *Store) AdmitQueuedRetry(ctx context.Context, jobID string, q QueuedRetry) (Admission, error) {
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		if ErrorCode(err) == CodeNotFound {
			return refuseRun(jobID, AdmitUnregistered, "job is not registered"), nil
		}
		return Admission{}, err
	}
	refuse := func(reason string) (Admission, error) {
		return refuseRun(jobID, AdmitRetryNotApproved, "not applied: "+reason), nil
	}
	action := job.Actions[q.Request.ActionID]
	if action != nil && action.Spec.Name == ActionRetryRun {
		var form queuedRetryForm
		if err := json.Unmarshal(action.Spec.Params, &form); err != nil {
			return refuse(fmt.Sprintf("action %s has unreadable params", action.ActionID))
		}
		switch {
		case form.Step == RetryStepPublish:
			return refuse(fmt.Sprintf("action %s was approved as a republish of the sealed result; a queued retry re-runs the whole run, so it is not carried out", action.ActionID))
		case form.Step != "":
			return refuse(fmt.Sprintf("action %s names step %q, which no queued retry carries", action.ActionID, form.Step))
		case form.Rerun:
			return refuse(fmt.Sprintf("action %s was approved as an explicit rerun, which runs only as a retry of step %q with its downstream; a queued retry names no step, so it is not carried out", action.ActionID, "run"))
		}
	}
	if checkRetryRun == nil {
		return refuse("the registry cannot bind a queued retry to its decision in this version")
	}
	if err := checkRetryRun(job, action, q, s.clock()); err != nil {
		if _, ok := errors.AsType[*Error](err); ok {
			return refuse(err.Error())
		}
		return Admission{}, err
	}
	return Admission{Admit: true, JobID: jobID}, nil
}
