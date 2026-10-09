// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AdmitCode says why a run of a registered job was refused.
type AdmitCode string

const (
	AdmitRetired           AdmitCode = "retired"
	AdmitCompleted         AdmitCode = "completed"
	AdmitPaused            AdmitCode = "paused"
	AdmitExpired           AdmitCode = "expired"
	AdmitNotReady          AdmitCode = "not_ready"
	AdmitDuplicate         AdmitCode = "duplicate"
	AdmitSupersededVersion AdmitCode = "superseded_version"
	AdmitUnregistered      AdmitCode = "unregistered"
)

// Admission is the registry's answer to "may this run of DAG start now?".
type Admission struct {
	Admit  bool
	JobID  string
	Code   AdmitCode
	Reason string
}

// IsJobDAG reports whether a DAG name is a registered-job name. Only such
// DAGs are governed by the registry; every other DAG keeps upstream behaviour.
func IsJobDAG(name string) bool {
	return ValidateID(PrefixJob, name) == nil
}

// AdmitRun decides whether a run of dagName may start. specSHA256 is the
// digest of the run's DAG snapshot; when set it must equal the current
// version's spec, so a run queued under an older version never executes
// after an update. A lifetime that has ended retires the job here, before
// any run can use it. Callers must treat an error as "do not run".
func (s *Store) AdmitRun(ctx context.Context, dagName, specSHA256 string) (Admission, error) {
	if !IsJobDAG(dagName) {
		return Admission{Admit: true}, nil
	}
	job, err := s.GetJob(ctx, dagName)
	if err != nil {
		if ErrorCode(err) == CodeNotFound {
			// The registry is the only writer of job DAGs, so a job-named DAG
			// without a record was not registered and must not run.
			return refuseRun(dagName, AdmitUnregistered, "job is not registered"), nil
		}
		return Admission{}, err
	}
	if expired(job, s.clock()) {
		job, err = s.retireExpired(ctx, job)
		if err != nil {
			return Admission{}, err
		}
	}
	switch {
	case job.Lifecycle == LifecycleRetired:
		code := AdmitRetired
		if job.Retirement != nil && job.Retirement.Reason == RetireExpired {
			code = AdmitExpired
		}
		return refuseRun(dagName, code, retirementReason(job)), nil
	case job.Lifecycle == LifecycleCompleted:
		return refuseRun(dagName, AdmitCompleted, retirementReason(job)), nil
	case job.Registration.State == RegistrationDuplicate:
		return refuseRun(dagName, AdmitDuplicate, "job duplicates "+job.Registration.DuplicateOf), nil
	case job.Registration.State != RegistrationReady:
		return refuseRun(dagName, AdmitNotReady, "registration is "+string(job.Registration.State)), nil
	case job.Lifecycle == LifecyclePaused:
		return refuseRun(dagName, AdmitPaused, "job is paused"), nil
	case specSHA256 != "" && specSHA256 != job.DAGSpecSHA256:
		return refuseRun(dagName, AdmitSupersededVersion, fmt.Sprintf("run was queued for another version; current is %d", job.Version)), nil
	}
	return Admission{Admit: true, JobID: dagName}, nil
}

func refuseRun(jobID string, code AdmitCode, reason string) Admission {
	return Admission{JobID: jobID, Code: code, Reason: reason}
}

func retirementReason(job *Job) string {
	if job.Retirement == nil {
		return "job is " + string(job.Lifecycle)
	}
	reason := "job " + string(job.Lifecycle) + ": " + string(job.Retirement.Reason)
	if job.Retirement.Detail != "" {
		reason += " (" + job.Retirement.Detail + ")"
	}
	return reason
}

func expired(job *Job, now time.Time) bool {
	return job.ExpiresAt != nil && !now.Before(*job.ExpiresAt) && !job.Lifecycle.Terminal()
}

var reconcilerActor = Actor{Kind: ActorReconciler, ID: "registry"}

func (s *Store) retireExpired(ctx context.Context, job *Job) (*Job, error) {
	committed, err := s.ChangeLifecycle(ctx, job.JobID, Transition{
		Op:     OpRetire,
		Reason: RetireExpired,
		Detail: "lifetime ended at " + job.ExpiresAt.UTC().Format(time.RFC3339),
	}, reconcilerActor)
	if ErrorCode(err) == CodeTransition {
		// Another writer ended the job first.
		return s.GetJob(ctx, job.JobID)
	}
	return committed, err
}

// ReconcileExpired retires every job whose lifetime has ended and returns
// their IDs. It is safe to run repeatedly and concurrently.
func (s *Store) ReconcileExpired(ctx context.Context) ([]string, error) {
	jobs, err := s.ListJobs(ctx, JobFilter{})
	if err != nil {
		return nil, err
	}
	now := s.clock()
	var retired []string
	var errs []error
	for _, job := range jobs {
		if !expired(job, now) {
			continue
		}
		committed, err := s.retireExpired(ctx, job)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", job.JobID, err))
			continue
		}
		if committed.Lifecycle == LifecycleRetired {
			retired = append(retired, job.JobID)
		}
	}
	return retired, errors.Join(errs...)
}

// RunRef is a queued or running run of a job's DAG.
type RunRef struct {
	RunID   string
	Running bool
}

// RunControl applies lifecycle changes to Dagu itself. Every method is
// best-effort after the registry commit: the committed lifecycle, enforced
// by AdmitRun, is the authority, and a failure is recorded on the job.
type RunControl interface {
	// ActiveRuns lists queued and running runs of the DAG.
	ActiveRuns(ctx context.Context, dagName string) ([]RunRef, error)
	// StopRun asks Dagu to stop a running run.
	StopRun(ctx context.Context, dagName, runID string) error
	// SetSuspended sets Dagu's own suspend flag for the DAG.
	SetSuspended(ctx context.Context, dagName string, suspended bool) error
}

// WithRunControl lets lifecycle changes suspend DAGs and stop runs.
func WithRunControl(rc RunControl) Option {
	return func(s *Store) { s.runs = rc }
}

// ChangeLifecycle commits a lifecycle transition and then applies it to
// Dagu. On completion or retirement the job's queued runs are listed as
// dropped (AdmitRun refuses them before they start) and its running runs are
// left to finish or asked to stop, as the job's active-run policy says; the
// DAG is suspended so nothing new is scheduled. Resuming or reactivating
// lifts the suspension. Effects that fail are recorded as a job event.
func (s *Store) ChangeLifecycle(ctx context.Context, jobID string, t Transition, by Actor) (*Job, error) {
	stopping := t.Op == OpComplete || t.Op == OpRetire
	var runs []RunRef
	var listErr error
	if stopping && s.runs != nil {
		runs, listErr = s.runs.ActiveRuns(ctx, jobID)
	}
	var policy ActiveRunPolicy
	committed, err := s.WithJobTx(ctx, jobID, by, func(tx *JobTx) error {
		tt := t
		if stopping {
			policy = tt.ActiveRunPolicy
			if policy == "" {
				v, err := tx.CurrentVersion()
				if err != nil {
					return err
				}
				policy = v.RetirementRules.ActiveRunPolicy
			}
			tt.ActiveRunPolicy = policy
			tt.Affected = append(append([]Affected(nil), t.Affected...), runDispositions(runs, policy)...)
			if listErr != nil {
				tt.Detail = strings.TrimSpace(tt.Detail + " (active runs could not be listed: " + listErr.Error() + ")")
			}
		}
		return tx.Transition(tt)
	})
	if err != nil || s.runs == nil {
		return committed, err
	}
	var failures []string
	switch t.Op {
	case OpPause, OpComplete, OpRetire:
		if err := s.runs.SetSuspended(ctx, jobID, true); err != nil {
			failures = append(failures, "suspend DAG: "+err.Error())
		}
	case OpResume, OpReactivate:
		if err := s.runs.SetSuspended(ctx, jobID, false); err != nil {
			failures = append(failures, "unsuspend DAG: "+err.Error())
		}
	case OpNeedsHuman:
	}
	var stopped []Affected
	if stopping && policy == ActiveRunCancel {
		for _, r := range runs {
			if !r.Running {
				continue
			}
			if err := s.runs.StopRun(ctx, jobID, r.RunID); err != nil {
				failures = append(failures, "stop run "+r.RunID+": "+err.Error())
				stopped = append(stopped, Affected{RunID: r.RunID, Disposition: DispositionStopFailed})
				continue
			}
			stopped = append(stopped, Affected{RunID: r.RunID, Disposition: DispositionStopRequested})
		}
	}
	if len(failures) == 0 && len(stopped) == 0 {
		return committed, nil
	}
	return s.WithJobTx(ctx, jobID, reconcilerActor, func(tx *JobTx) error {
		return tx.event(Event{Kind: EventEffect, Reason: string(t.Op), Detail: strings.Join(failures, "; "), Affected: stopped})
	})
}

func runDispositions(runs []RunRef, policy ActiveRunPolicy) []Affected {
	var out []Affected
	for _, r := range runs {
		d := DispositionQueuedDropped
		if r.Running {
			d = DispositionAllowedToFinish
			if policy == ActiveRunCancel {
				d = DispositionCancelRequested
			}
		}
		out = append(out, Affected{RunID: r.RunID, Disposition: d})
	}
	return out
}

// RecordDroppedRun notes on the job that a queued or claimed run was
// refused by AdmitRun. The run's own Dagu status carries the same reason.
func (s *Store) RecordDroppedRun(ctx context.Context, jobID, runID string, adm Admission) error {
	if !IsJobDAG(jobID) {
		return nil
	}
	_, err := s.WithJobTx(ctx, jobID, reconcilerActor, func(tx *JobTx) error {
		return tx.event(Event{Kind: EventRunDropped, Reason: string(adm.Code), Detail: adm.Reason,
			Affected: []Affected{{RunID: runID, Disposition: DispositionQueuedDropped}}})
	})
	if ErrorCode(err) == CodeNotFound {
		return nil
	}
	return err
}
