// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"errors"
	"fmt"
	"sort"
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

// maxAdmittedRuns bounds the admitted-run record kept on a job.
const maxAdmittedRuns = 200

// AdmitRun decides whether a run of dagName may start. specSHA256 is the
// digest of the run's DAG snapshot; when set it must equal the current
// version's spec, so a run queued under an older version never executes
// after an update. A lifetime that has ended retires the job here, before
// any run can use it. Callers must treat an error as "do not run".
//
// AdmitRun only reads. Where a run is handed to a worker, AdmitClaim records
// the admission so that it is ordered against retirement.
func (s *Store) AdmitRun(ctx context.Context, dagName, specSHA256 string) (Admission, error) {
	if !IsJobDAG(dagName) {
		return Admission{Admit: true}, nil
	}
	job, err := s.currentForAdmission(ctx, dagName)
	if err != nil || job == nil {
		return refuseRun(dagName, AdmitUnregistered, "job is not registered"), err
	}
	return admissionFor(job, specSHA256), nil
}

// AdmitClaim admits a run at the moment a worker takes it, and records the
// run on the job in the same commit. A retirement committed before it makes
// it refuse; one committed after it finds the run on the job and applies the
// job's active-run policy to it, even if Dagu does not yet report it running.
func (s *Store) AdmitClaim(ctx context.Context, dagName, specSHA256, runID string) (Admission, error) {
	if !IsJobDAG(dagName) {
		return Admission{Admit: true}, nil
	}
	job, err := s.currentForAdmission(ctx, dagName)
	if err != nil || job == nil {
		return refuseRun(dagName, AdmitUnregistered, "job is not registered"), err
	}
	var adm Admission
	_, err = s.WithJobTx(ctx, dagName, reconcilerActor, func(tx *JobTx) error {
		adm = admissionFor(tx.Job, specSHA256)
		if !adm.Admit || runID == "" {
			return nil
		}
		if _, ok := tx.Job.AdmittedRuns[runID]; ok {
			return nil
		}
		if tx.Job.AdmittedRuns == nil {
			tx.Job.AdmittedRuns = map[string]time.Time{}
		}
		tx.Job.AdmittedRuns[runID] = tx.now
		pruneAdmitted(tx.Job.AdmittedRuns)
		tx.touch()
		return nil
	})
	return adm, err
}

// currentForAdmission returns the job, retiring it first when its lifetime
// has ended. It returns nil when the job is not registered.
func (s *Store) currentForAdmission(ctx context.Context, jobID string) (*Job, error) {
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		if ErrorCode(err) == CodeNotFound {
			// The registry is the only writer of job DAGs, so a job-named DAG
			// without a record was not registered and must not run.
			return nil, nil
		}
		return nil, err
	}
	if expired(job, s.clock()) {
		return s.retireExpired(ctx, job.JobID)
	}
	return job, nil
}

func admissionFor(job *Job, specSHA256 string) Admission {
	switch {
	case job.Lifecycle == LifecycleRetired:
		code := AdmitRetired
		if job.Retirement != nil && job.Retirement.Reason == RetireExpired {
			code = AdmitExpired
		}
		return refuseRun(job.JobID, code, retirementReason(job))
	case job.Lifecycle == LifecycleCompleted:
		return refuseRun(job.JobID, AdmitCompleted, retirementReason(job))
	case job.Registration.State == RegistrationDuplicate:
		return refuseRun(job.JobID, AdmitDuplicate, "job duplicates another registration")
	case job.Registration.State != RegistrationReady:
		return refuseRun(job.JobID, AdmitNotReady, "registration is "+string(job.Registration.State))
	case job.Lifecycle == LifecyclePaused:
		return refuseRun(job.JobID, AdmitPaused, "job is paused")
	case specSHA256 != "" && specSHA256 != job.DAGSpecSHA256:
		return refuseRun(job.JobID, AdmitSupersededVersion, fmt.Sprintf("run is for another version; current is %d", job.Version))
	}
	return Admission{Admit: true, JobID: job.JobID}
}

func pruneAdmitted(m map[string]time.Time) {
	if len(m) <= maxAdmittedRuns {
		return
	}
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, k int) bool { return m[ids[i]].Before(m[ids[k]]) })
	for _, id := range ids[:len(ids)-maxAdmittedRuns] {
		delete(m, id)
	}
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

// retireExpired retires the job if, inside the retirement commit, its
// current lifetime has ended. A lifetime extended in the meantime wins.
func (s *Store) retireExpired(ctx context.Context, jobID string) (*Job, error) {
	committed, err := s.ChangeLifecycle(ctx, jobID, Transition{
		Op:     OpRetire,
		Reason: RetireExpired,
		Authorize: func(tx *JobTx) error {
			if !expired(tx.Job, tx.now) {
				return refuse(CodeTransition, "lifetime of %s has not ended", jobID)
			}
			return nil
		},
		DetailFor: func(job *Job) string {
			return "lifetime ended at " + job.ExpiresAt.UTC().Format(time.RFC3339)
		},
	}, reconcilerActor)
	if ErrorCode(err) == CodeTransition {
		return s.GetJob(ctx, jobID)
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
		committed, err := s.retireExpired(ctx, job.JobID)
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

// RunControl applies lifecycle changes to Dagu itself. The committed
// lifecycle, enforced by admission, is the authority; RunControl brings
// Dagu's own state in line with it.
type RunControl interface {
	// ActiveRuns lists queued and running runs of the DAG.
	ActiveRuns(ctx context.Context, dagName string) ([]RunRef, error)
	// StopRun asks Dagu to stop a run.
	StopRun(ctx context.Context, dagName, runID string) error
	// IsSuspended reports Dagu's own suspend flag for the DAG.
	IsSuspended(ctx context.Context, dagName string) (bool, error)
	// SetSuspended sets Dagu's own suspend flag for the DAG.
	SetSuspended(ctx context.Context, dagName string, suspended bool) error
}

// WithRunControl lets lifecycle changes suspend DAGs and stop runs.
func WithRunControl(rc RunControl) Option {
	return func(s *Store) { s.runs = rc }
}

// maxEffectAttempts bounds retries of a stop before it becomes an exception.
const maxEffectAttempts = 5

// ChangeLifecycle commits a lifecycle transition and then applies it to
// Dagu. On completion or retirement the job's queued runs are listed as
// dropped (admission refuses them), runs admitted to a worker or running are
// left to finish or, under the cancel policy, recorded as pending stops in
// the same commit. Effects are then applied from the job's current state by
// ApplyEffects; anything not applied is retried by ReconcileEffects, so a
// crash or a store without run control never loses them.
func (s *Store) ChangeLifecycle(ctx context.Context, jobID string, t Transition, by Actor) (*Job, error) {
	stopping := t.Op == OpComplete || t.Op == OpRetire
	var runs []RunRef
	var listErr error
	if stopping && s.runs != nil {
		runs, listErr = s.runs.ActiveRuns(ctx, jobID)
	}
	committed, err := s.WithJobTx(ctx, jobID, by, func(tx *JobTx) error {
		if t.Authorize != nil {
			if err := t.Authorize(tx); err != nil {
				return err
			}
		}
		tt := t
		if t.DetailFor != nil {
			tt.Detail = t.DetailFor(tx.Job)
		}
		if stopping {
			policy := tt.ActiveRunPolicy
			if policy == "" {
				v, err := tx.CurrentVersion()
				if err != nil {
					return err
				}
				policy = v.RetirementRules.ActiveRunPolicy
			}
			tt.ActiveRunPolicy = policy
			affected, stops := runDispositions(runs, tx.Job.AdmittedRuns, policy)
			tt.Affected = append(append([]Affected(nil), t.Affected...), affected...)
			if listErr != nil {
				tt.Detail = strings.TrimSpace(tt.Detail + " (active runs could not be listed: " + listErr.Error() + ")")
			}
			if len(stops) > 0 {
				tx.Job.PendingEffects = &PendingEffects{Revision: tx.Job.Revision + 1, StopRuns: stops, Since: tx.now}
			}
		}
		return tx.Transition(tt)
	})
	if err != nil || s.runs == nil {
		return committed, err
	}
	if err := s.ApplyEffects(ctx, jobID); err != nil {
		// The effects stay pending and are retried by ReconcileEffects.
		return committed, nil
	}
	return s.GetJob(ctx, jobID)
}

// runDispositions lists what happens to each known run and which runs must
// be stopped under the cancel policy. Admitted runs Dagu does not list yet
// are included: a worker may be about to start them.
func runDispositions(runs []RunRef, admitted map[string]time.Time, policy ActiveRunPolicy) ([]Affected, []string) {
	var out []Affected
	var stops []string
	seen := map[string]bool{}
	running := DispositionAllowedToFinish
	if policy == ActiveRunCancel {
		running = DispositionCancelRequested
	}
	for _, r := range runs {
		seen[r.RunID] = true
		switch {
		case r.Running:
			out = append(out, Affected{RunID: r.RunID, Disposition: running})
			if policy == ActiveRunCancel {
				stops = append(stops, r.RunID)
			}
		case admitted[r.RunID] != time.Time{}:
			out = append(out, Affected{RunID: r.RunID, Disposition: DispositionAdmittedBeforeEnd})
			if policy == ActiveRunCancel {
				stops = append(stops, r.RunID)
			}
		default:
			out = append(out, Affected{RunID: r.RunID, Disposition: DispositionQueuedDropped})
		}
	}
	ids := make([]string, 0, len(admitted))
	for id := range admitted {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		out = append(out, Affected{RunID: id, Disposition: DispositionAdmittedBeforeEnd})
		if policy == ActiveRunCancel {
			stops = append(stops, id)
		}
	}
	return out, stops
}

// wantsSuspension reports whether the job's lifecycle forbids new runs.
func wantsSuspension(l Lifecycle) bool {
	return l == LifecyclePaused || l.Terminal()
}

// ApplyEffects brings Dagu in line with the job's current state: the DAG is
// suspended while the job is paused, completed or retired, the registry's
// own suspension is lifted when the job is active again (a person's
// suspension is left alone), and pending stops are attempted. Because the
// desired state is read from the job, an older transition applied late
// cannot undo a newer one. Failed stops stay pending, and become an
// exception after a bounded number of attempts.
func (s *Store) ApplyEffects(ctx context.Context, jobID string) error {
	if s.runs == nil {
		return errors.New("registry: no run control to apply effects")
	}
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	var errs []error
	want := wantsSuspension(job.Lifecycle)
	if want || job.SuspendedByRegistry {
		suspended, err := s.runs.IsSuspended(ctx, jobID)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("read suspension: %w", err))
		case want && !suspended:
			if err := s.runs.SetSuspended(ctx, jobID, true); err != nil {
				errs = append(errs, fmt.Errorf("suspend DAG: %w", err))
			}
		case !want && suspended:
			if err := s.runs.SetSuspended(ctx, jobID, false); err != nil {
				errs = append(errs, fmt.Errorf("unsuspend DAG: %w", err))
			}
		}
	}
	var stopped []Affected
	var failed []string
	var stopErrs []string
	if pe := job.PendingEffects; pe != nil {
		for _, runID := range pe.StopRuns {
			if err := s.runs.StopRun(ctx, jobID, runID); err != nil {
				failed = append(failed, runID)
				stopErrs = append(stopErrs, runID+": "+err.Error())
				stopped = append(stopped, Affected{RunID: runID, Disposition: DispositionStopFailed})
				continue
			}
			stopped = append(stopped, Affected{RunID: runID, Disposition: DispositionStopRequested})
		}
	}
	_, err = s.WithJobTx(ctx, jobID, reconcilerActor, func(tx *JobTx) error {
		j := tx.Job
		if wantsSuspension(j.Lifecycle) == want && j.SuspendedByRegistry != want && len(errs) == 0 {
			j.SuspendedByRegistry = want
			tx.touch()
		}
		pe := job.PendingEffects
		if pe == nil || j.PendingEffects == nil || j.PendingEffects.Revision != pe.Revision {
			return nil
		}
		detail := strings.Join(stopErrs, "; ")
		switch {
		case len(failed) == 0:
			j.PendingEffects = nil
		case j.PendingEffects.Attempts+1 >= maxEffectAttempts:
			j.PendingEffects = nil
			id, err := NewID(PrefixException, tx.now)
			if err != nil {
				return err
			}
			if j.Exceptions == nil {
				j.Exceptions = map[string]*Exception{}
			}
			j.Exceptions[id] = &Exception{ExceptionID: id, Kind: "stop_failed", Detail: "runs could not be stopped after retirement: " + detail,
				Evidence: failed, Created: Stamp{At: tx.now, By: reconcilerActor}}
		default:
			j.PendingEffects.Attempts++
			j.PendingEffects.StopRuns = failed
			j.PendingEffects.LastError = detail
		}
		tx.touch()
		return tx.event(Event{Kind: EventEffect, Reason: "stop_runs", Detail: detail, Affected: stopped})
	})
	errs = append(errs, err)
	if len(failed) > 0 {
		errs = append(errs, fmt.Errorf("stop runs: %s", strings.Join(stopErrs, "; ")))
	}
	return errors.Join(errs...)
}

// ReconcileEffects applies pending or missing lifecycle effects for every
// job: lost after a crash, owed by a process without run control, or undone
// by a late concurrent transition.
func (s *Store) ReconcileEffects(ctx context.Context) error {
	if s.runs == nil {
		return nil
	}
	jobs, err := s.ListJobs(ctx, JobFilter{})
	if err != nil {
		return err
	}
	var errs []error
	for _, job := range jobs {
		if job.PendingEffects == nil && !wantsSuspension(job.Lifecycle) && !job.SuspendedByRegistry {
			continue
		}
		if err := s.ApplyEffects(ctx, job.JobID); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", job.JobID, err))
		}
	}
	return errors.Join(errs...)
}

// RecordDroppedRun notes on the job that a queued or claimed run was
// refused by admission. The run's own Dagu status carries the same reason.
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
