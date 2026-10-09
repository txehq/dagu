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
	// AdmitNotOnWorker refuses executing a job anywhere but through its
	// machine's worker, where the claim is admitted and recorded.
	AdmitNotOnWorker AdmitCode = "not_on_worker"
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
// AdmitRun only reads. Registered jobs execute only through a worker claim,
// and AdmitClaim records that admission so it is ordered against retirement.
func (s *Store) AdmitRun(ctx context.Context, dagName, specSHA256 string) (Admission, error) {
	if !IsJobDAG(dagName) {
		return Admission{Admit: true}, nil
	}
	job, err := s.currentForAdmission(ctx, dagName)
	if err != nil || job == nil {
		return refuseRun(dagName, AdmitUnregistered, "job is not registered"), err
	}
	return admissionFor(job, specSHA256, s.clock()), nil
}

// AdmitClaim admits a run at the moment a worker takes it, and records the
// run on the job in the same commit, which also re-checks the lifetime. A
// retirement committed before it makes it refuse; one committed after it
// finds the run on the job and applies the job's active-run policy to it,
// even if Dagu does not yet report it running.
func (s *Store) AdmitClaim(ctx context.Context, dagName, specSHA256 string, run RunRef) (Admission, error) {
	if !IsJobDAG(dagName) {
		return Admission{Admit: true}, nil
	}
	job, err := s.currentForAdmission(ctx, dagName)
	if err != nil || job == nil {
		return refuseRun(dagName, AdmitUnregistered, "job is not registered"), err
	}
	var adm Admission
	_, err = s.WithJobTx(ctx, dagName, reconcilerActor, func(tx *JobTx) error {
		adm = admissionFor(tx.Job, specSHA256, tx.now)
		if !adm.Admit || run.RunID == "" {
			return nil
		}
		if _, ok := tx.Job.AdmittedRuns[run.RunID]; ok {
			return nil
		}
		if tx.Job.AdmittedRuns == nil {
			tx.Job.AdmittedRuns = map[string]AdmittedRun{}
		}
		tx.Job.AdmittedRuns[run.RunID] = AdmittedRun{At: tx.now, RootName: run.RootName, RootRunID: run.RootRunID}
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

func admissionFor(job *Job, specSHA256 string, now time.Time) Admission {
	switch {
	case job.Lifecycle == LifecycleRetired:
		code := AdmitRetired
		if job.Retirement != nil && job.Retirement.Reason == RetireExpired {
			code = AdmitExpired
		}
		return refuseRun(job.JobID, code, retirementReason(job))
	case job.Lifecycle == LifecycleCompleted:
		return refuseRun(job.JobID, AdmitCompleted, retirementReason(job))
	case expired(job, now):
		return refuseRun(job.JobID, AdmitExpired, "lifetime ended at "+job.ExpiresAt.UTC().Format(time.RFC3339))
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

func pruneAdmitted(m map[string]AdmittedRun) {
	if len(m) <= maxAdmittedRuns {
		return
	}
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, k int) bool { return m[ids[i]].At.Before(m[ids[k]].At) })
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

// RunControl applies lifecycle changes to Dagu itself. The committed
// lifecycle, enforced by admission, is the authority; RunControl brings
// Dagu's own state in line with it.
type RunControl interface {
	// ActiveRuns lists queued and running runs of the DAG.
	ActiveRuns(ctx context.Context, dagName string) ([]RunRef, error)
	// StopRun asks Dagu to stop a run, a child run when run names its root.
	StopRun(ctx context.Context, dagName string, run RunRef) error
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
			discover := listErr != nil && policy == ActiveRunCancel
			if len(stops) > 0 || discover {
				tx.Job.PendingEffects = &PendingEffects{Revision: tx.Job.Revision + 1, StopRuns: stops, DiscoverRuns: discover, Since: tx.now}
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
func runDispositions(runs []RunRef, admitted map[string]AdmittedRun, policy ActiveRunPolicy) ([]Affected, []RunRef) {
	var out []Affected
	var stops []RunRef
	seen := map[string]bool{}
	running := DispositionAllowedToFinish
	if policy == ActiveRunCancel {
		running = DispositionCancelRequested
	}
	for _, r := range runs {
		seen[r.RunID] = true
		a, wasAdmitted := admitted[r.RunID]
		switch {
		case r.Running:
			out = append(out, Affected{RunID: r.RunID, Disposition: running})
		case wasAdmitted:
			out = append(out, Affected{RunID: r.RunID, Disposition: DispositionAdmittedBeforeEnd})
			r.RootName, r.RootRunID = a.RootName, a.RootRunID
		default:
			out = append(out, Affected{RunID: r.RunID, Disposition: DispositionQueuedDropped})
			continue
		}
		if policy == ActiveRunCancel {
			stops = append(stops, r)
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
			a := admitted[id]
			stops = append(stops, RunRef{RunID: id, RootName: a.RootName, RootRunID: a.RootRunID})
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
// own suspension is lifted when the job is active again (a suspension it did
// not make is left alone), and pending stops are attempted. Failed stops stay
// pending and become an exception after a bounded number of attempts.
func (s *Store) ApplyEffects(ctx context.Context, jobID string) error {
	if s.runs == nil {
		return errors.New("registry: no run control to apply effects")
	}
	return errors.Join(s.reconcileSuspension(ctx, jobID), s.applyPendingStops(ctx, jobID))
}

// reconcileSuspension owns a suspension only when it makes it: ownership is
// recorded before the write, and refused if the job no longer wants to be
// suspended; after the write the job is read again and a write made stale by
// a newer transition is undone. Whatever interleaving remains is corrected
// by the next reconciliation, which compares the job with Dagu again.
func (s *Store) reconcileSuspension(ctx context.Context, jobID string) error {
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	suspended, err := s.runs.IsSuspended(ctx, jobID)
	if err != nil {
		return fmt.Errorf("read suspension: %w", err)
	}
	want := wantsSuspension(job.Lifecycle)
	switch {
	case want && !suspended:
		owned := false
		if _, err := s.WithJobTx(ctx, jobID, reconcilerActor, func(tx *JobTx) error {
			owned = wantsSuspension(tx.Job.Lifecycle)
			if owned && !tx.Job.SuspendedByRegistry {
				tx.Job.SuspendedByRegistry = true
				tx.touch()
			}
			return nil
		}); err != nil || !owned {
			return err
		}
		if err := s.runs.SetSuspended(ctx, jobID, true); err != nil {
			return fmt.Errorf("suspend DAG: %w", err)
		}
		current, err := s.GetJob(ctx, jobID)
		if err != nil {
			return err
		}
		if wantsSuspension(current.Lifecycle) {
			return nil
		}
		if err := s.runs.SetSuspended(ctx, jobID, false); err != nil {
			return fmt.Errorf("undo stale suspension: %w", err)
		}
		return s.releaseSuspension(ctx, jobID)
	case !want && job.SuspendedByRegistry:
		if suspended {
			if err := s.runs.SetSuspended(ctx, jobID, false); err != nil {
				return fmt.Errorf("unsuspend DAG: %w", err)
			}
		}
		return s.releaseSuspension(ctx, jobID)
	}
	return nil
}

// releaseSuspension drops the registry's ownership of the DAG's suspension
// while the job is active.
func (s *Store) releaseSuspension(ctx context.Context, jobID string) error {
	_, err := s.WithJobTx(ctx, jobID, reconcilerActor, func(tx *JobTx) error {
		if !wantsSuspension(tx.Job.Lifecycle) && tx.Job.SuspendedByRegistry {
			tx.Job.SuspendedByRegistry = false
			tx.touch()
		}
		return nil
	})
	return err
}

// applyPendingStops stops the runs a completed or retired job still owes
// under the cancel policy, listing them first when that failed at the time.
func (s *Store) applyPendingStops(ctx context.Context, jobID string) error {
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	pe := job.PendingEffects
	if pe == nil {
		return nil
	}
	stops := append([]RunRef(nil), pe.StopRuns...)
	discovered := false
	var errs []string
	if pe.DiscoverRuns {
		runs, err := s.runs.ActiveRuns(ctx, jobID)
		if err != nil {
			errs = append(errs, "list runs: "+err.Error())
		} else {
			discovered = true
			have := map[string]bool{}
			for _, r := range stops {
				have[r.RunID] = true
			}
			for _, r := range runs {
				if r.Running && !have[r.RunID] {
					stops = append(stops, r)
				}
			}
		}
	}
	var affected []Affected
	var failed []RunRef
	for _, r := range stops {
		if err := s.runs.StopRun(ctx, jobID, r); err != nil {
			failed = append(failed, r)
			errs = append(errs, r.RunID+": "+err.Error())
			affected = append(affected, Affected{RunID: r.RunID, Disposition: DispositionStopFailed})
			continue
		}
		affected = append(affected, Affected{RunID: r.RunID, Disposition: DispositionStopRequested})
	}
	detail := strings.Join(errs, "; ")
	_, err = s.WithJobTx(ctx, jobID, reconcilerActor, func(tx *JobTx) error {
		j := tx.Job
		if j.PendingEffects == nil || j.PendingEffects.Revision != pe.Revision {
			return nil
		}
		discover := pe.DiscoverRuns && !discovered
		switch {
		case len(failed) == 0 && !discover:
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
			evidence := make([]string, 0, len(failed))
			for _, r := range failed {
				evidence = append(evidence, r.RunID)
			}
			j.Exceptions[id] = &Exception{ExceptionID: id, Kind: "stop_failed", Detail: "runs could not be stopped after the job ended: " + detail,
				Evidence: evidence, Created: Stamp{At: tx.now, By: reconcilerActor}}
		default:
			j.PendingEffects.Attempts++
			j.PendingEffects.StopRuns = failed
			j.PendingEffects.DiscoverRuns = discover
			j.PendingEffects.LastError = detail
		}
		tx.touch()
		if len(affected) == 0 && detail == "" {
			return nil
		}
		return tx.event(Event{Kind: EventEffect, Reason: "stop_runs", Detail: detail, Affected: affected})
	})
	if err != nil {
		return err
	}
	if detail != "" {
		return fmt.Errorf("stop runs: %s", detail)
	}
	return nil
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
