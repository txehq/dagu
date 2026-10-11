// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/persis"
)

type fakeRuns struct {
	mu        sync.Mutex
	runs      map[string][]RunRef
	stopped   []string
	suspended map[string]bool
	stopErr   error
	listErr   error
	// onSuspend runs after a suspend write, outside the lock.
	onSuspend func(dag string)
	// finished are run IDs RunFinished reports terminal; others are active.
	finished map[string]bool
	// onFinished runs after RunFinished answers, outside the lock.
	onFinished func()
	// unsuspendErr fails writes that lift a suspension.
	unsuspendErr error
	// onUnsuspend runs after a write lifting a suspension, outside the lock.
	onUnsuspend func(dag string)
	// attempts are the latest attempts of runs, by run ID.
	attempts map[string]RunAttempt
}

func (r *fakeRuns) LatestAttempt(_ context.Context, _, runID string) (RunAttempt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.attempts[runID]
	if !ok {
		return RunAttempt{}, ErrRunNotFound
	}
	return a, nil
}

// failedAttempt is a finished, unsuccessful attempt of a run of spec.
func failedAttempt(id, spec string) RunAttempt {
	return RunAttempt{AttemptID: id, SpecSHA256: spec, Status: "failed", Finished: true}
}

func (r *fakeRuns) RunFinished(_ context.Context, _ string, run RunRef) (bool, error) {
	r.mu.Lock()
	done, ok := r.finished[run.RunID]
	hook := r.onFinished
	r.mu.Unlock()
	if hook != nil {
		hook()
	}
	if !ok {
		return false, ErrRunNotFound
	}
	return done, nil
}

func newFakeRuns() *fakeRuns {
	return &fakeRuns{runs: map[string][]RunRef{}, suspended: map[string]bool{}}
}

func (r *fakeRuns) ActiveRuns(_ context.Context, dag string) ([]RunRef, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listErr != nil {
		return nil, r.listErr
	}
	return append([]RunRef(nil), r.runs[dag]...), nil
}

func (r *fakeRuns) StopRun(_ context.Context, dag string, run RunRef) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopErr != nil {
		return r.stopErr
	}
	name := dag + "/" + run.RunID
	if run.RootRunID != "" {
		name = run.RootName + "/" + run.RootRunID + ">" + name
	}
	r.stopped = append(r.stopped, name)
	return nil
}

func (r *fakeRuns) IsSuspended(_ context.Context, dag string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.suspended[dag], nil
}

func (r *fakeRuns) SetSuspended(_ context.Context, dag string, suspended bool) error {
	r.mu.Lock()
	if !suspended && r.unsuspendErr != nil {
		r.mu.Unlock()
		return r.unsuspendErr
	}
	r.suspended[dag] = suspended
	hook := r.onSuspend
	if !suspended {
		hook = r.onUnsuspend
	}
	r.mu.Unlock()
	if hook != nil {
		hook(dag)
	}
	return nil
}

func withRuns(f *fixture) *fakeRuns {
	rc := newFakeRuns()
	f.store.runs = rc
	return rc
}

// readyWith registers and readies a job whose first version is changed by mutate.
func (f *fixture) readyWith(jobKey string, mutate func(v *JobVersion)) *Job {
	f.t.Helper()
	jobID := f.mint(PrefixJob)
	v := f.version(1)
	mutate(&v)
	_, err := f.store.Register(f.ctx, RegisterInput{
		JobID: jobID, RequestID: "req-" + jobID, OwnerID: f.owner, ProjectID: f.project, MachineID: f.machine,
		JobKey: jobKey, Version: v,
	}, cli)
	require.NoError(f.t, err)
	saved, err := f.store.GetVersion(f.ctx, jobID, 1)
	require.NoError(f.t, err)
	_, err = f.store.MarkReady(f.ctx, jobID, 0, PackageEvidence{Digest: saved.Package.Digest, Path: saved.Package.Path, MachineID: f.machine}, cli)
	require.NoError(f.t, err)
	job, err := f.store.GetJob(f.ctx, jobID)
	require.NoError(f.t, err)
	return job
}

func target(uid string) Target {
	return Target{Kind: "kubernetes.volume", Environment: "dev", StableID: map[string]string{"cluster_uid": "c-1", "uid": uid}, DisplayName: "pvc-" + uid}
}

func (f *fixture) admit(jobID, spec string) Admission {
	f.t.Helper()
	adm, err := f.store.AdmitRun(f.ctx, jobID, spec)
	require.NoError(f.t, err)
	return adm
}

func TestAdmitRun(t *testing.T) {
	f := newFixture(t)
	assert.True(t, f.admit("ordinary-dag", "").Admit, "unregistered DAG names keep upstream behaviour")
	assert.Equal(t, AdmitUnregistered, f.admit(f.mint(PrefixJob), "").Code, "a job-named DAG without a record never runs")

	pending := f.register("pending")
	assert.Equal(t, AdmitNotReady, f.admit(pending.JobID, "").Code)

	job := f.ready("k")
	adm := f.admit(job.JobID, job.DAGSpecSHA256)
	assert.True(t, adm.Admit)
	assert.Equal(t, AdmitSupersededVersion, f.admit(job.JobID, "sha256:"+strings64("0")).Code, "a run queued for another version is refused")

	_, err := f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpPause}, person)
	require.NoError(t, err)
	assert.Equal(t, AdmitPaused, f.admit(job.JobID, "").Code)
	_, err = f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpResume}, person)
	require.NoError(t, err)

	_, err = f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpNeedsHuman, Detail: "ambiguous"}, agent)
	require.NoError(t, err)
	assert.True(t, f.admit(job.JobID, "").Admit, "checks keep running while a person is asked")
}

func strings64(c string) string {
	out := ""
	for range 64 {
		out += c
	}
	return out
}

// IT-13: completion, expiry and manual retirement each record a distinct
// reason, stop queued work, and keep the running run per the policy.
func TestRetirementReasonsAndRunPolicy(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)

	finish := f.ready("validation")
	rc.runs[finish.JobID] = []RunRef{{RunID: "r-queued"}, {RunID: "r-running", Running: true}}
	done, err := f.store.ChangeLifecycle(f.ctx, finish.JobID, Transition{Op: OpComplete, Detail: "success criteria met", Evidence: []string{"run:r-9"}}, agent)
	require.NoError(t, err)
	assert.Equal(t, LifecycleCompleted, done.Lifecycle)
	assert.Equal(t, RetireCompleted, done.Retirement.Reason)
	assert.Contains(t, done.Retirement.Affected, Affected{RunID: "r-queued", Disposition: DispositionQueuedDropped})
	assert.Contains(t, done.Retirement.Affected, Affected{RunID: "r-running", Disposition: DispositionAllowedToFinish})
	assert.True(t, rc.suspended[finish.JobID])
	assert.Empty(t, rc.stopped, "finish policy lets the running run end")
	assert.Equal(t, AdmitCompleted, f.admit(finish.JobID, "").Code)

	cancel := f.readyWith("manual", func(v *JobVersion) { v.RetirementRules.ActiveRunPolicy = ActiveRunCancel })
	rc.runs[cancel.JobID] = []RunRef{{RunID: "r-1", Running: true}}
	_, err = f.store.ChangeLifecycle(f.ctx, cancel.JobID, Transition{Op: OpRetire, Reason: RetireManual, Detail: "experiment over"}, person)
	require.NoError(t, err)
	assert.Equal(t, []string{cancel.JobID + "/r-1"}, rc.stopped)
	events, err := f.store.ListEvents(f.ctx, cancel.JobID, 0)
	require.NoError(t, err)
	assert.Equal(t, EventEffect, events[0].Kind)
	assert.Equal(t, []Affected{{RunID: "r-1", Disposition: DispositionStopRequested}}, events[0].Affected)
	assert.Equal(t, string(RetireManual), events[1].Reason)

	expiry := f.now.Add(time.Hour)
	expiring := f.readyWith("expiring", func(v *JobVersion) { v.Lifetime.ExpiresAt = &expiry })
	assert.True(t, f.admit(expiring.JobID, "").Admit)
	f.advance(2 * time.Hour)
	adm := f.admit(expiring.JobID, "")
	assert.Equal(t, AdmitExpired, adm.Code, "the next scheduling opportunity retires an expired job")
	got, err := f.store.GetJob(f.ctx, expiring.JobID)
	require.NoError(t, err)
	assert.Equal(t, RetireExpired, got.Retirement.Reason)
	assert.Equal(t, reconcilerActor, got.Retirement.Actor)

	// History is retained: versions and events stay readable after retirement.
	_, err = f.store.GetVersion(f.ctx, expiring.JobID, 1)
	require.NoError(t, err)
}

func TestReconcileExpired(t *testing.T) {
	f := newFixture(t)
	soon := f.now.Add(time.Minute)
	later := f.now.Add(24 * time.Hour)
	a := f.readyWith("a", func(v *JobVersion) { v.Lifetime.ExpiresAt = &soon })
	b := f.readyWith("b", func(v *JobVersion) { v.Lifetime.ExpiresAt = &later })
	c := f.ready("control")
	f.advance(2 * time.Minute)
	retired, err := f.store.ReconcileExpired(f.ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{a.JobID}, retired)
	again, err := f.store.ReconcileExpired(f.ctx)
	require.NoError(t, err)
	assert.Empty(t, again, "reconciliation is idempotent")
	for _, id := range []string{b.JobID, c.JobID} {
		job, err := f.store.GetJob(f.ctx, id)
		require.NoError(t, err)
		assert.Equal(t, LifecycleActive, job.Lifecycle)
	}
}

// IT-14: an authoritative deletion retires only dependents; a missing event
// later discovered by reconciliation has the same effect; a resource that
// reuses the name with a new identity is not adopted; the control job
// continues.
func TestResourceDeletionAndReplacement(t *testing.T) {
	f := newFixture(t)
	withRuns(f)
	dependent := f.readyWith("monitor-v1", func(v *JobVersion) { v.Targets = []Target{target("v-1")} })
	reviewRule := f.readyWith("monitor-v1-review", func(v *JobVersion) {
		v.Targets = []Target{target("v-1")}
		v.RetirementRules.OnTargetDeleted = RuleReview
	})
	other := f.readyWith("monitor-v2", func(v *JobVersion) { v.Targets = []Target{target("v-2")} })
	control := f.readyWith("control", func(v *JobVersion) { v.Targets = []Target{target("v-control")} })

	// A non-authoritative absence only asks a person.
	ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-1"), Observation: ResourceAbsent, Detail: "list did not include it"}, agent)
	require.NoError(t, err)
	assert.ElementsMatch(t, []ResourceDisposition{
		{JobID: dependent.JobID, Match: "identity", Outcome: OutcomeNeedsHuman, Detail: "target reported absent without authoritative evidence"},
		{JobID: reviewRule.JobID, Match: "identity", Outcome: OutcomeNeedsHuman, Detail: "target reported absent without authoritative evidence"},
	}, ev.Dispositions)
	for _, id := range []string{dependent.JobID, reviewRule.JobID} {
		_, err = f.store.ChangeLifecycle(f.ctx, id, Transition{Op: OpResume}, person)
		require.NoError(t, err)
	}

	// Reconciliation finds the omitted deletion authoritatively.
	ev, err = f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-1"), Observation: ResourceDeleted, Authoritative: true, Evidence: []string{"kubectl get pv: NotFound uid v-1"}}, Actor{Kind: ActorReconciler, ID: "mch-reconcile"})
	require.NoError(t, err)
	got, err := f.store.GetJob(f.ctx, dependent.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleRetired, got.Lifecycle)
	assert.Equal(t, RetireTargetDeleted, got.Retirement.Reason)
	assert.Contains(t, got.Retirement.Evidence, "resource_event:"+ev.EventID)
	got, err = f.store.GetJob(f.ctx, reviewRule.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleNeedsHuman, got.Lifecycle, "the job's own rule asks a person instead")
	stored, err := f.store.GetResourceEvent(f.ctx, ev.EventID)
	require.NoError(t, err)
	assert.Len(t, stored.Dispositions, 2)

	// Replaying the deletion changes nothing more.
	ev, err = f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-1"), Observation: ResourceDeleted, Authoritative: true}, agent)
	require.NoError(t, err)
	assert.Contains(t, ev.Dispositions, ResourceDisposition{JobID: dependent.JobID, Match: "identity", Outcome: OutcomeUnchanged, Detail: "job is retired"})

	// A new volume reusing the name pvc-v-2 is a replacement, not adoption.
	replacement := target("v-2-new")
	replacement.DisplayName = "pvc-v-2"
	ev, err = f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: replacement, Observation: ResourcePresent}, agent)
	require.NoError(t, err)
	require.Len(t, ev.Dispositions, 1)
	assert.Equal(t, other.JobID, ev.Dispositions[0].JobID)
	assert.Equal(t, "replacement", ev.Dispositions[0].Match)
	assert.Equal(t, OutcomeNeedsHuman, ev.Dispositions[0].Outcome)
	v, err := f.store.GetVersion(f.ctx, other.JobID, 1)
	require.NoError(t, err)
	assert.Equal(t, "v-2", v.Targets[0].StableID["uid"], "the job still targets the original identity")

	got, err = f.store.GetJob(f.ctx, control.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle)
	assert.True(t, f.admit(control.JobID, "").Admit)
}

// IT-15: unreachable, denied and timed-out targets change availability and
// never retire; a later present observation restores readiness.
func TestResourceUnavailabilityNeverRetires(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("monitor", func(v *JobVersion) { v.Targets = []Target{target("v-9")} })
	for obs, want := range map[ResourceObservation]AvailabilityState{
		ResourceUnreachable: AvailabilityTargetUnreachable,
		ResourceTimeout:     AvailabilityTargetUnreachable,
		ResourceAuthDenied:  AvailabilityAuthRequired,
	} {
		_, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-9"), Observation: obs}, agent)
		require.NoError(t, err)
		got, err := f.store.GetJob(f.ctx, job.JobID)
		require.NoError(t, err)
		assert.Equal(t, LifecycleActive, got.Lifecycle, string(obs))
		assert.Equal(t, want, got.Availability.State, string(obs))
		assert.True(t, f.admit(job.JobID, "").Admit, "availability does not block scheduling")
	}
	_, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-9"), Observation: ResourcePresent}, agent)
	require.NoError(t, err)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, AvailabilityReady, got.Availability.State)
}

func TestLifecycleEffectFailureIsRecorded(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.readyWith("k", func(v *JobVersion) { v.RetirementRules.ActiveRunPolicy = ActiveRunCancel })
	rc.runs[job.JobID] = []RunRef{{RunID: "r-1", Running: true}}
	rc.stopErr = errors.New("coordinator unavailable")
	got, err := f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpRetire, Reason: RetireManual}, person)
	require.NoError(t, err, "the retirement stands even when Dagu cannot stop the run")
	assert.Equal(t, LifecycleRetired, got.Lifecycle)
	events, err := f.store.ListEvents(f.ctx, job.JobID, 1)
	require.NoError(t, err)
	assert.Equal(t, EventEffect, events[0].Kind)
	assert.Contains(t, events[0].Detail, "coordinator unavailable")
	assert.Equal(t, []Affected{{RunID: "r-1", Disposition: DispositionStopFailed}}, events[0].Affected)
}

func TestRecordDroppedRun(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	adm := Admission{JobID: job.JobID, Code: AdmitRetired, Reason: "job retired: manual"}
	require.NoError(t, f.store.RecordDroppedRun(f.ctx, job.JobID, "r-7", adm))
	require.NoError(t, f.store.RecordDroppedRun(f.ctx, "ordinary-dag", "r-1", adm))
	events, err := f.store.ListEvents(f.ctx, job.JobID, 1)
	require.NoError(t, err)
	assert.Equal(t, EventRunDropped, events[0].Kind)
	assert.Equal(t, string(AdmitRetired), events[0].Reason)
}

// A reporter's permission is re-checked in the commit that changes the job:
// losing it between evaluation and commit leaves the job untouched.
func TestResourceEventRechecksPermissionAtCommit(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("monitor", func(v *JobVersion) { v.Targets = []Target{target("v-5")} })
	calls := 0
	flips := func(context.Context, *Job) bool {
		calls++
		return calls == 1
	}
	ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-5"), Observation: ResourceDeleted, Authoritative: true}, agent, flips)
	require.NoError(t, err)
	assert.Empty(t, ev.Dispositions)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle)
	assert.Greater(t, calls, 1, "the filter ran again inside the commit")
}

// A run admitted to a worker is recorded on the job, so a retirement that
// commits afterwards knows it and, under the cancel policy, stops it even
// though Dagu does not report it running. Retirement first refuses the claim.
func TestAdmitClaimOrdersAgainstRetirement(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.readyWith("k", func(v *JobVersion) { v.RetirementRules.ActiveRunPolicy = ActiveRunCancel })

	adm, err := f.store.AdmitClaim(f.ctx, job.JobID, job.DAGSpecSHA256, RunRef{RunID: "run-1"})
	require.NoError(t, err)
	require.True(t, adm.Admit)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Contains(t, got.AdmittedRuns, "run-1")

	retired, err := f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpRetire, Reason: RetireManual}, person)
	require.NoError(t, err)
	assert.Contains(t, retired.Retirement.Affected, Affected{RunID: "run-1", Disposition: DispositionAdmittedBeforeEnd})
	assert.Equal(t, []string{job.JobID + "/run-1"}, rc.stopped, "the admitted run is stopped although Dagu listed nothing")
	assert.Nil(t, retired.PendingEffects)

	adm, err = f.store.AdmitClaim(f.ctx, job.JobID, job.DAGSpecSHA256, RunRef{RunID: "run-2"})
	require.NoError(t, err)
	assert.Equal(t, AdmitRetired, adm.Code)
}

// Expiry is decided inside the retirement commit: a lifetime extended after
// the job was seen as expired wins.
func TestExpiryRecheckedAtCommit(t *testing.T) {
	f := newFixture(t)
	soon := f.now.Add(time.Minute)
	job := f.readyWith("k", func(v *JobVersion) { v.Lifetime.ExpiresAt = &soon })
	f.advance(2 * time.Minute)
	later := f.now.Add(24 * time.Hour)
	v := f.version(2)
	v.Lifetime.ExpiresAt = &later
	_, err := f.store.UpdateVersion(f.ctx, job.JobID, "extend", 1, v, cli)
	require.NoError(t, err)

	got, err := f.store.retireExpired(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle)
}

// Effects a store without run control could not apply are left pending and
// applied by a reconciling store.
func TestPendingEffectsAreReconciled(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) { v.RetirementRules.ActiveRunPolicy = ActiveRunCancel })
	_, err := f.store.AdmitClaim(f.ctx, job.JobID, "", RunRef{RunID: "run-1"})
	require.NoError(t, err)
	got, err := f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpRetire, Reason: RetireManual}, person)
	require.NoError(t, err)
	require.NotNil(t, got.PendingEffects)
	assert.Equal(t, []RunRef{{RunID: "run-1"}}, got.PendingEffects.StopRuns)

	rc := withRuns(f)
	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	assert.Equal(t, []string{job.JobID + "/run-1"}, rc.stopped)
	assert.True(t, rc.suspended[job.JobID])
	got, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Nil(t, got.PendingEffects)
	assert.True(t, got.SuspendedByRegistry)

	rc.stopped = nil
	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	assert.Empty(t, rc.stopped, "applied effects are not repeated")
}

// The registry lifts only its own suspension: a stale suspension it applied
// to a job that is active again is undone, a person's suspension is kept.
func TestSuspensionFollowsCurrentLifecycle(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.ready("k")
	_, err := f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpPause}, person)
	require.NoError(t, err)
	assert.True(t, rc.suspended[job.JobID])
	_, err = f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpResume}, person)
	require.NoError(t, err)
	assert.False(t, rc.suspended[job.JobID])

	// A late pause effect suspends the DAG again; the job is active.
	rc.suspended[job.JobID] = true
	_, err = f.store.WithJobTx(f.ctx, job.JobID, agent, func(tx *JobTx) error {
		tx.Job.SuspendedByRegistry = true
		tx.touch()
		return nil
	})
	require.NoError(t, err)
	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	assert.False(t, rc.suspended[job.JobID])

	human := f.ready("human-suspended")
	rc.suspended[human.JobID] = true
	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	assert.True(t, rc.suspended[human.JobID], "a person's suspension of an active job is kept")
}

// Jobs registered before the resource index existed are found after a rebuild.
func TestRebuildResourceIndex(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) { v.Targets = []Target{target("v-7")} })
	ids, err := f.store.indexedJobs(f.ctx, resourceIDsPrefix)
	require.NoError(t, err)
	page, err := f.store.col.List(f.ctx, persis.ListQuery{Prefix: resourceIDsPrefix})
	require.NoError(t, err)
	for _, rec := range page.Records {
		require.NoError(t, f.store.col.Delete(f.ctx, rec.ID))
	}
	require.NotEmpty(t, ids)
	ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-7"), Observation: ResourceUnreachable}, agent)
	require.NoError(t, err)
	assert.Empty(t, ev.Dispositions)

	require.NoError(t, f.store.RebuildResourceIndex(f.ctx))
	ev, err = f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-7"), Observation: ResourceUnreachable}, agent)
	require.NoError(t, err)
	require.Len(t, ev.Dispositions, 1)
	assert.Equal(t, job.JobID, ev.Dispositions[0].JobID)
}

// A version change between evaluation and commit makes the event be
// evaluated again on the new version, which no longer has the target.
func TestResourceEventReevaluatesChangedVersion(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) { v.Targets = []Target{target("v-8")} })
	calls := 0
	moveAway := func(ctx context.Context, j *Job) bool {
		calls++
		if calls == 2 {
			v := f.version(3)
			v.Targets = []Target{target("v-other")}
			_, err := f.store.UpdateVersion(ctx, j.JobID, "move", 1, v, cli)
			require.NoError(t, err)
		}
		return true
	}
	ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-8"), Observation: ResourceDeleted, Authoritative: true}, agent, moveAway)
	require.NoError(t, err)
	assert.Empty(t, ev.Dispositions)
	assert.True(t, ev.Complete)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle, "the decision for the old version is not applied to the new one")
}

// An event saved but not completely applied is completed by reconciliation.
func TestReconcileResourceEvents(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) { v.Targets = []Target{target("v-9")} })
	ev := ResourceEvent{Schema: SchemaVersion, EventID: f.mint(PrefixEvent), Target: target("v-9"), Observation: ResourceDeleted,
		Authoritative: true, ObservedAt: f.now, Reporter: agent, Pending: []ResourceDependent{{JobID: job.JobID, Match: matchIdentity}}}
	require.NoError(t, f.store.createJSON(f.ctx, resourceEventsPrefix+ev.EventID, &ev))
	require.NoError(t, f.store.createJSON(f.ctx, resourcePendingPrefix+ev.EventID, indexEntry{}))

	// Without a way to re-check the reporter's permission nothing is applied.
	require.NoError(t, f.store.ReconcileResourceEvents(f.ctx))
	untouched, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, untouched.Lifecycle)

	f.store.reauthorize = func(_ context.Context, reporter Actor, _ *Job) bool { return reporter.ID == agent.ID }
	require.NoError(t, f.store.ReconcileResourceEvents(f.ctx))
	stored, err := f.store.GetResourceEvent(f.ctx, ev.EventID)
	require.NoError(t, err)
	assert.True(t, stored.Complete)
	require.Len(t, stored.Dispositions, 1)
	assert.Equal(t, OutcomeRetired, stored.Dispositions[0].Outcome)
	pending, err := f.store.indexedJobs(f.ctx, resourcePendingPrefix)
	require.NoError(t, err)
	assert.Empty(t, pending)
}

// A reporter who lost permission since reporting does not get the event
// applied at reconciliation: the job is untouched and the event completes
// without a disposition for it.
func TestReconcileResourceEventsRechecksReporter(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) { v.Targets = []Target{target("v-10")} })
	ev := ResourceEvent{Schema: SchemaVersion, EventID: f.mint(PrefixEvent), Target: target("v-10"), Observation: ResourceDeleted,
		Authoritative: true, ObservedAt: f.now, Reporter: agent, Pending: []ResourceDependent{{JobID: job.JobID, Match: matchIdentity}}}
	require.NoError(t, f.store.createJSON(f.ctx, resourceEventsPrefix+ev.EventID, &ev))
	require.NoError(t, f.store.createJSON(f.ctx, resourcePendingPrefix+ev.EventID, indexEntry{}))
	f.store.reauthorize = func(context.Context, Actor, *Job) bool { return false }

	require.NoError(t, f.store.ReconcileResourceEvents(f.ctx))
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle)
	stored, err := f.store.GetResourceEvent(f.ctx, ev.EventID)
	require.NoError(t, err)
	assert.Empty(t, stored.Dispositions)
}

func TestAdmissionChecksExpiry(t *testing.T) {
	f := newFixture(t)
	past := f.now.Add(-time.Minute)
	job := f.ready("k")
	job.ExpiresAt = &past
	adm := admissionFor(job, "", f.now)
	assert.Equal(t, AdmitExpired, adm.Code, "the in-commit predicate refuses an ended lifetime")
}

// An admitted child run of a retired job is stopped through its root.
func TestPendingStopsKeepChildRoot(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.readyWith("k", func(v *JobVersion) { v.RetirementRules.ActiveRunPolicy = ActiveRunCancel })
	_, err := f.store.AdmitClaim(f.ctx, job.JobID, "", RunRef{RunID: "child-1", RootName: "parent", RootRunID: "root-1"})
	require.NoError(t, err)
	_, err = f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpRetire, Reason: RetireManual}, person)
	require.NoError(t, err)
	assert.Equal(t, []string{"parent/root-1>" + job.JobID + "/child-1"}, rc.stopped)
}

// Runs that could not be listed when a cancel-policy job retired are listed
// and stopped later; the obligation is not lost.
func TestFailedRunDiscoveryIsRetried(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.readyWith("k", func(v *JobVersion) { v.RetirementRules.ActiveRunPolicy = ActiveRunCancel })
	rc.listErr = errors.New("run store unavailable")
	got, err := f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpRetire, Reason: RetireManual}, person)
	require.NoError(t, err)
	require.NotNil(t, got.PendingEffects)
	assert.True(t, got.PendingEffects.DiscoverRuns)

	rc.listErr = nil
	rc.runs[job.JobID] = []RunRef{{RunID: "r-local", Running: true}}
	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	assert.Equal(t, []string{job.JobID + "/r-local"}, rc.stopped)
	got, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Nil(t, got.PendingEffects)
}

// A suspension the registry did not make is never taken over: pausing and
// resuming a manually suspended job leaves it suspended.
func TestManualSuspensionIsNotTakenOver(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.ready("k")
	rc.suspended[job.JobID] = true
	_, err := f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpPause}, person)
	require.NoError(t, err)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.False(t, got.SuspendedByRegistry)
	_, err = f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpResume}, person)
	require.NoError(t, err)
	assert.True(t, rc.suspended[job.JobID])
}

// A suspend write made stale by a resume committed while it ran is undone.
func TestStaleSuspendWriteIsUndone(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.ready("k")
	_, err := f.store.WithJobTx(f.ctx, job.JobID, person, func(tx *JobTx) error { return tx.Transition(Transition{Op: OpPause}) })
	require.NoError(t, err)
	rc.onSuspend = func(string) {
		rc.onSuspend = nil
		_, err := f.store.WithJobTx(f.ctx, job.JobID, person, func(tx *JobTx) error { return tx.Transition(Transition{Op: OpResume}) })
		require.NoError(t, err)
	}
	require.NoError(t, f.store.ApplyEffects(f.ctx, job.JobID))
	assert.False(t, rc.suspended[job.JobID])
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle)
	assert.False(t, got.SuspendedByRegistry)
}

func TestRegisterRefusesDeclaredName(t *testing.T) {
	f := newFixture(t)
	v := f.version(1)
	v.DAG.Spec = "name: monitor\n" + v.DAG.Spec
	_, err := f.store.Register(f.ctx, RegisterInput{JobID: f.mint(PrefixJob), RequestID: "r", OwnerID: f.owner, ProjectID: f.project,
		MachineID: f.machine, JobKey: "named", Version: v}, cli)
	assert.Equal(t, CodeInvalid, code(t, err))
}

func TestResourceEventsWaitForIndex(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.store.col.Delete(f.ctx, resourceIndexReady))
	_, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-1"), Observation: ResourcePresent}, agent)
	assert.Equal(t, CodeNotReady, code(t, err))
	require.NoError(t, f.store.RebuildResourceIndex(f.ctx))
	_, err = f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-1"), Observation: ResourcePresent}, agent)
	require.NoError(t, err)
}

// Sending a saved, incomplete event again under its ID resumes it; a
// different report under that ID is refused.
func TestResourceEventResumesByID(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) { v.Targets = []Target{target("v-11")} })
	id := f.mint(PrefixEvent)
	saved := ResourceEvent{Schema: SchemaVersion, EventID: id, Target: target("v-11"), Observation: ResourceDeleted, Authoritative: true,
		ObservedAt: f.now, Reporter: agent, Pending: []ResourceDependent{{JobID: job.JobID, Match: matchIdentity}}}
	require.NoError(t, f.store.createJSON(f.ctx, resourceEventsPrefix+id, &saved))
	require.NoError(t, f.store.createJSON(f.ctx, resourcePendingPrefix+id, indexEntry{}))

	_, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{EventID: id, Target: target("v-11"), Observation: ResourceAbsent}, agent)
	assert.Equal(t, CodeDuplicate, code(t, err))
	_, err = f.store.RecordResourceEvent(f.ctx, ResourceEvent{EventID: id, Target: target("v-11"), Observation: ResourceDeleted, Authoritative: true}, person)
	assert.Equal(t, CodeDuplicate, code(t, err), "only the reporter can resume")

	ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{EventID: id, Target: target("v-11"), Observation: ResourceDeleted, Authoritative: true}, agent)
	require.NoError(t, err)
	assert.True(t, ev.Complete)
	require.Len(t, ev.Dispositions, 1)
	assert.Equal(t, OutcomeRetired, ev.Dispositions[0].Outcome)
}

// Admissions are kept whatever their number, and dropped only once Dagu
// reports the run finished or has no record of it after the settling time.
func TestAdmissionsSettleWhenRunsFinish(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.ready("k")
	for i := range 250 {
		_, err := f.store.AdmitClaim(f.ctx, job.JobID, "", RunRef{RunID: fmt.Sprintf("run-%03d", i)})
		require.NoError(t, err)
	}
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Len(t, got.AdmittedRuns, 250, "no admission is dropped by count")

	rc.finished = map[string]bool{"run-000": true}
	for i := 1; i < 249; i++ {
		rc.finished[fmt.Sprintf("run-%03d", i)] = false
	}
	// run-249 has no record in Dagu.
	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	got, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Len(t, got.AdmittedRuns, 250, "nothing settles before the settling time")

	f.advance(admissionSettle)
	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	got, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Len(t, got.AdmittedRuns, 248)
	assert.NotContains(t, got.AdmittedRuns, "run-000")
	assert.NotContains(t, got.AdmittedRuns, "run-249")
	assert.Contains(t, got.AdmittedRuns, "run-001")
}

// A store without run control (the coordinator's) retiring a cancel-policy
// job leaves the runs to be listed and stopped by the scheduler.
func TestRetireWithoutRunControlRecordsDiscovery(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) { v.RetirementRules.ActiveRunPolicy = ActiveRunCancel })
	got, err := f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpRetire, Reason: RetireManual}, person)
	require.NoError(t, err)
	require.NotNil(t, got.PendingEffects)
	assert.True(t, got.PendingEffects.DiscoverRuns)

	rc := withRuns(f)
	rc.runs[job.JobID] = []RunRef{{RunID: "r-1", Running: true}}
	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	assert.Equal(t, []string{job.JobID + "/r-1"}, rc.stopped)
}

// A suspend writer that stopped after writing keeps the registry's
// ownership until its lease passes, so the suspension it left on an active
// job is lifted, however late the write lands.
func TestStoppedSuspendWriterIsRecovered(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.ready("k")
	_, err := f.store.WithJobTx(f.ctx, job.JobID, person, func(tx *JobTx) error {
		tx.Job.SuspendedByRegistry = true
		tx.Job.SuspendWriters = map[string]time.Time{"w-1": tx.now}
		tx.touch()
		return nil
	})
	require.NoError(t, err)
	rc.suspended[job.JobID] = true

	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	assert.False(t, rc.suspended[job.JobID])
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.True(t, got.SuspendedByRegistry, "ownership is kept while the writer may still write")

	rc.suspended[job.JobID] = true // the stopped writer's write lands late
	f.advance(suspendWriteLease)
	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	assert.False(t, rc.suspended[job.JobID])
	got, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.False(t, got.SuspendedByRegistry)
	assert.Empty(t, got.SuspendWriters)
}

// An event whose job change committed but whose progress was not saved is
// not applied again on replay, even after the job was reactivated.
func TestResourceEventReplayDoesNotReapply(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) {
		v.Targets = []Target{target("v-12")}
		v.RetirementRules.OnTargetDeleted = RuleReview
	})
	ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-12"), Observation: ResourceDeleted, Authoritative: true}, agent)
	require.NoError(t, err)
	require.Len(t, ev.Dispositions, 1)
	assert.Equal(t, OutcomeNeedsHuman, ev.Dispositions[0].Outcome)

	// Lose the progress write: the saved event still lists the job.
	lost := *ev
	lost.Dispositions, lost.Complete = nil, false
	lost.Pending = []ResourceDependent{{JobID: job.JobID, Match: matchIdentity}}
	require.NoError(t, f.store.putJSON(f.ctx, resourceEventsPrefix+ev.EventID, &lost))
	_, err = f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpResume}, person)
	require.NoError(t, err)

	replayed, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{EventID: ev.EventID, Target: target("v-12"), Observation: ResourceDeleted, Authoritative: true}, agent)
	require.NoError(t, err)
	assert.True(t, replayed.Complete)
	require.Len(t, replayed.Dispositions, 1)
	assert.Equal(t, OutcomeNeedsHuman, replayed.Dispositions[0].Outcome, "the recorded result is returned")
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle, "the reactivated job is not changed again")
}

// A different target under a reused event ID is a different report.
func TestResourceEventIDCoversWholeTarget(t *testing.T) {
	f := newFixture(t)
	ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-13"), Observation: ResourcePresent}, agent)
	require.NoError(t, err)
	other := target("v-13")
	other.DisplayName = "another name"
	_, err = f.store.RecordResourceEvent(f.ctx, ResourceEvent{EventID: ev.EventID, Target: other, Observation: ResourcePresent}, agent)
	assert.Equal(t, CodeDuplicate, code(t, err))
}

// A retry reusing a run ID refreshes its admission, so settling the earlier
// attempt it replaced does not remove it.
func TestRepeatedClaimSurvivesSettlement(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.ready("k")
	_, err := f.store.AdmitClaim(f.ctx, job.JobID, "", RunRef{RunID: "run-1"})
	require.NoError(t, err)
	f.advance(admissionSettle)
	rc.finished = map[string]bool{"run-1": true}
	rc.onFinished = func() {
		rc.onFinished = nil
		_, err := f.store.AdmitClaim(f.ctx, job.JobID, "", RunRef{RunID: "run-1"})
		require.NoError(t, err)
	}
	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Contains(t, got.AdmittedRuns, "run-1")
}

// A writer whose stale suspend could not be undone keeps its token and the
// registry's ownership, and the suspension is lifted after the lease.
func TestFailedUndoKeepsWriterToken(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.ready("k")
	_, err := f.store.WithJobTx(f.ctx, job.JobID, person, func(tx *JobTx) error { return tx.Transition(Transition{Op: OpPause}) })
	require.NoError(t, err)
	rc.unsuspendErr = errors.New("flag store unavailable")
	rc.onSuspend = func(string) {
		rc.onSuspend = nil
		_, err := f.store.WithJobTx(f.ctx, job.JobID, person, func(tx *JobTx) error { return tx.Transition(Transition{Op: OpResume}) })
		require.NoError(t, err)
	}
	require.Error(t, f.store.ApplyEffects(f.ctx, job.JobID))
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.True(t, got.SuspendedByRegistry)
	assert.Len(t, got.SuspendWriters, 1)

	rc.unsuspendErr = nil
	f.advance(suspendWriteLease)
	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	assert.False(t, rc.suspended[job.JobID])
	got, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.False(t, got.SuspendedByRegistry)
	assert.Empty(t, got.SuspendWriters)
}

// A job matching an event both by identity and as a replacement has both
// applied: the identity result does not stand in for the replacement rule.
func TestReplacementNotShadowedByIdentityResult(t *testing.T) {
	f := newFixture(t)
	a, b := target("v-15"), target("v-16")
	b.DisplayName = a.DisplayName
	job := f.readyWith("k", func(v *JobVersion) {
		v.Targets = []Target{a, b}
		v.RetirementRules.OnReplacement = RuleRetire
	})
	_, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: a, Observation: ResourceUnreachable}, agent)
	require.NoError(t, err)
	ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: a, Observation: ResourcePresent}, agent)
	require.NoError(t, err)
	outcomes := map[string]ResourceOutcome{}
	for _, d := range ev.Dispositions {
		outcomes[d.Match] = d.Outcome
	}
	assert.Equal(t, OutcomeAvailability, outcomes[matchIdentity])
	assert.Equal(t, OutcomeRetired, outcomes[matchReplacement])
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleRetired, got.Lifecycle)
}

// An older writer's undo does not release ownership of a suspension a newer
// writer made after it: the newer suspension is still lifted on resume.
func TestOldUndoDoesNotReleaseNewerSuspension(t *testing.T) {
	f := newFixture(t)
	rc := withRuns(f)
	job := f.ready("k")
	transition := func(op LifecycleOp) {
		_, err := f.store.WithJobTx(f.ctx, job.JobID, person, func(tx *JobTx) error { return tx.Transition(Transition{Op: op}) })
		require.NoError(t, err)
	}
	transition(OpPause)
	rc.onSuspend = func(string) {
		rc.onSuspend = nil
		transition(OpResume) // writer A's write is now stale
	}
	rc.onUnsuspend = func(string) {
		rc.onUnsuspend = nil
		// After A undid its write: a new pause, writer B suspends and
		// finishes, then a resume whose effect has not run yet.
		transition(OpPause)
		require.NoError(t, f.store.ApplyEffects(f.ctx, job.JobID))
		transition(OpResume)
	}
	require.NoError(t, f.store.ApplyEffects(f.ctx, job.JobID))
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.True(t, rc.suspended[job.JobID], "writer B's suspension is in place")
	assert.True(t, got.SuspendedByRegistry, "A's undo did not release B's suspension")

	require.NoError(t, f.store.ReconcileEffects(f.ctx))
	assert.False(t, rc.suspended[job.JobID])
	got, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.False(t, got.SuspendedByRegistry)
}

// A processor holding a stale copy of an event another processor completed
// neither applies it again nor reverses its completion, even after the
// job's applied record was compacted away.
func TestStaleEventProcessorStops(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) {
		v.Targets = []Target{target("v-17")}
		v.RetirementRules.OnTargetDeleted = RuleReview
	})
	id := f.mint(PrefixEvent)
	saved := ResourceEvent{Schema: SchemaVersion, EventID: id, Target: target("v-17"), Observation: ResourceDeleted, Authoritative: true,
		ObservedAt: f.now, Reporter: agent, Pending: []ResourceDependent{{JobID: job.JobID, Match: matchIdentity}}}
	require.NoError(t, f.store.createJSON(f.ctx, resourceEventsPrefix+id, &saved))
	stale := saved

	done := saved
	require.NoError(t, f.store.applyPending(f.ctx, &done, agent, func(context.Context, *Job) bool { return true }))
	require.True(t, done.Complete)
	_, err := f.store.ChangeLifecycle(f.ctx, job.JobID, Transition{Op: OpResume}, person)
	require.NoError(t, err)
	_, err = f.store.WithJobTx(f.ctx, job.JobID, person, func(tx *JobTx) error {
		tx.Job.AppliedResourceEvents = nil // compacted
		tx.touch()
		return nil
	})
	require.NoError(t, err)

	_, err = f.store.applyDependent(f.ctx, stale.Pending[0], &stale, agent, func(context.Context, *Job) bool { return true })
	assert.Equal(t, CodeEventComplete, code(t, err))
	require.NoError(t, f.store.applyPending(f.ctx, &stale, agent, func(context.Context, *Job) bool { return true }))
	assert.True(t, stale.Complete)

	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle)
	read, err := f.store.GetResourceEvent(f.ctx, id)
	require.NoError(t, err)
	assert.True(t, read.Complete)
}

// fillApplied gives job count applied records whose events still list it
// as pending, as a lost progress write leaves them, starting with first.
func (f *fixture) fillApplied(job *Job, t Target, first ResourceEvent, count int) {
	f.t.Helper()
	key := appliedKey(matchIdentity, t)
	pending := []ResourceDependent{{JobID: job.JobID, Match: matchIdentity}}
	first.Pending = pending
	require.NoError(f.t, f.store.createJSON(f.ctx, resourceEventsPrefix+first.EventID, &first))
	records := []AppliedResourceEvent{{Key: key, EventID: first.EventID, At: f.now,
		Disposition: ResourceDisposition{JobID: job.JobID, Match: matchIdentity, Outcome: OutcomeNeedsHuman}}}
	for range count - 1 {
		id := f.mint(PrefixEvent)
		ev := ResourceEvent{Schema: SchemaVersion, EventID: id, Target: t, Observation: ResourceUnreachable, Reporter: agent, Pending: pending}
		require.NoError(f.t, f.store.createJSON(f.ctx, resourceEventsPrefix+id, &ev))
		records = append(records, AppliedResourceEvent{Key: key, EventID: id, At: f.now,
			Disposition: ResourceDisposition{JobID: job.JobID, Match: matchIdentity, Outcome: OutcomeAvailability}})
	}
	_, err := f.store.WithJobTx(f.ctx, job.JobID, person, func(tx *JobTx) error {
		tx.Job.AppliedResourceEvents = records
		tx.touch()
		return nil
	})
	require.NoError(f.t, err)
}

// Past the limit, a record is dropped once its event's saved progress no
// longer lists the job, even while the event waits on other jobs; a record
// whose event still lists the job is kept.
func TestCompactAppliedIsScopedToTheJob(t *testing.T) {
	f := newFixture(t)
	save := func(pending ...ResourceDependent) string {
		id := f.mint(PrefixEvent)
		ev := ResourceEvent{Schema: SchemaVersion, EventID: id, Target: target("v-14"), Observation: ResourcePresent, Pending: pending}
		require.NoError(t, f.store.createJSON(f.ctx, resourceEventsPrefix+id, &ev))
		return id
	}
	mine := ResourceDependent{JobID: "job-a", Match: matchIdentity}
	other := ResourceDependent{JobID: "job-b", Match: matchIdentity}
	rec := func(id string) AppliedResourceEvent {
		return AppliedResourceEvent{EventID: id, Disposition: ResourceDisposition{JobID: "job-a", Match: matchIdentity}}
	}
	list := []AppliedResourceEvent{rec(save(mine)), rec(save(other))}
	for range maxAppliedResourceEvents {
		list = append(list, rec(save(mine)))
	}
	out := f.store.compactApplied(f.ctx, "job-a", list)
	assert.Len(t, out, maxAppliedResourceEvents+1)
	assert.Equal(t, list[0].EventID, out[0].EventID, "the event still owing this job keeps its record")
	assert.Equal(t, list[2].EventID, out[1].EventID, "the event waiting only on another job does not")
}

// A job whose records are full of lost progress refuses new events before
// any change, and replaying one of those events returns its recorded result
// without changing the job again.
func TestAppliedRecordsAtHardLimitRefuseNewEvents(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) {
		v.Targets = []Target{target("v-18")}
		v.RetirementRules.OnTargetDeleted = RuleReview
	})
	oldID := f.mint(PrefixEvent)
	f.fillApplied(job, target("v-18"), ResourceEvent{Schema: SchemaVersion, EventID: oldID, Target: target("v-18"),
		Observation: ResourceDeleted, Authoritative: true, ObservedAt: f.now, Reporter: agent}, hardMaxAppliedResourceEvents)

	ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-18"), Observation: ResourceDeleted, Authoritative: true}, agent)
	require.NoError(t, err)
	assert.False(t, ev.Complete)
	require.Len(t, ev.Failures, 1)
	assert.Contains(t, ev.Failures[0].Error, "send them again")
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle, "the refused event changed nothing")
	assert.Len(t, got.AppliedResourceEvents, hardMaxAppliedResourceEvents, "no record was dropped")

	replayed, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{EventID: oldID, Target: target("v-18"), Observation: ResourceDeleted, Authoritative: true}, agent)
	require.NoError(t, err)
	assert.True(t, replayed.Complete)
	require.Len(t, replayed.Dispositions, 1)
	assert.Equal(t, OutcomeNeedsHuman, replayed.Dispositions[0].Outcome, "the recorded result is returned")
	got, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle, "the old event is not applied again")
}

// A confirmed deletion still retires a job whose records are full: the
// lifecycle is never locked by the record bound.
func TestRetirementAppliesAtHardLimit(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) {
		v.Targets = []Target{target("v-19")}
		v.RetirementRules.OnTargetDeleted = RuleRetire
	})
	f.fillApplied(job, target("v-19"), ResourceEvent{Schema: SchemaVersion, EventID: f.mint(PrefixEvent), Target: target("v-19"),
		Observation: ResourceUnreachable, ObservedAt: f.now, Reporter: agent}, hardMaxAppliedResourceEvents)

	ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-19"), Observation: ResourceDeleted, Authoritative: true}, agent)
	require.NoError(t, err)
	assert.True(t, ev.Complete)
	require.Len(t, ev.Dispositions, 1)
	assert.Equal(t, OutcomeRetired, ev.Dispositions[0].Outcome)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleRetired, got.Lifecycle)
}

// A stale processor stops once the saved event no longer owes the job, even
// while the event is still incomplete for another job.
func TestStaleProcessorStopsWhenJobAlreadyApplied(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) {
		v.Targets = []Target{target("v-20")}
		v.RetirementRules.OnTargetDeleted = RuleReview
	})
	id := f.mint(PrefixEvent)
	pending := ResourceDependent{JobID: job.JobID, Match: matchIdentity}
	stale := ResourceEvent{Schema: SchemaVersion, EventID: id, Target: target("v-20"), Observation: ResourceDeleted, Authoritative: true,
		ObservedAt: f.now, Reporter: agent, Pending: []ResourceDependent{pending}}
	// Saved progress: this job is done, another job is still owed.
	saved := stale
	saved.Pending = []ResourceDependent{{JobID: "job-other", Match: matchIdentity}}
	require.NoError(t, f.store.createJSON(f.ctx, resourceEventsPrefix+id, &saved))

	_, err := f.store.applyDependent(f.ctx, pending, &stale, agent, func(context.Context, *Job) bool { return true })
	assert.Equal(t, CodeEventComplete, code(t, err))
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle)
}

// An unknown observation (a lookup that neither confirms nor denies the
// resource) is recorded on each dependent and changes nothing; it cannot be
// authoritative.
func TestUnknownObservationChangesNothing(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) {
		v.Targets = []Target{target("v-1")}
		v.RetirementRules.OnTargetDeleted = RuleRetire
	})
	_, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-1"), Observation: ResourceUnknown, Authoritative: true}, agent)
	assert.Equal(t, CodeInvalid, code(t, err))

	ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-1"), Observation: ResourceUnknown, Detail: "issue lookup returned null"}, agent)
	require.NoError(t, err)
	require.Len(t, ev.Dispositions, 1)
	assert.Equal(t, OutcomeRecorded, ev.Dispositions[0].Outcome)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, job.Lifecycle, got.Lifecycle, "not retired")
	assert.Equal(t, job.Availability.State, got.Availability.State, "availability unchanged")
}

// Incomplete events are listed oldest first, by the reporter's machine when
// asked, a page at a time; complete events are not listed.
func TestIncompleteResourceEventsAreListed(t *testing.T) {
	f := newFixture(t)
	save := func(machine string, complete bool) string {
		id := f.mint(PrefixEvent)
		ev := ResourceEvent{Schema: SchemaVersion, EventID: id, Target: target("v-1"), Observation: ResourceUnreachable,
			ObservedAt: f.now, Reporter: Actor{Kind: ActorReconciler, ID: "rec", MachineID: machine}, Complete: complete}
		require.NoError(t, f.store.createJSON(f.ctx, resourceEventsPrefix+id, &ev))
		if !complete {
			require.NoError(t, f.store.createJSON(f.ctx, resourcePendingPrefix+id, indexEntry{}))
		}
		f.now = f.now.Add(time.Second)
		return id
	}
	a1, b1, a2 := save("mch_a", false), save("mch_b", false), save("mch_a", false)
	save("mch_a", true)

	ids := func(evs []ResourceEvent) []string {
		var out []string
		for _, e := range evs {
			out = append(out, e.EventID)
		}
		return out
	}
	page, next, err := f.store.IncompleteResourceEvents(f.ctx, "mch_a", "", 1, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{a1}, ids(page))
	require.NotEmpty(t, next)
	page, next, err = f.store.IncompleteResourceEvents(f.ctx, "mch_a", next, 1, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{a2}, ids(page))
	assert.Empty(t, next)
	all, _, err := f.store.IncompleteResourceEvents(f.ctx, "", "", 10, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{a1, b1, a2}, ids(all))
}

// Visibility decides the page: hidden events neither fill a page nor become
// its cursor.
func TestIncompleteResourceEventsPageOnlyVisibleEvents(t *testing.T) {
	f := newFixture(t)
	var ids []string
	for range 4 {
		id := f.mint(PrefixEvent)
		ev := ResourceEvent{Schema: SchemaVersion, EventID: id, Target: target("v-1"), Observation: ResourceUnreachable,
			ObservedAt: f.now, Reporter: Actor{Kind: ActorReconciler, ID: "rec", MachineID: "mch_a"}}
		require.NoError(t, f.store.createJSON(f.ctx, resourceEventsPrefix+id, &ev))
		require.NoError(t, f.store.createJSON(f.ctx, resourcePendingPrefix+id, indexEntry{}))
		f.now = f.now.Add(time.Second)
		ids = append(ids, id)
	}
	// Only the second and fourth are visible.
	visible := func(ev *ResourceEvent) bool { return ev.EventID == ids[1] || ev.EventID == ids[3] }
	page, next, err := f.store.IncompleteResourceEvents(f.ctx, "", "", 1, visible)
	require.NoError(t, err)
	require.Len(t, page, 1)
	assert.Equal(t, ids[1], page[0].EventID)
	assert.Equal(t, ids[1], next, "the cursor is a visible event")
	page, next, err = f.store.IncompleteResourceEvents(f.ctx, "", next, 1, visible)
	require.NoError(t, err)
	require.Len(t, page, 1)
	assert.Equal(t, ids[3], page[0].EventID)
	assert.Empty(t, next)
}

// An unknown observation of a target checked before each run sets
// availability target_unconfirmed (actionable, never retiring), and a later
// present clears it; for other targets it changes nothing.
func TestUnknownPreRunTargetIsUnconfirmed(t *testing.T) {
	f := newFixture(t)
	pre := target("v-1")
	pre.ExistenceCheck = CheckPreRun
	job := f.readyWith("k", func(v *JobVersion) {
		v.Targets = []Target{pre}
		v.RetirementRules.OnTargetDeleted = RuleRetire
	})
	_, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-1"), Observation: ResourceUnknown}, agent)
	require.NoError(t, err)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, AvailabilityTargetUnconfirmed, got.Availability.State)
	assert.Equal(t, job.Lifecycle, got.Lifecycle)
	assert.True(t, f.admit(job.JobID, "").Admit, "availability does not refuse runs")

	_, err = f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: target("v-1"), Observation: ResourcePresent}, agent)
	require.NoError(t, err)
	got, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, AvailabilityReady, got.Availability.State)
}

// Target conditions belong to their target: a present observation of one
// target resolves only that target's exceptions, the job stays unavailable
// while another target's or the worker's condition is open, and becomes
// ready only when none is.
func TestTargetConditionsResolvePerTarget(t *testing.T) {
	f := newFixture(t)
	a, b := target("v-1"), target("v-2")
	a.ExistenceCheck, b.ExistenceCheck = CheckPreRun, CheckPreRun
	job := f.readyWith("k", func(v *JobVersion) { v.Targets = []Target{a, b} })
	report := func(tg Target, obs ResourceObservation) {
		_, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: tg, Observation: obs}, agent)
		require.NoError(t, err)
		f.now = f.now.Add(time.Second)
	}
	state := func() AvailabilityState {
		got, err := f.store.GetJob(f.ctx, job.JobID)
		require.NoError(t, err)
		return got.Availability.State
	}

	report(a, ResourceUnknown)
	report(b, ResourceUnreachable)
	report(b, ResourcePresent)
	assert.Equal(t, AvailabilityTargetUnconfirmed, state(), "A is still unconfirmed")
	report(a, ResourcePresent)
	assert.Equal(t, AvailabilityReady, state())

	// The worker goes offline, then a target is unconfirmed and recovers:
	// the worker's condition is not resolved by the target's recovery.
	_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
		return tx.Observe(Observation{State: AvailabilityWorkerOffline, Kind: "worker_offline"})
	})
	require.NoError(t, err)
	f.now = f.now.Add(time.Second)
	report(a, ResourceUnknown)
	report(a, ResourcePresent)
	assert.Equal(t, AvailabilityWorkerOffline, state(), "the worker is still offline")
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	open := 0
	for _, e := range got.Exceptions {
		if e.ResolvedAt == nil {
			open++
			assert.Equal(t, "worker_offline", e.Kind)
		}
	}
	assert.Equal(t, 1, open)

	// A present of a target with no open condition changes nothing.
	report(b, ResourcePresent)
	assert.Equal(t, AvailabilityWorkerOffline, state())
}

// A target exception recorded before exceptions carried their target is
// still resolved by that target's present, through the event in its
// evidence; the reply and the replay record report the availability the job
// ends with.
func TestLegacyTargetExceptionAndFallbackDisposition(t *testing.T) {
	f := newFixture(t)
	a, b := target("v-1"), target("v-2")
	a.ExistenceCheck, b.ExistenceCheck = CheckPreRun, CheckPreRun
	job := f.readyWith("k", func(v *JobVersion) { v.Targets = []Target{a, b} })
	report := func(tg Target, obs ResourceObservation) *ResourceEvent {
		ev, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: tg, Observation: obs}, agent)
		require.NoError(t, err)
		f.now = f.now.Add(time.Second)
		return ev
	}
	report(a, ResourceUnreachable)
	// As recorded before this change: no target on the exception.
	_, err := f.store.WithJobTx(f.ctx, job.JobID, person, func(tx *JobTx) error {
		for _, e := range tx.Job.Exceptions {
			e.Target = ""
		}
		tx.touch()
		return nil
	})
	require.NoError(t, err)
	report(b, ResourceUnknown)

	ev := report(b, ResourcePresent)
	require.Len(t, ev.Dispositions, 1)
	assert.Equal(t, string(AvailabilityTargetUnreachable), ev.Dispositions[0].Detail, "A still holds the job")
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, AvailabilityTargetUnreachable, got.Availability.State)
	applied := got.appliedResourceEvent(appliedKey(matchIdentity, b), ev.EventID)
	require.NotNil(t, applied)
	assert.Equal(t, string(AvailabilityTargetUnreachable), applied.Detail, "the replay record agrees")

	report(a, ResourcePresent)
	got, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, AvailabilityReady, got.Availability.State, "the legacy exception was resolved by its target")
}

// A legacy exception is matched only through the event that opened it: an
// originating event that is gone matches nothing, even when the reporter's
// evidence names another target's event.
func TestLegacyTargetExceptionUsesOnlyItsOrigin(t *testing.T) {
	f := newFixture(t)
	a, b := target("v-1"), target("v-2")
	job := f.readyWith("k", func(v *JobVersion) { v.Targets = []Target{a, b} })
	evB, err := f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: b, Observation: ResourceUnreachable}, agent)
	require.NoError(t, err)
	f.now = f.now.Add(time.Second)
	// A legacy exception whose originating event is missing, with the
	// reporter's evidence naming B's event.
	_, err = f.store.WithJobTx(f.ctx, job.JobID, person, func(tx *JobTx) error {
		for _, e := range tx.Job.Exceptions {
			e.Target = ""
			e.Evidence = []string{"resource_event:" + f.mint(PrefixEvent), "resource_event:" + evB.EventID}
		}
		tx.touch()
		return nil
	})
	require.NoError(t, err)
	_, err = f.store.RecordResourceEvent(f.ctx, ResourceEvent{Target: b, Observation: ResourcePresent}, agent)
	require.NoError(t, err)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, AvailabilityTargetUnreachable, got.Availability.State, "B's present does not resolve an exception of unknown origin")
}
