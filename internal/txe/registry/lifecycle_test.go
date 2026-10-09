// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRuns struct {
	mu        sync.Mutex
	runs      map[string][]RunRef
	stopped   []string
	suspended map[string]bool
	stopErr   error
}

func newFakeRuns() *fakeRuns {
	return &fakeRuns{runs: map[string][]RunRef{}, suspended: map[string]bool{}}
}

func (r *fakeRuns) ActiveRuns(_ context.Context, dag string) ([]RunRef, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RunRef(nil), r.runs[dag]...), nil
}

func (r *fakeRuns) StopRun(_ context.Context, dag, runID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopErr != nil {
		return r.stopErr
	}
	r.stopped = append(r.stopped, dag+"/"+runID)
	return nil
}

func (r *fakeRuns) SetSuspended(_ context.Context, dag string, suspended bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suspended[dag] = suspended
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
