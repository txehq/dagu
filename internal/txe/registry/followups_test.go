// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReservedActionNames(t *testing.T) {
	f := newFixture(t)
	v := f.version(1)
	v.ReviewPolicy.PermittedActions = append(v.ReviewPolicy.PermittedActions, PermittedAction{Name: "dagu.restart", TimeoutSec: 60})
	jobID := f.mint(PrefixJob)
	_, err := f.store.Register(f.ctx, RegisterInput{JobID: jobID, RequestID: "r", OwnerID: f.owner, ProjectID: f.project,
		MachineID: f.machine, JobKey: "reserved", Version: v}, cli)
	assert.Equal(t, CodeInvalid, code(t, err))

	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: f.mint(PrefixProposal), Action: ActionSpec{Name: "txe.other"}})
		return err
	})
	assert.Equal(t, CodeInvalid, code(t, err))
}

func TestNativeTaskLocator(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	put := func(task NativeTask) error {
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			_, err := tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: f.mint(PrefixProposal), Action: ActionSpec{Name: "resize"}, NativeTask: &task})
			return err
		})
		return err
	}
	assert.Equal(t, CodeInvalid, code(t, put(NativeTask{DAG: "other", RunID: "r-1", StepID: DecideTaskStep})))
	assert.Equal(t, CodeInvalid, code(t, put(NativeTask{DAG: DecideTaskDAG(f.machine), RunID: "r-1", StepID: "approve"})))
	require.NoError(t, put(NativeTask{DAG: DecideTaskDAG(f.machine), RunID: "r-1", StepID: DecideTaskStep}))
	assert.LessOrEqual(t, len(DecideTaskDAG(f.machine)), 40, "within Dagu's DAG name limit")
}

func TestRetryVerdictOnlyWhereItHasAMeaning(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	p := propose(t, f, job, c)
	_, err := decide(f, job.JobID, p, VerdictRetry, ProposalDecided, "k1")
	assert.Equal(t, CodeNotPermitted, code(t, err))
}

// An action whose outcome is unresolved blocks its intent in later episodes
// until a person answers its escalation with retry, which allows exactly one
// more attempt.
func TestUncertainEffectResolution(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, 24*time.Hour)
	actionID, g, err := routine(t, f, job, c, "restart")
	require.NoError(t, err)
	f.advance(61 * time.Second)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: c.ClaimID, Fence: c.Fence, State: ActionEscalated})
		return err
	})
	require.NoError(t, err)

	// End the episode; the escalated action stays in the aggregate.
	review, err := ReviewID(job.JobID, 0)
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		if err := tx.RecordReview(c.ClaimID, c.Fence, Review{ReviewID: review, Outcome: ReviewAct}); err != nil {
			return err
		}
		_, err := tx.AdvanceCheckpoint(c.ClaimID, c.Fence, 0, Checkpoint{})
		return err
	})
	require.NoError(t, err)
	job, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	require.Contains(t, job.Actions, actionID)

	_, _, err = routine(t, f, job, c, "restart")
	assert.Equal(t, CodeIntentUnresolved, code(t, err), "the same intent is not started again")

	params := json.RawMessage(`{"action_id":"` + actionID + `","attempt":1}`)
	escalation, err := EscalationProposalID(actionID, 1, job.Version)
	require.NoError(t, err)
	put := func(id string) (*Proposal, error) {
		var p *Proposal
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			var err error
			p, err = tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: id, Action: ActionSpec{Name: ActionUncertainEffect, Params: params}})
			return err
		})
		return p, err
	}
	_, err = put(f.mint(PrefixProposal))
	assert.Equal(t, CodeInvalid, code(t, err), "the escalation has a fixed ID")
	p, err := put(escalation)
	require.NoError(t, err)

	_, err = decide(f, job.JobID, p, VerdictApprove, ProposalDecided, "a1")
	assert.Equal(t, CodeNotPermitted, code(t, err), "an escalation is never executed")
	_, err = decide(f, job.JobID, p, VerdictRetry, ProposalDecided, "r1")
	require.NoError(t, err)
	job, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.NotContains(t, job.Proposals, escalation, "the escalation is closed")
	require.Contains(t, job.UncertainResolutions, actionID)

	newID, _, err := routine(t, f, job, c, "restart")
	require.NoError(t, err, "one more attempt is allowed")
	job, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Empty(t, job.UncertainResolutions, "the resolution is consumed with the grant")
	assert.NotContains(t, job.Actions, actionID, "the escalated action leaves for history")
	assert.Equal(t, ActionExecuting, job.Actions[newID].State)
	archived, err := f.store.ListArchivedProposals(f.ctx, job.JobID, 0)
	require.NoError(t, err)
	require.NotEmpty(t, archived)
	assert.Equal(t, ProposalClosed, archived[0].State)
}

// A retry verdict is refused once the action used every attempt its policy
// allows.
func TestUncertainResolutionRespectsMaxAttempts(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, 24*time.Hour)
	actionID, g, err := routine(t, f, job, c, "restart")
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: c.ClaimID, Fence: c.Fence, State: ActionFailed})
		return err
	})
	require.NoError(t, err)
	_, g, err = routine(t, f, job, c, "restart") // attempt 2 of 2
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: c.ClaimID, Fence: c.Fence, State: ActionUncertain})
		return err
	})
	require.NoError(t, err)
	escalation, err := EscalationProposalID(actionID, 2, job.Version)
	require.NoError(t, err)
	var p *Proposal
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		var err error
		p, err = tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: escalation,
			Action: ActionSpec{Name: ActionUncertainEffect, Params: json.RawMessage(`{"action_id":"` + actionID + `","attempt":2}`)}})
		return err
	})
	require.NoError(t, err)
	_, err = decide(f, job.JobID, p, VerdictRetry, ProposalDecided, "r1")
	assert.Equal(t, CodeNotPermitted, code(t, err))
}

// Only a person decides or requests a retry, and a decision is attributed
// to the person making it.
func TestDecisionsArePersonOnly(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	p := propose(t, f, job, c, VerdictApprove)
	decideAs := func(actor Actor, named Actor) error {
		_, err := f.tx(job.JobID, actor, func(tx *JobTx) error {
			cur := tx.Job.Proposals[p.ProposalID]
			_, err := tx.AppendDecision(Decision{DecisionID: f.mint(PrefixDecision), ProposalID: p.ProposalID, ProposalRevision: cur.Revision,
				BindingDigest: cur.BindingDigest, Verdict: VerdictApprove, Actor: named}, ProposalDecided)
			return err
		})
		return err
	}
	assert.Equal(t, CodeNotPermitted, code(t, decideAs(agent, Actor{})), "an agent cannot approve")
	assert.Equal(t, CodeInvalid, code(t, decideAs(person, Actor{Kind: ActorHuman, ID: "someone-else"})))
	require.NoError(t, decideAs(person, Actor{}))
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, person, got.Proposals[p.ProposalID].Decision.Actor)

	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, _, err := tx.ProposeRetry(RetryRunParams{RunID: "run-1", AttemptID: "a1", RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest}, "k1")
		return err
	})
	assert.Equal(t, CodeNotPermitted, code(t, err), "an agent cannot request a retry")
}

// A superseded proposal with a Dagu human task leaves a closure owed on its
// machine; failures are counted and retried oldest first, a final outcome
// ends it, and its replay returns the stored closure.
func TestProposalClosures(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	put := func(task *NativeTask) *Proposal {
		var p *Proposal
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			var err error
			p, err = tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: f.mint(PrefixProposal), Action: ActionSpec{Name: "resize"}, NativeTask: task})
			return err
		})
		require.NoError(t, err)
		return p
	}
	withTask := put(&NativeTask{DAG: DecideTaskDAG(f.machine), RunID: "r-1", StepID: DecideTaskStep})
	other := put(&NativeTask{DAG: DecideTaskDAG(f.machine), RunID: "r-2", StepID: DecideTaskStep})
	put(nil)

	_, err := f.tx(job.JobID, person, func(tx *JobTx) error { return tx.Transition(Transition{Op: OpPause}) })
	require.NoError(t, err)
	_, err = f.tx(job.JobID, person, func(tx *JobTx) error {
		return tx.Transition(Transition{Op: OpRetire, Reason: RetireManual})
	})
	require.NoError(t, err)

	pending, err := f.store.PendingClosures(f.ctx, f.machine, 0, nil)
	require.NoError(t, err)
	require.Len(t, pending, 2, "only proposals with a task are owed a closure")

	record := func(prp string, outcome ClosureOutcome) (*Closure, error) {
		var cl *Closure
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			var err error
			cl, err = tx.RecordClosure(f.ctx, f.store, prp, outcome, "detail")
			return err
		})
		return cl, err
	}
	_, err = record(withTask.ProposalID, ClosureFailed)
	require.NoError(t, err)
	pending, err = f.store.PendingClosures(f.ctx, f.machine, 0, nil)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	assert.Equal(t, other.ProposalID, pending[0].ProposalID, "never-attempted closures come first")
	assert.Equal(t, 1, pending[1].Failures)

	final, err := record(withTask.ProposalID, ClosureClosed)
	require.NoError(t, err)
	assert.Equal(t, 2, final.Attempt)
	replayed, err := record(withTask.ProposalID, ClosureClosed)
	require.NoError(t, err)
	assert.Equal(t, final.ClosureID, replayed.ClosureID)
	_, err = record(withTask.ProposalID, ClosureRunMissing)
	assert.Equal(t, CodeProposalState, code(t, err))

	pending, err = f.store.PendingClosures(f.ctx, f.machine, 0, nil)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	closures, err := f.store.ListClosures(f.ctx, job.JobID, 0)
	require.NoError(t, err)
	assert.Len(t, closures, 2, "every attempt is kept")

	// The other task's run ended before anyone answered: that ends it too.
	ended, err := record(other.ProposalID, ClosureRunEnded)
	require.NoError(t, err)
	assert.Equal(t, ClosureRunEnded, ended.Outcome)
	pending, err = f.store.PendingClosures(f.ctx, f.machine, 0, nil)
	require.NoError(t, err)
	assert.Empty(t, pending)
}

// Repeated observations of one condition keep one unresolved exception, for
// the job and for its reviewer; a ready observation resolves it and a later
// failure opens a new one.
func TestObservationsCoalesce(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	observe := func(o Observation) *Job {
		got, err := f.tx(job.JobID, agent, func(tx *JobTx) error { return tx.Observe(o) })
		require.NoError(t, err)
		return got
	}
	open := func(j *Job) int {
		n := 0
		for _, e := range j.Exceptions {
			if e.ResolvedAt == nil {
				n++
			}
		}
		return n
	}
	for range 3 {
		observe(Observation{State: AvailabilityAuthRequired, Scope: ScopeReviewer})
	}
	observe(Observation{State: AvailabilityWorkerOffline})
	got := observe(Observation{State: AvailabilityWorkerOffline})
	assert.Equal(t, 2, open(got), "one per scope, kind and state")
	got = observe(Observation{State: AvailabilityReady, Scope: ScopeReviewer})
	assert.Equal(t, 1, open(got), "the reviewer's is resolved, the job's stays")
	got = observe(Observation{State: AvailabilityAuthRequired, Scope: ScopeReviewer})
	assert.Equal(t, 2, open(got))
}

// retryFixture drives person retries of runs of one job.
type retryFixture struct {
	f   *fixture
	rc  *fakeRuns
	job *Job
}

func newRetryFixture(t *testing.T) *retryFixture {
	f := newFixture(t)
	rc := withRuns(f)
	rc.attempts = map[string]RunAttempt{}
	return &retryFixture{f: f, rc: rc, job: f.ready("k")}
}

func (r *retryFixture) params(run, attempt string) RetryRunParams {
	return RetryRunParams{RunID: run, AttemptID: attempt, RunSpecSHA256: r.job.DAGSpecSHA256, PackageDigest: r.job.PackageDigest}
}

func (r *retryFixture) propose(params RetryRunParams, key string) (*Proposal, *Decision, error) {
	var p *Proposal
	var d *Decision
	_, err := r.f.tx(r.job.JobID, person, func(tx *JobTx) error {
		var err error
		p, d, err = tx.ProposeRetry(params, key)
		return err
	})
	return p, d, err
}

func (r *retryFixture) authorize(p *Proposal, d *Decision, ec *Claim) (string, *Grant, error) {
	actionID, err := ApprovedActionID(p.ProposalID, d.DecisionID)
	require.NoError(r.f.t, err)
	var g *Grant
	_, err = r.f.tx(r.job.JobID, agent, func(tx *JobTx) error {
		var err error
		g, err = tx.Authorize(EffectRequest{ActionID: actionID, JobVersion: r.job.Version, PackageDigest: r.job.PackageDigest,
			Approved: &ApprovedEffect{ProposalID: p.ProposalID, DecisionID: d.DecisionID, ClaimID: ec.ClaimID, Fence: ec.Fence}})
		return err
	})
	return actionID, g, err
}

func (r *retryFixture) settle(actionID string, g *Grant, ec *Claim, state ActionState, receipt string) error {
	_, err := r.f.tx(r.job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: ec.ClaimID, Fence: ec.Fence, State: state, Receipt: receipt})
		return err
	})
	return err
}

// A person retries a failed attempt once; when that retry's attempt fails
// too, a fresh decision may retry it once more, while replaying the first
// decision changes nothing. The receipt is the observed new attempt.
func TestRetryIsBoundToTheFailedAttempt(t *testing.T) {
	r := newRetryFixture(t)
	r.rc.attempts["run-1"] = failedAttempt("a1", r.job.DAGSpecSHA256)

	p1, d1, err := r.propose(r.params("run-1", "a1"), "key-1")
	require.NoError(t, err)
	assert.Equal(t, ProposalDecided, p1.State)
	ec := acquire(t, r.f, r.job.JobID, ClaimExecution, time.Hour)
	act1, g1, err := r.authorize(p1, d1, ec)
	require.NoError(t, err)

	// The native retry is accepted; until a new attempt is observed there is
	// no receipt.
	assert.Equal(t, CodeInvalid, code(t, r.settle(act1, g1, ec, ActionSucceeded, ExecutionRef("a1", ""))), "the retried execution is no receipt")
	assert.Equal(t, CodeInvalid, code(t, r.settle(act1, g1, ec, ActionSucceeded, ExecutionRef("a9", ""))), "an execution not observed is no receipt")
	r.rc.attempts["run-1"] = RunAttempt{AttemptID: "a2", SpecSHA256: r.job.DAGSpecSHA256, Status: "queued"}
	assert.Equal(t, CodeInvalid, code(t, r.settle(act1, g1, ec, ActionSucceeded, "a2")), "the receipt is the execution reference")
	require.NoError(t, r.settle(act1, g1, ec, ActionSucceeded, ExecutionRef("a2", "")))

	// Replaying the first decision changes nothing.
	_, _, err = r.propose(r.params("run-1", "a1"), "key-1")
	assert.Equal(t, CodeDuplicate, code(t, err))
	_, _, err = r.authorize(p1, d1, ec)
	assert.Error(t, err, "the first decision authorizes nothing more")

	// While the new attempt runs, or after it succeeds, it is not retried.
	_, _, err = r.propose(r.params("run-1", "a2"), "key-2")
	assert.Equal(t, CodeStaleBinding, code(t, err), "a queued attempt is not retried")
	r.rc.attempts["run-1"] = RunAttempt{AttemptID: "a2", SpecSHA256: r.job.DAGSpecSHA256, Status: "succeeded", Finished: true, Succeeded: true}
	_, _, err = r.propose(r.params("run-1", "a2"), "key-2")
	assert.Equal(t, CodeStaleBinding, code(t, err), "a succeeded attempt is not retried")

	// It fails: a fresh decision on that attempt is a new proposal.
	r.rc.attempts["run-1"] = failedAttempt("a2", r.job.DAGSpecSHA256)
	_, _, err = r.propose(r.params("run-1", "a1"), "key-3")
	assert.Equal(t, CodeStaleBinding, code(t, err), "the earlier attempt is no longer the run's")
	p2, d2, err := r.propose(r.params("run-1", "a2"), "key-3")
	require.NoError(t, err)
	assert.NotEqual(t, p1.ProposalID, p2.ProposalID)
	_, _, err = r.authorize(p2, d2, ec)
	require.NoError(t, err, "one further retry within policy")
}

// The decision binds the attempt the person saw: if the run moved on before
// the executor acts, the grant is refused.
func TestRetryRefusedWhenTheRunMovedOn(t *testing.T) {
	r := newRetryFixture(t)
	r.rc.attempts["run-1"] = failedAttempt("a1", r.job.DAGSpecSHA256)
	p, d, err := r.propose(r.params("run-1", "a1"), "key-1")
	require.NoError(t, err)
	r.rc.attempts["run-1"] = RunAttempt{AttemptID: "a2", SpecSHA256: r.job.DAGSpecSHA256, Status: "running"}
	ec := acquire(t, r.f, r.job.JobID, ClaimExecution, time.Hour)
	_, _, err = r.authorize(p, d, ec)
	assert.Equal(t, CodeStaleBinding, code(t, err))
}

// The attempt and its digest are the run's own: a forged digest or attempt,
// a run the job does not have, or a run of an older version is refused, and
// without run history nothing is bound.
func TestRetryRejectsForgedOrStaleRuns(t *testing.T) {
	r := newRetryFixture(t)
	v1Spec, v1Pkg := r.job.DAGSpecSHA256, r.job.PackageDigest
	r.rc.attempts["old"] = failedAttempt("o1", v1Spec)
	v2 := r.f.version(2)
	v2.DAG.Spec += "  - name: report\n    run: /pkg/report.sh\n"
	job, err := r.f.store.UpdateVersion(r.f.ctx, r.job.JobID, r.f.mint(PrefixEvent), 1, v2, cli)
	require.NoError(t, err)
	r.job = job
	r.rc.attempts["new"] = failedAttempt("n1", job.DAGSpecSHA256)

	for name, params := range map[string]RetryRunParams{
		"old run, current digest":  {RunID: "old", AttemptID: "o1", RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest},
		"old run, its own digest":  {RunID: "old", AttemptID: "o1", RunSpecSHA256: v1Spec, PackageDigest: v1Pkg},
		"forged attempt":           {RunID: "new", AttemptID: "n0", RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest},
		"unknown run":              {RunID: "ghost", AttemptID: "g1", RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest},
		"current run, old package": {RunID: "new", AttemptID: "n1", RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: v1Pkg},
	} {
		_, _, err := r.propose(params, "key-"+name)
		assert.Equal(t, CodeStaleBinding, code(t, err), name)
	}
	_, _, err = r.propose(r.params("new", "n1"), "key-ok")
	require.NoError(t, err)

	// A spec two versions share with different packages names no package.
	shared := r.f.ready("k2")
	shared, err = r.f.store.UpdateVersion(r.f.ctx, shared.JobID, r.f.mint(PrefixEvent), 1, r.f.version(3), cli)
	require.NoError(t, err)
	require.Equal(t, v1Spec, shared.DAGSpecSHA256)
	r.rc.attempts["s"] = failedAttempt("s1", shared.DAGSpecSHA256)
	_, err = r.f.tx(shared.JobID, person, func(tx *JobTx) error {
		_, _, err := tx.ProposeRetry(RetryRunParams{RunID: "s", AttemptID: "s1", RunSpecSHA256: shared.DAGSpecSHA256, PackageDigest: shared.PackageDigest}, "k")
		return err
	})
	assert.Equal(t, CodeStaleBinding, code(t, err))

	bare := newFixture(t)
	j := bare.ready("k")
	_, err = bare.tx(j.JobID, person, func(tx *JobTx) error {
		_, _, err := tx.ProposeRetry(RetryRunParams{RunID: "run-1", AttemptID: "a1", RunSpecSHA256: j.DAGSpecSHA256, PackageDigest: j.PackageDigest}, "k1")
		return err
	})
	assert.Equal(t, CodeNotReady, code(t, err), "without run history nothing is bound")
}

// On the queued path Dagu runs the same attempt again under a later queue
// marker: that is a new execution, the receipt names it, and the stored
// status of the execution that was retried is retained before Dagu
// overwrites it in place.
func TestQueuedRetryIsANewExecution(t *testing.T) {
	r := newRetryFixture(t)
	failed := failedAttempt("a1", r.job.DAGSpecSHA256)
	failed.QueuedAt = "2026-10-09T12:00:00.000000001Z"
	failed.Snapshot = json.RawMessage(`{"attemptId":"a1","status":3}`)
	r.rc.attempts["run-1"] = failed
	params := r.params("run-1", "a1")
	params.QueuedAt = failed.QueuedAt

	_, _, err := r.propose(r.params("run-1", "a1"), "key-0")
	assert.Equal(t, CodeStaleBinding, code(t, err), "the attempt alone does not name the execution")
	p, d, err := r.propose(params, "key-1")
	require.NoError(t, err)
	ec := acquire(t, r.f, r.job.JobID, ClaimExecution, time.Hour)
	act, g, err := r.authorize(p, d, ec)
	require.NoError(t, err)

	// Dagu re-queues a1 in place.
	r.rc.attempts["run-1"] = RunAttempt{AttemptID: "a1", QueuedAt: "2026-10-09T12:00:00.000000002Z", SpecSHA256: r.job.DAGSpecSHA256, Status: "queued"}
	assert.Equal(t, CodeInvalid, code(t, r.settle(act, g, ec, ActionSucceeded, failed.Ref())), "the retried execution is no receipt")
	require.NoError(t, r.settle(act, g, ec, ActionSucceeded, ExecutionRef("a1", "2026-10-09T12:00:00.000000002Z")))

	kept, err := r.f.store.GetRetainedExecution(r.f.ctx, r.job.JobID, "run-1", failed.Ref(), EvidenceRetry)
	require.NoError(t, err)
	assert.JSONEq(t, string(failed.Snapshot), string(kept), "the retried execution's status is kept")
}

// Evidence is kept per purpose: a status observed while the execution
// published does not stand in for the terminal status a retry was decided
// on.
func TestRetryEvidenceIsTheTerminalStatus(t *testing.T) {
	r := newRetryFixture(t)
	spec := r.job.DAGSpecSHA256
	// The execution publishes while running...
	publishing := RunAttempt{AttemptID: "a1", QueuedAt: "q1", SpecSHA256: spec, Status: "running",
		Snapshot: json.RawMessage(`{"attemptId":"a1","status":1,"nodes":[{"status":1}]}`)}
	require.NoError(t, r.f.store.retainExecution(r.f.ctx, r.job.JobID, "run-1", publishing, EvidencePublication))
	// ...then fails, and a person retries it.
	failed := failedAttempt("a1", spec)
	failed.QueuedAt = "q1"
	failed.Snapshot = json.RawMessage(`{"attemptId":"a1","status":3,"nodes":[{"status":3}]}`)
	r.rc.attempts["run-1"] = failed
	params := r.params("run-1", "a1")
	params.QueuedAt = "q1"
	_, _, err := r.propose(params, "key-1")
	require.NoError(t, err)

	retry, err := r.f.store.GetRetainedExecution(r.f.ctx, r.job.JobID, "run-1", failed.Ref(), EvidenceRetry)
	require.NoError(t, err)
	assert.JSONEq(t, string(failed.Snapshot), string(retry), "the retry's evidence is the terminal failed status with its final nodes")
	published, err := r.f.store.GetRetainedExecution(r.f.ctx, r.job.JobID, "run-1", failed.Ref(), EvidencePublication)
	require.NoError(t, err)
	assert.JSONEq(t, string(publishing.Snapshot), string(published), "the publication observation is kept apart")
}

// Each escalation is about one attempt: after a retry decision and a second
// unresolved outcome, the first escalation's decision context does not
// carry over, and a decision filed against the earlier attempt is refused.
func TestEscalationsAreBoundToTheAttempt(t *testing.T) {
	f := newFixture(t)
	v := f.version(1)
	v.ReviewPolicy.MaxAttempts = 3
	job, err := f.store.Register(f.ctx, RegisterInput{JobID: f.mint(PrefixJob), RequestID: "r", OwnerID: f.owner, ProjectID: f.project,
		MachineID: f.machine, JobKey: "three", Version: v}, cli)
	require.NoError(t, err)
	pv, err := f.store.GetVersion(f.ctx, job.JobID, 1)
	require.NoError(t, err)
	_, err = f.store.MarkReady(f.ctx, job.JobID, 0, PackageEvidence{Digest: job.PackageDigest, Path: pv.Package.Path, MachineID: f.machine}, cli)
	require.NoError(t, err)
	job, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	c := acquire(t, f, job.JobID, ClaimReview, 24*time.Hour)

	escalate := func(actionID string, g *Grant, attempt int) *Proposal {
		t.Helper()
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: c.ClaimID, Fence: c.Fence, State: ActionUncertain})
			return err
		})
		require.NoError(t, err)
		id, err := EscalationProposalID(actionID, attempt, job.Version)
		require.NoError(t, err)
		var p *Proposal
		_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
			var err error
			p, err = tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: id,
				Action: ActionSpec{Name: ActionUncertainEffect, Params: json.RawMessage(fmt.Sprintf(`{"action_id":%q,"attempt":%d}`, actionID, attempt))}})
			return err
		})
		require.NoError(t, err)
		return p
	}
	actionID, g, err := routine(t, f, job, c, "restart")
	require.NoError(t, err)
	first := escalate(actionID, g, 1)
	_, err = decide(f, job.JobID, first, VerdictRetry, ProposalDecided, "r1")
	require.NoError(t, err)
	_, g, err = routine(t, f, job, c, "restart") // attempt 2, under the resolution
	require.NoError(t, err)
	second := escalate(actionID, g, 2)
	assert.NotEqual(t, first.ProposalID, second.ProposalID, "the second escalation is another proposal")

	// A decision against the first escalation finds no open proposal.
	_, err = decide(f, job.JobID, first, VerdictRetry, ProposalDecided, "r-stale")
	assert.Equal(t, CodeProposalState, code(t, err))
	// Filing the first escalation again is refused: the action moved on.
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: first.ProposalID,
			Action: ActionSpec{Name: ActionUncertainEffect, Params: json.RawMessage(fmt.Sprintf(`{"action_id":%q,"attempt":1}`, actionID))}})
		return err
	})
	assert.Equal(t, CodeStaleBinding, code(t, err))
	_, err = decide(f, job.JobID, second, VerdictRetry, ProposalDecided, "r2")
	require.NoError(t, err)
}

// The intent index keeps only unresolved intents.
func TestSettledIntentsAreDropped(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	actionID, g, err := routine(t, f, job, c, "restart")
	require.NoError(t, err)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	require.Len(t, got.Intents, 1)
	got, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: c.ClaimID, Fence: c.Fence, State: ActionSucceeded, Receipt: "done"})
		return err
	})
	require.NoError(t, err)
	assert.Empty(t, got.Intents)
}

// A decided retry whose run moved on can never be executed: it is
// superseded (by the registry, when the grant is refused or a new retry is
// requested) instead of waiting in the decision queue forever. A decided
// retry that still binds, and one being executed, are left alone.
func TestDecidedRetriesWhoseRunMovedOnAreEnded(t *testing.T) {
	r := newRetryFixture(t)
	r.rc.attempts["run-1"] = failedAttempt("a1", r.job.DAGSpecSHA256)
	r.rc.attempts["run-2"] = failedAttempt("b1", r.job.DAGSpecSHA256)
	p1, _, err := r.propose(r.params("run-1", "a1"), "key-1")
	require.NoError(t, err)
	p2, _, err := r.propose(r.params("run-2", "b1"), "key-2")
	require.NoError(t, err)

	affected, err := r.f.store.EndMovedOnRetries(r.f.ctx, r.job.JobID)
	require.NoError(t, err)
	assert.Empty(t, affected, "both still bind")

	// Run 1 moved on without this decision.
	r.rc.attempts["run-1"] = RunAttempt{AttemptID: "a2", SpecSHA256: r.job.DAGSpecSHA256, Status: "running"}
	affected, err = r.f.store.EndMovedOnRetries(r.f.ctx, r.job.JobID)
	require.NoError(t, err)
	assert.Equal(t, []Affected{{ProposalID: p1.ProposalID, Disposition: DispositionSuperseded}}, affected)
	got, err := r.f.store.GetJob(r.f.ctx, r.job.JobID)
	require.NoError(t, err)
	assert.NotContains(t, got.Proposals, p1.ProposalID, "it left the decision queue")
	archived, err := r.f.store.ListArchivedProposals(r.f.ctx, r.job.JobID, 0)
	require.NoError(t, err)
	require.Len(t, archived, 1)
	assert.Equal(t, p1.ProposalID, archived[0].ProposalID)
	assert.Equal(t, ProposalSuperseded, archived[0].State)
	assert.Contains(t, archived[0].Reasoning, "is now at execution")
	assert.Equal(t, ProposalDecided, got.Proposals[p2.ProposalID].State)

	affected, err = r.f.store.EndMovedOnRetries(r.f.ctx, r.job.JobID)
	require.NoError(t, err)
	assert.Empty(t, affected, "ending them again changes nothing")
}

// A person's retry request that finds another decided retry stale ends it as
// the registry, not as that person.
func TestRetriesEndedOnARequestAreTheRegistrys(t *testing.T) {
	r := newRetryFixture(t)
	r.rc.attempts["run-1"] = failedAttempt("a1", r.job.DAGSpecSHA256)
	r.rc.attempts["run-2"] = failedAttempt("b1", r.job.DAGSpecSHA256)
	p1, _, err := r.propose(r.params("run-1", "a1"), "key-1")
	require.NoError(t, err)
	r.rc.attempts["run-1"] = RunAttempt{AttemptID: "a2", SpecSHA256: r.job.DAGSpecSHA256, Status: "running"}
	_, _, err = r.propose(r.params("run-2", "b1"), "key-2")
	require.NoError(t, err)
	archived, err := r.f.store.ListArchivedProposals(r.f.ctx, r.job.JobID, 0)
	require.NoError(t, err)
	require.Len(t, archived, 1)
	assert.Equal(t, p1.ProposalID, archived[0].ProposalID)
	assert.Equal(t, registryActor, archived[0].Updated.By)
}

// A stalled action attempt is raised under the live claim as one action-scope
// exception per action, attempt and kind; it changes no availability, and the
// registry resolves it when the attempt ends.
func TestActionScopeExceptionsFollowTheAttempt(t *testing.T) {
	r := newRetryFixture(t)
	r.rc.attempts["run-1"] = failedAttempt("a1", r.job.DAGSpecSHA256)
	p, d, err := r.propose(r.params("run-1", "a1"), "key-1")
	require.NoError(t, err)
	ec := acquire(t, r.f, r.job.JobID, ClaimExecution, time.Hour)
	actionID, g, err := r.authorize(p, d, ec)
	require.NoError(t, err)

	observe := func(o Observation) error {
		_, err := r.f.tx(r.job.JobID, agent, func(tx *JobTx) error { return tx.Observe(o) })
		return err
	}
	stalled := Observation{Scope: ScopeAction, Kind: "retry_reservation_stalled", ActionID: actionID, Attempt: 1, ClaimID: ec.ClaimID, Fence: ec.Fence, Detail: "not started after 30m"}
	open := func() []*Exception {
		got, err := r.f.store.GetJob(r.f.ctx, r.job.JobID)
		require.NoError(t, err)
		var out []*Exception
		for _, e := range got.Exceptions {
			if e.Scope == ScopeAction && e.ResolvedAt == nil {
				out = append(out, e)
			}
		}
		assert.Equal(t, AvailabilityReady, got.Availability.State, "no availability change")
		require.NotNil(t, got.Actions[actionID].AttemptStartedAt, "the attempt's start is recorded")
		return out
	}

	wrong := stalled
	wrong.Attempt = 2
	assert.Equal(t, CodeActionState, code(t, observe(wrong)), "another attempt")
	noClaim := stalled
	noClaim.Fence = ec.Fence + 1
	assert.Equal(t, CodeClaimStale, code(t, observe(noClaim)), "only under the live claim")

	require.NoError(t, observe(stalled))
	require.NoError(t, observe(stalled), "a repeat changes nothing")
	got := open()
	require.Len(t, got, 1)
	assert.Equal(t, actionID, got[0].ActionID)
	assert.Equal(t, 1, got[0].Attempt)

	// The attempt ends: the registry resolves it.
	require.NoError(t, r.settle(actionID, g, ec, ActionFailed, ""))
	assert.Empty(t, open())
}

// An action that leaves the aggregate (archived, e.g. replaced by a later
// episode after its uncertainty was resolved) takes its open action-scope
// exceptions with it.
func TestArchivedActionResolvesItsExceptions(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	actionID, _, err := routine(t, f, job, c, "restart")
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		return tx.Observe(Observation{Scope: ScopeAction, Kind: "stalled", ActionID: actionID, Attempt: 1, ClaimID: c.ClaimID, Fence: c.Fence})
	})
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		tx.touch()
		return tx.archiveAction(tx.Job.Actions[actionID])
	})
	require.NoError(t, err)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	for _, e := range got.Exceptions {
		if e.Scope == ScopeAction {
			assert.NotNil(t, e.ResolvedAt, "resolved with its archived action")
		}
	}
}

// A run retry whose outcome is uncertain may be attempted once more, only on
// a person's retry of that uncertain outcome, and only while the run is still
// at the execution the person decided on; a failed run retry is never
// attempted again, and a third attempt is never allowed.
func TestUncertainRunRetryGetsOneApprovedExtraAttempt(t *testing.T) {
	setup := func(t *testing.T) (*retryFixture, *Proposal, *Decision, string) {
		r := newRetryFixture(t)
		r.rc.attempts["run-1"] = failedAttempt("a1", r.job.DAGSpecSHA256)
		p, d, err := r.propose(r.params("run-1", "a1"), "key-1")
		require.NoError(t, err)
		ec := acquire(t, r.f, r.job.JobID, ClaimExecution, time.Hour)
		actionID, g, err := r.authorize(p, d, ec)
		require.NoError(t, err)
		// The hub admitted the retry without naming an execution.
		require.NoError(t, r.settle(actionID, g, ec, ActionUncertain, ""))
		_, err = r.f.tx(r.job.JobID, agent, func(tx *JobTx) error { return tx.ReleaseClaim(ec.ClaimID, ec.Fence) })
		require.NoError(t, err)
		return r, p, d, actionID
	}
	resolve := func(t *testing.T, r *retryFixture, actionID string, attempt int) {
		rc := acquire(t, r.f, r.job.JobID, ClaimReview, time.Hour)
		escalation, err := EscalationProposalID(actionID, attempt, r.job.Version)
		require.NoError(t, err)
		var p *Proposal
		_, err = r.f.tx(r.job.JobID, agent, func(tx *JobTx) error {
			var err error
			p, err = tx.PutProposal(rc.ClaimID, rc.Fence, Proposal{ProposalID: escalation,
				Action: ActionSpec{Name: ActionUncertainEffect, Params: json.RawMessage(fmt.Sprintf(`{"action_id":%q,"attempt":%d}`, actionID, attempt))}})
			return err
		})
		require.NoError(t, err)
		_, err = decide(r.f, r.job.JobID, p, VerdictRetry, ProposalDecided, fmt.Sprintf("r-%d", attempt))
		require.NoError(t, err, "the person's retry of the uncertain outcome is accepted")
		_, err = r.f.tx(r.job.JobID, agent, func(tx *JobTx) error { return tx.ReleaseClaim(rc.ClaimID, rc.Fence) })
		require.NoError(t, err)
	}

	t.Run("the run is still at the decided execution", func(t *testing.T) {
		r, p, d, actionID := setup(t)
		ec := acquire(t, r.f, r.job.JobID, ClaimExecution, time.Hour)
		_, _, err := r.authorize(p, d, ec)
		require.Error(t, err, "no second attempt without a person's retry")
		_, err = r.f.tx(r.job.JobID, agent, func(tx *JobTx) error { return tx.ReleaseClaim(ec.ClaimID, ec.Fence) })
		require.NoError(t, err)

		resolve(t, r, actionID, 1)
		ec = acquire(t, r.f, r.job.JobID, ClaimExecution, time.Hour)
		_, g, err := r.authorize(p, d, ec)
		require.NoError(t, err, "one more attempt, bound to the same execution")
		assert.Equal(t, 2, g.Attempt)
		require.NoError(t, r.settle(actionID, g, ec, ActionUncertain, ""))
		_, err = r.f.tx(r.job.JobID, agent, func(tx *JobTx) error { return tx.ReleaseClaim(ec.ClaimID, ec.Fence) })
		require.NoError(t, err)
		rc := acquire(t, r.f, r.job.JobID, ClaimReview, time.Hour)
		escalation, err := EscalationProposalID(actionID, 2, r.job.Version)
		require.NoError(t, err)
		var esc *Proposal
		_, err = r.f.tx(r.job.JobID, agent, func(tx *JobTx) error {
			var err error
			esc, err = tx.PutProposal(rc.ClaimID, rc.Fence, Proposal{ProposalID: escalation,
				Action: ActionSpec{Name: ActionUncertainEffect, Params: json.RawMessage(fmt.Sprintf(`{"action_id":%q,"attempt":2}`, actionID))}})
			return err
		})
		require.NoError(t, err)
		_, err = decide(r.f, r.job.JobID, esc, VerdictRetry, ProposalDecided, "r-2")
		assert.Equal(t, CodeNotPermitted, code(t, err), "never a third attempt")
	})
	t.Run("the first attempt took effect", func(t *testing.T) {
		r, p, d, actionID := setup(t)
		resolve(t, r, actionID, 1)
		r.rc.attempts["run-1"] = RunAttempt{AttemptID: "a2", SpecSHA256: r.job.DAGSpecSHA256, Status: "running"}
		ec := acquire(t, r.f, r.job.JobID, ClaimExecution, time.Hour)
		_, _, err := r.authorize(p, d, ec)
		assert.Equal(t, CodeStaleBinding, code(t, err), "the run moved on: never retargeted to a later execution")
	})
	t.Run("a failed run retry is not attempted again", func(t *testing.T) {
		r := newRetryFixture(t)
		r.rc.attempts["run-1"] = failedAttempt("a1", r.job.DAGSpecSHA256)
		p, d, err := r.propose(r.params("run-1", "a1"), "key-1")
		require.NoError(t, err)
		ec := acquire(t, r.f, r.job.JobID, ClaimExecution, time.Hour)
		actionID, g, err := r.authorize(p, d, ec)
		require.NoError(t, err)
		require.NoError(t, r.settle(actionID, g, ec, ActionFailed, ""))
		_, _, err = r.authorize(p, d, ec)
		assert.Equal(t, CodeActionExists, code(t, err))
	})
}

// A binding problem (the job's commands are not bound on the reviewer's
// machine) is one exception per kind and version, raised under the live
// claim; it changes no availability, survives reviews and ready
// observations, and is resolved only by a ready binding observation of the
// same kind and version, or by the job moving to another version.
func TestBindingExceptionsPersistUntilRestored(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	observe := func(o Observation) error {
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error { return tx.Observe(o) })
		return err
	}
	unbound := Observation{Scope: ScopeBinding, Kind: "job_commands_unbound", State: AvailabilityStale, ClaimID: c.ClaimID, Fence: c.Fence, Detail: "run.sh not found"}
	open := func() []*Exception {
		got, err := f.store.GetJob(f.ctx, job.JobID)
		require.NoError(t, err)
		assert.Equal(t, AvailabilityReady, got.Availability.State, "no availability change")
		var out []*Exception
		for _, e := range got.Exceptions {
			if e.Scope == ScopeBinding && e.ResolvedAt == nil {
				out = append(out, e)
			}
		}
		return out
	}

	noClaim := unbound
	noClaim.Fence = c.Fence + 1
	assert.Equal(t, CodeClaimStale, code(t, observe(noClaim)))
	old := unbound
	old.JobVersion = job.Version + 1
	assert.Equal(t, CodeStaleBinding, code(t, observe(old)), "only the current version")

	require.NoError(t, observe(unbound))
	require.NoError(t, observe(unbound), "a repeat changes nothing")
	got := open()
	require.Len(t, got, 1)
	assert.Equal(t, job.Version, got[0].JobVersion)

	// Neither the reviewer's nor the job's ready observation resolves it.
	require.NoError(t, observe(Observation{Scope: ScopeReviewer, State: AvailabilityReady}))
	require.NoError(t, observe(Observation{State: AvailabilityReady}))
	assert.Len(t, open(), 1)

	restored := unbound
	restored.State = AvailabilityReady
	require.NoError(t, observe(restored))
	assert.Empty(t, open(), "the binding was verified again")

	// Raised again, then the job moves to another version: the old version's
	// binding problem ends with it.
	require.NoError(t, observe(unbound))
	require.Len(t, open(), 1)
	_, err := f.store.UpdateVersion(f.ctx, job.JobID, "upd-1", job.Version, f.version(2), cli)
	require.NoError(t, err)
	assert.Empty(t, open())
}

// Action- and binding-scope exceptions are not resolved directly; a job
// exception still is.
func TestScopedExceptionsAreNotResolvedDirectly(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
		if err := tx.Observe(Observation{Scope: ScopeBinding, Kind: "job_commands_unbound", State: AvailabilityStale, ClaimID: c.ClaimID, Fence: c.Fence}); err != nil {
			return err
		}
		return tx.Observe(Observation{State: AvailabilityWorkerOffline, Kind: "worker_offline"})
	})
	require.NoError(t, err)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	for id, e := range got.Exceptions {
		_, err := f.tx(job.JobID, person, func(tx *JobTx) error { return tx.ResolveException(id) })
		if e.Scope == ScopeBinding {
			assert.Equal(t, CodeNotPermitted, code(t, err))
		} else {
			assert.NoError(t, err)
		}
	}
}

// NormalizeVersion is what registration stores, without touching its input.
func TestNormalizeVersionIsWhatRegistrationStores(t *testing.T) {
	f := newFixture(t)
	input := func() JobVersion {
		v := f.version(1)
		v.ExpectedOutcome.Deliverables = []Deliverable{{Name: "report", Path: "out/report.md"}}
		return v
	}
	job := f.readyWith("k", func(jv *JobVersion) { *jv = input() })
	v := input()
	stored, err := f.store.GetVersion(f.ctx, job.JobID, 1)
	require.NoError(t, err)

	got, err := NormalizeVersion(job.JobID, v)
	require.NoError(t, err)
	assert.Empty(t, v.ExpectedOutcome.Deliverables[0].Delivery, "the input is not modified")
	assert.Empty(t, v.RetirementRules.OnTargetDeleted)
	got.OwnerID, got.Version, got.Created = stored.OwnerID, stored.Version, stored.Created
	want, err := CanonicalJSON(stored)
	require.NoError(t, err)
	have, err := CanonicalJSON(got)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(have))

	bad := v
	bad.Title = ""
	_, err = NormalizeVersion(job.JobID, bad)
	assert.Equal(t, CodeInvalid, code(t, err), "what registration refuses")
}
