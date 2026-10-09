// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
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

// A person's retry of a run is a decided dagu.retry_run proposal, executed
// once under an execution claim; a run of another version is refused.
func TestProposeRetry(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	propose := func(params RetryRunParams, key string) (*Proposal, *Decision, error) {
		var p *Proposal
		var d *Decision
		_, err := f.tx(job.JobID, person, func(tx *JobTx) error {
			var err error
			p, d, err = tx.ProposeRetry(params, key)
			return err
		})
		return p, d, err
	}
	_, _, err := propose(RetryRunParams{RunID: "run-1", RunSpecSHA256: "sha256:old", PackageDigest: job.PackageDigest}, "k1")
	assert.Equal(t, CodeStaleBinding, code(t, err), "a run of another version is not retried")

	params := RetryRunParams{RunID: "run-1", RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest}
	p, d, err := propose(params, "k1")
	require.NoError(t, err)
	assert.Equal(t, ProposalDecided, p.State)
	assert.Equal(t, VerdictRetry, d.Verdict)
	_, _, err = propose(params, "k1")
	assert.Equal(t, CodeDuplicate, code(t, err))

	actionID, err := ApprovedActionID(p.ProposalID, d.DecisionID)
	require.NoError(t, err)
	ec := acquire(t, f, job.JobID, ClaimExecution, time.Minute)
	authorize := func() (*Grant, error) {
		var g *Grant
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			var err error
			g, err = tx.Authorize(EffectRequest{ActionID: actionID, JobVersion: job.Version, PackageDigest: job.PackageDigest,
				Approved: &ApprovedEffect{ProposalID: p.ProposalID, DecisionID: d.DecisionID, ClaimID: ec.ClaimID, Fence: ec.Fence}})
			return err
		})
		return g, err
	}
	g, err := authorize()
	require.NoError(t, err)
	_, err = authorize()
	assert.Equal(t, CodeActionExists, code(t, err), "one retry decision, one new attempt")
	got, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: ec.ClaimID, Fence: ec.Fence, State: ActionSucceeded, Receipt: "run-1/attempt-2"})
		return err
	})
	require.NoError(t, err)
	assert.Empty(t, got.Proposals)
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

	params := json.RawMessage(`{"action_id":"` + actionID + `"}`)
	escalation, err := EscalationProposalID(actionID, job.Version)
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
	escalation, err := EscalationProposalID(actionID, job.Version)
	require.NoError(t, err)
	var p *Proposal
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		var err error
		p, err = tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: escalation,
			Action: ActionSpec{Name: ActionUncertainEffect, Params: json.RawMessage(`{"action_id":"` + actionID + `"}`)}})
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
		_, _, err := tx.ProposeRetry(RetryRunParams{RunID: "run-1", RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest}, "k1")
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
}
