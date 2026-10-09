// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/review"
	"github.com/dagucloud/dagu/v2/internal/txe/review/reviewtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// specDigest is the digest of the job's current DAG in these tests.
	specDigest = "sha256:5pec"
	jobID      = "job_01HZX0000000000000000000AA"
	targetID   = "volume-uid-1111"
)

// clock is a controllable time source shared by the registry and reviewer.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// effects is a fixture destination: it counts every external effect and can
// be told what the reviewer gets to learn about each one.
type effects struct {
	mu sync.Mutex
	// applied counts effects that really happened, by action name.
	applied map[string]int
	// keys records the idempotency key of every attempt.
	keys []string
	// run decides the reported result; the effect itself has already been
	// counted when it returns Applied or Unknown with happened=true.
	run   func(action review.Action) (res review.EffectResult, happened bool)
	probe func(action review.Action) review.EffectResult
}

func newEffects() *effects {
	return &effects{applied: map[string]int{}}
}

func (e *effects) Run(_ context.Context, _ review.Job, _ review.DeclaredAction, action review.Action) review.EffectResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.keys = append(e.keys, action.ID)
	res, happened := review.EffectResult{Status: review.EffectApplied, Receipt: "receipt-" + action.Name}, true
	if e.run != nil {
		res, happened = e.run(action)
	}
	if happened {
		e.applied[action.Name]++
	}
	return res
}

func (e *effects) Probe(_ context.Context, _ review.Job, _ review.DeclaredAction, action review.Action) review.EffectResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.probe != nil {
		return e.probe(action)
	}
	return review.EffectResult{Status: review.EffectUnknown}
}

func (e *effects) count(name string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.applied[name]
}

// opener records which proposals were made answerable.
type opener struct {
	mu     sync.Mutex
	opened map[string]int
	closed map[string]int
	// close decides what closing a proposal's run finds; closed when nil.
	close func(p review.Proposal) (review.ClosureOutcome, error)
}

func (o *opener) OpenDecision(_ context.Context, p review.Proposal) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.opened == nil {
		o.opened = map[string]int{}
	}
	o.opened[p.NativeTask.RunID]++
	return nil
}

func (o *opener) CloseDecision(_ context.Context, p review.Proposal) (review.ClosureOutcome, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed == nil {
		o.closed = map[string]int{}
	}
	o.closed[p.NativeTask.RunID]++
	if o.close != nil {
		return o.close(p)
	}
	return review.ClosureClosed, nil
}

// runs is a fake of the service's run API. Each run has a latest attempt;
// a retry keeps the run id and, by default, starts the next attempt.
type runs struct {
	mu    sync.Mutex
	state map[string]review.RunState
	// retried records every retry request that reached the service.
	retried []string
	// retry decides what a retry request does; it starts a new attempt
	// when nil.
	retry func(runID string) error
	// readErr fails reads of a run's state while set.
	readErr error
	// unreadable fails reads of single runs.
	unreadable map[string]error
	// requested records the execution every retry request named, admitted
	// or not; retried records only the admitted ones.
	requested []review.Execution
	// beforeAdmission runs as a retry request arrives, before the service
	// compares the run's latest execution with the one the request names.
	beforeAdmission func(runID string)
	seq             int
}

func newRuns() *runs {
	return &runs{state: map[string]review.RunState{}, seq: 1}
}

// fail records a finished, unsuccessful latest attempt of the run.
func (r *runs) fail(runID, attemptID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state[runID] = review.RunState{AttemptID: attemptID, Status: "failed"}
}

// start begins the run's next attempt, as a native retry on Dagu's direct
// path does.
func (r *runs) start(runID string) string {
	r.seq++
	id := fmt.Sprintf("att-%d", r.seq)
	r.state[runID] = review.RunState{AttemptID: id, Status: "running", Active: true}
	return id
}

// requeue queues the run's latest attempt again under the same attempt id,
// as a native retry on Dagu's queued path does: only the queued time moves.
func (r *runs) requeue(runID string) review.Execution {
	r.seq++
	state := r.state[runID]
	state.QueuedAt = fmt.Sprintf("2026-10-09T10:00:%02dZ", r.seq)
	state.Status, state.Active, state.Succeeded = "queued", true, false
	r.state[runID] = state
	return state.Execution()
}

// ref is the reference of the run's latest execution.
func (r *runs) ref(runID string) string {
	return r.state[runID].Execution().Ref()
}

func (r *runs) RunState(_ context.Context, _, runID string) (review.RunState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.readErr != nil {
		return review.RunState{}, r.readErr
	}
	if err := r.unreadable[runID]; err != nil {
		return review.RunState{}, err
	}
	state, ok := r.state[runID]
	if !ok {
		return review.RunState{}, review.ErrNotFound
	}
	return state, nil
}

// RetryRun is the service's conditional retry: it is admitted only while
// expected is the run's latest execution, and that is checked here, at the
// service, at the moment of admission.
func (r *runs) RetryRun(_ context.Context, _, runID string, expected review.Execution) error {
	// The hook runs before the lock is taken: it changes the run through
	// the fake's own methods, which lock.
	if r.beforeAdmission != nil {
		r.beforeAdmission(runID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requested = append(r.requested, expected)
	if now := r.state[runID].Execution(); now != expected {
		return fmt.Errorf("%w: 409 execution_changed: run %s is at %s, not %s", review.ErrRunNotRetryable, runID, now.Ref(), expected.Ref())
	}
	r.retried = append(r.retried, runID)
	if r.retry != nil {
		return r.retry(runID)
	}
	r.start(runID)
	return nil
}

type fixture struct {
	t        *testing.T
	clock    *clock
	registry *reviewtest.Registry
	effects  *effects
	opener   *opener
}

func fixtureJob() review.Job {
	return review.Job{
		ID:               jobID,
		OwnerID:          "own_01HZX0000000000000000000AA",
		ProjectID:        "prj_01HZX0000000000000000000AA",
		MachineID:        "mch_01HZX0000000000000000000AA",
		Version:          1,
		PackageDigest:    "sha256:aaaa",
		DAGSpecSHA256:    specDigest,
		Title:            "Volume monitor",
		Purpose:          "Watch free space on the data volume until the migration is done.",
		Targets:          []review.Target{{Kind: "k8s.pv", StableID: targetID, Environment: "development"}},
		ExpectedOutcomes: []string{"free space stays above 20%"},
		Deliverables:     []string{"daily usage report"},
		RetirementRules:  []string{"retire when the volume is deleted"},
		Lifecycle:        review.LifecycleActive,
		Availability:     review.AvailabilityReady,
		Review: review.ReviewPolicy{
			Brief:       "Check that usage reports keep arriving and free space is healthy.",
			CadenceSec:  3600,
			MaxAttempts: 2,
			Actions: []review.DeclaredAction{
				{Name: "collect_diagnostics", Routine: true, Command: []string{"true"}, Params: []string{"depth"}, Idempotency: review.IdempotencyReadOnly},
				{Name: "notify", Routine: true, Command: []string{"true"}, Idempotency: review.IdempotencyNone},
				{Name: "expand_volume", Routine: false, Command: []string{"true"}, Params: []string{"size_gb"}, Idempotency: review.IdempotencyNone},
			},
		},
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	c := &clock{now: time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)}
	reg := reviewtest.New()
	reg.Now = c.Now
	require.NoError(t, reg.PutJob(fixtureJob()))
	return &fixture{t: t, clock: c, registry: reg, effects: newEffects(), opener: &opener{}}
}

// reviewer returns a new Reviewer, as a fresh process would build one.
func (f *fixture) reviewer(holder string) *review.Reviewer {
	return &review.Reviewer{
		MachineID:   fixtureJob().MachineID,
		Registry:    f.registry,
		Effector:    f.effects,
		Opener:      f.opener,
		Holder:      holder,
		AgentClient: "fixture-agent 1.0",
		DecideDAG:   "txe-decide-mch",
		ClaimTTL:    10 * time.Minute,
		Now:         f.clock.Now,
	}
}

func (f *fixture) addRun(id, status string) {
	f.t.Helper()
	require.NoError(f.t, f.registry.AddRun(jobID, review.RunEvidence{
		RunID: id, JobVersion: 1, Status: status, SpecSHA256: specDigest, AttemptID: "att-1",
		Outputs:   map[string]string{"free_pct": "31"},
		Artifacts: []string{"reports/" + id + ".json"},
	}))
}

func (f *fixture) state() *reviewtest.State {
	var snapshot *reviewtest.State
	f.registry.View(func(s *reviewtest.State) { snapshot = s })
	return snapshot
}

func (f *fixture) prepare(holder string) review.Prepared {
	f.t.Helper()
	prepared, err := f.reviewer(holder).Prepare(context.Background(), jobID)
	require.NoError(f.t, err)
	return prepared
}

func (f *fixture) apply(holder string, prepared review.Prepared, d review.AgentDecision) review.Applied {
	f.t.Helper()
	applied, err := f.reviewer(holder).Apply(context.Background(), prepared, d)
	require.NoError(f.t, err)
	return applied
}

func act(name string, params map[string]string) review.AgentAction {
	return review.AgentAction{Name: name, TargetID: targetID, Params: params, Reason: "fixture"}
}

// IT-07: a reviewer with no earlier conversation is handed the job's saved
// purpose and policy, records an evidence-linked decision, and the
// checkpoint advances over exactly the runs it was shown.
func TestFreshReviewCoversOnlyPacketRuns(t *testing.T) {
	f := newFixture(t)
	f.addRun("run-1", "succeeded")
	f.addRun("run-2", "succeeded")

	prepared := f.prepare("reviewer-a")
	require.Empty(t, prepared.Skipped)
	packet := prepared.Packet
	assert.Equal(t, "Watch free space on the data volume until the migration is done.", packet.Job.Purpose)
	assert.Equal(t, []string{"daily usage report"}, packet.Job.Deliverables)
	assert.Equal(t, []string{"retire when the volume is deleted"}, packet.Job.RetirementRules)
	assert.Len(t, packet.Job.Review.Actions, 3)
	assert.Equal(t, []string{"run-1", "run-2"}, packet.RunIDs())

	// A result that lands while the agent is thinking is not covered.
	f.addRun("run-3", "failed")

	applied := f.apply("reviewer-a", prepared, review.AgentDecision{
		Outcome: review.OutcomeContinue, Reasoning: "Reports arrive and space is healthy.",
		EvidenceRunIDs: []string{"run-2"},
	})
	assert.Equal(t, review.OutcomeContinue, applied.Review.Outcome)
	assert.Equal(t, []string{"run-1", "run-2"}, applied.Review.CoveredRuns)
	assert.Equal(t, "fixture-agent 1.0", applied.Review.AgentClient)
	assert.Positive(t, applied.Review.PacketBytes)

	s := f.state()
	cp := s.Checkpoints[jobID]
	assert.Equal(t, 1, cp.Version)
	assert.Equal(t, "run-2", cp.RunCursor)
	assert.Equal(t, f.clock.Now().Add(time.Hour), cp.NextReviewAt)
	require.Len(t, s.Reviews[jobID], 1)
	assert.Empty(t, s.Claims, "the claim is released when the review is recorded")

	next := f.prepare("reviewer-b")
	assert.Equal(t, []string{"run-3"}, next.Packet.RunIDs())
	assert.NotEqual(t, packet.ReviewID, next.Packet.ReviewID)
}

// A decision that cites a run the reviewer was never shown is refused and
// nothing is recorded.
func TestDecisionCitingUnknownEvidenceIsRejected(t *testing.T) {
	f := newFixture(t)
	f.addRun("run-1", "succeeded")
	prepared := f.prepare("reviewer-a")

	_, err := f.reviewer("reviewer-a").Apply(context.Background(), prepared, review.AgentDecision{
		Outcome: review.OutcomeContinue, Reasoning: "ok", EvidenceRunIDs: []string{"run-99"},
	})
	var failure *review.AgentFailure
	require.ErrorAs(t, err, &failure)
	assert.Equal(t, review.ExceptionReviewerFailed, failure.Kind)
	assert.Equal(t, 0, f.state().Checkpoints[jobID].Version)
}

// IT-08: the routine action runs and records its receipt; the action that
// needs approval, an undeclared action, and one aimed at an unregistered
// target all wait for a human and cause no effect.
func TestRoutineRunsAndEverythingElseIsProposed(t *testing.T) {
	f := newFixture(t)
	f.addRun("run-1", "failed")
	prepared := f.prepare("reviewer-a")

	applied := f.apply("reviewer-a", prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "The run failed; collect diagnostics and grow the volume.",
		EvidenceRunIDs: []string{"run-1"},
		Actions: []review.AgentAction{
			act("collect_diagnostics", map[string]string{"depth": "full"}),
			act("expand_volume", map[string]string{"size_gb": "200"}),
			act("delete_volume", nil),
			{Name: "collect_diagnostics", TargetID: "some-other-volume", Reason: "fixture"},
			act("collect_diagnostics", map[string]string{"undeclared": "x"}),
		},
	})

	require.Len(t, applied.Executed, 1)
	assert.Equal(t, review.ActionSucceeded, applied.Executed[0].State)
	assert.Equal(t, "receipt-collect_diagnostics", applied.Executed[0].Receipt)
	assert.Equal(t, 1, f.effects.count("collect_diagnostics"))
	assert.Equal(t, 0, f.effects.count("expand_volume"))
	assert.Equal(t, 0, f.effects.count("delete_volume"))

	s := f.state()
	require.Len(t, s.Proposals[jobID], 4)
	kinds := map[review.ProposalKind]int{}
	for _, p := range s.Proposals[jobID] {
		kinds[p.Kind]++
		assert.Equal(t, review.ProposalOpen, p.State)
		assert.Equal(t, "txe-decide-mch", p.NativeTask.DAG)
		assert.Equal(t, "decide", p.NativeTask.StepID)
		assert.Equal(t, []string{"run-1"}, p.EvidenceRuns)
		assert.Equal(t, 1, f.opener.opened[p.NativeTask.RunID])
	}
	assert.Equal(t, 1, kinds[review.ProposalAction])
	assert.Equal(t, 3, kinds[review.ProposalQuestion])
	assert.Empty(t, s.Claims, "waiting on a human does not hold the claim")
}

// IT-09: approve, reject and redirect decisions reach the next fresh review;
// only the approved proposal produces an effect, exactly once, linked to its
// decision.
func TestHumanDecisionsDriveTheNextReview(t *testing.T) {
	f := newFixture(t)
	f.addRun("run-1", "failed")
	prepared := f.prepare("reviewer-a")
	f.apply("reviewer-a", prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Three options.", EvidenceRunIDs: []string{"run-1"},
		Actions: []review.AgentAction{
			act("expand_volume", map[string]string{"size_gb": "100"}),
			act("expand_volume", map[string]string{"size_gb": "200"}),
			act("expand_volume", map[string]string{"size_gb": "300"}),
		},
	})
	proposals := f.state().Proposals[jobID]
	require.Len(t, proposals, 3)

	approved, err := f.registry.Decide(jobID, proposals[0].ID, review.VerdictApprove, "", "connor")
	require.NoError(t, err)
	rejected, err := f.registry.Decide(jobID, proposals[1].ID, review.VerdictReject, "", "connor")
	require.NoError(t, err)
	redirected, err := f.registry.Decide(jobID, proposals[2].ID, review.VerdictRedirect, "Clean old snapshots first.", "connor")
	require.NoError(t, err)

	ctx := context.Background()
	exec := f.reviewer("executor")
	out, err := exec.Execute(ctx, jobID, proposals[0].ID, approved.ID)
	require.NoError(t, err)
	assert.Empty(t, out.Skipped)
	assert.Equal(t, review.ActionSucceeded, out.Action.State)
	assert.Equal(t, approved.ID, out.Action.DecisionID)
	assert.Equal(t, proposals[0].ID, out.Action.ProposalID)

	out, err = exec.Execute(ctx, jobID, proposals[1].ID, rejected.ID)
	require.NoError(t, err)
	assert.Equal(t, "verdict is reject", out.Skipped)
	out, err = exec.Execute(ctx, jobID, proposals[2].ID, redirected.ID)
	require.NoError(t, err)
	assert.Equal(t, "verdict is redirect", out.Skipped)

	// Completing the same task again does not repeat the effect.
	out, err = exec.Execute(ctx, jobID, proposals[0].ID, approved.ID)
	require.NoError(t, err)
	assert.Equal(t, "already journaled as succeeded", out.Skipped)
	// A rejected proposal cannot borrow another proposal's approval.
	out, err = exec.Execute(ctx, jobID, proposals[1].ID, approved.ID)
	require.NoError(t, err)
	assert.Equal(t, "decision belongs to another proposal", out.Skipped)

	assert.Equal(t, 1, f.effects.count("expand_volume"))
	assert.Empty(t, f.state().Claims, "the execution claim is released")

	next := f.prepare("reviewer-b")
	require.Len(t, next.Packet.HumanFeedback, 3)
	assert.Equal(t, "connor", next.Packet.HumanFeedback[2].Actor)
	assert.Equal(t, "Clean old snapshots first.", next.Packet.HumanFeedback[2].Instructions)

	// The redirect is guidance only: an undeclared action it inspires is
	// still proposed, never run.
	f.apply("reviewer-b", next, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Following the redirect.",
		Actions: []review.AgentAction{act("delete_snapshots", nil)},
	})
	assert.Equal(t, 0, f.effects.count("delete_snapshots"))
	assert.Equal(t, redirected.ID, f.state().Checkpoints[jobID].DecisionCursor)

	// Feedback is consumed once.
	f.clock.Advance(2 * time.Hour)
	assert.Empty(t, f.prepare("reviewer-c").Packet.HumanFeedback)
}

// IT-10: an approval given before the job's target, package or version
// changed cannot authorize the changed action.
func TestStaleApprovalAuthorizesNothing(t *testing.T) {
	f := newFixture(t)
	f.addRun("run-1", "failed")
	prepared := f.prepare("reviewer-a")
	f.apply("reviewer-a", prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Grow it.",
		Actions: []review.AgentAction{act("expand_volume", map[string]string{"size_gb": "200"})},
	})
	proposal := f.state().Proposals[jobID][0]
	approved, err := f.registry.Decide(jobID, proposal.ID, review.VerdictApprove, "", "connor")
	require.NoError(t, err)

	changed := fixtureJob()
	changed.Version = 2
	changed.PackageDigest = "sha256:bbbb"
	require.NoError(t, f.registry.PutJob(changed))

	out, err := f.reviewer("executor").Execute(context.Background(), jobID, proposal.ID, approved.ID)
	require.NoError(t, err)
	assert.Contains(t, out.Skipped, "proposal is superseded")
	assert.Equal(t, 0, f.effects.count("expand_volume"))
	assert.Empty(t, f.state().Actions[jobID])
	assert.Equal(t, review.ProposalSuperseded, f.state().Proposals[jobID][0].State)

	// The next review can ask again against the new revision.
	f.addRun("run-2", "failed")
	next := f.prepare("reviewer-b")
	f.apply("reviewer-b", next, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Still needed.",
		Actions: []review.AgentAction{act("expand_volume", map[string]string{"size_gb": "200"})},
	})
	proposals := f.state().Proposals[jobID]
	require.Len(t, proposals, 2)
	assert.Equal(t, review.ProposalOpen, proposals[1].State)
	assert.NotEqual(t, proposals[0].BindingDigest, proposals[1].BindingDigest)
}

// IT-11: of two overlapping reviewers only one holds the claim; a replayed
// completion does not repeat the action; a reviewer that crashes after
// claiming is replaced once its claim expires, and its late write is refused.
func TestOverlapReplayAndExpiredClaim(t *testing.T) {
	f := newFixture(t)
	f.addRun("run-1", "failed")

	first := f.prepare("reviewer-a")
	require.Empty(t, first.Skipped)
	second := f.prepare("reviewer-b")
	assert.Equal(t, review.SkipClaimHeld, second.Skipped)

	decision := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify once.",
		Actions: []review.AgentAction{act("notify", nil)},
	}
	f.apply("reviewer-a", first, decision)
	assert.Equal(t, 1, f.effects.count("notify"))

	replay, err := f.reviewer("reviewer-a").Apply(context.Background(), first, decision)
	require.NoError(t, err)
	assert.True(t, replay.Replayed)
	assert.Equal(t, 1, f.effects.count("notify"))

	// reviewer-c claims and dies without applying.
	f.clock.Advance(2 * time.Hour)
	f.addRun("run-2", "failed")
	crashed := f.prepare("reviewer-c")
	require.Empty(t, crashed.Skipped)
	assert.Equal(t, review.SkipClaimHeld, f.prepare("reviewer-d").Skipped)

	f.clock.Advance(11 * time.Minute)
	recovered := f.prepare("reviewer-d")
	require.Empty(t, recovered.Skipped)
	assert.Greater(t, recovered.Claim.Fence, crashed.Claim.Fence)
	assert.Equal(t, crashed.Packet.ReviewID, recovered.Packet.ReviewID, "the replacement works the same episode")

	// The dead reviewer's process wakes up and tries to finish.
	_, err = f.reviewer("reviewer-c").Apply(context.Background(), crashed, decision)
	require.ErrorIs(t, err, review.ErrStaleFence)
	assert.Equal(t, 1, f.effects.count("notify"))

	f.apply("reviewer-d", recovered, decision)
	assert.Equal(t, 2, f.effects.count("notify"), "a later episode is a new intent and may act again")

	s := f.state()
	assert.Equal(t, 2, s.Checkpoints[jobID].Version)
	assert.Len(t, s.Actions[jobID], 2)
	assert.Contains(t, s.Transitions, "claim "+crashed.Claim.ID+" fence 2 expired")
}

// Two decisions naming the same routine action in one episode produce one
// effect.
func TestSameIntentInOneEpisodeRunsOnce(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare("reviewer-a")
	f.apply("reviewer-a", prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil), act("notify", nil)},
	})
	assert.Equal(t, 1, f.effects.count("notify"))
	assert.Len(t, f.state().Actions[jobID], 1)
}

// crashAfterEffect makes the registry lose the outcome write, as if the
// process died right after the external effect.
type crashAfterEffect struct {
	*reviewtest.Registry
}

var errCrash = errors.New("process died")

func (c crashAfterEffect) FinishAction(context.Context, review.FinishRequest) error {
	return errCrash
}

// IT-12, crash after the effect and before its receipt: the action is found
// executing by the next claim, marked uncertain, and settled by the probe
// without a second effect.
func TestCrashAfterEffectReconcilesByProbe(t *testing.T) {
	f := newFixture(t)
	job := fixtureJob()
	job.Review.Actions[1].Reconcile = []string{"probe"}
	require.NoError(t, f.registry.PutJob(job))

	prepared := f.prepare("reviewer-a")
	dying := f.reviewer("reviewer-a")
	dying.Registry = crashAfterEffect{f.registry}
	decision := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	}
	_, err := dying.Apply(context.Background(), prepared, decision)
	require.ErrorIs(t, err, errCrash)
	assert.Equal(t, 1, f.effects.count("notify"))
	require.Len(t, f.state().Actions[jobID], 1)
	assert.Equal(t, review.ActionExecuting, f.state().Actions[jobID][0].State)
	assert.Equal(t, 0, f.state().Checkpoints[jobID].Version, "the checkpoint does not cover an unrecorded effect")

	f.effects.probe = func(review.Action) review.EffectResult {
		return review.EffectResult{Status: review.EffectApplied, Receipt: "found-at-destination"}
	}
	f.clock.Advance(11 * time.Minute)
	recovered := f.prepare("reviewer-b")
	require.Empty(t, recovered.Skipped)

	action := f.state().Actions[jobID][0]
	assert.Equal(t, review.ActionSucceeded, action.State)
	assert.Equal(t, "found-at-destination", action.Receipt)
	assert.Empty(t, recovered.Packet.UnresolvedActions)

	// The agent asks for the same thing again in the same episode.
	f.apply("reviewer-b", recovered, decision)
	assert.Equal(t, 1, f.effects.count("notify"), "the effect happened exactly once")
	assert.Len(t, f.state().Actions[jobID], 1)
}

// IT-12, the probe finds nothing after an interrupted attempt: that is not
// proof the attempt will not still apply, so the action is not closed as
// not applied. It goes to the owner and the intent stays blocked.
func TestAbsentProbeDoesNotCloseAnInterruptedAttempt(t *testing.T) {
	f := newFixture(t)
	job := fixtureJob()
	job.Review.Actions[1].Reconcile = []string{"probe"}
	require.NoError(t, f.registry.PutJob(job))

	// The process dies after the action is journaled and before the effect.
	f.effects.run = func(review.Action) (review.EffectResult, bool) {
		return review.EffectResult{Status: review.EffectUnknown}, false
	}
	prepared := f.prepare("reviewer-a")
	dying := f.reviewer("reviewer-a")
	dying.Registry = crashAfterEffect{f.registry}
	_, err := dying.Apply(context.Background(), prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	})
	require.ErrorIs(t, err, errCrash)
	assert.Equal(t, 0, f.effects.count("notify"))

	f.effects.probe = func(review.Action) review.EffectResult {
		return review.EffectResult{Status: review.EffectNotApplied, Detail: "nothing at destination"}
	}
	f.clock.Advance(11 * time.Minute)
	recovered := f.prepare("reviewer-b")
	s := f.state()
	assert.Equal(t, review.ActionEscalated, s.Actions[jobID][0].State)
	require.Len(t, s.Proposals[jobID], 1)
	assert.Equal(t, review.ProposalUncertain, s.Proposals[jobID][0].Kind)
	require.Len(t, recovered.Packet.UnresolvedActions, 1)

	// The agent asks again; nothing runs while the owner has not answered.
	f.effects.run = nil
	f.apply("reviewer-b", recovered, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	})
	assert.Equal(t, 0, f.effects.count("notify"))
	assert.Len(t, f.effects.keys, 1, "only the interrupted attempt was ever made")
}

// An interrupted read-only action has no external effect to wait for, so it
// is closed as not applied and may be requested again.
func TestInterruptedReadOnlyActionIsClosed(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare("reviewer-a")
	dying := f.reviewer("reviewer-a")
	dying.Registry = crashAfterEffect{f.registry}
	collect := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Collect.",
		Actions: []review.AgentAction{act("collect_diagnostics", nil)},
	}
	_, err := dying.Apply(context.Background(), prepared, collect)
	require.ErrorIs(t, err, errCrash)

	f.clock.Advance(11 * time.Minute)
	recovered := f.prepare("reviewer-b")
	assert.Equal(t, review.ActionNotApplied, f.state().Actions[jobID][0].State)
	assert.Empty(t, recovered.Packet.UnresolvedActions)
	assert.Empty(t, f.state().Proposals[jobID])

	// A later episode may run the diagnostic again.
	f.apply("reviewer-b", recovered, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "ok"})
	f.clock.Advance(2 * time.Hour)
	f.apply("reviewer-c", f.prepare("reviewer-c"), collect)
	assert.Equal(t, 2, f.effects.count("collect_diagnostics"))
}

// IT-12, timeout with an uncertain effect and no way to probe: the action
// becomes uncertain, is escalated to a human exactly once, and is never
// retried on its own.
func TestUncertainEffectEscalatesInsteadOfRetrying(t *testing.T) {
	f := newFixture(t)
	f.effects.run = func(review.Action) (review.EffectResult, bool) {
		return review.EffectResult{Status: review.EffectUnknown, Detail: "timed out"}, true
	}
	prepared := f.prepare("reviewer-a")
	decision := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	}
	applied := f.apply("reviewer-a", prepared, decision)
	require.Len(t, applied.Executed, 1)
	assert.Equal(t, review.ActionUncertain, applied.Executed[0].State)
	assert.Equal(t, 1, f.effects.count("notify"))

	f.clock.Advance(2 * time.Hour)
	next := f.prepare("reviewer-b")
	s := f.state()
	assert.Equal(t, review.ActionEscalated, s.Actions[jobID][0].State)
	require.Len(t, s.Proposals[jobID], 1)
	assert.Equal(t, review.ProposalUncertain, s.Proposals[jobID][0].Kind)
	assert.Equal(t, s.Actions[jobID][0].ID, s.Proposals[jobID][0].RelatedAction)
	assert.NotContains(t, s.Proposals[jobID][0].AllowedVerdicts, review.VerdictApprove)
	assert.Len(t, f.effects.keys, 1, "no second attempt was made")
	require.Len(t, next.Packet.OpenProposals, 1)

	// Reviewing again does not escalate the same action twice.
	f.apply("reviewer-b", next, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "Waiting on Connor."})
	f.clock.Advance(2 * time.Hour)
	f.prepare("reviewer-c")
	assert.Len(t, f.state().Proposals[jobID], 1)
}

// A routine action that keeps failing is bounded: after max_attempts
// consecutive failures it is proposed instead of tried again.
func TestRepeatedFailuresAreBounded(t *testing.T) {
	f := newFixture(t)
	f.effects.run = func(review.Action) (review.EffectResult, bool) {
		return review.EffectResult{Status: review.EffectNotApplied, Detail: "exit 1"}, false
	}
	decision := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Collect.",
		Actions: []review.AgentAction{act("collect_diagnostics", nil)},
	}
	for i, holder := range []string{"reviewer-a", "reviewer-b", "reviewer-c"} {
		f.apply(holder, f.prepare(holder), decision)
		f.clock.Advance(2 * time.Hour)
		assert.Len(t, f.effects.keys, min(i+1, 2))
	}
	s := f.state()
	assert.Len(t, s.Actions[jobID], 2)
	require.Len(t, s.Proposals[jobID], 1)
	assert.Contains(t, s.Proposals[jobID][0].Question, "failed 2 times in a row")
}

// IT-13: a review cannot act on, or advance the checkpoint of, a job that
// was retired while the agent was running, and a retired job is not claimed.
func TestStaleReviewCannotBypassRetirement(t *testing.T) {
	f := newFixture(t)
	f.addRun("run-1", "failed")
	prepared := f.prepare("reviewer-a")

	retired := fixtureJob()
	retired.Lifecycle = review.LifecycleRetired
	require.NoError(t, f.registry.PutJob(retired))

	applied := f.apply("reviewer-a", prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	})
	assert.Equal(t, "job lifecycle is retired", applied.Aborted)
	assert.Equal(t, 0, f.effects.count("notify"))
	s := f.state()
	assert.Equal(t, 0, s.Checkpoints[jobID].Version)
	assert.Empty(t, s.Reviews[jobID])
	assert.Equal(t, review.LifecycleRetired, s.Jobs[jobID].Lifecycle)

	assert.Equal(t, review.SkipNotReviewable, f.prepare("reviewer-b").Skipped)
}

// A job whose version changed under the review is not acted on from the old
// packet.
func TestVersionChangeAbortsApply(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare("reviewer-a")
	changed := fixtureJob()
	changed.Version = 2
	require.NoError(t, f.registry.PutJob(changed))

	applied := f.apply("reviewer-a", prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	})
	assert.Equal(t, "job version changed from 1 to 2", applied.Aborted)
	assert.Equal(t, 0, f.effects.count("notify"))
}

// IT-15: an unavailable target or machine is reported as an exception and
// never changes the lifecycle; a reviewer cannot retire a job on its own.
func TestUnavailabilityIsNotRetirement(t *testing.T) {
	f := newFixture(t)
	offline := fixtureJob()
	offline.Availability = review.AvailabilityWorkerOffline
	require.NoError(t, f.registry.PutJob(offline))
	f.addRun("run-1", "failed")

	prepared := f.prepare("reviewer-a")
	assert.Equal(t, review.AvailabilityWorkerOffline, prepared.Packet.Job.Availability)
	f.apply("reviewer-a", prepared, review.AgentDecision{
		Outcome: review.OutcomePauseUnavailable, Reasoning: "Permission denied reading the volume.",
		EvidenceRunIDs: []string{"run-1"},
	})
	s := f.state()
	require.Len(t, s.Exceptions, 1)
	assert.Equal(t, review.ExceptionUnavailable, s.Exceptions[0].Kind)
	assert.Equal(t, review.LifecycleActive, s.Jobs[jobID].Lifecycle)

	f.clock.Advance(2 * time.Hour)
	f.addRun("run-2", "failed")
	f.apply("reviewer-b", f.prepare("reviewer-b"), review.AgentDecision{
		Outcome: review.OutcomeRetire, Reasoning: "The volume looks gone.", EvidenceRunIDs: []string{"run-2"},
	})
	s = f.state()
	assert.Equal(t, review.LifecycleActive, s.Jobs[jobID].Lifecycle)
	require.Len(t, s.Proposals[jobID], 1)
	assert.Contains(t, s.Proposals[jobID][0].AllowedVerdicts, review.VerdictRetire)
}

// An agent that cannot authenticate leaves one visible exception, releases
// the claim, covers no evidence and is not relaunched on the next tick.
func TestAgentAuthFailureIsVisibleAndBounded(t *testing.T) {
	f := newFixture(t)
	f.addRun("run-1", "succeeded")
	prepared := f.prepare("reviewer-a")

	_, err := review.ParseAgentOutput([]byte("Invalid API key · Please run /login"))
	var failure *review.AgentFailure
	require.ErrorAs(t, err, &failure)
	assert.Equal(t, review.ExceptionReviewerAuth, failure.Kind)
	require.NoError(t, f.reviewer("reviewer-a").Fail(context.Background(), prepared, failure))

	s := f.state()
	require.Len(t, s.Exceptions, 1)
	assert.Equal(t, review.ExceptionReviewerAuth, s.Exceptions[0].Kind)
	assert.Equal(t, fixtureJob().MachineID, s.Exceptions[0].MachineID)
	assert.Empty(t, s.Claims)
	assert.Equal(t, 0, s.Checkpoints[jobID].Version)
	assert.Empty(t, s.Checkpoints[jobID].RunCursor)

	due, err := f.registry.DueJobs(context.Background(), fixtureJob().MachineID, f.clock.Now().Add(10*time.Minute))
	require.NoError(t, err)
	assert.Empty(t, due)
	due, err = f.registry.DueJobs(context.Background(), fixtureJob().MachineID, f.clock.Now().Add(61*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, []string{jobID}, due)
}

// Several unanswered proposals coexist, each in its own run, and none blocks
// later reviews.
func TestUnansweredProposalsDoNotBlockReviews(t *testing.T) {
	f := newFixture(t)
	for i, holder := range []string{"reviewer-a", "reviewer-b", "reviewer-c"} {
		prepared := f.prepare(holder)
		require.Empty(t, prepared.Skipped)
		f.apply(holder, prepared, review.AgentDecision{
			Outcome: review.OutcomeWaitHuman, Reasoning: "Need a call.", Question: "Which size?",
		})
		f.clock.Advance(2 * time.Hour)
		assert.Len(t, f.state().Proposals[jobID], i+1)
	}
	assert.Len(t, f.opener.opened, 3)
	assert.Len(t, f.prepare("reviewer-d").Packet.OpenProposals, 3)
}

// IT-13: an effect that was in flight when its job retired is still settled
// afterwards, by probe only, and the retired job gets no review, proposal or
// new effect.
func TestRetiredJobStillSettlesInFlightAction(t *testing.T) {
	f := newFixture(t)
	job := fixtureJob()
	job.Review.Actions[1].Reconcile = []string{"probe"}
	require.NoError(t, f.registry.PutJob(job))

	prepared := f.prepare("reviewer-a")
	dying := f.reviewer("reviewer-a")
	dying.Registry = crashAfterEffect{f.registry}
	_, err := dying.Apply(context.Background(), prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	})
	require.ErrorIs(t, err, errCrash)

	job.Lifecycle = review.LifecycleRetired
	require.NoError(t, f.registry.PutJob(job))
	f.effects.probe = func(review.Action) review.EffectResult {
		return review.EffectResult{Status: review.EffectApplied, Receipt: "found-at-destination"}
	}
	f.clock.Advance(11 * time.Minute)

	assert.Equal(t, review.SkipNotReviewable, f.prepare("reviewer-b").Skipped)
	s := f.state()
	assert.Equal(t, review.ActionSucceeded, s.Actions[jobID][0].State)
	assert.Equal(t, "found-at-destination", s.Actions[jobID][0].Receipt)
	assert.Equal(t, 1, f.effects.count("notify"))
	assert.Empty(t, s.Proposals[jobID])
	assert.Empty(t, s.Reviews[jobID])
	assert.Equal(t, 0, s.Checkpoints[jobID].Version)
	assert.Empty(t, s.Claims)
	assert.Equal(t, review.LifecycleRetired, s.Jobs[jobID].Lifecycle)

	// With nothing left open, a retired job is not claimed at all.
	before := len(f.state().Transitions)
	assert.Equal(t, review.SkipNotReviewable, f.prepare("reviewer-c").Skipped)
	assert.Len(t, f.state().Transitions, before)
}

// An approved action cannot be executed for a job that retired after the
// approval.
func TestApprovalDoesNotSurviveRetirement(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare("reviewer-a")
	f.apply("reviewer-a", prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Grow it.",
		Actions: []review.AgentAction{act("expand_volume", map[string]string{"size_gb": "200"})},
	})
	proposal := f.state().Proposals[jobID][0]
	approved, err := f.registry.Decide(jobID, proposal.ID, review.VerdictApprove, "", "connor")
	require.NoError(t, err)

	retired := fixtureJob()
	retired.Lifecycle = review.LifecycleRetired
	require.NoError(t, f.registry.PutJob(retired))

	out, err := f.reviewer("executor").Execute(context.Background(), jobID, proposal.ID, approved.ID)
	require.NoError(t, err)
	assert.Equal(t, "job lifecycle is retired", out.Skipped)
	assert.Equal(t, 0, f.effects.count("expand_volume"))
	assert.Empty(t, f.state().Actions[jobID])
}

// Review finding 1: once an attempt's outcome is unknown, the same action on
// the same target is not run again in a later episode, whatever the agent
// asks, until the owner answers the escalation with "retry".
func TestUnresolvedIntentIsNotRunAgain(t *testing.T) {
	f := newFixture(t)
	f.effects.run = func(review.Action) (review.EffectResult, bool) {
		return review.EffectResult{Status: review.EffectUnknown, Detail: "timed out"}, true
	}
	notify := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	}
	f.apply("reviewer-a", f.prepare("reviewer-a"), notify)
	require.Equal(t, review.ActionUncertain, f.state().Actions[jobID][0].State)
	f.effects.run = nil

	// Episode 2: the uncertain attempt is escalated, and the agent asks again.
	f.clock.Advance(2 * time.Hour)
	second := f.prepare("reviewer-b")
	require.Len(t, second.Packet.UnresolvedActions, 1, "an escalated action stays unresolved while its question is open")
	applied := f.apply("reviewer-b", second, notify)
	assert.Empty(t, applied.Executed)
	assert.Contains(t, applied.Review.Notes[0], "unresolved")
	assert.Equal(t, 1, f.effects.count("notify"))
	assert.Len(t, f.state().Actions[jobID], 1)

	// The registry guard refuses it as well, independently of the reviewer.
	f.clock.Advance(2 * time.Hour)
	third := f.prepare("reviewer-c")
	_, err := f.registry.BeginAction(context.Background(), review.BeginRequest{
		Claim: third.Claim, ActionID: "act_direct", JobVersion: 1, Name: "notify", TargetID: targetID,
		IntentKey: review.IntentKey("notify", targetID, nil), ReviewID: third.Packet.ReviewID,
	})
	var denied *review.GuardDeniedError
	require.ErrorAs(t, err, &denied)
	assert.Equal(t, review.DenyIntentUnresolved, denied.Reason)

	// Any answer but "retry" keeps it blocked.
	escalation := f.state().Proposals[jobID][0]
	require.Equal(t, review.ProposalUncertain, escalation.Kind)
	f.apply("reviewer-c", third, notify)
	assert.Equal(t, 1, f.effects.count("notify"))

	// "retry" from the owner is the explicit resolution.
	_, err = f.registry.Decide(jobID, escalation.ID, review.VerdictRetry, "It did not go out.", "connor")
	require.NoError(t, err)
	f.clock.Advance(2 * time.Hour)
	f.apply("reviewer-d", f.prepare("reviewer-d"), notify)
	assert.Equal(t, 2, f.effects.count("notify"))
}

// Review finding 3: a crash between recording a review and advancing the
// checkpoint is finished from the stored review. Evidence that arrived
// afterwards is not skipped, and a second decision cannot replace the first.
func TestInterruptedEpisodeAdvancesOnlyOverItsOwnReview(t *testing.T) {
	f := newFixture(t)
	f.addRun("run-1", "succeeded")
	prepared := f.prepare("reviewer-a")

	dying := f.reviewer("reviewer-a")
	dying.Registry = crashBeforeCheckpoint{f.registry}
	_, err := dying.Apply(context.Background(), prepared, review.AgentDecision{
		Outcome: review.OutcomeContinue, Reasoning: "Healthy.", EvidenceRunIDs: []string{"run-1"},
	})
	require.ErrorIs(t, err, errCrash)
	require.Len(t, f.state().Reviews[jobID], 1)
	require.Equal(t, 0, f.state().Checkpoints[jobID].Version)

	f.addRun("run-2", "failed")
	f.clock.Advance(11 * time.Minute)
	recovered := f.prepare("reviewer-b")
	require.Empty(t, recovered.Skipped)

	// The interrupted episode ended at run-1; run-2 belongs to a new one.
	assert.Equal(t, 1, recovered.Packet.Episode)
	assert.Equal(t, []string{"run-2"}, recovered.Packet.RunIDs())
	assert.NotEqual(t, prepared.Packet.ReviewID, recovered.Packet.ReviewID)

	f.apply("reviewer-b", recovered, review.AgentDecision{
		Outcome: review.OutcomeContinue, Reasoning: "run-2 failed once.", EvidenceRunIDs: []string{"run-2"},
	})
	s := f.state()
	require.Len(t, s.Reviews[jobID], 2)
	assert.Equal(t, []string{"run-1"}, s.Reviews[jobID][0].CoveredRuns)
	assert.Equal(t, []string{"run-2"}, s.Reviews[jobID][1].CoveredRuns)
	assert.Equal(t, 2, s.Checkpoints[jobID].Version)
	assert.Equal(t, "run-2", s.Checkpoints[jobID].RunCursor)

	// The registry itself refuses a review id recorded over other evidence.
	f.clock.Advance(2 * time.Hour)
	claim := f.prepare("reviewer-c").Claim
	clash := s.Reviews[jobID][0]
	clash.CoveredRuns = []string{"run-1", "run-2"}
	require.ErrorIs(t, f.registry.RecordReview(context.Background(), claim, clash), review.ErrConflict)
}

// crashBeforeCheckpoint loses the checkpoint write, as if the process died
// right after the review was recorded.
type crashBeforeCheckpoint struct {
	*reviewtest.Registry
}

func (c crashBeforeCheckpoint) AdvanceCheckpoint(context.Context, review.Claim, review.Checkpoint, int) error {
	return errCrash
}

// Review finding 4: a holder does not start an effect its claim cannot
// outlive, and a later holder does not probe an attempt whose grant is still
// running, so "nothing there yet" is never recorded as "not applied".
func TestEffectsAreBoundedByLeaseAndGrant(t *testing.T) {
	f := newFixture(t)
	job := fixtureJob()
	job.Review.Actions[1].Reconcile = []string{"probe"}
	job.Review.Actions[1].TimeoutSec = 15 * 60
	require.NoError(t, f.registry.PutJob(job))
	notify := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	}

	// A 10 minute claim cannot cover a 15 minute action.
	applied := f.apply("reviewer-a", f.prepare("reviewer-a"), notify)
	assert.Empty(t, applied.Executed)
	assert.Contains(t, applied.Review.Notes[0], "claim ends before")
	assert.Empty(t, f.state().Actions[jobID])
	assert.Equal(t, 0, f.effects.count("notify"))

	// An attempt whose grant is still running may yet perform its effect,
	// so the next holder leaves it alone instead of probing it.
	probes := 0
	f.effects.probe = func(review.Action) review.EffectResult {
		probes++
		return review.EffectResult{Status: review.EffectNotApplied}
	}
	inFlight := review.Action{
		ID: "act_INFLIGHT", JobID: jobID, JobVersion: 1, Name: "notify", TargetID: targetID,
		IntentKey: review.IntentKey("notify", targetID, nil), State: review.ActionExecuting,
		GrantID: "grt_INFLIGHT", GrantExpiresAt: f.clock.Now().Add(3 * time.Hour),
	}
	require.NoError(t, f.registry.Update(func(s *reviewtest.State) error {
		s.Actions[jobID] = append(s.Actions[jobID], inFlight)
		return nil
	}))
	f.clock.Advance(2 * time.Hour)
	early := f.prepare("reviewer-b")
	assert.Zero(t, probes)
	assert.Equal(t, review.ActionExecuting, f.state().Actions[jobID][0].State)
	require.Len(t, early.Packet.UnresolvedActions, 1)

	// While it is in flight the same intent is not started a second time.
	applied = f.apply("reviewer-b", early, notify)
	assert.Empty(t, applied.Executed)
	assert.Equal(t, 0, f.effects.count("notify"))

	// Once the grant and its margin have passed, the attempt is probed. The
	// probe finds nothing, which still does not close it.
	f.clock.Advance(2 * time.Hour)
	f.prepare("reviewer-c")
	assert.Equal(t, 1, probes)
	assert.Equal(t, review.ActionEscalated, f.state().Actions[jobID][0].State)
}

// A holder whose grant has already ended does not start the effect at all.
func TestEffectIsNotStartedAfterItsGrant(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare("reviewer-a")
	slow := f.reviewer("reviewer-a")
	slow.Registry = stallAfterBegin{f.registry, f.clock}
	applied, err := slow.Apply(context.Background(), prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	})
	// The stall also outlives the claim, so the outcome write is refused.
	require.ErrorIs(t, err, review.ErrStaleFence)
	assert.Empty(t, applied.Executed)
	assert.Equal(t, 0, f.effects.count("notify"))
	assert.Empty(t, f.effects.keys, "the effect was never attempted")
}

// stallAfterBegin freezes the holder between journaling an action and
// running it, for longer than its grant and its claim.
type stallAfterBegin struct {
	*reviewtest.Registry
	clock *clock
}

func (s stallAfterBegin) BeginAction(ctx context.Context, req review.BeginRequest) (review.Action, error) {
	action, err := s.Registry.BeginAction(ctx, req)
	s.clock.Advance(time.Hour)
	return action, err
}

// Review finding 5: an attempt journaled under another job version is not
// interpreted through the current declaration. It stays unknown and goes to
// the owner, even if the action is now declared read-only.
func TestReconcileDoesNotApplyANewPolicyToAnOldAttempt(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare("reviewer-a")
	dying := f.reviewer("reviewer-a")
	dying.Registry = crashAfterEffect{f.registry}
	_, err := dying.Apply(context.Background(), prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	})
	require.ErrorIs(t, err, errCrash)
	require.Equal(t, 1, f.effects.count("notify"))

	// Version 2 redeclares notify as a read-only diagnostic with a probe.
	v2 := fixtureJob()
	v2.Version = 2
	v2.Review.Actions[1].Idempotency = review.IdempotencyReadOnly
	v2.Review.Actions[1].Reconcile = []string{"probe"}
	require.NoError(t, f.registry.PutJob(v2))
	probes := 0
	f.effects.probe = func(review.Action) review.EffectResult {
		probes++
		return review.EffectResult{Status: review.EffectNotApplied}
	}

	f.clock.Advance(11 * time.Minute)
	f.prepare("reviewer-b")
	s := f.state()
	assert.Zero(t, probes, "the new version's probe says nothing about the old attempt")
	assert.Equal(t, review.ActionEscalated, s.Actions[jobID][0].State)
	require.Len(t, s.Proposals[jobID], 1)
	assert.Contains(t, s.Proposals[jobID][0].Question, "version 1")
}

// Pass 2 finding: a "retry" answer is about the job as it was when the owner
// gave it. After the job changes, that answer unlocks nothing: the intent
// stays blocked and the owner is asked again about the new version.
func TestStaleRetryAnswerDoesNotUnlockAChangedJob(t *testing.T) {
	f := newFixture(t)
	f.effects.run = func(review.Action) (review.EffectResult, bool) {
		return review.EffectResult{Status: review.EffectUnknown, Detail: "timed out"}, true
	}
	notify := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	}
	f.apply("reviewer-a", f.prepare("reviewer-a"), notify)
	f.effects.run = nil
	f.clock.Advance(2 * time.Hour)
	f.apply("reviewer-b", f.prepare("reviewer-b"), review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "Waiting."})

	first := f.state().Proposals[jobID][0]
	require.Equal(t, review.ProposalUncertain, first.Kind)
	_, err := f.registry.Decide(jobID, first.ID, review.VerdictRetry, "", "connor")
	require.NoError(t, err)

	// The job changes before the retry is used.
	v2 := fixtureJob()
	v2.Version = 2
	v2.PackageDigest = "sha256:bbbb"
	require.NoError(t, f.registry.PutJob(v2))

	f.clock.Advance(2 * time.Hour)
	third := f.prepare("reviewer-c")
	// The registry guard refuses it on its own.
	_, err = f.registry.BeginAction(context.Background(), review.BeginRequest{
		Claim: third.Claim, ActionID: "act_direct", JobVersion: 2, Name: "notify", TargetID: targetID,
		IntentKey: review.IntentKey("notify", targetID, nil), ReviewID: third.Packet.ReviewID,
	})
	var denied *review.GuardDeniedError
	require.ErrorAs(t, err, &denied)
	assert.Equal(t, review.DenyIntentUnresolved, denied.Reason)

	applied := f.apply("reviewer-c", third, notify)
	assert.Empty(t, applied.Executed)
	assert.Equal(t, 1, f.effects.count("notify"))

	// A new question, bound to version 2, is waiting for the owner.
	proposals := f.state().Proposals[jobID]
	require.Len(t, proposals, 2)
	second := proposals[1]
	assert.NotEqual(t, first.ID, second.ID)
	assert.Equal(t, 2, second.JobVersion)
	assert.Equal(t, review.ProposalOpen, second.State)
	assert.Contains(t, second.Question, "version 2")

	// An answer to that question is what unlocks the intent.
	_, err = f.registry.Decide(jobID, second.ID, review.VerdictRetry, "", "connor")
	require.NoError(t, err)
	f.clock.Advance(2 * time.Hour)
	f.apply("reviewer-d", f.prepare("reviewer-d"), notify)
	assert.Equal(t, 2, f.effects.count("notify"))
}

// supersede files n approval proposals and then changes the job, which
// supersedes all of them.
func (f *fixture) supersede(n int) []review.Proposal {
	f.t.Helper()
	var actions []review.AgentAction
	for i := range n {
		actions = append(actions, act("expand_volume", map[string]string{"size_gb": fmt.Sprint(100 + i)}))
	}
	f.apply("reviewer-a", f.prepare("reviewer-a"), review.AgentDecision{Outcome: review.OutcomeAct, Reasoning: "Grow it.", Actions: actions})
	changed := fixtureJob()
	changed.Version = 2
	changed.PackageDigest = "sha256:bbbb"
	require.NoError(f.t, f.registry.PutJob(changed))
	proposals := f.state().Proposals[jobID]
	require.Len(f.t, proposals, n)
	for _, p := range proposals {
		require.Equal(f.t, review.ProposalSuperseded, p.State)
	}
	return proposals
}

// CC4 finding: a superseded proposal can never be answered, so its decision
// run is closed by the system instead of waiting forever. The closure is a
// recorded system event with its reason, no human decision is created, and
// more proposals than one batch are all reached over successive ticks.
func TestSupersededProposalsAreClosedInBoundedBatches(t *testing.T) {
	f := newFixture(t)
	proposals := f.supersede(45)
	machine := fixtureJob().MachineID
	ctx := context.Background()

	for tick, want := range []int{20, 20, 5, 0} {
		done, err := f.reviewer("sweeper").CloseSuperseded(ctx, machine)
		require.NoError(t, err)
		assert.Len(t, done, want, "tick %d", tick)
	}
	s := f.state()
	for _, p := range proposals {
		assert.Equal(t, 1, f.opener.closed[p.NativeTask.RunID], "each run is closed exactly once")
		require.Len(t, s.Closures[p.ID], 1)
		c := s.Closures[p.ID][0]
		assert.Equal(t, review.ClosureClosed, c.Outcome)
		assert.Equal(t, "sweeper", c.By)
		assert.Contains(t, c.Reason, "superseded")
	}
	assert.Empty(t, s.Decisions[jobID], "a system closure is not a decision by anyone")

	// The closed run resumes into the execute step, which runs nothing
	// because the registry says the proposal is superseded.
	out, err := f.reviewer("executor").Execute(ctx, jobID, proposals[0].ID, review.NoDecisionID)
	require.NoError(t, err)
	assert.Contains(t, out.Skipped, "superseded")
	assert.Equal(t, 0, f.effects.count("expand_volume"))
}

// It also covers a retired job, which is never due for review.
func TestSupersededProposalsOfARetiredJobAreClosed(t *testing.T) {
	f := newFixture(t)
	proposals := f.supersede(1)
	retired := fixtureJob()
	retired.Version = 3
	retired.Lifecycle = review.LifecycleRetired
	require.NoError(t, f.registry.PutJob(retired))

	// A tick with nothing due still closes it.
	var packet bytes.Buffer
	require.NoError(t, f.steps("tick-1", t.TempDir()).Prepare(context.Background(), "tick-1", &packet))
	assert.Empty(t, packet.String())
	assert.Equal(t, 1, f.opener.closed[proposals[0].NativeTask.RunID])
}

// A failing closure is retried without blocking the others, and after
// repeated failures it becomes an exception instead of a silent warning.
func TestFailingClosureIsRetriedThenRaised(t *testing.T) {
	f := newFixture(t)
	proposals := f.supersede(3)
	stuck := proposals[1]
	f.opener.close = func(p review.Proposal) (review.ClosureOutcome, error) {
		if p.ID == stuck.ID {
			return review.ClosureFailed, errors.New("hub unreachable")
		}
		return review.ClosureClosed, nil
	}
	machine := fixtureJob().MachineID
	ctx := context.Background()

	done, err := f.reviewer("sweeper").CloseSuperseded(ctx, machine)
	require.NoError(t, err)
	require.Len(t, done, 3)
	assert.Empty(t, f.state().Exceptions)

	for range 2 {
		f.clock.Advance(10 * time.Minute)
		done, err = f.reviewer("sweeper").CloseSuperseded(ctx, machine)
		require.NoError(t, err)
		require.Len(t, done, 1, "only the failing one is still pending")
		assert.Equal(t, stuck.ID, done[0].ProposalID)
	}
	s := f.state()
	require.Len(t, s.Exceptions, 1)
	assert.Equal(t, review.ExceptionCleanupFailed, s.Exceptions[0].Kind)
	assert.Contains(t, s.Exceptions[0].Message, stuck.ID)
	assert.Len(t, s.Closures[stuck.ID], 3)

	// Once it can be closed, it is, and it leaves the pending list.
	f.opener.close = nil
	f.clock.Advance(10 * time.Minute)
	done, err = f.reviewer("sweeper").CloseSuperseded(ctx, machine)
	require.NoError(t, err)
	require.Len(t, done, 1)
	assert.Equal(t, review.ClosureClosed, done[0].Outcome)
	done, err = f.reviewer("sweeper").CloseSuperseded(ctx, machine)
	require.NoError(t, err)
	assert.Empty(t, done)
}

// A real answer that raced the supersession, a run the service does not
// know, and a locator that is not the proposal's own run are each recorded
// as what they are. None is treated as a completed wait or as a decision,
// and a foreign task is never touched.
func TestClosureRecordsWhatItActuallyFound(t *testing.T) {
	f := newFixture(t)
	proposals := f.supersede(3)
	answered, missing, foreign := proposals[0], proposals[1], proposals[2]
	require.NoError(t, f.registry.Update(func(s *reviewtest.State) error {
		s.Proposals[jobID][2].NativeTask = review.TaskLocator{DAG: "production-release", RunID: "release-42", StepID: "approve"}
		return nil
	}))
	f.opener.close = func(p review.Proposal) (review.ClosureOutcome, error) {
		switch p.ID {
		case answered.ID:
			return review.ClosureAnswered, nil
		case missing.ID:
			return review.ClosureMissing, nil
		}
		return review.ClosureClosed, nil
	}
	_, err := f.reviewer("sweeper").CloseSuperseded(context.Background(), fixtureJob().MachineID)
	require.NoError(t, err)

	s := f.state()
	assert.Equal(t, review.ClosureAnswered, s.Closures[answered.ID][0].Outcome)
	assert.Equal(t, review.ClosureMissing, s.Closures[missing.ID][0].Outcome)
	assert.Equal(t, review.ClosureRefused, s.Closures[foreign.ID][0].Outcome)
	assert.Zero(t, f.opener.closed["release-42"], "a foreign task was completed with the reviewer's credential")

	// The raced answer authorizes nothing: the proposal is superseded.
	out, err := f.reviewer("executor").Execute(context.Background(), jobID, answered.ID, "dec_raced")
	require.NoError(t, err)
	assert.Contains(t, out.Skipped, "superseded")
	assert.Equal(t, 0, f.effects.count("expand_volume"))
}

// Security finding: the registry returns the stored proposal when its id
// already exists. If that stored record names another run, the reviewer does
// not enqueue it with its own credential.
func TestOpenRefusesAStoredLocatorThatIsNotTheProposalsOwnRun(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare("reviewer-a")
	tampering := f.reviewer("reviewer-a")
	tampering.Registry = foreignLocator{f.registry}
	_, err := tampering.Apply(context.Background(), prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Grow it.",
		Actions: []review.AgentAction{act("expand_volume", map[string]string{"size_gb": "200"})},
	})
	require.ErrorContains(t, err, "not its decision run")
	assert.Empty(t, f.opener.opened, "a run named by a stored record was enqueued")
	assert.Equal(t, 0, f.state().Checkpoints[jobID].Version)
}

// foreignLocator returns proposals as if the stored record pointed at
// another workflow's run.
type foreignLocator struct {
	*reviewtest.Registry
}

func (r foreignLocator) CreateProposal(ctx context.Context, claim review.Claim, draft review.Proposal) (review.Proposal, error) {
	stored, err := r.Registry.CreateProposal(ctx, claim, draft)
	stored.NativeTask = review.TaskLocator{DAG: "production-release", RunID: "release-42", StepID: "approve"}
	return stored, err
}
