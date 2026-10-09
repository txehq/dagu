// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	defaultClaimTTL    = 20 * time.Minute
	defaultCadence     = time.Hour
	defaultMaxAttempts = 3
	minReviewInterval  = time.Minute
	decideStepID       = "decide"
	// leaseMargin separates the end of an attempt from anyone else drawing
	// conclusions about it, to absorb clock and scheduling slack.
	leaseMargin     = 30 * time.Second
	waitingOnPerson = "person"
)

var (
	// actionVerdicts are the answers to a proposal that carries an action.
	actionVerdicts = []Verdict{VerdictApprove, VerdictReject, VerdictRedirect, VerdictSnooze}
	// questionVerdicts are the answers to a proposal with nothing to run.
	// Approve is absent on purpose: there is nothing it could authorize.
	questionVerdicts = []Verdict{VerdictRedirect, VerdictRetry, VerdictPause, VerdictSnooze, VerdictRetire, VerdictReject}
)

// Reviewer drives one job's review against the registry. It holds no state
// between calls: Prepare, Apply and Execute may run in different processes.
type Reviewer struct {
	Registry Registry
	Effector Effector
	Opener   DecisionOpener
	// Holder names this reviewer in claims and review records.
	Holder string
	// AgentClient is the agent CLI name and version actually used.
	AgentClient string
	// AgentInputTokens and AgentOutputTokens are the agent CLI's reported
	// usage for the decision being applied.
	AgentInputTokens  int
	AgentOutputTokens int
	// DecideDAG is the DAG whose runs carry proposals as native human tasks.
	DecideDAG string
	ClaimTTL  time.Duration
	Now       func() time.Time
}

func (r *Reviewer) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reviewer) claimTTL() time.Duration {
	if r.ClaimTTL > 0 {
		return r.ClaimTTL
	}
	return defaultClaimTTL
}

// SkipReason says why Prepare produced no packet.
type SkipReason string

const (
	SkipNotReviewable SkipReason = "lifecycle_not_reviewable"
	SkipClaimHeld     SkipReason = "claim_held"
)

// Prepared is the hand-off from Prepare to the agent and to Apply.
type Prepared struct {
	Skipped SkipReason `json:"skipped,omitempty"`
	Claim   Claim      `json:"claim,omitzero"`
	Packet  Packet     `json:"packet,omitzero"`
}

// Prepare claims the job, settles effects left open by earlier claims, and
// builds the context packet. A skipped result is not an error.
func (r *Reviewer) Prepare(ctx context.Context, jobID string) (Prepared, error) {
	job, err := r.Registry.Job(ctx, jobID)
	if err != nil {
		return Prepared{}, fmt.Errorf("read job: %w", err)
	}
	if !job.Lifecycle.Reviewable() {
		if err := r.settleTerminal(ctx, job); err != nil {
			return Prepared{}, fmt.Errorf("reconcile open actions: %w", err)
		}
		return Prepared{Skipped: SkipNotReviewable}, nil
	}
	claim, err := r.Registry.AcquireClaim(ctx, ClaimRequest{JobID: jobID, Kind: ClaimReview, Holder: r.Holder, TTL: r.claimTTL()})
	if errors.Is(err, ErrClaimHeld) {
		return Prepared{Skipped: SkipClaimHeld}, nil
	}
	if err != nil {
		return Prepared{}, fmt.Errorf("acquire claim: %w", err)
	}

	packet, err := r.prepareClaimed(ctx, claim, job)
	if err != nil {
		// The claim is released so the next tick can retry promptly; a
		// failed release only delays that retry until the claim expires.
		_ = r.Registry.ReleaseClaim(ctx, claim)
		return Prepared{}, err
	}
	return Prepared{Claim: claim, Packet: packet}, nil
}

// settleTerminal settles effects left open on a job that completed or
// retired while they were in flight, so its history does not end on an
// unknown. It can only probe and record: a terminal job gets no new effect,
// proposal or review.
func (r *Reviewer) settleTerminal(ctx context.Context, job Job) error {
	actions, err := r.Registry.Actions(ctx, job.ID)
	if err != nil {
		return err
	}
	open := false
	for _, a := range actions {
		open = open || a.State == ActionExecuting || (a.State == ActionUncertain && hasProbe(job, a))
	}
	if !open {
		return nil
	}
	claim, err := r.Registry.AcquireClaim(ctx, ClaimRequest{JobID: job.ID, Kind: ClaimReconcile, Holder: r.Holder, TTL: r.claimTTL()})
	if errors.Is(err, ErrClaimHeld) {
		// The holder may still be settling its own action.
		return nil
	}
	if err != nil {
		return err
	}
	err = r.reconcile(ctx, claim, job, false)
	if releaseErr := r.Registry.ReleaseClaim(ctx, claim); err == nil {
		err = releaseErr
	}
	return err
}

func hasProbe(job Job, action Action) bool {
	declared, ok := job.Review.Action(action.Name)
	return ok && len(declared.Reconcile) > 0
}

func (r *Reviewer) prepareClaimed(ctx context.Context, claim Claim, job Job) (Packet, error) {
	if err := r.reconcile(ctx, claim, job, true); err != nil {
		return Packet{}, fmt.Errorf("reconcile open actions: %w", err)
	}
	cp, err := r.Registry.Checkpoint(ctx, job.ID)
	if err != nil {
		return Packet{}, fmt.Errorf("read checkpoint: %w", err)
	}
	if cp, err = r.finishInterrupted(ctx, claim, cp); err != nil {
		return Packet{}, fmt.Errorf("finish interrupted episode: %w", err)
	}
	runs, err := r.Registry.RunsAfter(ctx, job.ID, cp.RunCursor)
	if err != nil {
		return Packet{}, fmt.Errorf("read runs: %w", err)
	}
	decisions, err := r.Registry.DecisionsAfter(ctx, job.ID, cp.DecisionCursor)
	if err != nil {
		return Packet{}, fmt.Errorf("read decisions: %w", err)
	}
	proposals, err := r.Registry.OpenProposals(ctx, job.ID)
	if err != nil {
		return Packet{}, fmt.Errorf("read proposals: %w", err)
	}
	actions, err := r.Registry.Actions(ctx, job.ID)
	if err != nil {
		return Packet{}, fmt.Errorf("read actions: %w", err)
	}
	return buildPacket(r.now(), job, cp, runs, decisions, proposals, actions), nil
}

// finishInterrupted completes an episode whose review was recorded but whose
// checkpoint never advanced. The stored review is the only decision that
// exists for that episode, so the checkpoint moves over exactly what it
// covered and anything newer is left for the next episode. Without this, a
// second decision made in the same episode would be dropped by the
// idempotent record while its evidence was skipped.
func (r *Reviewer) finishInterrupted(ctx context.Context, claim Claim, cp Checkpoint) (Checkpoint, error) {
	stored, err := r.Registry.Review(ctx, claim.JobID, ReviewID(claim.JobID, cp.Version))
	if errors.Is(err, ErrNotFound) {
		return cp, nil
	}
	if err != nil {
		return cp, err
	}
	next := Checkpoint{
		JobID:          claim.JobID,
		Version:        cp.Version + 1,
		RunCursor:      cp.RunCursor,
		DecisionCursor: cp.DecisionCursor,
		LastReviewID:   stored.ID,
		NextReviewAt:   r.now(),
	}
	if n := len(stored.CoveredRuns); n > 0 {
		next.RunCursor = stored.CoveredRuns[n-1]
	}
	if n := len(stored.CoveredDecisions); n > 0 {
		next.DecisionCursor = stored.CoveredDecisions[n-1]
	}
	if err := r.Registry.AdvanceCheckpoint(ctx, claim, next, cp.Version); err != nil {
		return cp, err
	}
	return next, nil
}

// reconcile settles every action whose effect is unresolved. Holding the
// job's claim proves no other holder is still executing one, so a started
// action here belongs to a holder that crashed or timed out. Such an action
// is never simply run again. With escalate false, an action that cannot be
// settled stays uncertain instead of becoming a proposal.
func (r *Reviewer) reconcile(ctx context.Context, claim Claim, job Job, escalate bool) error {
	actions, err := r.Registry.Actions(ctx, job.ID)
	if err != nil {
		return err
	}
	for _, action := range actions {
		if !action.State.Open() {
			continue
		}
		if err := r.reconcileOne(ctx, claim, job, action, escalate); err != nil {
			return fmt.Errorf("action %s: %w", action.ID, err)
		}
	}
	return nil
}

func (r *Reviewer) reconcileOne(ctx context.Context, claim Claim, job Job, action Action, escalate bool) error {
	finish := func(state ActionState, res EffectResult) error {
		return r.Registry.FinishAction(ctx, FinishRequest{
			Claim: claim, JobID: job.ID, ActionID: action.ID, GrantID: action.GrantID,
			State: state, Receipt: res.Receipt, Detail: res.Detail,
		})
	}
	if action.State == ActionExecuting {
		// Until its grant has run out, the attempt's holder may still be
		// about to perform the effect. A probe now could see nothing and
		// settle as absent an effect that then lands, so the attempt is
		// left alone and stays in the packet as unresolved.
		if r.now().Before(action.GrantExpiresAt.Add(leaseMargin)) {
			return nil
		}
		// The interrupted attempt is recorded as uncertain before anything
		// else, so the journal never shows a dead attempt as still running.
		if err := finish(ActionUncertain, EffectResult{Detail: "the attempt ended without a recorded outcome"}); err != nil {
			return err
		}
	}

	declared, ok := job.Review.Action(action.Name)
	res := EffectResult{Status: EffectUnknown, Detail: "the action is no longer declared by the job"}
	if ok && action.JobVersion != job.Version {
		// The attempt ran under another version's declaration. The current
		// one may name a different command, probe or idempotency class, so
		// it cannot say what the old attempt did.
		ok = false
		res.Detail = fmt.Sprintf("the attempt ran under job version %d and the job is now at version %d", action.JobVersion, job.Version)
	}
	if ok {
		switch {
		case len(declared.Reconcile) > 0:
			res = r.Effector.Probe(ctx, job, declared, action)
		case declared.Idempotency == IdempotencyReadOnly:
			res = EffectResult{Status: EffectNotApplied, Detail: "read-only action was interrupted"}
		default:
			// Nothing re-runs from an unknown outcome, not even a keyed
			// action: only a probe or a human can settle it.
			res = EffectResult{Status: EffectUnknown, Detail: "no reconcile probe is declared"}
		}
	}

	switch res.Status {
	case EffectApplied:
		res.Detail = "reconciled: the effect was applied"
		return finish(ActionSucceeded, res)
	case EffectNotApplied:
		return finish(ActionNotApplied, res)
	case EffectUnknown:
	}
	if !escalate {
		return nil
	}
	// Still unknown: ask a human once, then stop probing this action.
	if err := r.escalate(ctx, claim, job, action, res.Detail); err != nil {
		return err
	}
	return finish(ActionEscalated, res)
}

// escalate asks the owner how to settle an attempt whose effect is unknown.
// The question is bound to the job's current version and filing it again is
// a no-op.
func (r *Reviewer) escalate(ctx context.Context, claim Claim, job Job, action Action, detail string) error {
	id := UncertainProposalID(action.ID, job.Version)
	proposal, err := r.Registry.CreateProposal(ctx, claim, Proposal{
		ID:              id,
		JobID:           job.ID,
		JobVersion:      job.Version,
		PackageDigest:   job.PackageDigest,
		Kind:            ProposalUncertain,
		TargetID:        action.TargetID,
		ObservedAt:      r.now(),
		WaitingOn:       waitingOnPerson,
		AllowedVerdicts: questionVerdicts,
		Question:        fmt.Sprintf("Action %q on %s may or may not have taken effect (%s). Confirm its real state before it is tried again.", action.Name, action.TargetID, detail),
		RelatedAction:   action.ID,
		ReviewID:        action.ReviewID,
		NativeTask:      r.taskLocator(id),
	})
	if err != nil {
		return fmt.Errorf("escalate: %w", err)
	}
	if err := r.Opener.OpenDecision(ctx, proposal); err != nil {
		return fmt.Errorf("open decision: %w", err)
	}
	return nil
}

func (r *Reviewer) taskLocator(proposalID string) TaskLocator {
	return TaskLocator{DAG: r.DecideDAG, RunID: DecisionRunID(proposalID), StepID: decideStepID}
}

// Applied reports what one Apply did.
type Applied struct {
	// Replayed is true when this episode was already applied; nothing ran.
	Replayed bool `json:"replayed,omitempty"`
	// Aborted is set when the job changed under the review; nothing ran and
	// the checkpoint did not move.
	Aborted   string   `json:"aborted,omitempty"`
	Review    Review   `json:"review,omitzero"`
	Executed  []Action `json:"executed,omitempty"`
	Proposals []string `json:"proposal_ids,omitempty"`
}

// Apply turns the agent's decision into journaled effects and proposals,
// records the review, and only then advances the checkpoint over exactly the
// evidence the packet contained.
func (r *Reviewer) Apply(ctx context.Context, prepared Prepared, decision AgentDecision) (Applied, error) {
	claim, packet := prepared.Claim, prepared.Packet
	jobID := packet.Job.ID

	cp, err := r.Registry.Checkpoint(ctx, jobID)
	if err != nil {
		return Applied{}, fmt.Errorf("read checkpoint: %w", err)
	}
	if cp.Version != packet.Episode {
		// A repeated completion of an episode that already advanced.
		return Applied{Replayed: true}, nil
	}
	job, err := r.Registry.Job(ctx, jobID)
	if err != nil {
		return Applied{}, fmt.Errorf("read job: %w", err)
	}
	// The packet describes a job that no longer exists in that form, so the
	// decision made from it authorizes nothing.
	if !job.Lifecycle.Reviewable() {
		return r.abort(ctx, claim, "job lifecycle is "+string(job.Lifecycle))
	}
	if job.Version != packet.Job.Version {
		return r.abort(ctx, claim, fmt.Sprintf("job version changed from %d to %d", packet.Job.Version, job.Version))
	}
	if err := decision.validate(packet); err != nil {
		return Applied{}, &AgentFailure{Kind: ExceptionReviewerFailed, Message: "invalid decision: " + err.Error()}
	}

	review := Review{
		ID:                packet.ReviewID,
		JobID:             jobID,
		JobVersion:        job.Version,
		Episode:           packet.Episode,
		Outcome:           decision.Outcome,
		Reasoning:         decision.Reasoning,
		EvidenceRuns:      decision.EvidenceRunIDs,
		CoveredRuns:       packet.RunIDs(),
		CoveredDecisions:  packet.DecisionIDs(),
		PacketBytes:       packet.size(),
		AgentInputTokens:  r.AgentInputTokens,
		AgentOutputTokens: r.AgentOutputTokens,
		Reviewer:          r.Holder,
		AgentClient:       r.AgentClient,
		RecordedAt:        r.now(),
	}
	result := Applied{}
	history, err := r.Registry.Actions(ctx, jobID)
	if err != nil {
		return Applied{}, fmt.Errorf("read actions: %w", err)
	}
	decisions, err := r.Registry.DecisionsAfter(ctx, jobID, "")
	if err != nil {
		return Applied{}, fmt.Errorf("read decisions: %w", err)
	}

	for _, requested := range decision.Actions {
		if err := r.applyAction(ctx, claim, job, packet, requested, history, decisions, &review, &result); err != nil {
			return Applied{}, err
		}
	}
	if err := r.applyOutcome(ctx, claim, job, packet, decision, &review, &result); err != nil {
		return Applied{}, err
	}

	if err := r.Registry.RecordReview(ctx, claim, review); err != nil {
		return Applied{}, fmt.Errorf("record review: %w", err)
	}
	next := Checkpoint{
		JobID:          jobID,
		Version:        cp.Version + 1,
		RunCursor:      cp.RunCursor,
		DecisionCursor: cp.DecisionCursor,
		LastReviewID:   review.ID,
		NextReviewAt:   r.nextReviewAt(job, decision, packet),
	}
	if n := len(packet.NewRuns); n > 0 {
		next.RunCursor = packet.NewRuns[n-1].RunID
	}
	if n := len(packet.HumanFeedback); n > 0 {
		next.DecisionCursor = packet.HumanFeedback[n-1].ID
	}
	if err := r.Registry.AdvanceCheckpoint(ctx, claim, next, cp.Version); err != nil {
		return Applied{}, fmt.Errorf("advance checkpoint: %w", err)
	}
	if err := r.Registry.ReleaseClaim(ctx, claim); err != nil {
		return Applied{}, fmt.Errorf("release claim: %w", err)
	}
	result.Review = review
	return result, nil
}

func (r *Reviewer) abort(ctx context.Context, claim Claim, reason string) (Applied, error) {
	if err := r.Registry.ReleaseClaim(ctx, claim); err != nil && !errors.Is(err, ErrStaleFence) {
		return Applied{}, fmt.Errorf("release claim: %w", err)
	}
	return Applied{Aborted: reason}, nil
}

func (r *Reviewer) nextReviewAt(job Job, decision AgentDecision, packet Packet) time.Time {
	interval := defaultCadence
	if job.Review.CadenceSec > 0 {
		interval = time.Duration(job.Review.CadenceSec) * time.Second
	}
	// The agent may ask to look again sooner, never later than the cadence.
	if s := time.Duration(decision.NextReviewAfterSec) * time.Second; s > 0 && s < interval {
		interval = s
	}
	if packet.MoreRunsPending {
		interval = minReviewInterval
	}
	if interval < minReviewInterval {
		interval = minReviewInterval
	}
	return r.now().Add(interval)
}

// applyAction runs a requested action when the saved policy makes it
// routine, and otherwise turns it into a proposal.
func (r *Reviewer) applyAction(ctx context.Context, claim Claim, job Job, packet Packet, requested AgentAction, history []Action, decisions []Decision, review *Review, result *Applied) error {
	declared, isDeclared := job.Review.Action(requested.Name)
	propose := func(kind ProposalKind, question string) error {
		return r.propose(ctx, claim, job, packet, kind, requested, question, review, result)
	}

	switch {
	case !isDeclared:
		return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests %q on %s, which this job does not declare: %s", requested.Name, requested.TargetID, requested.Reason))
	case !job.HasTarget(requested.TargetID):
		return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests %q on %s, which is not a registered target of this job: %s", requested.Name, requested.TargetID, requested.Reason))
	case !paramsDeclared(declared, requested.Params):
		return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests %q with parameters the job does not declare: %s", requested.Name, requested.Reason))
	case !declared.Routine:
		return propose(ProposalAction, fmt.Sprintf("Approve %q on %s? %s", requested.Name, requested.TargetID, requested.Reason))
	}

	intent := IntentKey(requested.Name, requested.TargetID, requested.Params)
	if blocking, ok := unresolvedAttempt(history, decisions, intent, job.Version); ok {
		// The effect of an earlier attempt is still unknown. Running the
		// intent again could apply it twice, whatever the agent asks.
		review.Notes = append(review.Notes, fmt.Sprintf("action %q not run: earlier attempt %s is %s and unresolved", requested.Name, blocking.ID, blocking.State))
		if blocking.State == ActionEscalated {
			// The job may have changed since the owner was first asked, in
			// which case no answer exists for the job as it is now.
			detail := fmt.Sprintf("it ran under job version %d and has no answer for version %d", blocking.JobVersion, job.Version)
			if err := r.escalate(ctx, claim, job, blocking, detail); err != nil {
				return fmt.Errorf("escalate action %s: %w", blocking.ID, err)
			}
		}
		return nil
	}
	if !r.leaseCovers(claim, declared) {
		review.Notes = append(review.Notes, fmt.Sprintf("action %q not run: the claim ends before the action's timeout", requested.Name))
		return nil
	}
	if failures := trailingFailures(history, intent); failures >= maxAttempts(job) {
		return propose(ProposalQuestion, fmt.Sprintf("Routine action %q on %s failed %d times in a row and was not tried again: %s", requested.Name, requested.TargetID, failures, requested.Reason))
	}

	action, err := r.Registry.BeginAction(ctx, BeginRequest{
		Claim:      claim,
		ActionID:   RoutineActionID(packet.ReviewID, requested.Name, requested.TargetID, requested.Params),
		IntentKey:  intent,
		JobVersion: job.Version,
		Name:       requested.Name,
		TargetID:   requested.TargetID,
		Params:     requested.Params,
		ReviewID:   packet.ReviewID,
		Timeout:    declared.Timeout(),
	})
	var denied *GuardDeniedError
	switch {
	case errors.Is(err, ErrActionExists):
		// Already journaled in this episode: the stored record stands and
		// nothing runs. An unresolved one is settled by the next Prepare.
		review.ActionIDs = append(review.ActionIDs, action.ID)
		review.Notes = append(review.Notes, fmt.Sprintf("action %s was already journaled as %s; not repeated", action.ID, action.State))
		return nil
	case errors.As(err, &denied):
		review.Notes = append(review.Notes, fmt.Sprintf("action %q denied by the guard: %s", requested.Name, denied.Reason))
		return nil
	case err != nil:
		return fmt.Errorf("begin action %q: %w", requested.Name, err)
	}

	finished, err := r.runJournaled(ctx, claim, job, declared, action)
	if err != nil {
		return err
	}
	review.ActionIDs = append(review.ActionIDs, finished.ID)
	result.Executed = append(result.Executed, finished)
	return nil
}

// runJournaled performs a started action and records its outcome. If the
// process dies between the two, the action stays started and the next
// Prepare reconciles it.
func (r *Reviewer) runJournaled(ctx context.Context, claim Claim, job Job, declared DeclaredAction, action Action) (Action, error) {
	var res EffectResult
	if r.now().Before(action.GrantExpiresAt) {
		// The effect is killed when the grant ends, so a later holder that
		// waits for that moment never probes an attempt still in progress.
		runCtx, cancel := context.WithDeadline(ctx, action.GrantExpiresAt)
		res = r.Effector.Run(runCtx, job, declared, action)
		cancel()
	} else {
		res = EffectResult{Status: EffectNotApplied, Detail: "the grant ended before the effect could start"}
	}
	state := ActionSucceeded
	switch res.Status {
	case EffectApplied:
	case EffectNotApplied:
		state = ActionFailed
	case EffectUnknown:
		state = ActionUncertain
	}
	err := r.Registry.FinishAction(ctx, FinishRequest{
		Claim: claim, JobID: job.ID, ActionID: action.ID, GrantID: action.GrantID,
		State: state, Receipt: res.Receipt, Detail: res.Detail,
	})
	if err != nil {
		return Action{}, fmt.Errorf("record outcome of action %s: %w", action.ID, err)
	}
	action.State, action.Receipt, action.Detail = state, res.Receipt, res.Detail
	return action, nil
}

func (r *Reviewer) propose(ctx context.Context, claim Claim, job Job, packet Packet, kind ProposalKind, requested AgentAction, question string, review *Review, result *Applied) error {
	id := ProposalID(packet.ReviewID, kind, requested.Name, requested.TargetID, requested.Params, question)
	draft := Proposal{
		ID:              id,
		JobID:           job.ID,
		JobVersion:      job.Version,
		PackageDigest:   job.PackageDigest,
		Kind:            kind,
		Question:        question,
		Rationale:       requested.Reason,
		EvidenceRuns:    review.EvidenceRuns,
		ArtifactRefs:    packet.artifactRefs(review.EvidenceRuns),
		ObservedAt:      packet.GeneratedAt,
		WaitingOn:       waitingOnPerson,
		AllowedVerdicts: questionVerdicts,
		ReviewID:        packet.ReviewID,
		NativeTask:      r.taskLocator(id),
	}
	if kind == ProposalAction {
		draft.ActionName, draft.TargetID, draft.Params = requested.Name, requested.TargetID, requested.Params
		draft.AllowedVerdicts = actionVerdicts
	}
	proposal, err := r.Registry.CreateProposal(ctx, claim, draft)
	if err != nil {
		return fmt.Errorf("create proposal: %w", err)
	}
	if err := r.Opener.OpenDecision(ctx, proposal); err != nil {
		return fmt.Errorf("open decision for proposal %s: %w", proposal.ID, err)
	}
	review.ProposalIDs = append(review.ProposalIDs, proposal.ID)
	result.Proposals = append(result.Proposals, proposal.ID)
	return nil
}

// applyOutcome handles what the outcome itself asks for. A reviewer never
// changes a job's lifecycle: completing or retiring is proposed to a human.
func (r *Reviewer) applyOutcome(ctx context.Context, claim Claim, job Job, packet Packet, decision AgentDecision, review *Review, result *Applied) error {
	ask := func(question string) error {
		return r.propose(ctx, claim, job, packet, ProposalQuestion, AgentAction{Reason: decision.Reasoning}, question, review, result)
	}
	switch decision.Outcome {
	case OutcomeWaitHuman:
		return ask(decision.Question)
	case OutcomeComplete:
		return ask("The reviewer finds this job's purpose fulfilled and recommends completing it.")
	case OutcomeRetire:
		return ask("The reviewer recommends retiring this job.")
	case OutcomePauseUnavailable:
		err := r.Registry.RaiseException(ctx, Exception{
			JobID: job.ID, Kind: ExceptionUnavailable, MachineID: job.MachineID,
			Message: decision.Reasoning, ReviewID: packet.ReviewID,
		})
		if err != nil {
			return fmt.Errorf("raise exception: %w", err)
		}
	case OutcomeContinue, OutcomeAct:
	}
	return nil
}

// leaseCovers reports whether the claim outlives one full attempt of the
// action with room to record its outcome.
func (r *Reviewer) leaseCovers(claim Claim, declared DeclaredAction) bool {
	return claim.ExpiresAt.Sub(r.now()) >= declared.Timeout()+leaseMargin
}

// unresolvedAttempt returns the latest attempt of an intent when its effect
// is still unknown: executing, uncertain, or escalated to a human who has
// not answered "retry" for the job at its current version. Only that answer
// says the intent may run again; an answer given before the job changed was
// about a different command and unlocks nothing.
func unresolvedAttempt(history []Action, decisions []Decision, intent string, jobVersion int) (Action, bool) {
	for i := len(history) - 1; i >= 0; i-- {
		a := history[i]
		if a.IntentKey != intent {
			continue
		}
		switch a.State {
		case ActionExecuting, ActionUncertain:
			return a, true
		case ActionEscalated:
			return a, !retryDecided(decisions, UncertainProposalID(a.ID, jobVersion))
		case ActionSucceeded, ActionFailed, ActionNotApplied:
			return Action{}, false
		}
	}
	return Action{}, false
}

func retryDecided(decisions []Decision, proposalID string) bool {
	verdict := Verdict("")
	for _, d := range decisions {
		if d.ProposalID == proposalID {
			verdict = d.Verdict
		}
	}
	return verdict == VerdictRetry
}

func paramsDeclared(declared DeclaredAction, params map[string]string) bool {
	for name := range params {
		found := false
		for _, allowed := range declared.Params {
			if allowed == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func maxAttempts(job Job) int {
	if job.Review.MaxAttempts > 0 {
		return job.Review.MaxAttempts
	}
	return defaultMaxAttempts
}

// trailingFailures counts how many of the most recent attempts of an intent
// failed without a success in between.
func trailingFailures(history []Action, intent string) int {
	n := 0
	for i := len(history) - 1; i >= 0; i-- {
		a := history[i]
		if a.IntentKey != intent {
			continue
		}
		if a.State != ActionFailed && a.State != ActionNotApplied {
			break
		}
		n++
	}
	return n
}

// Fail records that the agent produced no usable decision. The checkpoint
// does not move, the claim is released, and the next attempt is deferred so
// a missing login is one visible exception instead of a retry loop.
func (r *Reviewer) Fail(ctx context.Context, prepared Prepared, failure *AgentFailure) error {
	job := prepared.Packet.Job
	if err := r.Registry.RaiseException(ctx, Exception{
		JobID: job.ID, Kind: failure.Kind, MachineID: job.MachineID,
		Message: failure.Message, ReviewID: prepared.Packet.ReviewID,
	}); err != nil {
		return fmt.Errorf("raise exception: %w", err)
	}
	interval := defaultCadence
	if job.Review.CadenceSec > 0 {
		interval = time.Duration(job.Review.CadenceSec) * time.Second
	}
	if err := r.Registry.DeferReview(ctx, prepared.Claim, r.now().Add(interval)); err != nil {
		return fmt.Errorf("defer review: %w", err)
	}
	if err := r.Registry.ReleaseClaim(ctx, prepared.Claim); err != nil {
		return fmt.Errorf("release claim: %w", err)
	}
	return nil
}

// Executed reports what Execute did with one decision.
type Executed struct {
	// Skipped says why no effect was attempted; empty when one was.
	Skipped string `json:"skipped,omitempty"`
	Action  Action `json:"action,omitzero"`
}

// Execute performs the single effect an approve decision authorizes. It runs
// in the proposal's own run after the human task completes, under a fresh
// execution claim. The registry's decision record is the authority: the
// task's input is only a pointer to it.
func (r *Reviewer) Execute(ctx context.Context, jobID, proposalID, decisionID string) (Executed, error) {
	decision, err := r.Registry.Decision(ctx, jobID, decisionID)
	if errors.Is(err, ErrNotFound) {
		return Executed{Skipped: "no recorded decision " + decisionID}, nil
	}
	if err != nil {
		return Executed{}, fmt.Errorf("read decision: %w", err)
	}
	if decision.ProposalID != proposalID {
		return Executed{Skipped: "decision belongs to another proposal"}, nil
	}
	if decision.Verdict != VerdictApprove {
		return Executed{Skipped: "verdict is " + string(decision.Verdict)}, nil
	}
	proposal, err := r.Registry.Proposal(ctx, jobID, proposalID)
	if err != nil {
		return Executed{}, fmt.Errorf("read proposal: %w", err)
	}
	if proposal.Kind != ProposalAction {
		return Executed{Skipped: "proposal carries no executable action"}, nil
	}
	job, err := r.Registry.Job(ctx, jobID)
	if err != nil {
		return Executed{}, fmt.Errorf("read job: %w", err)
	}
	declared, ok := job.Review.Action(proposal.ActionName)
	if !ok {
		return Executed{Skipped: "action is no longer declared by the job"}, nil
	}

	if !job.Lifecycle.Reviewable() {
		return Executed{Skipped: "job lifecycle is " + string(job.Lifecycle)}, nil
	}

	claim, err := r.Registry.AcquireClaim(ctx, ClaimRequest{JobID: jobID, Kind: ClaimExecution, Holder: r.Holder, TTL: r.claimTTL()})
	var refused *GuardDeniedError
	if errors.As(err, &refused) {
		// The job left a live lifecycle between the read and the claim.
		return Executed{Skipped: "denied by the guard: " + string(refused.Reason)}, nil
	}
	if err != nil {
		// A held claim is retried by the step's retry policy.
		return Executed{}, fmt.Errorf("acquire execution claim: %w", err)
	}
	executed, err := r.executeClaimed(ctx, claim, job, declared, proposal, decision)
	if releaseErr := r.Registry.ReleaseClaim(ctx, claim); err == nil && releaseErr != nil {
		err = fmt.Errorf("release claim: %w", releaseErr)
	}
	return executed, err
}

func (r *Reviewer) executeClaimed(ctx context.Context, claim Claim, job Job, declared DeclaredAction, proposal Proposal, decision Decision) (Executed, error) {
	if !r.leaseCovers(claim, declared) {
		return Executed{}, fmt.Errorf("execution claim ends before the timeout of action %q", declared.Name)
	}
	action, err := r.Registry.BeginAction(ctx, BeginRequest{
		Claim:      claim,
		Timeout:    declared.Timeout(),
		ActionID:   ApprovedActionID(proposal.ID, decision.ID),
		IntentKey:  IntentKey(proposal.ActionName, proposal.TargetID, proposal.Params),
		JobVersion: job.Version,
		Name:       proposal.ActionName,
		TargetID:   proposal.TargetID,
		Params:     proposal.Params,
		ProposalID: proposal.ID,
		DecisionID: decision.ID,
	})
	var denied *GuardDeniedError
	switch {
	case errors.Is(err, ErrActionExists):
		return Executed{Skipped: "already journaled as " + string(action.State), Action: action}, nil
	case errors.As(err, &denied):
		return Executed{Skipped: "denied by the guard: " + string(denied.Reason)}, nil
	case err != nil:
		return Executed{}, fmt.Errorf("begin action: %w", err)
	}
	finished, err := r.runJournaled(ctx, claim, job, declared, action)
	if err != nil {
		return Executed{}, err
	}
	return Executed{Action: finished}, nil
}
