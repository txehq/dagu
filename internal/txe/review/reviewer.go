// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
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
	// Retry is absent too: it is valid on two kinds of proposal only.
	questionVerdicts = []Verdict{VerdictRedirect, VerdictPause, VerdictSnooze, VerdictRetire, VerdictReject}
	// retryRunVerdicts are the answers to a proposal to re-run one run.
	retryRunVerdicts = []Verdict{VerdictRetry, VerdictReject, VerdictRedirect, VerdictSnooze}
	// uncertainVerdicts are the answers to an effect whose outcome is
	// unknown. Retry here means the owner confirms it did not take effect
	// and allows one more attempt of that same action.
	// Redirect is absent: the registry never executes an escalation, so it
	// refuses approve and redirect on one.
	uncertainVerdicts = []Verdict{VerdictRetry, VerdictReject, VerdictPause, VerdictSnooze, VerdictRetire}
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
	// Handoff is recorded on the review as the local location of the
	// prepared review this decision was made from.
	Handoff LocalFile
	// PacketArtifact and DecisionArtifact are recorded on the review when
	// the step saved them as run artifacts.
	PacketArtifact   string
	DecisionArtifact string
	// AgentInputTokens and AgentOutputTokens are the agent CLI's reported
	// usage for the decision being applied.
	AgentInputTokens  int
	AgentOutputTokens int
	// MachineID is the machine this reviewer runs on. A job registered on
	// another machine is never claimed, reviewed or acted on here: its
	// declared commands, its package and its credentials are that
	// machine's. Empty disables the check, which only a test harness with
	// no machines should rely on.
	MachineID string
	// Runs reads and retries the job's runs for the reserved retry action;
	// nil disables it.
	Runs RunRetrier
	// RetryObserve is how long a dispatched retry is watched for its new
	// attempt; retryObserveFor when zero.
	RetryObserve time.Duration
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
	// SkipOtherMachine means the job is registered on another machine.
	SkipOtherMachine SkipReason = "other_machine"
	SkipClaimHeld    SkipReason = "claim_held"
	// SkipUnreviewable means the job was raised as an exception instead.
	SkipUnreviewable SkipReason = "unreviewable"
)

// onThisMachine reports whether the job is registered on the machine this
// reviewer runs on.
func (r *Reviewer) onThisMachine(job Job) bool {
	return r.MachineID == "" || job.MachineID == r.MachineID
}

// Prepared is the hand-off from Prepare to the agent and to Apply.
type Prepared struct {
	Skipped SkipReason `json:"skipped,omitempty"`
	Claim   Claim      `json:"claim,omitzero"`
	Packet  Packet     `json:"packet,omitzero"`
	// RunCursor is where the checkpoint moves to once the packet's runs
	// are covered: exactly those runs and nothing after them. It is the
	// reviewer's own bookkeeping and is not part of what the agent is shown.
	RunCursor string `json:"run_cursor,omitempty"`
}

// Prepare claims the job, settles effects left open by earlier claims, and
// builds the context packet. A skipped result is not an error.
func (r *Reviewer) Prepare(ctx context.Context, jobID string) (Prepared, error) {
	job, err := r.Registry.Job(ctx, jobID)
	if err != nil {
		return Prepared{}, fmt.Errorf("read job: %w", err)
	}
	if !r.onThisMachine(job) {
		return Prepared{Skipped: SkipOtherMachine}, nil
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
	if errors.Is(err, ErrPacketTooLarge) {
		// A job that cannot be reviewed must not simply go quiet. It is
		// raised as an exception and deferred, and it stays unreviewed and
		// visible until its context is fixed.
		return r.unreviewable(ctx, claim, job, err)
	}
	if err != nil {
		// The claim is released so the next tick can retry promptly; a
		// failed release only delays that retry until the claim expires.
		_ = r.Registry.ReleaseClaim(ctx, claim)
		return Prepared{}, err
	}
	return Prepared{Claim: claim, Packet: packet, RunCursor: packet.runCursor()}, nil
}

const (
	// closureBatch bounds the superseded proposals one tick closes.
	closureBatch = 20
	// closureAttemptsBeforeException is how many failed attempts on one
	// proposal turn into an exception someone has to look at.
	closureAttemptsBeforeException = 3
	closureReason                  = "the proposal was superseded and can no longer be answered"
)

// CloseSuperseded closes the decision runs of superseded proposals on a
// machine. A run waiting at a human task has no process and the service
// cannot abort it, so without this it would wait for an answer the registry
// will never accept.
//
// It works through a bounded batch of the registry's pending list, least
// recently attempted first, so repeated ticks reach every proposal and a
// failing one is retried without blocking the others. Each result is
// recorded as a system closure. No human decision is ever created.
func (r *Reviewer) CloseSuperseded(ctx context.Context, machineID string) ([]Closure, error) {
	pending, err := r.Registry.PendingClosures(ctx, machineID, closureBatch)
	if err != nil {
		return nil, fmt.Errorf("list superseded proposals: %w", err)
	}
	var done []Closure
	for _, proposal := range pending {
		closure := r.closeOne(ctx, proposal)
		failed, err := r.Registry.RecordClosure(ctx, closure)
		if err != nil {
			return done, fmt.Errorf("record closure of proposal %s: %w", proposal.ID, err)
		}
		done = append(done, closure)
		if closure.Outcome != ClosureFailed || failed < closureAttemptsBeforeException {
			continue
		}
		err = r.Registry.RaiseException(ctx, Exception{
			JobID: proposal.JobID, Kind: ExceptionCleanupFailed, MachineID: machineID,
			Message: fmt.Sprintf("the decision run of superseded proposal %s could not be closed after %d attempts: %s", proposal.ID, failed, closure.Detail),
		})
		if err != nil {
			return done, fmt.Errorf("raise exception: %w", err)
		}
	}
	return done, nil
}

func (r *Reviewer) closeOne(ctx context.Context, proposal Proposal) Closure {
	closure := Closure{JobID: proposal.JobID, ProposalID: proposal.ID, Reason: closureReason, By: r.Holder}
	// The reviewer completes a human task here with its own credential, so
	// it touches only the task it would itself have opened for this
	// proposal of this job. A stored locator pointing anywhere else, such
	// as another workflow's approval, is refused.
	if proposal.NativeTask != r.taskLocator(proposal.ID) {
		closure.Outcome, closure.Detail = ClosureRefused, "the stored task locator is not this proposal's decision run"
		return closure
	}
	outcome, err := r.Opener.CloseDecision(ctx, proposal)
	if err != nil {
		closure.Outcome, closure.Detail = ClosureFailed, err.Error()
		return closure
	}
	closure.Outcome = outcome
	return closure
}

// RequestedRetry is a retry of one run that a person asked for and decided
// in one step, without a decision run.
type RequestedRetry struct {
	JobID      string `json:"job_id"`
	ProposalID string `json:"proposal_id"`
	DecisionID string `json:"decision_id"`
}

// RetryOutcome is what executing one requested retry came to.
type RetryOutcome struct {
	RequestedRetry
	Executed Executed `json:"executed,omitzero"`
	Error    string   `json:"error,omitempty"`
}

// RunRequestedRetries executes the retries a person requested directly. A
// proposal the reviewer files is executed by its own decision run; a retry
// requested from the dashboard or CLI is already decided and has no such
// run, so each tick carries out a bounded batch of them through the same
// executor: a fresh execution claim, the registry's grant, one attempt.
// One that cannot run now, such as a job whose claim is held, is reported
// and left for the next tick; the registry's journal keeps a second attempt
// from ever being granted.
func (r *Reviewer) RunRequestedRetries(ctx context.Context, machineID string) ([]RetryOutcome, error) {
	if r.Runs == nil {
		return nil, nil
	}
	// The listing can return requests together with an error: the ones it
	// could check, and a report of the ones it could not. Those found are
	// executed either way.
	pending, listErr := r.Registry.RequestedRetries(ctx, machineID, closureBatch)
	if listErr != nil {
		listErr = fmt.Errorf("list requested retries: %w", listErr)
	}
	out := make([]RetryOutcome, 0, len(pending))
	for _, req := range pending {
		res := RetryOutcome{RequestedRetry: req}
		executed, err := r.Execute(ctx, req.JobID, req.ProposalID, req.DecisionID)
		if err != nil {
			res.Error = err.Error()
		}
		res.Executed = executed
		out = append(out, res)
	}
	return out, listErr
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
	return buildPacket(r.now(), job, cp, runs, decisions, proposals, actions)
}

// unreviewable records that a job cannot be reviewed as it is registered.
func (r *Reviewer) unreviewable(ctx context.Context, claim Claim, job Job, cause error) (Prepared, error) {
	err := r.Registry.RaiseException(ctx, Exception{
		JobID: job.ID, Kind: ExceptionContextTooLarge, MachineID: job.MachineID,
		Message: "the job is not being reviewed: " + cause.Error(),
	})
	if err != nil {
		_ = r.Registry.ReleaseClaim(ctx, claim)
		return Prepared{}, fmt.Errorf("raise exception: %w", err)
	}
	interval := defaultCadence
	if job.Review.CadenceSec > 0 {
		interval = time.Duration(job.Review.CadenceSec) * time.Second
	}
	if err := r.Registry.DeferReview(ctx, claim, r.now().Add(interval)); err != nil {
		_ = r.Registry.ReleaseClaim(ctx, claim)
		return Prepared{}, fmt.Errorf("defer review: %w", err)
	}
	if err := r.Registry.ReleaseClaim(ctx, claim); err != nil {
		return Prepared{}, fmt.Errorf("release claim: %w", err)
	}
	return Prepared{Skipped: SkipUnreviewable}, nil
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
	switch n := len(stored.CoveredRuns); {
	case stored.RunCursor != "":
		next.RunCursor = stored.RunCursor
	case n > 0:
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
	if action.Name == RetryRunAction {
		// The reserved retry is not a declared command: the run itself is
		// its only evidence, whatever version the job is at now.
		ok = false
		res = r.probeRetry(ctx, job, action)
	}
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
		if res.Detail == "" || action.Name != RetryRunAction {
			res.Detail = "the effect was applied"
		}
		res.Detail = "reconciled: " + res.Detail
		return finish(ActionSucceeded, res)
	case EffectNotApplied:
		// Only an action with no external effect can be closed as not
		// applied. For any other, a probe that finds nothing proves only
		// that the effect is absent now: a request the interrupted attempt
		// already sent can still commit afterwards. Presence settles an
		// attempt; absence leaves it to the owner.
		if ok && declared.Idempotency == IdempotencyReadOnly {
			return finish(ActionNotApplied, res)
		}
		res = EffectResult{Status: EffectUnknown, Detail: "a probe found no effect yet, which does not prove the interrupted attempt will not still apply"}
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
		AllowedVerdicts: uncertainVerdicts,
		ActionName:      UncertainEffectAction,
		Params:          map[string]string{UncertainEffectParam: action.ID},
		Question:        fmt.Sprintf("Action %q on %s may or may not have taken effect (%s). Confirm its real state before it is tried again.", action.Name, action.TargetID, detail),
		RelatedAction:   action.ID,
		ReviewID:        action.ReviewID,
		NativeTask:      r.taskLocator(id),
	})
	if err != nil {
		return fmt.Errorf("escalate: %w", err)
	}
	if err := r.openDecision(ctx, proposal); err != nil {
		return fmt.Errorf("open decision: %w", err)
	}
	return nil
}

// openDecision enqueues the proposal's decision run. The registry returns
// the stored proposal when one with this id already exists, so its locator
// is checked first: the reviewer enqueues, with its own credential, only the
// run it derives for this proposal, never a run a stored record names.
func (r *Reviewer) openDecision(ctx context.Context, proposal Proposal) error {
	if proposal.NativeTask != r.taskLocator(proposal.ID) {
		return fmt.Errorf("proposal %s is stored with a task locator that is not its decision run", proposal.ID)
	}
	return r.Opener.OpenDecision(ctx, proposal)
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
		CoveredExecutions: packet.coveredExecutions(),
		TrimmedExecutions: packet.trimmedExecutions(),
		RunCursor:         prepared.RunCursor,
		CoveredDecisions:  packet.DecisionIDs(),
		Handoff:           r.Handoff,
		PacketArtifact:    r.PacketArtifact,
		DecisionArtifact:  r.DecisionArtifact,
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
	if review.RunCursor != "" {
		next.RunCursor = review.RunCursor
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

	if requested.Name == RetryRunAction {
		// A retry is proposed only for a run the reviewer was shown, and it
		// names that run exactly. It runs when the owner says so.
		runID := requested.Params[RetryRunParam]
		run, shown := packet.run(runID)
		if len(requested.Params) != 1 || !shown {
			return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests retrying a run it was not shown (%q): %s", runID, requested.Reason))
		}
		if !run.Execution().known() {
			// Without the service's identity of the failed execution there
			// is nothing to bind one retry to.
			return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests retrying run %s, whose attempt the service does not identify, so it cannot be retried from here: %s", runID, requested.Reason))
		}
		if run.SpecSHA256 == "" || run.SpecSHA256 != job.DAGSpecSHA256 {
			// A run of an older version is never retried, on the new code
			// or the old. The owner still sees what the reviewer wanted.
			return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests retrying run %s, which did not run the job's current version %d and cannot be retried: %s", runID, job.Version, requested.Reason))
		}
		// The proposal is bound to the failed execution the reviewer was
		// shown, the snapshot it ran and the package of that version; the
		// agent chooses none of them.
		requested.Params = map[string]string{
			RetryRunParam: runID, RetryRunAttemptParam: run.AttemptID, RetryRunQueuedParam: run.QueuedAt,
			RetryRunSpecParam: run.SpecSHA256, RetryRunPackageParam: job.PackageDigest,
		}
		requested.TargetID = ""
		return propose(ProposalAction, fmt.Sprintf("Retry run %s of this job? %s", runID, requested.Reason))
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
		if action.Name == RetryRunAction {
			res = r.retryRun(runCtx, job, action)
		} else {
			res = r.Effector.Run(runCtx, job, declared, action)
		}
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
	// The agent sees a bounded list of open proposals, so it may ask again
	// for something the owner is already being asked. The registry's full
	// list decides: the same action on the same target with the same
	// parameters is not put in front of the owner twice.
	if kind == ProposalAction {
		open, err := r.Registry.OpenProposals(ctx, job.ID)
		if err != nil {
			return fmt.Errorf("read open proposals: %w", err)
		}
		for _, existing := range open {
			if existing.Kind == ProposalAction && existing.ActionName == requested.Name && existing.TargetID == requested.TargetID &&
				maps.Equal(normalizeParams(existing.Params), normalizeParams(requested.Params)) {
				// Its decision run is opened again all the same. Opening is a
				// no-op when the run exists, and it repairs a proposal whose
				// earlier review died between filing it and opening its run,
				// which would otherwise never become answerable.
				if err := r.openDecision(ctx, existing); err != nil {
					return fmt.Errorf("open decision for proposal %s: %w", existing.ID, err)
				}
				review.Notes = append(review.Notes, fmt.Sprintf("action %q is already proposed as %s; not proposed again", requested.Name, existing.ID))
				review.ProposalIDs = append(review.ProposalIDs, existing.ID)
				return nil
			}
		}
	}
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
		if requested.Name == RetryRunAction {
			draft.AllowedVerdicts = retryRunVerdicts
		}
	}
	proposal, err := r.Registry.CreateProposal(ctx, claim, draft)
	if err != nil {
		return fmt.Errorf("create proposal: %w", err)
	}
	if err := r.openDecision(ctx, proposal); err != nil {
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
		return ask("The reviewer finds this job's purpose fulfilled and recommends completing it." + packet.trimmedCaveat())
	case OutcomeRetire:
		return ask("The reviewer recommends retiring this job." + packet.trimmedCaveat())
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

// retryRunDeclaration bounds the built-in retry like any other effect. A
// retry starts a run, so an unknown outcome is uncertain, not harmless.
var retryRunDeclaration = DeclaredAction{Name: RetryRunAction, Idempotency: IdempotencyNone, TimeoutSec: 60}

// RunState is what the service reports about one run of a job.
type RunState struct {
	// AttemptID and QueuedAt identify the run's latest execution. A native
	// retry keeps the run id and either starts a new attempt or queues the
	// latest one again; one of the two always changes.
	AttemptID string `json:"attempt_id"`
	QueuedAt  string `json:"queued_at,omitempty"`
	// Status is the service's status label of that attempt.
	Status string `json:"status"`
	// Active means the attempt is queued, running or waiting. Succeeded
	// means it finished successfully. A run that is neither has a finished,
	// unsuccessful latest attempt, which is the only thing a retry is for.
	Active    bool `json:"active,omitempty"`
	Succeeded bool `json:"succeeded,omitempty"`
}

// Execution is the run's latest execution.
func (s RunState) Execution() Execution {
	return Execution{AttemptID: s.AttemptID, QueuedAt: s.QueuedAt}
}

// retryable reports whether the run's latest execution is the given one
// and has finished unsuccessfully.
func (s RunState) retryable(e Execution) bool {
	return e.known() && s.Execution() == e && !s.Active && !s.Succeeded
}

// retriedExecution is the execution a retry decision is about. It is
// complete only when the decision names both parts: an attempt, and that
// attempt's queued time, which may be empty for an attempt that was never
// queued but may not be left out. A decision that names less is never
// completed from whatever the run's latest execution happens to be.
func retriedExecution(params map[string]string) (e Execution, complete bool) {
	queuedAt, named := params[RetryRunQueuedParam]
	e = Execution{AttemptID: params[RetryRunAttemptParam], QueuedAt: queuedAt}
	return e, e.known() && named
}

// ErrRunNotRetryable is returned by RunRetrier.RetryRun when the service
// definitely refused the retry and started nothing.
var ErrRunNotRetryable = errors.New("txe review: the service refused to retry the run")

// RunRetrier reads and retries a job's runs through the service.
type RunRetrier interface {
	// RunState returns the state of the run's latest attempt.
	RunState(ctx context.Context, jobID, runID string) (RunState, error)
	// RetryRun asks the service to retry the run. It returns
	// ErrRunNotRetryable when the service refused; after any other error
	// whether a retry started is unknown.
	RetryRun(ctx context.Context, jobID, runID string) error
}

const (
	// retryObserveFor is how long a dispatched retry is watched for its new
	// attempt, and retryObserveEvery how often the run is read meanwhile.
	retryObserveFor   = 20 * time.Second
	retryObserveEvery = time.Second
	// runReadTries bounds the reads of a run's state before a dispatch.
	runReadTries = 3
)

// retryRun performs the reserved retry action: one native retry of one run,
// for the one failed attempt the decision was made about.
//
// Nothing is dispatched unless that attempt is still the run's latest and
// is finished and unsuccessful: a run that moved on since the decision is
// not retried again on its strength. After a dispatch the result is applied
// only when a new attempt is observed on the run, and its id is the
// receipt. A dispatch whose outcome was not observed is unknown; it is
// never reported from the service's acceptance alone, and never repeated.
func (r *Reviewer) retryRun(ctx context.Context, job Job, action Action) EffectResult {
	runID := action.Params[RetryRunParam]
	bound, complete := retriedExecution(action.Params)
	if !complete {
		return EffectResult{Status: EffectNotApplied, Detail: "not dispatched: the decision does not name the attempt and queued time of the execution of run " + runID + " it is about"}
	}
	var before RunState
	var err error
	for range runReadTries {
		if before, err = r.Runs.RunState(ctx, job.ID, runID); err == nil {
			break
		}
	}
	if err != nil {
		return EffectResult{Status: EffectNotApplied, Detail: "not dispatched: run " + runID + " could not be read: " + err.Error()}
	}
	if !before.retryable(bound) {
		return EffectResult{Status: EffectNotApplied, Detail: fmt.Sprintf(
			"not dispatched: the decision is about execution %s of run %s, and the run is now at %s (%s)", bound.Ref(), runID, before.Execution().Ref(), before.Status)}
	}
	if err := r.Runs.RetryRun(ctx, job.ID, runID); err != nil {
		if errors.Is(err, ErrRunNotRetryable) {
			return EffectResult{Status: EffectNotApplied, Detail: "not dispatched: " + err.Error()}
		}
		// The request may have reached the service. Only the run can say.
		if res, ok := r.observeRetry(ctx, job.ID, runID, bound, 0); ok {
			return res
		}
		return EffectResult{Status: EffectUnknown, Detail: "retry of run " + runID + ": " + err.Error()}
	}
	watch := r.RetryObserve
	if watch <= 0 {
		watch = retryObserveFor
	}
	if res, ok := r.observeRetry(ctx, job.ID, runID, bound, watch); ok {
		return res
	}
	return EffectResult{Status: EffectUnknown, Detail: fmt.Sprintf(
		"the service accepted a retry of run %s but no execution after %s was observed", runID, bound.Ref())}
}

// observeRetry reads the run until an execution other than the bound one is
// seen or the time is up. With no time to watch it reads once. The wait is
// real time: it is spent waiting for the service, not measured against the
// registry's clock.
func (r *Reviewer) observeRetry(ctx context.Context, jobID, runID string, bound Execution, watch time.Duration) (EffectResult, bool) {
	until := time.Now().Add(watch)
	for {
		state, err := r.Runs.RunState(ctx, jobID, runID)
		if now := state.Execution(); err == nil && now.known() && now != bound {
			return EffectResult{
				Status:  EffectApplied,
				Receipt: now.Ref(),
				Detail:  fmt.Sprintf("run %s was retried as execution %s (attempt %s), which was %s when observed", runID, now.Ref(), now.AttemptID, state.Status),
			}, true
		}
		left := time.Until(until)
		if left <= 0 {
			return EffectResult{}, false
		}
		select {
		case <-ctx.Done():
			return EffectResult{}, false
		case <-time.After(min(left, retryObserveEvery)):
		}
	}
}

// probeRetry settles an interrupted or unobserved retry from the run
// itself. An attempt after the bound one proves the retry happened. The
// same attempt still being the latest proves nothing: the dispatch may yet
// land, so it stays unknown and is left to the owner.
func (r *Reviewer) probeRetry(ctx context.Context, job Job, action Action) EffectResult {
	runID := action.Params[RetryRunParam]
	bound, complete := retriedExecution(action.Params)
	if r.Runs == nil || !complete {
		return EffectResult{Status: EffectUnknown, Detail: "the retry of run " + runID + " cannot be checked against the run"}
	}
	if res, ok := r.observeRetry(ctx, job.ID, runID, bound, 0); ok {
		return res
	}
	return EffectResult{Status: EffectUnknown, Detail: fmt.Sprintf("no execution of run %s after %s has been observed", runID, bound.Ref())}
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
	for _, a := range slices.Backward(history) {
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

// verifyGranted compares the action the registry journaled for an approval
// with the proposal the reviewer is about to act on.
func (r *Reviewer) verifyGranted(ctx context.Context, jobID string, action Action, proposal Proposal) error {
	stored, err := r.Registry.Actions(ctx, jobID)
	if err != nil {
		return fmt.Errorf("read granted action: %w", err)
	}
	for _, a := range slices.Backward(stored) {
		if a.ID != action.ID {
			continue
		}
		if a.Name != proposal.ActionName || a.TargetID != proposal.TargetID || !maps.Equal(normalizeParams(a.Params), normalizeParams(proposal.Params)) {
			return errors.New("the granted action is not the action of the approved proposal")
		}
		return nil
	}
	return errors.New("the granted action is not in the journal")
}

func paramsDeclared(declared DeclaredAction, params map[string]string) bool {
	for name := range params {
		found := slices.Contains(declared.Params, name)
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
	for _, a := range slices.Backward(history) {
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
	// The registry's current view of the proposal comes first: a proposal
	// that was superseded runs nothing, whatever the task was given.
	current, err := r.Registry.Proposal(ctx, jobID, proposalID)
	if err != nil {
		return Executed{}, fmt.Errorf("read proposal: %w", err)
	}
	if current.State == ProposalSuperseded {
		return Executed{Skipped: "proposal is superseded: no answer to it authorizes anything and nothing runs"}, nil
	}
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
	proposal := current
	// An approval runs a proposed action. A retry verdict runs exactly one
	// thing: the re-run of the one run a retry proposal names.
	runs := decision.Verdict == VerdictApprove || (decision.Verdict == VerdictRetry && proposal.ActionName == RetryRunAction)
	if !runs {
		return Executed{Skipped: "verdict is " + string(decision.Verdict)}, nil
	}
	if proposal.Kind != ProposalAction {
		return Executed{Skipped: "proposal carries no executable action"}, nil
	}
	job, err := r.Registry.Job(ctx, jobID)
	if err != nil {
		return Executed{}, fmt.Errorf("read job: %w", err)
	}
	if !r.onThisMachine(job) {
		// A decision is valid wherever it is read, but its effect is the
		// job's machine's to perform. Run here, the job's command would use
		// this machine's files and credentials.
		return Executed{Skipped: fmt.Sprintf("job %s is registered on machine %s, not this one (%s): nothing runs here", jobID, job.MachineID, r.MachineID)}, nil
	}
	declared, ok := job.Review.Action(proposal.ActionName)
	if proposal.ActionName == RetryRunAction {
		declared, ok = retryRunDeclaration, r.Runs != nil && proposal.Params[RetryRunParam] != ""
	}
	if !ok {
		return Executed{Skipped: "action is not available for this job"}, nil
	}
	if proposal.ActionName == RetryRunAction {
		// The run is read before anything is granted. If the service cannot
		// be reached now, nothing is journaled and the decision keeps its
		// one attempt for a later try. If the run has moved on from the
		// attempt the decision is about, the registry would refuse the
		// grant, so none is asked for.
		runID := proposal.Params[RetryRunParam]
		bound, complete := retriedExecution(proposal.Params)
		if !complete {
			return Executed{Skipped: "the decision does not name the attempt and queued time of the execution of run " + runID + " it is about: nothing is retried"}, nil
		}
		state, err := r.Runs.RunState(ctx, jobID, runID)
		if err != nil {
			return Executed{}, fmt.Errorf("read run %s: %w", runID, err)
		}
		if !state.retryable(bound) {
			return Executed{Skipped: fmt.Sprintf(
				"the decision is about execution %s of run %s, and the run is now at %s (%s): nothing is retried", bound.Ref(), runID, state.Execution().Ref(), state.Status)}, nil
		}
	}

	if !job.Lifecycle.Reviewable() {
		return Executed{Skipped: "job lifecycle is " + string(job.Lifecycle)}, nil
	}

	claim, err := r.Registry.AcquireClaim(ctx, ClaimRequest{JobID: jobID, Kind: ClaimExecution, Holder: r.Holder, TTL: r.claimTTL()})
	if refused, ok := errors.AsType[*GuardDeniedError](err); ok {
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
	// What runs is what the registry granted, not what this process read
	// earlier. If the journaled action differs from the proposal as read,
	// nothing runs and the attempt is closed as not applied.
	if err := r.verifyGranted(ctx, job.ID, action, proposal); err != nil {
		finishErr := r.Registry.FinishAction(ctx, FinishRequest{
			Claim: claim, JobID: job.ID, ActionID: action.ID, GrantID: action.GrantID,
			State: ActionFailed, Detail: err.Error(),
		})
		if finishErr != nil {
			return Executed{}, fmt.Errorf("record refused action %s: %w", action.ID, finishErr)
		}
		return Executed{Skipped: err.Error()}, nil
	}
	finished, err := r.runJournaled(ctx, claim, job, declared, action)
	if err != nil {
		return Executed{}, err
	}
	return Executed{Action: finished}, nil
}
