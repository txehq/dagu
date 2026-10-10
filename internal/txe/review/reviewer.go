// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
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

	// The owner is told, in the place exceptions are read, when none of the
	// job's commands will be started, and told that this is over once the
	// job is bound again. The job is reviewed either way: telling must not
	// stop the review, and what could not be said is said by the next one.
	binding := Exception{JobID: job.ID, Kind: ExceptionCommandsUnbound, MachineID: job.MachineID, Claim: claim, JobVersion: job.Version}
	if job.CommandsRefused != "" {
		binding.Message = CommandsUnboundMessage(job)
	} else {
		binding.Cleared, binding.Message = true, "the job's commands are bound to this machine's registration again"
	}
	if err := r.Registry.RaiseException(ctx, binding); err != nil {
		fmt.Fprintf(os.Stderr, "txe review: job %s: report on the binding of its commands: %v; the review goes on\n", job.ID, err)
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
			// The registry replaces the stored outcome, so what is known
			// about the request's admission is written again with it.
			Admitted: action.Admitted, AdmittedRef: action.AdmittedRef,
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

	if job.CommandsRefused != "" && action.Name != RetryRunAction {
		// What the registry says this action is could not be established
		// as what was registered. Its declaration is not used for anything:
		// not to run its probe, and not to decide from its idempotency
		// class that the interrupted attempt had no effect. The outcome
		// stays as it is, unresolved and visible, until the job is bound
		// again; the owner already has the exception about that.
		return nil
	}
	declared, ok := job.Review.Action(action.Name)
	res := EffectResult{Status: EffectUnknown, Detail: "the action is no longer declared by the job"}
	if action.Name == RetryRunAction {
		// The reserved retry is not a declared command: the run itself is
		// its only evidence, whatever version the job is at now.
		ok = false
		res = r.probeRetry(ctx, job, action)
		if res.Status == EffectUnknown && res.Pending {
			// The service admitted this retry and its execution has not
			// been seen started yet: a worker may simply not have taken it.
			// Asking the owner would end the action as escalated, and an
			// escalated action is never probed again, so the retry would
			// stay unresolved after it visibly ran. It is left uncertain
			// instead: it stays in every packet as unresolved and is
			// probed again by every review until the run settles it.
			//
			// A reservation that outlasts reservationStalledAfter is put in
			// front of the owner as an exception, not as a question: an
			// answer could only allow another retry, and the reserved
			// execution can still start.
			//
			// Both ends of that time are the registry's: when it granted
			// this attempt of the action, and when it gave this review its
			// claim. The reviewer's own clock is not consulted, so a host
			// whose clock is wrong or stepped reports neither early nor
			// late. The grant precedes the service's admission by the one
			// request in between, and the claim precedes this moment by the
			// start of the review; both only round the half hour. The time
			// decides when the owner is told and nothing else: it never
			// dispatches, settles or re-opens anything.
			if escalate && !claim.AcquiredAt.Before(action.AttemptStartedAt.Add(reservationStalledAfter)) {
				// Telling the owner must not stop the review: a registry
				// that cannot take the exception would otherwise keep the
				// job from ever being reviewed again. Nothing is recorded
				// on a failure, so the next review raises it again.
				if err := r.raiseStalled(ctx, claim, job, action); err != nil {
					fmt.Fprintf(os.Stderr, "txe review: action %s of %s: %v; the action stays uncertain and the review goes on\n", action.ID, job.ID, err)
				}
			}
			return nil
		}
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
		if action.Name == RetryRunAction {
			// A retry is found not applied only by the service's own
			// record that it abandoned exactly the admitted execution
			// before dispatch. That is proof, not absence: nothing of it
			// can still start.
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
// reservationStalledAfter is how long an admitted retry may stay a
// reservation before the owner is told, measured between two times of the
// registry's clock: the grant of the attempt and the review's claim.
const reservationStalledAfter = 30 * time.Minute

// raiseStalled files the exception for an admitted retry whose execution
// has not started. It names the attempt, the execution and the machine, and
// says what to look at. It grants nothing and asks for no decision.
func (r *Reviewer) raiseStalled(ctx context.Context, claim Claim, job Job, action Action) error {
	err := r.Registry.RaiseException(ctx, Exception{
		JobID: job.ID, Kind: ExceptionRetryStalled, MachineID: job.MachineID, Claim: claim,
		ActionID: action.ID, Attempt: action.Attempt, ReviewID: action.ReviewID,
		Message: fmt.Sprintf(
			"The retry of run %s (action %s, attempt %d) was admitted by the service as execution %s on machine %s, in the attempt granted at %s, and no worker has started it. "+
				"Check that a worker for this job is connected to the service and can take queued work, and look at execution %s of the run. "+
				"Nothing is sent again: the reviewer keeps looking and records the retry when that execution starts, or when the service records that its preparation was abandoned. "+
				"Do not retry the run by hand while the execution can still start, or it may run twice.",
			action.Params[RetryRunParam], action.ID, action.Attempt, action.AdmittedRef, job.MachineID, action.AttemptStartedAt.UTC().Format(time.RFC3339), action.AdmittedRef),
	})
	if err != nil {
		return fmt.Errorf("raise exception: %w", err)
	}
	return nil
}

// uncertainVerdictsFor are the answers offered about an attempt whose
// outcome is unknown. "Retry" allows one more attempt of the same action,
// so it is not offered about an attempt that was the last the registry
// allows: the registry would refuse that answer.
func uncertainVerdictsFor(action Action) []Verdict {
	if action.MaxAttempts > 0 && action.Attempt >= action.MaxAttempts {
		return slices.DeleteFunc(slices.Clone(uncertainVerdicts), func(v Verdict) bool { return v == VerdictRetry })
	}
	return uncertainVerdicts
}

func (r *Reviewer) escalate(ctx context.Context, claim Claim, job Job, action Action, detail string) error {
	id := UncertainProposalID(action.ID, action.Attempt, job.Version)
	proposal, err := r.Registry.CreateProposal(ctx, claim, Proposal{
		ID:              id,
		JobID:           job.ID,
		JobVersion:      job.Version,
		PackageDigest:   job.PackageDigest,
		Kind:            ProposalUncertain,
		TargetID:        action.TargetID,
		ObservedAt:      r.now(),
		WaitingOn:       waitingOnPerson,
		AllowedVerdicts: uncertainVerdictsFor(action),
		ActionName:      UncertainEffectAction,
		Params:          map[string]string{UncertainEffectParam: action.ID, UncertainAttemptParam: strconv.Itoa(action.Attempt)},
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

// executeAgain performs the one further attempt the owner allowed by
// answering "retry" to the question about an attempt whose outcome was
// unknown. It applies to an action that ran on a decision: that decision is
// executed again, as it was. The registry decides whether the attempt is
// granted: it consumes the owner's answer with the grant, binds the attempt
// to what the original decision was about, and refuses it when that has
// moved, so nothing is retargeted here. A routine action has no decision to
// run again; the next review may request it.
func (r *Reviewer) executeAgain(ctx context.Context, jobID string, question Proposal) (Executed, error) {
	actions, err := r.Registry.Actions(ctx, jobID)
	if err != nil {
		return Executed{}, fmt.Errorf("read actions: %w", err)
	}
	for _, action := range actions {
		if action.ID != question.RelatedAction {
			continue
		}
		if action.ProposalID == "" || action.DecisionID == "" {
			return Executed{Skipped: "the action was not run on a decision: the next review may request it again"}, nil
		}
		if strconv.Itoa(action.Attempt) != question.Params[UncertainAttemptParam] {
			return Executed{Skipped: fmt.Sprintf("the answer is about attempt %s of action %s, which is now at attempt %d: nothing runs", question.Params[UncertainAttemptParam], action.ID, action.Attempt)}, nil
		}
		original, err := r.Registry.Proposal(ctx, jobID, action.ProposalID)
		if err != nil {
			return Executed{}, fmt.Errorf("read proposal %s: %w", action.ProposalID, err)
		}
		if original.Kind != ProposalAction {
			return Executed{Skipped: "the action's proposal carries no executable action"}, nil
		}
		return r.Execute(ctx, jobID, action.ProposalID, action.DecisionID)
	}
	return Executed{Skipped: "the action the answer is about is not in the journal"}, nil
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
			return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests retrying a run it was not shown (%s). %s", agentText(runID), agentReason(requested.Reason)))
		}
		if !run.Execution().known() {
			// Without the service's identity of the failed execution there
			// is nothing to bind one retry to.
			return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests retrying run %s, whose attempt the service does not identify, so it cannot be retried from here. %s", runID, agentReason(requested.Reason)))
		}
		if run.SpecSHA256 == "" || run.SpecSHA256 != job.DAGSpecSHA256 {
			// A run of an older version is never retried, on the new code
			// or the old. The owner still sees what the reviewer wanted.
			return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests retrying run %s, which did not run the job's current version %d and cannot be retried. %s", runID, job.Version, agentReason(requested.Reason)))
		}
		// The proposal is bound to the failed execution the reviewer was
		// shown, the snapshot it ran and the package of that version; the
		// agent chooses none of them.
		requested.Params = map[string]string{
			RetryRunParam: runID, RetryRunAttemptParam: run.AttemptID, RetryRunQueuedParam: run.QueuedAt,
			RetryRunSpecParam: run.SpecSHA256, RetryRunPackageParam: job.PackageDigest,
		}
		requested.TargetID = ""
		return propose(ProposalAction, fmt.Sprintf("Retry run %s of this job? %s", runID, agentReason(requested.Reason)))
	}
	switch {
	case !isDeclared:
		return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests %s on %s, which this job does not declare. %s", agentText(requested.Name), agentText(requested.TargetID), agentReason(requested.Reason)))
	case !job.HasTarget(requested.TargetID):
		return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests %q on %s (the target as the agent wrote it), which is not a registered target of this job. %s", requested.Name, agentText(requested.TargetID), agentReason(requested.Reason)))
	case !paramsDeclared(declared, requested.Params):
		return propose(ProposalQuestion, fmt.Sprintf("The reviewer suggests %q with parameters the job does not declare. %s", requested.Name, agentReason(requested.Reason)))
	case !declared.Routine:
		return propose(ProposalAction, fmt.Sprintf("Approve %q on %s? %s", requested.Name, requested.TargetID, agentReason(requested.Reason)))
	}

	if job.CommandsRefused != "" {
		// Nothing is granted or journaled for a command that will not be
		// started; the review says why.
		review.Notes = append(review.Notes, fmt.Sprintf("action %q not run: %s", requested.Name, job.CommandsRefused))
		return nil
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
		return propose(ProposalQuestion, fmt.Sprintf("Routine action %q on %s failed %d times in a row and was not tried again. %s", requested.Name, requested.TargetID, failures, agentReason(requested.Reason)))
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
		review.Notes = append(review.Notes, fmt.Sprintf("action %q denied by the guard: %s", requested.Name, deniedText(denied)))
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
		State: state, Receipt: res.Receipt, Detail: res.Detail, Admitted: res.Admitted, AdmittedRef: res.AdmittedRef,
	})
	if err != nil {
		return Action{}, fmt.Errorf("record outcome of action %s: %w", action.ID, err)
	}
	action.State, action.Receipt, action.Detail = state, res.Receipt, res.Detail
	action.Admitted, action.AdmittedRef = res.Admitted, res.AdmittedRef
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
		ID:            id,
		JobID:         job.ID,
		JobVersion:    job.Version,
		PackageDigest: job.PackageDigest,
		Kind:          kind,
		Question:      question,
		// The rationale is the agent's text too, shown beside the question.
		Rationale:       agentText(requested.Reason),
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
		return ask("The review agent asks, in its own words (not checked): " + agentText(decision.Question))
	case OutcomeComplete:
		return ask("The reviewer finds this job's purpose fulfilled and recommends completing it." + packet.trimmedCaveat())
	case OutcomeRetire:
		return ask("The reviewer recommends retiring this job." + packet.trimmedCaveat())
	case OutcomePauseUnavailable:
		err := r.Registry.RaiseException(ctx, Exception{
			JobID: job.ID, Kind: ExceptionUnavailable, MachineID: job.MachineID,
			Message:  "The review agent judged the job's target, credentials or machine unreachable. Its reasoning, in its own words (not checked): " + agentText(decision.Reasoning),
			ReviewID: packet.ReviewID,
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
	// RetryRun asks the service to retry the run, on the condition that
	// expected is still the run's latest execution. The service checks that
	// together with admitting the retry, so a run that moved on between
	// this caller's own read and its request is refused, not retried again.
	// It returns ErrRunNotRetryable only for a refusal the service is known
	// to make before anything is started; after any other error whether a
	// retry started is unknown.
	//
	// With no error the service admitted the request. admitted is then the
	// execution the service says it admitted it as, or the zero Execution
	// when the service does not name one.
	RetryRun(ctx context.Context, jobID, runID string, expected Execution) (admitted Execution, err error)
	// Abandoned reports whether the service recorded that the execution of
	// the run named by ref was created and never dispatched. known is false
	// when its records cannot answer that for this execution.
	Abandoned(ctx context.Context, jobID, runID, ref string) (abandoned, known bool)
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
// not retried again on its strength. The check here only spares a request
// that would be refused; what binds the retry to the execution is the
// service, which is given the execution and compares it as it admits the
// retry. After a dispatch the result is applied only when the retry's
// execution is observed on the run, and its reference is the receipt. A
// dispatch whose outcome was not observed is unknown; it is never reported
// from the service's acceptance alone, and never repeated.
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
	admitted, err := r.Runs.RetryRun(ctx, job.ID, runID, bound)
	if err != nil {
		if errors.Is(err, ErrRunNotRetryable) {
			return EffectResult{Status: EffectNotApplied, Detail: "not dispatched: " + err.Error()}
		}
		// Whether the service started anything is not known. What the run
		// shows now cannot settle it either: without the service's word
		// that it admitted this request, a newer execution on the run may
		// be another caller's retry, such as the one that made the service
		// refuse this request in a way this client does not recognise.
		// The outcome stays unknown and says what was seen.
		return EffectResult{Status: EffectUnknown, Detail: "retry of run " + runID + ": " + err.Error() + ". " + r.seenOnRun(ctx, job.ID, runID, bound)}
	}
	watch := r.RetryObserve
	if watch <= 0 {
		watch = retryObserveFor
	}
	if !admitted.known() || admitted == bound {
		// The service admitted the retry without saying which execution it
		// admitted it as. Then no execution on the run can be recorded as
		// this retry's: the one seen may be a later one, started by another
		// caller after this retry's execution finished or was abandoned.
		return unnamedAdmission(runID, r.seenOnRun(ctx, job.ID, runID, bound))
	}
	return r.observeRetry(ctx, job.ID, runID, bound, admitted.Ref(), watch, "the service accepted a retry of run "+runID)
}

// unnamedAdmission is the unknown outcome of a retry the service admitted
// without naming its execution. It is not pending: nothing the run shows
// later can be attributed to it either, so the owner is asked.
func unnamedAdmission(runID, seen string) EffectResult {
	return EffectResult{
		Status: EffectUnknown, Admitted: true,
		Detail: "the service accepted a retry of run " + runID + " but did not name the execution it admitted it as, so no execution of the run can be recorded as this retry's. " + seen,
	}
}

// seenOnRun says what the run shows, for the record of an outcome that
// cannot be settled from it.
func (r *Reviewer) seenOnRun(ctx context.Context, jobID, runID string, bound Execution) string {
	state, err := r.Runs.RunState(ctx, jobID, runID)
	switch now := state.Execution(); {
	case err != nil:
		return "The run could not be read afterwards."
	case now == bound:
		return fmt.Sprintf("The run still shows execution %s (%s).", now.Ref(), state.Status)
	default:
		return fmt.Sprintf("The run now shows execution %s (%s); whether this request or another caller started it cannot be told.", now.Ref(), state.Status)
	}
}

// observeRetry reads the run of a retry the service admitted as the
// execution named, until it shows that execution dispatched, or the time is
// up. With no time to watch it reads once. The wait is real time: it is
// spent waiting for the service, not measured against the registry's clock.
//
// Only the named execution is the retry: once it is the run's latest and
// queued, running or over, it is the receipt. Another execution on the run
// is not, even though it came after the retried one: the admitted execution
// can finish and be retried by someone else before this reviewer looks, and
// the run's latest execution is then theirs. That outcome is unknown and is
// not waited on, because the latest execution will not turn back into the
// admitted one.
//
// The named execution shows the retry dispatched only once it is queued,
// running or over. While it is not started, it is a reservation: the
// service creates the new attempt before it hands it to a worker, which may
// not have taken it yet, and the service can stop in between. A reservation
// is reported as such, never as the retry, and the outcome is pending:
// later reviews look again.
func (r *Reviewer) observeRetry(ctx context.Context, jobID, runID string, bound Execution, named string, watch time.Duration, cause string) EffectResult {
	until := time.Now().Add(watch)
	reserved := ""
	for {
		state, err := r.Runs.RunState(ctx, jobID, runID)
		if now := state.Execution(); err == nil && now.known() && now != bound {
			ref := now.Ref()
			switch {
			case ref != named:
				if was, _ := r.Runs.Abandoned(ctx, jobID, runID, named); was {
					return notDispatched(runID, named)
				}
				return EffectResult{
					Status: EffectUnknown, Admitted: true, AdmittedRef: named,
					Detail: fmt.Sprintf("the service admitted the retry of run %s as execution %s, and the run now shows execution %s (%s), which is not it; whether %s ran cannot be told from the run's latest execution", runID, named, ref, state.Status, named),
				}
			case state.Status == runFailed:
				// A failed execution is not proof that anything ran: the
				// service marks one it never dispatched the same way. Its
				// record of that is read before the execution is taken for
				// the retry.
				switch was, known := r.Runs.Abandoned(ctx, jobID, runID, named); {
				case was:
					return notDispatched(runID, named)
				case !known:
					return EffectResult{
						Status: EffectUnknown, Admitted: true, AdmittedRef: named,
						Detail: fmt.Sprintf("execution %s of run %s is failed, and the service could not say whether it was ever dispatched", named, runID),
					}
				}
				fallthrough
			case state.Status != runNotStarted && state.Status != "":
				return EffectResult{
					Status: EffectApplied, Receipt: ref, Admitted: true, AdmittedRef: named,
					Detail: fmt.Sprintf("run %s was retried as execution %s (attempt %s), which was %s when observed", runID, ref, now.AttemptID, state.Status),
				}
			}
			reserved = ref
		}
		left := time.Until(until)
		if left > 0 {
			select {
			case <-ctx.Done():
				left = 0
			case <-time.After(min(left, retryObserveEvery)):
			}
		}
		if left <= 0 {
			break
		}
	}
	// The admitted execution was not seen dispatched. The service may have
	// recorded that it abandoned its preparation: that record, for exactly
	// this execution, is what settles the retry as not dispatched. The
	// retried execution being the latest again, or the reservation being
	// gone, does not.
	if was, _ := r.Runs.Abandoned(ctx, jobID, runID, named); was {
		return notDispatched(runID, named)
	}
	detail := fmt.Sprintf("no execution of run %s after %s was seen queued or started", runID, bound.Ref())
	if reserved != "" {
		detail = fmt.Sprintf("an attempt (%s) was created for the retry of run %s but was not seen queued or started; it may not have been handed to a worker yet, or never will be", reserved, runID)
	}
	if cause != "" {
		detail = cause + ": " + detail
	}
	// Only a reservation is waited on. With none on the run, the admitted
	// retry left nothing that could still start, and the retried execution
	// being the latest again does not prove nothing ran: the owner is asked.
	return EffectResult{Status: EffectUnknown, Detail: detail, Admitted: true, AdmittedRef: named, Pending: reserved != ""}
}

// runNotStarted is the service's status of an attempt that exists but has
// not been queued or started, and runFailed of one that failed, which
// includes one the service marked failed without ever dispatching it.
const (
	runNotStarted = "not_started"
	runFailed     = "failed"
)

// notDispatched is the outcome of a retry whose admitted execution the
// service recorded as abandoned before dispatch: nothing ran.
func notDispatched(runID, named string) EffectResult {
	return EffectResult{
		Status: EffectNotApplied, Admitted: true, AdmittedRef: named,
		Detail: fmt.Sprintf("not dispatched: the service recorded that it abandoned the preparation of execution %s of run %s before handing it to a worker", named, runID),
	}
}

// probeRetry settles a retry whose result was not seen, from the run, when
// that is sound. It is sound only when the service had admitted the
// request; observeRetry says what the run then proves. Until the admitted
// execution is seen queued, running or over the outcome is pending, however
// long a worker takes: nothing is dispatched again and the owner is not
// asked, because that would end the action before its execution ran.
//
// When the service's answer was never known, because the request failed in
// a way that says nothing or the reviewer died before recording it, a newer
// execution on the run may be someone else's retry. Nothing is settled from
// it: the outcome stays unknown, says what the run shows, and goes to the
// owner.
func (r *Reviewer) probeRetry(ctx context.Context, job Job, action Action) EffectResult {
	runID := action.Params[RetryRunParam]
	bound, complete := retriedExecution(action.Params)
	if r.Runs == nil || !complete {
		return EffectResult{Status: EffectUnknown, Detail: "the retry of run " + runID + " cannot be checked against the run"}
	}
	if !action.Admitted {
		return EffectResult{Status: EffectUnknown, Detail: "it is not known whether the service admitted the retry of run " + runID + ". " + r.seenOnRun(ctx, job.ID, runID, bound)}
	}
	if action.AdmittedRef == "" {
		return unnamedAdmission(runID, r.seenOnRun(ctx, job.ID, runID, bound))
	}
	return r.observeRetry(ctx, job.ID, runID, bound, action.AdmittedRef, 0, "")
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
			return a, !retryDecided(decisions, UncertainProposalID(a.ID, a.Attempt, jobVersion))
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

// maxAgentText bounds how much of the agent's own text a question carries.
const maxAgentText = 600

// agentText renders text the agent wrote for a question the owner reads.
// The agent read the job's output, which can contain anything a script
// printed, so its words are shown as a quotation and never as part of the
// reviewer's own statement: line breaks and other control characters are
// folded into spaces, the length is bounded, and the result is quoted with
// its own quotation marks escaped, so the text cannot end the quotation or
// start what looks like a new section of the question.
func agentText(text string) string {
	text = strings.Join(strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}), " ")
	if runes := []rune(text); len(runes) > maxAgentText {
		text = string(runes[:maxAgentText]) + " [cut]"
	}
	return strconv.Quote(text)
}

// agentReason marks the agent's own words in a question the owner is asked
// to answer: offered as its opinion, not as a fact the reviewer checked.
func agentReason(reason string) string {
	return "The review agent's reason, in its own words (not checked): " + agentText(reason)
}

// deniedText is what is recorded of a refusal by the guard. A refusal of
// the parameter values says which value and why, in the registry's words,
// which quote the value the agent chose: that part is shown as a bounded
// quotation like the agent's other text.
func deniedText(denied *GuardDeniedError) string {
	if denied.Reason == DenyInvalidParams && denied.Detail != "" {
		return string(denied.Reason) + ": the registry said " + agentText(denied.Detail)
	}
	return string(denied.Reason)
}

// CommandsUnboundMessage is the exception raised for a job none of whose
// commands is started: what is wrong, on which machine, and what to do.
func CommandsUnboundMessage(job Job) string {
	return "The job's commands are not started. On machine " + job.MachineID + ": " + job.CommandsRefused +
		". Reviews and questions go on; routine actions, approved actions and reconcile probes of this job do not run. " +
		"If an update of the job from that machine was interrupted, finish it there with `dagu txe resume <request id>`; the unfinished request is under the TXE home's receipts/pending. " +
		"If the job was changed on purpose from elsewhere, update it from that machine with `dagu txe update <job id> -f <spec> --expected-version <n>`, which keeps the job and its history and records the new version there. " +
		"If nobody changed it, the registry's record of the job was altered: find out who wrote to it before updating."
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
	if proposal.Kind == ProposalUncertain && decision.Verdict == VerdictRetry {
		return r.executeAgain(ctx, jobID, proposal)
	}
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
	if job.CommandsRefused != "" && proposal.ActionName != RetryRunAction {
		// An approval does not make an unregistered command the registered
		// one. Nothing is granted, so the decision keeps its attempt for
		// when the job is bound again. A retry of a run is the service's
		// own operation, not a command of the job started here.
		return Executed{Skipped: "not run: " + job.CommandsRefused}, nil
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
		return Executed{Skipped: "denied by the guard: " + deniedText(denied)}, nil
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
