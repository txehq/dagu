// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"
)

// BindingDigest binds an action to the job version and package it was
// proposed against. Any change to the version, package, target identity,
// action name or parameters yields a different digest. It is the only
// implementation; callers never compute bindings themselves.
func BindingDigest(job *Job, spec ActionSpec) (string, error) {
	var target any
	if spec.Target != nil {
		target = map[string]any{"kind": spec.Target.Kind, "stable_id": spec.Target.StableID}
	}
	params := spec.Params
	if len(params) == 0 {
		params = json.RawMessage("null")
	}
	b, err := CanonicalJSON(map[string]any{
		"job_id":         job.JobID,
		"job_version":    job.Version,
		"package_digest": job.PackageDigest,
		"target":         target,
		"action":         map[string]any{"name": spec.Name, "params": params},
	})
	if err != nil {
		return "", fmt.Errorf("registry: binding digest: %w", err)
	}
	return sha256Hex(b), nil
}

// ReviewID is the deterministic ID of the review episode that starts from
// the given checkpoint version. A replacement reviewer for the same episode
// gets the same ID.
func ReviewID(jobID string, checkpointVersion int) (string, error) {
	return DerivedID(PrefixReview, jobID, checkpointVersion)
}

// RoutineActionID is the ID of a routine action intent within one review.
func RoutineActionID(reviewID string, spec ActionSpec) (string, error) {
	var targetKey string
	if spec.Target != nil {
		targetKey = TargetKey(*spec.Target)
	}
	return DerivedID(PrefixAction, reviewID, spec.Name, targetKey, spec.Params)
}

// ApprovedActionID is the ID of the single action an approval authorizes.
func ApprovedActionID(proposalID, decisionID string) (string, error) {
	return DerivedID(PrefixAction, proposalID, decisionID)
}

// LifecycleOp is a requested lifecycle change.
type LifecycleOp string

const (
	OpPause      LifecycleOp = "pause"
	OpResume     LifecycleOp = "resume"
	OpNeedsHuman LifecycleOp = "needs_human"
	OpComplete   LifecycleOp = "complete"
	OpRetire     LifecycleOp = "retire"
	OpReactivate LifecycleOp = "reactivate"
)

// Transition is a lifecycle change with its reason and evidence.
type Transition struct {
	Op       LifecycleOp
	Reason   RetirementReason // required for OpRetire
	Detail   string
	Evidence []string
	// ActiveRunPolicy overrides the job's rule for this retirement.
	ActiveRunPolicy ActiveRunPolicy
	// Affected lists runs the caller found queued or running, with what
	// happens to each. The registry adds proposals, claims and actions.
	Affected []Affected
	// Authorize, when set, is checked against the job inside the same
	// commit as the change (ChangeLifecycle only).
	Authorize func(tx *JobTx) error
	// DetailFor, when set, computes Detail from the job being committed
	// (ChangeLifecycle only).
	DetailFor func(job *Job) string
}

// Transition applies a lifecycle change. Completion and retirement are
// terminal: only a human reactivation leaves them, and in the same commit
// every open proposal is superseded and every in-flight action is listed
// for reconciliation.
func (tx *JobTx) Transition(t Transition) error {
	j := tx.Job
	from := j.Lifecycle
	var to Lifecycle
	switch t.Op {
	case OpPause:
		if from != LifecycleActive && from != LifecycleNeedsHuman {
			return tx.badTransition(t.Op)
		}
		to = LifecyclePaused
	case OpResume:
		if from != LifecyclePaused && from != LifecycleNeedsHuman {
			return tx.badTransition(t.Op)
		}
		to = LifecycleActive
	case OpNeedsHuman:
		if from != LifecycleActive {
			return tx.badTransition(t.Op)
		}
		to = LifecycleNeedsHuman
	case OpComplete:
		if from.Terminal() {
			return tx.badTransition(t.Op)
		}
		to = LifecycleCompleted
		t.Reason = RetireCompleted
	case OpRetire:
		if from.Terminal() {
			return tx.badTransition(t.Op)
		}
		switch t.Reason {
		case RetireExpired, RetireManual, RetireTargetDeleted, RetireReplaced:
		case RetireCompleted:
			return refuse(CodeInvalid, "use complete for a fulfilled purpose")
		default:
			return refuse(CodeInvalid, "retire needs a reason: expired, manual, target_deleted or replaced")
		}
		to = LifecycleRetired
	case OpReactivate:
		if !from.Terminal() {
			return tx.badTransition(t.Op)
		}
		if tx.actor.Kind != ActorHuman {
			return refuse(CodeNotPermitted, "only a person can reactivate a %s job", from)
		}
		to = LifecycleActive
	default:
		return refuse(CodeInvalid, "unknown lifecycle op %q", t.Op)
	}

	affected := append([]Affected(nil), t.Affected...)
	if to.Terminal() {
		more, err := tx.stopFollowUps(fmt.Sprintf("job %s", to))
		if err != nil {
			return err
		}
		affected = append(affected, more...)
		policy := t.ActiveRunPolicy
		if policy == "" {
			v, err := tx.CurrentVersion()
			if err != nil {
				return err
			}
			policy = v.RetirementRules.ActiveRunPolicy
		}
		j.Retirement = &Retirement{
			Reason:          t.Reason,
			Detail:          t.Detail,
			Evidence:        t.Evidence,
			Actor:           tx.actor,
			At:              tx.now,
			ActiveRunPolicy: policy,
			Affected:        affected,
		}
	}
	if t.Op == OpReactivate {
		j.Retirement = nil
	}
	j.Lifecycle = to
	j.LifecycleReason = t.Detail
	if t.Reason != "" {
		j.LifecycleReason = string(t.Reason)
	}
	return tx.event(Event{
		Kind:     EventLifecycle,
		From:     string(from),
		To:       string(to),
		Reason:   string(t.Reason),
		Detail:   t.Detail,
		Evidence: t.Evidence,
		Affected: affected,
	})
}

func (tx *JobTx) badTransition(op LifecycleOp) error {
	return &Error{Code: CodeTransition, Message: fmt.Sprintf("cannot %s a %s job", op, tx.Job.Lifecycle), Current: tx.Job}
}

// stopFollowUps supersedes open proposals and lists in-flight actions. The
// live claim is left to expire so its holder can still settle what it
// started, but a terminal job refuses every new grant, proposal and claim
// other than reconcile. In-flight actions stay on the job until settled;
// their effects may already have happened.
func (tx *JobTx) stopFollowUps(reason string) ([]Affected, error) {
	affected, err := tx.supersedeProposals(reason)
	if err != nil {
		return nil, err
	}
	for _, a := range sortedActions(tx.Job.Actions) {
		if a.State == ActionExecuting || a.State == ActionUncertain {
			affected = append(affected, Affected{ActionID: a.ActionID, Disposition: DispositionInFlightReconcile})
		}
	}
	tx.touch()
	return affected, nil
}

// supersedeProposals finishes every proposal that has no action in flight.
func (tx *JobTx) supersedeProposals(reason string) ([]Affected, error) {
	var affected []Affected
	for _, p := range sortedProposals(tx.Job.Proposals) {
		if p.State.Terminal() || tx.proposalInFlight(p.ProposalID) {
			continue
		}
		p.State = ProposalSuperseded
		p.Revision++
		p.Reasoning = reason
		p.Updated = Stamp{At: tx.now, By: tx.actor}
		if err := tx.archiveProposal(p); err != nil {
			return nil, err
		}
		affected = append(affected, Affected{ProposalID: p.ProposalID, Disposition: DispositionSuperseded})
	}
	return affected, nil
}

func (tx *JobTx) proposalInFlight(proposalID string) bool {
	for _, a := range tx.Job.Actions {
		if a.ProposalID == proposalID && (a.State == ActionExecuting || a.State == ActionUncertain) {
			return true
		}
	}
	return false
}

func (tx *JobTx) archiveProposal(p *Proposal) error {
	cp := *p
	if _, err := tx.attach(kindProposals, &cp, func(prev string) { cp.Prev = prev }); err != nil {
		return err
	}
	delete(tx.Job.Proposals, p.ProposalID)
	return nil
}

func (tx *JobTx) archiveAction(a *Action) error {
	cp := *a
	if _, err := tx.attach(kindActions, &cp, func(prev string) { cp.Prev = prev }); err != nil {
		return err
	}
	delete(tx.Job.Actions, a.ActionID)
	return nil
}

// Observation reports execution availability or an actionable failure.
type Observation struct {
	State    AvailabilityState
	Kind     string // exception kind, e.g. "auth", "worker_offline", "reviewer_launch"
	Detail   string
	Evidence []string
}

// Observe records availability. It never changes the lifecycle: an offline
// machine, an expired login or an unreachable target is not a retirement.
// A non-ready observation opens an exception; a ready one resolves them.
func (tx *JobTx) Observe(o Observation) error {
	j := tx.Job
	if o.State == "" {
		return refuse(CodeInvalid, "observation state is required")
	}
	from := j.Availability.State
	now := tx.now
	actor := tx.actor
	j.Availability = Availability{State: o.State, Detail: o.Detail, Evidence: o.Evidence, ObservedAt: &now, Reporter: &actor}
	if o.State == AvailabilityReady {
		for _, e := range j.Exceptions {
			if e.ResolvedAt == nil && e.State != "" {
				e.ResolvedAt = &now
			}
		}
	} else {
		id, err := NewID(PrefixException, now)
		if err != nil {
			return err
		}
		if j.Exceptions == nil {
			j.Exceptions = map[string]*Exception{}
		}
		kind := o.Kind
		if kind == "" {
			kind = string(o.State)
		}
		j.Exceptions[id] = &Exception{ExceptionID: id, Kind: kind, State: o.State, Detail: o.Detail, Evidence: o.Evidence, Created: Stamp{At: now, By: actor}}
	}
	tx.touch()
	if from == o.State {
		return nil
	}
	return tx.event(Event{Kind: EventAvailability, From: string(from), To: string(o.State), Detail: o.Detail, Evidence: o.Evidence})
}

// ResolveException marks one exception resolved.
func (tx *JobTx) ResolveException(id string) error {
	e, ok := tx.Job.Exceptions[id]
	if !ok {
		return refuse(CodeNotFound, "exception %s not found", id)
	}
	if e.ResolvedAt == nil {
		now := tx.now
		e.ResolvedAt = &now
		tx.touch()
	}
	return nil
}

// AcquireClaim grants the per-job claim slot. A live claim is refused; an
// expired one is taken over with a higher fence, and the actions it left
// executing become uncertain (failed when read-only) so they are reconciled,
// never re-run. A reconcile claim is allowed on a completed or retired job;
// review and execution claims need a ready job that accepts effects.
func (tx *JobTx) AcquireClaim(kind ClaimKind, r Reviewer, ttl time.Duration) (*Claim, error) {
	j := tx.Job
	switch kind {
	case ClaimReview, ClaimExecution:
		if j.Registration.State != RegistrationReady {
			return nil, refuse(CodeNotReady, "job registration is %s", j.Registration.State)
		}
		if !j.Lifecycle.AcceptsEffects() {
			return nil, &Error{Code: CodeLifecycle, Message: "job is " + string(j.Lifecycle), Current: j}
		}
	case ClaimReconcile:
	default:
		return nil, refuse(CodeInvalid, "claim kind must be review, execution or reconcile")
	}
	if ttl <= 0 {
		return nil, refuse(CodeInvalid, "claim ttl must be positive")
	}
	if c := j.Claim; c != nil {
		if c.State == ClaimLive {
			if tx.now.Before(c.ExpiresAt) {
				return nil, &Error{Code: CodeClaimHeld, Message: "claim " + c.ClaimID + " is live", Current: c}
			}
			c.State = ClaimExpired
		}
		tx.interruptClaim(c.ClaimID)
	}
	id, err := NewID(PrefixClaim, tx.now)
	if err != nil {
		return nil, err
	}
	j.Fence++
	claim := &Claim{ClaimID: id, Kind: kind, Reviewer: r, Fence: j.Fence, AcquiredAt: tx.now, ExpiresAt: tx.now.Add(ttl), State: ClaimLive}
	j.Claim = claim
	tx.touch()
	cp := *claim
	return &cp, nil
}

// interruptClaim interrupts the actions claimID left executing. Once its
// claim is gone no holder can settle them, so they are reconciled instead.
func (tx *JobTx) interruptClaim(claimID string) {
	for _, a := range tx.Job.Actions {
		if a.ClaimID == claimID && a.State == ActionExecuting {
			tx.interrupt(a)
		}
	}
}

// interrupt marks an executing action whose holder is gone. Its effect may
// have happened, so it is uncertain unless the creator declared it read-only.
func (tx *JobTx) interrupt(a *Action) {
	a.State = ActionUncertain
	if a.ReadOnly {
		a.State = ActionFailed
	}
	a.Updated = Stamp{At: tx.now, By: Actor{Kind: ActorSystem, ID: "registry"}}
	tx.touch()
}

// CheckClaim refuses unless claimID with fence is the job's live claim and,
// when kinds are given, of one of those kinds.
func (tx *JobTx) CheckClaim(claimID string, fence int64, kinds ...ClaimKind) error {
	c := tx.Job.Claim
	if c == nil || c.ClaimID != claimID || c.Fence != fence || c.State != ClaimLive || !tx.now.Before(c.ExpiresAt) {
		return &Error{Code: CodeClaimStale, Message: "claim " + claimID + " is not the live claim", Current: c}
	}
	if len(kinds) == 0 {
		return nil
	}
	if slices.Contains(kinds, c.Kind) {
		return nil
	}
	return &Error{Code: CodeClaimStale, Message: fmt.Sprintf("claim %s is a %s claim", claimID, c.Kind), Current: c}
}

// ReleaseClaim ends a live claim and interrupts the actions it left
// executing. Releasing an already released claim with the same fence is a
// no-op.
func (tx *JobTx) ReleaseClaim(claimID string, fence int64) error {
	c := tx.Job.Claim
	if c != nil && c.ClaimID == claimID && c.Fence == fence && c.State == ClaimReleased {
		return nil
	}
	if err := tx.CheckClaim(claimID, fence); err != nil {
		return err
	}
	c.State = ClaimReleased
	tx.interruptClaim(claimID)
	tx.touch()
	return nil
}

// RecordReview saves an immutable review under the live claim. Replaying the
// most recently recorded review is a no-op.
func (tx *JobTx) RecordReview(claimID string, fence int64, r Review) error {
	j := tx.Job
	if r.ReviewID != "" && r.ReviewID == j.LastRecordedReview {
		return nil
	}
	if err := tx.CheckClaim(claimID, fence, ClaimReview); err != nil {
		return err
	}
	want, err := ReviewID(j.JobID, j.Checkpoint.Version)
	if err != nil {
		return err
	}
	if r.ReviewID != want {
		return refuse(CodeClaimStale, "review %s is not the current episode %s", r.ReviewID, want)
	}
	r.JobVersion = j.Version
	r.CheckpointVersion = j.Checkpoint.Version
	r.ClaimID = claimID
	r.Fence = fence
	r.Created = Stamp{At: tx.now, By: tx.actor}
	if _, err := tx.attach(kindReviews, &r, func(prev string) { r.Prev = prev }); err != nil {
		return err
	}
	j.LastRecordedReview = r.ReviewID
	return nil
}

// AdvanceCheckpoint ends the current review episode. expectedVersion must be
// the current checkpoint version. Finished routine actions leave the job
// aggregate for history; executing or uncertain ones stay to be settled.
func (tx *JobTx) AdvanceCheckpoint(claimID string, fence int64, expectedVersion int, cp Checkpoint) (*Checkpoint, error) {
	j := tx.Job
	if err := tx.CheckClaim(claimID, fence, ClaimReview); err != nil {
		return nil, err
	}
	if j.Checkpoint.Version != expectedVersion {
		return nil, &Error{Code: CodeVersionConflict, Message: fmt.Sprintf("checkpoint is at %d, not %d", j.Checkpoint.Version, expectedVersion), Current: j.Checkpoint}
	}
	for _, a := range sortedActions(j.Actions) {
		if a.Kind == ActionRoutine && a.State != ActionExecuting && a.State != ActionUncertain {
			if err := tx.archiveAction(a); err != nil {
				return nil, err
			}
		}
	}
	cp.Version = expectedVersion + 1
	if cp.JobVersion == 0 {
		cp.JobVersion = j.Version
	}
	j.Checkpoint = cp
	tx.touch()
	out := cp
	return &out, nil
}

// DeferReview moves only the next review time, keeping the episode and its
// evidence cursors, e.g. after the reviewer could not authenticate.
func (tx *JobTx) DeferReview(claimID string, fence int64, next time.Time) error {
	if err := tx.CheckClaim(claimID, fence, ClaimReview); err != nil {
		return err
	}
	tx.Job.Checkpoint.NextReviewAt = &next
	tx.touch()
	return nil
}

// PutProposal files a proposal under the live claim. The registry computes
// the binding against the current version. Re-filing the same proposal with
// the same binding is a no-op.
func (tx *JobTx) PutProposal(claimID string, fence int64, p Proposal) (*Proposal, error) {
	j := tx.Job
	if err := ValidateID(PrefixProposal, p.ProposalID); err != nil {
		return nil, err
	}
	if !j.Lifecycle.AcceptsEffects() {
		return nil, &Error{Code: CodeLifecycle, Message: "job is " + string(j.Lifecycle), Current: j}
	}
	binding, err := BindingDigest(j, p.Action)
	if err != nil {
		return nil, err
	}
	if cur, ok := j.Proposals[p.ProposalID]; ok {
		if cur.BindingDigest == binding {
			out := *cur
			return &out, nil
		}
		return nil, &Error{Code: CodeProposalState, Message: "proposal " + p.ProposalID + " exists with another binding", Current: cur}
	}
	if err := tx.CheckClaim(claimID, fence, ClaimReview); err != nil {
		return nil, err
	}
	for _, v := range p.AllowedVerdicts {
		if !knownVerdict(v) {
			return nil, refuse(CodeInvalid, "unknown verdict %q", v)
		}
	}
	p.JobVersion = j.Version
	p.PackageDigest = j.PackageDigest
	p.BindingDigest = binding
	p.Revision = 1
	p.State = ProposalOpen
	p.Decision = nil
	p.Created = Stamp{At: tx.now, By: tx.actor}
	p.Updated = p.Created
	if j.Proposals == nil {
		j.Proposals = map[string]*Proposal{}
	}
	stored := p
	j.Proposals[p.ProposalID] = &stored
	tx.touch()
	out := stored
	return &out, nil
}

// Proposal returns the open proposal for modification within the
// transaction, or nil.
func (tx *JobTx) Proposal(id string) *Proposal {
	p := tx.Job.Proposals[id]
	if p != nil {
		tx.touch()
	}
	return p
}

func knownVerdict(v Verdict) bool {
	switch v {
	case VerdictApprove, VerdictReject, VerdictRedirect, VerdictRetry, VerdictPause, VerdictSnooze, VerdictRetire:
		return true
	}
	return false
}

// DecisionByKey returns the decision ID recorded under idempotencyKey.
func (tx *JobTx) DecisionByKey(idempotencyKey string) (string, bool) {
	id, ok := tx.Job.DecisionKeys[idempotencyKey]
	return id, ok
}

// AppendDecision records a human decision on an open or snoozed proposal and
// moves the proposal to next: decided (executable only when the verdict is
// approve), snoozed, or rejected (finished). The decision must name the
// proposal's current revision and the binding of the current job, and use an
// allowed verdict; otherwise it is refused. The caller owns the meaning of
// each verdict; lifecycle verdicts call Transition in the same transaction.
// A replayed idempotency key is refused with CodeDuplicate and the stored
// decision ID, so the caller can return the stored decision.
func (tx *JobTx) AppendDecision(d Decision, next ProposalState) (*Decision, error) {
	j := tx.Job
	if d.IdempotencyKey != "" {
		if id, ok := j.DecisionKeys[d.IdempotencyKey]; ok {
			return nil, &Error{Code: CodeDuplicate, Message: "idempotency key already decided", Current: id}
		}
	}
	p, ok := j.Proposals[d.ProposalID]
	if !ok {
		return nil, refuse(CodeProposalState, "proposal %s is not open", d.ProposalID)
	}
	if err := ValidateID(PrefixDecision, d.DecisionID); err != nil {
		return nil, err
	}
	if !knownVerdict(d.Verdict) {
		return nil, refuse(CodeInvalid, "unknown verdict %q", d.Verdict)
	}
	if len(p.AllowedVerdicts) > 0 {
		allowed := false
		for _, v := range p.AllowedVerdicts {
			allowed = allowed || v == d.Verdict
		}
		if !allowed {
			return nil, &Error{Code: CodeNotPermitted, Message: "verdict " + string(d.Verdict) + " is not allowed for this proposal", Current: p}
		}
	}
	switch next {
	case ProposalDecided, ProposalSnoozed, ProposalRejected:
	case ProposalOpen, ProposalExecuted, ProposalSuperseded:
		return nil, refuse(CodeInvalid, "a decision moves a proposal to decided, snoozed or rejected, not %s", next)
	default:
		return nil, refuse(CodeInvalid, "unknown proposal state %q", next)
	}
	if p.State != ProposalOpen && p.State != ProposalSnoozed {
		return nil, &Error{Code: CodeProposalState, Message: "proposal is " + string(p.State), Current: p}
	}
	if d.ProposalRevision != p.Revision {
		return nil, &Error{Code: CodeStaleBinding, Message: fmt.Sprintf("proposal is at revision %d, not %d", p.Revision, d.ProposalRevision), Current: p}
	}
	current, err := BindingDigest(j, p.Action)
	if err != nil {
		return nil, err
	}
	if d.BindingDigest != current || p.BindingDigest != current {
		return nil, &Error{Code: CodeStaleBinding, Message: "decision binding does not match the current job and action", Current: p}
	}
	if j.Lifecycle.Terminal() {
		return nil, &Error{Code: CodeLifecycle, Message: "job is " + string(j.Lifecycle), Current: j}
	}
	d.DecidedAt = tx.now
	if d.Actor.Kind == "" {
		d.Actor = tx.actor
	}
	// A snooze leaves the Dagu human task waiting, so there is nothing to
	// resume yet.
	if p.NativeTask != nil && next != ProposalSnoozed {
		d.NativeResume = "pending"
		if j.NativeResumes == nil {
			j.NativeResumes = map[string]*NativeResume{}
		}
		j.NativeResumes[d.DecisionID] = &NativeResume{DecisionID: d.DecisionID, ProposalID: p.ProposalID, NativeTask: *p.NativeTask, Since: tx.now}
	}
	stored := d
	if _, err := tx.attach(kindDecisions, &stored, func(prev string) { stored.Prev = prev }); err != nil {
		return nil, err
	}
	p.Decision = &stored
	p.Revision++
	p.Updated = Stamp{At: tx.now, By: tx.actor}
	p.State = next
	p.SnoozeUntil = nil
	if next == ProposalSnoozed {
		p.SnoozeUntil = d.SnoozeUntil
	}
	if d.IdempotencyKey != "" {
		if j.DecisionKeys == nil {
			j.DecisionKeys = map[string]string{}
		}
		j.DecisionKeys[d.IdempotencyKey] = d.DecisionID
	}
	if next == ProposalRejected {
		if err := tx.archiveProposal(p); err != nil {
			return nil, err
		}
	}
	out := stored
	return &out, nil
}

// CurrentNativeResume is the native task state of decision d on job now:
// "pending" while job still has to complete the decision's Dagu human task,
// "completed" once it has, and "" when there was none to complete (no
// native task, or a snooze). The decision record keeps the value it was
// written with; readers report this instead.
func CurrentNativeResume(job *Job, d *Decision) string {
	if _, pending := job.NativeResumes[d.DecisionID]; pending {
		return "pending"
	}
	if d.NativeResume == "" || d.Verdict == VerdictSnooze {
		return ""
	}
	return "completed"
}

// PendingNativeResumes returns decisions whose Dagu human task has not been
// completed yet, oldest first.
func (tx *JobTx) PendingNativeResumes() []NativeResume {
	out := make([]NativeResume, 0, len(tx.Job.NativeResumes))
	for _, r := range tx.Job.NativeResumes {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, k int) bool { return out[i].Since.Before(out[k].Since) })
	return out
}

// MarkNativeResumed records that the Dagu human task for decisionID was
// completed. It works after the proposal left the aggregate and is a no-op
// when already recorded.
func (tx *JobTx) MarkNativeResumed(decisionID string) error {
	if _, ok := tx.Job.NativeResumes[decisionID]; !ok {
		return nil
	}
	delete(tx.Job.NativeResumes, decisionID)
	if p := tx.Job.Proposals; p != nil {
		for _, prop := range p {
			if prop.Decision != nil && prop.Decision.DecisionID == decisionID {
				prop.Decision.NativeResume = "completed"
			}
		}
	}
	tx.touch()
	return nil
}

// EffectRequest asks to perform one attempt of a follow-up action. Exactly
// one of Approved or Routine is set.
type EffectRequest struct {
	ActionID      string
	JobVersion    int
	PackageDigest string
	Approved      *ApprovedEffect
	Routine       *RoutineEffect
}

// ApprovedEffect is an action authorized by a human approval, performed
// under a live execution claim.
type ApprovedEffect struct {
	ProposalID string
	DecisionID string
	ClaimID    string
	Fence      int64
}

// RoutineEffect is an action the job's saved policy permits without approval.
type RoutineEffect struct {
	ReviewID string
	ClaimID  string
	Fence    int64
	Spec     ActionSpec
}

const defaultActionTimeout = 15 * time.Minute

// Authorize is the pre-effect guard. In one commit it checks lifecycle, job
// version, package, binding and claim, and records the action as executing
// under a grant that expires after the action's timeout. A retirement
// committed before the grant refuses it; one committed after lists the
// action as in flight. The effect itself is never retracted, so an unsettled
// grant becomes uncertain on expiry and is reconciled, never re-run.
func (tx *JobTx) Authorize(req EffectRequest) (*Grant, error) {
	j := tx.Job
	if (req.Approved == nil) == (req.Routine == nil) {
		return nil, refuse(CodeInvalid, "exactly one of approved or routine is required")
	}
	if j.Registration.State != RegistrationReady {
		return nil, refuse(CodeNotReady, "job registration is %s", j.Registration.State)
	}
	if !j.Lifecycle.AcceptsEffects() {
		return nil, &Error{Code: CodeLifecycle, Message: "job is " + string(j.Lifecycle), Current: j}
	}
	if req.JobVersion != j.Version || req.PackageDigest != j.PackageDigest {
		return nil, &Error{Code: CodeStaleBinding, Message: fmt.Sprintf("job is at version %d package %s", j.Version, j.PackageDigest), Current: j}
	}
	v, err := tx.CurrentVersion()
	if err != nil {
		return nil, err
	}

	var a *Action
	switch {
	case req.Routine != nil:
		a, err = tx.routineAction(v, req)
	default:
		a, err = tx.approvedAction(v, req)
	}
	if err != nil {
		return nil, err
	}

	if cur, ok := j.Actions[a.ActionID]; ok {
		if (cur.State != ActionFailed && cur.State != ActionNotApplied) || cur.Attempt >= cur.MaxAttempts {
			return nil, &Error{Code: CodeActionExists, Message: "action " + a.ActionID + " is " + string(cur.State), Current: cur}
		}
		// A retry keeps the version, binding and policy of the first attempt;
		// the same intent under another version is a new episode.
		if cur.JobVersion != a.JobVersion || cur.BindingDigest != a.BindingDigest {
			return nil, &Error{Code: CodeStaleBinding, Message: fmt.Sprintf("action %s was attempted under version %d; start a new episode", a.ActionID, cur.JobVersion), Current: cur}
		}
		a = cur
		a.ClaimID = claimOf(req)
	} else {
		a.Created = Stamp{At: tx.now, By: tx.actor}
		if j.Actions == nil {
			j.Actions = map[string]*Action{}
		}
		j.Actions[a.ActionID] = a
	}
	a.Attempt++
	timeout := defaultActionTimeout
	if pa, ok := v.PermittedAction(a.Spec.Name); ok && pa.TimeoutSec > 0 {
		timeout = time.Duration(pa.TimeoutSec) * time.Second
	}
	grantID, err := DerivedID(PrefixGrant, a.ActionID, a.Attempt)
	if err != nil {
		return nil, err
	}
	a.Grant = &Grant{GrantID: grantID, ActionID: a.ActionID, Attempt: a.Attempt, ExpiresAt: tx.now.Add(timeout)}
	a.State = ActionExecuting
	a.Receipt = ""
	a.Outcome = nil
	a.Updated = Stamp{At: tx.now, By: tx.actor}
	tx.touch()
	g := *a.Grant
	return &g, nil
}

func maxAttempts(v *JobVersion, pa PermittedAction) int {
	switch {
	case pa.MaxAttempts > 0:
		return pa.MaxAttempts
	case v.ReviewPolicy.MaxAttempts > 0:
		return v.ReviewPolicy.MaxAttempts
	}
	return 1
}

func (tx *JobTx) routineAction(v *JobVersion, req EffectRequest) (*Action, error) {
	j := tx.Job
	r := req.Routine
	if err := tx.CheckClaim(r.ClaimID, r.Fence, ClaimReview); err != nil {
		return nil, err
	}
	episode, err := ReviewID(j.JobID, j.Checkpoint.Version)
	if err != nil {
		return nil, err
	}
	if r.ReviewID != episode {
		return nil, refuse(CodeClaimStale, "review %s is not the current episode %s", r.ReviewID, episode)
	}
	pa, ok := v.PermittedAction(r.Spec.Name)
	if !ok || !pa.Routine {
		return nil, refuse(CodeNotPermitted, "action %q is not a routine action of version %d", r.Spec.Name, v.Version)
	}
	want, err := RoutineActionID(r.ReviewID, r.Spec)
	if err != nil {
		return nil, err
	}
	if req.ActionID != want {
		return nil, refuse(CodeInvalid, "routine action id must be %s", want)
	}
	binding, err := BindingDigest(j, r.Spec)
	if err != nil {
		return nil, err
	}
	return &Action{
		ActionID:      want,
		Kind:          ActionRoutine,
		JobVersion:    j.Version,
		ReviewID:      r.ReviewID,
		ClaimID:       r.ClaimID,
		ReadOnly:      pa.Idempotency == IdempotencyReadOnly,
		Spec:          r.Spec,
		BindingDigest: binding,
		MaxAttempts:   maxAttempts(v, pa),
	}, nil
}

func (tx *JobTx) approvedAction(v *JobVersion, req EffectRequest) (*Action, error) {
	j := tx.Job
	ap := req.Approved
	if err := tx.CheckClaim(ap.ClaimID, ap.Fence, ClaimExecution); err != nil {
		return nil, err
	}
	p, ok := j.Proposals[ap.ProposalID]
	if !ok {
		return nil, refuse(CodeProposalState, "proposal %s is not open", ap.ProposalID)
	}
	d := p.Decision
	if p.State != ProposalDecided || d == nil || d.Verdict != VerdictApprove || d.DecisionID != ap.DecisionID {
		return nil, &Error{Code: CodeStaleBinding, Message: "decision " + ap.DecisionID + " is not the approval of this proposal", Current: p}
	}
	current, err := BindingDigest(j, p.Action)
	if err != nil {
		return nil, err
	}
	if d.BindingDigest != current || p.BindingDigest != current {
		return nil, &Error{Code: CodeStaleBinding, Message: "approval binding does not match the current job and action", Current: p}
	}
	want, err := ApprovedActionID(ap.ProposalID, ap.DecisionID)
	if err != nil {
		return nil, err
	}
	if req.ActionID != want {
		return nil, refuse(CodeInvalid, "approved action id must be %s", want)
	}
	pa, _ := v.PermittedAction(p.Action.Name)
	return &Action{
		ActionID:      want,
		Kind:          ActionApproved,
		JobVersion:    j.Version,
		ClaimID:       ap.ClaimID,
		ReadOnly:      pa.Idempotency == IdempotencyReadOnly,
		ReviewID:      p.ReviewID,
		ProposalID:    p.ProposalID,
		DecisionID:    d.DecisionID,
		Spec:          p.Action,
		BindingDigest: current,
		MaxAttempts:   maxAttempts(v, pa),
	}, nil
}

func claimOf(req EffectRequest) string {
	if req.Routine != nil {
		return req.Routine.ClaimID
	}
	return req.Approved.ClaimID
}

// Settlement reports the outcome of a granted attempt.
type Settlement struct {
	ActionID string
	GrantID  string
	// ClaimID and Fence name the caller's live claim, of any kind. It may be
	// a later claim than the one the attempt ran under: that is how a
	// reconciler settles an interrupted action.
	ClaimID string
	Fence   int64
	State   ActionState
	Receipt string
	Outcome json.RawMessage
}

// SettleAction records an attempt's outcome. The caller must hold the
// job's live claim and present the action's current grant; possessing the
// action ID is not enough. A reconcile claim can settle after retirement so
// that in-flight outcomes are never lost.
func (tx *JobTx) SettleAction(s Settlement) (*Action, error) {
	j := tx.Job
	if err := tx.CheckClaim(s.ClaimID, s.Fence); err != nil {
		return nil, err
	}
	a, ok := j.Actions[s.ActionID]
	if !ok {
		return nil, refuse(CodeNotFound, "action %s is not in flight", s.ActionID)
	}
	if a.Grant == nil || a.Grant.GrantID != s.GrantID {
		return nil, &Error{Code: CodeGrantInvalid, Message: "grant " + s.GrantID + " is not the action's current grant", Current: a}
	}
	allowed := false
	switch a.State {
	case ActionExecuting:
		allowed = s.State == ActionSucceeded || s.State == ActionFailed || s.State == ActionUncertain || s.State == ActionNotApplied
	case ActionUncertain:
		allowed = s.State == ActionSucceeded || s.State == ActionNotApplied || s.State == ActionEscalated
	case ActionSucceeded, ActionFailed, ActionNotApplied, ActionEscalated:
	}
	if !allowed {
		return nil, &Error{Code: CodeActionState, Message: fmt.Sprintf("cannot settle %s action as %s", a.State, s.State), Current: a}
	}
	if s.State == ActionSucceeded && s.Receipt == "" {
		return nil, refuse(CodeInvalid, "succeeded needs a receipt")
	}
	a.State = s.State
	a.Receipt = s.Receipt
	a.Outcome = s.Outcome
	a.SettledUnderClaim = s.ClaimID
	a.Updated = Stamp{At: tx.now, By: tx.actor}
	out := *a
	if a.Kind == ActionApproved && a.State == ActionSucceeded {
		if p := j.Proposals[a.ProposalID]; p != nil {
			p.State = ProposalExecuted
			p.Revision++
			p.Updated = a.Updated
			if err := tx.archiveProposal(p); err != nil {
				return nil, err
			}
		}
		if err := tx.archiveAction(a); err != nil {
			return nil, err
		}
	}
	if a.State == ActionEscalated {
		id, err := NewID(PrefixException, tx.now)
		if err != nil {
			return nil, err
		}
		if j.Exceptions == nil {
			j.Exceptions = map[string]*Exception{}
		}
		j.Exceptions[id] = &Exception{ExceptionID: id, Kind: "action_escalated", Detail: "outcome of " + a.ActionID + " could not be reconciled", Evidence: []string{a.ActionID}, Created: a.Updated}
	}
	tx.touch()
	return &out, nil
}

// sweep applies time-based transitions before a transaction runs: an
// executing action whose grant expired is interrupted.
func (tx *JobTx) sweep() {
	for _, a := range tx.Job.Actions {
		if a.State == ActionExecuting && a.Grant != nil && !tx.now.Before(a.Grant.ExpiresAt) {
			tx.interrupt(a)
		}
	}
}
