// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

// Package review runs bounded, fresh periodic reviews of registered TXE jobs.
//
// A review is three separate steps of one DAG run on the job's machine:
// Prepare claims the job and builds a context packet, an agent CLI turns the
// packet into one structured decision, and Apply turns that decision into
// journaled effects and proposals. The agent holds no authority: only actions
// the job's saved policy declares can run, and everything else waits for a
// human decision.
package review

import "time"

// Lifecycle is the registry's job lifecycle state.
type Lifecycle string

const (
	LifecycleActive     Lifecycle = "active"
	LifecyclePaused     Lifecycle = "paused"
	LifecycleNeedsHuman Lifecycle = "needs_human"
	LifecycleCompleted  Lifecycle = "completed"
	LifecycleRetired    Lifecycle = "retired"
)

// Reviewable reports whether a reviewer may still act on a job. A completed
// or retired job is never reactivated by a review.
func (l Lifecycle) Reviewable() bool {
	return l == LifecycleActive || l == LifecycleNeedsHuman
}

// Availability is independent of lifecycle: an offline machine or an expired
// login is never evidence that a job should retire.
type Availability string

const (
	AvailabilityReady             Availability = "ready"
	AvailabilityWorkerOffline     Availability = "worker_offline"
	AvailabilityAuthRequired      Availability = "auth_required"
	AvailabilityTargetUnreachable Availability = "target_unreachable"
	AvailabilityStale             Availability = "stale"
)

// Target is an external resource a job depends on, named by stable identity.
type Target struct {
	Kind        string `json:"kind"`
	StableID    string `json:"stable_id"`
	Environment string `json:"environment,omitempty"`
}

// Idempotency describes what the action's destination guarantees.
type Idempotency string

const (
	// IdempotencyReadOnly means the action has no external effect, such as
	// a diagnostic. Its failures are never uncertain.
	IdempotencyReadOnly Idempotency = "read_only"
	// IdempotencyKeyed means the destination deduplicates on the key passed
	// in TXE_IDEMPOTENCY_KEY. The key is per attempt, so it makes a repeat
	// of the same attempt safe; it says nothing about whether a failed
	// attempt took effect.
	IdempotencyKeyed Idempotency = "keyed"
	// IdempotencyNone means a repeat may repeat the external effect.
	IdempotencyNone Idempotency = "none"
)

// DeclaredAction is an executable follow-up saved with the job. The reviewer
// runs nothing that is not declared here.
type DeclaredAction struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Routine actions run without a per-run human decision. Any other
	// declared action runs only after an approve decision bound to it.
	Routine     bool        `json:"routine"`
	Command     []string    `json:"command"`
	Params      []string    `json:"params,omitempty"`
	Idempotency Idempotency `json:"idempotency"`
	// Reconcile is an optional probe run when an earlier attempt's outcome
	// is unknown. Exit 0 means the effect was applied, exit 3 means it was
	// not, and anything else leaves the action uncertain.
	Reconcile  []string `json:"reconcile,omitempty"`
	TimeoutSec int      `json:"timeout_sec,omitempty"`
}

// ReviewPolicy is the saved review contract of a job.
type ReviewPolicy struct {
	Brief                   string           `json:"brief"`
	CadenceSec              int              `json:"cadence_sec"`
	MaxAttempts             int              `json:"max_attempts"`
	Actions                 []DeclaredAction `json:"actions,omitempty"`
	HumanDecisionConditions []string         `json:"human_decision_conditions,omitempty"`
}

// Action returns the declared action with the given name.
func (p ReviewPolicy) Action(name string) (DeclaredAction, bool) {
	for _, a := range p.Actions {
		if a.Name == name {
			return a, true
		}
	}
	return DeclaredAction{}, false
}

// Job is the reviewer's read view of a registered job.
type Job struct {
	ID               string       `json:"job_id"`
	OwnerID          string       `json:"owner_id"`
	ProjectID        string       `json:"project_id"`
	MachineID        string       `json:"machine_id"`
	Version          int          `json:"version"`
	PackageDigest    string       `json:"package_digest"`
	WorkingDir       string       `json:"working_dir"`
	Title            string       `json:"title"`
	Purpose          string       `json:"purpose"`
	Targets          []Target     `json:"targets"`
	ExpectedOutcomes []string     `json:"expected_outcomes"`
	Deliverables     []string     `json:"deliverables"`
	RetirementRules  []string     `json:"retirement_rules"`
	Lifecycle        Lifecycle    `json:"lifecycle"`
	Availability     Availability `json:"availability"`
	Review           ReviewPolicy `json:"review"`
}

// HasTarget reports whether the job depends on the given stable identity.
func (j Job) HasTarget(stableID string) bool {
	for _, t := range j.Targets {
		if t.StableID == stableID {
			return true
		}
	}
	return false
}

// ClaimKind says what the holder of a job's single claim slot may do.
type ClaimKind string

const (
	// ClaimReview allows a review: routine actions, proposals, checkpoint.
	ClaimReview ClaimKind = "review"
	// ClaimExecution allows the one effect of an approved proposal.
	ClaimExecution ClaimKind = "execution"
	// ClaimReconcile allows only settling actions whose outcome is open. It
	// is the only kind granted on a completed or retired job.
	ClaimReconcile ClaimKind = "reconcile"
)

// Claim is a per-job exclusive lease. Fence increases on every grant, and
// every claim-scoped write carries it, so a late write from a reviewer whose
// claim expired is refused instead of overwriting newer state.
type Claim struct {
	ID        string    `json:"claim_id"`
	JobID     string    `json:"job_id"`
	Kind      ClaimKind `json:"kind"`
	Holder    string    `json:"holder"`
	Fence     int       `json:"fence"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Checkpoint records how far reviews of a job have durably progressed.
type Checkpoint struct {
	JobID string `json:"job_id"`
	// Version is the review episode: it changes only when a review's
	// decisions and effects were persisted.
	Version        int       `json:"version"`
	RunCursor      string    `json:"run_cursor,omitempty"`
	DecisionCursor string    `json:"decision_cursor,omitempty"`
	LastReviewID   string    `json:"last_review_id,omitempty"`
	NextReviewAt   time.Time `json:"next_review_at,omitzero"`
}

// RunEvidence is one finished run of the job's own script.
type RunEvidence struct {
	RunID      string            `json:"run_id"`
	JobVersion int               `json:"job_version"`
	Status     string            `json:"status"`
	StartedAt  time.Time         `json:"started_at,omitzero"`
	FinishedAt time.Time         `json:"finished_at,omitzero"`
	Outputs    map[string]string `json:"outputs,omitempty"`
	Artifacts  []string          `json:"artifacts,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// ActionState is the journal state of one follow-up action.
type ActionState string

const (
	// ActionExecuting is written before the effect is attempted.
	ActionExecuting ActionState = "executing"
	// ActionSucceeded is written only with the effect's receipt.
	ActionSucceeded ActionState = "succeeded"
	// ActionFailed means the action itself reported that it did not apply.
	ActionFailed ActionState = "failed"
	// ActionUncertain means the effect may or may not have happened.
	ActionUncertain ActionState = "uncertain"
	// ActionNotApplied means reconciliation proved the effect did not happen.
	ActionNotApplied ActionState = "not_applied"
	// ActionEscalated means a human was asked to resolve the uncertainty.
	ActionEscalated ActionState = "escalated"
)

// Open reports whether the action's external effect is still unresolved.
func (s ActionState) Open() bool {
	return s == ActionExecuting || s == ActionUncertain
}

// Action is one journaled follow-up.
type Action struct {
	ID         string            `json:"action_id"`
	JobID      string            `json:"job_id"`
	JobVersion int               `json:"job_version"`
	Name       string            `json:"name"`
	TargetID   string            `json:"target_id"`
	Params     map[string]string `json:"params,omitempty"`
	// IntentKey identifies the same intent across review episodes.
	IntentKey  string      `json:"intent_key"`
	ReviewID   string      `json:"review_id,omitempty"`
	ProposalID string      `json:"proposal_id,omitempty"`
	DecisionID string      `json:"decision_id,omitempty"`
	State      ActionState `json:"state"`
	Receipt    string      `json:"receipt,omitempty"`
	Detail     string      `json:"detail,omitempty"`
	// GrantID is the registry's authorization of this attempt; settling
	// the action requires it.
	GrantID string `json:"grant_id"`
	// GrantExpiresAt bounds the attempt: its holder must not start or
	// continue the effect after this time, and nobody else may conclude
	// anything about the attempt before it.
	GrantExpiresAt time.Time `json:"grant_expires_at,omitzero"`
	ClaimID        string    `json:"claim_id"`
	StartedAt      time.Time `json:"started_at,omitzero"`
	FinishedAt     time.Time `json:"finished_at,omitzero"`
}

// ProposalKind distinguishes what a human is being asked.
type ProposalKind string

const (
	// ProposalAction asks to authorize a declared action.
	ProposalAction ProposalKind = "action"
	// ProposalQuestion asks for guidance; approving it executes nothing.
	ProposalQuestion ProposalKind = "question"
	// ProposalUncertain asks how to settle an effect whose outcome is unknown.
	ProposalUncertain ProposalKind = "uncertain_effect"
)

// ProposalState mirrors the registry's proposal states.
type ProposalState string

const (
	ProposalOpen       ProposalState = "open"
	ProposalSnoozed    ProposalState = "snoozed"
	ProposalDecided    ProposalState = "decided"
	ProposalExecuted   ProposalState = "executed"
	ProposalRejected   ProposalState = "rejected"
	ProposalSuperseded ProposalState = "superseded"
)

// TaskLocator points at the native human task that carries a proposal.
type TaskLocator struct {
	DAG    string `json:"dag"`
	RunID  string `json:"run_id"`
	StepID string `json:"step_id"`
}

// Proposal is a request for a human decision. The registry computes the
// binding digest; the reviewer never hashes a binding itself.
type Proposal struct {
	ID            string            `json:"proposal_id"`
	JobID         string            `json:"job_id"`
	JobVersion    int               `json:"job_version"`
	PackageDigest string            `json:"package_digest"`
	Kind          ProposalKind      `json:"kind"`
	ActionName    string            `json:"action_name,omitempty"`
	TargetID      string            `json:"target_id,omitempty"`
	Params        map[string]string `json:"params,omitempty"`
	Question      string            `json:"question"`
	Rationale     string            `json:"rationale,omitempty"`
	EvidenceRuns  []string          `json:"evidence_run_ids,omitempty"`
	ArtifactRefs  []string          `json:"artifact_refs,omitempty"`
	ObservedAt    time.Time         `json:"observed_at,omitzero"`
	// WaitingOn is who must act next: person, agent, credentials or machine.
	WaitingOn       string        `json:"waiting_on"`
	AllowedVerdicts []Verdict     `json:"allowed_verdicts"`
	RelatedAction   string        `json:"related_action_id,omitempty"`
	ReviewID        string        `json:"review_id,omitempty"`
	BindingDigest   string        `json:"binding_digest,omitempty"`
	State           ProposalState `json:"state"`
	NativeTask      TaskLocator   `json:"native_task,omitzero"`
}

// Verdict is a human's answer to a proposal.
type Verdict string

const (
	VerdictApprove  Verdict = "approve"
	VerdictReject   Verdict = "reject"
	VerdictRedirect Verdict = "redirect"
	VerdictSnooze   Verdict = "snooze"
	VerdictRetry    Verdict = "retry"
	VerdictPause    Verdict = "pause"
	VerdictRetire   Verdict = "retire"
)

// Decision is an immutable human decision. The reviewer only reads it.
type Decision struct {
	ID            string    `json:"decision_id"`
	ProposalID    string    `json:"proposal_id"`
	JobID         string    `json:"job_id"`
	BindingDigest string    `json:"binding_digest,omitempty"`
	Verdict       Verdict   `json:"verdict"`
	Instructions  string    `json:"instructions,omitempty"`
	Actor         string    `json:"actor"`
	CreatedAt     time.Time `json:"created_at,omitzero"`
}

// Outcome is the single recorded result of a review.
type Outcome string

const (
	OutcomeContinue         Outcome = "continue"
	OutcomeAct              Outcome = "act"
	OutcomeWaitHuman        Outcome = "wait_human"
	OutcomePauseUnavailable Outcome = "pause_unavailable"
	OutcomeComplete         Outcome = "complete"
	OutcomeRetire           Outcome = "retire"
)

// Review is the durable record of one review episode.
type Review struct {
	ID           string   `json:"review_id"`
	JobID        string   `json:"job_id"`
	JobVersion   int      `json:"job_version"`
	Episode      int      `json:"episode"`
	Outcome      Outcome  `json:"outcome"`
	Reasoning    string   `json:"reasoning"`
	EvidenceRuns []string `json:"evidence_run_ids"`
	// CoveredRuns and CoveredDecisions are what the packet contained; the
	// checkpoint advances over exactly these and nothing newer.
	CoveredRuns      []string `json:"covered_run_ids"`
	CoveredDecisions []string `json:"covered_decision_ids"`
	ActionIDs        []string `json:"action_ids,omitempty"`
	ProposalIDs      []string `json:"proposal_ids,omitempty"`
	Notes            []string `json:"notes,omitempty"`
	// Handoff locates the prepared review (claim and packet) on the machine
	// that ran it. It is a reference to a local file, not a copy held by
	// the service: retrieving it needs that machine.
	Handoff LocalFile `json:"handoff,omitzero"`
	// PacketArtifact and DecisionArtifact name the run artifacts holding
	// the context the agent was given and the decision it returned.
	PacketArtifact   string `json:"packet_artifact,omitempty"`
	DecisionArtifact string `json:"decision_artifact,omitempty"`
	// PacketBytes is the size of the context the agent was given.
	PacketBytes int `json:"packet_bytes"`
	// AgentInputTokens and AgentOutputTokens are what the agent CLI reports
	// for the whole invocation, cached input included.
	AgentInputTokens  int       `json:"agent_input_tokens,omitempty"`
	AgentOutputTokens int       `json:"agent_output_tokens,omitempty"`
	Reviewer          string    `json:"reviewer"`
	AgentClient       string    `json:"agent_client,omitempty"`
	RecordedAt        time.Time `json:"recorded_at,omitzero"`
}

// ExceptionKind classifies a condition that needs local attention.
type ExceptionKind string

const (
	// ExceptionReviewerAuth means the agent CLI could not authenticate.
	ExceptionReviewerAuth ExceptionKind = "reviewer_authentication_required"
	// ExceptionReviewerFailed means the agent ran but produced no usable decision.
	ExceptionReviewerFailed ExceptionKind = "reviewer_failed"
	// ExceptionCleanupFailed means a superseded proposal's decision run
	// could not be closed after repeated attempts.
	ExceptionCleanupFailed ExceptionKind = "decision_run_cleanup_failed"
	// ExceptionUnavailable means the reviewer judged the job's target or
	// credentials unavailable. It is not a retirement.
	ExceptionUnavailable ExceptionKind = "target_unavailable"
)

// Exception is an actionable condition surfaced on the dashboard.
type Exception struct {
	JobID     string        `json:"job_id"`
	Kind      ExceptionKind `json:"kind"`
	MachineID string        `json:"machine_id"`
	Message   string        `json:"message"`
	ReviewID  string        `json:"review_id,omitempty"`
}

// LocalFile is a reference to a file kept on one machine. The digest lets a
// later inventory tell the same bytes from a different file at the path.
type LocalFile struct {
	MachineID string `json:"machine_id"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
}
