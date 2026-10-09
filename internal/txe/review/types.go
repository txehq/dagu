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

import (
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

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
	Kind string `json:"kind"`
	// StableID is the one string that names this target: what an action
	// gives as its target_id. It is opaque, and distinct for every
	// registered target.
	StableID string `json:"stable_id"`
	// Identity is the target's stable identity as it was registered, for
	// reading. It is never matched against.
	Identity    map[string]string `json:"identity,omitempty"`
	Environment string            `json:"environment,omitempty"`
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

const (
	// RetryRunAction is the reserved action that re-runs one exact run of
	// the job through the service. It is never routine and never declared by
	// a job: only the owner's decision on a proposal carrying it runs it.
	RetryRunAction = registry.ActionRetryRun
	// RetryRunParam names the run to retry. It is the only parameter the
	// agent gives; the reviewer adds the other two from what it was shown.
	RetryRunParam = "run_id"
	// RetryRunSpecParam is the digest of the DAG snapshot the run ran, and
	// RetryRunPackageParam the package the job had when the reviewer looked.
	// The registry refuses the proposal, and later its execution, when
	// either is no longer the job's current one.
	RetryRunSpecParam    = "run_spec_sha256"
	RetryRunPackageParam = "package_digest"
	// RetryRunAttemptParam and RetryRunQueuedParam name the failed
	// execution being retried: its attempt and when that attempt was
	// queued. A native retry keeps the run id, so this is what makes one
	// retry decision mean one execution: the retry is dispatched only while
	// that execution is still the run's latest.
	RetryRunAttemptParam = "attempt_id"
	RetryRunQueuedParam  = "queued_at"
	// UncertainEffectAction is the reserved action name of a proposal that
	// asks the owner about an effect whose outcome is unknown. It is not
	// executable.
	UncertainEffectAction = registry.ActionUncertainEffect
	// UncertainEffectParam names the journaled action in question, and
	// UncertainAttemptParam the attempt of it whose outcome is unknown.
	UncertainEffectParam  = "action_id"
	UncertainAttemptParam = "attempt"
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
	ID            string `json:"job_id"`
	OwnerID       string `json:"owner_id"`
	ProjectID     string `json:"project_id"`
	MachineID     string `json:"machine_id"`
	Version       int    `json:"version"`
	PackageDigest string `json:"package_digest"`
	// DAGSpecSHA256 is the digest of the job's current DAG. A run with
	// another digest ran an older version.
	DAGSpecSHA256    string       `json:"dag_spec_sha256,omitempty"`
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
	// CredentialRefs are the credentials the job declares: where each is
	// found on the job's machine and the variable its commands read it
	// from. They are resolved on that machine when a command of the job is
	// started. They are removed from the copy of the job that goes into the
	// packet, so they are never part of what the review agent is shown.
	//
	// They are trusted input: whatever is here is read and handed to the
	// job's command. A Registry that fills them from a record another
	// party can change must first check them against what was authorized
	// on the job's machine when the job was registered, and leave out, or
	// refuse the job over, any that differ. The effector does not check.
	CredentialRefs []CredentialRef `json:"credential_refs,omitempty"`
}

// CredentialRef names a credential a job declares. The locator is a path or
// a variable name on the job's machine, never a value.
type CredentialRef struct {
	// Name is the variable the job's command reads the credential from.
	Name string `json:"name"`
	// Kind is CredentialFile or CredentialEnv.
	Kind string `json:"kind"`
	// Locator is the file's path, or the name of the variable to copy.
	Locator string `json:"locator"`
}

// What the service recorded about a failed execution's preparation.
const (
	PreparationAbandoned = "abandoned_before_dispatch"
	PreparationUnknown   = "unknown"
)

// The kinds of credential reference.
const (
	CredentialFile = "file"
	CredentialEnv  = "env"
)

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
	// AcquiredAt is when the registry gave the claim, by its own clock.
	AcquiredAt time.Time `json:"acquired_at,omitzero"`
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
	RunID      string `json:"run_id"`
	JobVersion int    `json:"job_version"`
	// SpecSHA256 is the digest of the DAG snapshot the run ran.
	SpecSHA256 string `json:"spec_sha256,omitempty"`
	// AttemptID and QueuedAt identify the run's latest execution, the one
	// this evidence is of.
	AttemptID string `json:"attempt_id,omitempty"`
	QueuedAt  string `json:"queued_at,omitempty"`
	// Preparation says what the service recorded about whether this
	// execution was ever handed to a worker, for a run that failed:
	// PreparationAbandoned when the service recorded that it was created and
	// never dispatched, so nothing of the job ran; PreparationUnknown when
	// the service could not say. Empty when the run is not a failed one, or
	// the service's records show no abandonment of this execution.
	Preparation string `json:"preparation,omitempty"`
	// EvidenceTrimmed is true when this run's evidence was shortened to fit
	// the packet: steps left out, or step output cut to its end.
	EvidenceTrimmed bool `json:"evidence_trimmed,omitempty"`
	// OmittedSteps counts, by status, the steps of this run that are not in
	// Steps. What was left out is always stated, so a step that did not
	// succeed is never missing without the evidence saying so.
	OmittedSteps map[string]int `json:"omitted_steps,omitempty"`
	// Cursor is the checkpoint's run cursor once this run, and every run
	// listed before it, has been covered, for a registry that keeps its
	// place in the run history that way. A run without one is its own
	// cursor.
	Cursor     string            `json:"-"`
	Status     string            `json:"status"`
	StartedAt  time.Time         `json:"started_at,omitzero"`
	FinishedAt time.Time         `json:"finished_at,omitzero"`
	Outputs    map[string]string `json:"outputs,omitempty"`
	Artifacts  []string          `json:"artifacts,omitempty"`
	Error      string            `json:"error,omitempty"` // Steps carry the end of each step's own output, which is where a
	// script's result usually is.
	Steps []StepEvidence `json:"steps,omitempty"`
}

// outputTruncated reports whether any step of the run printed more than the
// evidence shows.
func (r RunEvidence) outputTruncated() bool {
	for _, s := range r.Steps {
		if s.Truncated {
			return true
		}
	}
	return false
}

// Execution is the execution of the run this evidence is of.
func (r RunEvidence) Execution() Execution {
	return Execution{AttemptID: r.AttemptID, QueuedAt: r.QueuedAt}
}

// StepEvidence is one step of a finished run.
type StepEvidence struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Stdout string `json:"stdout_tail,omitempty"`
	Stderr string `json:"stderr_tail,omitempty"`
	// Truncated is true when the step printed more than is shown here.
	Truncated bool `json:"truncated,omitempty"`
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
	// Admitted is true when the destination accepted the request for this
	// action's effect and only the result was not seen.
	Admitted bool `json:"admitted,omitempty"`
	// AdmittedRef is the execution the destination said it admitted the
	// request as, when it names one. Only that execution is then this
	// action's effect.
	AdmittedRef string `json:"admitted_execution,omitempty"`
	// MaxAttempts is how many attempts the registry allows this action, when
	// it says; zero when it does not.
	MaxAttempts int `json:"max_attempts,omitempty"`
	// AttemptStartedAt is when the registry granted the current attempt of
	// the action, by the registry's clock.
	AttemptStartedAt time.Time `json:"attempt_started_at,omitzero"`
	// Attempt is the registry's count of attempts of this action. An
	// owner's answer about an unknown outcome is about one attempt.
	Attempt int `json:"attempt,omitempty"`
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
	// CoveredExecutions names each covered run with the execution of it
	// that was shown, as "run@execution": a retried run keeps its id, so
	// the id alone does not say which result a review saw. These names, in
	// the job's recorded reviews, are the record of what has been covered:
	// a result is shown to a review until a recorded review names it.
	CoveredExecutions []string `json:"covered_executions,omitempty"`
	// TrimmedExecutions are the covered executions whose evidence had been
	// shortened to fit when the review was shown them. They are covered,
	// and the record says on what: a job cannot have a result reviewed on
	// part of its evidence without that being on the record.
	TrimmedExecutions []string `json:"trimmed_executions,omitempty"`
	// RunCursor is the checkpoint's run cursor after this review.
	RunCursor   string   `json:"run_cursor,omitempty"`
	ActionIDs   []string `json:"action_ids,omitempty"`
	ProposalIDs []string `json:"proposal_ids,omitempty"`
	Notes       []string `json:"notes,omitempty"`
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
	// ExceptionContextTooLarge means the job's context does not fit a review
	// packet, so it is not being reviewed.
	ExceptionContextTooLarge ExceptionKind = "review_context_too_large"
	// ExceptionCleanupFailed means a superseded proposal's decision run
	// could not be closed after repeated attempts.
	ExceptionCleanupFailed ExceptionKind = "decision_run_cleanup_failed"
	// ExceptionUnavailable means the reviewer judged the job's target or
	// credentials unavailable. It is not a retirement.
	ExceptionUnavailable ExceptionKind = "target_unavailable"
	// ExceptionRetryStalled means a retry the service admitted has stayed a
	// reservation: its execution exists and no worker has started it. It
	// is about one attempt of one action, which stays uncertain and keeps
	// being probed; the registry resolves the exception when that attempt
	// is settled.
	ExceptionRetryStalled ExceptionKind = "retry_reservation_stalled"
)

// Exception is an actionable condition surfaced on the dashboard.
type Exception struct {
	JobID     string        `json:"job_id"`
	Kind      ExceptionKind `json:"kind"`
	MachineID string        `json:"machine_id"`
	Message   string        `json:"message"`
	ReviewID  string        `json:"review_id,omitempty"`
	// ActionID and Attempt name the action attempt an exception is about.
	// Such an exception is open once per attempt, however often it is
	// raised, and does not change the job's or the reviewer's availability.
	ActionID string `json:"action_id,omitempty"`
	Attempt  int    `json:"attempt,omitempty"`
	// Claim is the live claim an action's exception is raised under. It
	// is not part of the record.
	Claim Claim `json:"-"`
	// ResolvedAt is set by the registry when the condition is over.
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// LocalFile is a reference to a file kept on one machine. The digest lets a
// later inventory tell the same bytes from a different file at the path.
type LocalFile struct {
	MachineID string `json:"machine_id"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
}
