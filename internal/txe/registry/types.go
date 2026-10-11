// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"sort"
	"time"
)

// SchemaVersion is written into every stored record.
const SchemaVersion = 1

// ActorKind says what kind of party performed a write. Owner is never
// derived from an actor.
type ActorKind string

const (
	ActorHuman      ActorKind = "human"
	ActorAgent      ActorKind = "agent"
	ActorReviewer   ActorKind = "reviewer"
	ActorReconciler ActorKind = "reconciler"
	ActorSystem     ActorKind = "system"
	ActorCLI        ActorKind = "cli"
)

// Actor identifies who made a change: a person, a coding session, a reviewer
// run or the hub itself.
type Actor struct {
	Kind      ActorKind `json:"kind"`
	ID        string    `json:"id"`
	Session   string    `json:"session,omitempty"`
	MachineID string    `json:"machine_id,omitempty"`
	// Client is the client build and skill revision.
	Client string `json:"client,omitempty"`
}

// Stamp records when and by whom a record was created or last changed.
type Stamp struct {
	At time.Time `json:"at"`
	By Actor     `json:"by"`
}

// Owner is the stable opaque owner of jobs; its display name is not an identity.
type Owner struct {
	Schema      int    `json:"schema"`
	OwnerID     string `json:"owner_id"`
	DisplayName string `json:"display_name"`
	Provenance  string `json:"provenance,omitempty"`
	Created     Stamp  `json:"created"`
}

// Project groups jobs under one owner. Key is a stable natural key such as
// a normalized git remote; one key maps to one project per owner.
type Project struct {
	Schema    int    `json:"schema"`
	ProjectID string `json:"project_id"`
	OwnerID   string `json:"owner_id"`
	Key       string `json:"key,omitempty"`
	Name      string `json:"name"`
	Created   Stamp  `json:"created"`
}

// Machine is an execution machine; machine_id is also its Dagu worker ID.
type Machine struct {
	Schema      int    `json:"schema"`
	MachineID   string `json:"machine_id"`
	OwnerID     string `json:"owner_id"`
	DisplayName string `json:"display_name"`
	Created     Stamp  `json:"created"`
}

// ExistenceCheck says how a target's existence is observed.
type ExistenceCheck string

const (
	CheckPreRun    ExistenceCheck = "pre_run"
	CheckReconcile ExistenceCheck = "reconcile"
	CheckEventOnly ExistenceCheck = "event_only"
)

// Target is an external resource identified by kind and stable ID. The
// display name never identifies it: the same name with a different stable
// ID is a different resource.
type Target struct {
	Kind           string            `json:"kind"`
	Environment    string            `json:"environment,omitempty"`
	StableID       map[string]string `json:"stable_id"`
	DisplayName    string            `json:"display_name,omitempty"`
	ExistenceCheck ExistenceCheck    `json:"existence_check,omitempty"`
}

// Origin records where a job came from. It is context, not ownership.
type Origin struct {
	Repo         string `json:"repo,omitempty"`
	Commit       string `json:"commit,omitempty"`
	Session      string `json:"session,omitempty"`
	WorktreePath string `json:"worktree_path,omitempty"`
	ChatRef      string `json:"chat_ref,omitempty"`
}

// CredentialRef names a credential resolved on the assigned machine. Locator
// is a file path or variable name, never a value.
type CredentialRef struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // file | env
	Locator string `json:"locator"`
}

// Package describes the durable execution package on the assigned machine.
type Package struct {
	Digest         string          `json:"digest"`
	Path           string          `json:"path"`
	Entrypoint     string          `json:"entrypoint"`
	WorkingDir     string          `json:"working_dir,omitempty"`
	Runtime        []string        `json:"runtime,omitempty"`
	CredentialRefs []CredentialRef `json:"credential_refs,omitempty"`
}

// DAGRef binds a job version to its Dagu DAG, which is named by the job ID.
// Spec is the YAML the registry saved; the registry is the only writer of a
// job's DAG file.
type DAGRef struct {
	Name       string `json:"name"`
	Spec       string `json:"spec"`
	SpecSHA256 string `json:"spec_sha256"`
}

// Schedule mirrors the DAG schedule for review context; Dagu remains the
// scheduling authority.
type Schedule struct {
	Cron       string `json:"cron,omitempty"`
	Timezone   string `json:"timezone,omitempty"`
	Overlap    string `json:"overlap,omitempty"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
	Retry      int    `json:"retry,omitempty"`
	MissedRun  string `json:"missed_run,omitempty"`
}

// Deliverable is one file a run is expected to produce, named so a run's
// manifest can report it.
type Deliverable struct {
	Name string `json:"name"`
	// Path is the exact file, relative to the run's output directory.
	Path        string `json:"path"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
	// Delivery is machine (the default) or hub.
	Delivery string `json:"delivery,omitempty"`
	// Required makes a run that does not produce it need a person.
	Required bool `json:"required,omitempty"`
}

// ExpectedOutcome states what success means and when the job is finished.
type ExpectedOutcome struct {
	SuccessCriteria []string      `json:"success_criteria,omitempty"`
	Deliverables    []Deliverable `json:"deliverables,omitempty"`
}

// Lifetime bounds a job in time.
type Lifetime struct {
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Rule values for RetirementRules.
const (
	RuleRetire = "retire"
	RuleReview = "review"
	RuleKeep   = "keep"
)

// ActiveRunPolicy says what happens to a run that is executing when its job
// retires.
type ActiveRunPolicy string

const (
	ActiveRunFinish ActiveRunPolicy = "finish"
	ActiveRunCancel ActiveRunPolicy = "cancel"
)

// RetirementRules are the job's stopping rules.
type RetirementRules struct {
	OnTargetDeleted string          `json:"on_target_deleted,omitempty"`
	OnReplacement   string          `json:"on_replacement,omitempty"`
	OnCompletion    string          `json:"on_completion,omitempty"`
	ActiveRunPolicy ActiveRunPolicy `json:"active_run_policy,omitempty"`
}

// Idempotency classes for PermittedAction. A read_only action has no
// external effect by the creator's saved declaration, so an interrupted
// attempt is failed rather than uncertain.
const (
	IdempotencyKeyed    = "keyed"
	IdempotencyNone     = "none"
	IdempotencyReadOnly = "read_only"
)

// PermittedAction is a follow-up the reviewer may take. Routine actions run
// without a human decision; others are proposed.
type PermittedAction struct {
	Name        string          `json:"name"`
	Command     string          `json:"command,omitempty"`
	Entrypoint  string          `json:"entrypoint,omitempty"`
	ParamSchema json.RawMessage `json:"param_schema,omitempty"`
	Idempotency string          `json:"idempotency,omitempty"`
	Reconcile   string          `json:"reconcile,omitempty"`
	TimeoutSec  int             `json:"timeout_sec"`
	Routine     bool            `json:"routine"`
	MaxAttempts int             `json:"max_attempts,omitempty"`
}

// ReviewPolicy is the brief and bounds for periodic review.
type ReviewPolicy struct {
	Cadence                 string            `json:"cadence,omitempty"`
	MaxDurationSec          int               `json:"max_duration_sec,omitempty"`
	MaxAttempts             int               `json:"max_attempts,omitempty"`
	Brief                   string            `json:"brief,omitempty"`
	PermittedActions        []PermittedAction `json:"permitted_actions,omitempty"`
	HumanDecisionConditions []string          `json:"human_decision_conditions,omitempty"`
}

// JobVersion is an immutable snapshot of a job's context. A change creates a
// new version.
type JobVersion struct {
	Schema          int             `json:"schema"`
	JobID           string          `json:"job_id"`
	OwnerID         string          `json:"owner_id"`
	Version         int             `json:"version"`
	Title           string          `json:"title"`
	Purpose         string          `json:"purpose"`
	Origin          Origin          `json:"origin"`
	Package         Package         `json:"package"`
	DAG             DAGRef          `json:"dag"`
	Schedule        Schedule        `json:"schedule"`
	Targets         []Target        `json:"targets,omitempty"`
	ExpectedOutcome ExpectedOutcome `json:"expected_outcome"`
	Lifetime        Lifetime        `json:"lifetime"`
	RetirementRules RetirementRules `json:"retirement_rules"`
	ReviewPolicy    ReviewPolicy    `json:"review_policy"`
	Created         Stamp           `json:"created"`
	Prev            string          `json:"prev,omitempty"`
}

// PermittedAction returns the named action from the version's review policy.
func (v *JobVersion) PermittedAction(name string) (PermittedAction, bool) {
	for _, a := range v.ReviewPolicy.PermittedActions {
		if a.Name == name {
			return a, true
		}
	}
	return PermittedAction{}, false
}

// Lifecycle is the job's purpose-level state, separate from run status and
// machine availability.
type Lifecycle string

const (
	LifecycleActive     Lifecycle = "active"
	LifecyclePaused     Lifecycle = "paused"
	LifecycleNeedsHuman Lifecycle = "needs_human"
	LifecycleCompleted  Lifecycle = "completed"
	LifecycleRetired    Lifecycle = "retired"
)

// Terminal reports whether only an explicit human reactivation can leave l.
func (l Lifecycle) Terminal() bool {
	return l == LifecycleCompleted || l == LifecycleRetired
}

// AcceptsEffects reports whether follow-up effects may be authorized in l.
func (l Lifecycle) AcceptsEffects() bool {
	return l == LifecycleActive || l == LifecycleNeedsHuman
}

// AvailabilityState describes whether the job can currently execute. It
// never implies anything about the target's existence.
type AvailabilityState string

const (
	AvailabilityReady             AvailabilityState = "ready"
	AvailabilityWorkerOffline     AvailabilityState = "worker_offline"
	AvailabilityAuthRequired      AvailabilityState = "auth_required"
	AvailabilityTargetUnreachable AvailabilityState = "target_unreachable"
	// AvailabilityTargetUnconfirmed: a target checked before each run could
	// be neither confirmed nor denied (an unknown observation).
	AvailabilityTargetUnconfirmed AvailabilityState = "target_unconfirmed"
	AvailabilityStale             AvailabilityState = "stale"
)

// Availability is the latest execution-availability observation.
type Availability struct {
	State      AvailabilityState `json:"state"`
	Detail     string            `json:"detail,omitempty"`
	Evidence   []string          `json:"evidence,omitempty"`
	ObservedAt *time.Time        `json:"observed_at,omitempty"`
	Reporter   *Actor            `json:"reporter,omitempty"`
}

// RetirementReason distinguishes why a job stopped.
type RetirementReason string

const (
	RetireCompleted     RetirementReason = "completed"
	RetireExpired       RetirementReason = "expired"
	RetireManual        RetirementReason = "manual"
	RetireTargetDeleted RetirementReason = "target_deleted"
	RetireReplaced      RetirementReason = "replaced"
)

// Affected records what happened to one piece of in-flight work when the
// job's lifecycle changed.
type Affected struct {
	RunID       string `json:"run_id,omitempty"`
	ActionID    string `json:"action_id,omitempty"`
	ProposalID  string `json:"proposal_id,omitempty"`
	Disposition string `json:"disposition"`
}

// Dispositions for Affected.
const (
	DispositionSuperseded        = "superseded"
	DispositionInFlightReconcile = "in_flight_reconcile"
	DispositionQueuedDropped     = "queued_dropped"
	DispositionAllowedToFinish   = "allowed_to_finish"
	DispositionCancelRequested   = "cancel_requested"
	DispositionStopRequested     = "stop_requested"
	DispositionStopFailed        = "stop_failed"
	DispositionAdmittedBeforeEnd = "admitted_before_end"
)

// Retirement is the recorded end of a job.
type Retirement struct {
	Reason          RetirementReason `json:"reason"`
	Detail          string           `json:"detail,omitempty"`
	Evidence        []string         `json:"evidence,omitempty"`
	Actor           Actor            `json:"actor"`
	At              time.Time        `json:"at"`
	ActiveRunPolicy ActiveRunPolicy  `json:"active_run_policy"`
	Affected        []Affected       `json:"affected,omitempty"`
}

// RegistrationState says whether a job may run.
type RegistrationState string

const (
	RegistrationIncomplete RegistrationState = "incomplete"
	RegistrationReady      RegistrationState = "ready"
	RegistrationDuplicate  RegistrationState = "duplicate"
)

// PackageEvidence is the client's statement that the package exists on the
// assigned machine. The hub cannot read the machine's disk, so it is recorded
// as an assertion with its author.
type PackageEvidence struct {
	Digest         string    `json:"digest"`
	Path           string    `json:"path"`
	MachineID      string    `json:"machine_id"`
	ManifestSHA256 string    `json:"manifest_sha256,omitempty"`
	Files          int       `json:"files,omitempty"`
	Bytes          int64     `json:"bytes,omitempty"`
	AssertedAt     time.Time `json:"asserted_at"`
	AssertedBy     Actor     `json:"asserted_by"`
}

// Registration tracks whether every part of a registration was saved.
type Registration struct {
	State       RegistrationState `json:"state"`
	JobKey      string            `json:"job_key"`
	DedupeKey   string            `json:"dedupe_key"`
	RequestID   string            `json:"request_id,omitempty"`
	RequestHash string            `json:"request_hash,omitempty"`
	DuplicateOf string            `json:"duplicate_of,omitempty"`
	Package     *PackageEvidence  `json:"package,omitempty"`
	DAGVerified bool              `json:"dag_verified"`
	ReadyAt     *time.Time        `json:"ready_at,omitempty"`
}

// ClaimState is the state of a review claim.
type ClaimState string

const (
	ClaimLive     ClaimState = "live"
	ClaimReleased ClaimState = "released"
	ClaimExpired  ClaimState = "expired"
)

// ClaimKind says what a claim permits. All kinds share one per-job slot.
// review: record reviews, advance the checkpoint, file proposals, authorize
// routine actions. execution: authorize approved actions. reconcile: settle
// in-flight actions only, also on a completed or retired job, which it can
// never revive. Any live claim may settle an action it holds the grant for.
type ClaimKind string

const (
	ClaimReview    ClaimKind = "review"
	ClaimExecution ClaimKind = "execution"
	ClaimReconcile ClaimKind = "reconcile"
)

// Reviewer identifies the reviewer run holding a claim.
type Reviewer struct {
	MachineID          string `json:"machine_id"`
	DAGRunID           string `json:"dag_run_id,omitempty"`
	AgentClientVersion string `json:"agent_client_version,omitempty"`
}

// Claim is a per-job review lease. Fence strictly increases with every grant,
// so a write carrying an older fence is from a superseded reviewer.
type Claim struct {
	ClaimID    string     `json:"claim_id"`
	Kind       ClaimKind  `json:"kind"`
	Reviewer   Reviewer   `json:"reviewer"`
	Fence      int64      `json:"fence"`
	AcquiredAt time.Time  `json:"acquired_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	State      ClaimState `json:"state"`
}

// Checkpoint is the reviewer's progress. Version increases on every advance;
// an episode is (job, checkpoint version).
type Checkpoint struct {
	Version        int        `json:"version"`
	JobVersion     int        `json:"job_version,omitempty"`
	RunCursor      string     `json:"run_cursor,omitempty"`
	DecisionCursor string     `json:"decision_cursor,omitempty"`
	LastReviewID   string     `json:"last_review_id,omitempty"`
	NextReviewAt   *time.Time `json:"next_review_at,omitempty"`
}

// ActionSpec names an action, its target and its parameters.
type ActionSpec struct {
	Name   string          `json:"name"`
	Target *Target         `json:"target,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
}

// ProposalState is the state of a proposed follow-up.
type ProposalState string

const (
	ProposalOpen       ProposalState = "open"
	ProposalSnoozed    ProposalState = "snoozed"
	ProposalDecided    ProposalState = "decided"
	ProposalExecuted   ProposalState = "executed"
	ProposalRejected   ProposalState = "rejected"
	ProposalSuperseded ProposalState = "superseded"
	// ProposalClosed is an escalation answered with retry: finished, never
	// executed itself.
	ProposalClosed ProposalState = "closed"
)

// Terminal reports whether the proposal is finished.
func (s ProposalState) Terminal() bool {
	return s == ProposalExecuted || s == ProposalRejected || s == ProposalSuperseded || s == ProposalClosed
}

// NativeTask points at the Dagu human task that collects the decision.
type NativeTask struct {
	DAG    string `json:"dag"`
	RunID  string `json:"run_id"`
	StepID string `json:"step_id"`
}

// ArtifactRef points at a Dagu run artifact.
type ArtifactRef struct {
	DAG   string `json:"dag"`
	RunID string `json:"run_id"`
	Path  string `json:"path"`
}

// ProposalEvidence is what a proposal is based on.
type ProposalEvidence struct {
	RunIDs       []string      `json:"run_ids,omitempty"`
	ArtifactRefs []ArtifactRef `json:"artifact_refs,omitempty"`
	ObservedAt   *time.Time    `json:"observed_at,omitempty"`
}

// Proposal is an action awaiting a human decision.
type Proposal struct {
	ProposalID    string           `json:"proposal_id"`
	ReviewID      string           `json:"review_id,omitempty"`
	JobVersion    int              `json:"job_version"`
	PackageDigest string           `json:"package_digest"`
	Question      string           `json:"question,omitempty"`
	Rationale     string           `json:"rationale,omitempty"`
	Evidence      ProposalEvidence `json:"evidence"`
	// WaitingOn is person, agent, credentials or machine.
	WaitingOn string `json:"waiting_on,omitempty"`
	// AllowedVerdicts limits the verdicts a decision may use; empty allows all.
	AllowedVerdicts []Verdict     `json:"allowed_verdicts,omitempty"`
	Action          ActionSpec    `json:"action"`
	BindingDigest   string        `json:"binding_digest"`
	Revision        int           `json:"revision"`
	State           ProposalState `json:"state"`
	SnoozeUntil     *time.Time    `json:"snooze_until,omitempty"`
	NativeTask      *NativeTask   `json:"native_task,omitempty"`
	Reasoning       string        `json:"reasoning,omitempty"`
	Decision        *Decision     `json:"decision,omitempty"`
	Created         Stamp         `json:"created"`
	Updated         Stamp         `json:"updated"`
	Prev            string        `json:"prev,omitempty"`
}

// RunRef identifies a run of a job's DAG. RootName and RootRunID are set
// when the run is a child of another DAG's run.
type RunRef struct {
	RunID     string `json:"run_id"`
	Running   bool   `json:"running,omitempty"`
	RootName  string `json:"root_name,omitempty"`
	RootRunID string `json:"root_run_id,omitempty"`
}

// AppliedResourceEvent is a resource event's result on one job.
type AppliedResourceEvent struct {
	Key         string              `json:"key"`
	EventID     string              `json:"event_id"`
	At          time.Time           `json:"at"`
	Disposition ResourceDisposition `json:"disposition"`
}

// AdmittedRun records when a worker was allowed to start a run.
type AdmittedRun struct {
	At        time.Time `json:"at"`
	RootName  string    `json:"root_name,omitempty"`
	RootRunID string    `json:"root_run_id,omitempty"`
}

// PendingEffects is Dagu work a lifecycle transition still owes: runs to
// stop under the cancel policy. Suspension is not stored here; it is always
// reconciled to the state the current lifecycle requires.
type PendingEffects struct {
	Revision int64    `json:"revision"`
	StopRuns []RunRef `json:"stop_runs,omitempty"`
	// DiscoverRuns means the job's runs could not be listed when it ended
	// under the cancel policy; they are listed again and stopped.
	DiscoverRuns bool      `json:"discover_runs,omitempty"`
	Attempts     int       `json:"attempts"`
	Since        time.Time `json:"since"`
	LastError    string    `json:"last_error,omitempty"`
}

// NativeResume is a pending completion of the Dagu human task that collected
// a decision.
type NativeResume struct {
	DecisionID string     `json:"decision_id"`
	ProposalID string     `json:"proposal_id"`
	NativeTask NativeTask `json:"native_task"`
	Since      time.Time  `json:"since"`
}

// Verdict is a human response to a proposal.
type Verdict string

const (
	VerdictApprove  Verdict = "approve"
	VerdictReject   Verdict = "reject"
	VerdictRedirect Verdict = "redirect"
	VerdictRetry    Verdict = "retry"
	VerdictPause    Verdict = "pause"
	VerdictSnooze   Verdict = "snooze"
	VerdictRetire   Verdict = "retire"
)

// Decision is an append-only human decision bound to one proposal revision
// and binding digest.
type Decision struct {
	DecisionID       string     `json:"decision_id"`
	ProposalID       string     `json:"proposal_id"`
	ProposalRevision int        `json:"proposal_revision"`
	BindingDigest    string     `json:"binding_digest"`
	Verdict          Verdict    `json:"verdict"`
	Instructions     string     `json:"instructions,omitempty"`
	SnoozeUntil      *time.Time `json:"snooze_until,omitempty"`
	Actor            Actor      `json:"actor"`
	DecidedAt        time.Time  `json:"decided_at"`
	IdempotencyKey   string     `json:"idempotency_key,omitempty"`
	NativeResume     string     `json:"native_resume,omitempty"`
	Prev             string     `json:"prev,omitempty"`
}

// ActionKind distinguishes policy-permitted routine actions from
// human-approved ones.
type ActionKind string

const (
	ActionRoutine  ActionKind = "routine"
	ActionApproved ActionKind = "approved"
)

// ActionState is the execution state of a follow-up action.
type ActionState string

const (
	ActionExecuting  ActionState = "executing"
	ActionSucceeded  ActionState = "succeeded"
	ActionFailed     ActionState = "failed"
	ActionUncertain  ActionState = "uncertain"
	ActionNotApplied ActionState = "not_applied"
	ActionEscalated  ActionState = "escalated"
)

// Final reports whether no further transition is possible.
func (s ActionState) Final() bool {
	return s == ActionSucceeded || s == ActionEscalated
}

// Grant authorizes one attempt of an action until ExpiresAt.
type Grant struct {
	GrantID   string    `json:"grant_id"`
	ActionID  string    `json:"action_id"`
	Attempt   int       `json:"attempt"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Action is a follow-up effect and its outcome. An action ID names one
// intent; retries are attempts on the same record.
type Action struct {
	ActionID      string      `json:"action_id"`
	Kind          ActionKind  `json:"kind"`
	JobVersion    int         `json:"job_version"`
	ReviewID      string      `json:"review_id,omitempty"`
	ClaimID       string      `json:"claim_id,omitempty"`
	ProposalID    string      `json:"proposal_id,omitempty"`
	DecisionID    string      `json:"decision_id,omitempty"`
	Spec          ActionSpec  `json:"spec"`
	BindingDigest string      `json:"binding_digest"`
	State         ActionState `json:"state"`
	Attempt       int         `json:"attempt"`
	MaxAttempts   int         `json:"max_attempts"`
	// AttemptStartedAt is when the current attempt was granted.
	AttemptStartedAt *time.Time      `json:"attempt_started_at,omitempty"`
	Grant            *Grant          `json:"grant,omitempty"`
	Receipt          string          `json:"receipt,omitempty"`
	Outcome          json.RawMessage `json:"outcome,omitempty"`
	// SettledUnderClaim is the claim whose holder recorded the outcome; it
	// differs from ClaimID when a later claim reconciled the action.
	SettledUnderClaim string `json:"settled_under_claim,omitempty"`
	// ReadOnly copies the creator's declaration that the action has no
	// external effect.
	ReadOnly bool   `json:"read_only,omitempty"`
	Created  Stamp  `json:"created"`
	Updated  Stamp  `json:"updated"`
	Prev     string `json:"prev,omitempty"`
}

// ReviewOutcome is the single recorded result of a review run.
type ReviewOutcome string

const (
	ReviewContinue         ReviewOutcome = "continue"
	ReviewAct              ReviewOutcome = "act"
	ReviewWaitHuman        ReviewOutcome = "wait_human"
	ReviewPauseUnavailable ReviewOutcome = "pause_unavailable"
	ReviewComplete         ReviewOutcome = "complete"
	ReviewRetire           ReviewOutcome = "retire"
)

// Review is an immutable record of one review run.
type Review struct {
	ReviewID           string        `json:"review_id"`
	JobVersion         int           `json:"job_version"`
	CheckpointVersion  int           `json:"checkpoint_version"`
	ClaimID            string        `json:"claim_id"`
	Fence              int64         `json:"fence"`
	EvidenceRunIDs     []string      `json:"evidence_run_ids,omitempty"`
	EvidenceDecisions  []string      `json:"evidence_decision_ids,omitempty"`
	Outcome            ReviewOutcome `json:"outcome"`
	Reasoning          string        `json:"reasoning,omitempty"`
	PacketArtifact     string        `json:"packet_artifact,omitempty"`
	DecisionArtifact   string        `json:"decision_artifact,omitempty"`
	AgentClientVersion string        `json:"agent_client_version,omitempty"`
	// PacketBytes and the token counts are what the review cost.
	PacketBytes       int64           `json:"packet_bytes,omitempty"`
	AgentInputTokens  int64           `json:"agent_input_tokens,omitempty"`
	AgentOutputTokens int64           `json:"agent_output_tokens,omitempty"`
	Detail            json.RawMessage `json:"detail,omitempty"`
	Created           Stamp           `json:"created"`
	Prev              string          `json:"prev,omitempty"`
}

// Exception is an actionable item for a person: a failure that needs local
// action, never a retirement.
type Exception struct {
	ExceptionID string `json:"exception_id"`
	Kind        string `json:"kind"`
	// Scope is "reviewer" for a problem with the job's reviewer, which never
	// changes the job's own availability; empty for the job.
	Scope string            `json:"scope,omitempty"`
	State AvailabilityState `json:"state,omitempty"`
	// Target is the key of the target whose observation opened it, if one
	// did; a present observation of that target resolves it.
	Target string `json:"target,omitempty"`
	// ActionID and Attempt name the action attempt an action-scope
	// exception is about; it is resolved when that attempt ends.
	ActionID string `json:"action_id,omitempty"`
	Attempt  int    `json:"attempt,omitempty"`
	// JobVersion is the version a binding-scope exception is about.
	JobVersion int        `json:"job_version,omitempty"`
	Detail     string     `json:"detail"`
	Evidence   []string   `json:"evidence,omitempty"`
	Created    Stamp      `json:"created"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// EventKind classifies a job history event.
type EventKind string

const (
	EventRegistered   EventKind = "registered"
	EventReady        EventKind = "ready"
	EventDuplicate    EventKind = "duplicate"
	EventVersion      EventKind = "version"
	EventLifecycle    EventKind = "lifecycle"
	EventAvailability EventKind = "availability"
	EventClaim        EventKind = "claim"
	EventEffect       EventKind = "effect"
	EventRunDropped   EventKind = "run_dropped"
	EventResource     EventKind = "resource"
)

// Event is one immutable entry in a job's history.
type Event struct {
	EventID  string     `json:"event_id"`
	JobID    string     `json:"job_id"`
	Revision int64      `json:"revision"`
	Kind     EventKind  `json:"kind"`
	From     string     `json:"from,omitempty"`
	To       string     `json:"to,omitempty"`
	Reason   string     `json:"reason,omitempty"`
	Detail   string     `json:"detail,omitempty"`
	Evidence []string   `json:"evidence,omitempty"`
	Affected []Affected `json:"affected,omitempty"`
	Actor    Actor      `json:"actor"`
	At       time.Time  `json:"at"`
	Prev     string     `json:"prev,omitempty"`
}

// Chains holds the head record of each append-only history. Only records
// reachable from a committed head are visible.
type Chains struct {
	Events    string `json:"events,omitempty"`
	Decisions string `json:"decisions,omitempty"`
	Reviews   string `json:"reviews,omitempty"`
	Actions   string `json:"actions,omitempty"`
	Proposals string `json:"proposals,omitempty"`
	Closures  string `json:"closures,omitempty"`
}

// Job is the job aggregate: every mutable fact about one job lives in this
// single record so that each change is one atomic compare-and-swap.
type Job struct {
	Schema          int                  `json:"schema"`
	JobID           string               `json:"job_id"`
	OwnerID         string               `json:"owner_id"`
	ProjectID       string               `json:"project_id"`
	MachineID       string               `json:"machine_id"`
	Revision        int64                `json:"revision"`
	Version         int                  `json:"version"`
	VersionRefs     []string             `json:"version_refs"`
	PackageDigest   string               `json:"package_digest"`
	DAGSpecSHA256   string               `json:"dag_spec_sha256"`
	Registration    Registration         `json:"registration"`
	Lifecycle       Lifecycle            `json:"lifecycle"`
	LifecycleReason string               `json:"lifecycle_reason,omitempty"`
	Availability    Availability         `json:"availability"`
	Retirement      *Retirement          `json:"retirement,omitempty"`
	ExpiresAt       *time.Time           `json:"expires_at,omitempty"`
	Proposals       map[string]*Proposal `json:"proposals,omitempty"`
	Claim           *Claim               `json:"claim,omitempty"`
	Fence           int64                `json:"fence"`
	Checkpoint      Checkpoint           `json:"checkpoint"`
	// LastRecordedReview makes replaying the latest review a no-op.
	LastRecordedReview string `json:"last_recorded_review,omitempty"`
	// LastRecordedReviewDigest is the latest review's evidence and outcome,
	// so a replay that differs is refused instead of ignored.
	LastRecordedReviewDigest string `json:"last_recorded_review_digest,omitempty"`
	// ReviewerAvailability is the reviewer's availability, kept apart from
	// the job's: a reviewer that cannot run does not make the job unavailable.
	ReviewerAvailability *Availability         `json:"reviewer_availability,omitempty"`
	Actions              map[string]*Action    `json:"actions,omitempty"`
	Exceptions           map[string]*Exception `json:"exceptions,omitempty"`
	// DecisionKeys maps decision idempotency keys to decision IDs so that a
	// replayed decision is recognized after its proposal left the aggregate.
	DecisionKeys map[string]string `json:"decision_keys,omitempty"`
	// NativeResumes tracks decisions whose Dagu human task still has to be
	// completed, so a failed completion can be retried after its proposal
	// left the aggregate. Entries are removed once completed.
	NativeResumes map[string]*NativeResume `json:"native_resumes,omitempty"`
	// AdmittedRuns are runs a worker was allowed to start, by run ID, so a
	// later retirement knows them even before Dagu reports them running.
	AdmittedRuns map[string]AdmittedRun `json:"admitted_runs,omitempty"`
	// UncertainResolutions are retry verdicts on escalations, by action ID,
	// each allowing one more attempt of that action.
	UncertainResolutions map[string]*UncertainResolution `json:"uncertain_resolutions,omitempty"`
	// PendingClosures are superseded proposals whose Dagu human task is still
	// waiting, by proposal ID, until a closure with a final outcome.
	PendingClosures map[string]*PendingClosure `json:"pending_closures,omitempty"`
	// Intents are the latest action of each intent, by intent key.
	Intents map[string]*IntentRecord `json:"intents,omitempty"`
	// SuspendWriters are suspend writes in progress, by token, with when each
	// started. Ownership of the suspension is not released while one is live.
	SuspendWriters map[string]time.Time `json:"suspend_writers,omitempty"`
	// SuspendGen counts the registry's suspend writes. Releasing ownership is
	// fenced by it, so reconciling an older write never releases a newer one.
	SuspendGen int64 `json:"suspend_gen,omitempty"`
	// AppliedResourceEvents are the resource events applied to the job, oldest
	// first, keyed by match and target, with their results, so a replayed
	// event is not applied twice.
	AppliedResourceEvents []AppliedResourceEvent `json:"applied_resource_events,omitempty"`
	// PendingEffects are lifecycle effects on Dagu committed with the
	// transition and not yet confirmed applied.
	PendingEffects *PendingEffects `json:"pending_effects,omitempty"`
	// SuspendedByRegistry is set while the registry holds the job's DAG
	// suspended, so lifting it never overrides a person's own suspension.
	SuspendedByRegistry bool   `json:"suspended_by_registry,omitempty"`
	Chains              Chains `json:"chains"`
	Created             Stamp  `json:"created"`
	Updated             Stamp  `json:"updated"`
}

// Runnable reports whether Dagu may start a run of this job now.
func (j *Job) Runnable() bool {
	return j.Registration.State == RegistrationReady && j.Lifecycle != LifecyclePaused && !j.Lifecycle.Terminal()
}

func sortedActions(m map[string]*Action) []*Action {
	out := make([]*Action, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, k int) bool { return out[i].ActionID < out[k].ActionID })
	return out
}

func sortedProposals(m map[string]*Proposal) []*Proposal {
	out := make([]*Proposal, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, k int) bool { return out[i].ProposalID < out[k].ProposalID })
	return out
}
