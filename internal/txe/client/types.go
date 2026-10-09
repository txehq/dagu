// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"encoding/json"
	"time"
)

// The types in this file are the bodies of the registry calls the CLI makes.
// Their JSON matches the registry's records field for field; the request and
// response examples under txe/contract/fixtures/registration are the reference.

// Actor says who made a change. It is never the owner.
type Actor struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	// Session is the coding session that ran the CLI, such as cc2-s855054.
	Session   string `json:"session,omitempty"`
	MachineID string `json:"machine_id,omitempty"`
	// Client is the CLI build and skill revision.
	Client string `json:"client,omitempty"`
}

// ActorKindCLI is the actor kind for changes made through this CLI.
const ActorKindCLI = "cli"

// Stamp records when and by whom a record was created or changed.
type Stamp struct {
	At time.Time `json:"at"`
	By Actor     `json:"by"`
}

// Installation describes the registry and the owners it holds.
type Installation struct {
	Schema int     `json:"schema"`
	Owners []Owner `json:"owners"`
}

// Owner is the stable opaque owner of jobs.
type Owner struct {
	OwnerID     string `json:"owner_id"`
	DisplayName string `json:"display_name"`
}

// Project groups an owner's jobs. Key is its stable natural key.
type Project struct {
	ProjectID string `json:"project_id"`
	OwnerID   string `json:"owner_id"`
	Key       string `json:"key,omitempty"`
	Name      string `json:"name"`
}

// Machine is an execution machine known to the registry.
type Machine struct {
	MachineID   string `json:"machine_id"`
	OwnerID     string `json:"owner_id"`
	DisplayName string `json:"display_name"`
}

// Target is an external resource a job concerns, identified by kind and
// stable ID. The display name never identifies it.
type Target struct {
	Kind           string            `json:"kind" yaml:"kind"`
	Environment    string            `json:"environment,omitempty" yaml:"environment"`
	StableID       map[string]string `json:"stable_id" yaml:"stable_id"`
	DisplayName    string            `json:"display_name,omitempty" yaml:"display_name"`
	ExistenceCheck string            `json:"existence_check,omitempty" yaml:"existence_check"`
}

// Origin records where a job came from. It is context, not ownership.
type Origin struct {
	Repo         string `json:"repo,omitempty"`
	Commit       string `json:"commit,omitempty"`
	Session      string `json:"session,omitempty"`
	WorktreePath string `json:"worktree_path,omitempty"`
	ChatRef      string `json:"chat_ref,omitempty"`
}

// CredentialRef names a credential the worker resolves on its own machine.
type CredentialRef struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
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

// DAGRef carries the job's Dagu definition. The registry writes it.
type DAGRef struct {
	Name       string `json:"name,omitempty"`
	Spec       string `json:"spec"`
	SpecSHA256 string `json:"spec_sha256,omitempty"`
}

// Schedule mirrors the DAG's schedule for a reviewer to read.
type Schedule struct {
	Cron       string `json:"cron,omitempty"`
	Timezone   string `json:"timezone,omitempty"`
	Overlap    string `json:"overlap,omitempty"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
	Retry      int    `json:"retry,omitempty"`
	MissedRun  string `json:"missed_run,omitempty"`
}

// Deliveries say where a deliverable's bytes are kept.
const (
	// DeliveryMachine keeps the file on the machine that ran the job. The hub
	// records its digest and that it is stored there, not that it can be fetched.
	DeliveryMachine = "machine"
	// DeliveryHub also uploads the file to the hub as a run artifact.
	DeliveryHub = "hub"
)

// Deliverable is one file a run is expected to produce. Only files named here
// are ever published; nothing else a script writes leaves the machine.
type Deliverable struct {
	Name string `json:"name" yaml:"name"`
	// Path is the file's exact name relative to the run's output directory.
	Path        string `json:"path" yaml:"path"`
	Type        string `json:"type,omitempty" yaml:"type"`
	Description string `json:"description,omitempty" yaml:"description"`
	Delivery    string `json:"delivery,omitempty" yaml:"delivery"`
	Required    bool   `json:"required,omitempty" yaml:"required"`
}

// ExpectedOutcome states what success means.
type ExpectedOutcome struct {
	SuccessCriteria []string      `json:"success_criteria,omitempty" yaml:"success_criteria"`
	Deliverables    []Deliverable `json:"deliverables,omitempty" yaml:"deliverables"`
}

// Lifetime bounds a job in time.
type Lifetime struct {
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// RetirementRules are the job's stopping rules.
type RetirementRules struct {
	OnTargetDeleted string `json:"on_target_deleted,omitempty" yaml:"on_target_deleted"`
	OnReplacement   string `json:"on_replacement,omitempty" yaml:"on_replacement"`
	OnCompletion    string `json:"on_completion,omitempty" yaml:"on_completion"`
	ActiveRunPolicy string `json:"active_run_policy,omitempty" yaml:"active_run_policy"`
}

// PermittedAction is a follow-up a reviewer may take.
type PermittedAction struct {
	Name        string          `json:"name" yaml:"name"`
	Command     string          `json:"command,omitempty" yaml:"command"`
	Entrypoint  string          `json:"entrypoint,omitempty" yaml:"entrypoint"`
	ParamSchema json.RawMessage `json:"param_schema,omitempty" yaml:"-"`
	Idempotency string          `json:"idempotency,omitempty" yaml:"idempotency"`
	Reconcile   string          `json:"reconcile,omitempty" yaml:"reconcile"`
	TimeoutSec  int             `json:"timeout_sec" yaml:"timeout_sec"`
	Routine     bool            `json:"routine" yaml:"routine"`
	MaxAttempts int             `json:"max_attempts,omitempty" yaml:"max_attempts"`
}

// ReviewPolicy is the brief and bounds for periodic review.
type ReviewPolicy struct {
	Cadence                 string            `json:"cadence,omitempty" yaml:"cadence"`
	MaxDurationSec          int               `json:"max_duration_sec,omitempty" yaml:"max_duration_sec"`
	MaxAttempts             int               `json:"max_attempts,omitempty" yaml:"max_attempts"`
	Brief                   string            `json:"brief,omitempty" yaml:"brief"`
	PermittedActions        []PermittedAction `json:"permitted_actions,omitempty" yaml:"permitted_actions"`
	HumanDecisionConditions []string          `json:"human_decision_conditions,omitempty" yaml:"human_decision_conditions"`
}

// JobVersion is the context of one immutable version of a job.
type JobVersion struct {
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
	// Version is set by the registry on a stored version.
	Version int `json:"version,omitempty"`
}

// RegisterRequest is the body of POST /txe/jobs.
type RegisterRequest struct {
	JobID     string     `json:"job_id"`
	RequestID string     `json:"request_id"`
	OwnerID   string     `json:"owner_id"`
	ProjectID string     `json:"project_id"`
	MachineID string     `json:"machine_id"`
	JobKey    string     `json:"job_key"`
	Version   JobVersion `json:"version"`
	Actor     Actor      `json:"actor"`
}

// VersionRequest is the body of POST /txe/jobs/{job}/versions.
type VersionRequest struct {
	RequestID       string     `json:"request_id"`
	ExpectedVersion int        `json:"expected_version"`
	Version         JobVersion `json:"version"`
	Actor           Actor      `json:"actor"`
}

// PackageEvidence is this machine's statement that a package is in place.
type PackageEvidence struct {
	Digest         string `json:"digest"`
	Path           string `json:"path"`
	MachineID      string `json:"machine_id"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	Files          int    `json:"files"`
	Bytes          int64  `json:"bytes"`
}

// ReadyRequest is the body of POST /txe/jobs/{job}/ready.
type ReadyRequest struct {
	ExpectedRevision int64           `json:"expected_revision"`
	Package          PackageEvidence `json:"package"`
	Actor            Actor           `json:"actor"`
}

// Registration states.
const (
	RegistrationIncomplete = "incomplete"
	RegistrationReady      = "ready"
)

// Registration is how far a job's registration has got.
type Registration struct {
	State       string           `json:"state"`
	JobKey      string           `json:"job_key"`
	RequestID   string           `json:"request_id,omitempty"`
	Package     *PackageEvidence `json:"package,omitempty"`
	DAGVerified bool             `json:"dag_verified"`
	ReadyAt     *time.Time       `json:"ready_at,omitempty"`
}

// Availability is whether the job's machine and credentials are usable.
type Availability struct {
	State      string     `json:"state"`
	Detail     string     `json:"detail,omitempty"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
}

// Retirement records why and when a job stopped.
type Retirement struct {
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// Job is the part of a job's record the CLI reads. Raw holds the whole record
// as the registry sent it, for structured output.
type Job struct {
	JobID           string                     `json:"job_id"`
	OwnerID         string                     `json:"owner_id"`
	ProjectID       string                     `json:"project_id"`
	MachineID       string                     `json:"machine_id"`
	Revision        int64                      `json:"revision"`
	Version         int                        `json:"version"`
	PackageDigest   string                     `json:"package_digest"`
	DAGSpecSHA256   string                     `json:"dag_spec_sha256"`
	Registration    Registration               `json:"registration"`
	Lifecycle       string                     `json:"lifecycle"`
	LifecycleReason string                     `json:"lifecycle_reason,omitempty"`
	Availability    Availability               `json:"availability"`
	Retirement      *Retirement                `json:"retirement,omitempty"`
	ExpiresAt       *time.Time                 `json:"expires_at,omitempty"`
	Proposals       map[string]json.RawMessage `json:"proposals,omitempty"`
	Exceptions      map[string]json.RawMessage `json:"exceptions,omitempty"`
	Created         Stamp                      `json:"created"`
	Updated         Stamp                      `json:"updated"`

	Raw json.RawMessage `json:"-"`
}

// UnmarshalJSON keeps the whole record beside the fields the CLI reads.
func (j *Job) UnmarshalJSON(data []byte) error {
	type plain Job
	if err := json.Unmarshal(data, (*plain)(j)); err != nil {
		return err
	}
	j.Raw = append(j.Raw[:0], data...)
	return nil
}

// Receipt is the registry's proof that a job version is fully registered.
type Receipt struct {
	JobID         string `json:"job_id"`
	OwnerID       string `json:"owner_id"`
	ProjectID     string `json:"project_id"`
	MachineID     string `json:"machine_id"`
	Version       int    `json:"version"`
	PackageDigest string `json:"package_digest"`
	DAGName       string `json:"dag_name"`
	DAGSpecSHA256 string `json:"dag_spec_sha256"`
	Registration  string `json:"registration"`
	Revision      int64  `json:"revision"`

	Raw json.RawMessage `json:"-"`
}

// EventReady is the kind of the event the registry writes when a version is
// marked ready. Its evidence names the package digest and the DAG's hash.
const EventReady = "ready"

// Event is one entry of a job's history in the registry. Entries are never
// changed or removed.
type Event struct {
	EventID  string   `json:"event_id"`
	JobID    string   `json:"job_id"`
	Revision int64    `json:"revision"`
	Kind     string   `json:"kind"`
	Evidence []string `json:"evidence,omitempty"`
	At       string   `json:"at"`

	Raw json.RawMessage `json:"-"`
}

// UnmarshalJSON keeps the whole event as the registry sent it.
func (e *Event) UnmarshalJSON(data []byte) error {
	type plain Event
	if err := json.Unmarshal(data, (*plain)(e)); err != nil {
		return err
	}
	e.Raw = append(e.Raw[:0], data...)
	return nil
}

// UnmarshalJSON keeps the whole receipt as the registry sent it.
func (r *Receipt) UnmarshalJSON(data []byte) error {
	type plain Receipt
	if err := json.Unmarshal(data, (*plain)(r)); err != nil {
		return err
	}
	r.Raw = append(r.Raw[:0], data...)
	return nil
}

// Health is the hub's own status, which carries its build.
type Health struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// ArtifactRecord is one deliverable of one run: what was produced, its
// digest, and where the bytes are.
type ArtifactRecord struct {
	Deliverable string `json:"deliverable"`
	Path        string `json:"path"`
	// Missing is set when the run did not produce the file.
	Missing    bool   `json:"missing,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`
	Location   string `json:"location,omitempty"`
	MachineID  string `json:"machine_id,omitempty"`
	RecordedAt string `json:"recorded_at,omitempty"`
}

// ArtifactManifest is the body of POST /txe/jobs/{job}/runs/{run}/artifacts.
type ArtifactManifest struct {
	JobVersion int `json:"job_version"`
	// Execution is the execution that publishes: attempt_id and queued_at.
	// A run has one manifest per execution.
	Execution
	// ProducedIn is the execution whose run of the job wrote the files. It
	// differs from the publishing one only when that is a retry that ran
	// the publish step alone.
	ProducedIn Execution        `json:"produced_in"`
	Artifacts  []ArtifactRecord `json:"artifacts"`
	Actor      Actor            `json:"actor"`
}
