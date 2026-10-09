// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrClaimHeld means another live claim owns the job.
	ErrClaimHeld = errors.New("txe review: job is claimed by another holder")
	// ErrStaleFence means the write came from a claim that is no longer the
	// current one for the job.
	ErrStaleFence = errors.New("txe review: claim is stale")
	// ErrConflict means a compare-and-set write lost to a concurrent change.
	ErrConflict = errors.New("txe review: version conflict")
	// ErrActionExists means the action was already journaled. Nothing may
	// run on this error; the stored record is authoritative.
	ErrActionExists = errors.New("txe review: action already journaled")
	// ErrNotFound means the record does not exist.
	ErrNotFound = errors.New("txe review: not found")
)

// DenyReason is why the registry's pre-effect guard refused an action.
type DenyReason string

const (
	DenyLifecycle      DenyReason = "lifecycle"
	DenyVersionChanged DenyReason = "version_changed"
	DenyDecisionStale  DenyReason = "decision_stale"
	DenyNotApproved    DenyReason = "not_approved"
	DenyNotPermitted   DenyReason = "not_permitted"
	// DenyIntentUnresolved means an earlier attempt of the same intent has
	// an outcome nobody has settled yet.
	DenyIntentUnresolved DenyReason = "intent_unresolved"
)

// GuardDeniedError reports that the guard refused an effect. It is an
// expected outcome, not a failure of the review.
type GuardDeniedError struct {
	Reason DenyReason
	Detail string
}

func (e *GuardDeniedError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("txe review: effect denied: %s", e.Reason)
	}
	return fmt.Sprintf("txe review: effect denied: %s: %s", e.Reason, e.Detail)
}

// ClaimRequest asks for the per-job lease.
type ClaimRequest struct {
	JobID  string
	Kind   ClaimKind
	Holder string
	TTL    time.Duration
}

// BeginRequest asks the guard to authorize one effect and journal it as
// executing in the same transaction. Exactly one of ReviewID (a routine action)
// or DecisionID (an approved proposal) is set.
type BeginRequest struct {
	Claim      Claim
	ActionID   string
	IntentKey  string
	JobVersion int
	Name       string
	TargetID   string
	Params     map[string]string
	ReviewID   string
	ProposalID string
	DecisionID string
	// Timeout is how long the attempt may take. The registry grants the
	// attempt for exactly this long.
	Timeout time.Duration
}

// FinishRequest records the outcome of a journaled action.
type FinishRequest struct {
	Claim    Claim
	JobID    string
	ActionID string
	GrantID  string
	State    ActionState
	Receipt  string
	Detail   string
}

// Registry is the part of the TXE job registry the reviewer consumes. The
// registry is the single authority: the reviewer keeps no state of its own.
//
// Every method that takes a Claim must refuse with ErrStaleFence when that
// claim is not the job's current live claim.
type Registry interface {
	// DueJobs lists jobs on the machine whose next review time has passed.
	DueJobs(ctx context.Context, machineID string, now time.Time) ([]string, error)
	Job(ctx context.Context, jobID string) (Job, error)
	Checkpoint(ctx context.Context, jobID string) (Checkpoint, error)

	// AcquireClaim grants the lease when no live claim exists and returns
	// ErrClaimHeld otherwise. Taking over an expired claim raises the fence.
	AcquireClaim(ctx context.Context, req ClaimRequest) (Claim, error)
	ReleaseClaim(ctx context.Context, claim Claim) error

	// RunsAfter returns finished runs after the cursor, oldest first.
	RunsAfter(ctx context.Context, jobID, cursor string) ([]RunEvidence, error)
	// DecisionsAfter returns decisions after the cursor, oldest first,
	// including decisions on proposals that were later superseded.
	DecisionsAfter(ctx context.Context, jobID, cursor string) ([]Decision, error)
	Decision(ctx context.Context, jobID, decisionID string) (Decision, error)
	Proposal(ctx context.Context, jobID, proposalID string) (Proposal, error)
	OpenProposals(ctx context.Context, jobID string) ([]Proposal, error)
	// Review returns a recorded review, or ErrNotFound.
	Review(ctx context.Context, jobID, reviewID string) (Review, error)
	// Actions returns the job's journaled actions, oldest first.
	Actions(ctx context.Context, jobID string) ([]Action, error)

	// BeginAction runs the pre-effect guard and journals the action as
	// executing atomically. It returns ErrActionExists with the stored record
	// when the action id is already journaled, and *GuardDeniedError when
	// the current lifecycle, version, policy or decision forbids the effect.
	BeginAction(ctx context.Context, req BeginRequest) (Action, error)
	FinishAction(ctx context.Context, req FinishRequest) error

	// CreateProposal is idempotent on the proposal id, which the reviewer
	// derives, and returns the stored proposal on a repeat.
	CreateProposal(ctx context.Context, claim Claim, draft Proposal) (Proposal, error)
	// RecordReview is idempotent on the review id for the same coverage and
	// returns ErrConflict when the stored review covers different evidence.
	RecordReview(ctx context.Context, claim Claim, review Review) error
	// AdvanceCheckpoint replaces the checkpoint when its stored version
	// still equals expectedVersion.
	AdvanceCheckpoint(ctx context.Context, claim Claim, next Checkpoint, expectedVersion int) error
	// DeferReview moves the next review time without covering any evidence,
	// so a reviewer that cannot run does not retry on every tick.
	DeferReview(ctx context.Context, claim Claim, until time.Time) error
	RaiseException(ctx context.Context, exc Exception) error
}

// DecisionOpener makes a proposal answerable without keeping any process
// alive. Opening the same proposal twice must be a no-op.
type DecisionOpener interface {
	OpenDecision(ctx context.Context, proposal Proposal) error
}
