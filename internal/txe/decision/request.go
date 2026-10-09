// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Package decision records human decisions on TXE job proposals. A decision is
// bound to the proposal revision and binding digest the person reviewed, so a
// material change to the job, target or action refuses it instead of letting
// an old approval authorize something different.
package decision

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Verdict is a person's response to a proposal.
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

// Verdicts lists every verdict in display order.
var Verdicts = []Verdict{
	VerdictApprove, VerdictReject, VerdictRedirect, VerdictRetry,
	VerdictPause, VerdictSnooze, VerdictRetire,
}

const (
	// MaxSnooze bounds how far ahead a snooze may expire.
	MaxSnooze = 30 * 24 * time.Hour
	// MaxInstructionsBytes bounds saved redirect instructions.
	MaxInstructionsBytes = 16 << 10
)

var (
	bindingDigestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
)

// ErrInvalid marks a request that is malformed independent of current state.
var ErrInvalid = errors.New("invalid decision request")

// Request is a decision as submitted by the dashboard or CLI.
type Request struct {
	ExpectedProposalRevision int
	BindingDigest            string
	Verdict                  Verdict
	Instructions             string
	SnoozeUntil              *time.Time
	IdempotencyKey           string
}

// Validate checks the request shape. State checks (revision, digest,
// lifecycle, allowed verdicts) happen inside the job transaction.
func (r *Request) Validate(now time.Time) error {
	if r.ExpectedProposalRevision < 1 {
		return fmt.Errorf("%w: expectedProposalRevision must be at least 1", ErrInvalid)
	}
	if !bindingDigestPattern.MatchString(r.BindingDigest) {
		return fmt.Errorf("%w: bindingDigest must be sha256:<64 lowercase hex>", ErrInvalid)
	}
	if !slices.Contains(Verdicts, r.Verdict) {
		return fmt.Errorf("%w: unknown verdict %q", ErrInvalid, r.Verdict)
	}
	if !idempotencyKeyPattern.MatchString(r.IdempotencyKey) {
		return fmt.Errorf("%w: idempotencyKey must be 8-128 characters of [A-Za-z0-9._:-]", ErrInvalid)
	}
	r.Instructions = strings.TrimSpace(r.Instructions)
	if len(r.Instructions) > MaxInstructionsBytes {
		return fmt.Errorf("%w: instructions exceed %d bytes", ErrInvalid, MaxInstructionsBytes)
	}
	if r.Verdict == VerdictRedirect && r.Instructions == "" {
		return fmt.Errorf("%w: redirect requires instructions", ErrInvalid)
	}
	if r.Verdict == VerdictSnooze {
		if r.SnoozeUntil == nil {
			return fmt.Errorf("%w: snooze requires snoozeUntil", ErrInvalid)
		}
		until := r.SnoozeUntil.UTC()
		r.SnoozeUntil = &until
		if !until.After(now) {
			return fmt.Errorf("%w: snoozeUntil must be in the future", ErrInvalid)
		}
		if until.Sub(now) > MaxSnooze {
			return fmt.Errorf("%w: snoozeUntil must be within %s", ErrInvalid, MaxSnooze)
		}
	} else if r.SnoozeUntil != nil {
		return fmt.Errorf("%w: snoozeUntil is only valid with snooze", ErrInvalid)
	}
	return nil
}

// SameAs reports whether two requests carry the same decision content, which
// decides whether a repeated idempotency key is a replay or a conflict.
func (r *Request) SameAs(other *Request) bool {
	if r.ExpectedProposalRevision != other.ExpectedProposalRevision ||
		r.BindingDigest != other.BindingDigest ||
		r.Verdict != other.Verdict ||
		r.Instructions != other.Instructions {
		return false
	}
	if (r.SnoozeUntil == nil) != (other.SnoozeUntil == nil) {
		return false
	}
	return r.SnoozeUntil == nil || r.SnoozeUntil.Equal(*other.SnoozeUntil)
}

// ProposalOutcome is the proposal state a verdict leaves behind.
type ProposalOutcome string

const (
	OutcomeDecided  ProposalOutcome = "decided"
	OutcomeRejected ProposalOutcome = "rejected"
	OutcomeSnoozed  ProposalOutcome = "snoozed"
)

// LifecycleOp names a job lifecycle transition a verdict requests in the same
// commit as the decision.
type LifecycleOp string

const (
	LifecycleNone   LifecycleOp = ""
	LifecyclePause  LifecycleOp = "pause"
	LifecycleRetire LifecycleOp = "retire"
)

// Effect describes what recording a verdict changes. Only approve can lead to
// an action, and only through the pre-effect guard; redirect saves
// instructions for the next review and grants nothing.
type Effect struct {
	Proposal  ProposalOutcome
	Lifecycle LifecycleOp
	// RetryRun asks for a native retry of the job's latest run after commit.
	RetryRun bool
}

// EffectOf maps a verdict to its effect.
func EffectOf(v Verdict) Effect {
	switch v {
	case VerdictReject:
		return Effect{Proposal: OutcomeRejected}
	case VerdictSnooze:
		return Effect{Proposal: OutcomeSnoozed}
	case VerdictPause:
		return Effect{Proposal: OutcomeDecided, Lifecycle: LifecyclePause}
	case VerdictRetire:
		return Effect{Proposal: OutcomeDecided, Lifecycle: LifecycleRetire}
	case VerdictRetry:
		return Effect{Proposal: OutcomeDecided, RetryRun: true}
	case VerdictApprove, VerdictRedirect:
		return Effect{Proposal: OutcomeDecided}
	}
	return Effect{Proposal: OutcomeDecided}
}
