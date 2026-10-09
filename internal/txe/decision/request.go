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

	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// Verdict is a person's response to a proposal.
type Verdict = registry.Verdict

const (
	VerdictApprove  = registry.VerdictApprove
	VerdictReject   = registry.VerdictReject
	VerdictRedirect = registry.VerdictRedirect
	VerdictRetry    = registry.VerdictRetry
	VerdictPause    = registry.VerdictPause
	VerdictSnooze   = registry.VerdictSnooze
	VerdictRetire   = registry.VerdictRetire
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

// ValidateShape checks the request independently of time and current state.
// It applies to every request, including an identical replay of a decision
// stored earlier.
func (r *Request) ValidateShape() error {
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
	switch {
	case r.Verdict == VerdictSnooze && r.SnoozeUntil == nil:
		return fmt.Errorf("%w: snooze requires snoozeUntil", ErrInvalid)
	case r.Verdict != VerdictSnooze && r.SnoozeUntil != nil:
		return fmt.Errorf("%w: snoozeUntil is only valid with snooze", ErrInvalid)
	case r.SnoozeUntil != nil:
		until := r.SnoozeUntil.UTC()
		r.SnoozeUntil = &until
	}
	return nil
}

// ValidateNew checks what only a new decision must satisfy at now: a snooze
// expiry in the future and within MaxSnooze. A replay of a stored decision
// skips it, so a committed snooze can be recovered after it expired.
func (r *Request) ValidateNew(now time.Time) error {
	if r.SnoozeUntil == nil {
		return nil
	}
	if !r.SnoozeUntil.After(now) {
		return fmt.Errorf("%w: snoozeUntil must be in the future", ErrInvalid)
	}
	if r.SnoozeUntil.Sub(now) > MaxSnooze {
		return fmt.Errorf("%w: snoozeUntil must be within %s", ErrInvalid, MaxSnooze)
	}
	return nil
}

// Validate checks a new decision: its shape and its timing at now.
func (r *Request) Validate(now time.Time) error {
	if err := r.ValidateShape(); err != nil {
		return err
	}
	return r.ValidateNew(now)
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

// LifecycleOp names a job lifecycle transition a verdict requests in the same
// commit as the decision.
type LifecycleOp string

const (
	LifecycleNone   LifecycleOp = ""
	LifecyclePause  LifecycleOp = "pause"
	LifecycleRetire LifecycleOp = "retire"
)

// Effect describes what recording a verdict changes. Only approve leaves the
// proposal executable, and only through the pre-effect guard. Every other
// verdict except snooze closes the proposal; redirect saves instructions for
// the next review and grants nothing.
type Effect struct {
	Proposal  registry.ProposalState
	Lifecycle LifecycleOp
	// RetryRun asks for a native retry of the job's latest run after commit.
	RetryRun bool
}

// EffectOf maps a verdict to its effect.
func EffectOf(v Verdict) Effect {
	switch v {
	case VerdictApprove:
		return Effect{Proposal: registry.ProposalDecided}
	case VerdictSnooze:
		return Effect{Proposal: registry.ProposalSnoozed}
	case VerdictPause:
		return Effect{Proposal: registry.ProposalRejected, Lifecycle: LifecyclePause}
	case VerdictRetire:
		return Effect{Proposal: registry.ProposalRejected, Lifecycle: LifecycleRetire}
	case VerdictRetry:
		return Effect{Proposal: registry.ProposalRejected, RetryRun: true}
	case VerdictReject, VerdictRedirect:
		return Effect{Proposal: registry.ProposalRejected}
	}
	return Effect{Proposal: registry.ProposalRejected}
}
