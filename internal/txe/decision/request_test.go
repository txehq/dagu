// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package decision

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

var testNow = time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)

func validRequest() Request {
	return Request{
		ExpectedProposalRevision: 2,
		BindingDigest:            "sha256:" + strings.Repeat("a", 64),
		Verdict:                  VerdictApprove,
		IdempotencyKey:           "key-0000001",
	}
}

func at(d time.Duration) *time.Time {
	t := testNow.Add(d)
	return &t
}

func TestRequestValidate(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Request)
		ok     bool
	}{
		{"approve", func(*Request) {}, true},
		{"zero revision", func(r *Request) { r.ExpectedProposalRevision = 0 }, false},
		{"short digest", func(r *Request) { r.BindingDigest = "sha256:abc" }, false},
		{"unprefixed digest", func(r *Request) { r.BindingDigest = strings.Repeat("a", 64) }, false},
		{"unknown verdict", func(r *Request) { r.Verdict = "escalate" }, false},
		{"short key", func(r *Request) { r.IdempotencyKey = "k" }, false},
		{"redirect without instructions", func(r *Request) {
			r.Verdict, r.Instructions = VerdictRedirect, "   "
		}, false},
		{"redirect", func(r *Request) {
			r.Verdict, r.Instructions = VerdictRedirect, "collect events first"
		}, true},
		{"snooze without expiry", func(r *Request) { r.Verdict = VerdictSnooze }, false},
		{"snooze in the past", func(r *Request) {
			r.Verdict, r.SnoozeUntil = VerdictSnooze, at(-time.Minute)
		}, false},
		{"snooze too far", func(r *Request) {
			r.Verdict, r.SnoozeUntil = VerdictSnooze, at(MaxSnooze+time.Minute)
		}, false},
		{"snooze", func(r *Request) {
			r.Verdict, r.SnoozeUntil = VerdictSnooze, at(24*time.Hour)
		}, true},
		{"expiry on approve", func(r *Request) { r.SnoozeUntil = at(time.Hour) }, false},
		{"instructions too long", func(r *Request) {
			r.Instructions = strings.Repeat("x", MaxInstructionsBytes+1)
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validRequest()
			tt.modify(&r)
			err := r.Validate(testNow)
			if tt.ok && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
			if !tt.ok && !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestRequestSameAs(t *testing.T) {
	a := validRequest()
	a.Verdict, a.SnoozeUntil = VerdictSnooze, at(time.Hour)
	b := a
	inOtherZone := a.SnoozeUntil.In(time.FixedZone("AWST", 8*3600))
	b.SnoozeUntil = &inOtherZone
	if !a.SameAs(&b) {
		t.Fatal("same instant in another zone should be the same request")
	}
	b.SnoozeUntil = at(2 * time.Hour)
	if a.SameAs(&b) {
		t.Fatal("different snooze expiry should differ")
	}
	c := validRequest()
	d := validRequest()
	d.BindingDigest = "sha256:" + strings.Repeat("b", 64)
	if c.SameAs(&d) {
		t.Fatal("different binding digest should differ")
	}
}

func TestEffectOf(t *testing.T) {
	if got := EffectOf(VerdictReject, ""); got.Proposal != registry.ProposalRejected || got.Lifecycle != LifecycleNone {
		t.Fatalf("reject = %+v", got)
	}
	if got := EffectOf(VerdictRetire, ""); got.Lifecycle != LifecycleRetire {
		t.Fatalf("retire = %+v", got)
	}
	if got := EffectOf(VerdictApprove, ""); got.Proposal != registry.ProposalDecided {
		t.Fatalf("approve = %+v", got)
	}
	if got := EffectOf(VerdictRedirect, ""); got.Proposal != registry.ProposalRejected || got.Lifecycle != LifecycleNone {
		t.Fatalf("redirect must grant nothing beyond a decided proposal: %+v", got)
	}
	// Retry is executable only on the bound native-retry proposal; on an
	// uncertain-effect escalation it closes the escalation.
	if got := EffectOf(VerdictRetry, ActionRetryRun); got != (Effect{Proposal: registry.ProposalDecided}) {
		t.Fatalf("retry on %s = %+v", ActionRetryRun, got)
	}
	if got := EffectOf(VerdictRetry, ActionUncertainEffect); got != (Effect{Proposal: registry.ProposalRejected}) {
		t.Fatalf("retry on %s = %+v", ActionUncertainEffect, got)
	}
	if got := EffectOf(VerdictSnooze, ""); got.Proposal != registry.ProposalSnoozed {
		t.Fatalf("snooze = %+v", got)
	}
}
