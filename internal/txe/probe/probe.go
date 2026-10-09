// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package probe observes whether a job's external targets still exist, on
// the machine that holds the credentials for them. A probe reports what it
// could prove: a target is absent only when the probe reached the place the
// target lives and was told it is not there. Anything it could not prove
// (wrong place, no permission, no answer) is reported as such, never as a
// deletion.
package probe

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// Outcome is what a probe observed of one target. The values match the
// registry's resource-event observations.
type Outcome string

const (
	// Present: the target exists with the identity the job names, or, with
	// Result.Observed set, a resource of the same name exists under another
	// identity (a replacement).
	Present Outcome = "present"
	// Absent: the target does not exist where it lives. Authoritative only
	// when Result.Authoritative is set.
	Absent Outcome = "absent"
	// Unknown: the probe got an answer that does not prove absence, such as
	// a lookup that returns nothing for an id it cannot vouch for.
	Unknown Outcome = "unknown"
	// Unreachable: the probe could not reach the place the target lives, or
	// reached a different place than the target names.
	Unreachable Outcome = "unreachable"
	// AuthDenied: the credential was refused, or there is no credential.
	AuthDenied Outcome = "auth_denied"
	// Timeout: the probe gave up waiting.
	Timeout Outcome = "timeout"
)

// Target is an external resource as a job version declares it: a kind and a
// stable identity. The display name never identifies it.
type Target struct {
	Kind        string            `json:"kind"`
	Environment string            `json:"environment,omitempty"`
	StableID    map[string]string `json:"stable_id"`
	DisplayName string            `json:"display_name,omitempty"`
}

// Result is one observation of one target.
type Result struct {
	Outcome Outcome
	// Authoritative is set only for Absent, and only when the probe proved
	// it looked where the target lives.
	Authoritative bool
	// Observed is the identity actually found when it differs from the
	// target's: same kind, environment and name, another stable identity.
	Observed *Target
	Detail   string
	Evidence []string
}

// Credential is a secret resolved on this machine from a job's credential
// reference. Its value never leaves the machine.
type Credential struct {
	// Path is set for a file credential, Value for an environment one.
	Path  string
	Value string
}

// Credentials resolves a job's credential references by name.
type Credentials interface {
	Lookup(name string) (Credential, bool)
}

// Prober observes targets of the kinds it supports.
type Prober interface {
	Supports(kind string) bool
	Probe(ctx context.Context, t Target, creds Credentials) Result
}

// Probes dispatches each target to the first prober that supports its kind.
type Probes []Prober

// TargetTimeout bounds one target's probe; requestTimeout bounds each
// request a probe makes.
const (
	TargetTimeout  = 20 * time.Second
	requestTimeout = 15 * time.Second
)

// Probe observes t within TargetTimeout. A kind no prober supports is
// reported unreachable: nothing could look, which says nothing about the
// target.
func (ps Probes) Probe(ctx context.Context, t Target, creds Credentials) Result {
	for _, p := range ps {
		if p.Supports(t.Kind) {
			ctx, cancel := context.WithTimeout(ctx, TargetTimeout)
			defer cancel()
			return p.Probe(ctx, t, creds)
		}
	}
	return Result{Outcome: Unreachable, Detail: "no probe for kind " + t.Kind}
}

// classify maps a transport error to the outcome it allows. It never yields
// Absent: an error is not an answer about the target.
func classify(ctx context.Context, err error) Outcome {
	if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
		return Timeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Timeout
	}
	return Unreachable
}

// noCredential reports a credential the probe needs and does not have. It
// is auth_denied, which asks for the credential, never an absence.
func noCredential(creds Credentials, name string) Result {
	detail := "no credential reference named " + name + " on this machine"
	if e, ok := creds.(interface{ MissingReason(string) string }); ok {
		if why := e.MissingReason(name); why != "" {
			detail = why
		}
	}
	return Result{Outcome: AuthDenied, Detail: detail}
}

// trimmed returns s without surrounding space, so an id copied with a stray
// newline still matches.
func trimmed(s string) string { return strings.TrimSpace(s) }
