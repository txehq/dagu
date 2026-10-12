// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package license

import (
	"slices"
	"time"
)

// Status describes the current license state without exposing license credentials.
type Status struct {
	Valid       bool
	Plan        string
	Expiry      time.Time
	Features    []string
	GracePeriod bool
	GraceEndsAt time.Time
	Community   bool
	Source      DiscoverySource
	WarningCode string
	Failure     string
	// ForkPolicy is true when a fork policy is configured. Community stays
	// true and Plan stays empty unless a license is loaded as well.
	ForkPolicy bool
	// ForkFeatures lists the gates the fork policy opens. They are kept apart
	// from Features, which holds the claims of a loaded license and nothing else.
	ForkFeatures []string
}

// PublicFeatures returns the feature list shown to clients. The public status
// has one list and no field that says where an entry came from, so it never
// mixes the two: a loaded license reports its own claims, exactly as before,
// and only a server with no license reports what the fork policy opened,
// together with a source that names the policy.
func (s Status) PublicFeatures() []string {
	if s.Community && s.ForkPolicy {
		return append([]string{}, s.ForkFeatures...)
	}
	return s.Features
}

// PublicSource returns the source category shown to clients. It names the
// fork policy only when no license is loaded, so a loaded license keeps
// reporting where it came from. See PublicFeatures.
func (s Status) PublicSource() string {
	switch {
	case s.Community && s.ForkPolicy:
		return ForkPolicySource
	case s.Source.IsEnv():
		return "env"
	case s.Source == SourceNone:
		return ""
	default:
		return "file"
	}
}

// StatusFor returns the current status reported by checker.
func StatusFor(checker Checker) Status {
	status := Status{
		Community: true,
		Features:  []string{},
	}
	if checker == nil {
		return status
	}

	claims := checker.Claims()
	if claims == nil {
		return status
	}

	now := time.Now()
	status.Community = false
	status.Plan = claims.Plan
	status.Features = make([]string, len(claims.Features))
	copy(status.Features, claims.Features)
	status.WarningCode = claims.WarningCode
	status.Valid = claims.ExpiresAt == nil || claims.ExpiresAt.After(now)
	if claims.ExpiresAt != nil {
		status.Expiry = claims.ExpiresAt.Time
		status.GraceEndsAt = claims.ExpiresAt.Add(graceDurationForClaims(claims))
		status.GracePeriod = !status.Valid && now.Before(status.GraceEndsAt)
	}

	return status
}

// Status returns the current license status. The fork policy is reported
// beside the license state and never as part of it.
func (m *Manager) Status() Status {
	status := StatusFor(m.Checker())
	status.Source = m.Source()
	status.Failure = m.Failure()
	policy := m.cfg.ForkPolicy
	status.ForkPolicy = !policy.IsZero()
	status.ForkFeatures = slices.Clone(policy.Features)
	return status
}
