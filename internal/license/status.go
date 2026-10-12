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
}

// PublicSource returns the source category shown to clients. It names the
// fork policy only when no license is loaded, so a loaded license keeps
// reporting where it came from.
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

// Status returns the current license status. Features opened by the fork
// policy are listed with the license's own, because both are enabled.
func (m *Manager) Status() Status {
	status := StatusFor(m.Checker())
	status.Source = m.Source()
	status.Failure = m.Failure()
	policy := m.cfg.ForkPolicy
	status.ForkPolicy = !policy.IsZero()
	for _, feature := range policy.Features {
		if !slices.Contains(status.Features, feature) {
			status.Features = append(status.Features, feature)
		}
	}
	return status
}
