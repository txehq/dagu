// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package license

import (
	"fmt"
	"slices"
	"strings"
)

// ForkPolicySource is the public source category reported when the fork
// policy, and no license, decides what is enabled.
const ForkPolicySource = "txe-fork-policy"

// ForkPolicy is this fork's own configuration for the feature gates that a
// license otherwise decides. It is not a license: it claims no plan, loads no
// claims, and leaves every check of an active license (HasActiveLicense) as it
// is. The zero value changes nothing.
type ForkPolicy struct {
	// Features lists the gates that are open without a license. Only
	// FeatureAudit, FeatureRBAC and FeatureSSO are accepted.
	Features []string
	// MaxAPIKeys replaces the community API key limit when it is set. Zero
	// means no limit. Nil keeps the community limit.
	MaxAPIKeys *int
}

// ForkPolicyFeatures returns the feature names a fork policy may list.
func ForkPolicyFeatures() []string {
	return []string{FeatureAudit, FeatureRBAC, FeatureSSO}
}

// Validate reports a feature the policy may not open, or a negative key limit.
func (p ForkPolicy) Validate() error {
	allowed := ForkPolicyFeatures()
	for _, feature := range p.Features {
		if !slices.Contains(allowed, feature) {
			return fmt.Errorf("fork policy: unknown feature %q (allowed: %s)", feature, strings.Join(allowed, ", "))
		}
	}
	if p.MaxAPIKeys != nil && *p.MaxAPIKeys < 0 {
		return fmt.Errorf("fork policy: API key limit must be 0 (no limit) or more, got %d", *p.MaxAPIKeys)
	}
	return nil
}

// IsZero reports whether the policy changes nothing.
func (p ForkPolicy) IsZero() bool {
	return len(p.Features) == 0 && p.MaxAPIKeys == nil
}

// Enables reports whether the policy opens the gate for feature.
func (p ForkPolicy) Enables(feature string) bool {
	return slices.Contains(p.Features, feature)
}

// normalized returns a copy holding only the accepted features, sorted and
// without repeats, so a policy that was never validated cannot open a gate it
// does not name exactly.
func (p ForkPolicy) normalized() ForkPolicy {
	out := ForkPolicy{}
	for _, feature := range ForkPolicyFeatures() {
		if slices.Contains(p.Features, feature) {
			out.Features = append(out.Features, feature)
		}
	}
	if p.MaxAPIKeys != nil && *p.MaxAPIKeys >= 0 {
		limit := *p.MaxAPIKeys
		out.MaxAPIKeys = &limit
	}
	return out
}

func (p ForkPolicy) clone() ForkPolicy {
	out := ForkPolicy{Features: slices.Clone(p.Features)}
	if p.MaxAPIKeys != nil {
		limit := *p.MaxAPIKeys
		out.MaxAPIKeys = &limit
	}
	return out
}

// forkPolicyChecker answers feature checks from the policy first and defers
// everything else, including the claims that HasActiveLicense reads, to the
// wrapped checker.
type forkPolicyChecker struct {
	Checker
	policy ForkPolicy
}

var _ Checker = (*forkPolicyChecker)(nil)

func (c *forkPolicyChecker) IsFeatureEnabled(feature string) bool {
	return c.policy.Enables(feature) || c.Checker.IsFeatureEnabled(feature)
}

// WithForkPolicy returns a checker that applies policy on top of checker.
// A policy that opens no gate returns checker unchanged.
func WithForkPolicy(checker Checker, policy ForkPolicy) Checker {
	policy = policy.normalized()
	if checker == nil || len(policy.Features) == 0 {
		return checker
	}
	return &forkPolicyChecker{Checker: checker, policy: policy}
}
