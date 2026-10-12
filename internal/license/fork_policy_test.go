// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package license

import (
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func forkPolicyManager(policy ForkPolicy) *Manager {
	return NewManager(ManagerConfig{ForkPolicy: policy}, nil, nil, nil)
}

func loadTestClaims(m *Manager, expiresAt time.Time, features ...string) {
	zeroGraceDays := 0
	m.state.Update(&LicenseClaims{
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expiresAt)},
		Plan:             "pro",
		Features:         features,
		GraceDays:        &zeroGraceDays,
	}, "token")
}

func TestForkPolicyDefault(t *testing.T) {
	t.Parallel()

	m := forkPolicyManager(ForkPolicy{})

	// With no policy the manager hands out its own state, as it did before.
	assert.Same(t, Checker(m.state), m.Checker())
	for _, feature := range ForkPolicyFeatures() {
		assert.False(t, m.Checker().IsFeatureEnabled(feature), feature)
	}
	assert.True(t, m.ForkPolicy().IsZero())

	status := m.Status()
	assert.True(t, status.Community)
	assert.False(t, status.ForkPolicy)
	assert.Empty(t, status.Features)
	assert.Empty(t, status.ForkFeatures)
	assert.Empty(t, status.PublicFeatures())
	assert.Empty(t, status.PublicSource())
}

func TestForkPolicyOpensOnlyListedGates(t *testing.T) {
	t.Parallel()

	m := forkPolicyManager(ForkPolicy{Features: []string{FeatureSSO, FeatureRBAC}})
	checker := m.Checker()

	assert.True(t, checker.IsFeatureEnabled(FeatureSSO))
	assert.True(t, checker.IsFeatureEnabled(FeatureRBAC))
	assert.False(t, checker.IsFeatureEnabled(FeatureAudit))

	// Nothing about a license is claimed.
	assert.True(t, checker.IsCommunity())
	assert.Empty(t, checker.Plan())
	assert.Nil(t, checker.Claims())
	assert.False(t, checker.IsGracePeriod())
	assert.False(t, HasActiveLicense(checker), "the policy must not unlock what an active license unlocks")
}

func TestForkPolicyStatus(t *testing.T) {
	t.Parallel()

	t.Run("no license", func(t *testing.T) {
		t.Parallel()

		m := forkPolicyManager(ForkPolicy{Features: []string{FeatureSSO, FeatureRBAC}})
		status := m.Status()

		assert.True(t, status.Community)
		assert.False(t, status.Valid)
		assert.Empty(t, status.Plan)
		assert.True(t, status.Expiry.IsZero())
		assert.True(t, status.ForkPolicy)
		assert.Empty(t, status.Features, "Features holds license claims only")
		assert.Equal(t, []string{FeatureRBAC, FeatureSSO}, status.ForkFeatures)
		assert.Equal(t, []string{FeatureRBAC, FeatureSSO}, status.PublicFeatures())
		assert.Equal(t, ForkPolicySource, status.PublicSource())
	})

	t.Run("key limit only", func(t *testing.T) {
		t.Parallel()

		limit := 5
		m := forkPolicyManager(ForkPolicy{MaxAPIKeys: &limit})

		assert.Same(t, Checker(m.state), m.Checker(), "a policy that opens no gate needs no wrapper")
		status := m.Status()
		assert.True(t, status.ForkPolicy)
		assert.Empty(t, status.Features)
		assert.NotNil(t, status.PublicFeatures())
		assert.Empty(t, status.PublicFeatures())
		assert.Equal(t, ForkPolicySource, status.PublicSource())
	})

	// With a license loaded, what clients see is that license and nothing
	// else: a feature the policy opened must not read as a license claim.
	t.Run("with a license", func(t *testing.T) {
		t.Parallel()

		m := forkPolicyManager(ForkPolicy{Features: []string{FeatureSSO, FeatureAudit}})
		loadTestClaims(m, time.Now().Add(time.Hour), FeatureAudit)
		m.setSource(SourceFileJWT)
		status := m.Status()

		assert.False(t, status.Community)
		assert.True(t, status.Valid)
		assert.Equal(t, "pro", status.Plan)
		assert.Equal(t, []string{FeatureAudit}, status.Features)
		assert.Equal(t, []string{FeatureAudit}, status.PublicFeatures())
		assert.Equal(t, "file", status.PublicSource(), "a loaded license keeps reporting its own source")
		assert.True(t, status.ForkPolicy)
		assert.Equal(t, []string{FeatureAudit, FeatureSSO}, status.ForkFeatures)

		assert.True(t, m.Checker().IsFeatureEnabled(FeatureSSO), "the policy still opens its gate")
		assert.True(t, HasActiveLicense(m.Checker()))
	})

	t.Run("with an expired license", func(t *testing.T) {
		t.Parallel()

		m := forkPolicyManager(ForkPolicy{Features: []string{FeatureRBAC}})
		loadTestClaims(m, time.Now().Add(-time.Hour), FeatureAudit)

		assert.True(t, m.Checker().IsFeatureEnabled(FeatureRBAC), "the policy does not expire with a license")
		assert.False(t, m.Checker().IsFeatureEnabled(FeatureAudit))
		assert.False(t, HasActiveLicense(m.Checker()))
	})
}

func TestForkPolicyValidate(t *testing.T) {
	t.Parallel()

	negative, zero, three := -1, 0, 3

	require.NoError(t, ForkPolicy{}.Validate())
	require.NoError(t, ForkPolicy{Features: ForkPolicyFeatures(), MaxAPIKeys: &zero}.Validate())
	require.NoError(t, ForkPolicy{MaxAPIKeys: &three}.Validate())

	err := ForkPolicy{Features: []string{FeatureSSO, "incidents"}}.Validate()
	require.ErrorContains(t, err, `unknown feature "incidents"`)
	require.ErrorContains(t, err, "audit, rbac, sso")

	require.ErrorContains(t, ForkPolicy{Features: []string{"SSO"}}.Validate(), `unknown feature "SSO"`)
	require.ErrorContains(t, ForkPolicy{MaxAPIKeys: &negative}.Validate(), "API key limit")
}

// A policy that reaches the manager without being validated opens only the
// gates it names exactly.
func TestForkPolicyUnvalidated(t *testing.T) {
	t.Parallel()

	negative := -1
	m := forkPolicyManager(ForkPolicy{
		Features:   []string{"incidents", "SSO", "*", FeatureAudit, FeatureAudit},
		MaxAPIKeys: &negative,
	})

	assert.Equal(t, []string{FeatureAudit}, m.ForkPolicy().Features)
	assert.Nil(t, m.ForkPolicy().MaxAPIKeys)
	assert.True(t, m.Checker().IsFeatureEnabled(FeatureAudit))
	for _, feature := range []string{"incidents", "SSO", "*", FeatureSSO, FeatureRBAC, ""} {
		assert.False(t, m.Checker().IsFeatureEnabled(feature), feature)
	}
}

func TestForkPolicyIsCopied(t *testing.T) {
	t.Parallel()

	limit := 3
	features := []string{FeatureSSO}
	m := forkPolicyManager(ForkPolicy{Features: features, MaxAPIKeys: &limit})

	features[0] = FeatureAudit
	limit = 99
	got := m.ForkPolicy()
	got.Features[0] = FeatureRBAC
	*got.MaxAPIKeys = 0

	assert.Equal(t, []string{FeatureSSO}, m.ForkPolicy().Features)
	assert.Equal(t, 3, *m.ForkPolicy().MaxAPIKeys)
	assert.True(t, m.Checker().IsFeatureEnabled(FeatureSSO))
	assert.False(t, m.Checker().IsFeatureEnabled(FeatureAudit))
}

func TestWithForkPolicyNilChecker(t *testing.T) {
	t.Parallel()

	assert.Nil(t, WithForkPolicy(nil, ForkPolicy{Features: []string{FeatureSSO}}))
}

// The config package validates the names and cannot import this package.
func TestForkPolicyFeaturesMatchConfig(t *testing.T) {
	t.Parallel()

	assert.Equal(t, config.LicenseForkFeatures(), ForkPolicyFeatures())
}
