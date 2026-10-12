// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"testing"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/license"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLicenseForkPolicy(t *testing.T) {
	t.Parallel()

	t.Run("default", func(t *testing.T) {
		t.Parallel()

		policy := licenseForkPolicy(&config.Config{})
		require.NoError(t, policy.Validate())
		assert.True(t, policy.IsZero())
		assert.Equal(t, "community limit", forkPolicyAPIKeyLimitText(policy))
	})

	t.Run("configured", func(t *testing.T) {
		t.Parallel()

		limit := 0
		cfg := &config.Config{}
		cfg.License.ForkPolicy.Features = []string{config.LicenseForkFeatureSSO, config.LicenseForkFeatureAudit}
		cfg.License.ForkPolicy.MaxAPIKeys = &limit

		policy := licenseForkPolicy(cfg)
		require.NoError(t, policy.Validate())
		assert.Equal(t, []string{license.FeatureSSO, license.FeatureAudit}, policy.Features)
		assert.Equal(t, "no limit", forkPolicyAPIKeyLimitText(policy))

		// The policy handed to the manager does not share memory with the config.
		limit = 7
		cfg.License.ForkPolicy.Features[0] = config.LicenseForkFeatureRBAC
		assert.Equal(t, []string{license.FeatureSSO, license.FeatureAudit}, policy.Features)
		assert.Equal(t, 0, *policy.MaxAPIKeys)
	})

	t.Run("finite limit", func(t *testing.T) {
		t.Parallel()

		limit := 12
		assert.Equal(t, "12", forkPolicyAPIKeyLimitText(license.ForkPolicy{MaxAPIKeys: &limit}))
	})
}
