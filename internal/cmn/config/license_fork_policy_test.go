// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_LicenseForkPolicyDefault(t *testing.T) {
	for name, yaml := range map[string]string{
		"NoLicenseSection": "",
		"LicenseWithoutPolicy": `
license:
  cloud_url: https://license.example.com
`,
		"EmptyPolicy": `
license:
  fork_policy: {}
`,
		"EmptyFeatures": `
license:
  fork_policy:
    features: []
`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := loadFromYAML(t, yaml)
			assert.Empty(t, cfg.License.ForkPolicy.Features)
			assert.Nil(t, cfg.License.ForkPolicy.MaxAPIKeys)
		})
	}
}

func TestLoad_LicenseForkPolicyFromYAML(t *testing.T) {
	t.Run("FeaturesAndLimit", func(t *testing.T) {
		cfg := loadFromYAML(t, `
license:
  fork_policy:
    features: [sso, rbac, sso]
    max_api_keys: 10
`)
		assert.Equal(t, []string{"sso", "rbac"}, cfg.License.ForkPolicy.Features)
		require.NotNil(t, cfg.License.ForkPolicy.MaxAPIKeys)
		assert.Equal(t, 10, *cfg.License.ForkPolicy.MaxAPIKeys)
	})

	t.Run("ZeroMeansNoLimitAndIsNotUnset", func(t *testing.T) {
		cfg := loadFromYAML(t, `
license:
  fork_policy:
    max_api_keys: 0
`)
		assert.Empty(t, cfg.License.ForkPolicy.Features)
		require.NotNil(t, cfg.License.ForkPolicy.MaxAPIKeys)
		assert.Equal(t, 0, *cfg.License.ForkPolicy.MaxAPIKeys)
	})

	t.Run("FeaturesAsOneString", func(t *testing.T) {
		cfg := loadFromYAML(t, `
license:
  fork_policy:
    features: "audit, rbac"
`)
		assert.Equal(t, []string{"audit", "rbac"}, cfg.License.ForkPolicy.Features)
		assert.Nil(t, cfg.License.ForkPolicy.MaxAPIKeys)
	})
}

func TestLoad_LicenseForkPolicyFromEnv(t *testing.T) {
	t.Run("Set", func(t *testing.T) {
		cfg := loadWithEnv(t, "", map[string]string{
			"DAGU_LICENSE_FORK_FEATURES":     "sso, audit,",
			"DAGU_LICENSE_FORK_MAX_API_KEYS": " 0 ",
		})
		assert.Equal(t, []string{"sso", "audit"}, cfg.License.ForkPolicy.Features)
		require.NotNil(t, cfg.License.ForkPolicy.MaxAPIKeys)
		assert.Equal(t, 0, *cfg.License.ForkPolicy.MaxAPIKeys)
	})

	t.Run("OverridesFile", func(t *testing.T) {
		cfg := loadWithEnv(t, `
license:
  fork_policy:
    features: [sso]
    max_api_keys: 3
`, map[string]string{
			"DAGU_LICENSE_FORK_FEATURES":     "rbac",
			"DAGU_LICENSE_FORK_MAX_API_KEYS": "7",
		})
		assert.Equal(t, []string{"rbac"}, cfg.License.ForkPolicy.Features)
		require.NotNil(t, cfg.License.ForkPolicy.MaxAPIKeys)
		assert.Equal(t, 7, *cfg.License.ForkPolicy.MaxAPIKeys)
	})
}

// A value the loader cannot read exactly must stop the load. Nothing here may
// fall back to "no policy", and nothing may be converted to a nearby value.
func TestLoad_LicenseForkPolicyRefused(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		env  map[string]string
		want string
	}{
		{
			name: "UnknownFeature",
			yaml: "license:\n  fork_policy:\n    features: [sso, incidents]\n",
			want: `license.fork_policy.features: unknown feature "incidents" (allowed: audit, rbac, sso)`,
		},
		{
			name: "FeatureInAnotherCase",
			yaml: "license:\n  fork_policy:\n    features: [SSO]\n",
			want: `unknown feature "SSO"`,
		},
		{
			name: "Wildcard",
			yaml: "license:\n  fork_policy:\n    features: [\"*\"]\n",
			want: `unknown feature "*"`,
		},
		{
			name: "FeatureNotAString",
			yaml: "license:\n  fork_policy:\n    features: [sso, 1]\n",
			want: "license.fork_policy.features: every entry must be a feature name",
		},
		{
			name: "EmptyFeatureName",
			yaml: "license:\n  fork_policy:\n    features: [sso, \"\"]\n",
			want: "license.fork_policy.features: a feature name is empty",
		},
		{
			name: "FeaturesNotAList",
			yaml: "license:\n  fork_policy:\n    features: true\n",
			want: "license.fork_policy.features must be a list of feature names",
		},
		{
			name: "FeaturesAsMapping",
			yaml: "license:\n  fork_policy:\n    features:\n      sso: true\n",
			want: "license.fork_policy.features must be a list of feature names",
		},
		{
			name: "UnknownFeatureFromEnv",
			env:  map[string]string{"DAGU_LICENSE_FORK_FEATURES": "sso,everything"},
			want: `unknown feature "everything"`,
		},
		{
			name: "NegativeLimit",
			yaml: "license:\n  fork_policy:\n    max_api_keys: -1\n",
			want: "license.fork_policy.max_api_keys must be 0 (no limit) or a positive number, got -1",
		},
		{
			name: "FractionalLimit",
			yaml: "license:\n  fork_policy:\n    max_api_keys: 2.5\n",
			want: "license.fork_policy.max_api_keys must be a whole number",
		},
		{
			name: "BooleanLimit",
			yaml: "license:\n  fork_policy:\n    max_api_keys: true\n",
			want: "license.fork_policy.max_api_keys must be a whole number",
		},
		{
			name: "WordLimit",
			yaml: "license:\n  fork_policy:\n    max_api_keys: unlimited\n",
			want: "license.fork_policy.max_api_keys must be a whole number",
		},
		{
			name: "WordLimitFromEnv",
			env:  map[string]string{"DAGU_LICENSE_FORK_MAX_API_KEYS": "many"},
			want: "license.fork_policy.max_api_keys must be a whole number",
		},
		{
			name: "FractionalLimitFromEnv",
			env:  map[string]string{"DAGU_LICENSE_FORK_MAX_API_KEYS": "2.0"},
			want: "license.fork_policy.max_api_keys must be a whole number",
		},
		{
			name: "UnknownKey",
			yaml: "license:\n  fork_policy:\n    feature: [sso]\n",
			want: `license.fork_policy: unknown key "feature" (allowed: features, max_api_keys)`,
		},
		{
			name: "IncidentsKey",
			yaml: "license:\n  fork_policy:\n    features: [sso]\n    incidents: true\n",
			want: `license.fork_policy: unknown key "incidents"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			err := loadWithErrorFromYAML(t, tt.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

// The scheduler, worker and coordinator do not read the license section, so a
// policy in a shared config file must neither apply to them nor stop them.
func TestLoad_LicenseForkPolicyOnlyWhereLicenseIsLoaded(t *testing.T) {
	for _, service := range []Service{ServiceScheduler, ServiceWorker, ServiceCoordinator} {
		cfg := loadFromYAMLForService(t, service, `
license:
  fork_policy:
    features: [sso]
    max_api_keys: 4
`)
		assert.Empty(t, cfg.License.ForkPolicy.Features)
		assert.Nil(t, cfg.License.ForkPolicy.MaxAPIKeys)
	}

	cfg := loadFromYAMLForService(t, ServiceServer, `
license:
  fork_policy:
    features: [sso]
    max_api_keys: 4
`)
	assert.Equal(t, []string{"sso"}, cfg.License.ForkPolicy.Features)
	require.NotNil(t, cfg.License.ForkPolicy.MaxAPIKeys)
	assert.Equal(t, 4, *cfg.License.ForkPolicy.MaxAPIKeys)
}

func loadFromYAMLForService(t *testing.T, service Service, yamlContent string) *Config {
	t.Helper()

	configFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0600))
	return testLoad(t, WithConfigFile(configFile), WithService(service))
}
