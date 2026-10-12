// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/license"
	"github.com/dagucloud/dagu/v2/internal/service/frontend"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupForkPolicyServer starts a server the way `dagu server` builds it: with
// a license manager, no license loaded, and the given fork policy. The zero
// policy is the default deployment.
func setupForkPolicyServer(t *testing.T, policy license.ForkPolicy) test.Server {
	t.Helper()
	require.NoError(t, policy.Validate())

	server := test.SetupServer(t,
		test.WithConfigMutator(func(cfg *config.Config) {
			cfg.Server.Auth.Mode = config.AuthModeBuiltin
			cfg.Server.Auth.Builtin.Token.Secret = "jwt-secret-key"
			cfg.Server.Auth.Builtin.Token.TTL = 24 * time.Hour
			cfg.Server.Audit.Enabled = true
		}),
		test.WithServerOptions(frontend.WithLicenseManager(
			license.NewManager(license.ManagerConfig{ForkPolicy: policy}, nil, nil, nil),
		)),
	)
	server.Client().Post("/api/v1/auth/setup", api.SetupRequest{
		Username: "admin",
		Password: "adminpass",
	}).ExpectStatus(http.StatusOK).Send(t)
	return server
}

func createForkPolicyTestKeys(t *testing.T, server test.Server, token string, count int) {
	t.Helper()
	for i := 1; i <= count; i++ {
		server.Client().Post("/api/v1/api-keys", newCreateAPIKeyRequest(fmt.Sprintf("key-%d", i), api.UserRoleViewer)).
			WithBearerToken(token).ExpectStatus(http.StatusCreated).Send(t)
	}
}

func createForkPolicyTestUser(t *testing.T, server test.Server, token string, wantStatus int) api.UserResponse {
	t.Helper()
	resp := server.Client().Post("/api/v1/users", api.CreateUserRequest{
		Username: "fork-policy-user",
		Password: "password123",
		Role:     api.UserRoleViewer,
	}).WithBearerToken(token).ExpectStatus(wantStatus).Send(t)

	var created api.UserResponse
	if wantStatus == http.StatusCreated {
		resp.Unmarshal(t, &created)
	}
	return created
}

// With no policy, a server that has a license manager and no license keeps
// every upstream gate shut and the upstream key limit.
func TestForkPolicy_DefaultKeepsGates(t *testing.T) {
	t.Parallel()
	server := setupForkPolicyServer(t, license.ForkPolicy{})
	token := getAdminToken(t, server)

	createForkPolicyTestUser(t, server, token, http.StatusForbidden)
	server.Client().Get("/api/v1/audit").
		WithBearerToken(token).ExpectStatus(http.StatusForbidden).Send(t)
	server.Client().Get("/api/v1/incident-providers").
		WithBearerToken(token).ExpectStatus(http.StatusForbidden).Send(t)

	createForkPolicyTestKeys(t, server, token, 2)
	resp := server.Client().Post("/api/v1/api-keys", newCreateAPIKeyRequest("key-3", api.UserRoleViewer)).
		WithBearerToken(token).ExpectStatus(http.StatusForbidden).Send(t)
	var errResp api.Error
	resp.Unmarshal(t, &errResp)
	assert.Contains(t, errResp.Message, "Community edition supports up to 2 API keys")

	var status api.LicenseStatusResponse
	server.Client().Get("/api/v1/license/status").
		WithBearerToken(token).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &status)
	assert.True(t, status.Community)
	assert.False(t, status.Valid)
	assert.Empty(t, status.Plan)
	assert.Empty(t, status.Features)
	assert.Empty(t, status.Source)
}

func TestForkPolicy_RBACOpensUserManagement(t *testing.T) {
	t.Parallel()
	server := setupForkPolicyServer(t, license.ForkPolicy{Features: []string{license.FeatureRBAC}})
	token := getAdminToken(t, server)

	created := createForkPolicyTestUser(t, server, token, http.StatusCreated)
	userID := created.User.Id
	require.NotEmpty(t, userID)

	role := api.UserRoleOperator
	server.Client().Patch("/api/v1/users/"+userID, api.UpdateUserRequest{Role: &role}).
		WithBearerToken(token).ExpectStatus(http.StatusOK).Send(t)
	server.Client().Delete("/api/v1/users/" + userID).
		WithBearerToken(token).ExpectStatus(http.StatusNoContent).Send(t)

	// The policy named one gate. The others stay shut.
	server.Client().Get("/api/v1/audit").
		WithBearerToken(token).ExpectStatus(http.StatusForbidden).Send(t)
	createForkPolicyTestKeys(t, server, token, 2)
	server.Client().Post("/api/v1/api-keys", newCreateAPIKeyRequest("key-3", api.UserRoleViewer)).
		WithBearerToken(token).ExpectStatus(http.StatusForbidden).Send(t)
}

func TestForkPolicy_AuditOpensAuditLog(t *testing.T) {
	t.Parallel()
	server := setupForkPolicyServer(t, license.ForkPolicy{Features: []string{license.FeatureAudit}})
	token := getAdminToken(t, server)

	// An API key is created so that something is written to the audit log.
	createForkPolicyTestKeys(t, server, token, 1)

	var logs api.AuditLogsResponse
	server.Client().Get("/api/v1/audit").
		WithBearerToken(token).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &logs)
	assert.NotEmpty(t, logs.Entries, "the audit log must be written as well as readable")

	createForkPolicyTestUser(t, server, token, http.StatusForbidden)
}

func TestForkPolicy_APIKeyLimit(t *testing.T) {
	t.Parallel()

	t.Run("no limit", func(t *testing.T) {
		t.Parallel()
		server := setupForkPolicyServer(t, license.ForkPolicy{MaxAPIKeys: new(0)})
		token := getAdminToken(t, server)

		createForkPolicyTestKeys(t, server, token, 10)

		var list api.APIKeysListResponse
		server.Client().Get("/api/v1/api-keys").
			WithBearerToken(token).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &list)
		assert.Len(t, list.ApiKeys, 10)

		// A key limit opens no feature gate.
		createForkPolicyTestUser(t, server, token, http.StatusForbidden)
	})

	t.Run("finite limit", func(t *testing.T) {
		t.Parallel()
		server := setupForkPolicyServer(t, license.ForkPolicy{MaxAPIKeys: new(3)})
		token := getAdminToken(t, server)

		createForkPolicyTestKeys(t, server, token, 3)
		resp := server.Client().Post("/api/v1/api-keys", newCreateAPIKeyRequest("key-4", api.UserRoleViewer)).
			WithBearerToken(token).ExpectStatus(http.StatusForbidden).Send(t)

		var errResp api.Error
		resp.Unmarshal(t, &errResp)
		assert.Equal(t, api.ErrorCodeForbidden, errResp.Code)
		assert.Contains(t, errResp.Message, "up to 3 API keys")
		assert.Contains(t, errResp.Message, "license.fork_policy.max_api_keys")
		assert.NotContains(t, errResp.Message, "Community edition")

		var list api.APIKeysListResponse
		server.Client().Get("/api/v1/api-keys").
			WithBearerToken(token).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &list)
		assert.Len(t, list.ApiKeys, 3)
	})

	t.Run("limit below the community limit", func(t *testing.T) {
		t.Parallel()
		server := setupForkPolicyServer(t, license.ForkPolicy{MaxAPIKeys: new(1)})
		token := getAdminToken(t, server)

		createForkPolicyTestKeys(t, server, token, 1)
		server.Client().Post("/api/v1/api-keys", newCreateAPIKeyRequest("key-2", api.UserRoleViewer)).
			WithBearerToken(token).ExpectStatus(http.StatusForbidden).Send(t)
	})

	t.Run("features without a limit keep the community limit", func(t *testing.T) {
		t.Parallel()
		server := setupForkPolicyServer(t, license.ForkPolicy{Features: license.ForkPolicyFeatures()})
		token := getAdminToken(t, server)

		createForkPolicyTestKeys(t, server, token, 2)
		resp := server.Client().Post("/api/v1/api-keys", newCreateAPIKeyRequest("key-3", api.UserRoleViewer)).
			WithBearerToken(token).ExpectStatus(http.StatusForbidden).Send(t)

		var errResp api.Error
		resp.Unmarshal(t, &errResp)
		assert.Contains(t, errResp.Message, "Community edition supports up to 2 API keys")
	})
}

// Incidents are unlocked by an active license only. The policy lists no such
// feature and must not reach them, whatever else it opens.
func TestForkPolicy_IncidentsStayGated(t *testing.T) {
	t.Parallel()
	server := setupForkPolicyServer(t, license.ForkPolicy{
		Features:   license.ForkPolicyFeatures(),
		MaxAPIKeys: new(0),
	})
	token := getAdminToken(t, server)

	for _, path := range []string{"/api/v1/incident-providers", "/api/v1/incident-policies/global"} {
		server.Client().Get(path).
			WithBearerToken(token).ExpectStatus(http.StatusForbidden).Send(t)
	}
}

func TestForkPolicy_StatusClaimsNoLicense(t *testing.T) {
	t.Parallel()
	server := setupForkPolicyServer(t, license.ForkPolicy{
		Features:   []string{license.FeatureSSO, license.FeatureRBAC},
		MaxAPIKeys: new(0),
	})
	token := getAdminToken(t, server)

	var status api.LicenseStatusResponse
	server.Client().Get("/api/v1/license/status").
		WithBearerToken(token).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &status)

	assert.True(t, status.Community, "no license is loaded")
	assert.False(t, status.Valid)
	assert.Empty(t, status.Plan)
	assert.Empty(t, status.Expiry)
	assert.False(t, status.GracePeriod)
	assert.Empty(t, status.WarningCode)
	assert.Empty(t, status.Error)
	assert.Equal(t, []string{license.FeatureRBAC, license.FeatureSSO}, status.Features)
	assert.Equal(t, license.ForkPolicySource, status.Source)
}
