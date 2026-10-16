// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	persiststore "github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	apiv1 "github.com/dagucloud/dagu/v2/internal/service/frontend/api/v1"
)

// terminalWithoutOIDCOrOwners serves the real terminal route of a hub with no
// browser sign-in and no owner registry, the branch that used to register the
// handler bare, and returns a builtin administrator's token.
func terminalWithoutOIDCOrOwners(t *testing.T, passwordDisabled bool) (*httptest.Server, string) {
	t.Helper()
	ctx := testContext(t)
	users, err := persiststore.NewUserStore(testutil.NewMemoryBackend().Collection("users"))
	require.NoError(t, err)
	secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
	require.NoError(t, err)
	svc := authservice.New(users, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4})
	admin, err := svc.CreateUser(ctx, authservice.CreateUserInput{Username: "admin", Password: "password123", Role: authmodel.RoleAdmin})
	require.NoError(t, err)
	// Minted before the switch, as a session that outlived it would be.
	token, err := svc.GenerateToken(admin)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.Server.Auth.Mode = config.AuthModeBuiltin
	cfg.Server.Auth.Builtin.PasswordDisabled = passwordDisabled
	cfg.Server.Terminal.MaxSessions = 2
	cfg.Core.DefaultShell = "/bin/sh"
	srv := &Server{config: cfg, apiV1: &apiv1.API{}, authService: svc, sessionWatchClock: newRouteClock()}
	router := chi.NewMux()
	srv.setupTerminalRoute(ctx, router, "/api/v1")
	ts := httptest.NewServer(router)
	t.Cleanup(func() {
		ts.CloseClientConnections()
		ts.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.terminalManager.Shutdown(shutdownCtx)
	})
	return ts, token.Token
}

func terminalStatus(t *testing.T, ts *httptest.Server, token string) int {
	t.Helper()
	resp, err := http.Get(ts.URL + "/api/v1/terminal/ws?token=" + token)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestPasswordDisabled_TerminalRefusesAPasswordUsersToken(t *testing.T) {
	ts, token := terminalWithoutOIDCOrOwners(t, true)
	assert.Equal(t, http.StatusForbidden, terminalStatus(t, ts, token))
}

func TestPasswordDisabled_OffTheTerminalStillTakesTheAdministrator(t *testing.T) {
	ts, token := terminalWithoutOIDCOrOwners(t, false)
	// Not a WebSocket upgrade, so the handler answers it, but it is not refused.
	assert.NotEqual(t, http.StatusForbidden, terminalStatus(t, ts, token))
	assert.NotEqual(t, http.StatusUnauthorized, terminalStatus(t, ts, token))
}

func TestPasswordDisabled_AnEmptyStoreNeedsNoSetup(t *testing.T) {
	users, err := persiststore.NewUserStore(testutil.NewMemoryBackend().Collection("users"))
	require.NoError(t, err)
	secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
	require.NoError(t, err)
	svc := authservice.New(users, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4})
	ctx := testContext(t)

	assert.True(t, (&setupChecker{authSvc: svc}).IsSetupRequired(ctx), "without the switch, an empty store needs setup")
	assert.False(t, (&setupChecker{authSvc: svc, passwordDisabled: true}).IsSetupRequired(ctx),
		"with it, setup would create a password administrator, so none is required")
	complete, err := noPasswordBootstrap(ctx)
	require.NoError(t, err)
	assert.True(t, complete, "identity provider sign-in does not wait for a password administrator")
}
