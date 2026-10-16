// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"context"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	persiststore "github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	apiv1 "github.com/dagucloud/dagu/v2/internal/service/frontend/api/v1"
	frontendauth "github.com/dagucloud/dagu/v2/internal/service/frontend/auth"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// personHub is the hub's real event stream, MCP and terminal routes, as the
// server mounts them, with owner authorization on. It holds two accounts
// that came from the identity provider, one of them given the hub's
// administrator role, and the builtin administrator.
type personHub struct {
	t       *testing.T
	svc     *authservice.Service
	http    *httptest.Server
	person  *authmodel.User
	adminP  *authmodel.User
	builtin *authmodel.User
}

// newPersonHub mounts the routes. browserOIDC says whether browser sign-in
// is configured; persons are refused either way, since a hub token of a
// person outlives a change of that configuration.
func newPersonHub(t *testing.T, browserOIDC bool, opts ...apiv1.APIOption) *personHub {
	t.Helper()
	ctx := testContext(t)
	backend := testutil.NewMemoryBackend()
	users, err := persiststore.NewUserStore(backend.Collection("users"))
	require.NoError(t, err)
	secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
	require.NoError(t, err)
	svc := authservice.New(users, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4})

	h := &personHub{t: t, svc: svc}
	h.builtin, err = svc.CreateUser(ctx, authservice.CreateUserInput{Username: "admin", Password: "password123", Role: authmodel.RoleAdmin})
	require.NoError(t, err)
	oidcUser := func(name, subject string, role authmodel.Role) *authmodel.User {
		u := authmodel.NewUser(name, "", role)
		u.AuthProvider = authmodel.AuthProviderOIDC
		u.OIDCIssuer, u.OIDCSubject = "https://issuer.example/realms/test", subject
		u.WorkspaceAccess = authmodel.AllWorkspaceAccess()
		require.NoError(t, users.Create(ctx, u))
		return u
	}
	h.person = oidcUser("pat", "subject-person", authmodel.RoleViewer)
	h.adminP = oidcUser("ada", "subject-admin", authmodel.RoleAdmin)

	dataDir := t.TempDir()
	reg, err := registry.NewFileStore(dataDir)
	require.NoError(t, err)
	owners, err := txeauth.NewService(config.TXEConfig{}, dataDir, reg)
	require.NoError(t, err)
	api := &apiv1.API{}
	apiv1.WithTxeRegistry(reg)(api)
	apiv1.WithTxeAuth(owners)(api)
	for _, opt := range opts {
		opt(api)
	}

	cfg := &config.Config{}
	cfg.Server.Auth.Mode = config.AuthModeBuiltin
	cfg.Server.Terminal.MaxSessions = 2
	cfg.Core.DefaultShell = "/bin/sh"
	srv := &Server{config: cfg, apiV1: api, authService: svc, sessionWatchClock: newRouteClock()}
	if browserOIDC {
		srv.builtinOIDCCfg = &frontendauth.BuiltinOIDCConfig{AuthService: svc, LoginBasePath: "/"}
	}

	router := chi.NewMux()
	srv.setupSSERoute(ctx, router, "/api/v1")
	srv.setupMCPRoute(ctx, router)
	srv.setupTerminalRoute(ctx, router, "/api/v1")
	h.http = httptest.NewServer(router)
	t.Cleanup(func() {
		h.http.CloseClientConnections()
		h.http.Close()
		if srv.sseMultiplexer != nil {
			srv.sseMultiplexer.Shutdown()
		}
		if srv.appStream != nil {
			srv.appStream.Shutdown()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.terminalManager.Shutdown(shutdownCtx)
	})
	return h
}

func (h *personHub) token(u *authmodel.User) string {
	h.t.Helper()
	token, err := h.svc.GenerateToken(u)
	require.NoError(h.t, err)
	return token.Token
}

// status sends a request and reports the status it was answered with,
// without waiting for a stream to end.
func (h *personHub) status(method, target, bearer, body string, header http.Header) int {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, h.http.URL+target, strings.NewReader(body))
	require.NoError(h.t, err)
	maps.Copy(request.Header, header)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := h.http.Client().Do(request)
	require.NoError(h.t, err)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		_, _ = io.Copy(io.Discard, response.Body)
	}
	return response.StatusCode
}

var personMCPInitialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"route-test","version":"0"}}}`

func mcpHeader() http.Header {
	header := http.Header{}
	header.Set("Accept", "application/json, text/event-stream")
	header.Set("Content-Type", "application/json")
	return header
}

// A person, with or without the hub's administrator role on its account, is
// refused the event stream and MCP through the real routes; the builtin
// administrator is not.
func TestTxePersonIsRefusedTheEventStreamAndMCP(t *testing.T) {
	for _, browserOIDC := range []bool{true, false} {
		h := newPersonHub(t, browserOIDC)
		for _, u := range []*authmodel.User{h.person, h.adminP} {
			bearer := h.token(u)
			require.Equal(t, http.StatusForbidden, h.status(http.MethodGet, "/api/v1/events/stream", bearer, "", nil), u.Username)
			require.Equal(t, http.StatusForbidden, h.status(http.MethodPost, "/api/v1/events/stream/topics", bearer, `{}`, nil), u.Username)
			require.Equal(t, http.StatusForbidden, h.status(http.MethodPost, "/mcp", bearer, personMCPInitialize, mcpHeader()), u.Username)
			// A token in the query string is the same token.
			require.Equal(t, http.StatusForbidden, h.status(http.MethodGet, "/api/v1/events/stream?token="+bearer, "", "", nil), u.Username)
		}
		admin := h.token(h.builtin)
		require.Equal(t, http.StatusOK, h.status(http.MethodGet, "/api/v1/events/stream", admin, "", nil))
		require.Equal(t, http.StatusOK, h.status(http.MethodPost, "/mcp", admin, personMCPInitialize, mcpHeader()))
	}
}

// A person txe.authz.platform_admins names follows the event stream as the
// administrator, and is still refused MCP and the terminal like every other
// identity provider sign-in. A person it does not name is refused all three.
func TestTxePlatformAdminGetsTheEventStreamOnly(t *testing.T) {
	h := newPersonHub(t, true, apiv1.WithTxePlatformAdmins([]config.TXEPlatformAdmin{
		{Issuer: "https://issuer.example/realms/test", Subject: "subject-admin"},
	}))

	listed := h.token(h.adminP)
	require.Equal(t, http.StatusOK, h.status(http.MethodGet, "/api/v1/events/stream", listed, "", nil))
	require.Equal(t, http.StatusOK, h.status(http.MethodGet, "/api/v1/events/stream?token="+listed, "", "", nil))
	require.Equal(t, http.StatusForbidden, h.status(http.MethodPost, "/mcp", listed, personMCPInitialize, mcpHeader()))
	require.Equal(t, http.StatusForbidden, h.status(http.MethodGet, "/api/v1/terminal/ws?token="+listed, "", "", nil))

	unlisted := h.token(h.person)
	require.Equal(t, http.StatusForbidden, h.status(http.MethodGet, "/api/v1/events/stream", unlisted, "", nil))
	require.Equal(t, http.StatusForbidden, h.status(http.MethodPost, "/api/v1/events/stream/topics", unlisted, `{}`, nil))
	require.Equal(t, http.StatusForbidden, h.status(http.MethodPost, "/mcp", unlisted, personMCPInitialize, mcpHeader()))
	require.Equal(t, http.StatusForbidden, h.status(http.MethodGet, "/api/v1/terminal/ws?token="+unlisted, "", "", nil))
}
