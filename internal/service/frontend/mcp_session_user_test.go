// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// mcpHub is the hub's real MCP route in one authentication mode.
type mcpHub struct {
	t    *testing.T
	svc  *authservice.Service
	http *httptest.Server
}

func newMCPHub(t *testing.T, mode config.AuthMode) *mcpHub {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.Auth.Mode = mode
	cfg.Server.Auth.Basic.Username, cfg.Server.Auth.Basic.Password = "operator", "basic-password"
	hub := &mcpHub{t: t}
	srv := &Server{config: cfg, apiV1: &apiv1.API{}}
	if mode == config.AuthModeBuiltin {
		backend := testutil.NewMemoryBackend()
		users, err := persiststore.NewUserStore(backend.Collection("users"))
		require.NoError(t, err)
		keys, err := persiststore.NewAPIKeyStore(backend.Collection("api_keys"))
		require.NoError(t, err)
		secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
		require.NoError(t, err)
		hub.svc = authservice.New(users, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4},
			authservice.WithAPIKeyStore(keys))
		srv.authService = hub.svc
	}
	router := chi.NewMux()
	srv.setupMCPRoute(testContext(t), router)
	hub.http = httptest.NewServer(router)
	t.Cleanup(func() {
		hub.http.CloseClientConnections()
		hub.http.Close()
	})
	return hub
}

func (h *mcpHub) user(name string, role authmodel.Role) *authmodel.User {
	h.t.Helper()
	user, err := h.svc.CreateUser(testContext(h.t), authservice.CreateUserInput{Username: name, Password: "password123", Role: role})
	require.NoError(h.t, err)
	return user
}

func (h *mcpHub) tokenOf(user *authmodel.User) string {
	h.t.Helper()
	token, err := h.svc.GenerateToken(user)
	require.NoError(h.t, err)
	return "Bearer " + token.Token
}

// mcpAnswer is what the hub answered an MCP request with. A stream that
// opened is closed again at once and reported as such.
type mcpAnswer struct {
	status  int
	session string
	stream  bool
	body    string
}

// ask sends one MCP request with the given Authorization header, on the given
// MCP session if there is one.
func (h *mcpHub) ask(method, authorization, session, body string) mcpAnswer {
	h.t.Helper()
	request, err := http.NewRequest(method, h.http.URL+"/mcp", strings.NewReader(body))
	require.NoError(h.t, err)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	request.Header.Set("Accept", "application/json, text/event-stream")
	if method == http.MethodGet {
		request.Header.Set("Accept", "text/event-stream")
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if session != "" {
		request.Header.Set("Mcp-Session-Id", session)
	}
	response, err := h.http.Client().Do(request)
	require.NoError(h.t, err)
	defer func() { _ = response.Body.Close() }()
	answer := mcpAnswer{status: response.StatusCode, session: response.Header.Get("Mcp-Session-Id")}
	if strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		answer.stream = true
		return answer
	}
	raw, err := io.ReadAll(response.Body)
	require.NoError(h.t, err)
	answer.body = string(raw)
	return answer
}

const (
	mcpInitialize  = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`
	mcpInitialized = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	mcpListTools   = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
)

// open starts an MCP session as the given caller and returns its id.
func (h *mcpHub) open(authorization string) string {
	h.t.Helper()
	initialized := h.ask(http.MethodPost, authorization, "", mcpInitialize)
	require.Equal(h.t, http.StatusOK, initialized.status, initialized.body)
	require.NotEmpty(h.t, initialized.session)
	require.Less(h.t, h.ask(http.MethodPost, authorization, initialized.session, mcpInitialized).status, 300)
	return initialized.session
}

// works reports that the caller can use the session.
func (h *mcpHub) works(authorization, session string) {
	h.t.Helper()
	listed := h.ask(http.MethodPost, authorization, session, mcpListTools)
	require.Equal(h.t, http.StatusOK, listed.status, listed.body)
	require.Contains(h.t, listed.body, `"tools"`)
}

// refused reports that the caller can do nothing with the session: not send
// a request on it, not hold its stream, not end it.
func (h *mcpHub) refused(authorization, session string, why string) {
	h.t.Helper()
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		body := ""
		if method == http.MethodPost {
			body = mcpListTools
		}
		answer := h.ask(method, authorization, session, body)
		assert.Equal(h.t, http.StatusForbidden, answer.status, "%s %s: %s", why, method, answer.body)
		assert.False(h.t, answer.stream, "%s %s: the stream was opened", why, method)
	}
}

// An MCP session belongs to the caller who created it. Another caller who
// has a credential of their own and knows the session's id can neither use
// it, nor listen on it, nor end it, and it goes on working for its owner.
func TestAnMCPSessionBelongsToTheCallerWhoCreatedIt(t *testing.T) {
	t.Parallel()
	hub := newMCPHub(t, config.AuthModeBuiltin)
	alice, bob := hub.user("alice", authmodel.RoleAdmin), hub.user("bob", authmodel.RoleViewer)
	aliceToken, bobToken := hub.tokenOf(alice), hub.tokenOf(bob)

	session := hub.open(aliceToken)
	hub.works(aliceToken, session)

	hub.refused(bobToken, session, "another user")
	hub.refused(hub.tokenOf(hub.user("carol", authmodel.RoleAdmin)), session, "another administrator")
	hub.works(aliceToken, session)

	// The session is its user's, not one token's: the same user with
	// another token, here one for a session of OIDC's, carries on with it,
	// and can hold its stream and end it.
	other, err := hub.svc.GenerateSessionToken(alice, "0123456789abcdef0123456789abcdef", time.Now().Add(time.Hour))
	require.NoError(t, err)
	again := "Bearer " + other.Token
	require.NotEqual(t, aliceToken, again)
	hub.svc.SetSessionChecker(sessionInOrder{})
	hub.works(again, session)
	stream := hub.ask(http.MethodGet, again, session, "")
	require.Equal(t, http.StatusOK, stream.status)
	require.True(t, stream.stream)
	require.Equal(t, http.StatusNoContent, hub.ask(http.MethodDelete, again, session, "").status)
	require.Equal(t, http.StatusNotFound, hub.ask(http.MethodPost, aliceToken, session, mcpListTools).status)

	// A session bob opens is bob's.
	bobs := hub.open(bobToken)
	hub.works(bobToken, bobs)
	hub.refused(aliceToken, bobs, "an administrator on a viewer's session")
}

// sessionInOrder is an OIDC session check that always passes.
type sessionInOrder struct{}

func (sessionInOrder) CheckSession(context.Context, string, *authmodel.User) error { return nil }

// An API key owns the sessions it creates. The user the key belongs to is
// another caller, and so is another key of the same user.
func TestAnMCPSessionOfAnAPIKeyIsNotItsOwnersSession(t *testing.T) {
	t.Parallel()
	hub := newMCPHub(t, config.AuthModeBuiltin)
	alice := hub.user("alice", authmodel.RoleAdmin)
	aliceToken := hub.tokenOf(alice)
	key := func(name string) string {
		created, err := hub.svc.CreateAPIKey(testContext(t), authservice.CreateAPIKeyInput{
			Name: name, Role: authmodel.RoleAdmin,
			AllowedSurfaces:  []authmodel.APIKeySurface{authmodel.APIKeySurfaceMCP},
			AttributionClass: authmodel.APIKeyAttributionUserOwned, OwnerUserID: alice.ID,
		}, alice.ID)
		require.NoError(t, err)
		return "Bearer " + created.FullKey
	}
	first, second := key("first"), key("second")

	ofTheKey := hub.open(first)
	hub.works(first, ofTheKey)
	hub.refused(aliceToken, ofTheKey, "the key's owner on the key's session")
	hub.refused(second, ofTheKey, "another key of the same user")
	hub.works(first, ofTheKey)

	ofTheUser := hub.open(aliceToken)
	hub.refused(first, ofTheUser, "the user's key on the user's session")
	hub.works(aliceToken, ofTheUser)
}

// A hub that authenticates nobody has one caller, and its MCP route works as
// it did: the request carries no bearer token, and a session carries on.
func TestMCPSessionsOnAHubWithoutAuthentication(t *testing.T) {
	t.Parallel()
	hub := newMCPHub(t, config.AuthModeNone)

	session := hub.open("")
	hub.works("", session)
	stream := hub.ask(http.MethodGet, "", session, "")
	require.Equal(t, http.StatusOK, stream.status)
	require.True(t, stream.stream)
	require.Equal(t, http.StatusNoContent, hub.ask(http.MethodDelete, "", session, "").status)
}

// A hub with basic authentication has one user, who presents no bearer token
// at all. The MCP route works for them as it did.
func TestMCPSessionsOnAHubWithBasicAuthentication(t *testing.T) {
	t.Parallel()
	hub := newMCPHub(t, config.AuthModeBasic)
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("operator:basic-password"))

	require.Equal(t, http.StatusUnauthorized, hub.ask(http.MethodPost, "", "", mcpInitialize).status)
	session := hub.open(basic)
	hub.works(basic, session)
	require.Equal(t, http.StatusUnauthorized, hub.ask(http.MethodPost, "", session, mcpListTools).status)
	require.Equal(t, http.StatusNoContent, hub.ask(http.MethodDelete, basic, session, "").status)
}
