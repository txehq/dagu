// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package terminal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	persiststore "github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	terminalpkg "github.com/dagucloud/dagu/v2/internal/service/frontend/terminal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminOnlyHub is a terminal handler with one slot over a real auth service.
type adminOnlyHub struct {
	t       *testing.T
	svc     *authservice.Service
	users   authmodel.UserStore
	manager *terminalpkg.Manager
	handler *terminalpkg.Handler
}

func newAdminOnlyHub(t *testing.T) *adminOnlyHub {
	t.Helper()
	users, err := persiststore.NewUserStore(testutil.NewMemoryBackend().Collection("users"))
	require.NoError(t, err)
	secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
	require.NoError(t, err)
	svc := authservice.New(users, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4})
	// OIDC sessions are on, and every session is in order: a refusal below
	// is about the user, not about a session.
	svc.SetSessionChecker(fixedSession{})
	manager := terminalpkg.NewManager(context.Background(), 1)
	return &adminOnlyHub{t: t, svc: svc, users: users, manager: manager,
		handler: terminalpkg.NewHandler(svc, nil, nil, manager, "/bin/sh")}
}

// ask asks for a terminal with a token. The recorder cannot be upgraded to a
// WebSocket, so a request that got as far as the upgrade is not answered
// with any of the refusals below.
func (h *adminOnlyHub) ask(token string) *httptest.ResponseRecorder {
	target := "/api/v1/terminal/ws"
	if token != "" {
		target += "?token=" + url.QueryEscape(token)
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	return recorder
}

// slotIsFree reports that the hub's one terminal slot was not taken.
func (h *adminOnlyHub) slotIsFree() {
	h.t.Helper()
	lease, err := h.manager.Acquire()
	require.NoError(h.t, err, "a refused request took the terminal slot")
	lease.Release()
}

func (h *adminOnlyHub) builtin(name string, role authmodel.Role) *authmodel.User {
	h.t.Helper()
	user, err := h.svc.CreateUser(context.Background(), authservice.CreateUserInput{Username: name, Password: "password123", Role: role})
	require.NoError(h.t, err)
	return user
}

func (h *adminOnlyHub) token(user *authmodel.User) string {
	h.t.Helper()
	token, err := h.svc.GenerateToken(user)
	require.NoError(h.t, err)
	return token.Token
}

// The terminal is a shell as the hub's own account. Only an administrator
// gets one: every other role is refused before a slot is taken, the
// connection upgraded or a shell started, however they signed in.
func TestTerminal_OnlyAnAdministratorGetsATerminal(t *testing.T) {
	t.Parallel()
	hub := newAdminOnlyHub(t)

	for _, role := range []authmodel.Role{
		authmodel.RoleManager, authmodel.RoleDeveloper, authmodel.RoleOperator, authmodel.RoleViewer,
	} {
		response := hub.ask(hub.token(hub.builtin("builtin-"+role.String(), role)))
		assert.Equal(t, http.StatusForbidden, response.Code, "builtin %s", role)
		hub.slotIsFree()

		// The same role, signed in through OIDC with a session in order.
		user := authmodel.NewUser("oidc-"+role.String(), "", role)
		user.AuthProvider = authmodel.AuthProviderOIDC
		require.NoError(t, hub.users.Create(context.Background(), user))
		token, err := hub.svc.GenerateSessionToken(user, "0123456789abcdef0123456789abcdef", time.Now().Add(time.Hour))
		require.NoError(t, err)
		response = hub.ask(token.Token)
		assert.Equal(t, http.StatusForbidden, response.Code, "OIDC %s", role)
		hub.slotIsFree()
	}

	// Every role there is was tried: a new one has to be decided here.
	for _, role := range []authmodel.Role{
		authmodel.RoleAdmin, authmodel.RoleManager, authmodel.RoleDeveloper, authmodel.RoleOperator, authmodel.RoleViewer,
	} {
		assert.Equal(t, role == authmodel.RoleAdmin, role.IsAdmin(), "%s", role)
	}

	// What is not a signed-in user at all is not let in either.
	assert.Equal(t, http.StatusUnauthorized, hub.ask("").Code, "no token")
	assert.Equal(t, http.StatusUnauthorized, hub.ask("dagu_0123456789abcdef0123456789abcdef").Code, "an API key")
	assert.Equal(t, http.StatusUnauthorized, hub.ask("not-a-token").Code, "not a token")
	hub.slotIsFree()
}

// The role that counts is the one the user has now, not the one they had
// when the token was issued: an administrator who has been demoted is
// refused the next terminal on the token they already hold.
func TestTerminal_ADemotedAdministratorGetsNoNewTerminal(t *testing.T) {
	t.Parallel()
	hub := newAdminOnlyHub(t)
	admin := hub.builtin("admin", authmodel.RoleAdmin)
	token := hub.token(admin)

	// As an administrator the request gets past the role check, as far as
	// the upgrade, which a recorder cannot do.
	asAdmin := hub.ask(token)
	require.NotEqual(t, http.StatusForbidden, asAdmin.Code)
	require.NotEqual(t, http.StatusUnauthorized, asAdmin.Code)

	viewer := authmodel.RoleViewer
	_, err := hub.svc.UpdateUser(context.Background(), admin.ID, authservice.UpdateUserInput{Role: &viewer})
	require.NoError(t, err)

	assert.Equal(t, http.StatusForbidden, hub.ask(token).Code)
	hub.slotIsFree()
}
