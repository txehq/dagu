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

// ask asks for a terminal with a token, by a plain request. One that gets as
// far as the upgrade to a WebSocket is answered 426, which is none of the
// refusals below.
func (h *adminOnlyHub) ask(token string) *httptest.ResponseRecorder {
	target := "/api/v1/terminal/ws"
	if token != "" {
		target += "?token=" + url.QueryEscape(token)
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	return recorder
}

// slotIsFree reports that no refused request has kept the hub's one
// terminal slot.
func (h *adminOnlyHub) slotIsFree() {
	h.t.Helper()
	lease, err := h.manager.Acquire()
	require.NoError(h.t, err, "a refused request kept the terminal slot")
	lease.Release()
}

// withTheSlotTaken runs ask while the hub's one slot is held by someone
// else. A request that is refused for what its user is must be refused that
// way all the same: one that got as far as asking for a slot would be told
// the hub is full instead.
func (h *adminOnlyHub) withTheSlotTaken(ask func()) {
	h.t.Helper()
	lease, err := h.manager.Acquire()
	require.NoError(h.t, err)
	defer lease.Release()
	ask()
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

// The web terminal is a shell as the hub's own account. Only an
// administrator gets one: every other role is refused before a slot is asked
// for, the connection upgraded or a shell started, however they signed in.
// This is about the web terminal, not about every way a command can be run
// on the hub's host: a workflow runs commands too, under its own rules.
func TestTerminal_OnlyAnAdministratorGetsATerminal(t *testing.T) {
	t.Parallel()
	hub := newAdminOnlyHub(t)

	// Every role there is, so that a new one has to be decided here.
	ordinary := 0
	for _, role := range authmodel.AllRoles() {
		if role == authmodel.RoleAdmin {
			require.True(t, role.IsAdmin())
			continue
		}
		ordinary++
		require.False(t, role.IsAdmin(), "%s", role)

		builtin := hub.token(hub.builtin("builtin-"+role.String(), role))
		// The same role, signed in through OIDC with a session in order.
		user := authmodel.NewUser("oidc-"+role.String(), "", role)
		user.AuthProvider = authmodel.AuthProviderOIDC
		require.NoError(t, hub.users.Create(context.Background(), user))
		session, err := hub.svc.GenerateSessionToken(user, "0123456789abcdef0123456789abcdef", time.Now().Add(time.Hour))
		require.NoError(t, err)

		for how, token := range map[string]string{"builtin": builtin, "OIDC": session.Token} {
			assert.Equal(t, http.StatusForbidden, hub.ask(token).Code, "%s %s", how, role)
			hub.slotIsFree()
			hub.withTheSlotTaken(func() {
				assert.Equal(t, http.StatusForbidden, hub.ask(token).Code, "%s %s, with the hub full", how, role)
			})
		}
	}
	require.Equal(t, 4, ordinary, "manager, developer, operator and viewer")

	// What is not a signed-in user at all is not let in either, and is told
	// so before a slot is asked for.
	for what, token := range map[string]string{
		"no token": "", "an API key": "dagu_0123456789abcdef0123456789abcdef", "not a token": "not-a-token",
	} {
		assert.Equal(t, http.StatusUnauthorized, hub.ask(token).Code, what)
		hub.withTheSlotTaken(func() {
			assert.Equal(t, http.StatusUnauthorized, hub.ask(token).Code, "%s, with the hub full", what)
		})
	}
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

	// As an administrator the request gets past the role check and takes a
	// slot: it gets as far as the upgrade, which this plain request is not,
	// and with the hub full it is told so.
	require.Equal(t, http.StatusUpgradeRequired, hub.ask(token).Code)
	hub.withTheSlotTaken(func() {
		require.Equal(t, http.StatusTooManyRequests, hub.ask(token).Code)
	})

	viewer := authmodel.RoleViewer
	_, err := hub.svc.UpdateUser(context.Background(), admin.ID, authservice.UpdateUserInput{Role: &viewer})
	require.NoError(t, err)

	assert.Equal(t, http.StatusForbidden, hub.ask(token).Code)
	hub.withTheSlotTaken(func() {
		assert.Equal(t, http.StatusForbidden, hub.ask(token).Code)
	})
	hub.slotIsFree()
}
