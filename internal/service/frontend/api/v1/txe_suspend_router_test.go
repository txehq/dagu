// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/service/frontend"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// suspendHub is a hub in enforce, served through its real router, with two
// owners' machines and their reviewer DAGs on file. The provider identity
// providerToken signs (subject-a) is bound to owner A.
type suspendHub struct {
	server               test.Server
	admin, legacy, cliA  string
	reviewerA, reviewerB string
	machineA             string
}

func newSuspendHub(t *testing.T) suspendHub {
	t.Helper()
	return newOwnerHub(t, config.TXEAuthzModeEnforce)
}

// newOwnerHub is suspendHub's hub in the given authz mode.
func newOwnerHub(t *testing.T, mode string) suspendHub {
	t.Helper()
	jwks := providerKeys(t)
	server := test.SetupServer(t, test.WithConfigMutator(func(cfg *config.Config) {
		cfg.Server.Auth.Mode = config.AuthModeBuiltin
		cfg.Server.Auth.Builtin.Token.Secret = "jwt-secret-key"
		cfg.Server.Auth.Builtin.Token.TTL = 24 * time.Hour
		cfg.TXE.Authz.Mode = mode
		cfg.TXE.Authn = config.TXEAuthnConfig{
			Issuer: providerIssuer, Audience: providerAudience, JWKSURL: jwks + "/certs",
			Clients: []config.TXEAuthnClient{{ID: providerCLI, Class: "cli"}},
		}
	}), test.WithServerOptions(frontend.WithLicenseManager(defaultTestLicenseManager())))
	server.Client().Post("/api/v1/auth/setup", api.SetupRequest{Username: "admin", Password: "adminpass"}).
		ExpectStatus(http.StatusOK).Send(t)
	h := suspendHub{server: server, admin: getAdminToken(t, server), cliA: providerToken(t, time.Now(), 5*time.Minute)}

	server.Client().Post("/api/v1/users", api.CreateUserRequest{Username: "legacy-operator", Password: "legacypass1", Role: api.UserRoleOperator}).
		WithBearerToken(h.admin).ExpectStatus(http.StatusCreated).Send(t)
	var login api.LoginResponse
	server.Client().Post("/api/v1/auth/login", api.LoginRequest{Username: "legacy-operator", Password: "legacypass1"}).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &login)
	h.legacy = login.Token

	// Two owners and their machines, and subject-a bound to A, written
	// where the hub reads them.
	ctx := context.Background()
	dataDir := server.Config.Paths.DataDir
	reg, err := registry.NewFileStore(dataDir)
	require.NoError(t, err)
	owners, err := txeauth.NewService(config.TXEConfig{}, dataDir, reg)
	require.NoError(t, err)
	system := registry.Actor{Kind: registry.ActorSystem, ID: "test"}
	mint := func(p registry.Prefix) string {
		id, err := registry.NewID(p, time.Now())
		require.NoError(t, err)
		return id
	}
	ownerA, ownerB := mint(registry.PrefixOwner), mint(registry.PrefixOwner)
	h.machineA = mint(registry.PrefixMachine)
	machineB := mint(registry.PrefixMachine)
	for _, o := range []struct{ owner, machine string }{{ownerA, h.machineA}, {ownerB, machineB}} {
		_, err := reg.CreateOwner(ctx, registry.Owner{OwnerID: o.owner, DisplayName: o.owner}, system)
		require.NoError(t, err)
		_, err = reg.CreateMachine(ctx, registry.Machine{MachineID: o.machine, OwnerID: o.owner, DisplayName: "laptop"}, system)
		require.NoError(t, err)
	}
	id := authn.Identity{Issuer: providerIssuer, Subject: "subject-a"}
	// A binding is of the identity: the person asks, and its cli token acts
	// for the owner too.
	_, err = owners.Store().RequestBinding(ctx, authn.Principal{Identity: id, Class: authn.ClassPerson}, authz.Shown{})
	require.NoError(t, err)
	_, err = owners.Store().ApproveBinding(ctx, authz.PlatformAdmin("admin"), id, ownerA)
	require.NoError(t, err)

	h.reviewerA, h.reviewerB = txeauth.MachineDAGs(h.machineA)[0], txeauth.MachineDAGs(machineB)[0]
	for name, machine := range map[string]string{h.reviewerA: h.machineA, h.reviewerB: machineB} {
		server.CreateDAGFile(t, server.Config.Paths.DAGsDir, name, []byte(pinnedReviewer(machine)))
	}
	return h
}

func pinnedReviewer(machine string) string {
	return "schedule: \"*/2 * * * *\"\nworker_selector:\n  txe.machine: " + machine + "\nsteps:\n  - name: s\n    run: echo s\n"
}

func (h suspendHub) suspend(t *testing.T, name, bearer string, suspend bool) int {
	t.Helper()
	resp := h.server.Client().Post("/api/v1/dags/"+name+"/suspend", map[string]bool{"suspend": suspend}).
		WithBearerToken(bearer).Send(t)
	return resp.Response.StatusCode()
}

func (h suspendHub) details(t *testing.T, name string) api.GetDAGDetails200JSONResponse {
	t.Helper()
	var got api.GetDAGDetails200JSONResponse
	h.server.Client().Get("/api/v1/dags/"+name).WithBearerToken(h.admin).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &got)
	return got
}

// Under enforce a machine's owner pauses and resumes its machine DAGs'
// schedules with its own bearer, through the real router: the suspension is
// only the scheduler's flag, so the spec and its schedule are kept, and it
// survives the owner reinstalling the DAG. Another owner, a legacy
// credential and the platform administrator may not (TXE-4429).
func TestTxeOwnerSuspendsMachineScheduleThroughTheRouter(t *testing.T) {
	h := newSuspendHub(t)
	specBefore := h.details(t, h.reviewerA).Spec

	require.Equal(t, http.StatusOK, h.suspend(t, h.reviewerA, h.cliA, true), "the owner's cli token suspends")
	require.True(t, h.details(t, h.reviewerA).Suspended)
	require.Equal(t, specBefore, h.details(t, h.reviewerA).Spec, "the spec and its schedule are kept")

	// Reinstalled by its owner while suspended, it stays suspended.
	h.server.Client().Put("/api/v1/dags/"+h.reviewerA+"/spec", api.UpdateDAGSpecJSONRequestBody{Spec: pinnedReviewer(h.machineA)}).
		WithBearerToken(h.cliA).ExpectStatus(http.StatusOK).Send(t)
	require.True(t, h.details(t, h.reviewerA).Suspended, "suspension survives a reinstall")

	require.Equal(t, http.StatusOK, h.suspend(t, h.reviewerA, h.cliA, false), "the owner's cli token resumes")
	require.False(t, h.details(t, h.reviewerA).Suspended)

	// Nobody else changes it.
	require.Equal(t, http.StatusNotFound, h.suspend(t, h.reviewerB, h.cliA, true), "another owner's machine DAG")
	require.Equal(t, http.StatusNotFound, h.suspend(t, h.reviewerA, h.legacy, true), "a legacy credential in enforce")
	require.Equal(t, http.StatusForbidden, h.suspend(t, h.reviewerA, h.admin, true), "the platform administrator holds view only")
	require.False(t, h.details(t, h.reviewerA).Suspended)
	require.False(t, h.details(t, h.reviewerB).Suspended)
}
