// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// ssoAdmin is the browser session of the identity subject that the
// configuration names a platform administrator, as TxePlatformAdminSession
// leaves it for the handlers.
func ssoAdmin(subject string) context.Context {
	user := &auth.User{Username: "admin-" + subject, Role: auth.RoleAdmin, WorkspaceAccess: auth.AllWorkspaceAccess(),
		AuthProvider: auth.AuthProviderOIDC, OIDCIssuer: ownersIssuer, OIDCSubject: subject}
	return txeauth.WithPlatformAdminSession(auth.WithUser(context.Background(), user),
		authn.Identity{Issuer: ownersIssuer, Subject: subject})
}

func txeIdentityOf(t *testing.T, a *API, ctx context.Context) apigen.TxeIdentity {
	t.Helper()
	resp, err := a.GetTxeIdentity(ctx, apigen.GetTxeIdentityRequestObject{})
	require.NoError(t, err)
	return apigen.TxeIdentity(resp.(apigen.GetTxeIdentity200JSONResponse))
}

// The listed administrator whose identity is bound to owner A approves A's
// machine's enrolment and is told its pending applications, as A's person
// is; it gets nothing of the kind for B's machine. Its own command line is
// still only A's cli. In every mode (TXE-4710).
func TestTxeBoundSSOAdministratorActsAsItsOwnersPerson(t *testing.T) {
	for _, mode := range []string{"", "enforce"} {
		t.Run("mode="+mode, func(t *testing.T) {
			w := newTwoOwners(t, mode)
			ctx := context.Background()
			admin := ssoAdmin("a")

			got := txeIdentityOf(t, w.api, admin)
			require.Equal(t, apigen.TxeIdentityPrincipalClassPlatformAdmin, got.Principal.Class)
			require.Equal(t, ownersIssuer, *got.Principal.Issuer)
			require.Equal(t, "a", *got.Principal.Subject)
			require.True(t, got.PlatformAdmin)
			require.True(t, got.IsPerson)
			require.Equal(t, apigen.TxeIdentityStateBound, got.State)
			require.Equal(t, apigen.TxeIdentityScopeKindPlatformAdmin, got.Scope.Kind)
			require.Len(t, got.Owners, 1)
			require.Equal(t, w.ownerA, got.Owners[0].OwnerId)

			// A new machine of A's, not yet enrolled, and applications
			// waiting on it and on B's.
			machineA, err := registry.NewID(registry.PrefixMachine, time.Now())
			require.NoError(t, err)
			_, err = w.reg.CreateMachine(ctx, registry.Machine{MachineID: machineA, OwnerID: w.ownerA, DisplayName: "desktop"},
				registry.Actor{Kind: registry.ActorSystem, ID: "test"})
			require.NoError(t, err)
			apply := func(subject, client, machine string) authn.Identity {
				id := authn.Identity{Issuer: ownersIssuer, Subject: subject}
				_, err := w.svc.Store().ApplyForEnrolment(ctx, authn.Principal{Identity: id, Class: authn.ClassWorker, ClientID: client,
					Expires: time.Now().Add(time.Hour)}, machine)
				require.NoError(t, err)
				return id
			}
			seenA := apply("a", "dagu-worker-new-a", machineA)
			seenB := apply("b", "dagu-worker-new-b", w.machineB)

			machines := listedMachines(t, w, admin)
			require.Len(t, machines, 3, "the administrator sees every machine")
			require.Equal(t, 1, *machines[machineA].PendingApplications, "as A's person")
			require.Nil(t, machines[w.machineB].PendingApplications, "approves nothing for B")

			_, err = w.api.ListTxeEnrolmentApplications(admin, apigen.ListTxeEnrolmentApplicationsRequestObject{MachineId: w.machineB})
			require.Equal(t, http.StatusNotFound, statusOf(err))
			_, err = w.api.EnrolTxeMachine(admin, apigen.EnrolTxeMachineRequestObject{MachineId: w.machineB,
				Body: &apigen.EnrolTxeMachineJSONRequestBody{Class: "worker", ClientId: "dagu-worker-new-b", Issuer: seenB.Issuer, Subject: seenB.Subject}})
			require.Equal(t, http.StatusNotFound, statusOf(err), "B's machine")

			resp, err := w.api.EnrolTxeMachine(admin, apigen.EnrolTxeMachineRequestObject{MachineId: machineA,
				Body: &apigen.EnrolTxeMachineJSONRequestBody{Class: "worker", ClientId: "dagu-worker-new-a", Issuer: seenA.Issuer, Subject: seenA.Subject}})
			require.NoError(t, err)
			require.Equal(t, w.ownerA, resp.(apigen.EnrolTxeMachine200JSONResponse).OwnerId)

			// The same identity's command line is A's cli, never the
			// administrator.
			cli := txeIdentityOf(t, w.api, w.cliA)
			require.Equal(t, apigen.TxeIdentityPrincipalClassCli, cli.Principal.Class)
			require.False(t, cli.PlatformAdmin)
			require.False(t, cli.IsPerson)
			require.Equal(t, apigen.TxeIdentityScopeKindOwner, cli.Scope.Kind)
		})
	}
}

// A listed administrator bound to nobody is the administrator only: it may
// ask to be bound, as a person may, and approves no enrolment meanwhile.
// The builtin administrator is unchanged.
func TestTxeUnboundSSOAdministratorIsNoPerson(t *testing.T) {
	w := newTwoOwners(t, "enforce")
	admin := ssoAdmin("z")

	got := txeIdentityOf(t, w.api, admin)
	require.True(t, got.PlatformAdmin)
	require.False(t, got.IsPerson)
	require.Equal(t, apigen.TxeIdentityStateUnbound, got.State)
	require.Empty(t, got.Owners)

	_, err := w.api.RequestTxeBinding(admin, apigen.RequestTxeBindingRequestObject{})
	require.NoError(t, err)
	got = txeIdentityOf(t, w.api, admin)
	require.Equal(t, apigen.TxeIdentityStatePending, got.State)
	require.NotNil(t, got.Request)

	_, err = w.api.EnrolTxeMachine(admin, apigen.EnrolTxeMachineRequestObject{MachineId: w.machineA,
		Body: &apigen.EnrolTxeMachineJSONRequestBody{Class: "worker", ClientId: "c", Issuer: ownersIssuer, Subject: "z"}})
	require.Equal(t, http.StatusForbidden, statusOf(err))

	builtin := txeIdentityOf(t, w.api, w.admin)
	require.True(t, builtin.PlatformAdmin)
	require.False(t, builtin.IsPerson)
	require.Nil(t, builtin.Principal.Issuer)
	require.Empty(t, builtin.Owners)
	_, err = w.api.RequestTxeBinding(w.admin, apigen.RequestTxeBindingRequestObject{})
	require.Equal(t, http.StatusForbidden, statusOf(err), "the builtin administrator has no identity to bind")
}
