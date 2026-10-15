// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

func listedMachines(t *testing.T, w *twoOwners, ctx context.Context) map[string]apigen.TxeMachineSummary {
	t.Helper()
	resp, err := w.api.ListTxeMachines(ctx, apigen.ListTxeMachinesRequestObject{})
	require.NoError(t, err)
	out := map[string]apigen.TxeMachineSummary{}
	for _, m := range resp.(apigen.ListTxeMachines200JSONResponse).Machines {
		out[m.MachineId] = m
	}
	return out
}

// Each caller is listed the machines owner view lets it see, and only a
// person of the machine's owner is told how many applications wait.
func TestTxeMachinesAreListedByOwner(t *testing.T) {
	for _, mode := range []string{"", "observe", "enforce"} {
		t.Run("mode="+mode, func(t *testing.T) {
			w := newTwoOwners(t, mode)
			ctx := context.Background()
			system := registry.Actor{Kind: registry.ActorSystem, ID: "test"}
			mint := func() string {
				id, err := registry.NewID(registry.PrefixMachine, time.Now())
				require.NoError(t, err)
				return id
			}
			// A second machine for A, and applications waiting on A's
			// machines and on B's: one fresh, one whose credential has
			// expired since.
			second := mint()
			_, err := w.reg.CreateMachine(ctx, registry.Machine{MachineID: second, OwnerID: w.ownerA, DisplayName: "desktop"}, system)
			require.NoError(t, err)
			// An application comes from an identity bound to the machine's
			// owner, under a client not yet enrolled.
			apply := func(subject, client, machine string, expires time.Time) {
				p := authn.Principal{Identity: authn.Identity{Issuer: ownersIssuer, Subject: subject}, Class: authn.ClassWorker,
					ClientID: client, Expires: expires}
				_, err := w.svc.Store().ApplyForEnrolment(ctx, p, machine)
				require.NoError(t, err)
			}
			apply("a", "dagu-worker-new-a", w.machineA, time.Now().Add(time.Hour))
			apply("b", "dagu-worker-new-b", w.machineB, time.Now().Add(time.Hour))
			apply("a", "dagu-worker-soon-a", second, time.Now().Add(150*time.Millisecond))
			time.Sleep(200 * time.Millisecond)

			personA := listedMachines(t, w, w.personA)
			require.Len(t, personA, 2)
			require.NotContains(t, personA, w.machineB, "another owner's machine is not told to exist")
			require.Equal(t, 1, *personA[w.machineA].PendingApplications)
			require.Equal(t, 0, *personA[second].PendingApplications, "an expired application is not pending")
			require.Equal(t, w.ownerA, personA[w.machineA].OwnerId)
			require.Equal(t, "desktop", personA[second].DisplayName)

			personB := listedMachines(t, w, w.personB)
			require.Len(t, personB, 1)
			require.Equal(t, 1, *personB[w.machineB].PendingApplications)

			// The owner's cli sees the machines, not the counts; a
			// machine's own credential sees that machine only.
			cliA := listedMachines(t, w, w.cliA)
			require.Len(t, cliA, 2)
			require.Nil(t, cliA[w.machineA].PendingApplications)
			reviewerA := listedMachines(t, w, w.reviewerA)
			require.Len(t, reviewerA, 1)
			require.Contains(t, reviewerA, w.machineA)
			require.Nil(t, reviewerA[w.machineA].PendingApplications)

			// Unbound, a person or a token: nothing at all.
			unboundPerson := auth.WithUser(ctx, &auth.User{Username: "user-z", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderOIDC,
				OIDCIssuer: ownersIssuer, OIDCSubject: "z"})
			require.Empty(t, listedMachines(t, w, unboundPerson))
			require.Empty(t, listedMachines(t, w, w.nobody))

			// The platform administrator sees every machine, and approves
			// nothing for an owner, so no counts.
			admin := listedMachines(t, w, w.admin)
			require.Len(t, admin, 3)
			require.Nil(t, admin[w.machineB].PendingApplications)

			// A legacy key sees what the mode lets it: everything in off
			// and observe, no owner's machine in enforce.
			legacy := listedMachines(t, w, w.legacy)
			if mode == "enforce" {
				require.Empty(t, legacy)
			} else {
				require.Len(t, legacy, 3)
			}
			for _, m := range legacy {
				require.Nil(t, m.PendingApplications)
			}
		})
	}
}

// An application already approved is not pending: one whose credential is
// the machine's active enrolment for its class. Another client's application
// of the same class still is, and a revoked enrolment approves nothing.
func TestTxeMachinesPendingExcludesEnrolledApplications(t *testing.T) {
	w := newTwoOwners(t, "")
	ctx := context.Background()
	// A new machine of A's, not yet enrolled.
	machine, err := registry.NewID(registry.PrefixMachine, time.Now())
	require.NoError(t, err)
	_, err = w.reg.CreateMachine(ctx, registry.Machine{MachineID: machine, OwnerID: w.ownerA, DisplayName: "new"},
		registry.Actor{Kind: registry.ActorSystem, ID: "test"})
	require.NoError(t, err)
	apply := func(client string) authn.Identity {
		id := authn.Identity{Issuer: ownersIssuer, Subject: "a"}
		_, err := w.svc.Store().ApplyForEnrolment(ctx, authn.Principal{Identity: id, Class: authn.ClassWorker, ClientID: client,
			Expires: time.Now().Add(time.Hour)}, machine)
		require.NoError(t, err)
		return id
	}
	pending := func() int {
		return *listedMachines(t, w, w.personA)[machine].PendingApplications
	}
	seen := apply("dagu-worker-first")
	require.Equal(t, 1, pending())

	scope, err := w.svc.Scope(ctx, txeauth.Classify(w.personA))
	require.NoError(t, err)
	_, err = w.svc.Store().EnrolFromApplication(ctx, scope, machine, authn.ClassWorker, "dagu-worker-first", seen)
	require.NoError(t, err)
	require.Zero(t, pending(), "the approved application is not pending")

	apply("dagu-worker-second")
	require.Equal(t, 1, pending(), "another client's application of the same class still waits")

	_, err = w.svc.Store().RevokeEnrolment(ctx, scope, machine, authn.ClassWorker, "lost")
	require.NoError(t, err)
	require.Equal(t, 2, pending(), "a revoked enrolment approves nothing")
}
