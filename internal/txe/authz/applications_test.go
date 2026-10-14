// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

func TestApproveBindingRequestNamesTheRequestRead(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	alice := person("alice")
	_, err := f.store.RequestBinding(ctx, alice, Shown{Username: "alice"})
	require.NoError(t, err)

	pending, err := f.store.PendingRequests(ctx)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, 1, pending[0].Generation)

	// An approval naming another generation than the one on file changes
	// nothing.
	_, err = f.store.ApproveBindingRequest(ctx, f.admin, alice.Identity, ownerA, 2)
	require.Equal(t, CodeConflict, CodeOf(err))
	scope := f.resolve(alice)
	require.Equal(t, ScopeUnbound, scope.Kind())

	b, err := f.store.ApproveBindingRequest(ctx, f.admin, alice.Identity, ownerA, 1)
	require.NoError(t, err)
	require.Equal(t, ownerA, b.OwnerID)
	// A replay with the same request returns the binding that stands.
	again, err := f.store.ApproveBindingRequest(ctx, f.admin, alice.Identity, ownerA, 1)
	require.NoError(t, err)
	require.Equal(t, b.Generation, again.Generation)
	pending, err = f.store.PendingRequests(ctx)
	require.NoError(t, err)
	require.Empty(t, pending)

	_, err = f.store.ApproveBindingRequest(ctx, f.admin, alice.Identity, ownerA, 0)
	require.Equal(t, CodeInvalid, CodeOf(err))
	require.Equal(t, BindingID(alice.Identity), BindingID(authn.Identity{Issuer: issuer, Subject: "alice"}))
	require.NotEqual(t, BindingID(alice.Identity), BindingID(authn.Identity{Issuer: otherIssuer, Subject: "alice"}))
}

func TestSharesReceivedAndShareID(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.bind("alice", ownerA)
	f.bind("bob", ownerB)
	share, err := f.store.GrantShare(ctx, a, ShareGrant{Resource: ResourceRef{Kind: KindJob, ID: jobA1}, GranteeOwnerID: ownerB,
		Permissions: []Permission{PermissionView}})
	require.NoError(t, err)

	received, err := f.store.SharesReceived(ctx, ownerB)
	require.NoError(t, err)
	require.Len(t, received, 1)
	require.Equal(t, ShareID(share), ShareID(received[0]))
	received, err = f.store.SharesReceived(ctx, ownerA)
	require.NoError(t, err)
	require.Empty(t, received)
}

func TestEnrolmentApplications(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.bind("alice", ownerA)
	worker := f.token(authn.ClassWorker, "alice", "dagu-worker-a1", "s1")

	// Only a machine credential applies, for a registered machine.
	_, err := f.store.ApplyForEnrolment(ctx, f.token(authn.ClassCLI, "alice", "dagu-cli", "s1"), machineA1)
	require.Equal(t, CodeForbidden, CodeOf(err))
	_, err = f.store.ApplyForEnrolment(ctx, worker, "mch_unknown")
	require.Equal(t, CodeNotFound, CodeOf(err))
	// Another owner's machine is answered as one that does not exist.
	_, err = f.store.ApplyForEnrolment(ctx, worker, machineB1)
	require.Equal(t, CodeNotFound, CodeOf(err))
	// So is any machine for an identity bound to nobody.
	_, err = f.store.ApplyForEnrolment(ctx, f.token(authn.ClassWorker, "nobody", "dagu-worker-a1", "s1"), machineA1)
	require.Equal(t, CodeNotFound, CodeOf(err))

	app, err := f.store.ApplyForEnrolment(ctx, worker, machineA1)
	require.NoError(t, err)
	require.Equal(t, machineA1, app.MachineID)
	apps, err := f.store.EnrolmentApplications(ctx, machineA1)
	require.NoError(t, err)
	require.Len(t, apps, 1)
	// Applying grants nothing.
	require.Equal(t, ScopeUnbound, f.resolve(worker).Kind())

	// Only the machine owner's person approves.
	b := f.bind("bob", ownerB)
	_, err = f.store.EnrolFromApplication(ctx, b, machineA1, authn.ClassWorker, "dagu-worker-a1", worker.Identity)
	require.Equal(t, CodeNotFound, CodeOf(err))
	absent, err := f.store.EnrolFromApplication(ctx, b, machineA1, authn.ClassWorker, "no-such-client", worker.Identity)
	require.Nil(t, absent)
	// Another owner learns nothing about the applications on file: a wrong
	// identity, an absent application and (below) a stale one all give the
	// same answer.
	_, otherIdentity := f.store.EnrolFromApplication(ctx, b, machineA1, authn.ClassWorker, "dagu-worker-a1", authn.Identity{Issuer: issuer, Subject: "mallory"})
	require.Equal(t, CodeNotFound, CodeOf(otherIdentity))
	require.Equal(t, CodeOf(err), CodeOf(otherIdentity))
	_, err = f.store.EnrolFromApplication(ctx, f.resolve(f.token(authn.ClassCLI, "alice", "dagu-cli", "s1")), machineA1, authn.ClassWorker, "dagu-worker-a1", worker.Identity)
	require.Equal(t, CodeForbidden, CodeOf(err))

	// An approval naming another identity than the one on file is refused.
	_, err = f.store.EnrolFromApplication(ctx, a, machineA1, authn.ClassWorker, "dagu-worker-a1", authn.Identity{Issuer: issuer, Subject: "mallory"})
	require.Equal(t, CodeConflict, CodeOf(err))

	// Once the credential on file has expired, approval waits for a fresh
	// application.
	f.clock.Advance(6 * time.Minute)
	_, err = f.store.EnrolFromApplication(ctx, a, machineA1, authn.ClassWorker, "dagu-worker-a1", worker.Identity)
	require.Equal(t, CodeStale, CodeOf(err))
	_, err = f.store.EnrolFromApplication(ctx, b, machineA1, authn.ClassWorker, "dagu-worker-a1", worker.Identity)
	require.Equal(t, CodeNotFound, CodeOf(err), "another owner is not told the application is stale")
	fresh := f.token(authn.ClassWorker, "alice", "dagu-worker-a1", "s1")
	_, err = f.store.ApplyForEnrolment(ctx, fresh, machineA1)
	require.NoError(t, err)
	enrolment, err := f.store.EnrolFromApplication(ctx, a, machineA1, authn.ClassWorker, "dagu-worker-a1", worker.Identity)
	require.NoError(t, err)
	require.Equal(t, StateActive, enrolment.State)
	require.Equal(t, ScopeMachine, f.resolve(fresh).Kind())

	// An enrolled credential has nothing to apply for.
	_, err = f.store.ApplyForEnrolment(ctx, fresh, machineA1)
	require.Equal(t, CodeConflict, CodeOf(err))
	_, err = f.store.EnrolFromApplication(ctx, a, machineA1, authn.ClassReviewer, "dagu-worker-a1", worker.Identity)
	require.Equal(t, CodeNotFound, CodeOf(err))
}

// A credential with no expiry would never go stale: it is not stored, and
// not approved.
func TestEnrolmentApplicationNeedsAnExpiry(t *testing.T) {
	f := newFixture(t)
	f.bind("alice", ownerA)
	forever := f.token(authn.ClassWorker, "alice", "dagu-worker-a1", "s1")
	forever.Expires = time.Time{}
	_, err := f.store.ApplyForEnrolment(context.Background(), forever, machineA1)
	require.Equal(t, CodeInvalid, CodeOf(err))
	apps, err := f.store.EnrolmentApplications(context.Background(), machineA1)
	require.NoError(t, err)
	require.Empty(t, apps)
}
