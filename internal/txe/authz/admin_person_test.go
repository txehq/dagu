// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// resolveAdmin is the scope of a platform administrator who signed in through
// the identity provider as subject.
func (f *fixture) resolveAdmin(subject string) Scope {
	f.t.Helper()
	scope, err := f.store.ResolvePlatformAdmin(context.Background(), "connor", person(subject).Identity)
	require.NoError(f.t, err)
	return scope
}

// A platform administrator whose identity is bound is also its owner's
// person for viewing, deciding and administering that owner's records, and
// the administrator's own rights come on top. On another owner's records it
// gains nothing beyond the administrator's view (TXE-4710).
func TestBoundPlatformAdministratorIsItsOwnersPerson(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.bind("connor", ownerA)
	admin := f.resolveAdmin("connor")

	assert.Equal(t, ScopePlatformAdmin, admin.Kind())
	assert.Equal(t, ownerA, admin.OwnerID())
	assert.True(t, IsHuman(admin), "its decisions are a person's")
	person, ok := admin.OwnerPerson()
	require.True(t, ok)
	assert.Equal(t, ScopeOwner, person.Kind())

	// The platform, as any administrator.
	assert.True(t, f.enforce(admin, PermissionAdminister, Platform()).Allowed)

	// Its own owner's job and machine: it views, decides and administers as
	// the person, not break-glass. It does not author or execute: those
	// stay with the owner's own credentials.
	machine, err := f.store.Machine(context.Background(), machineA1)
	require.NoError(t, err)
	own, err := OwnData(admin)
	require.NoError(t, err)
	for _, res := range []Resource{f.job(jobA1), machine, own} {
		for _, permission := range []Permission{PermissionView, PermissionApprove, PermissionAdminister} {
			decision := f.enforce(admin, permission, res)
			assert.True(t, decision.Allowed, "%s %s", permission, res.ID())
			assert.False(t, decision.BreakGlass, "%s %s: its own owner's data is not break-glass", permission, res.ID())
			assert.Equal(t, ReasonOwner, decision.Reason, permission)
		}
		for _, permission := range []Permission{PermissionAuthor, PermissionExecute} {
			assert.False(t, f.enforce(admin, permission, res).Allowed, "%s %s", permission, res.ID())
		}
	}

	// Another owner's: view as break-glass, and nothing else.
	view := f.enforce(admin, PermissionView, f.job(jobB1))
	assert.True(t, view.Allowed)
	assert.True(t, view.BreakGlass)
	for _, permission := range []Permission{PermissionAuthor, PermissionExecute, PermissionApprove, PermissionAdminister} {
		assert.False(t, f.enforce(admin, permission, f.job(jobB1)).Allowed, permission)
	}
	machineB, err := f.store.Machine(context.Background(), machineB1)
	require.NoError(t, err)
	assert.False(t, f.enforce(admin, PermissionAuthor, machineB).Allowed)
}

// A listed administrator who is not bound, and the builtin administrator, are
// the administrator only, as before.
func TestUnboundPlatformAdministratorIsNoPerson(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for name, admin := range map[string]Scope{"unbound": f.resolveAdmin("connor"), "builtin": f.admin} {
		assert.Equal(t, ScopePlatformAdmin, admin.Kind(), name)
		assert.Empty(t, admin.OwnerID(), name)
		assert.False(t, IsHuman(admin), name)
		_, ok := admin.OwnerPerson()
		assert.False(t, ok, name)
		assert.False(t, f.enforce(admin, PermissionAuthor, f.job(jobA1)).Allowed, name)
		assert.True(t, f.enforce(admin, PermissionView, f.job(jobA1)).BreakGlass, name)
	}
}

// The binding is read again on every decision: revoking it ends the
// person's rights at once, for a scope already resolved too, and the next
// resolve is the administrator only. The administrator's own rights stay.
func TestRevokingTheAdministratorsBindingEndsItsOwnerRights(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.bind("connor", ownerA)
	admin := f.resolveAdmin("connor")
	require.True(t, f.enforce(admin, PermissionApprove, f.job(jobA1)).Allowed)

	_, err := f.store.RevokeBinding(context.Background(), f.admin, person("connor").Identity, "test")
	require.NoError(t, err)

	assert.False(t, f.enforce(admin, PermissionApprove, f.job(jobA1)).Allowed, "the scope already resolved")
	assert.True(t, f.enforce(admin, PermissionView, f.job(jobA1)).BreakGlass, "view stays, as the administrator's")
	assert.True(t, f.enforce(admin, PermissionAdminister, Platform()).Allowed)
	again := f.resolveAdmin("connor")
	assert.Empty(t, again.OwnerID())
	assert.False(t, IsHuman(again))
}

// A bound administrator approves its own machine's enrolment, which only a
// person of the machine's owner may, and it is recorded as that person. It
// may not enrol another owner's machine, and an unbound administrator may
// enrol none.
func TestBoundPlatformAdministratorEnrolsItsOwnersMachine(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.bind("connor", ownerA)
	admin := f.resolveAdmin("connor")
	ctx := context.Background()

	worker := f.token(authn.ClassWorker, "connor", "worker-a1", "s")
	_, err := f.store.Enrol(ctx, f.resolveAdmin("someone"), EnrolmentRequest{MachineID: machineA1, Credential: worker})
	require.Error(t, err, "an unbound administrator is no person")
	assert.Equal(t, CodeForbidden, CodeOf(err))

	_, err = f.store.Enrol(ctx, admin, EnrolmentRequest{MachineID: machineB1, Credential: worker})
	require.Error(t, err, "another owner's machine")

	enrolment, err := f.store.Enrol(ctx, admin, EnrolmentRequest{MachineID: machineA1, Credential: worker})
	require.NoError(t, err)
	assert.Equal(t, ownerA, enrolment.OwnerID)
	assert.Equal(t, ActorPerson, enrolment.Enrolled.By.Kind)
	assert.Equal(t, "connor", enrolment.Enrolled.By.Subject)
	assert.Equal(t, ScopeMachine, f.resolve(worker).Kind())
}

// A bound administrator is also its owner's person, so it may not approve a
// binding of its own identity: it would make itself any owner's person. Its
// request waits for another administrator.
func TestPlatformAdministratorDoesNotBindItself(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	id := person("connor").Identity
	_, err := f.store.RequestBinding(ctx, person("connor"), Shown{Username: "connor"})
	require.NoError(t, err)

	for _, owner := range []string{ownerA, ownerB} {
		_, err = f.store.ApproveBinding(ctx, f.resolveAdmin("connor"), id, owner)
		require.Error(t, err, owner)
		assert.Equal(t, CodeForbidden, CodeOf(err), owner)
	}
	assert.Empty(t, f.resolveAdmin("connor").OwnerID(), "still bound to nobody")

	// Another administrator approves it; then the bound administrator still
	// may not move its own binding.
	_, err = f.store.ApproveBinding(ctx, f.admin, id, ownerA)
	require.NoError(t, err)
	admin := f.resolveAdmin("connor")
	require.Equal(t, ownerA, admin.OwnerID())
	_, err = f.store.RevokeBinding(ctx, admin, id, "move")
	require.NoError(t, err, "giving up its own binding is allowed")
	_, err = f.store.RequestBinding(ctx, person("connor"), Shown{Username: "connor"})
	require.NoError(t, err)
	_, err = f.store.ApproveBinding(ctx, f.resolveAdmin("connor"), id, ownerB)
	assert.Equal(t, CodeForbidden, CodeOf(err))

	// It still approves anyone else's.
	_, err = f.store.RequestBinding(ctx, person("bob"), Shown{Username: "bob"})
	require.NoError(t, err)
	_, err = f.store.ApproveBinding(ctx, f.resolveAdmin("connor"), person("bob").Identity, ownerB)
	require.NoError(t, err)
}
