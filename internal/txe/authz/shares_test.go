// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var jobA1Ref = ResourceRef{Kind: KindJob, ID: jobA1}

func TestGrantShare(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	bob := f.bind("bob", ownerB)

	require.False(t, f.enforce(bob, PermissionView, f.job(jobA1)).Allowed, "before the share")

	share, err := f.store.GrantShare(ctx, alice, ShareGrant{
		Resource: jobA1Ref, GranteeOwnerID: ownerB,
		Permissions: []Permission{PermissionExecute, PermissionView, PermissionView},
	})
	require.NoError(t, err)
	assert.Equal(t, ownerA, share.OwnerID, "the owner is the registry's, not the caller's word")
	assert.Equal(t, []Permission{PermissionView, PermissionExecute}, share.Permissions, "sorted, without repeats")
	assert.Equal(t, 1, share.Generation)
	assert.Equal(t, ActorPerson, share.Granted.By.Kind)
	assert.Equal(t, "alice", share.Granted.By.Subject)

	view := f.enforce(bob, PermissionView, f.job(jobA1))
	assert.True(t, view.Allowed)
	assert.Equal(t, ReasonShare, view.Reason)
	assert.Equal(t, ownerA, view.ShareOwnerID)
	assert.True(t, f.enforce(bob, PermissionExecute, f.job(jobA1)).Allowed)

	// Only what was granted, only on what was shared.
	for _, permission := range []Permission{PermissionAuthor, PermissionApprove, PermissionAdminister} {
		decision := f.enforce(bob, permission, f.job(jobA1))
		assert.False(t, decision.Allowed, permission)
		assert.Equal(t, ReasonNotOwner, decision.Reason, permission)
	}
	assert.False(t, f.enforce(bob, PermissionView, f.job(jobA2)).Allowed, "another job of the same owner")
	project, err := f.store.Project(ctx, projectA)
	require.NoError(t, err)
	assert.False(t, f.enforce(bob, PermissionView, project).Allowed, "the project the job is in")
	machine, err := f.store.Machine(ctx, machineA1)
	require.NoError(t, err)
	assert.False(t, f.enforce(bob, PermissionView, machine).Allowed, "the machine the job runs on")

	// A repeat is the same share. Other permissions are a conflict.
	again, err := f.store.GrantShare(ctx, alice, ShareGrant{
		Resource: jobA1Ref, GranteeOwnerID: ownerB, Permissions: []Permission{PermissionView, PermissionExecute},
	})
	require.NoError(t, err)
	assert.Equal(t, share, again)
	_, err = f.store.GrantShare(ctx, alice, ShareGrant{
		Resource: jobA1Ref, GranteeOwnerID: ownerB, Permissions: []Permission{PermissionView, PermissionAuthor},
	})
	assert.Equal(t, CodeConflict, CodeOf(err))
	assert.False(t, f.enforce(bob, PermissionAuthor, f.job(jobA1)).Allowed, "the refused grant changed nothing")

	shares, err := f.store.Shares(ctx, ownerA)
	require.NoError(t, err)
	require.Len(t, shares, 1)
}

// A share of a project covers the jobs in it.
func TestProjectShareCoversItsJobs(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	bob := f.bind("bob", ownerB)

	_, err := f.store.GrantShare(ctx, alice, ShareGrant{
		Resource: ResourceRef{Kind: KindProject, ID: projectA}, GranteeOwnerID: ownerB, Permissions: []Permission{PermissionView},
	})
	require.NoError(t, err)

	assert.True(t, f.enforce(bob, PermissionView, f.job(jobA1)).Allowed)
	assert.True(t, f.enforce(bob, PermissionView, f.job(jobA2)).Allowed)
	project, err := f.store.Project(ctx, projectA)
	require.NoError(t, err)
	assert.True(t, f.enforce(bob, PermissionView, project).Allowed)
	assert.False(t, f.enforce(bob, PermissionExecute, f.job(jobA1)).Allowed)
}

func TestGrantShareRefusals(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	bob := f.bind("bob", ownerB)
	view := []Permission{PermissionView}

	tests := []struct {
		name  string
		by    Scope
		grant ShareGrant
		want  Code
	}{
		{"ByTheGrantee", bob, ShareGrant{Resource: jobA1Ref, GranteeOwnerID: ownerB, Permissions: view}, CodeNotFound},
		{"ByTheOwnersCLI", f.resolve(f.token(authn.ClassCLI, "alice", "cli", "")), ShareGrant{Resource: jobA1Ref, GranteeOwnerID: ownerB, Permissions: view}, CodeForbidden},
		{"ByThePlatformAdmin", f.admin, ShareGrant{Resource: jobA1Ref, GranteeOwnerID: ownerB, Permissions: view}, CodeForbidden},
		{"ByNobody", Scope{}, ShareGrant{Resource: jobA1Ref, GranteeOwnerID: ownerB, Permissions: view}, CodeForbidden},
		{"AnotherOwnersJob", alice, ShareGrant{Resource: ResourceRef{Kind: KindJob, ID: jobB1}, GranteeOwnerID: ownerB, Permissions: view}, CodeNotFound},
		{"UnknownJob", alice, ShareGrant{Resource: ResourceRef{Kind: KindJob, ID: "job_none"}, GranteeOwnerID: ownerB, Permissions: view}, CodeNotFound},
		{"AMachine", alice, ShareGrant{Resource: ResourceRef{Kind: KindMachine, ID: machineA1}, GranteeOwnerID: ownerB, Permissions: view}, CodeInvalid},
		{"ToItself", alice, ShareGrant{Resource: jobA1Ref, GranteeOwnerID: ownerA, Permissions: view}, CodeInvalid},
		{"ToNobody", alice, ShareGrant{Resource: jobA1Ref, Permissions: view}, CodeInvalid},
		{"ToAnUnregisteredOwner", alice, ShareGrant{Resource: jobA1Ref, GranteeOwnerID: "own_new", Permissions: view}, CodeNotFound},
		{"NoPermissions", alice, ShareGrant{Resource: jobA1Ref, GranteeOwnerID: ownerB}, CodeInvalid},
		{"Administer", alice, ShareGrant{Resource: jobA1Ref, GranteeOwnerID: ownerB, Permissions: []Permission{PermissionView, PermissionAdminister}}, CodeInvalid},
		{"UnknownPermission", alice, ShareGrant{Resource: jobA1Ref, GranteeOwnerID: ownerB, Permissions: []Permission{"own"}}, CodeInvalid},
	}
	for _, tt := range tests {
		_, err := f.store.GrantShare(ctx, tt.by, tt.grant)
		assert.Equal(t, tt.want, CodeOf(err), tt.name)
	}
	shares, err := f.store.Shares(ctx, ownerA)
	require.NoError(t, err)
	assert.Empty(t, shares)
	assert.Equal(t, 2, f.registry.ownerCount(), "no owner was created")
}

// A share ends at the next decision after it is revoked, and granting again
// makes a new one.
func TestRevokeShare(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	bob := f.bind("bob", ownerB)
	_, err := f.store.GrantShare(ctx, alice, ShareGrant{Resource: jobA1Ref, GranteeOwnerID: ownerB, Permissions: []Permission{PermissionView}})
	require.NoError(t, err)
	require.True(t, f.enforce(bob, PermissionView, f.job(jobA1)).Allowed)

	_, err = f.store.RevokeShare(ctx, bob, jobA1Ref, ownerB, "done")
	assert.Equal(t, CodeNotFound, CodeOf(err), "the grantee cannot revoke, and learns nothing")
	_, err = f.store.RevokeShare(ctx, alice, jobA1Ref, ownerB, "")
	assert.Equal(t, CodeInvalid, CodeOf(err))
	_, err = f.store.RevokeShare(ctx, alice, ResourceRef{Kind: KindJob, ID: jobA2}, ownerB, "done")
	assert.Equal(t, CodeNotFound, CodeOf(err))

	revoked, err := f.store.RevokeShare(ctx, alice, jobA1Ref, ownerB, "done")
	require.NoError(t, err)
	assert.Equal(t, StateRevoked, revoked.State)
	again, err := f.store.RevokeShare(ctx, alice, jobA1Ref, ownerB, "again")
	require.NoError(t, err)
	assert.Equal(t, revoked, again)

	decision := f.enforce(bob, PermissionView, f.job(jobA1))
	assert.False(t, decision.Allowed, "the same scope, the next decision")
	assert.Equal(t, ReasonNotOwner, decision.Reason)

	regranted, err := f.store.GrantShare(ctx, alice, ShareGrant{Resource: jobA1Ref, GranteeOwnerID: ownerB, Permissions: []Permission{PermissionView, PermissionAuthor}})
	require.NoError(t, err)
	assert.Equal(t, 2, regranted.Generation)
	assert.True(t, f.enforce(bob, PermissionAuthor, f.job(jobA1)).Allowed)
}

// A share is to an owner's people and their CLI, within what each class may
// do. It never reaches a machine.
func TestShareAndClasses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	bob := f.bind("bob", ownerB)
	_, err := f.store.GrantShare(ctx, alice, ShareGrant{
		Resource: jobA1Ref, GranteeOwnerID: ownerB,
		Permissions: []Permission{PermissionView, PermissionAuthor, PermissionExecute, PermissionApprove},
	})
	require.NoError(t, err)

	assert.True(t, f.enforce(bob, PermissionApprove, f.job(jobA1)).Allowed, "a person of the grantee")

	cli := f.resolve(f.token(authn.ClassCLI, "bob", "cli", ""))
	assert.True(t, f.enforce(cli, PermissionView, f.job(jobA1)).Allowed)
	approve := f.enforce(cli, PermissionApprove, f.job(jobA1))
	assert.False(t, approve.Allowed, "a share does not make a CLI a person")
	assert.Equal(t, ReasonClass, approve.Reason)

	worker := f.token(authn.ClassWorker, "bob", "worker-b1", "")
	f.enrol(bob, machineB1, worker, KeyClient)
	machine := f.resolve(worker)
	require.Equal(t, ScopeMachine, machine.Kind())
	shared := f.enforce(machine, PermissionView, f.job(jobA1))
	assert.False(t, shared.Allowed, "no share reaches a machine")
	assert.Equal(t, ReasonNotOwner, shared.Reason)

	// The owner whose binding was revoked can no longer grant or revoke.
	_, err = f.store.RevokeBinding(ctx, f.admin, person("alice").Identity, "left")
	require.NoError(t, err)
	_, err = f.store.RevokeShare(ctx, alice, jobA1Ref, ownerB, "late")
	assert.Equal(t, CodeForbidden, CodeOf(err))
	_, err = f.store.GrantShare(ctx, alice, ShareGrant{Resource: ResourceRef{Kind: KindJob, ID: jobA2}, GranteeOwnerID: ownerB, Permissions: []Permission{PermissionView}})
	assert.Equal(t, CodeForbidden, CodeOf(err))
}
