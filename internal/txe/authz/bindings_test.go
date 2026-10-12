// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"sync"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Signing in binds nobody. The identity can see that it asked, and nothing
// else.
func TestSigningInBindsNobody(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := person("alice")

	scope := f.resolve(alice)
	assert.Equal(t, ScopeUnbound, scope.Kind())
	assert.Equal(t, ReasonUnbound, scope.UnboundReason())

	request, err := f.store.RequestBinding(ctx, alice, Shown{Username: "alice", Email: "alice@example.invalid"})
	require.NoError(t, err)
	assert.Equal(t, RequestPending, request.State)
	assert.Equal(t, 1, request.Generation)

	scope = f.resolve(alice)
	assert.Equal(t, ScopeUnbound, scope.Kind(), "a request is not a binding")
	assert.Empty(t, scope.OwnerID())
	for _, permission := range allPermissions {
		assert.False(t, f.enforce(scope, permission, f.job(jobA1)).Allowed, permission)
	}

	again, err := f.store.RequestBinding(ctx, alice, Shown{Username: "changed"})
	require.NoError(t, err)
	assert.Equal(t, request, again, "asking again while pending changes nothing")
	bindings, err := f.store.Bindings(ctx, ownerA)
	require.NoError(t, err)
	assert.Empty(t, bindings)
}

// Only someone who signed in themselves can ask. A token of any class cannot
// open a request.
func TestOnlyAPersonRequestsABinding(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	for _, class := range []authn.Class{authn.ClassCLI, authn.ClassWorker, authn.ClassReviewer, authn.ClassPlatformAdmin, ""} {
		_, err := f.store.RequestBinding(ctx, f.token(class, "alice", "client", ""), Shown{})
		assert.Equal(t, CodeForbidden, CodeOf(err), class)
	}
	_, err := f.store.RequestBinding(ctx, authn.Principal{Class: authn.ClassPerson}, Shown{})
	assert.Equal(t, CodeInvalid, CodeOf(err))

	expiring := f.token(authn.ClassPerson, "alice", "web", "")
	f.clock.Advance(5 * 60e9)
	_, err = f.store.RequestBinding(ctx, expiring, Shown{})
	assert.Equal(t, CodeForbidden, CodeOf(err))

	pending, err := f.store.PendingRequest(ctx, person("alice").Identity)
	require.NoError(t, err)
	assert.Nil(t, pending)
}

func TestApproveBinding(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := person("alice")

	// No request yet: the subject has not signed in and asked.
	_, err := f.store.ApproveBinding(ctx, f.admin, alice.Identity, ownerA)
	assert.Equal(t, CodeNotFound, CodeOf(err))

	_, err = f.store.RequestBinding(ctx, alice, Shown{Username: "alice", Email: "alice@example.invalid", Name: "Alice"})
	require.NoError(t, err)

	binding, err := f.store.ApproveBinding(ctx, f.admin, alice.Identity, ownerA)
	require.NoError(t, err)
	assert.Equal(t, SchemaVersion, binding.Schema)
	assert.Equal(t, ownerA, binding.OwnerID)
	assert.Equal(t, alice.Identity, binding.Identity())
	assert.Equal(t, StateActive, binding.State)
	assert.Equal(t, 1, binding.Generation)
	assert.Equal(t, Actor{Kind: ActorPlatformAdmin, Name: "admin"}, binding.Bound.By)
	assert.True(t, binding.Bound.At.Equal(f.clock.Now()))
	assert.Equal(t, "alice@example.invalid", binding.Shown.Email, "what was shown is recorded")

	scope := f.resolve(alice)
	assert.Equal(t, ScopeOwner, scope.Kind())
	assert.Equal(t, ownerA, scope.OwnerID())
	assert.Empty(t, scope.UnboundReason())

	pending, err := f.store.PendingRequest(ctx, alice.Identity)
	require.NoError(t, err)
	assert.Nil(t, pending, "the request was used")

	// A repeat with the same owner is the same binding.
	again, err := f.store.ApproveBinding(ctx, f.admin, alice.Identity, ownerA)
	require.NoError(t, err)
	assert.Equal(t, binding, again)

	// Another owner for a bound identity is refused and changes nothing.
	_, err = f.store.ApproveBinding(ctx, f.admin, alice.Identity, ownerB)
	require.Equal(t, CodeConflict, CodeOf(err))
	var refused *Error
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, binding, refused.Current)
	assert.Equal(t, ownerA, f.resolve(alice).OwnerID())

	bindings, err := f.store.Bindings(ctx, ownerA)
	require.NoError(t, err)
	require.Len(t, bindings, 1)
	other, err := f.store.Bindings(ctx, ownerB)
	require.NoError(t, err)
	assert.Empty(t, other)
}

// Only the platform administrator approves, and nobody approves themselves.
func TestApproveBindingNeedsThePlatformAdministrator(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	bob := f.bind("bob", ownerB)
	alice := person("alice")
	_, err := f.store.RequestBinding(ctx, alice, Shown{})
	require.NoError(t, err)

	for name, by := range map[string]Scope{
		"Zero":          {},
		"Unbound":       f.resolve(alice),
		"AnotherPerson": bob,
		"CLIOfAnOwner":  f.resolve(f.token(authn.ClassCLI, "bob", "cli", "")),
	} {
		_, err := f.store.ApproveBinding(ctx, by, alice.Identity, ownerA)
		assert.Equal(t, CodeForbidden, CodeOf(err), name)
	}
	assert.Equal(t, ScopeUnbound, f.resolve(alice).Kind())
}

// A binding never creates an owner.
func TestApproveBindingCreatesNoOwner(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := person("alice")
	_, err := f.store.RequestBinding(ctx, alice, Shown{})
	require.NoError(t, err)
	before := f.registry.ownerCount()

	_, err = f.store.ApproveBinding(ctx, f.admin, alice.Identity, "own_new")
	assert.Equal(t, CodeNotFound, CodeOf(err))
	_, err = f.store.ApproveBinding(ctx, f.admin, alice.Identity, "")
	assert.Equal(t, CodeInvalid, CodeOf(err))
	_, err = f.store.ApproveBinding(ctx, f.admin, authn.Identity{Issuer: issuer}, ownerA)
	assert.Equal(t, CodeInvalid, CodeOf(err))

	assert.Equal(t, before, f.registry.ownerCount())
	assert.Equal(t, ScopeUnbound, f.resolve(alice).Kind())
	pending, err := f.store.PendingRequest(ctx, alice.Identity)
	require.NoError(t, err)
	assert.NotNil(t, pending, "the refused approval left the request waiting")
}

// The identity is the issuer and the subject. The same email, username and
// name under another subject, or the same subject under another issuer, is
// someone else and is bound to nothing.
func TestBindingIsByIssuerAndSubjectOnly(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	shown := Shown{Username: "alice", Email: "alice@example.invalid", Name: "Alice"}
	alice := person("subject-1")
	_, err := f.store.RequestBinding(ctx, alice, shown)
	require.NoError(t, err)
	_, err = f.store.ApproveBinding(ctx, f.admin, alice.Identity, ownerA)
	require.NoError(t, err)

	sameShownOtherSubject := person("subject-2")
	_, err = f.store.RequestBinding(ctx, sameShownOtherSubject, shown)
	require.NoError(t, err)
	scope := f.resolve(sameShownOtherSubject)
	assert.Equal(t, ScopeUnbound, scope.Kind(), "equal email, username and name bind nothing")
	assert.False(t, f.enforce(scope, PermissionView, f.job(jobA1)).Allowed)

	sameSubjectOtherIssuer := authn.Principal{Identity: authn.Identity{Issuer: otherIssuer, Subject: "subject-1"}, Class: authn.ClassPerson}
	scope = f.resolve(sameSubjectOtherIssuer)
	assert.Equal(t, ScopeUnbound, scope.Kind(), "the same subject from another issuer is someone else")
	assert.False(t, f.enforce(scope, PermissionView, f.job(jobA1)).Allowed)

	// Parts that concatenate to the same text are still different identities.
	shifted := authn.Principal{Identity: authn.Identity{Issuer: issuer + "s", Subject: "ubject-1"}, Class: authn.ClassPerson}
	assert.Equal(t, ScopeUnbound, f.resolve(shifted).Kind())

	assert.Equal(t, ScopeOwner, f.resolve(alice).Kind())
}

func TestRevokeBinding(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := person("alice")
	before := f.bind("alice", ownerA)
	require.True(t, f.enforce(before, PermissionView, f.job(jobA1)).Allowed)

	_, err := f.store.RevokeBinding(ctx, before, alice.Identity, "left")
	assert.Equal(t, CodeForbidden, CodeOf(err), "nobody revokes with their own scope")
	_, err = f.store.RevokeBinding(ctx, f.admin, alice.Identity, "")
	assert.Equal(t, CodeInvalid, CodeOf(err))
	_, err = f.store.RevokeBinding(ctx, f.admin, person("nobody").Identity, "left")
	assert.Equal(t, CodeNotFound, CodeOf(err))

	revoked, err := f.store.RevokeBinding(ctx, f.admin, alice.Identity, "left")
	require.NoError(t, err)
	assert.Equal(t, StateRevoked, revoked.State)
	require.NotNil(t, revoked.Revoked)
	assert.Equal(t, "left", revoked.Revoked.Reason)
	again, err := f.store.RevokeBinding(ctx, f.admin, alice.Identity, "again")
	require.NoError(t, err)
	assert.Equal(t, revoked, again, "revoking twice changes nothing")

	// The scope resolved before the revocation is refused by the next
	// decision, and a new resolution is unbound.
	decision := f.enforce(before, PermissionView, f.job(jobA1))
	assert.False(t, decision.Allowed)
	assert.Equal(t, ReasonBindingRevoked, decision.Reason)
	scope := f.resolve(alice)
	assert.Equal(t, ScopeUnbound, scope.Kind())
	assert.Equal(t, ReasonBindingRevoked, scope.UnboundReason())

	// Binding again needs the subject to sign in and ask again.
	_, err = f.store.ApproveBinding(ctx, f.admin, alice.Identity, ownerA)
	assert.Equal(t, CodeNotFound, CodeOf(err))
	request, err := f.store.RequestBinding(ctx, alice, Shown{Username: "alice"})
	require.NoError(t, err)
	assert.Equal(t, 2, request.Generation)
	rebound, err := f.store.ApproveBinding(ctx, f.admin, alice.Identity, ownerA)
	require.NoError(t, err)
	assert.Equal(t, 2, rebound.Generation)
	assert.Nil(t, rebound.Revoked)

	// The old scope came from the first binding. The second does not revive it.
	decision = f.enforce(before, PermissionView, f.job(jobA1))
	assert.False(t, decision.Allowed)
	assert.Equal(t, ReasonBindingRevoked, decision.Reason)
	assert.True(t, f.enforce(f.resolve(alice), PermissionView, f.job(jobA1)).Allowed)

	// The first binding is kept, not overwritten.
	var archived Binding
	_, found, err := f.store.read(ctx, bindingHistory+identityDigest(alice.Identity)+"/000001", &archived)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, StateRevoked, archived.State)
	assert.Equal(t, 1, archived.Generation)
}

// A revoked identity may be bound to another owner afterwards, by the same
// two steps.
func TestRebindToAnotherOwnerAfterRevocation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := person("alice")
	f.bind("alice", ownerA)
	_, err := f.store.RevokeBinding(ctx, f.admin, alice.Identity, "moved")
	require.NoError(t, err)

	moved := f.bind("alice", ownerB)
	assert.Equal(t, ownerB, moved.OwnerID())
	assert.False(t, f.enforce(moved, PermissionView, f.job(jobA1)).Allowed)
	assert.True(t, f.enforce(moved, PermissionView, f.job(jobB1)).Allowed)

	a, err := f.store.Bindings(ctx, ownerA)
	require.NoError(t, err)
	assert.Empty(t, a, "the record now holds the binding to the other owner; the first is in the history")
}

// Approvals that race for one identity end with one binding. Those for the
// same owner all return it; those for another owner are refused.
func TestConcurrentApprovals(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := person("alice")
	_, err := f.store.RequestBinding(ctx, alice, Shown{})
	require.NoError(t, err)

	const each = 12
	owners := []string{ownerA, ownerB}
	results := make([]*Binding, 2*each)
	errs := make([]error, 2*each)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 2 * each {
		wg.Go(func() {
			<-start
			results[i], errs[i] = f.store.ApproveBinding(ctx, f.admin, alice.Identity, owners[i%2])
		})
	}
	close(start)
	wg.Wait()

	winner := f.resolve(alice).OwnerID()
	require.Contains(t, owners, winner)
	for i := range results {
		if owners[i%2] == winner {
			require.NoError(t, errs[i])
			assert.Equal(t, winner, results[i].OwnerID)
			assert.Equal(t, 1, results[i].Generation)
		} else {
			assert.Equal(t, CodeConflict, CodeOf(errs[i]))
		}
	}
	total := 0
	for _, owner := range owners {
		bindings, err := f.store.Bindings(ctx, owner)
		require.NoError(t, err)
		total += len(bindings)
	}
	assert.Equal(t, 1, total)
}

func TestNewStoreRequiresItsParts(t *testing.T) {
	t.Parallel()
	_, err := New(nil, newFakeRegistry())
	require.Error(t, err)
	_, err = NewFileStore("", newFakeRegistry())
	require.Error(t, err)
	_, err = NewFileStore(t.TempDir(), nil)
	require.Error(t, err)
}
