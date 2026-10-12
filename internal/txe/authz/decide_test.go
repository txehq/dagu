// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The three modes on the same questions: off allows without looking, observe
// allows and reports, enforce denies.
func TestModesOnTheSameDecisions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	stranger := f.resolve(person("stranger"))

	questions := []struct {
		name       string
		scope      Scope
		permission Permission
		resource   Resource
		allowed    bool
		reason     Reason
	}{
		{"OwnJob", alice, PermissionAuthor, f.job(jobA1), true, ReasonOwner},
		{"AnotherOwnersJob", alice, PermissionView, f.job(jobB1), false, ReasonNotOwner},
		{"UnboundPrincipal", stranger, PermissionView, f.job(jobA1), false, ReasonUnbound},
		{"ZeroScope", Scope{}, PermissionView, f.job(jobA1), false, ReasonUnbound},
	}
	for _, q := range questions {
		off, err := f.store.Decide(ctx, ModeOff, q.scope, q.permission, q.resource)
		require.NoError(t, err, q.name)
		assert.Equal(t, Decision{Allowed: true, Mode: ModeOff, Reason: ReasonModeOff}, off, q.name)

		observe, err := f.store.Decide(ctx, ModeObserve, q.scope, q.permission, q.resource)
		require.NoError(t, err, q.name)
		assert.True(t, observe.Allowed, q.name)
		assert.True(t, observe.Evaluated, q.name)
		assert.Equal(t, !q.allowed, observe.WouldDeny, q.name)
		assert.Equal(t, q.reason, observe.Reason, q.name)

		enforce, err := f.store.Decide(ctx, ModeEnforce, q.scope, q.permission, q.resource)
		require.NoError(t, err, q.name)
		assert.Equal(t, q.allowed, enforce.Allowed, q.name)
		assert.False(t, enforce.WouldDeny, q.name)
		assert.Equal(t, q.reason, enforce.Reason, q.name)
	}

	// Off does not even look at what it is given.
	off, err := f.store.Decide(ctx, ModeOff, Scope{}, "no-such-permission", Resource{})
	require.NoError(t, err)
	assert.True(t, off.Allowed)
	assert.False(t, off.Evaluated)

	// A mode that is not one is not a reason to allow.
	decision, err := f.store.Decide(ctx, "enforced", alice, PermissionView, f.job(jobA1))
	require.Error(t, err)
	assert.False(t, decision.Allowed)
}

func TestParseMode(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]Mode{"": ModeOff, "off": ModeOff, "observe": ModeObserve, "enforce": ModeEnforce} {
		mode, err := ParseMode(text)
		require.NoError(t, err, text)
		assert.Equal(t, want, mode, text)
	}
	for _, text := range []string{"on", "Enforce", "enforced", " off", "true"} {
		_, err := ParseMode(text)
		require.Error(t, err, text)
	}
}

// What each class may do to its own owner's data.
func TestClassPermissions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	alice := f.bind("alice", ownerA)
	cli := f.resolve(f.token(authn.ClassCLI, "alice", "cli", ""))
	workerCredential := f.token(authn.ClassWorker, "alice", "worker-a1", "")
	reviewerCredential := f.token(authn.ClassReviewer, "alice", "reviewer-a1", "")
	f.enrol(alice, machineA1, workerCredential)
	f.enrol(alice, machineA1, reviewerCredential)
	worker, reviewer := f.resolve(workerCredential), f.resolve(reviewerCredential)

	allowed := map[string][]Permission{
		"person":   {PermissionView, PermissionAuthor, PermissionExecute, PermissionApprove, PermissionAdminister},
		"cli":      {PermissionView, PermissionAuthor, PermissionExecute},
		"worker":   {PermissionView, PermissionExecute},
		"reviewer": {PermissionView, PermissionExecute},
	}
	for name, scope := range map[string]Scope{"person": alice, "cli": cli, "worker": worker, "reviewer": reviewer} {
		for _, permission := range allPermissions {
			decision := f.enforce(scope, permission, f.job(jobA1))
			want := false
			for _, p := range allowed[name] {
				want = want || p == permission
			}
			assert.Equal(t, want, decision.Allowed, "%s %s", name, permission)
			if !want {
				assert.Equal(t, ReasonClass, decision.Reason, "%s %s", name, permission)
			}
		}
	}

	// Only a person signed in through the browser is a human.
	assert.True(t, IsHuman(alice))
	for name, scope := range map[string]Scope{"cli": cli, "worker": worker, "reviewer": reviewer, "admin": f.admin, "unbound": f.resolve(person("stranger")), "zero": {}} {
		assert.False(t, IsHuman(scope), name)
	}
	assert.Equal(t, authn.ClassPlatformAdmin, f.admin.Class())
	assert.Equal(t, authn.ClassCLI, cli.Class())
}

// A bearer principal with no binding acts for nobody. It has no owner, no
// permission on anything, and nothing to fall back on.
func TestUnboundPrincipalsHoldNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.bind("alice", ownerA)
	project, err := f.store.Project(ctx, projectA)
	require.NoError(t, err)
	machine, err := f.store.Machine(ctx, machineA1)
	require.NoError(t, err)

	principals := map[string]authn.Principal{
		"CLI":            f.token(authn.ClassCLI, "nobody", "cli", ""),
		"Worker":         f.token(authn.ClassWorker, "nobody", "worker", "s"),
		"Reviewer":       f.token(authn.ClassReviewer, "nobody", "reviewer", "s"),
		"Person":         person("nobody"),
		"AdminClass":     {Identity: authn.Identity{Issuer: issuer, Subject: "alice"}, Class: authn.ClassPlatformAdmin},
		"UnknownClass":   {Identity: authn.Identity{Issuer: issuer, Subject: "alice"}, Class: "owner"},
		"NoClass":        {Identity: authn.Identity{Issuer: issuer, Subject: "alice"}},
		"NoSubject":      {Identity: authn.Identity{Issuer: issuer}, Class: authn.ClassPerson},
		"WorkerOfABound": f.token(authn.ClassWorker, "alice", "worker", "s"),
	}
	for name, p := range principals {
		scope := f.resolve(p)
		assert.Equal(t, ScopeUnbound, scope.Kind(), name)
		assert.Empty(t, scope.OwnerID(), name)
		assert.Empty(t, scope.MachineID(), name)
		assert.NotEmpty(t, scope.UnboundReason(), name)
		_, err := OwnData(scope)
		require.Error(t, err, name)
		for _, resource := range []Resource{f.job(jobA1), project, machine, Platform()} {
			for _, permission := range allPermissions {
				assert.False(t, f.enforce(scope, permission, resource).Allowed, "%s %s %s", name, permission, resource.Kind())
			}
		}
	}
}

// The platform administrator approves bindings and may look. It is not an
// owner.
func TestPlatformAdministrator(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	assert.True(t, f.enforce(f.admin, PermissionAdminister, Platform()).Allowed)
	assert.True(t, f.enforce(f.admin, PermissionView, Platform()).Allowed)
	assert.False(t, f.enforce(f.admin, PermissionView, Platform()).BreakGlass)

	view := f.enforce(f.admin, PermissionView, f.job(jobA1))
	assert.True(t, view.Allowed)
	assert.True(t, view.BreakGlass, "looking at an owner's data is to be recorded")
	assert.Equal(t, ReasonPlatformAdmin, view.Reason)

	for _, permission := range []Permission{PermissionAuthor, PermissionExecute, PermissionApprove, PermissionAdminister} {
		decision := f.enforce(f.admin, permission, f.job(jobA1))
		assert.False(t, decision.Allowed, permission)
		assert.False(t, decision.BreakGlass, permission)
	}
	_, err := OwnData(f.admin)
	require.Error(t, err, "the administrator owns nothing")

	// An owner's person does not administer the platform.
	alice := f.bind("alice", ownerA)
	assert.False(t, f.enforce(alice, PermissionAdminister, Platform()).Allowed)
	assert.False(t, f.enforce(alice, PermissionView, Platform()).Allowed)
}

// A scope is good until its token expires and not an instant longer, however
// long the request that holds it runs.
func TestDecideRefusesAnExpiredScope(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.bind("alice", ownerA)
	cli := f.resolve(f.token(authn.ClassCLI, "alice", "cli", ""))

	f.clock.Advance(5*time.Minute - time.Nanosecond)
	assert.True(t, f.enforce(cli, PermissionView, f.job(jobA1)).Allowed)
	f.clock.Advance(time.Nanosecond)
	decision := f.enforce(cli, PermissionView, f.job(jobA1))
	assert.False(t, decision.Allowed)
	assert.Equal(t, ReasonExpired, decision.Reason)

	// An expired token resolves to nobody.
	scope := f.resolve(cli.Principal())
	assert.Equal(t, ScopeUnbound, scope.Kind())
	assert.Equal(t, ReasonExpired, scope.UnboundReason())
}

// The owner of a resource is the registry's. Own data is the scope's own
// owner. Neither can be supplied by a request.
func TestResources(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)

	job := f.job(jobA1)
	assert.Equal(t, KindJob, job.Kind())
	assert.Equal(t, jobA1, job.ID())
	assert.Equal(t, ownerA, job.OwnerID())

	own, err := OwnData(alice)
	require.NoError(t, err)
	assert.Equal(t, ownerA, own.OwnerID())
	assert.True(t, f.enforce(alice, PermissionAuthor, own).Allowed)
	bob := f.bind("bob", ownerB)
	assert.False(t, f.enforce(bob, PermissionView, own).Allowed, "one owner's data is not another's")

	for name, lookup := range map[string]func() (Resource, error){
		"UnknownJob":     func() (Resource, error) { return f.store.Job(ctx, "job_none") },
		"UnknownProject": func() (Resource, error) { return f.store.Project(ctx, "prj_none") },
		"UnknownMachine": func() (Resource, error) { return f.store.Machine(ctx, "mch_none") },
	} {
		_, err := lookup()
		assert.Equal(t, CodeNotFound, CodeOf(err), name)
	}
	for name, lookup := range map[string]func() (Resource, error){
		"NoJob":     func() (Resource, error) { return f.store.Job(ctx, "") },
		"NoProject": func() (Resource, error) { return f.store.Project(ctx, "") },
		"NoMachine": func() (Resource, error) { return f.store.Machine(ctx, "") },
	} {
		_, err := lookup()
		assert.Equal(t, CodeInvalid, CodeOf(err), name)
	}

	// A zero resource and a permission that is not one are never allowed.
	assert.Equal(t, ReasonInvalid, f.enforce(alice, PermissionView, Resource{}).Reason)
	assert.Equal(t, ReasonInvalid, f.enforce(alice, "own", job).Reason)
	assert.False(t, f.enforce(alice, "own", job).Allowed)
}

// When the registry cannot be read, enforcing denies and observing reports
// that it would have.
func TestDecideWhenTheRegistryFails(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	credential := f.token(authn.ClassWorker, "alice", "worker-a1", "")
	f.enrol(alice, machineA1, credential)
	machine := f.resolve(credential)
	job := f.job(jobA1)

	f.registry.fail(errRegistryDown)

	_, err := f.store.Job(ctx, jobA1)
	require.ErrorIs(t, err, errRegistryDown)
	_, err = f.store.Resolve(ctx, credential)
	require.ErrorIs(t, err, errRegistryDown, "a machine cannot be resolved without the registry, and is not called unbound")
	_, reason, err := f.store.ResolveMachine(ctx, credential)
	require.ErrorIs(t, err, errRegistryDown)
	assert.Equal(t, ReasonEvaluationFailed, reason)

	enforce, err := f.store.Decide(ctx, ModeEnforce, machine, PermissionExecute, job)
	require.ErrorIs(t, err, errRegistryDown)
	assert.False(t, enforce.Allowed)
	assert.Equal(t, ReasonEvaluationFailed, enforce.Reason)

	observe, err := f.store.Decide(ctx, ModeObserve, machine, PermissionExecute, job)
	require.NoError(t, err)
	assert.True(t, observe.Allowed)
	assert.True(t, observe.WouldDeny)
	assert.Equal(t, ReasonEvaluationFailed, observe.Reason)

	off, err := f.store.Decide(ctx, ModeOff, machine, PermissionExecute, job)
	require.NoError(t, err)
	assert.True(t, off.Allowed)

	// A person's decision on a resource already looked up needs no registry.
	assert.True(t, f.enforce(alice, PermissionView, job).Allowed)

	_, err = f.store.ApproveBinding(ctx, f.admin, person("carol").Identity, ownerA)
	require.ErrorIs(t, err, errRegistryDown)
}

func TestPermissions(t *testing.T) {
	t.Parallel()
	for _, permission := range allPermissions {
		assert.True(t, permission.Valid(), permission)
	}
	assert.False(t, Permission("").Valid())
	assert.False(t, Permission("own").Valid())
	assert.False(t, PermissionAdminister.Shareable())
	assert.True(t, PermissionApprove.Shareable())
	assert.False(t, Permission("own").Shareable())

	assert.Empty(t, CodeOf(nil))
	assert.Empty(t, CodeOf(errRegistryDown))
	assert.Equal(t, CodeConflict, CodeOf(refuse(CodeConflict, "x")))
}
