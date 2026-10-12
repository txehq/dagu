// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (f *fixture) machine(p authn.Principal) (Machine, Reason) {
	f.t.Helper()
	machine, reason, err := f.store.ResolveMachine(context.Background(), p)
	require.NoError(f.t, err)
	return machine, reason
}

// One provider client per machine: the client is the key.
func TestEnrolByClient(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	alice := f.bind("alice", ownerA)
	credential := f.token(authn.ClassWorker, "alice", "worker-a1", "browser-session")

	_, reason := f.machine(credential)
	assert.Equal(t, ReasonNotEnrolled, reason, "before enrolment the credential is nobody's")
	assert.Equal(t, ScopeUnbound, f.resolve(credential).Kind())

	enrolment := f.enrol(alice, machineA1, credential, KeyClient)
	assert.Equal(t, machineA1, enrolment.MachineID)
	assert.Equal(t, authn.ClassWorker, enrolment.Class)
	assert.Equal(t, ownerA, enrolment.OwnerID)
	assert.Equal(t, EnrolmentKey{Kind: KeyClient, Issuer: issuer, ClientID: "worker-a1"}, enrolment.Key)
	assert.Equal(t, "alice", enrolment.Subject)
	assert.Equal(t, 1, enrolment.Generation)

	machine, reason := f.machine(credential)
	assert.Empty(t, reason)
	assert.Equal(t, Machine{MachineID: machineA1, OwnerID: ownerA, Class: authn.ClassWorker}, machine)
	scope := f.resolve(credential)
	assert.Equal(t, ScopeMachine, scope.Kind())
	assert.Equal(t, machineA1, scope.MachineID())
	assert.Equal(t, ownerA, scope.OwnerID())

	// A token refreshed later carries the same key and is the same machine.
	f.clock.Advance(4 * time.Minute)
	refreshed := f.token(authn.ClassWorker, "alice", "worker-a1", "another-session")
	machine, reason = f.machine(refreshed)
	assert.Empty(t, reason)
	assert.Equal(t, machineA1, machine.MachineID)

	// A repeat is the same enrolment.
	again := f.enrol(alice, machineA1, refreshed, KeyClient)
	assert.Equal(t, enrolment, again)

	enrolments, err := f.store.Enrolments(context.Background(), ownerA)
	require.NoError(t, err)
	require.Len(t, enrolments, 1)
}

// The machine comes from the credential. One machine's credential is never
// another machine, whatever a request might say, and each is ended alone.
func TestOneMachinesCredentialIsNeverAnother(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	a1 := f.token(authn.ClassWorker, "alice", "worker-a1", "shared-session")
	a2 := f.token(authn.ClassWorker, "alice", "worker-a2", "shared-session")
	f.enrol(alice, machineA1, a1, KeyClient)
	f.enrol(alice, machineA2, a2, KeyClient)

	first, _ := f.machine(a1)
	second, _ := f.machine(a2)
	assert.Equal(t, machineA1, first.MachineID)
	assert.Equal(t, machineA2, second.MachineID)

	// Machine A1's credential on machine A2's job, same owner.
	scope := f.resolve(a1)
	assert.True(t, f.enforce(scope, PermissionExecute, f.job(jobA1)).Allowed)
	decision := f.enforce(scope, PermissionExecute, f.job(jobA2))
	assert.False(t, decision.Allowed)
	assert.Equal(t, ReasonOtherMachine, decision.Reason)
	other, err := f.store.Machine(ctx, machineA2)
	require.NoError(t, err)
	assert.Equal(t, ReasonOtherMachine, f.enforce(scope, PermissionView, other).Reason)

	// Revoke A1. A1 stops at the next decision; A2 is untouched.
	_, err = f.store.RevokeEnrolment(ctx, alice, machineA1, authn.ClassWorker, "retired")
	require.NoError(t, err)
	decision = f.enforce(scope, PermissionExecute, f.job(jobA1))
	assert.False(t, decision.Allowed)
	assert.Equal(t, ReasonEnrolmentRevoked, decision.Reason)
	_, reason := f.machine(a1)
	assert.Equal(t, ReasonEnrolmentRevoked, reason)
	second, reason = f.machine(a2)
	assert.Empty(t, reason)
	assert.Equal(t, machineA2, second.MachineID)
	assert.True(t, f.enforce(f.resolve(a2), PermissionExecute, f.job(jobA2)).Allowed)
}

// A key that already belongs to a machine is refused for another and never
// reassigned. This is what a provider that hands two sign-ins the same
// session comes to: the second machine is not enrolled, and the first is as
// it was.
func TestAKeyBelongsToOneMachineForGood(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)

	// Two machines signed in through one signed-in browser: same session.
	a1 := f.token(authn.ClassWorker, "alice", "worker", "browser-session")
	a2 := f.token(authn.ClassWorker, "alice", "worker", "browser-session")
	first := f.enrol(alice, machineA1, a1, KeySession)

	_, err := f.store.Enrol(ctx, alice, EnrolmentRequest{MachineID: machineA2, Credential: a2, KeyKind: KeySession})
	require.Equal(t, CodeConflict, CodeOf(err))
	machine, reason := f.machine(a2)
	assert.Empty(t, reason)
	assert.Equal(t, machineA1, machine.MachineID, "the credential is still the first machine's and nothing else")
	enrolments, err := f.store.Enrolments(ctx, ownerA)
	require.NoError(t, err)
	require.Len(t, enrolments, 1)
	assert.Equal(t, first, enrolments[0])

	// A machine that signed in on its own gets its own session, and enrols.
	separate := f.token(authn.ClassWorker, "alice", "worker", "its-own-session")
	f.enrol(alice, machineA2, separate, KeySession)
	machine, _ = f.machine(separate)
	assert.Equal(t, machineA2, machine.MachineID)

	// Revoking the first enrolment does not free its key for another machine.
	_, err = f.store.RevokeEnrolment(ctx, alice, machineA1, authn.ClassWorker, "retired")
	require.NoError(t, err)
	bob := f.bind("bob", ownerB)
	_, err = f.store.Enrol(ctx, bob, EnrolmentRequest{
		MachineID: machineB1, Credential: f.token(authn.ClassWorker, "bob", "worker", "browser-session"), KeyKind: KeySession,
	})
	assert.Equal(t, CodeConflict, CodeOf(err))

	// It can be enrolled again for the same machine, as a new generation.
	again := f.enrol(alice, machineA1, a1, KeySession)
	assert.Equal(t, 2, again.Generation)
	var archived Enrolment
	_, found, err := f.store.read(ctx, enrolmentHistory+enrolmentDigest(machineA1, authn.ClassWorker)+"/000001", &archived)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, StateRevoked, archived.State)
}

// A session key needs a session, and a credential without the enrolled
// session is not the machine.
func TestSessionKeyNeedsItsSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)

	_, err := f.store.Enrol(ctx, alice, EnrolmentRequest{
		MachineID: machineA1, Credential: f.token(authn.ClassWorker, "alice", "worker", ""), KeyKind: KeySession,
	})
	assert.Equal(t, CodeInvalid, CodeOf(err))

	f.enrol(alice, machineA1, f.token(authn.ClassWorker, "alice", "worker", "session-1"), KeySession)
	for name, credential := range map[string]authn.Principal{
		"AnotherSession": f.token(authn.ClassWorker, "alice", "worker", "session-2"),
		"NoSession":      f.token(authn.ClassWorker, "alice", "worker", ""),
		"AnotherClient":  f.token(authn.ClassWorker, "alice", "worker-2", "session-1"),
	} {
		_, reason := f.machine(credential)
		assert.Equal(t, ReasonNotEnrolled, reason, name)
	}
}

// A client is used with one kind of key. Otherwise a client whose machines
// are told apart by session could be claimed whole by one machine, which
// would then be every machine of that client.
func TestAClientHasOneKindOfKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	a1 := f.token(authn.ClassWorker, "alice", "worker", "session-1")
	a2 := f.token(authn.ClassWorker, "alice", "worker", "session-2")
	f.enrol(alice, machineA1, a1, KeySession)

	_, err := f.store.Enrol(ctx, alice, EnrolmentRequest{MachineID: machineA2, Credential: a2, KeyKind: KeyClient})
	require.Equal(t, CodeConflict, CodeOf(err))
	machine, reason := f.machine(a1)
	assert.Empty(t, reason)
	assert.Equal(t, machineA1, machine.MachineID, "machine A1's credential is still machine A1")
	_, reason = f.machine(a2)
	assert.Equal(t, ReasonNotEnrolled, reason)

	// And the other way round.
	f.enrol(alice, machineA2, f.token(authn.ClassWorker, "alice", "worker-a2", "s"), KeyClient)
	bob := f.bind("bob", ownerB)
	_, err = f.store.Enrol(ctx, bob, EnrolmentRequest{
		MachineID: machineB1, Credential: f.token(authn.ClassWorker, "bob", "worker-a2", "its-own"), KeyKind: KeySession,
	})
	assert.Equal(t, CodeConflict, CodeOf(err))

	_, err = f.store.Enrol(ctx, alice, EnrolmentRequest{MachineID: machineA1, Credential: a1, KeyKind: "proof"})
	assert.Equal(t, CodeInvalid, CodeOf(err))
}

// A forged machine, owner or class is refused at enrolment.
func TestEnrolRefusals(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	bob := f.bind("bob", ownerB)
	expiring := f.token(authn.ClassWorker, "alice", "worker-old", "")
	f.clock.Advance(5 * time.Minute)
	worker := f.token(authn.ClassWorker, "alice", "worker-a1", "")

	tests := []struct {
		name    string
		by      Scope
		request EnrolmentRequest
		want    Code
	}{
		{"AnotherOwnersMachine", alice, EnrolmentRequest{MachineID: machineB1, Credential: worker, KeyKind: KeyClient}, CodeNotFound},
		{"UnknownMachine", alice, EnrolmentRequest{MachineID: "mch_none", Credential: worker, KeyKind: KeyClient}, CodeNotFound},
		{"NoMachine", alice, EnrolmentRequest{Credential: worker, KeyKind: KeyClient}, CodeInvalid},
		{"CredentialOfAnotherOwner", alice, EnrolmentRequest{MachineID: machineA1, Credential: f.token(authn.ClassWorker, "bob", "worker-a1", ""), KeyKind: KeyClient}, CodeForbidden},
		{"CredentialOfAnUnboundIdentity", alice, EnrolmentRequest{MachineID: machineA1, Credential: f.token(authn.ClassWorker, "carol", "worker-a1", ""), KeyKind: KeyClient}, CodeForbidden},
		{"CLICredential", alice, EnrolmentRequest{MachineID: machineA1, Credential: f.token(authn.ClassCLI, "alice", "cli", ""), KeyKind: KeyClient}, CodeInvalid},
		{"PersonCredential", alice, EnrolmentRequest{MachineID: machineA1, Credential: person("alice"), KeyKind: KeyClient}, CodeInvalid},
		{"ExpiredCredential", alice, EnrolmentRequest{MachineID: machineA1, Credential: expiring, KeyKind: KeyClient}, CodeForbidden},
		{"CredentialWithNoClient", alice, EnrolmentRequest{MachineID: machineA1, Credential: f.token(authn.ClassWorker, "alice", "", ""), KeyKind: KeyClient}, CodeInvalid},
		{"ByAnotherOwnersPerson", bob, EnrolmentRequest{MachineID: machineA1, Credential: worker, KeyKind: KeyClient}, CodeNotFound},
		{"ByTheOwnersCLI", f.resolve(f.token(authn.ClassCLI, "alice", "cli", "")), EnrolmentRequest{MachineID: machineA1, Credential: worker, KeyKind: KeyClient}, CodeForbidden},
		{"ByThePlatformAdmin", f.admin, EnrolmentRequest{MachineID: machineA1, Credential: worker, KeyKind: KeyClient}, CodeForbidden},
		{"ByNobody", Scope{}, EnrolmentRequest{MachineID: machineA1, Credential: worker, KeyKind: KeyClient}, CodeForbidden},
	}
	for _, tt := range tests {
		_, err := f.store.Enrol(ctx, tt.by, tt.request)
		assert.Equal(t, tt.want, CodeOf(err), tt.name)
	}
	enrolments, err := f.store.Enrolments(ctx, ownerA)
	require.NoError(t, err)
	assert.Empty(t, enrolments)
	_, reason := f.machine(worker)
	assert.Equal(t, ReasonNotEnrolled, reason, "no refused enrolment left a key behind that works")

	// A machine already enrolled for a class is not re-pointed at another
	// credential.
	f.enrol(alice, machineA1, worker, KeyClient)
	other := f.token(authn.ClassWorker, "alice", "worker-new", "")
	_, err = f.store.Enrol(ctx, alice, EnrolmentRequest{MachineID: machineA1, Credential: other, KeyKind: KeyClient})
	assert.Equal(t, CodeConflict, CodeOf(err))
	machine, _ := f.machine(worker)
	assert.Equal(t, machineA1, machine.MachineID)
	// The refused credential's key was not claimed: it can still enrol the
	// machine it belongs to.
	f.enrol(alice, machineA2, other, KeyClient)
	machine, _ = f.machine(other)
	assert.Equal(t, machineA2, machine.MachineID)
}

// Class, subject and owner are checked beside the key on every resolution.
func TestMachineCredentialMustAgreeWithItsEnrolment(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	f.bind("bob", ownerB)
	worker := f.token(authn.ClassWorker, "alice", "worker-a1", "")
	f.enrol(alice, machineA1, worker, KeyClient)

	// Someone else signs in to the machine's client.
	_, reason := f.machine(f.token(authn.ClassWorker, "bob", "worker-a1", ""))
	assert.Equal(t, ReasonNotEnrolled, reason)
	// The same key presented as another class.
	_, reason = f.machine(f.token(authn.ClassReviewer, "alice", "worker-a1", ""))
	assert.Equal(t, ReasonClass, reason)
	// A CLI token is not a machine, and neither is a person.
	_, reason = f.machine(f.token(authn.ClassCLI, "alice", "worker-a1", ""))
	assert.Equal(t, ReasonClass, reason)
	_, reason = f.machine(person("alice"))
	assert.Equal(t, ReasonClass, reason)
	// The same subject from another issuer.
	foreign := worker
	foreign.Issuer = otherIssuer
	_, reason = f.machine(foreign)
	assert.Equal(t, ReasonNotEnrolled, reason)
	// An expired credential.
	f.clock.Advance(5 * time.Minute)
	_, reason = f.machine(worker)
	assert.Equal(t, ReasonExpired, reason)

	// The registry now says the machine is another owner's.
	fresh := f.token(authn.ClassWorker, "alice", "worker-a1", "")
	scope := f.resolve(fresh)
	require.Equal(t, ScopeMachine, scope.Kind())
	f.registry.setMachineOwner(machineA1, ownerB)
	_, reason = f.machine(fresh)
	assert.Equal(t, ReasonNotEnrolled, reason)
	f.registry.setMachineOwner(machineA1, ownerA)

	// The owner's binding is revoked: every machine under it stops.
	require.True(t, f.enforce(scope, PermissionExecute, f.job(jobA1)).Allowed)
	_, err := f.store.RevokeBinding(ctx, f.admin, person("alice").Identity, "left")
	require.NoError(t, err)
	decision := f.enforce(scope, PermissionExecute, f.job(jobA1))
	assert.False(t, decision.Allowed)
	assert.Equal(t, ReasonBindingRevoked, decision.Reason)
	_, reason = f.machine(fresh)
	assert.Equal(t, ReasonBindingRevoked, reason)

	// Bound again, the old machine scope is from the old binding.
	f.bind("alice", ownerA)
	assert.Equal(t, ReasonBindingRevoked, f.enforce(scope, PermissionExecute, f.job(jobA1)).Reason)
	machine, reason := f.machine(fresh)
	assert.Empty(t, reason)
	assert.Equal(t, machineA1, machine.MachineID)
}

func TestRevokeEnrolment(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	bob := f.bind("bob", ownerB)
	worker := f.token(authn.ClassWorker, "alice", "worker-a1", "")
	reviewer := f.token(authn.ClassReviewer, "alice", "reviewer-a1", "")
	f.enrol(alice, machineA1, worker, KeyClient)
	f.enrol(alice, machineA1, reviewer, KeyClient)

	_, err := f.store.RevokeEnrolment(ctx, bob, machineA1, authn.ClassWorker, "mine now")
	assert.Equal(t, CodeNotFound, CodeOf(err), "another owner learns nothing")
	_, err = f.store.RevokeEnrolment(ctx, alice, machineA1, authn.ClassWorker, "")
	assert.Equal(t, CodeInvalid, CodeOf(err))
	_, err = f.store.RevokeEnrolment(ctx, alice, machineA2, authn.ClassWorker, "none")
	assert.Equal(t, CodeNotFound, CodeOf(err))
	_, err = f.store.RevokeEnrolment(ctx, f.resolve(f.token(authn.ClassCLI, "alice", "cli", "")), machineA1, authn.ClassWorker, "cli")
	assert.Equal(t, CodeForbidden, CodeOf(err))

	// The platform administrator may revoke any enrolment.
	revoked, err := f.store.RevokeEnrolment(ctx, f.admin, machineA1, authn.ClassWorker, "incident")
	require.NoError(t, err)
	assert.Equal(t, StateRevoked, revoked.State)
	assert.Equal(t, ActorPlatformAdmin, revoked.Revoked.By.Kind)
	again, err := f.store.RevokeEnrolment(ctx, alice, machineA1, authn.ClassWorker, "again")
	require.NoError(t, err)
	assert.Equal(t, revoked, again)

	_, reason := f.machine(worker)
	assert.Equal(t, ReasonEnrolmentRevoked, reason)
	machine, reason := f.machine(reviewer)
	assert.Empty(t, reason, "the same machine's other class is a separate enrolment")
	assert.Equal(t, Machine{MachineID: machineA1, OwnerID: ownerA, Class: authn.ClassReviewer}, machine)
}

// Two machines that present the same key at the same moment: exactly one is
// enrolled.
func TestConcurrentEnrolmentsOfOneKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	alice := f.bind("alice", ownerA)
	credential := f.token(authn.ClassWorker, "alice", "worker", "browser-session")

	machines := []string{machineA1, machineA2}
	const each = 10
	errs := make([]error, 2*each)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 2 * each {
		wg.Go(func() {
			<-start
			_, errs[i] = f.store.Enrol(ctx, alice, EnrolmentRequest{MachineID: machines[i%2], Credential: credential, KeyKind: KeySession})
		})
	}
	close(start)
	wg.Wait()

	winner, reason := f.machine(credential)
	require.Empty(t, reason)
	require.Contains(t, machines, winner.MachineID)
	for i, err := range errs {
		if machines[i%2] == winner.MachineID {
			require.NoError(t, err)
		} else {
			assert.Equal(t, CodeConflict, CodeOf(err))
		}
	}
	enrolments, err := f.store.Enrolments(ctx, ownerA)
	require.NoError(t, err)
	require.Len(t, enrolments, 1)
	assert.Equal(t, winner.MachineID, enrolments[0].MachineID)
}
