// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/stretchr/testify/require"
)

const (
	issuer      = "https://issuer.example/realms/test"
	otherIssuer = "https://issuer.example/realms/other"

	ownerA = "own_A"
	ownerB = "own_B"

	projectA  = "prj_A"
	jobA1     = "job_A1" // owner A, project A, machine A1
	jobA2     = "job_A2" // owner A, project A, machine A2
	jobB1     = "job_B1" // owner B
	machineA1 = "mch_A1"
	machineA2 = "mch_A2"
	machineB1 = "mch_B1"
)

// fakeRegistry is the registry's answer to the four questions this package
// asks. It records nothing this package does, so a test can check that
// nothing was created in it.
type fakeRegistry struct {
	mu       sync.Mutex
	owners   map[string]bool
	jobs     map[string]JobFacts
	projects map[string]string
	machines map[string]string
	err      error
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		owners: map[string]bool{ownerA: true, ownerB: true},
		jobs: map[string]JobFacts{
			jobA1: {OwnerID: ownerA, ProjectID: projectA, MachineID: machineA1},
			jobA2: {OwnerID: ownerA, ProjectID: projectA, MachineID: machineA2},
			jobB1: {OwnerID: ownerB, ProjectID: "prj_B", MachineID: machineB1},
		},
		projects: map[string]string{projectA: ownerA, "prj_B": ownerB},
		machines: map[string]string{machineA1: ownerA, machineA2: ownerA, machineB1: ownerB},
	}
}

func (r *fakeRegistry) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

func (r *fakeRegistry) setMachineOwner(machineID, ownerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.machines[machineID] = ownerID
}

func (r *fakeRegistry) ownerCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.owners)
}

func (r *fakeRegistry) OwnerExists(_ context.Context, ownerID string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.owners[ownerID], r.err
}

func (r *fakeRegistry) JobFacts(_ context.Context, jobID string) (JobFacts, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return JobFacts{}, r.err
	}
	facts, ok := r.jobs[jobID]
	if !ok {
		return JobFacts{}, ErrNotFound
	}
	return facts, nil
}

func (r *fakeRegistry) ProjectOwner(_ context.Context, projectID string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return "", r.err
	}
	owner, ok := r.projects[projectID]
	if !ok {
		return "", ErrNotFound
	}
	return owner, nil
}

func (r *fakeRegistry) MachineOwner(_ context.Context, machineID string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return "", r.err
	}
	owner, ok := r.machines[machineID]
	if !ok {
		return "", ErrNotFound
	}
	return owner, nil
}

var errRegistryDown = errors.New("registry unavailable")

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fixture is a store on real files with a fake registry and a hand-moved
// clock.
type fixture struct {
	t        *testing.T
	store    *Store
	registry *fakeRegistry
	clock    *testClock
	admin    Scope
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		t:        t,
		registry: newFakeRegistry(),
		clock:    &testClock{now: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)},
		admin:    PlatformAdmin("admin"),
	}
	store, err := NewFileStore(t.TempDir(), f.registry, WithClock(f.clock.Now))
	require.NoError(t, err)
	f.store = store
	return f
}

// person is someone signed in through the browser. Its session does not
// expire here.
func person(subject string) authn.Principal {
	return authn.Principal{Identity: authn.Identity{Issuer: issuer, Subject: subject}, Class: authn.ClassPerson}
}

// token is a verified bearer principal, valid for five minutes from now.
func (f *fixture) token(class authn.Class, subject, client, session string) authn.Principal {
	now := f.clock.Now()
	return authn.Principal{
		Identity:  authn.Identity{Issuer: issuer, Subject: subject},
		Class:     class,
		ClientID:  client,
		SessionID: session,
		IssuedAt:  now,
		Expires:   now.Add(5 * time.Minute),
	}
}

// bind signs subject in, has the administrator approve it for owner, and
// returns the person's scope.
func (f *fixture) bind(subject, ownerID string) Scope {
	f.t.Helper()
	ctx := context.Background()
	_, err := f.store.RequestBinding(ctx, person(subject), Shown{Username: subject, Email: subject + "@example.invalid"})
	require.NoError(f.t, err)
	_, err = f.store.ApproveBinding(ctx, f.admin, person(subject).Identity, ownerID)
	require.NoError(f.t, err)
	return f.resolve(person(subject))
}

func (f *fixture) resolve(p authn.Principal) Scope {
	f.t.Helper()
	scope, err := f.store.Resolve(context.Background(), p)
	require.NoError(f.t, err)
	return scope
}

func (f *fixture) job(jobID string) Resource {
	f.t.Helper()
	resource, err := f.store.Job(context.Background(), jobID)
	require.NoError(f.t, err)
	return resource
}

// enforce returns the decision in ModeEnforce.
func (f *fixture) enforce(scope Scope, permission Permission, resource Resource) Decision {
	f.t.Helper()
	decision, err := f.store.Decide(context.Background(), ModeEnforce, scope, permission, resource)
	require.NoError(f.t, err)
	return decision
}

// enrol enrols a machine with a credential, as the person scope given.
func (f *fixture) enrol(by Scope, machineID string, credential authn.Principal) *Enrolment {
	f.t.Helper()
	enrolment, err := f.store.Enrol(context.Background(), by, EnrolmentRequest{MachineID: machineID, Credential: credential})
	require.NoError(f.t, err)
	return enrolment
}
