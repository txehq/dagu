// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"errors"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// ScopeKind says what a principal resolved to.
type ScopeKind string

const (
	// ScopeUnbound is an authenticated principal that acts for nobody. It
	// holds no permission on anything.
	ScopeUnbound ScopeKind = "unbound"
	// ScopeOwner is a person or a developer's CLI acting for an owner.
	ScopeOwner ScopeKind = "owner"
	// ScopeMachine is an enrolled machine acting for its owner.
	ScopeMachine ScopeKind = "machine"
	// ScopePlatformAdmin is the installation's administrator. It owns
	// nothing; an administrator signed in through the identity provider whose
	// identity is bound is also that owner's person (OwnerPerson).
	ScopePlatformAdmin ScopeKind = "platform_admin"
)

// Scope is what a principal may act as. It is a snapshot: Decide checks again
// that the binding or enrolment it came from still stands.
//
// A Scope is built only by Resolve and PlatformAdmin. Its zero value is
// unbound.
type Scope struct {
	kind      ScopeKind
	principal authn.Principal
	ownerID   string
	// bindingGeneration is the binding the scope was resolved from.
	bindingGeneration int
	// machineID and enrolmentGeneration are set for a machine.
	machineID           string
	enrolmentGeneration int
	// admin is the platform administrator's account name.
	admin string
	// reason says why a principal is unbound.
	reason Reason
}

// Kind returns what the principal resolved to.
func (s Scope) Kind() ScopeKind {
	if s.kind == "" {
		return ScopeUnbound
	}
	return s.kind
}

// Principal returns the authenticated caller. For the platform administrator
// it is the person it also is, when it is bound, and otherwise the zero value.
func (s Scope) Principal() authn.Principal { return s.principal }

// OwnerID returns the owner the scope acts for, or "" when there is none. For
// the platform administrator it is the owner it is bound to as a person.
func (s Scope) OwnerID() string { return s.ownerID }

// MachineID returns the machine a machine scope is, or "".
func (s Scope) MachineID() string { return s.machineID }

// Class returns the class of the caller.
func (s Scope) Class() authn.Class {
	if s.Kind() == ScopePlatformAdmin {
		return authn.ClassPlatformAdmin
	}
	return s.principal.Class
}

// UnboundReason says why the principal acts for nobody, or "" when it acts
// for someone.
func (s Scope) UnboundReason() Reason { return s.reason }

func (s Scope) actor() Actor {
	if s.Kind() == ScopePlatformAdmin {
		return Actor{Kind: ActorPlatformAdmin, Name: s.admin}
	}
	return Actor{Kind: ActorPerson, Issuer: s.principal.Issuer, Subject: s.principal.Subject, OwnerID: s.ownerID}
}

// OwnerPerson returns the person a bound platform administrator also is:
// the scope of its identity's binding, as a person signed in through the
// browser would have it. It reports false for every other scope.
func (s Scope) OwnerPerson() (Scope, bool) {
	if s.Kind() != ScopePlatformAdmin || s.ownerID == "" {
		return Scope{}, false
	}
	return Scope{kind: ScopeOwner, principal: s.principal, ownerID: s.ownerID, bindingGeneration: s.bindingGeneration}, true
}

func unbound(p authn.Principal, reason Reason) Scope {
	return Scope{kind: ScopeUnbound, principal: p, reason: reason}
}

// PlatformAdmin returns the scope of the installation's administrator. The
// caller must have authenticated that administrator by the installation's own
// means; no token yields this scope. name is recorded with what the
// administrator does and is never matched.
func PlatformAdmin(name string) Scope {
	return Scope{kind: ScopePlatformAdmin, admin: name}
}

// ResolvePlatformAdmin returns the scope of a platform administrator who
// signed in through the identity provider as id: the administrator, and if
// id is bound to an owner, that owner's person too (OwnerPerson). Nothing is
// written; the binding is read again whenever the person's rights are used,
// so revoking it ends them on the next request. An unbound administrator is
// the administrator only. An error means the store could not be read.
func (s *Store) ResolvePlatformAdmin(ctx context.Context, name string, id authn.Identity) (Scope, error) {
	scope := PlatformAdmin(name)
	binding, _, err := s.activeBinding(ctx, id)
	if err != nil {
		return Scope{}, err
	}
	if binding != nil {
		scope.principal = authn.Principal{Identity: id, Class: authn.ClassPerson}
		scope.ownerID, scope.bindingGeneration = binding.OwnerID, binding.Generation
	}
	return scope, nil
}

// Resolve finds what an authenticated principal may act as.
//
// A person or a CLI acts for the owner its identity is bound to. A worker or
// a reviewer acts as the machine its credential is enrolled for. Anything
// else, a revoked binding or enrolment included, resolves to an unbound scope
// with the reason, and no error: being unbound is an answer, not a failure.
// An error means the store or the registry could not be read, and the caller
// must not proceed as if the principal were unbound.
func (s *Store) Resolve(ctx context.Context, p authn.Principal) (Scope, error) {
	if p.IsZero() {
		return unbound(p, ReasonNoIdentity), nil
	}
	if expired(p, s.clock()) {
		return unbound(p, ReasonExpired), nil
	}
	switch {
	case p.Class == authn.ClassPerson || p.Class == authn.ClassCLI:
		binding, reason, err := s.activeBinding(ctx, p.Identity)
		if err != nil {
			return Scope{}, err
		}
		if binding == nil {
			return unbound(p, reason), nil
		}
		return Scope{kind: ScopeOwner, principal: p, ownerID: binding.OwnerID, bindingGeneration: binding.Generation}, nil

	case p.Class.Machine():
		found, err := s.activeEnrolment(ctx, p)
		if err != nil {
			return Scope{}, err
		}
		if found.enrolment == nil {
			return unbound(p, found.reason), nil
		}
		return Scope{
			kind:                ScopeMachine,
			principal:           p,
			ownerID:             found.enrolment.OwnerID,
			bindingGeneration:   found.binding.Generation,
			machineID:           found.enrolment.MachineID,
			enrolmentGeneration: found.enrolment.Generation,
		}, nil

	default:
		// The platform administrator is not a principal a token can be, and
		// an unknown class is nobody.
		return unbound(p, ReasonClass), nil
	}
}

// Machine is the enrolled machine a credential belongs to.
type Machine struct {
	MachineID string
	OwnerID   string
	Class     authn.Class
}

// ResolveMachine finds the machine a worker's or reviewer's credential is
// enrolled for. It is Resolve for callers that accept machines only, such as
// a worker transport: anything else is refused with the reason.
//
// The machine comes from the credential and from nothing else. A caller that
// was also told a machine id must compare it with the one returned and refuse
// a difference; it must never use it to choose.
func (s *Store) ResolveMachine(ctx context.Context, p authn.Principal) (Machine, Reason, error) {
	if !p.Class.Machine() {
		return Machine{}, ReasonClass, nil
	}
	scope, err := s.Resolve(ctx, p)
	if err != nil {
		return Machine{}, ReasonEvaluationFailed, err
	}
	if scope.Kind() != ScopeMachine {
		return Machine{}, scope.reason, nil
	}
	return Machine{MachineID: scope.machineID, OwnerID: scope.ownerID, Class: p.Class}, "", nil
}

// expired reports whether a principal is at or past the expiry of the token
// it came from. A principal with no expiry, such as a person whose session
// the caller keeps alive by other means, does not expire here.
func expired(p authn.Principal, now time.Time) bool {
	return !p.Expires.IsZero() && !now.Before(p.Expires)
}

// Resource is something a decision is about. It carries the owner the
// registry records for it. It is built only by the constructors below, each
// of which looks the owner up, so an owner named in a request cannot become
// the owner a decision is made against.
type Resource struct {
	kind      ResourceKind
	id        string
	ownerID   string
	projectID string
	machineID string
}

// Kind returns the kind of resource.
func (r Resource) Kind() ResourceKind { return r.kind }

// ID returns the resource's id.
func (r Resource) ID() string { return r.id }

// OwnerID returns the owner the registry records for the resource. It is ""
// for the platform.
func (r Resource) OwnerID() string { return r.ownerID }

// Job returns the job as a resource, with its owner, project and machine as
// the registry records them.
func (s *Store) Job(ctx context.Context, jobID string) (Resource, error) {
	if jobID == "" {
		return Resource{}, refuse(CodeInvalid, "a job id is required")
	}
	facts, err := s.registry.JobFacts(ctx, jobID)
	owner, err := lookupOwner(facts.OwnerID, err, "job", jobID)
	if err != nil {
		return Resource{}, err
	}
	return Resource{kind: KindJob, id: jobID, ownerID: owner, projectID: facts.ProjectID, machineID: facts.MachineID}, nil
}

// Project returns the project as a resource.
func (s *Store) Project(ctx context.Context, projectID string) (Resource, error) {
	if projectID == "" {
		return Resource{}, refuse(CodeInvalid, "a project id is required")
	}
	owner, err := s.registry.ProjectOwner(ctx, projectID)
	owner, err = lookupOwner(owner, err, "project", projectID)
	if err != nil {
		return Resource{}, err
	}
	return Resource{kind: KindProject, id: projectID, ownerID: owner, projectID: projectID}, nil
}

// Machine returns the machine as a resource.
func (s *Store) Machine(ctx context.Context, machineID string) (Resource, error) {
	if machineID == "" {
		return Resource{}, refuse(CodeInvalid, "a machine id is required")
	}
	owner, err := s.registry.MachineOwner(ctx, machineID)
	owner, err = lookupOwner(owner, err, "machine", machineID)
	if err != nil {
		return Resource{}, err
	}
	return Resource{kind: KindMachine, id: machineID, ownerID: owner, machineID: machineID}, nil
}

// OwnData returns everything the scope's own owner holds, for a request that
// lists or creates under it. The owner is the scope's, so there is nothing to
// look up and nothing a request can substitute. It fails for a scope with no
// owner.
func OwnData(scope Scope) (Resource, error) {
	if scope.ownerID == "" {
		return Resource{}, errors.New("authz: the scope acts for no owner")
	}
	return Resource{kind: KindOwner, id: scope.ownerID, ownerID: scope.ownerID}, nil
}

// Platform returns the installation itself: its bindings and their requests.
func Platform() Resource {
	return Resource{kind: KindPlatform, id: "platform"}
}
