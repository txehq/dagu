// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// EnrolmentRequest asks for a machine to be enrolled.
type EnrolmentRequest struct {
	// MachineID is the machine, as the registry knows it.
	MachineID string
	// Credential is the verified principal of a token the machine obtained
	// by its own sign-in. Its class is the class enrolled, and the key is
	// read from it.
	Credential authn.Principal
	// KeyKind chooses which provider-set value ties the credential to the
	// machine.
	KeyKind KeyKind
}

// Enrol lets a machine act for its owner.
//
// The caller must be a person acting for the machine's owner, as the registry
// records it. The credential must be a worker's or a reviewer's, unexpired,
// and its identity must be bound to that same owner.
//
// The enrolment is found from then on by the key the credential carries. A
// key belongs to the first machine and class it was enrolled for, for good:
// presenting it for another machine is refused with CodeConflict, the first
// enrolment is untouched, and nothing is ever reassigned. That is what makes
// two machines that received the same key from the provider fail closed
// instead of becoming each other.
//
// Enrolling again with the same key and identity returns the enrolment that
// stands. A different key or identity for a machine and class whose
// enrolment stands is refused with CodeConflict: revoke it first.
func (s *Store) Enrol(ctx context.Context, by Scope, request EnrolmentRequest) (*Enrolment, error) {
	if err := s.requirePerson(ctx, by); err != nil {
		return nil, err
	}
	credential := request.Credential
	class := credential.Class
	if !class.Machine() {
		return nil, refuse(CodeInvalid, "only a worker or a reviewer credential enrols a machine, not a %q one", class)
	}
	if credential.IsZero() {
		return nil, refuse(CodeInvalid, "the credential has no issuer or no subject")
	}
	if expired(credential, s.clock()) {
		return nil, refuse(CodeForbidden, "the credential has expired")
	}
	if request.MachineID == "" {
		return nil, refuse(CodeInvalid, "a machine id is required")
	}
	key, err := KeyOf(request.KeyKind, credential)
	if err != nil {
		return nil, err
	}

	owner, err := s.registry.MachineOwner(ctx, request.MachineID)
	owner, err = lookupOwner(owner, err, "machine", request.MachineID)
	if err != nil {
		return nil, err
	}
	if owner != by.ownerID {
		// Another owner's machine is answered like one that does not exist.
		return nil, refuse(CodeNotFound, "machine %s is not registered", request.MachineID)
	}
	binding, _, err := s.activeBinding(ctx, credential.Identity)
	if err != nil {
		return nil, err
	}
	if binding == nil || binding.OwnerID != owner {
		return nil, refuse(CodeForbidden, "the credential's identity is not bound to the machine's owner")
	}

	// Judge the machine's standing enrolment before claiming anything, so
	// that a refused request leaves no claim behind.
	digest := enrolmentDigest(request.MachineID, class)
	var standing Enrolment
	if _, found, err := s.read(ctx, enrolmentsPrefix+digest, &standing); err != nil {
		return nil, err
	} else if found && standing.State == StateActive && !sameEnrolment(&standing, key, credential, owner) {
		return nil, enrolledOtherwise(&standing)
	}

	if err := s.claimKey(ctx, key, request.MachineID, class); err != nil {
		return nil, err
	}

	for range attempts {
		var current Enrolment
		raw, found, err := s.read(ctx, enrolmentsPrefix+digest, &current)
		if err != nil {
			return nil, err
		}
		if found && current.State == StateActive {
			if !sameEnrolment(&current, key, credential, owner) {
				return nil, enrolledOtherwise(&current)
			}
			return &current, nil
		}
		next := Enrolment{
			Schema: SchemaVersion, MachineID: request.MachineID, Class: class, OwnerID: owner,
			Issuer: credential.Issuer, Subject: credential.Subject, Key: key,
			Generation: 1, State: StateActive, Enrolled: Stamp{At: s.clock(), By: by.actor()},
		}
		var applied bool
		if found {
			next.Generation = current.Generation + 1
			if err := s.archive(ctx, enrolmentHistory, digest, current.Generation, current); err != nil {
				return nil, err
			}
			applied, err = s.swap(ctx, enrolmentsPrefix+digest, raw, next)
		} else {
			applied, err = s.create(ctx, enrolmentsPrefix+digest, next)
		}
		if err != nil {
			return nil, err
		}
		if applied {
			return &next, nil
		}
	}
	return nil, errContended
}

func sameEnrolment(e *Enrolment, key EnrolmentKey, credential authn.Principal, owner string) bool {
	return e.Key == key && e.Issuer == credential.Issuer && e.Subject == credential.Subject && e.OwnerID == owner
}

func enrolledOtherwise(current *Enrolment) *Error {
	return &Error{
		Code:    CodeConflict,
		Message: "the machine is already enrolled for this class with another credential; revoke that enrolment first",
		Current: current,
	}
}

// claimKey makes a key belong to a machine and class, or confirms that it
// already does. The claim is one create-only record, so of two machines that
// present the same key at the same moment exactly one gets it.
//
// It first fixes which kind of key the client's machines are enrolled by. A
// client is used with one kind only.
func (s *Store) claimKey(ctx context.Context, key EnrolmentKey, machineID string, class authn.Class) error {
	mode, err := s.claimMode(ctx, key)
	if err != nil {
		return err
	}
	if mode != key.Kind {
		return refuse(CodeConflict,
			"machines of this provider client are enrolled by %s key; a client is used with one kind of key only", mode)
	}

	id := keysPrefix + keyDigest(key)
	claim := keyClaim{Schema: SchemaVersion, Key: key, MachineID: machineID, Class: class, ClaimedAt: s.clock()}
	created, err := s.create(ctx, id, claim)
	if err != nil || created {
		return err
	}
	var current keyClaim
	_, found, err := s.read(ctx, id, &current)
	if err != nil {
		return err
	}
	if !found {
		return errContended
	}
	if current.Key != key || current.MachineID != machineID || current.Class != class {
		return refuse(CodeConflict,
			"this credential's key already belongs to another machine or class; it is not reassigned. "+
				"The provider gave two sign-ins the same key: sign the machine in so that it gets its own")
	}
	return nil
}

// claimMode records the kind of key a client's machines are enrolled by, the
// first time one is enrolled, and returns the kind that stands.
func (s *Store) claimMode(ctx context.Context, key EnrolmentKey) (KeyKind, error) {
	id := modesPrefix + clientDigest(key.Issuer, key.ClientID)
	created, err := s.create(ctx, id, clientMode{Schema: SchemaVersion, Issuer: key.Issuer, ClientID: key.ClientID, Kind: key.Kind})
	if err != nil {
		return "", err
	}
	if created {
		return key.Kind, nil
	}
	return s.modeOf(ctx, key.Issuer, key.ClientID)
}

// modeOf returns the kind of key a client's machines are enrolled by, or ""
// when none has been enrolled.
func (s *Store) modeOf(ctx context.Context, issuer, clientID string) (KeyKind, error) {
	var mode clientMode
	_, found, err := s.read(ctx, modesPrefix+clientDigest(issuer, clientID), &mode)
	if err != nil || !found {
		return "", err
	}
	if mode.Issuer != issuer || mode.ClientID != clientID {
		return "", nil
	}
	return mode.Kind, nil
}

// RevokeEnrolment ends a machine's enrolment for one class. From the next
// decision on, its credential acts for nobody. The key stays the machine's:
// it can be enrolled again for the same machine and class, and never for
// another. Revoking an enrolment that is already revoked returns it
// unchanged.
//
// The caller is a person acting for the machine's owner, or the platform
// administrator.
func (s *Store) RevokeEnrolment(ctx context.Context, by Scope, machineID string, class authn.Class, reason string) (*Enrolment, error) {
	if reason == "" {
		return nil, refuse(CodeInvalid, "a reason is required")
	}
	if by.Kind() != ScopePlatformAdmin {
		if err := s.requirePerson(ctx, by); err != nil {
			return nil, err
		}
	}
	id := enrolmentsPrefix + enrolmentDigest(machineID, class)
	for range attempts {
		var current Enrolment
		raw, found, err := s.read(ctx, id, &current)
		if err != nil {
			return nil, err
		}
		if !found || (by.Kind() != ScopePlatformAdmin && current.OwnerID != by.ownerID) {
			return nil, refuse(CodeNotFound, "machine %s has no %s enrolment", machineID, class)
		}
		if current.State == StateRevoked {
			return &current, nil
		}
		current.State = StateRevoked
		current.Revoked = &Revocation{At: s.clock(), By: by.actor(), Reason: reason}
		swapped, err := s.swap(ctx, id, raw, current)
		if err != nil {
			return nil, err
		}
		if swapped {
			return &current, nil
		}
	}
	return nil, errContended
}

// Enrolments returns an owner's enrolments, revoked ones included, oldest
// first.
func (s *Store) Enrolments(ctx context.Context, ownerID string) ([]*Enrolment, error) {
	var out []*Enrolment
	err := s.each(ctx, enrolmentsPrefix, func(data []byte) error {
		var enrolment Enrolment
		if err := json.Unmarshal(data, &enrolment); err != nil {
			return err
		}
		if enrolment.OwnerID == ownerID {
			out = append(out, &enrolment)
		}
		return nil
	})
	return out, err
}

// activeEnrolment finds the enrolment a machine credential belongs to, with
// the binding of its identity, or the reason there is none.
//
// The enrolment is found by a key read from the credential, of the kind its
// client's machines are enrolled by. Nothing the caller says takes part.
// Everything else the credential carries must then agree with the enrolment
// found: class, issuer and subject. The identity's binding to the machine's
// owner, and the registry's record of who owns the machine, must still stand.
type enrolled struct {
	enrolment *Enrolment
	binding   *Binding
	// reason says why there is no enrolment, when there is none.
	reason Reason
}

func notEnrolled(reason Reason) (enrolled, error) { return enrolled{reason: reason}, nil }

func (s *Store) activeEnrolment(ctx context.Context, p authn.Principal) (enrolled, error) {
	kind, err := s.modeOf(ctx, p.Issuer, p.ClientID)
	if err != nil {
		return enrolled{reason: ReasonEvaluationFailed}, err
	}
	if kind == "" {
		return notEnrolled(ReasonNotEnrolled)
	}
	key, err := KeyOf(kind, p)
	if err != nil {
		// A session key is wanted and the credential names no session.
		return notEnrolled(ReasonNotEnrolled)
	}
	var claim keyClaim
	_, claimed, err := s.read(ctx, keysPrefix+keyDigest(key), &claim)
	if err != nil {
		return enrolled{reason: ReasonEvaluationFailed}, err
	}
	if !claimed || claim.Key != key {
		return notEnrolled(ReasonNotEnrolled)
	}

	var enrolment Enrolment
	_, found, err := s.read(ctx, enrolmentsPrefix+enrolmentDigest(claim.MachineID, claim.Class), &enrolment)
	if err != nil {
		return enrolled{reason: ReasonEvaluationFailed}, err
	}
	switch {
	case !found:
		return notEnrolled(ReasonNotEnrolled)
	// The machine may have been enrolled again with another key since.
	case enrolment.Key != claim.Key || enrolment.MachineID != claim.MachineID || enrolment.Class != claim.Class:
		return notEnrolled(ReasonNotEnrolled)
	case enrolment.State != StateActive:
		return notEnrolled(ReasonEnrolmentRevoked)
	case enrolment.Class != p.Class:
		return notEnrolled(ReasonClass)
	case enrolment.Issuer != p.Issuer || enrolment.Subject != p.Subject:
		return notEnrolled(ReasonNotEnrolled)
	}

	binding, reason, err := s.activeBinding(ctx, p.Identity)
	if err != nil {
		return enrolled{reason: ReasonEvaluationFailed}, err
	}
	if binding == nil {
		return notEnrolled(reason)
	}
	if binding.OwnerID != enrolment.OwnerID {
		return notEnrolled(ReasonBindingRevoked)
	}
	// The registry is the authority on who owns the machine, now.
	owner, err := s.registry.MachineOwner(ctx, enrolment.MachineID)
	if errors.Is(err, ErrNotFound) {
		return notEnrolled(ReasonNotEnrolled)
	}
	if err != nil {
		return enrolled{reason: ReasonEvaluationFailed}, err
	}
	if owner != enrolment.OwnerID {
		return notEnrolled(ReasonNotEnrolled)
	}
	return enrolled{enrolment: &enrolment, binding: binding}, nil
}
