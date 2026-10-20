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
	// by its own sign-in, through the provider client that exists for this
	// machine and class. Its class is the class enrolled, and the key is its
	// issuer and client.
	Credential authn.Principal
}

// Enrol lets a machine act for its owner.
//
// The caller must be a person acting for the machine's owner, as the registry
// records it. The credential must be a worker's or a reviewer's, unexpired,
// and its identity must be bound to that same owner.
//
// The enrolment is found from then on by the credential's issuer and client.
// That key belongs to the first machine and class it was enrolled for, for
// good: presenting it for another machine or class is refused with
// CodeConflict, the first enrolment is untouched, and nothing is ever
// reassigned. A machine that is both a worker and a reviewer has two clients.
//
// Enrolling again with the same credential returns the enrolment that stands.
// Another credential for a machine and class whose enrolment stands, or is
// being made, is refused with CodeConflict: revoke it first.
//
// The enrolment is written in three steps, each one record: it is reserved
// as pending, which grants nothing and settles which request the machine and
// class go to; then the key is claimed; then it is made active. A request
// that stops in between leaves a pending enrolment, which repeating the
// request finishes and revoking clears.
func (s *Store) Enrol(ctx context.Context, by Scope, request EnrolmentRequest) (*Enrolment, error) {
	by = asPerson(by)
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
	key, err := KeyOf(credential)
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

	// A key that is another machine's is refused before anything is written.
	claim, err := s.keyClaim(ctx, key)
	if err != nil {
		return nil, err
	}
	if claim != nil && (claim.MachineID != request.MachineID || claim.Class != class) {
		return nil, keyBelongsElsewhere()
	}

	want := Enrolment{
		Schema: SchemaVersion, MachineID: request.MachineID, Class: class, OwnerID: owner,
		Issuer: credential.Issuer, Subject: credential.Subject, Key: key, SessionID: credential.SessionID,
	}
	reserved, err := s.reserve(ctx, by, want)
	if err != nil {
		return nil, err
	}
	if reserved.State == StateActive {
		return reserved, nil
	}

	if err := s.claimKey(ctx, key, request.MachineID, class); err != nil {
		// The key went to another machine between the check above and here.
		// The reservation granted nothing; clear it so the machine is free.
		if CodeOf(err) == CodeConflict {
			if clearErr := s.clearReservation(ctx, by, reserved); clearErr != nil {
				return nil, clearErr
			}
		}
		return nil, err
	}
	return s.activate(ctx, reserved)
}

// reserve makes the machine and class this request's, as a pending enrolment,
// or returns the enrolment of the same credential that is already there. It
// is where two requests for one machine and class are told apart: one record,
// written by create or compare-and-swap, so exactly one of them holds it.
func (s *Store) reserve(ctx context.Context, by Scope, want Enrolment) (*Enrolment, error) {
	digest := enrolmentDigest(want.MachineID, want.Class)
	for range attempts {
		var current Enrolment
		raw, found, err := s.read(ctx, enrolmentsPrefix+digest, &current)
		if err != nil {
			return nil, err
		}
		if found && current.State != StateRevoked {
			if !sameCredential(&current, &want) {
				return nil, &Error{
					Code:    CodeConflict,
					Message: "the machine is already enrolled for this class, or being enrolled, with another credential; revoke that enrolment first",
					Current: &current,
				}
			}
			return &current, nil
		}
		next := want
		next.Generation, next.State = 1, StatePending
		next.Enrolled = Stamp{At: s.clock(), By: by.actor()}
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

// activate makes a pending enrolment active once its key is claimed.
func (s *Store) activate(ctx context.Context, reserved *Enrolment) (*Enrolment, error) {
	id := enrolmentsPrefix + enrolmentDigest(reserved.MachineID, reserved.Class)
	for range attempts {
		var current Enrolment
		raw, found, err := s.read(ctx, id, &current)
		if err != nil {
			return nil, err
		}
		if !found || current.Generation != reserved.Generation || !sameCredential(&current, reserved) || current.State == StateRevoked {
			// Revoked, or replaced, while it was being made.
			return nil, refuse(CodeConflict, "the enrolment was revoked while it was being made")
		}
		if current.State == StateActive {
			return &current, nil
		}
		current.State = StateActive
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

// clearReservation revokes a pending enrolment that cannot be finished.
func (s *Store) clearReservation(ctx context.Context, by Scope, reserved *Enrolment) error {
	id := enrolmentsPrefix + enrolmentDigest(reserved.MachineID, reserved.Class)
	for range attempts {
		var current Enrolment
		raw, found, err := s.read(ctx, id, &current)
		if err != nil {
			return err
		}
		if !found || current.Generation != reserved.Generation || current.State != StatePending {
			return nil
		}
		current.State = StateRevoked
		current.Revoked = &Revocation{At: s.clock(), By: by.actor(), Reason: "the credential's key belongs to another machine"}
		swapped, err := s.swap(ctx, id, raw, current)
		if err != nil {
			return err
		}
		if swapped {
			return nil
		}
	}
	return errContended
}

func sameCredential(a, b *Enrolment) bool {
	return a.Key == b.Key && a.Issuer == b.Issuer && a.Subject == b.Subject && a.OwnerID == b.OwnerID
}

func keyBelongsElsewhere() *Error {
	return refuse(CodeConflict,
		"this credential's client already belongs to another machine or class; it is not reassigned. "+
			"Each machine and class needs a provider client of its own")
}

// keyClaim returns the record of which machine and class a key belongs to,
// or nil when it belongs to none.
func (s *Store) keyClaim(ctx context.Context, key EnrolmentKey) (*keyClaim, error) {
	var claim keyClaim
	_, found, err := s.read(ctx, keysPrefix+keyDigest(key), &claim)
	if err != nil || !found {
		return nil, err
	}
	if claim.Key != key {
		// The record is found by a digest. A record for another key under
		// this one's digest is not this key's.
		return nil, errors.New("authz: an enrolment key record does not match its id")
	}
	return &claim, nil
}

// claimKey makes a key belong to a machine and class, or confirms that it
// already does. The claim is one create-only record, so of two machines that
// present the same key at the same moment exactly one gets it. Only the
// holder of the machine's reservation calls it.
func (s *Store) claimKey(ctx context.Context, key EnrolmentKey, machineID string, class authn.Class) error {
	claim := keyClaim{Schema: SchemaVersion, Key: key, MachineID: machineID, Class: class, ClaimedAt: s.clock()}
	created, err := s.create(ctx, keysPrefix+keyDigest(key), claim)
	if err != nil || created {
		return err
	}
	current, err := s.keyClaim(ctx, key)
	if err != nil {
		return err
	}
	if current == nil {
		return errContended
	}
	if current.MachineID != machineID || current.Class != class {
		return keyBelongsElsewhere()
	}
	return nil
}

// RevokeEnrolment ends a machine's enrolment for one class, or clears one
// that was left pending. From the next decision on, its credential acts for
// nobody. The key stays the machine's: it can be enrolled again for the same
// machine and class, and never for another. Revoking an enrolment that is
// already revoked returns it unchanged.
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

// Enrolments returns an owner's enrolments, pending and revoked ones
// included, oldest first.
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

type enrolled struct {
	enrolment *Enrolment
	binding   *Binding
	// reason says why there is no enrolment, when there is none.
	reason Reason
}

func notEnrolled(reason Reason) (enrolled, error) { return enrolled{reason: reason}, nil }

// activeEnrolment finds the enrolment a machine credential belongs to, with
// the binding of its identity, or the reason there is none.
//
// The enrolment is found by one key, the credential's issuer and client.
// There is no second way to find one, and nothing the caller says takes
// part. Everything else the credential carries must then agree with the
// enrolment found: class, issuer and subject. The identity's binding to the
// machine's owner, and the registry's record of who owns the machine, must
// still stand.
func (s *Store) activeEnrolment(ctx context.Context, p authn.Principal) (enrolled, error) {
	key, err := KeyOf(p)
	if err != nil {
		return notEnrolled(ReasonNotEnrolled)
	}
	claim, err := s.keyClaim(ctx, key)
	if err != nil {
		return enrolled{reason: ReasonEvaluationFailed}, err
	}
	if claim == nil {
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
	// The machine may have been enrolled again with another client since.
	case enrolment.Key != claim.Key || enrolment.MachineID != claim.MachineID || enrolment.Class != claim.Class:
		return notEnrolled(ReasonNotEnrolled)
	case enrolment.State == StateRevoked:
		return notEnrolled(ReasonEnrolmentRevoked)
	// A pending enrolment grants nothing.
	case enrolment.State != StateActive:
		return notEnrolled(ReasonNotEnrolled)
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
