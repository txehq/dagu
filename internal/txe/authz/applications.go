// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// CodeStale is an enrolment application whose credential has expired: the
// machine must present a fresh one before its owner can approve it.
const CodeStale Code = "credential_stale"

// EnrolmentApplication records that a machine signed in through the
// provider client that exists for it and one class, and asks to be enrolled.
// It grants nothing. Its owner's person approves it while the credential it
// carries is still unexpired; the machine keeps it fresh by applying again.
type EnrolmentApplication struct {
	Schema    int         `json:"schema"`
	MachineID string      `json:"machine_id"`
	Class     authn.Class `json:"class"`
	Issuer    string      `json:"issuer"`
	Subject   string      `json:"subject"`
	ClientID  string      `json:"client_id"`
	SessionID string      `json:"session_id,omitempty"`
	// ReceivedAt is when the latest credential was presented.
	ReceivedAt time.Time `json:"received_at"`
	// CredentialIssuedAt and CredentialExpires bound the latest credential.
	// Nothing is enrolled from it at or after its expiry.
	CredentialIssuedAt time.Time `json:"credential_issued_at"`
	CredentialExpires  time.Time `json:"credential_expires"`
}

const applicationsPrefix = "enrolment_applications/"

func applicationID(machineID string, class authn.Class, clientID string) string {
	return applicationsPrefix + digest("application", machineID, string(class), clientID)
}

// ApplyForEnrolment records a machine's application to be enrolled, from
// the verified principal of the machine's own sign-in. Applying again with a
// newer credential replaces the one on file, so the owner can approve within
// the newer credential's lifetime.
//
// Only a worker or reviewer credential applies, and only for a machine of
// the owner its identity is bound to. Any other machine, registered or not,
// is answered as not found, so an application tells nobody which machines
// exist and nobody can file one against another owner's machine. A
// credential that is already enrolled has nothing to apply for and is
// refused with CodeConflict.
func (s *Store) ApplyForEnrolment(ctx context.Context, p authn.Principal, machineID string) (*EnrolmentApplication, error) {
	if !p.Class.Machine() {
		return nil, refuse(CodeForbidden, "only a worker or a reviewer credential applies to enrol a machine, not a %q one", p.Class)
	}
	if p.IsZero() || p.ClientID == "" {
		return nil, refuse(CodeInvalid, "the credential names no issuer, subject or client")
	}
	if p.Expires.IsZero() {
		// A stored credential with no expiry would never go stale, and
		// could be approved at any time later.
		return nil, refuse(CodeInvalid, "the credential carries no expiry")
	}
	if expired(p, s.clock()) {
		return nil, refuse(CodeForbidden, "the credential has expired")
	}
	if machineID == "" {
		return nil, refuse(CodeInvalid, "a machine id is required")
	}
	owner, err := s.registry.MachineOwner(ctx, machineID)
	owner, err = lookupOwner(owner, err, "machine", machineID)
	if err != nil {
		return nil, err
	}
	binding, _, err := s.activeBinding(ctx, p.Identity)
	if err != nil {
		return nil, err
	}
	if binding == nil || binding.OwnerID != owner {
		return nil, refuse(CodeNotFound, "machine %s is not registered", machineID)
	}
	found, err := s.activeEnrolment(ctx, p)
	if err != nil {
		return nil, err
	}
	if found.enrolment != nil {
		return nil, refuse(CodeConflict, "this credential is already enrolled")
	}

	next := EnrolmentApplication{
		Schema: SchemaVersion, MachineID: machineID, Class: p.Class, Issuer: p.Issuer, Subject: p.Subject,
		ClientID: p.ClientID, SessionID: p.SessionID, ReceivedAt: s.clock(),
		CredentialIssuedAt: p.IssuedAt, CredentialExpires: p.Expires,
	}
	id := applicationID(machineID, p.Class, p.ClientID)
	for range attempts {
		var current EnrolmentApplication
		raw, exists, err := s.read(ctx, id, &current)
		if err != nil {
			return nil, err
		}
		if !exists {
			created, err := s.create(ctx, id, next)
			if err != nil {
				return nil, err
			}
			if created {
				return &next, nil
			}
			continue
		}
		// One record per machine, class and client: another identity on the
		// same client replaces it only by presenting its own credential,
		// which the owner then sees before approving.
		if !next.CredentialExpires.After(current.CredentialExpires) && current.Issuer == next.Issuer && current.Subject == next.Subject {
			return &current, nil
		}
		swapped, err := s.swap(ctx, id, raw, next)
		if err != nil {
			return nil, err
		}
		if swapped {
			return &next, nil
		}
	}
	return nil, errContended
}

// EnrolmentApplications returns the applications on file for a machine,
// oldest first. The caller decides who may see them.
func (s *Store) EnrolmentApplications(ctx context.Context, machineID string) ([]*EnrolmentApplication, error) {
	var out []*EnrolmentApplication
	err := s.each(ctx, applicationsPrefix, func(data []byte) error {
		var application EnrolmentApplication
		if err := json.Unmarshal(data, &application); err != nil {
			return err
		}
		if application.MachineID == machineID {
			out = append(out, &application)
		}
		return nil
	})
	slices.SortStableFunc(out, func(a, b *EnrolmentApplication) int { return a.ReceivedAt.Compare(b.ReceivedAt) })
	return out, err
}

// EnrolFromApplication enrols a machine from its application on file, as
// Enrol does from a credential presented in the same request. The caller
// must be a person acting for the machine's owner, and names the identity
// it read on the application: if the application on file is now another
// identity's, it is refused with CodeConflict, so an owner never enrols an
// identity it did not see. An application whose credential has expired is
// refused with CodeStale and changes nothing: the machine applies again with
// a fresh credential.
func (s *Store) EnrolFromApplication(ctx context.Context, by Scope, machineID string, class authn.Class, clientID string, seen authn.Identity) (*Enrolment, error) {
	if err := s.requirePerson(ctx, by); err != nil {
		return nil, err
	}
	notFound := refuse(CodeNotFound, "machine %s has no %s application from client %s", machineID, class, clientID)
	// Another owner's machine is answered before its applications are
	// looked at, exactly as a machine with none: nothing about them is told.
	owner, err := s.registry.MachineOwner(ctx, machineID)
	if errors.Is(err, ErrNotFound) {
		return nil, notFound
	}
	if err != nil {
		return nil, err
	}
	if owner != by.ownerID {
		return nil, notFound
	}
	var application EnrolmentApplication
	_, found, err := s.read(ctx, applicationID(machineID, class, clientID), &application)
	if err != nil {
		return nil, err
	}
	if !found || application.MachineID != machineID || application.Class != class || application.ClientID != clientID {
		return nil, notFound
	}
	if application.Issuer != seen.Issuer || application.Subject != seen.Subject {
		return nil, &Error{Code: CodeConflict, Message: "the application on file is not the one you read; read it again", Current: &application}
	}
	credential := authn.Principal{
		Identity: authn.Identity{Issuer: application.Issuer, Subject: application.Subject},
		Class:    application.Class, ClientID: application.ClientID, SessionID: application.SessionID,
		IssuedAt: application.CredentialIssuedAt, Expires: application.CredentialExpires,
	}
	if credential.Expires.IsZero() || expired(credential, s.clock()) {
		return nil, &Error{Code: CodeStale, Message: "the application's credential has expired; the machine must apply again", Current: &application}
	}
	return s.Enrol(ctx, by, EnrolmentRequest{MachineID: machineID, Credential: credential})
}
