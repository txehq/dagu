// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package authn verifies access tokens issued by the identity provider and
// names who a request is authenticated as.
//
// It is a library. Nothing in it listens, reads server configuration or
// accepts a credential by itself: a caller builds a Verifier and decides what
// a verified Principal may do.
//
// An identity is the pair of issuer and subject. Email, username and display
// name are never read, so two tokens that agree on those and differ in
// subject, or in issuer, are different identities.
package authn

import (
	"fmt"
	"slices"
	"time"
)

// Class says how a principal authenticated. It decides what kind of actor the
// principal is; it grants nothing by itself.
type Class string

const (
	// ClassPerson is a human signed in through the browser. It is the only
	// class that counts as a person. A bearer token never yields it.
	ClassPerson Class = "person"
	// ClassCLI is a developer's command-line session.
	ClassCLI Class = "cli"
	// ClassWorker is an enrolled machine running jobs.
	ClassWorker Class = "worker"
	// ClassReviewer is an enrolled machine reviewing jobs.
	ClassReviewer Class = "reviewer"
	// ClassPlatformAdmin is the installation's builtin administrator. A
	// bearer token never yields it.
	ClassPlatformAdmin Class = "platform_admin"
)

// Valid reports whether c is one of the defined classes.
func (c Class) Valid() bool {
	switch c {
	case ClassPerson, ClassCLI, ClassWorker, ClassReviewer, ClassPlatformAdmin:
		return true
	default:
		return false
	}
}

// Bearer reports whether a provider access token may yield c.
func (c Class) Bearer() bool {
	return c == ClassCLI || c == ClassWorker || c == ClassReviewer
}

// Machine reports whether c is a machine class, which acts only through a
// machine's enrolment.
func (c Class) Machine() bool {
	return c == ClassWorker || c == ClassReviewer
}

// Identity is who the provider says a principal is. Both fields are compared
// as exact strings.
type Identity struct {
	Issuer  string
	Subject string
}

// IsZero reports whether either field is missing. Such a value identifies
// nobody.
func (i Identity) IsZero() bool {
	return i.Issuer == "" || i.Subject == ""
}

// Principal is an authenticated caller.
type Principal struct {
	Identity
	Class Class
	// ClientID is the provider client the token was issued to.
	ClientID string
	// SessionID is the provider session the token belongs to (its "sid"
	// claim), or "" when the token names none. Tokens obtained by one
	// sign-in share it, and two sign-ins by the same subject differ in it,
	// which is what lets a credential be tied to one enrolled machine.
	// Nothing in this package relies on it: a caller that does must require
	// it to be present.
	SessionID string
	// IssuedAt and Expires bound the token the principal came from. A
	// principal must not be used at or after Expires.
	IssuedAt time.Time
	Expires  time.Time
}

// IsPerson reports whether the principal is a human signed in through the
// browser. Callers that need a personal decision must check this and not
// infer it from any other field.
func (p Principal) IsPerson() bool {
	return p.Class == ClassPerson
}

// RequireClass returns an error unless the principal has one of classes.
func (p Principal) RequireClass(classes ...Class) error {
	if slices.Contains(classes, p.Class) {
		return nil
	}
	return fmt.Errorf("authn: a %q principal is not accepted here", p.Class)
}
