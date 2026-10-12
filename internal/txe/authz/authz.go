// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package authz decides who may do what to whose data.
//
// It is a library. Nothing in it listens, reads server configuration or is
// called by a route: a caller resolves an authenticated principal to a Scope,
// names a Resource through the registry, and asks Decide.
//
// The rules it holds:
//
//   - Data belongs to an owner. An identity, which is an issuer and a subject
//     and nothing else, acts for an owner only through an active binding. A
//     binding is made by the platform administrator against a recorded request,
//     for an owner that already exists. Nothing here creates an owner, and
//     nothing matches a login, an email address or a name.
//   - A machine acts for its owner only through an enrolment, which is found by
//     a key the identity provider sets and never by what a request says.
//   - A principal with no binding or enrolment has no owner and no permission.
//     It inherits nothing from any other kind of user.
//   - Every decision reads the binding, share or enrolment it relies on again,
//     so a revocation takes effect on the next decision.
//   - A resource's owner is looked up through the Registry. It is never taken
//     from a request.
package authz

import (
	"errors"
	"fmt"
	"slices"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// SchemaVersion is the version written into every record of this package.
const SchemaVersion = 1

// Permission is one thing a principal may do to a resource.
type Permission string

const (
	// PermissionView reads.
	PermissionView Permission = "view"
	// PermissionAuthor creates and changes.
	PermissionAuthor Permission = "author"
	// PermissionExecute runs, retries and stops.
	PermissionExecute Permission = "execute"
	// PermissionApprove makes a personal decision. Only a person holds it.
	PermissionApprove Permission = "approve"
	// PermissionAdminister manages bindings, shares and enrolments. Only a
	// person, or the platform administrator, holds it, and it cannot be shared.
	PermissionAdminister Permission = "administer"
)

var allPermissions = []Permission{
	PermissionView, PermissionAuthor, PermissionExecute, PermissionApprove, PermissionAdminister,
}

// Valid reports whether p is a defined permission.
func (p Permission) Valid() bool {
	return slices.Contains(allPermissions, p)
}

// Shareable reports whether an owner may grant p to another owner.
func (p Permission) Shareable() bool {
	return p.Valid() && p != PermissionAdminister
}

// classPermissions is what each class of principal may ever hold on its own
// owner's data. A share can only narrow it.
var classPermissions = map[authn.Class][]Permission{
	authn.ClassPerson:   allPermissions,
	authn.ClassCLI:      {PermissionView, PermissionAuthor, PermissionExecute},
	authn.ClassWorker:   {PermissionView, PermissionExecute},
	authn.ClassReviewer: {PermissionView, PermissionExecute},
}

// Mode says what Decide does with what it finds.
type Mode string

const (
	// ModeOff allows everything without evaluating. It is the behaviour of a
	// service that does not use this package.
	ModeOff Mode = "off"
	// ModeObserve evaluates, allows, and reports what ModeEnforce would deny.
	ModeObserve Mode = "observe"
	// ModeEnforce evaluates and denies.
	ModeEnforce Mode = "enforce"
)

// ParseMode reads a mode. The empty string is ModeOff; anything else that is
// not a mode is an error, so a misspelt setting cannot pass for one.
func ParseMode(text string) (Mode, error) {
	switch Mode(text) {
	case "", ModeOff:
		return ModeOff, nil
	case ModeObserve:
		return ModeObserve, nil
	case ModeEnforce:
		return ModeEnforce, nil
	default:
		return "", fmt.Errorf("authz: unknown mode %q (off, observe or enforce)", text)
	}
}

// Code classifies a refused change to the store.
type Code string

const (
	// CodeInvalid is a request that is malformed or incomplete.
	CodeInvalid Code = "invalid"
	// CodeForbidden is a caller without the authority for the change.
	CodeForbidden Code = "forbidden"
	// CodeNotFound is a record, owner, job, project or machine that does not
	// exist.
	CodeNotFound Code = "not_found"
	// CodeConflict is a change that contradicts what is already recorded. The
	// store is left as it was.
	CodeConflict Code = "conflict"
)

// Error is a refused change. Current, when set, is the record that stands.
type Error struct {
	Code    Code
	Message string
	Current any
}

func (e *Error) Error() string { return "authz: " + string(e.Code) + ": " + e.Message }

func refuse(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// CodeOf returns the Code of a refused change, or "" for any other error.
func CodeOf(err error) Code {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code
	}
	return ""
}

// ErrNotFound is what a Registry returns for an owner, job, project or
// machine it does not hold.
var ErrNotFound = errors.New("authz: not found in the registry")
