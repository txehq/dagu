// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"errors"
	"fmt"
)

// Code classifies a refused registry operation. Every code except
// CodeNotFound and CodeInvalid maps to HTTP 409.
type Code string

const (
	CodeNotFound        Code = "not_found"
	CodeInvalid         Code = "invalid"
	CodeVersionConflict Code = "version_conflict"
	CodeDuplicate       Code = "duplicate"
	CodeNotReady        Code = "not_ready"
	CodeLifecycle       Code = "lifecycle"
	CodeTransition      Code = "invalid_transition"
	CodeClaimHeld       Code = "claim_held"
	CodeClaimStale      Code = "claim_stale"
	CodeNotPermitted    Code = "not_permitted"
	CodeStaleBinding    Code = "stale_binding"
	CodeProposalState   Code = "proposal_state"
	CodeActionExists    Code = "action_exists"
	CodeActionState     Code = "action_state"
	CodeGrantInvalid    Code = "grant_invalid"
	CodeDAGMismatch     Code = "dag_mismatch"
	CodeIncomplete      Code = "incomplete"
)

// Error is a refused registry operation. Current, when set, is the record
// state the caller should re-read before retrying.
type Error struct {
	Code    Code
	Message string
	Current any
}

func (e *Error) Error() string {
	return fmt.Sprintf("registry: %s: %s", e.Code, e.Message)
}

// ErrorCode returns err's registry code, or "" when err is not a registry error.
func ErrorCode(err error) Code {
	if re, ok := errors.AsType[*Error](err); ok {
		return re.Code
	}
	return ""
}

func refuse(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
