// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import "strings"

// redactedToken replaces the token wherever Redact finds it.
const redactedToken = "<token>"

// Redact returns err with the token of cdpURL replaced in its message. The
// SDK and the websocket library put the address they dialed into their
// errors, and net/http's url.Error prints the whole URL, so every error
// about a gated browser passes through here before it is logged, shown or
// kept. The returned error unwraps to err, so errors.Is and errors.As still
// see the original; only its text is replaced.
func Redact(err error, cdpURL string) error {
	if err == nil {
		return nil
	}
	token := TokenOf(cdpURL)
	if token == "" {
		return err
	}
	message := err.Error()
	redacted := strings.ReplaceAll(message, token, redactedToken)
	if redacted == message {
		return err
	}
	return &redactedError{message: redacted, err: err}
}

// RedactString returns s with the token of cdpURL replaced. Session
// summaries and timeline text are strings rather than errors; this is the
// same replacement for them.
func RedactString(s, cdpURL string) string {
	token := TokenOf(cdpURL)
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, redactedToken)
}

type redactedError struct {
	message string
	err     error
}

func (e *redactedError) Error() string { return e.message }
func (e *redactedError) Unwrap() error { return e.err }
