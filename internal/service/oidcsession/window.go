// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package oidcsession

import (
	"context"
	"time"
)

// Window is when a session next needs the identity provider, as Check counts
// it on this hub process.
type Window struct {
	// RevalidateAt is from when Check asks the provider about the session
	// again.
	RevalidateAt time.Time
	// ServedUntil is from when Check serves nothing on the session unless the
	// provider has confirmed it again by then. It is never later than the
	// expiry of the session's hub token.
	ServedUntil time.Time
}

// Window reports when a session next needs the provider. It is for a caller
// that holds a connection open and has to stop serving it at the time a new
// request would be refused. It is not an answer about a request: only Check
// is. In particular it does not look at who presents the session, and it does
// not see an end this process has decided and the store has not recorded.
//
// It reads the session and nothing else: it asks the provider nothing, writes
// nothing, and starts no round. A session that does not exist or has ended is
// ErrSessionEnded; any other error is from the store.
func (m *Manager) Window(ctx context.Context, sessionID string) (Window, error) {
	session, _, err := m.load(ctx, sessionID)
	if err != nil {
		return Window{}, err
	}
	if session.EndedAt != nil {
		return Window{}, ErrSessionEnded
	}
	now := m.now()
	// The same allowance as age makes: a time another process's clock wrote
	// counts as that much earlier, and one that is in the future even so
	// counts as past the limit.
	confirmed := session.LastConfirmedAt
	if session.ConfirmedBy != m.owner {
		confirmed = confirmed.Add(-maxClockSkew)
	}
	if confirmed.After(now) {
		return Window{RevalidateAt: now, ServedUntil: now}, nil
	}
	window := Window{
		RevalidateAt: confirmed.Add(m.cfg.RevalidateAfter),
		ServedUntil:  confirmed.Add(m.cfg.RevalidateLimit),
	}
	if session.ExpiresAt.Before(window.ServedUntil) {
		window.ServedUntil = session.ExpiresAt
	}
	return window, nil
}
