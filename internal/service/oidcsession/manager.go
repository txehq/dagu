// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package oidcsession keeps a hub session for each browser user who signed
// in through OIDC, and lets that user in only while the identity provider
// keeps confirming them.
//
// A session holds the provider's refresh token, encrypted. Within
// RevalidateAfter of the provider's last confirmation a request is served
// with no provider call. After it, one request refreshes at the provider
// while the others are served. Past RevalidateLimit nothing is served until
// the provider confirms. There is no grace beyond the limit.
//
// The provider's answer to a refresh is one of three things, never merged:
//
//   - granted: the session is confirmed and its refresh token replaced;
//   - refused: the session ends, and the user signs in again;
//   - nothing usable (no answer, a timeout, a 5xx, a body that is not an OAuth
//     error): the session is left alone. Requests are served until the limit
//     and then told the provider is unavailable, never that they are signed
//     out.
//
// What this package bounds is the next request. A connection that was
// already open when a session ended, such as an event stream or a terminal
// WebSocket, was checked when it opened and is not closed by this package.
package oidcsession

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/dagucloud/dagu/v2/internal/persis"
)

const (
	// MaxRevalidateLimit is the longest RevalidateLimit accepted: the longest
	// a user the provider has stopped confirming can still be served.
	MaxRevalidateLimit = 5 * time.Minute

	schemaVersion = 1

	// defaultRetryInterval is the least time between two provider calls for
	// one session after a call that got nothing usable.
	defaultRetryInterval = 5 * time.Second
)

var (
	// ErrSessionEnded means the session does not exist, has expired, was
	// signed out, or was refused by the provider. The user signs in again.
	ErrSessionEnded = errors.New("oidcsession: the session has ended")
	// ErrProviderUnavailable means the session is past its limit and the
	// provider could not be asked. Nothing is known about the session; the
	// request is to be retried, not sent to sign in.
	ErrProviderUnavailable = errors.New("oidcsession: the identity provider is unavailable")
)

// Encryptor encrypts the refresh token at rest.
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}

// IDTokenChecker verifies a raw ID token and returns its issuer and subject.
type IDTokenChecker func(ctx context.Context, rawIDToken string) (issuer, subject string, err error)

// Config configures a Manager.
type Config struct {
	// RevalidateAfter is how long after the provider's last confirmation a
	// request is served without asking again.
	RevalidateAfter time.Duration
	// RevalidateLimit is how long after the provider's last confirmation a
	// request can be served at all. It is more than RevalidateAfter and at
	// most MaxRevalidateLimit.
	RevalidateLimit time.Duration
	// RetryInterval is the least time between two provider calls for one
	// session after one that got nothing usable. Zero means five seconds.
	RetryInterval time.Duration
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// Validate reports a configuration this package refuses.
func (c Config) Validate() error {
	if c.RevalidateAfter <= 0 || c.RevalidateLimit <= 0 {
		return errors.New("oidcsession: revalidate_after and revalidate_limit must both be set and positive")
	}
	if c.RevalidateAfter >= c.RevalidateLimit {
		return errors.New("oidcsession: revalidate_after must be less than revalidate_limit")
	}
	if c.RevalidateLimit > MaxRevalidateLimit {
		return fmt.Errorf("oidcsession: revalidate_limit must be at most %s", MaxRevalidateLimit)
	}
	if c.RetryInterval < 0 {
		return errors.New("oidcsession: the retry interval must not be negative")
	}
	return nil
}

// Session is the stored record. The refresh token in it is encrypted.
type Session struct {
	Schema  int    `json:"schema"`
	ID      string `json:"id"`
	UserID  string `json:"user_id"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	// RefreshToken is the provider's refresh token, encrypted.
	RefreshToken string    `json:"refresh_token"`
	CreatedAt    time.Time `json:"created_at"`
	// ExpiresAt is when the hub token issued with the session expires.
	ExpiresAt time.Time `json:"expires_at"`
	// LastConfirmedAt is when the provider last granted a refresh, or the
	// sign-in itself.
	LastConfirmedAt time.Time `json:"last_confirmed_at"`
	// Rotations counts the refreshes the provider granted.
	Rotations int `json:"rotations"`
	// EndedAt and EndReason are set once, when the session ends.
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	EndReason string     `json:"end_reason,omitempty"`
}

// Identity is who a session must belong to for a request to use it.
type Identity struct {
	UserID  string
	Issuer  string
	Subject string
}

// Manager creates, checks and ends sessions. It is safe for concurrent use.
type Manager struct {
	cfg      Config
	col      persis.Collection
	enc      Encryptor
	provider Provider
	checkID  IDTokenChecker
	now      func() time.Time

	mu      sync.Mutex
	flights map[string]*flight
	// failedAt is when a session's last provider call got nothing usable.
	failedAt map[string]time.Time
}

// flight is one refresh in progress, which other requests for the same
// session may wait for.
type flight struct {
	done chan struct{}
	err  error
}

// NewManager returns a manager over col. checkID may be nil, in which case a
// renewed ID token is not examined.
func NewManager(cfg Config, col persis.Collection, enc Encryptor, provider Provider, checkID IDTokenChecker) (*Manager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if col == nil || enc == nil || provider == nil {
		return nil, errors.New("oidcsession: a collection, an encryptor and a provider are required")
	}
	if cfg.RetryInterval == 0 {
		cfg.RetryInterval = defaultRetryInterval
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{
		cfg: cfg, col: col, enc: enc, provider: provider, checkID: checkID, now: now,
		flights: map[string]*flight{}, failedAt: map[string]time.Time{},
	}, nil
}

// Create starts a session for a user who has just signed in. expiresAt is
// when the hub token that will carry the session expires.
func (m *Manager) Create(ctx context.Context, who Identity, refreshToken string, expiresAt time.Time) (*Session, error) {
	if who.UserID == "" || who.Issuer == "" || who.Subject == "" {
		return nil, errors.New("oidcsession: a user, an issuer and a subject are required")
	}
	if refreshToken == "" {
		return nil, errors.New("oidcsession: the identity provider returned no refresh token, so the session could not be revalidated")
	}
	encrypted, err := m.enc.Encrypt(refreshToken)
	if err != nil {
		return nil, errors.New("oidcsession: the refresh token could not be encrypted")
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	now := m.now().UTC()
	session := &Session{
		Schema: schemaVersion, ID: hex.EncodeToString(raw[:]),
		UserID: who.UserID, Issuer: who.Issuer, Subject: who.Subject,
		RefreshToken: encrypted, CreatedAt: now, ExpiresAt: expiresAt.UTC(), LastConfirmedAt: now,
	}
	data, err := encode(session)
	if err != nil {
		return nil, err
	}
	if err := m.col.Create(ctx, &persis.Record{ID: session.ID, Data: data, CreatedAt: now, UpdatedAt: now}); err != nil {
		return nil, fmt.Errorf("oidcsession: store the session: %w", err)
	}
	m.purge(ctx, now)
	return session, nil
}

// purgeAfter is how long a session's record is kept after it ended or
// expired, for someone to see why.
const purgeAfter = 24 * time.Hour

// purge removes records of sessions that ended or expired more than a day
// ago. It runs at sign-in, so the records never outgrow the sign-ins of a
// day by much, and it is best effort: a record it misses is harmless, because
// an ended or expired session serves nothing.
func (m *Manager) purge(ctx context.Context, now time.Time) {
	cursor := ""
	for {
		page, err := m.col.List(ctx, persis.ListQuery{Cursor: cursor})
		if err != nil {
			return
		}
		for _, rec := range page.Records {
			var session Session
			if json.Unmarshal(rec.Data, &session) != nil {
				continue
			}
			gone := now.Sub(session.ExpiresAt) > purgeAfter || (session.EndedAt != nil && now.Sub(*session.EndedAt) > purgeAfter)
			if gone {
				_ = m.col.CompareAndDelete(ctx, rec)
			}
		}
		if page.NextCursor == "" {
			return
		}
		cursor = page.NextCursor
	}
}

// Check decides whether a request carrying this session may be served now.
// It returns nil, ErrSessionEnded, ErrProviderUnavailable, or an error from
// the store, which the caller must treat as a failure and not as an answer.
func (m *Manager) Check(ctx context.Context, sessionID string, who Identity) error {
	session, _, err := m.load(ctx, sessionID)
	if err != nil {
		return err
	}
	now := m.now()
	if err := usable(session, who, now); err != nil {
		return err
	}
	age := now.Sub(session.LastConfirmedAt)
	if age < m.cfg.RevalidateAfter {
		return nil
	}
	pastLimit := age >= m.cfg.RevalidateLimit

	// One request asks the provider. Others are served meanwhile if the
	// session is still inside its limit, and wait for the answer if it is not.
	current, leader := m.join(sessionID, now)
	switch {
	case current == nil && !pastLimit:
		// A recent call got nothing usable; it is not repeated yet.
		return nil
	case current == nil:
		return ErrProviderUnavailable
	case !leader && !pastLimit:
		return nil
	case !leader:
		select {
		case <-current.done:
		case <-ctx.Done():
			return ctx.Err()
		}
		return m.afterRefresh(ctx, sessionID, who, current.err)
	}

	// The refresh serves every waiting request, so it must not die with the
	// one that happened to start it.
	current.err = m.refresh(context.WithoutCancel(ctx), sessionID)
	m.finish(sessionID, current)
	return m.afterRefresh(ctx, sessionID, who, current.err)
}

// afterRefresh turns the outcome of a refresh into the answer for a request.
// It reads the session again: what counts is what is stored now.
func (m *Manager) afterRefresh(ctx context.Context, sessionID string, who Identity, refreshErr error) error {
	if refreshErr != nil && !errors.Is(refreshErr, errNothingUsable) {
		return refreshErr
	}
	session, _, err := m.load(ctx, sessionID)
	if err != nil {
		return err
	}
	now := m.now()
	if err := usable(session, who, now); err != nil {
		return err
	}
	if now.Sub(session.LastConfirmedAt) >= m.cfg.RevalidateLimit {
		return ErrProviderUnavailable
	}
	return nil
}

// errNothingUsable marks a provider call that told us nothing.
var errNothingUsable = errors.New("oidcsession: the identity provider gave no usable answer")

// join returns the refresh in progress for a session, starting one if there
// is none. leader is true for the caller that must perform it. It returns a
// nil flight when a call that got nothing usable was made too recently to
// repeat.
func (m *Manager) join(sessionID string, now time.Time) (current *flight, leader bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.flights[sessionID]; ok {
		return current, false
	}
	if failed, ok := m.failedAt[sessionID]; ok && now.Sub(failed) < m.cfg.RetryInterval {
		return nil, false
	}
	current = &flight{done: make(chan struct{})}
	m.flights[sessionID] = current
	return current, true
}

func (m *Manager) finish(sessionID string, current *flight) {
	m.mu.Lock()
	delete(m.flights, sessionID)
	if errors.Is(current.err, errNothingUsable) {
		m.failedAt[sessionID] = m.now()
	} else {
		delete(m.failedAt, sessionID)
	}
	m.mu.Unlock()
	close(current.done)
}

// refresh asks the provider once and records the answer.
func (m *Manager) refresh(ctx context.Context, sessionID string) error {
	session, raw, err := m.load(ctx, sessionID)
	if err != nil {
		return err
	}
	if session.EndedAt != nil {
		return ErrSessionEnded
	}
	refreshToken, err := m.enc.Decrypt(session.RefreshToken)
	if err != nil {
		// A token that cannot be read can never confirm the session.
		return m.end(ctx, sessionID, "the stored refresh token could not be read")
	}

	renewal, err := m.provider.Refresh(ctx, refreshToken)
	var refused *RefusedError
	switch {
	case errors.As(err, &refused):
		slog.Info("OIDC session ended: the identity provider refused the refresh",
			slog.String("session", sessionID), slog.String("oauth_error", refused.Code), slog.Int("status", refused.Status))
		return m.end(ctx, sessionID, "refused by the identity provider: "+refused.Code)
	case err != nil:
		// Only the kind of error is logged. Its text is the provider
		// client's, and a refresh carries the refresh token.
		slog.Warn("OIDC session could not be revalidated: the identity provider gave no usable answer",
			slog.String("session", sessionID), slog.String("cause", fmt.Sprintf("%T", err)))
		return errNothingUsable
	}

	// A renewed token must be for the same person. Otherwise the session is
	// someone else's, and it ends.
	if renewal.IDToken != "" && m.checkID != nil {
		issuer, subject, err := m.checkID(ctx, renewal.IDToken)
		if err != nil || issuer != session.Issuer || subject != session.Subject {
			m.revokeAtProvider(ctx, renewal.RefreshToken, refreshToken)
			return m.end(ctx, sessionID, "the renewed token is not for this session's identity")
		}
	}

	next := *session
	next.LastConfirmedAt = m.now().UTC()
	next.Rotations++
	if renewal.RefreshToken != "" {
		encrypted, err := m.enc.Encrypt(renewal.RefreshToken)
		if err != nil {
			return errors.New("oidcsession: the refresh token could not be encrypted")
		}
		next.RefreshToken = encrypted
	}
	data, err := encode(&next)
	if err != nil {
		return err
	}
	err = m.col.CompareAndSwap(ctx, sessionID, raw, data)
	if err == nil {
		return nil
	}
	if !errors.Is(err, persis.ErrConflict) && !errors.Is(err, persis.ErrNotFound) {
		return fmt.Errorf("oidcsession: store the renewed session: %w", err)
	}
	// The session changed while the provider was being asked: it was signed
	// out, or renewed by another process. What is stored now stands. If it
	// has ended, the token just obtained must not outlive it.
	stored, _, loadErr := m.load(ctx, sessionID)
	if loadErr != nil {
		return loadErr
	}
	if stored.EndedAt != nil {
		m.revokeAtProvider(ctx, renewal.RefreshToken)
		return ErrSessionEnded
	}
	return nil
}

// End ends a session now, for a sign-out, and asks the provider to end its
// refresh token. Ending a session that has ended, or that does not exist, is
// not an error.
func (m *Manager) End(ctx context.Context, sessionID, reason string) error {
	session, _, err := m.load(ctx, sessionID)
	if errors.Is(err, ErrSessionEnded) {
		return nil
	}
	if err != nil {
		return err
	}
	if session.EndedAt != nil {
		return nil
	}
	if err := m.end(ctx, sessionID, reason); err != nil && !errors.Is(err, ErrSessionEnded) {
		return err
	}
	if refreshToken, err := m.enc.Decrypt(session.RefreshToken); err == nil {
		m.revokeAtProvider(ctx, refreshToken)
	}
	return nil
}

// end marks a session ended and returns ErrSessionEnded, or the store's
// error. It keeps the record, without its refresh token.
func (m *Manager) end(ctx context.Context, sessionID, reason string) error {
	for range 8 {
		session, raw, err := m.load(ctx, sessionID)
		if err != nil {
			return err
		}
		if session.EndedAt != nil {
			return ErrSessionEnded
		}
		now := m.now().UTC()
		session.EndedAt, session.EndReason, session.RefreshToken = &now, reason, ""
		data, err := encode(session)
		if err != nil {
			return err
		}
		err = m.col.CompareAndSwap(ctx, sessionID, raw, data)
		if err == nil {
			m.mu.Lock()
			delete(m.failedAt, sessionID)
			m.mu.Unlock()
			return ErrSessionEnded
		}
		if !errors.Is(err, persis.ErrConflict) {
			return fmt.Errorf("oidcsession: end the session: %w", err)
		}
	}
	return errors.New("oidcsession: the session kept changing while it was being ended")
}

// revokeAtProvider asks the provider to end refresh tokens that must not be
// used again. It is best effort: the hub's own record is what ends a session.
func (m *Manager) revokeAtProvider(ctx context.Context, refreshTokens ...string) {
	for _, token := range refreshTokens {
		if token == "" {
			continue
		}
		if err := m.provider.Revoke(context.WithoutCancel(ctx), token); err != nil {
			slog.Warn("OIDC refresh token could not be revoked at the identity provider", slog.String("cause", fmt.Sprintf("%T", err)))
		}
	}
}

// load reads a session and the bytes it is stored as. A session that does not
// exist is ErrSessionEnded.
func (m *Manager) load(ctx context.Context, sessionID string) (*Session, []byte, error) {
	if !validID(sessionID) {
		return nil, nil, ErrSessionEnded
	}
	rec, err := m.col.Get(ctx, sessionID)
	if errors.Is(err, persis.ErrNotFound) {
		return nil, nil, ErrSessionEnded
	}
	if err != nil {
		return nil, nil, fmt.Errorf("oidcsession: read the session: %w", err)
	}
	var session Session
	if err := json.Unmarshal(rec.Data, &session); err != nil {
		return nil, nil, fmt.Errorf("oidcsession: decode the session: %w", err)
	}
	if session.ID != sessionID {
		return nil, nil, ErrSessionEnded
	}
	return &session, rec.Data, nil
}

// usable reports whether a session may serve this identity now, apart from
// how long ago the provider confirmed it.
func usable(session *Session, who Identity, now time.Time) error {
	switch {
	case session.EndedAt != nil:
		return ErrSessionEnded
	case !now.Before(session.ExpiresAt):
		return ErrSessionEnded
	case session.UserID != who.UserID || session.Issuer != who.Issuer || session.Subject != who.Subject:
		// The user was re-linked to another identity, or the token is being
		// presented for someone else.
		return ErrSessionEnded
	}
	return nil
}

// encode serializes a session for the store. The refresh token in it is
// already encrypted; a session is never serialized anywhere else.
func encode(session *Session) ([]byte, error) {
	return json.Marshal(session) //nolint:gosec // G117: the field holds ciphertext, not the token
}

// validID reports whether a string is a session id this package minted: 32
// lowercase hex characters. Anything else never reaches the store.
func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range []byte(id) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
