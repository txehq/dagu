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
// More than one hub process may share the store. A process claims a session
// in its record before it asks the provider, so that a refresh token is sent
// by one process at a time; a claim runs out, so a process that died does not
// hold a session for long.
//
// An end the store did not take, because a write failed, is known only to
// the process that decided it. That process refuses the session from then on
// and keeps trying to write the end. Another process, and the same one after
// a restart, go by the store. They stop serving the session when the provider
// next refuses its refresh token, which a sign-out brings about by revoking
// the token at once, and in any case they never serve it past the limit
// without the provider's confirmation.
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

	// refreshClaim is how long a hub process's claim on a session's refresh
	// holds. It is longer than a provider call takes, so that only a process
	// that died holds a claim until it runs out.
	refreshClaim = 20 * time.Second

	// casAttempts is how often a write that lost to another writer is made
	// again on what that writer stored.
	casAttempts = 8
)

var (
	// ErrSessionEnded means the session does not exist, has expired, was
	// signed out, or was refused by the provider. The user signs in again.
	ErrSessionEnded = errors.New("oidcsession: the session has ended")
	// ErrProviderUnavailable means the session is past its limit and the
	// provider could not be asked. Nothing is known about the session; the
	// request is to be retried, not sent to sign in.
	ErrProviderUnavailable = errors.New("oidcsession: the identity provider is unavailable")
	// ErrIDTokenUnverifiable is what an IDTokenChecker returns when it could
	// not decide whether a token is genuine, for example because the
	// provider's signing keys could not be fetched. It is not an answer about
	// the token.
	ErrIDTokenUnverifiable = errors.New("oidcsession: the ID token could not be verified")
)

// Encryptor encrypts the refresh token at rest.
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}

// IDTokenChecker verifies a raw ID token and returns its issuer and subject.
//
// An error means the token is not a valid one, except ErrIDTokenUnverifiable,
// which means the checker could not tell. With that error it still returns
// the issuer and subject the token names, unverified.
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
	// RefreshOwner names the hub process that is asking the provider about
	// this session, and RefreshUntil is when its claim runs out.
	RefreshOwner string     `json:"refresh_owner,omitempty"`
	RefreshUntil *time.Time `json:"refresh_until,omitempty"`
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
	// owner names this process in the claims it makes.
	owner string

	mu      sync.Mutex
	flights map[string]*flight
	// failedAt is when a session's last provider call got nothing usable.
	failedAt map[string]time.Time
	// undone holds the ends this process has decided and the store has not
	// recorded. A session in it is refused here whatever the store says.
	undone map[string]decision
}

// decision is the end of a session, as decided.
type decision struct {
	reason string
	// ifToken, when set, limits the end to a record that still holds this
	// encrypted refresh token. A record that holds another one was renewed by
	// another hub process since, and what was decided about the old token
	// says nothing about it.
	ifToken string
	// revoke says the ended record's refresh token is to be revoked at the
	// provider.
	revoke bool
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
	var owner [8]byte
	if _, err := rand.Read(owner[:]); err != nil {
		return nil, err
	}
	return &Manager{
		cfg: cfg, col: col, enc: enc, provider: provider, checkID: checkID, now: now,
		owner:   hex.EncodeToString(owner[:]),
		flights: map[string]*flight{}, failedAt: map[string]time.Time{}, undone: map[string]decision{},
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
	// A failed provider call matters only for the retry interval after it.
	m.mu.Lock()
	for id, failed := range m.failedAt {
		if now.Sub(failed) >= m.cfg.RetryInterval {
			delete(m.failedAt, id)
		}
	}
	m.mu.Unlock()

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
	if d, ok := m.decided(sessionID); ok {
		// The session's end was decided and the store did not take it. It is
		// tried again, and the session is refused whether or not it takes.
		if err := m.conclude(ctx, sessionID, d); err != nil {
			return err
		}
	}
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
	if refreshErr != nil && !errors.Is(refreshErr, errNothingUsable) && !errors.Is(refreshErr, errClaimedElsewhere) {
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

var (
	// errNothingUsable marks a provider call that told us nothing.
	errNothingUsable = errors.New("oidcsession: the identity provider gave no usable answer")
	// errClaimedElsewhere marks a session another hub process is asking the
	// provider about. Nothing is known until that process has stored its
	// answer.
	errClaimedElsewhere = errors.New("oidcsession: another hub process is revalidating the session")
	// errFresh marks a session that was confirmed between a request reading
	// it and that request coming to refresh it.
	errFresh = errors.New("oidcsession: the session has just been confirmed")
)

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
	session, err := m.claim(ctx, sessionID)
	if errors.Is(err, errFresh) {
		return nil
	}
	if err != nil {
		return err
	}
	held := session.RefreshToken
	refreshToken, err := m.enc.Decrypt(held)
	if err != nil {
		// A token that cannot be read can never confirm the session.
		return m.conclude(ctx, sessionID, decision{reason: "the stored refresh token could not be read", ifToken: held})
	}

	renewal, err := m.provider.Refresh(ctx, refreshToken)
	var refused *RefusedError
	switch {
	case errors.As(err, &refused):
		slog.Info("OIDC session ended: the identity provider refused the refresh",
			slog.String("session", sessionID), slog.String("oauth_error", refused.Code), slog.Int("status", refused.Status))
		return m.conclude(ctx, sessionID, decision{reason: "refused by the identity provider: " + refused.Code, ifToken: held})
	case err != nil:
		// Only the kind of error is logged. Its text is the provider
		// client's, and a refresh carries the refresh token.
		slog.Warn("OIDC session could not be revalidated: the identity provider gave no usable answer",
			slog.String("session", sessionID), slog.String("cause", fmt.Sprintf("%T", err)))
		m.release(ctx, sessionID)
		return errNothingUsable
	}

	// The provider granted the refresh. If it sent a new refresh token, the
	// one in the store has been used up, and the new one has to be kept.
	rotated := renewal.RefreshToken != "" && renewal.RefreshToken != refreshToken
	replacement := ""
	if rotated {
		replacement, err = m.enc.Encrypt(renewal.RefreshToken)
		if err != nil {
			return m.abandon(ctx, sessionID, held, renewal.RefreshToken, "the renewed refresh token could not be encrypted")
		}
	}

	// A renewed token must be for the same person. Otherwise the session is
	// someone else's, and it ends.
	confirmed := true
	if renewal.IDToken != "" && m.checkID != nil {
		issuer, subject, err := m.checkID(ctx, renewal.IDToken)
		unverifiable := errors.Is(err, ErrIDTokenUnverifiable)
		switch {
		case (err != nil && !unverifiable) || issuer != session.Issuer || subject != session.Subject:
			m.revokeAtProvider(ctx, renewal.RefreshToken, refreshToken)
			return m.conclude(ctx, sessionID, decision{reason: "the renewed token is not for this session's identity", ifToken: held})
		case unverifiable:
			// The token names this session's identity and could not be
			// verified, for example because the provider's signing keys
			// could not be fetched. That is not a confirmation and not a
			// refusal. The new refresh token is kept, so that the next
			// attempt can be made at all.
			slog.Warn("OIDC session could not be revalidated: the renewed ID token could not be verified",
				slog.String("session", sessionID))
			confirmed = false
		}
	}

	err = m.commit(ctx, sessionID, held, renewal.RefreshToken, rotated, func(stored *Session) {
		if rotated {
			stored.RefreshToken = replacement
		}
		if confirmed {
			stored.LastConfirmedAt = m.now().UTC()
			stored.Rotations++
		}
	})
	if err != nil {
		return err
	}
	if !confirmed {
		return errNothingUsable
	}
	return nil
}

// claim takes a session's refresh for this process, in the session's record,
// and returns the session as claimed. It returns errFresh when the session
// has been confirmed since the caller looked, and errClaimedElsewhere when
// another hub process holds a claim that has not run out.
func (m *Manager) claim(ctx context.Context, sessionID string) (*Session, error) {
	for range casAttempts {
		session, raw, err := m.load(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		if session.EndedAt != nil {
			return nil, ErrSessionEnded
		}
		now := m.now()
		if now.Sub(session.LastConfirmedAt) < m.cfg.RevalidateAfter {
			return nil, errFresh
		}
		if session.RefreshOwner != "" && session.RefreshOwner != m.owner &&
			session.RefreshUntil != nil && now.Before(*session.RefreshUntil) {
			return nil, errClaimedElsewhere
		}
		until := now.Add(refreshClaim).UTC()
		session.RefreshOwner, session.RefreshUntil = m.owner, &until
		data, err := encode(session)
		if err != nil {
			return nil, err
		}
		err = m.col.CompareAndSwap(ctx, sessionID, raw, data)
		switch {
		case err == nil:
			return session, nil
		case errors.Is(err, persis.ErrNotFound):
			return nil, ErrSessionEnded
		case !errors.Is(err, persis.ErrConflict):
			return nil, fmt.Errorf("oidcsession: claim the session: %w", err)
		}
	}
	return nil, errors.New("oidcsession: the session kept changing while it was being claimed")
}

// release gives up this process's claim after a provider call that told it
// nothing, so that another process need not wait for the claim to run out.
// It is best effort.
func (m *Manager) release(ctx context.Context, sessionID string) {
	session, raw, err := m.load(ctx, sessionID)
	if err != nil || session.EndedAt != nil || session.RefreshOwner != m.owner {
		return
	}
	session.RefreshOwner, session.RefreshUntil = "", nil
	data, err := encode(session)
	if err != nil {
		return
	}
	_ = m.col.CompareAndSwap(ctx, sessionID, raw, data)
}

// commit stores the outcome of a granted refresh. held is the encrypted
// refresh token that was exchanged, and apply writes the outcome into the
// record as it is stored now.
//
// The record may have changed while the provider was being asked. If the
// session has ended, the token just obtained must not outlive it. If the
// record no longer holds the token that was exchanged, another hub process
// renewed the session, and what it stored stands.
func (m *Manager) commit(ctx context.Context, sessionID, held, newToken string, rotated bool, apply func(*Session)) error {
	var failure error
	for range casAttempts {
		if _, ok := m.decided(sessionID); ok {
			// Ended by this process, though the store has not recorded it.
			m.revokeAtProvider(ctx, newToken)
			return ErrSessionEnded
		}
		session, raw, err := m.load(ctx, sessionID)
		if errors.Is(err, ErrSessionEnded) || (err == nil && session.EndedAt != nil) {
			m.revokeAtProvider(ctx, newToken)
			return ErrSessionEnded
		}
		if err != nil {
			failure = err
			break
		}
		if session.RefreshToken != held {
			return nil
		}
		apply(session)
		if session.RefreshOwner == m.owner {
			session.RefreshOwner, session.RefreshUntil = "", nil
		}
		data, err := encode(session)
		if err != nil {
			failure = err
			break
		}
		err = m.col.CompareAndSwap(ctx, sessionID, raw, data)
		if err == nil {
			return nil
		}
		if !errors.Is(err, persis.ErrConflict) && !errors.Is(err, persis.ErrNotFound) {
			failure = fmt.Errorf("oidcsession: store the renewed session: %w", err)
			break
		}
	}
	if failure == nil {
		failure = errors.New("oidcsession: the session kept changing while its renewal was being stored")
	}
	if !rotated {
		// Nothing is lost: the stored refresh token is still the session's.
		return failure
	}
	return m.abandon(ctx, sessionID, held, newToken, "the renewed session could not be stored")
}

// abandon ends a session whose new refresh token could not be kept. The token
// the store still holds has been used up at the provider, and sending it
// again would be a replay, so the session cannot be revalidated any more. The
// new token is revoked, and the user signs in again.
func (m *Manager) abandon(ctx context.Context, sessionID, held, newToken, reason string) error {
	slog.Error("OIDC session ended: its renewed refresh token could not be kept",
		slog.String("session", sessionID), slog.String("reason", reason))
	m.revokeAtProvider(ctx, newToken)
	return m.conclude(ctx, sessionID, decision{reason: reason, ifToken: held})
}

// End ends a session now, for a sign-out, and asks the provider to end its
// refresh token. Ending a session that has ended, or that does not exist, is
// not an error. If the store does not take the end, an error is returned and
// this process refuses the session all the same.
func (m *Manager) End(ctx context.Context, sessionID, reason string) error {
	_, err := m.endAndRevoke(ctx, sessionID, decision{reason: reason, revoke: true})
	return err
}

// endAndRevoke ends a session and, if the decision says so, revokes the
// refresh token its record held.
//
// The token is revoked even when the store did not take the end. This
// process refuses the session either way, but another hub process goes by the
// store, and the revocation is what makes the provider refuse it there.
func (m *Manager) endAndRevoke(ctx context.Context, sessionID string, d decision) (ended bool, err error) {
	held, ended, err := m.end(ctx, sessionID, d)
	if d.revoke && held != "" {
		m.revokeHeld(ctx, held)
		if err != nil {
			m.revocationDone(sessionID)
		}
	}
	return ended, err
}

// conclude ends a session for good and returns the answer for the request
// that found out: ErrSessionEnded, or nil when the decision does not apply to
// what is stored now (see decision.ifToken), in which case the caller reads
// the session again.
func (m *Manager) conclude(ctx context.Context, sessionID string, d decision) error {
	ended, err := m.endAndRevoke(ctx, sessionID, d)
	if err != nil {
		// What was decided stands although the store did not take it: this
		// process refuses the session until it does.
		slog.Error("OIDC session end could not be stored; the session is refused until it is",
			slog.String("session", sessionID), slog.String("cause", fmt.Sprintf("%T", err)))
		return ErrSessionEnded
	}
	if !ended {
		return nil
	}
	return ErrSessionEnded
}

// end marks a session ended, keeping the record without its refresh token.
// It reports whether the session is ended now, and returns the encrypted
// refresh token of the record it ended, or of the record it read and could
// not write.
//
// A decision the store did not take is remembered, and forgotten once the
// store holds it or it turns out not to apply.
func (m *Manager) end(ctx context.Context, sessionID string, d decision) (held string, ended bool, err error) {
	for range casAttempts {
		session, raw, err := m.load(ctx, sessionID)
		if errors.Is(err, ErrSessionEnded) {
			m.settle(sessionID)
			return "", true, nil
		}
		if err != nil {
			m.remember(sessionID, d)
			return "", false, err
		}
		if session.EndedAt != nil {
			m.settle(sessionID)
			return "", true, nil
		}
		if d.ifToken != "" && session.RefreshToken != d.ifToken {
			m.settle(sessionID)
			return "", false, nil
		}
		held := session.RefreshToken
		now := m.now().UTC()
		session.EndedAt, session.EndReason, session.RefreshToken = &now, d.reason, ""
		session.RefreshOwner, session.RefreshUntil = "", nil
		data, err := encode(session)
		if err != nil {
			m.remember(sessionID, d)
			return "", false, err
		}
		err = m.col.CompareAndSwap(ctx, sessionID, raw, data)
		switch {
		case err == nil:
			m.settle(sessionID)
			return held, true, nil
		case errors.Is(err, persis.ErrNotFound):
			m.settle(sessionID)
			return "", true, nil
		case !errors.Is(err, persis.ErrConflict):
			m.remember(sessionID, d)
			return held, false, fmt.Errorf("oidcsession: end the session: %w", err)
		}
	}
	m.remember(sessionID, d)
	return "", false, errors.New("oidcsession: the session kept changing while it was being ended")
}

func (m *Manager) decided(sessionID string) (decision, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.undone[sessionID]
	return d, ok
}

// remember keeps a decision the store did not take. A sign-out is never
// replaced by a narrower decision.
func (m *Manager) remember(sessionID string, d decision) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if earlier, ok := m.undone[sessionID]; ok && earlier.ifToken == "" {
		return
	}
	m.undone[sessionID] = d
}

// revocationDone notes that the refresh token of a remembered end has been
// revoked, so that it is not revoked again when the store takes the end.
func (m *Manager) revocationDone(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.undone[sessionID]; ok {
		d.revoke = false
		m.undone[sessionID] = d
	}
}

func (m *Manager) settle(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.undone, sessionID)
	delete(m.failedAt, sessionID)
}

// revokeHeld revokes the refresh token an ended record held.
func (m *Manager) revokeHeld(ctx context.Context, held string) {
	if held == "" {
		return
	}
	if refreshToken, err := m.enc.Decrypt(held); err == nil {
		m.revokeAtProvider(ctx, refreshToken)
	}
}

// revokeAtProvider asks the provider to end refresh tokens that must not be
// used again. It is best effort: the hub's own record is what ends a session.
func (m *Manager) revokeAtProvider(ctx context.Context, refreshTokens ...string) {
	seen := map[string]bool{}
	for _, token := range refreshTokens {
		if token == "" || seen[token] {
			continue
		}
		seen[token] = true
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
