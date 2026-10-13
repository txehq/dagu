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
// Processes that share a store compare times written by each other's clocks.
// Those clocks are required to agree to within maxClockSkew, and every such
// comparison is made against the process's interest by that much: a session
// another process confirmed counts as that much older, and another process's
// claim as holding that much longer. Clocks further apart than that are a
// deployment fault this package cannot see, and they shorten or lengthen the
// times here by the excess.
//
// What a hub owes after a session has ended, a refresh token to be revoked at
// the provider or an end the session's record did not take, is kept in the
// store, so that it holds for every hub process and across a restart. See
// obligations.go.
//
// What this package bounds is the next request. A connection that was
// already open when a session ended, such as an event stream or a terminal
// WebSocket, was checked when it opened and is not closed by this package.
package oidcsession

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
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

	// maxClockSkew is how far apart the clocks of hub processes that share a
	// session store may be. See the package documentation.
	maxClockSkew = 10 * time.Second

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
	// ClientAuth is the way the provider takes the client secret, as a
	// refresh it granted established. Every call to the provider for this
	// session is made that way.
	ClientAuth ClientAuth `json:"client_auth"`
	// ConfirmedBy names the hub process whose clock wrote LastConfirmedAt.
	ConfirmedBy string `json:"confirmed_by,omitempty"`
	// Rotations counts the refreshes the provider granted.
	Rotations int `json:"rotations"`
	// EndedAt and EndReason are set once, when the session ends.
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	EndReason string     `json:"end_reason,omitempty"`
	// RefreshOwner names the hub process that is asking the provider about
	// this session, and RefreshUntil is when its claim runs out.
	RefreshOwner string     `json:"refresh_owner,omitempty"`
	RefreshUntil *time.Time `json:"refresh_until,omitempty"`
	// Owed lists the refresh tokens of this session that the provider has
	// still to be asked to revoke. A record that owes one is never purged.
	Owed []Owed `json:"owed,omitempty"`
	// Revocations records how each revocation that was owed ended.
	Revocations []Disposition `json:"revocations,omitempty"`
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
	// owedFailedAt is when the provider last left a revocation unanswered.
	owedFailedAt time.Time
	// reconciling is set while a round of reconciling runs, and lastRound is
	// when the last one was started, in Unix nanoseconds.
	reconciling atomic.Bool
	lastRound   atomic.Int64
	// spawn runs a round beside the request that started it.
	spawn func(func())
}

// decision is the end of a session, as decided.
type decision struct {
	reason string
	// ifToken, when set, limits the end to a record that still holds this
	// encrypted refresh token. A record that holds another one was renewed by
	// another hub process since, and what was decided about the old token
	// says nothing about it.
	ifToken string
	// orToken, when set with ifToken, is a second encrypted refresh token
	// the end applies to: the one a write whose outcome is not known may
	// have stored.
	orToken string
	// revoke says the ended record's refresh token is to be revoked at the
	// provider. It then becomes owed in the write that ends the session. A
	// token the provider has refused is not owed: it is erased.
	revoke bool
	// owe lists further refresh tokens to be revoked with this end, as
	// entries ready to go into the record.
	owe []Owed
	// passive marks an end nothing depends on: that of a session whose hub
	// token has expired, which serves nothing either way. If its write
	// fails it is not marked or remembered; a later round tries again.
	passive bool
	// expires is when the session's hub token expires. After it nothing can
	// present the session, and the decision is dropped. It is zero only when
	// the caller of End did not say and the session could not be read.
	expires time.Time
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
		spawn: func(round func()) { go round() },
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
	// The way the provider takes the client secret is established now, while
	// a refusal can only be about the client: the token is a moment old.
	//
	// Whatever happens from here on, the token is not left behind. If the
	// session cannot be started, the token is recorded as owed, in a record of
	// its own, and revoked like any other. failed returns the sign-in's error,
	// and says so if the token could be neither revoked nor recorded.
	failed := func(auth ClientAuth, token string, tryNow bool, cause error) error {
		if err := m.orphan(ctx, who, auth, token, "the sign-in did not start a session", tryNow); err != nil {
			return fmt.Errorf("%w; %w", cause, err)
		}
		return cause
	}
	auth, renewal, err := m.provider.Establish(ctx, refreshToken)
	var refused *RefusedError
	switch {
	case errors.As(err, &refused):
		// The provider answers, so it is asked now. The way is not known,
		// and it is asked both ways.
		return nil, failed(ClientAuthDetect, refreshToken, true,
			fmt.Errorf("oidcsession: the identity provider will not refresh the token it has just issued (%s), so the session could not be revalidated", refused.Code))
	case err != nil:
		// The provider does not answer, so it is not asked now: a later
		// round asks.
		return nil, failed(ClientAuthDetect, refreshToken, false,
			fmt.Errorf("%w: it did not answer when the session was being started", ErrProviderUnavailable))
	case auth != ClientAuthForm && auth != ClientAuthHeader:
		return nil, failed(ClientAuthDetect, refreshToken, true,
			errors.New("oidcsession: the way the identity provider takes the client secret was not established"))
	}
	if renewal.RefreshToken != "" {
		refreshToken = renewal.RefreshToken
	}
	discard := func(cause error) error { return failed(auth, refreshToken, true, cause) }

	// Establishing may have been a refresh, and a refresh that returns an ID
	// token is held to what every later one is: the token must be for this
	// identity, and one that cannot be verified is not a confirmation. A
	// session does not start on either.
	if renewal.IDToken != "" && m.checkID != nil {
		issuer, subject, err := m.checkID(ctx, renewal.IDToken)
		switch {
		case errors.Is(err, ErrIDTokenUnverifiable) && issuer == who.Issuer && subject == who.Subject:
			return nil, discard(fmt.Errorf("%w: the token it returned when the session was being started could not be verified", ErrProviderUnavailable))
		case err != nil || issuer != who.Issuer || subject != who.Subject:
			return nil, discard(errors.New("oidcsession: the identity provider returned a token for another identity when the session was being started"))
		}
	}
	encrypted, err := m.enc.Encrypt(refreshToken)
	if err != nil {
		return nil, discard(errors.New("oidcsession: the refresh token could not be encrypted"))
	}
	id, err := newSessionID()
	if err != nil {
		return nil, discard(err)
	}
	now := m.now().UTC()
	session := &Session{
		Schema: schemaVersion, ID: id,
		UserID: who.UserID, Issuer: who.Issuer, Subject: who.Subject,
		RefreshToken: encrypted, ClientAuth: auth,
		CreatedAt: now, ExpiresAt: expiresAt.UTC(), LastConfirmedAt: now, ConfirmedBy: m.owner,
	}
	data, err := encode(session)
	if err != nil {
		return nil, discard(err)
	}
	if err := m.col.Create(ctx, &persis.Record{ID: session.ID, Data: data, CreatedAt: now, UpdatedAt: now}); err != nil {
		return nil, discard(fmt.Errorf("oidcsession: store the session: %w", err))
	}
	m.kick(ctx, now, true)
	return session, nil
}

// newSessionID returns a new session id: 32 lowercase hex characters.
func newSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// purgeAfter is how long a session's record is kept after it ended or
// expired, for someone to see why. A record that still owes a revocation is
// kept for as long as it does.
const purgeAfter = 24 * time.Hour

// Check decides whether a request carrying this session may be served now.
// It returns nil, ErrSessionEnded, ErrProviderUnavailable, or an error from
// the store, which the caller must treat as a failure and not as an answer.
func (m *Manager) Check(ctx context.Context, sessionID string, who Identity) error {
	// What is left over is dealt with at the prompting of requests, whatever
	// their own answer, at most once in a while, so that it does not wait for
	// somebody to sign in. It is started before the request is decided and
	// runs beside it: the answer below is made on what is true when it is
	// given, not on what was true before a round.
	m.kick(ctx, m.now(), false)
	return m.decide(ctx, sessionID, who)
}

func (m *Manager) decide(ctx context.Context, sessionID string, who Identity) error {
	if err := m.refuseIfDecided(ctx, sessionID); err != nil {
		return err
	}
	if err := m.check(ctx, sessionID, who); err != nil {
		return err
	}
	// An end may have been decided while this request was being checked, by
	// a sign-out whose write failed. It is not served on what the store says.
	return m.refuseIfDecided(ctx, sessionID)
}

// refuseIfDecided refuses a session whose end this process has decided and
// the store has not taken. The write is tried again, and the session is
// refused whether or not it takes. It returns nil when there is no such
// decision, or when the one there was does not apply to what is stored now.
func (m *Manager) refuseIfDecided(ctx context.Context, sessionID string) error {
	d, ok := m.decided(sessionID)
	if !ok {
		return nil
	}
	return m.conclude(ctx, sessionID, d)
}

func (m *Manager) check(ctx context.Context, sessionID string, who Identity) error {
	session, _, err := m.load(ctx, sessionID)
	if err != nil {
		return err
	}
	now := m.now()
	if err := usable(session, who, now); err != nil {
		return err
	}
	age := m.age(session, now)
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

// age is how long ago the provider confirmed a session, as this process must
// count it. A time another process's clock wrote may be ahead of this one's
// by maxClockSkew, so such a session counts as that much older. A time that
// is in the future even so cannot be trusted at all, and the session counts
// as past its limit: nothing is served until the provider confirms it.
func (m *Manager) age(session *Session, now time.Time) time.Duration {
	age := now.Sub(session.LastConfirmedAt)
	if session.ConfirmedBy != m.owner {
		age += maxClockSkew
	}
	if age < 0 {
		return m.cfg.RevalidateLimit
	}
	return age
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
	if m.age(session, now) >= m.cfg.RevalidateLimit {
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
	session, tookOver, err := m.claim(ctx, sessionID)
	if errors.Is(err, errFresh) {
		return nil
	}
	if err != nil {
		return err
	}
	held := session.RefreshToken
	// ends is the end of this session for a reason that is about the refresh
	// token it holds now.
	ends := func(reason string) decision {
		return decision{reason: reason, ifToken: held, expires: session.ExpiresAt}
	}
	refreshToken, err := m.enc.Decrypt(held)
	if err != nil {
		// A token that cannot be read can never confirm the session, so the
		// session ends. The token is not erased: the key may come back, and
		// then it can still be revoked.
		unreadable := ends("the stored refresh token could not be read")
		unreadable.revoke = true
		return m.conclude(ctx, sessionID, unreadable)
	}

	renewal, err := m.provider.Refresh(ctx, refreshToken, session.ClientAuth)
	var refused *RefusedError
	switch {
	case errors.As(err, &refused) && tookOver:
		// This process took the session over from one whose claim had run
		// out. That process may have exchanged the same refresh token a
		// moment ago and not stored the new one yet, and a provider that
		// accepts each token once refuses this one for that reason alone. So
		// this refusal is not believed. The claim is given up, the other
		// process's result goes in if it comes, and the next attempt, which
		// takes nothing over, is believed.
		slog.Warn("OIDC session not revalidated: the refresh was refused after taking over another hub process's claim",
			slog.String("session", sessionID), slog.String("oauth_error", refused.Code))
		m.release(ctx, sessionID)
		return errNothingUsable
	case errors.As(err, &refused):
		slog.Info("OIDC session ended: the identity provider refused the refresh",
			slog.String("session", sessionID), slog.String("oauth_error", refused.Code), slog.Int("status", refused.Status))
		return m.conclude(ctx, sessionID, ends("refused by the identity provider: "+refused.Code))
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
			return m.abandon(ctx, sessionID, session.ClientAuth, renewal.RefreshToken, "", ends("the renewed refresh token could not be encrypted"))
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
			// Both tokens are to be revoked: the one the session held, in the
			// write that ends it, and the one that came back.
			mismatch := ends("the renewed token is not for this session's identity")
			mismatch.revoke = true
			if rotated {
				mismatch.owe = []Owed{m.newOwed(replacement, session.ClientAuth)}
			}
			return m.conclude(ctx, sessionID, mismatch)
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

	lost := ends("the renewed session could not be stored")
	lost.orToken = replacement
	err = m.commit(ctx, sessionID, renewed{
		held: held, sent: refreshToken, newToken: renewal.RefreshToken, replacement: replacement, lost: lost, auth: session.ClientAuth,
		apply: func(stored *Session) {
			if rotated {
				stored.RefreshToken = replacement
			}
			if confirmed {
				stored.LastConfirmedAt, stored.ConfirmedBy = m.now().UTC(), m.owner
				stored.Rotations++
			}
		},
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
// and returns the session as claimed. tookOver reports that the record named
// another process whose claim had run out. It returns errFresh when the
// session has been confirmed since the caller looked, and errClaimedElsewhere
// when another hub process holds a claim that has not run out.
func (m *Manager) claim(ctx context.Context, sessionID string) (session *Session, tookOver bool, err error) {
	// An end another hub process decided, or this one before a restart, and
	// that the record did not take, is beside the record. It is applied
	// before the provider is asked anything about the session.
	refuse, _, err := m.applyMark(ctx, sessionID)
	if err != nil {
		// Whether the session's end is marked is not known. Nothing is asked
		// of the provider on a guess.
		return nil, false, err
	}
	if refuse {
		return nil, false, ErrSessionEnded
	}
	for range casAttempts {
		session, raw, err := m.load(ctx, sessionID)
		if err != nil {
			return nil, false, err
		}
		if session.EndedAt != nil {
			return nil, false, ErrSessionEnded
		}
		now := m.now()
		if m.age(session, now) < m.cfg.RevalidateAfter {
			return nil, false, errFresh
		}
		tookOver := session.RefreshOwner != "" && session.RefreshOwner != m.owner
		if tookOver && claimHolds(session.RefreshUntil, now) {
			return nil, false, errClaimedElsewhere
		}
		until := now.Add(refreshClaim).UTC()
		session.RefreshOwner, session.RefreshUntil = m.owner, &until
		data, err := encode(session)
		if err != nil {
			return nil, false, err
		}
		err = m.col.CompareAndSwap(ctx, sessionID, raw, data)
		switch {
		case err == nil:
			return session, tookOver, nil
		case errors.Is(err, persis.ErrNotFound):
			return nil, false, ErrSessionEnded
		case !errors.Is(err, persis.ErrConflict):
			return nil, false, fmt.Errorf("oidcsession: claim the session: %w", err)
		}
	}
	return nil, false, errors.New("oidcsession: the session kept changing while it was being claimed")
}

// claimHolds reports whether another process's claim, good until the given
// time by that process's clock, still holds by this one's. That clock may be
// behind this one by maxClockSkew, so the claim holds that much longer. A
// claim that would end later than any claim made now could is not one a
// process within that skew made, and does not hold.
func claimHolds(until *time.Time, now time.Time) bool {
	if until == nil {
		return false
	}
	return now.Before(until.Add(maxClockSkew)) && !until.After(now.Add(refreshClaim+maxClockSkew))
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

// renewed is the outcome of a granted refresh, to be stored.
type renewed struct {
	// held is the encrypted refresh token that was exchanged, and sent is
	// that token as it was sent.
	held, sent string
	// newToken is the refresh token the provider returned, and replacement
	// is the same encrypted. Both are empty when the provider returned the
	// token it was sent, or none.
	newToken, replacement string
	// apply writes the outcome into the record as it is stored now.
	apply func(*Session)
	// lost is the end of the session if a new refresh token cannot be kept.
	lost decision
	// auth is the session's way with the provider.
	auth ClientAuth
}

// commit stores the outcome of a granted refresh.
//
// The record may have changed while the provider was being asked. If the
// session has ended, the token just obtained must not outlive it. If the
// record no longer holds the token that was exchanged, another hub process
// renewed the session, and what it stored stands.
func (m *Manager) commit(ctx context.Context, sessionID string, r renewed) error {
	var failure error
	for range casAttempts {
		if _, ok := m.decided(sessionID); ok {
			// Ended by this process, though the store has not recorded it.
			m.oweRenewed(ctx, sessionID, r)
			return ErrSessionEnded
		}
		session, raw, err := m.load(ctx, sessionID)
		if errors.Is(err, ErrSessionEnded) || (err == nil && session.EndedAt != nil) {
			m.oweRenewed(ctx, sessionID, r)
			return ErrSessionEnded
		}
		if err != nil {
			failure = err
			break
		}
		if session.RefreshToken != r.held {
			return nil
		}
		r.apply(session)
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
		if errors.Is(err, persis.ErrConflict) || errors.Is(err, persis.ErrNotFound) {
			continue
		}
		// A write that reports an error may have been made all the same: the
		// store can fail after it has replaced the record. What is stored
		// now says which.
		if _, stored, readErr := m.load(ctx, sessionID); readErr == nil && bytes.Equal(stored, data) {
			return nil
		}
		failure = fmt.Errorf("oidcsession: store the renewed session: %w", err)
		break
	}
	if failure == nil {
		failure = errors.New("oidcsession: the session kept changing while its renewal was being stored")
	}
	if r.replacement == "" {
		// Nothing is lost: the stored refresh token is still the session's.
		return failure
	}
	return m.abandon(ctx, sessionID, r.auth, r.newToken, r.replacement, r.lost)
}

// oweRenewed records, for a session that ended while the provider was being
// asked, the refresh token the granted refresh leaves good at the provider:
// it must not outlive the session.
func (m *Manager) oweRenewed(ctx context.Context, sessionID string, r renewed) {
	if r.replacement != "" {
		_ = m.oweToken(ctx, sessionID, r.auth, r.newToken, r.replacement)
		return
	}
	// The provider granted the refresh and returned no new token: the one
	// the session held is still good at the provider. A session that ended
	// by sign-out owes it already, and it is not recorded twice. One that
	// ended on a refusal erased it as refused, which this grant contradicts.
	_ = m.oweToken(ctx, sessionID, r.auth, r.sent, r.held)
}

// abandon ends a session whose new refresh token could not be kept. The token
// the store still holds has been used up at the provider, and sending it
// again would be a replay, so the session cannot be revalidated any more. The
// user signs in again.
//
// Both tokens are to be revoked: the new one, and the old one, which a
// provider that does not invalidate on use still honours. replacement is the
// new one encrypted, or empty if it could not be encrypted, in which case it
// cannot be recorded and the provider is asked directly.
//
// The end applies to the record whether it holds the old token or, after a
// write whose outcome is not known, the new one. It does not apply to a
// record another hub process has renewed since; the new token is recorded as
// owed there all the same.
func (m *Manager) abandon(ctx context.Context, sessionID string, auth ClientAuth, newToken, replacement string, lost decision) error {
	slog.Error("OIDC session ended: its renewed refresh token could not be kept",
		slog.String("session", sessionID), slog.String("reason", lost.reason))
	lost.revoke = true
	if replacement == "" {
		_ = m.revokeUnrecorded(ctx, sessionID, auth, newToken)
	} else {
		lost.owe = []Owed{m.newOwed(replacement, auth)}
	}
	out, err := m.end(ctx, sessionID, lost)
	if err != nil {
		// The record did not take it, which is likely: it is the store that
		// failed. The new token is in the marker if there is one. The
		// provider is asked now all the same; this is not counted as the
		// revocation, which is made again once the end is written.
		if replacement != "" {
			_ = m.askNow(ctx, auth, newToken)
		}
		slog.Error("OIDC session end could not be written into its record; the session is refused until it is",
			slog.String("session", sessionID), slog.Bool("marked", out.marked), slog.String("cause", fmt.Sprintf("%T", err)))
		return ErrSessionEnded
	}
	if out.owes {
		m.attemptNow(ctx, sessionID)
	}
	if !out.ended {
		return nil
	}
	return ErrSessionEnded
}

// End ends a session now, for a sign-out. The session's refresh token becomes
// owed in the write that ends it, and the provider is asked to revoke it.
// Ending a session that has ended, or that does not exist, is not an error.
//
// It returns nil only when the end is in the store: in the session's record,
// or beside it as a marker that every hub process applies. Otherwise it
// returns an error, and this process refuses the session all the same.
//
// expiresAt is when the hub token that carried the session expires, which the
// caller knows from the token. It bounds how long the end is kept if the
// session cannot even be read.
func (m *Manager) End(ctx context.Context, sessionID, reason string, expiresAt time.Time) error {
	out, err := m.end(ctx, sessionID, decision{reason: reason, revoke: true, expires: expiresAt})
	if err != nil {
		// The record did not take the end. The provider is asked now all the
		// same: another hub process still goes by the record until it meets
		// the marker, and a revoked token is refused there sooner. This is
		// not counted as the revocation; the token becomes owed, and is asked
		// for again, when the end is written.
		if refreshToken, decryptErr := m.enc.Decrypt(out.held); out.held != "" && decryptErr == nil {
			_ = m.askNow(ctx, out.auth, refreshToken)
		}
		if out.marked {
			return nil
		}
		return err
	}
	if out.owes {
		m.attemptNow(ctx, sessionID)
	}
	return nil
}

// ending is what end did.
type ending struct {
	// ended reports whether the session is ended in its record now.
	ended bool
	// owes reports that the record now owes a revocation that is due.
	owes bool
	// marked reports that the end, which the record did not take, is in the
	// store as a marker.
	marked bool
	// held is the encrypted refresh token of a record end read and could not
	// write, and auth that session's way with the provider.
	held string
	auth ClientAuth
}

// conclude ends a session for good and returns the answer for the request
// that found out: ErrSessionEnded, or nil when the decision does not apply to
// what is stored now (see decision.ifToken), in which case the caller reads
// the session again.
func (m *Manager) conclude(ctx context.Context, sessionID string, d decision) error {
	out, err := m.end(ctx, sessionID, d)
	if err != nil {
		// What was decided stands although the record did not take it: this
		// process refuses the session until it does.
		slog.Error("OIDC session end could not be written into its record; the session is refused until it is",
			slog.String("session", sessionID), slog.Bool("marked", out.marked), slog.String("cause", fmt.Sprintf("%T", err)))
		return ErrSessionEnded
	}
	if out.owes {
		m.attemptNow(ctx, sessionID)
	}
	if !out.ended {
		return nil
	}
	return ErrSessionEnded
}

// end writes a decision into a session's record. If the session is open and
// the decision applies, the session is ended: the refresh token becomes owed
// if it is to be revoked and is erased if not, and the tokens the decision
// brings become owed with it, all in one write.
//
// A session that has already ended, and one the decision does not apply to
// because another hub process has renewed it, are not ended again; the
// tokens the decision brings are recorded as owed in the record all the same.
//
// The decision applied is the one given, unless this process has decided a
// sign-out for the session that the store has not taken: that one is wider
// and is applied instead.
//
// A decision the record did not take is written beside it as a marker and
// remembered by this process. Both are cleared once the session is ended in
// its record, or, for a decision about one refresh token, once the record
// holds another.
func (m *Manager) end(ctx context.Context, sessionID string, d decision) (ending, error) {
	failure := errors.New("oidcsession: the session kept changing while it was being ended")
	var out ending
	for range casAttempts {
		// beside is the marker that was read and folded into the decision. It
		// is removed once what it says is in the record.
		var beside markedEnd
		var err error
		d, beside, err = m.widest(ctx, sessionID, d)
		if err != nil {
			failure = err
			break
		}
		mark, marked := beside.rec, beside.decision
		session, raw, err := m.load(ctx, sessionID)
		if errors.Is(err, ErrSessionEnded) {
			// There is no such session. Tokens that came with the decision
			// have no record to go into, and get one.
			if len(d.owe) > 0 {
				if err := m.stub(ctx, d.reason, d.owe); err != nil {
					failure = err
					break
				}
			}
			m.settle(sessionID)
			m.unmark(ctx, mark)
			return ending{ended: true}, nil
		}
		if err != nil {
			failure = err
			break
		}
		d.expires = session.ExpiresAt
		out.held, out.auth = session.RefreshToken, session.ClientAuth
		already := session.EndedAt != nil
		applies := d.appliesTo(session)
		if !applies && mark != nil && marked.appliesTo(session) {
			// The decision given is about a refresh token the record no
			// longer holds, and the one marked beside the record is about
			// the one it does hold. That one is applied; the marker is not
			// removed with nothing done about it.
			owe := d.owe
			d = marked
			d.owe, applies = owe, true
		}
		if (already || !applies) && len(d.owe) == 0 {
			if already {
				m.settle(sessionID)
			} else {
				m.drop(sessionID, d.ifToken)
			}
			m.unmark(ctx, mark)
			_, due := earliestDue(session.Owed, m.now())
			return ending{ended: already, owes: already && due}, nil
		}
		if !already && applies {
			now := m.now().UTC()
			session.EndedAt, session.EndReason = &now, d.reason
			if d.revoke && session.RefreshToken != "" {
				session.Owed = addOwed(session.Owed, m.newOwed(session.RefreshToken, session.ClientAuth))
			}
			session.RefreshToken = ""
			session.RefreshOwner, session.RefreshUntil = "", nil
		}
		session.Owed = addOwed(session.Owed, d.owe...)
		data, err := encode(session)
		if err != nil {
			failure = err
			break
		}
		err = m.col.CompareAndSwap(ctx, sessionID, raw, data)
		if err == nil {
			ended := already || applies
			if ended {
				m.settle(sessionID)
			} else {
				m.drop(sessionID, d.ifToken)
			}
			m.unmark(ctx, mark)
			_, due := earliestDue(session.Owed, m.now())
			return ending{ended: ended, owes: due}, nil
		}
		if errors.Is(err, persis.ErrNotFound) {
			continue
		}
		if !errors.Is(err, persis.ErrConflict) {
			failure = fmt.Errorf("oidcsession: end the session: %w", err)
			break
		}
		out.held = ""
	}
	if d.passive {
		return out, failure
	}
	out.marked = m.mark(ctx, sessionID, d)
	m.remember(sessionID, d)
	return out, failure
}

// stub creates a record that is ended from the start and holds refresh
// tokens that are owed and have no session's record to go into.
func (m *Manager) stub(ctx context.Context, reason string, owed []Owed) error {
	id, err := newSessionID()
	if err != nil {
		return err
	}
	now := m.now().UTC()
	data, err := encode(&Session{
		Schema: schemaVersion, ID: id, CreatedAt: now, ExpiresAt: now, LastConfirmedAt: now, ConfirmedBy: m.owner,
		EndedAt: &now, EndReason: reason, Owed: owed,
	})
	if err != nil {
		return err
	}
	return m.col.Create(ctx, &persis.Record{ID: id, Data: data, CreatedAt: now, UpdatedAt: now})
}

func (m *Manager) decided(sessionID string) (decision, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.undone[sessionID]
	return d, ok
}

// widest returns the decision to apply to a session: the one given, or a
// sign-out that has been decided for it and that the record has not taken,
// whether this process remembers it or it is marked beside the record. A
// sign-out is the wider decision and is applied in place of one about a
// single refresh token.
//
// The tokens any of them brings go with the decision that is applied. So
// when the end is written and what was kept is cleared, no token that was
// only in a marker or in memory is lost with it. The marker that was read is
// returned, for the caller to remove once what it says is in the record.
//
// An error means the store could not say whether there is a marker. The end
// is then not written: it might clear a marker it never read.
func (m *Manager) widest(ctx context.Context, sessionID string, d decision) (decision, markedEnd, error) {
	marked, mark, err := m.marked(ctx, sessionID)
	if err != nil {
		return d, markedEnd{}, err
	}
	m.mu.Lock()
	remembered, ok := m.undone[sessionID]
	m.mu.Unlock()
	kept := []decision{}
	if ok {
		kept = append(kept, remembered)
	}
	if mark != nil {
		kept = append(kept, marked)
	}
	for _, earlier := range kept {
		owe := addOwed(slices.Clone(d.owe), earlier.owe...)
		if earlier.ifToken == "" && d.ifToken != "" {
			if earlier.expires.IsZero() {
				earlier.expires = d.expires
			}
			d = earlier
		}
		d.owe = owe
	}
	return d, markedEnd{decision: marked, rec: mark}, nil
}

// markedEnd is an end marker as it was read: the decision in it, and its
// record, which is nil when there is no marker.
type markedEnd struct {
	decision decision
	rec      *persis.Record
}

// appliesTo reports whether the decision is about the session as its record
// holds it: every sign-out is, and a decision about one refresh token is if
// the record still holds that token.
func (d decision) appliesTo(session *Session) bool {
	return d.ifToken == "" || session.RefreshToken == d.ifToken || (d.orToken != "" && session.RefreshToken == d.orToken)
}

// remember keeps a decision the record did not take, so that this process
// refuses the session at once. A sign-out is never replaced by a decision
// about one refresh token, and what is known about a kept decision is not
// lost.
func (m *Manager) remember(sessionID string, d decision) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if earlier, ok := m.undone[sessionID]; ok {
		if earlier.ifToken == "" {
			d.reason, d.ifToken, d.orToken, d.revoke = earlier.reason, "", "", earlier.revoke
		}
		if d.expires.IsZero() {
			d.expires = earlier.expires
		}
		d.owe = addOwed(slices.Clone(earlier.owe), d.owe...)
	}
	m.undone[sessionID] = d
}

// settle clears what this process remembers about a session that is ended in
// its record.
func (m *Manager) settle(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.undone, sessionID)
	delete(m.failedAt, sessionID)
}

// drop clears a remembered decision about one refresh token, which the record
// no longer holds. A sign-out decided meanwhile is not that decision, and
// stays.
func (m *Manager) drop(sessionID, ifToken string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.undone[sessionID]; ok && d.ifToken == ifToken {
		delete(m.undone, sessionID)
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
