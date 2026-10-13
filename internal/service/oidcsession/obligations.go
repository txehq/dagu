// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package oidcsession

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/persis"
)

// What a hub owes after a session has ended, or a sign-in has failed, is kept
// in the store and not in memory.
//
// A refresh token the provider has still to be asked to revoke is an entry in
// the owed list of the session's record. It gets there in the same write that
// ends the session, so there is no moment at which the session is ended and
// the obligation is not recorded, and every hub process, and the same one
// after a restart, finds it. A sign-in that fails after the provider issued a
// token gets a record of its own, ended from the start, that holds the token.
//
// An entry leaves the list in one of four ways, each written into the record
// as a Disposition before the token is erased: the provider revoked it; the
// provider answered no maxRevocationRefusals times; the provider has no
// revocation endpoint; or it is given up, which takes both giveUpAfter and
// giveUpAttempts. Age alone ends nothing, and a record with an entry in its
// list is never purged.
//
// A session end the record's own write did not take is written beside it as
// an end marker. Every process applies a session's marker when it next comes
// to refresh that session and at each reconcile. So a session one process has
// ended is ended for the others within the time a session may go unconfirmed,
// and a restart does not bring it back.
//
// What cannot be made durable is what happens while the store takes no write
// at all. Then the process that decided refuses from memory, tries again at
// each request and each reconcile, and reports the failure to its caller.

const (
	// owedRetryInterval is the wait before the second attempt at a
	// revocation, and how long no round asks the provider after it has not
	// answered one.
	owedRetryInterval = time.Minute

	// maxOwedBackoff is the longest wait between two attempts at one
	// revocation. An entry therefore comes due again, and one that is due
	// goes ahead of every entry that came due after it.
	maxOwedBackoff = time.Hour

	// maxRevocationRefusals is how often the provider may answer no to one
	// revocation before that is taken as its answer. A provider that answers
	// is not down, and what it will not revoke it will not revoke.
	maxRevocationRefusals = 3

	// giveUpAfter and giveUpAttempts are both needed before a revocation the
	// provider never answered, or whose token could never be read, is given
	// up. It is then written down as given up, and logged.
	giveUpAfter    = 30 * 24 * time.Hour
	giveUpAttempts = 20

	// reconcilePerRound is how many end markers, how many remembered ends
	// and how many revocations one round deals with. A round runs inside a
	// request, and somebody is waiting for that request.
	reconcilePerRound = 16

	// reconcileInterval is the least time between two rounds started by
	// ordinary requests. A sign-in always starts one.
	reconcileInterval = time.Minute

	endMarkerPrefix = "end-"
	endMarkerKind   = "end"
)

// ErrObligationUnrecorded means a refresh token could be neither revoked at
// the provider nor recorded as owed. Nothing will revoke it. It is never
// reported as handled.
var ErrObligationUnrecorded = errors.New("oidcsession: a refresh token could be neither revoked nor recorded as owed")

// Owed is a provider refresh token that the provider has still to be asked to
// revoke, with what has been tried so far.
type Owed struct {
	// Token is the refresh token, encrypted, and Auth the way its session
	// had with the provider, or ClientAuthDetect if it never had one.
	Token string     `json:"token"`
	Auth  ClientAuth `json:"auth"`
	// Since is when the revocation was first owed.
	Since time.Time `json:"since"`
	// Attempts counts the attempts made, and Refusals those the provider
	// answered no to.
	Attempts int `json:"attempts,omitempty"`
	Refusals int `json:"refusals,omitempty"`
	// NextAttempt is when the next attempt is due.
	NextAttempt time.Time `json:"next_attempt"`
	// Last says how the last attempt went.
	Last string `json:"last,omitempty"`
}

// Disposition is the record of how an owed revocation ended. It holds no
// token.
type Disposition struct {
	At       time.Time `json:"at"`
	Outcome  string    `json:"outcome"`
	Attempts int       `json:"attempts"`
	// Since is when the revocation was first owed.
	Since time.Time `json:"since"`
}

// The outcomes of an attempt, and the dispositions they lead to.
const (
	attemptRevoked     = "revoked"
	attemptRefused     = "refused"
	attemptUnsupported = "unsupported"
	attemptUnanswered  = "unanswered"
	attemptUnreadable  = "unreadable"

	disposedRevoked     = "revoked by the identity provider"
	disposedRefused     = "the identity provider refused to revoke it"
	disposedUnsupported = "not revoked: the identity provider has no revocation endpoint"
	disposedGivenUp     = "given up: the identity provider never answered, or the token could not be read"
)

// endMarker is a session end the session's own record did not take, kept
// beside it until it does.
type endMarker struct {
	Schema  int    `json:"schema"`
	Kind    string `json:"kind"`
	Session string `json:"session"`
	Reason  string `json:"reason"`
	// IfToken, OrToken, Revoke and Owe are the decision: see decision.
	IfToken string `json:"if_token,omitempty"`
	OrToken string `json:"or_token,omitempty"`
	Revoke  bool   `json:"revoke,omitempty"`
	Owe     []Owed `json:"owe,omitempty"`
	// Expires is when the session's hub token expires.
	Expires   time.Time `json:"expires"`
	DecidedAt time.Time `json:"decided_at"`
}

func endMarkerID(sessionID string) string { return endMarkerPrefix + sessionID }

// newOwed is an entry for an encrypted refresh token that is owed from now.
func (m *Manager) newOwed(encrypted string, auth ClientAuth) Owed {
	now := m.now().UTC()
	return Owed{Token: encrypted, Auth: auth, Since: now, NextAttempt: now}
}

// addOwed adds entries to a list, leaving out a token that is already in it.
func addOwed(list []Owed, entries ...Owed) []Owed {
	for _, entry := range entries {
		if entry.Token == "" || slices.ContainsFunc(list, func(o Owed) bool { return o.Token == entry.Token }) {
			continue
		}
		list = append(list, entry)
	}
	return list
}

// mark writes a session end beside the session's record, which did not take
// it, and reports whether the marker is in the store. A marker that is
// already there is kept if it is a sign-out, which is the wider decision, and
// takes on whatever tokens this decision brings.
func (m *Manager) mark(ctx context.Context, sessionID string, d decision) bool {
	if !validID(sessionID) {
		return false
	}
	id := endMarkerID(sessionID)
	now := m.now().UTC()
	next := endMarker{
		Schema: schemaVersion, Kind: endMarkerKind, Session: sessionID, Reason: d.reason,
		IfToken: d.ifToken, OrToken: d.orToken, Revoke: d.revoke, Owe: d.owe, Expires: d.expires.UTC(), DecidedAt: now,
	}
	for range casAttempts {
		rec, err := m.col.Get(ctx, id)
		if errors.Is(err, persis.ErrNotFound) {
			data, encodeErr := json.Marshal(next) //nolint:gosec // G117: the tokens in it are ciphertext
			if encodeErr != nil {
				return false
			}
			err = m.col.Create(ctx, &persis.Record{ID: id, Data: data, CreatedAt: now, UpdatedAt: now})
			if err == nil {
				return true
			}
			if errors.Is(err, persis.ErrConflict) {
				continue
			}
			return false
		}
		if err != nil {
			return false
		}
		var kept endMarker
		if json.Unmarshal(rec.Data, &kept) != nil || kept.Kind != endMarkerKind {
			return false
		}
		merged := next
		if kept.IfToken == "" {
			// A sign-out is not replaced by a decision about one token.
			merged = kept
			if merged.Expires.IsZero() {
				merged.Expires = next.Expires
			}
		}
		merged.Owe = addOwed(slices.Clone(kept.Owe), d.owe...)
		if merged.IfToken == kept.IfToken && merged.Revoke == kept.Revoke && len(merged.Owe) == len(kept.Owe) {
			// What is marked already says this. It is not written again.
			return true
		}
		data, encodeErr := json.Marshal(merged) //nolint:gosec // G117: the tokens in it are ciphertext
		if encodeErr != nil {
			return false
		}
		err = m.col.CompareAndSwap(ctx, id, rec.Data, data)
		if err == nil {
			return true
		}
		if !errors.Is(err, persis.ErrConflict) && !errors.Is(err, persis.ErrNotFound) {
			return false
		}
	}
	return false
}

// unmark removes the end marker that was read, now that it has been applied
// or does not apply. It removes that marker and no other: one that another
// write has changed since, to add a token to it, stays, and is applied again.
func (m *Manager) unmark(ctx context.Context, rec *persis.Record) {
	if rec != nil {
		_ = m.col.CompareAndDelete(ctx, rec)
	}
}

// marked returns the end left beside a session's record and the marker's own
// record, which is nil when there is no marker. An error means the store
// could not say whether there is one.
//
// A marker that is there and cannot be understood says that the session's end
// was decided, and not how. It is taken as a sign-out, which is the wider
// decision: the session ends and its token is revoked.
func (m *Manager) marked(ctx context.Context, sessionID string) (decision, *persis.Record, error) {
	if !validID(sessionID) {
		return decision{}, nil, nil
	}
	rec, err := m.col.Get(ctx, endMarkerID(sessionID))
	if errors.Is(err, persis.ErrNotFound) {
		return decision{}, nil, nil
	}
	if err != nil {
		return decision{}, nil, fmt.Errorf("oidcsession: read the end marker: %w", err)
	}
	var marker endMarker
	if json.Unmarshal(rec.Data, &marker) != nil || marker.Kind != endMarkerKind || marker.Session != sessionID {
		return decision{reason: "its end marker could not be read", revoke: true}, rec, nil
	}
	return decision{
		reason: marker.Reason, ifToken: marker.IfToken, orToken: marker.OrToken,
		revoke: marker.Revoke, owe: marker.Owe, expires: marker.Expires,
	}, rec, nil
}

// applyMark ends a session whose end is marked beside its record. It is what
// makes an end one hub process decided hold for the others.
//
// refuse reports that the session is not to be served or refreshed: it is
// ended, or its end is marked and this process could not write it into the
// record either, in which case the mark stands. written reports that the end
// is in the record now. An error means the store could not say whether the
// session's end is marked, and then nothing is known.
func (m *Manager) applyMark(ctx context.Context, sessionID string) (refuse, written bool, err error) {
	d, rec, err := m.marked(ctx, sessionID)
	if err != nil {
		return true, false, err
	}
	if rec == nil {
		return false, false, nil
	}
	out, endErr := m.end(ctx, sessionID, d)
	if endErr != nil {
		return true, false, nil
	}
	return out.ended, out.ended, nil
}

// appendOwed records more refresh tokens as owed in a session's record,
// whatever state the session is in.
func (m *Manager) appendOwed(ctx context.Context, sessionID string, entries ...Owed) error {
	failure := errors.New("oidcsession: the session kept changing while a revocation was being recorded")
	for range casAttempts {
		session, raw, err := m.load(ctx, sessionID)
		if err != nil {
			return err
		}
		session.Owed = addOwed(session.Owed, entries...)
		data, err := encode(session)
		if err != nil {
			return err
		}
		err = m.col.CompareAndSwap(ctx, sessionID, raw, data)
		if err == nil {
			return nil
		}
		if !errors.Is(err, persis.ErrConflict) {
			return fmt.Errorf("oidcsession: record the revocation: %w", err)
		}
	}
	return failure
}

// oweToken records that a refresh token of a session is to be revoked, and
// asks the provider once now. encrypted may be empty, in which case the token
// is encrypted here.
//
// If the token cannot be recorded, the provider is asked directly. If it does
// not take the revocation either, nothing will: that is logged as an error
// and returned, and never counted as handled.
func (m *Manager) oweToken(ctx context.Context, sessionID string, auth ClientAuth, refreshToken, encrypted string) error {
	if refreshToken == "" {
		return nil
	}
	var err error
	if encrypted == "" {
		encrypted, err = m.enc.Encrypt(refreshToken)
	}
	if err == nil {
		err = m.appendOwed(ctx, sessionID, m.newOwed(encrypted, auth))
	}
	if err == nil {
		m.attemptNow(ctx, sessionID)
		return nil
	}
	return m.revokeUnrecorded(ctx, sessionID, auth, refreshToken)
}

// askNow asks the provider to revoke a refresh token outside the rounds, for
// a caller that cannot wait for one. It does not ask a provider that has just
// left a revocation unanswered, and it notes when this one is. What it
// returns is the provider's answer, or that it was not asked.
func (m *Manager) askNow(ctx context.Context, auth ClientAuth, refreshToken string) error {
	now := m.now()
	if m.providerPaused(now) {
		return errors.New("oidcsession: the identity provider is not being asked for the moment")
	}
	err := m.provider.Revoke(context.WithoutCancel(ctx), refreshToken, auth)
	if err != nil && !errors.Is(err, ErrRevocationRefused) && !errors.Is(err, ErrRevocationUnsupported) {
		m.mu.Lock()
		m.owedFailedAt = now
		m.mu.Unlock()
	}
	return err
}

// revokeUnrecorded asks the provider to revoke a refresh token that could not
// be recorded as owed. It is the last thing that can be done for it, so the
// provider is asked whether or not it answered a moment ago.
func (m *Manager) revokeUnrecorded(ctx context.Context, sessionID string, auth ClientAuth, refreshToken string) error {
	err := m.provider.Revoke(context.WithoutCancel(ctx), refreshToken, auth)
	if err == nil {
		return nil
	}
	slog.Error("OIDC refresh token could be neither revoked nor recorded as owed; nothing will revoke it",
		slog.String("session", sessionID), slog.String("cause", fmt.Sprintf("%T", err)))
	return ErrObligationUnrecorded
}

// orphan records the refresh token of a sign-in that failed: the provider
// issued it and no session holds it. It gets a record of its own, ended from
// the start, so that it is revoked like any other. tryNow says the provider
// is answering and is to be asked at once.
func (m *Manager) orphan(ctx context.Context, who Identity, auth ClientAuth, refreshToken, reason string, tryNow bool) error {
	encrypted, err := m.enc.Encrypt(refreshToken)
	if err != nil {
		return m.revokeUnrecorded(ctx, "", auth, refreshToken)
	}
	id, err := newSessionID()
	if err != nil {
		return m.revokeUnrecorded(ctx, "", auth, refreshToken)
	}
	now := m.now().UTC()
	session := &Session{
		Schema: schemaVersion, ID: id, UserID: who.UserID, Issuer: who.Issuer, Subject: who.Subject,
		ClientAuth: auth, CreatedAt: now, ExpiresAt: now, LastConfirmedAt: now, ConfirmedBy: m.owner,
		EndedAt: &now, EndReason: reason, Owed: []Owed{m.newOwed(encrypted, auth)},
	}
	data, err := encode(session)
	if err == nil {
		err = m.col.Create(ctx, &persis.Record{ID: id, Data: data, CreatedAt: now, UpdatedAt: now})
	}
	if err != nil {
		return m.revokeUnrecorded(ctx, id, auth, refreshToken)
	}
	if tryNow {
		m.attemptNow(ctx, id)
	}
	return nil
}

// providerPaused reports whether the provider left a revocation unanswered so
// recently that it is not to be asked again yet.
func (m *Manager) providerPaused(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.owedFailedAt.IsZero() && now.Sub(m.owedFailedAt) < owedRetryInterval
}

// attemptNow makes the revocations a session owes that are due, for a caller
// that has just recorded one. It asks nothing of a provider that has just
// left one unanswered: the rounds will.
func (m *Manager) attemptNow(ctx context.Context, sessionID string) {
	now := m.now()
	if m.providerPaused(now) {
		return
	}
	if _, unanswered := m.attemptOwed(ctx, sessionID, reconcilePerRound); unanswered {
		m.mu.Lock()
		m.owedFailedAt = now
		m.mu.Unlock()
	}
}

// attemptOwed makes up to limit of the revocations a session owes that are
// due, the ones that came due first going first, and writes what came of
// each into the session's record. It returns how many it attempted, and
// whether the provider left one unanswered, at which it stops.
func (m *Manager) attemptOwed(ctx context.Context, sessionID string, limit int) (attempted int, unanswered bool) {
	session, _, err := m.load(ctx, sessionID)
	if err != nil {
		return 0, false
	}
	now := m.now()
	due := make([]Owed, 0, len(session.Owed))
	for _, entry := range session.Owed {
		if !entry.NextAttempt.After(now) {
			due = append(due, entry)
		}
	}
	slices.SortStableFunc(due, func(a, b Owed) int { return cmp.Or(a.NextAttempt.Compare(b.NextAttempt), a.Since.Compare(b.Since)) })
	outcomes := map[string]string{}
	for _, entry := range due {
		if attempted >= limit || unanswered {
			break
		}
		attempted++
		refreshToken, err := m.enc.Decrypt(entry.Token)
		if err != nil {
			// The key is not the one the token was encrypted with, or not
			// there. That may change, so the entry waits like one the
			// provider did not answer; it is not erased.
			outcomes[entry.Token] = attemptUnreadable
			continue
		}
		err = m.provider.Revoke(context.WithoutCancel(ctx), refreshToken, entry.Auth)
		switch {
		case err == nil:
			outcomes[entry.Token] = attemptRevoked
		case errors.Is(err, ErrRevocationUnsupported):
			outcomes[entry.Token] = attemptUnsupported
		case errors.Is(err, ErrRevocationRefused):
			outcomes[entry.Token] = attemptRefused
		default:
			slog.Warn("OIDC refresh token could not be revoked at the identity provider; it stays owed",
				slog.String("session", sessionID), slog.String("cause", fmt.Sprintf("%T", err)))
			outcomes[entry.Token] = attemptUnanswered
			unanswered = true
		}
	}
	if len(outcomes) > 0 {
		m.recordAttempts(ctx, sessionID, outcomes, now)
	}
	return attempted, unanswered
}

// recordAttempts writes the outcomes of attempts into a session's record. An
// entry that is done leaves the owed list and becomes a Disposition. One that
// is not gets its next attempt. If the write is lost the entries stay as they
// were, due, and are attempted again, which is safe: a revocation can be
// asked for twice.
func (m *Manager) recordAttempts(ctx context.Context, sessionID string, outcomes map[string]string, now time.Time) {
	for range casAttempts {
		session, raw, err := m.load(ctx, sessionID)
		if err != nil {
			return
		}
		kept := session.Owed[:0:0]
		for _, entry := range session.Owed {
			outcome, attempted := outcomes[entry.Token]
			if !attempted {
				kept = append(kept, entry)
				continue
			}
			disposed := settleAttempt(&entry, outcome, now)
			if disposed == "" {
				kept = append(kept, entry)
				continue
			}
			session.Revocations = append(session.Revocations, Disposition{
				At: now.UTC(), Outcome: disposed, Attempts: entry.Attempts, Since: entry.Since,
			})
			if disposed != disposedRevoked {
				slog.Error("OIDC refresh token was not revoked at the identity provider and will not be asked for again",
					slog.String("session", sessionID), slog.String("outcome", disposed), slog.Int("attempts", entry.Attempts))
			}
		}
		session.Owed = kept
		data, err := encode(session)
		if err != nil {
			return
		}
		err = m.col.CompareAndSwap(ctx, sessionID, raw, data)
		if err == nil || !errors.Is(err, persis.ErrConflict) {
			return
		}
	}
}

// settleAttempt counts an attempt on an entry. It returns the disposition if
// the entry is done, and otherwise sets when it is next due.
func settleAttempt(entry *Owed, outcome string, now time.Time) (disposed string) {
	entry.Attempts++
	entry.Last = outcome
	switch outcome {
	case attemptRevoked:
		return disposedRevoked
	case attemptUnsupported:
		return disposedUnsupported
	case attemptRefused:
		entry.Refusals++
		if entry.Refusals >= maxRevocationRefusals {
			return disposedRefused
		}
	default:
		if entry.Attempts >= giveUpAttempts && now.Sub(entry.Since) >= giveUpAfter {
			return disposedGivenUp
		}
	}
	entry.NextAttempt = now.Add(owedBackoff(entry.Attempts)).UTC()
	return ""
}

// owedBackoff is the wait after the given number of attempts at one
// revocation: a minute, doubling, and at most maxOwedBackoff.
func owedBackoff(attempts int) time.Duration {
	wait := owedRetryInterval
	for range attempts - 1 {
		wait *= 2
		if wait >= maxOwedBackoff {
			return maxOwedBackoff
		}
	}
	return wait
}

// kick starts a round of reconciling if one is due. A sign-in always starts
// one; an ordinary request starts one at most every reconcileInterval. So the
// rounds do not depend on anybody signing in.
//
// The round does not run inside the request. It reads the whole collection,
// and may wait for the provider, and neither is something for a request to
// wait for, or for the answer to a request to grow stale during. It runs
// beside it, on its own, and ends by itself.
func (m *Manager) kick(ctx context.Context, now time.Time, signIn bool) {
	last := m.lastRound.Load()
	if !signIn && last != 0 && now.Sub(time.Unix(0, last)) < reconcileInterval {
		return
	}
	// One request starts the round that is due; the others that arrive at
	// the same moment see that it has been started.
	if !m.lastRound.CompareAndSwap(last, now.UnixNano()) && !signIn {
		return
	}
	background := context.WithoutCancel(ctx)
	m.spawn(func() { m.reconcile(background, now) })
}

// dueEntry is a revocation that is owed and due, and the session whose record
// holds it.
type dueEntry struct {
	session string
	token   string
	// due is when it came due, and since when it was first owed.
	due, since time.Time
}

// reconcile does what is left over: it writes the session ends the store did
// not take, applies the end markers other writes left, ends the sessions
// whose hub token has expired, makes the revocations that are due, and
// removes the records of sessions that ended more than a day ago and owe
// nothing.
//
// One at a time does it, and another that is started meanwhile returns at
// once. A round deals with reconcilePerRound of each kind. The revocations
// that came due first go first, whichever records they are in. One the
// provider answers no to does not hold up the others, because the provider is
// there; one it does not answer ends the round, and no round asks again for
// owedRetryInterval.
//
// A round reads every record of the collection once. That is the store's
// cost of listing, and why a round does not run inside a request.
func (m *Manager) reconcile(ctx context.Context, now time.Time) {
	if !m.reconciling.CompareAndSwap(false, true) {
		return
	}
	defer m.reconciling.Store(false)
	m.lastRound.Store(now.UnixNano())

	// What this process remembers.
	m.mu.Lock()
	for id, failed := range m.failedAt {
		if now.Sub(failed) >= m.cfg.RetryInterval {
			delete(m.failedAt, id)
		}
	}
	pending := make(map[string]decision, reconcilePerRound)
	expired := map[string]decision{}
	for id, d := range m.undone {
		if !d.expires.IsZero() && !now.Before(d.expires) {
			// The hub token has expired: nothing can present the session, so
			// its end need not be remembered. The session's own refresh token
			// is dealt with below, where every expired session is ended. The
			// tokens the decision itself brings are in no record, and are
			// given one before the decision is forgotten.
			expired[id] = d
			continue
		}
		if len(pending) < reconcilePerRound {
			pending[id] = d
		}
	}
	m.mu.Unlock()
	for id, d := range expired {
		if len(d.owe) > 0 && m.stub(ctx, d.reason, d.owe) != nil {
			continue
		}
		m.mu.Lock()
		delete(m.undone, id)
		m.mu.Unlock()
	}
	// A session that is ended in this round may owe a revocation from that
	// moment. It is looked at again below, so that the revocation does not
	// wait for the next round.
	var justEnded []string
	for id, d := range pending {
		if out, err := m.end(ctx, id, d); err == nil && out.owes {
			justEnded = append(justEnded, id)
		}
	}

	// What the store holds.
	var due []dueEntry
	marks, lapsed := 0, 0
	cursor := ""
	for {
		page, err := m.col.List(ctx, persis.ListQuery{Cursor: cursor})
		if err != nil {
			break
		}
		for _, rec := range page.Records {
			if strings.HasPrefix(rec.ID, endMarkerPrefix) {
				if marks < reconcilePerRound {
					marks++
					if id, ended := m.reconcileMark(ctx, rec, now); ended {
						justEnded = append(justEnded, id)
					}
				}
				continue
			}
			var session Session
			if json.Unmarshal(rec.Data, &session) != nil {
				continue
			}
			switch {
			case len(session.Owed) > 0:
				// A record that owes a revocation is kept, however old.
				due = appendDue(due, rec.ID, session.Owed, now)
			case session.EndedAt == nil && !now.Before(session.ExpiresAt):
				// The hub token has expired and the session was never ended.
				// The hub will not use its refresh token again, and the token
				// is still good at the provider. The session is ended now, so
				// that the token becomes owed and is revoked like any other.
				if lapsed < reconcilePerRound {
					lapsed++
					out, err := m.end(ctx, rec.ID, decision{reason: "the hub token expired", revoke: true, expires: session.ExpiresAt, passive: true})
					if err == nil && out.owes {
						justEnded = append(justEnded, rec.ID)
					}
				}
			case session.EndedAt != nil && now.Sub(*session.EndedAt) > purgeAfter:
				m.purge(ctx, rec)
			}
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	for _, id := range justEnded {
		if slices.ContainsFunc(due, func(d dueEntry) bool { return d.session == id }) {
			continue
		}
		if session, _, err := m.load(ctx, id); err == nil {
			due = appendDue(due, id, session.Owed, now)
		}
	}
	if len(due) == 0 || m.providerPaused(now) {
		return
	}
	// The ones that came due first go first, whichever records they are in.
	// An entry's wait is capped, so an old one comes due again and is then
	// ahead of every one that came due after it; and one the provider keeps
	// leaving unanswered moves behind the others each time it is tried.
	slices.SortFunc(due, func(a, b dueEntry) int {
		return cmp.Or(a.due.Compare(b.due), a.since.Compare(b.since), cmp.Compare(a.session, b.session), cmp.Compare(a.token, b.token))
	})
	if len(due) > reconcilePerRound {
		due = due[:reconcilePerRound]
	}
	// Each is made by asking its record for the one that came due first
	// there, which is this one unless another process has made it meanwhile.
	for _, entry := range due {
		if _, unanswered := m.attemptOwed(ctx, entry.session, 1); unanswered {
			m.mu.Lock()
			m.owedFailedAt = now
			m.mu.Unlock()
			break
		}
	}
}

// appendDue adds a record's owed revocations that are due to a list.
func appendDue(due []dueEntry, sessionID string, owed []Owed, now time.Time) []dueEntry {
	for _, entry := range owed {
		if !entry.NextAttempt.After(now) {
			due = append(due, dueEntry{session: sessionID, token: entry.Token, due: entry.NextAttempt, since: entry.Since})
		}
	}
	return due
}

// purge removes the record of a session that ended more than a day ago and
// owes nothing. A record whose end is still marked beside it is not removed:
// the marker may be about to move the session's refresh token into the
// record's owed list, and removing the record first would lose the token.
//
// No marker can be written for such a record after this look. A marker is
// written when a write that ends a session fails, and a session that ended a
// day ago is not ended again.
func (m *Manager) purge(ctx context.Context, rec *persis.Record) {
	if _, mark, err := m.marked(ctx, rec.ID); err != nil || mark != nil {
		return
	}
	_ = m.col.CompareAndDelete(ctx, rec)
}

// earliestDue returns when the earliest of the entries that are due came due.
func earliestDue(owed []Owed, now time.Time) (time.Time, bool) {
	var first time.Time
	found := false
	for _, entry := range owed {
		if entry.NextAttempt.After(now) {
			continue
		}
		if !found || entry.NextAttempt.Before(first) {
			first, found = entry.NextAttempt, true
		}
	}
	return first, found
}

// reconcileMark applies an end marker, and reports the session it ended. One
// whose session's record cannot be read stays until the session's hub token
// has long expired. Then nothing can present the session, the token in the
// unreadable record cannot be revoked by anyone, and the marker is closed
// with an error in the log.
func (m *Manager) reconcileMark(ctx context.Context, rec *persis.Record, now time.Time) (sessionID string, ended bool) {
	var marker endMarker
	if json.Unmarshal(rec.Data, &marker) != nil || marker.Kind != endMarkerKind || !validID(marker.Session) {
		// A marker that cannot be understood. If its name still says whose it
		// is, that session is ended; see marked.
		marker = endMarker{Session: strings.TrimPrefix(rec.ID, endMarkerPrefix)}
		if !validID(marker.Session) {
			return "", false
		}
	}
	if _, written, _ := m.applyMark(ctx, marker.Session); written {
		return marker.Session, true
	}
	_, current, err := m.marked(ctx, marker.Session)
	if err != nil || current == nil {
		return "", false
	}
	if !marker.Expires.IsZero() && now.Sub(marker.Expires) > purgeAfter {
		// The tokens the marker itself carries can still be revoked. They
		// get a record of their own before the marker goes.
		if len(marker.Owe) > 0 && m.stub(ctx, marker.Reason, marker.Owe) != nil {
			return "", false
		}
		slog.Error("OIDC session end could never be written into its record; the record's refresh token was not revoked",
			slog.String("session", marker.Session))
		// The marker as it is now, not as the listing saw it.
		m.unmark(ctx, current)
	}
	return "", false
}
