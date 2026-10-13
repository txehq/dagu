// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package oidcsession

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errProviderDown = errors.New("the provider did not answer")

// owing puts a record in the store that owes the revocation of the given
// refresh token: ended, with the token due now and never tried. It is what a
// hub process leaves when it stops right after ending a session. It returns
// the record.
func (f *fixture) owing(refreshToken string) *Session {
	f.t.Helper()
	require.NoError(f.t, f.manager.orphan(context.Background(), alice, ClientAuthHeader, refreshToken, "signed out", false))
	sessions, _ := f.records()
	for _, session := range sessions {
		for _, entry := range session.Owed {
			if token, err := f.enc.Decrypt(entry.Token); err == nil && token == refreshToken {
				return session
			}
		}
	}
	f.t.Fatalf("no record owes %q", refreshToken)
	return nil
}

// round runs one round of reconciling on a hub process, as a request or a
// sign-in would.
func (f *fixture) round(m *Manager) {
	m.reconcile(context.Background(), f.clock.Now())
}

// The revocation of a signed-out session's refresh token is in the session's
// record from the write that ends it. It does not depend on the process that
// took the sign-out: another one, or the same one restarted, makes it.
func TestAnOwedRevocationIsInTheRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("TheWriteThatEndsTheSessionRecordsIt", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		f.provider.failRevocations(errProviderDown)
		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt),
			"the sign-out does not wait for the provider, and does not fail for it")

		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Empty(t, stored.RefreshToken, "an ended session does not hold a token it could refresh with")
		require.Len(t, stored.Owed, 1)
		owed := stored.Owed[0]
		assert.Equal(t, []string{"refresh-token-0"}, f.owedTokens(), "it is kept, encrypted, as owed")
		assert.NotContains(t, owed.Token, "refresh-token-0")
		assert.Equal(t, 1, owed.Attempts)
		assert.Equal(t, attemptUnanswered, owed.Last)
		assert.Equal(t, f.clock.Now().Add(owedRetryInterval), owed.NextAttempt)
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
	})

	// The process is gone the moment the end is written: before it asked the
	// provider, and with everything it had in memory.
	t.Run("ACrashRightAfterTheEndIsWritten", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		_, err := f.manager.end(ctx, session.ID, decision{reason: "signed out", revoke: true, expires: session.ExpiresAt})
		require.NoError(t, err)
		require.Empty(t, f.provider.revocations())

		restarted := f.process()
		f.round(restarted)
		assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations())
		stored := f.stored(session)
		assert.Empty(t, stored.Owed)
		require.Len(t, stored.Revocations, 1)
		assert.Equal(t, disposedRevoked, stored.Revocations[0].Outcome)
		assert.Equal(t, 1, stored.Revocations[0].Attempts)
	})

	t.Run("AnotherHubProcessMakesIt", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.owing("refresh-token-a")
		other := f.process()

		f.round(other)
		assert.Equal(t, []string{"refresh-token-a"}, f.provider.revocations())
		assert.Empty(t, f.stored(session).Owed)
		f.provider.mu.Lock()
		assert.Equal(t, []ClientAuth{ClientAuthHeader}, f.provider.revokedWays, "the way the session had goes with the token")
		f.provider.mu.Unlock()

		f.clock.Advance(owedRetryInterval)
		f.round(f.manager)
		f.round(other)
		assert.Len(t, f.provider.revocations(), 1, "and once it is made, neither process makes it again")
	})

	// A round is started by an ordinary request, not only by a sign-in.
	t.Run("ItDoesNotWaitForASignIn", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		someoneElse := f.signIn()
		f.owing("refresh-token-a")
		require.Empty(t, f.provider.revocations())

		f.clock.Advance(reconcileInterval)
		require.NoError(t, f.check(someoneElse))
		assert.Equal(t, []string{"refresh-token-a"}, f.provider.revocations())

		// And not at every request.
		f.owing("refresh-token-b")
		require.NoError(t, f.check(someoneElse))
		require.NoError(t, f.check(someoneElse))
		assert.Len(t, f.provider.revocations(), 1)
	})

	// A request for the session that was signed out starts a round too, though
	// it is itself refused.
	t.Run("ARefusedRequestStartsARoundAsWell", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.owing("refresh-token-a")
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		assert.Equal(t, []string{"refresh-token-a"}, f.provider.revocations())
	})
}

// Nothing ends a revocation but the provider's answer, or an explicit and
// recorded giving up. Its age does not.
func TestAnOwedRevocationIsNotDroppedForItsAge(t *testing.T) {
	t.Parallel()

	// Nobody signs in, and no request comes, for longer than any record is
	// kept. The revocation has never been tried again. It is still made.
	t.Run("AnIdleHub", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.owing("refresh-token-a")
		f.clock.Advance(40 * 24 * time.Hour)
		f.round(f.manager)
		assert.Equal(t, []string{"refresh-token-a"}, f.provider.revocations())
		assert.Equal(t, disposedRevoked, f.stored(session).Revocations[0].Outcome)
	})

	// A failed sign-in's token was never tried at all.
	t.Run("OneThatWasNeverTried", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		f.provider.establish = func(string) (ClientAuth, Renewal, error) {
			return ClientAuthDetect, Renewal{}, errProviderDown
		}
		_, err := f.manager.Create(context.Background(), alice, "refresh-token-a", f.clock.Now().Add(time.Hour))
		require.ErrorIs(t, err, ErrProviderUnavailable)
		require.NotErrorIs(t, err, ErrObligationUnrecorded)
		sessions, _ := f.records()
		require.Len(t, sessions, 1)
		require.Zero(t, sessions[0].Owed[0].Attempts)

		f.clock.Advance(40 * 24 * time.Hour)
		f.round(f.process())
		assert.Equal(t, []string{"refresh-token-a"}, f.provider.revocations())
		f.provider.mu.Lock()
		assert.Equal(t, []ClientAuth{ClientAuthDetect}, f.provider.revokedWays, "its session never had a way, so it is asked both")
		f.provider.mu.Unlock()
	})

	// The record that holds it is not purged, however long ago the session
	// ended. It is purged once it owes nothing.
	t.Run("ItsRecordIsKept", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		f.owing("refresh-token-a")
		f.provider.failRevocations(errProviderDown)
		for range 5 {
			f.clock.Advance(3 * 24 * time.Hour)
			f.round(f.manager)
		}
		sessions, _ := f.records()
		require.Len(t, sessions, 1, "fifteen days after the session ended")
		require.Equal(t, []string{"refresh-token-a"}, f.owedTokens())

		f.provider.failRevocations(nil)
		f.clock.Advance(maxOwedBackoff)
		f.round(f.manager)
		require.Empty(t, f.owedTokens())
		f.round(f.manager)
		sessions, _ = f.records()
		assert.Empty(t, sessions, "it owes nothing now, and it ended more than a day ago")
	})

	// Giving up takes both a long time and many attempts, and is written down.
	t.Run("GivingUpTakesBothTimeAndAttempts", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.owing("refresh-token-a")
		f.provider.failRevocations(errProviderDown)

		// Many attempts in a short time: not given up.
		for f.stored(session).Owed[0].Attempts < giveUpAttempts+5 {
			f.clock.Advance(maxOwedBackoff)
			f.round(f.manager)
		}
		require.Less(t, f.clock.Now().Sub(f.stored(session).Owed[0].Since), giveUpAfter)
		require.Len(t, f.stored(session).Owed, 1)

		// A long time, and then one more attempt.
		f.clock.Advance(giveUpAfter)
		f.round(f.manager)
		stored := f.stored(session)
		require.Empty(t, stored.Owed)
		require.Len(t, stored.Revocations, 1)
		assert.Equal(t, disposedGivenUp, stored.Revocations[0].Outcome)
		assert.Equal(t, giveUpAttempts+6, stored.Revocations[0].Attempts)
		assert.Empty(t, f.provider.revocations(), "it is recorded as not revoked, not as revoked")
	})

	// A long time alone is not enough either.
	t.Run("ALongTimeAndFewAttempts", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.owing("refresh-token-a")
		f.provider.failRevocations(errProviderDown)
		f.clock.Advance(2 * giveUpAfter)
		f.round(f.manager)
		require.Len(t, f.stored(session).Owed, 1)
		assert.Equal(t, 1, f.stored(session).Owed[0].Attempts)
	})
}

// What the provider's answers to a revocation lead to.
func TestTheProvidersAnswerToARevocation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A provider that answers no has answered. Three times is its answer.
	t.Run("No", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		f.provider.failRevocations(fmt.Errorf("%w: 400", ErrRevocationRefused))
		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))
		require.Equal(t, 1, f.stored(session).Owed[0].Refusals)
		for range maxRevocationRefusals - 1 {
			require.Len(t, f.stored(session).Owed, 1)
			f.clock.Advance(maxOwedBackoff)
			f.round(f.manager)
		}
		stored := f.stored(session)
		require.Empty(t, stored.Owed)
		assert.Equal(t, disposedRefused, stored.Revocations[0].Outcome)
		assert.Equal(t, maxRevocationRefusals, stored.Revocations[0].Attempts)
	})

	// A provider that says to come back later has not answered no.
	t.Run("ComeBackLater", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.owing("refresh-token-a")
		f.provider.failRevocations(errors.New("the revocation endpoint answered 429"))
		for range 4 * maxRevocationRefusals {
			f.clock.Advance(maxOwedBackoff)
			f.round(f.manager)
		}
		require.Len(t, f.stored(session).Owed, 1)
		assert.Zero(t, f.stored(session).Owed[0].Refusals)

		f.provider.failRevocations(nil)
		f.clock.Advance(maxOwedBackoff)
		f.round(f.manager)
		assert.Equal(t, []string{"refresh-token-a"}, f.provider.revocations())
	})

	// A provider with no revocation endpoint cannot be asked. The hub does
	// not keep a credential it can never use up: it records that the token
	// was not revoked, and why, and erases it.
	t.Run("NoRevocationEndpoint", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		f.provider.failRevocations(ErrRevocationUnsupported)
		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))
		stored := f.stored(session)
		require.Empty(t, stored.Owed)
		require.Len(t, stored.Revocations, 1)
		assert.Equal(t, disposedUnsupported, stored.Revocations[0].Outcome)
	})

	// Each wait is longer than the last, up to a limit.
	t.Run("TheWaitBetweenAttempts", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, time.Minute, owedBackoff(1))
		assert.Equal(t, 2*time.Minute, owedBackoff(2))
		assert.Equal(t, 32*time.Minute, owedBackoff(6))
		assert.Equal(t, maxOwedBackoff, owedBackoff(7))
		assert.Equal(t, maxOwedBackoff, owedBackoff(500))
		assert.Equal(t, time.Minute, owedBackoff(0))
	})
}

// A round is bounded, and what it leaves waits its turn: the revocations that
// came due first go first, so one that has been tried is not left behind by
// those that have not.
func TestARoundOfRevocations(t *testing.T) {
	t.Parallel()

	t.Run("IsBounded", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		for i := range 2*reconcilePerRound + 3 {
			f.owing(fmt.Sprintf("refresh-token-%02d", i))
			f.clock.Advance(time.Second)
		}
		f.clock.Advance(maxOwedBackoff)
		f.round(f.manager)
		revoked := f.provider.revocations()
		require.Len(t, revoked, reconcilePerRound)
		for i, token := range revoked {
			assert.Equal(t, fmt.Sprintf("refresh-token-%02d", i), token, "in the order they came due")
		}
		f.round(f.manager)
		f.round(f.manager)
		assert.Len(t, f.provider.revocations(), 2*reconcilePerRound+3)
		assert.Empty(t, f.owedTokens())
	})

	// An old one that the provider left unanswered once, and more new ones in
	// every round than a round can make. Only the ones that came due before
	// it are ahead of it, and there are no more of those to come: everything
	// that arrives later comes due later. So it is made after them, however
	// many new ones keep arriving.
	t.Run("AnOldOneIsNotStarvedByNewOnes", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		old := f.owing("the-old-token")
		f.provider.failRevocations(errProviderDown)
		f.round(f.manager)
		f.provider.failRevocations(nil)
		require.Equal(t, 1, f.stored(old).Owed[0].Attempts)
		require.Equal(t, f.clock.Now().Add(owedRetryInterval), f.stored(old).Owed[0].NextAttempt)

		// Twenty that arrive while it waits. They came due before it does.
		for i := range reconcilePerRound + 4 {
			f.owing(fmt.Sprintf("ahead-%02d", i))
		}
		made := 0
		for round := 1; round <= 6 && made == 0; round++ {
			f.clock.Advance(owedRetryInterval + time.Second)
			for i := range reconcilePerRound + 4 {
				f.owing(fmt.Sprintf("later-%d-%02d", round, i)) // these come due after it
			}
			f.round(f.manager)
			if len(f.stored(old).Owed) == 0 {
				made = round
			}
		}
		assert.Equal(t, 2, made, "sixteen of the twenty ahead of it in the first round, the other four and then it in the second")
		revoked := f.provider.revocations()
		at := slices.Index(revoked, "the-old-token")
		require.GreaterOrEqual(t, at, 0)
		for _, token := range revoked[:at] {
			assert.Contains(t, token, "ahead-", "nothing that came due after it was made before it")
		}
	})

	// One that the provider answers no to does not hold up the others. One it
	// does not answer ends the round, and no round asks again for a while.
	t.Run("ANoDoesNotHoldUpTheOthersAndSilenceEndsTheRound", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		for i := range 4 {
			f.owing(fmt.Sprintf("refresh-token-%d", i))
			f.clock.Advance(time.Second)
		}
		attempts := 0
		f.provider.mu.Lock()
		f.provider.onRevoke = func() { attempts++ }
		f.provider.revokeErrFor = map[string]error{
			"refresh-token-0": fmt.Errorf("%w: 400", ErrRevocationRefused),
			"refresh-token-2": errProviderDown,
		}
		f.provider.mu.Unlock()

		f.clock.Advance(maxOwedBackoff)
		f.round(f.manager)
		assert.Equal(t, 3, attempts, "the third got no answer, and the fourth was not tried")
		assert.Equal(t, []string{"refresh-token-1"}, f.provider.revocations())

		f.clock.Advance(owedRetryInterval - time.Second)
		f.round(f.manager)
		assert.Equal(t, 3, attempts, "the provider is not asked again so soon")

		f.clock.Advance(time.Second)
		f.round(f.manager)
		assert.Contains(t, f.provider.revocations(), "refresh-token-3", "the one that was not reached is made once the pause is over")
	})

	t.Run("OneAtATime", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		f.owing("refresh-token-a")
		f.clock.Advance(maxOwedBackoff)
		f.manager.reconciling.Store(true) // another request is at it
		f.round(f.manager)
		require.Empty(t, f.provider.revocations())
		f.manager.reconciling.Store(false)
		f.round(f.manager)
		assert.Equal(t, []string{"refresh-token-a"}, f.provider.revocations())
	})
}

// A token that cannot be read now, because the key is not the one it was
// encrypted with, is not erased and not called revoked. It waits, and is
// revoked when it can be read.
func TestAKeyFailureIsNotAnErasure(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.owing("refresh-token-a")
	good := f.manager.enc
	f.manager.enc = brokenKey{good}

	f.clock.Advance(maxOwedBackoff)
	f.round(f.manager)
	stored := f.stored(session)
	require.Len(t, stored.Owed, 1)
	assert.Equal(t, attemptUnreadable, stored.Owed[0].Last)
	assert.Empty(t, stored.Revocations)
	assert.Empty(t, f.provider.revocations())

	f.manager.enc = good
	f.clock.Advance(maxOwedBackoff)
	f.round(f.manager)
	assert.Equal(t, []string{"refresh-token-a"}, f.provider.revocations())
}

// brokenKey decrypts nothing, as a hub started with another key would.
type brokenKey struct{ Encryptor }

func (brokenKey) Decrypt(string) (string, error) { return "", errors.New("wrong key") }

// noKey can neither encrypt nor decrypt.
type noKey struct{}

func (noKey) Encrypt(string) (string, error) { return "", errors.New("no key") }
func (noKey) Decrypt(string) (string, error) { return "", errors.New("no key") }

// A live session whose token cannot be read ends, because it can never be
// confirmed. Its token is kept as owed, not erased.
func TestASessionWhoseTokenCannotBeReadEndsAndKeepsTheToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	good := f.manager.enc
	f.manager.enc = brokenKey{good}
	f.clock.Advance(4 * time.Minute)
	require.ErrorIs(t, f.check(session), ErrSessionEnded)
	stored := f.stored(session)
	require.NotNil(t, stored.EndedAt)
	require.Len(t, stored.Owed, 1)
	assert.Zero(t, f.provider.calls())

	f.manager.enc = good
	f.clock.Advance(maxOwedBackoff)
	f.round(f.manager)
	assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations())
}

// A token is never called handled when it was neither revoked nor recorded.
func TestATokenThatCouldBeNeitherRevokedNorRecorded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	refuses := func(string) (ClientAuth, Renewal, error) {
		return ClientAuthDetect, Renewal{}, &RefusedError{Status: 401, Code: "invalid_client"}
	}

	// A sign-in fails, the store takes no new record, and the provider does
	// not take the revocation. The sign-in's error says so.
	t.Run("AtAFailedSignIn", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		f.provider.establish = refuses
		f.manager.col = &failingCollection{Collection: f.col, create: errors.New("disk full")}
		f.provider.failRevocations(errProviderDown)
		_, err := f.manager.Create(ctx, alice, "refresh-token-a", f.clock.Now().Add(time.Hour))
		require.ErrorIs(t, err, ErrObligationUnrecorded)
		require.ErrorContains(t, err, "will not refresh the token it has just issued", "the sign-in's own failure is still what it says first")
		sessions, _ := f.records()
		assert.Empty(t, sessions)
	})

	// The store takes no new record, and the provider does take the
	// revocation: nothing is owed, and nothing is reported as unrecorded.
	t.Run("TheProviderTakesIt", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		f.provider.establish = refuses
		f.manager.col = &failingCollection{Collection: f.col, create: errors.New("disk full")}
		_, err := f.manager.Create(ctx, alice, "refresh-token-a", f.clock.Now().Add(time.Hour))
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrObligationUnrecorded)
		assert.Equal(t, []string{"refresh-token-a"}, f.provider.revocations())
	})

	// No key to encrypt it with, so it cannot be recorded.
	t.Run("ItCannotBeEncrypted", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		f.provider.establish = refuses
		f.manager.enc = noKey{}
		f.provider.failRevocations(errProviderDown)
		_, err := f.manager.Create(ctx, alice, "refresh-token-a", f.clock.Now().Add(time.Hour))
		require.ErrorIs(t, err, ErrObligationUnrecorded)

		f.provider.failRevocations(nil)
		_, err = f.manager.Create(ctx, alice, "refresh-token-b", f.clock.Now().Add(time.Hour))
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrObligationUnrecorded)
		assert.Equal(t, []string{"refresh-token-b"}, f.provider.revocations())
	})

	// Sign-out reports success only when the end is in the store.
	t.Run("ASignOutTheStoreTookNothingOf", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col, create: errors.New("disk full")}
		f.manager.col = broken
		broken.failWritesAfter(0)
		require.Error(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))
		require.ErrorIs(t, f.check(session), ErrSessionEnded, "this process refuses all the same")
		_, markers := f.records()
		assert.Zero(t, markers)
		assert.Nil(t, f.stored(session).EndedAt)
	})
}

// A session end the session's record did not take is written beside it as a
// marker. It holds for every hub process, and across a restart.
func TestAnEndTheRecordDidNotTake(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// unwritable makes a hub process unable to change the session records it
	// has. It can still create a record.
	unwritable := func(f *fixture, m *Manager) (heal func()) {
		broken := &failingCollection{Collection: f.col}
		m.col = broken
		return broken.failWritesAfter(0)
	}

	t.Run("IsMarkedAndTheSignOutSucceeds", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		unwritable(f, f.manager)

		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt), "the end is in the store")
		_, markers := f.records()
		require.Equal(t, 1, markers)
		require.Nil(t, f.stored(session).EndedAt, "though not in the record")
		require.ErrorIs(t, f.check(session), ErrSessionEnded, "the process that took the sign-out refuses at once")
		assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations(),
			"and the provider is asked at once, so that the token is refused wherever it is tried")
	})

	// Another hub process goes by the record until it next comes to refresh
	// the session. Then it finds the marker and ends the session, without
	// asking the provider whether the session is still good.
	t.Run("AnotherHubProcessAppliesIt", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		other := f.process()
		other.spawn = func(func()) {} // no round runs on it, so that only the refresh can find the marker
		unwritable(f, f.manager)
		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))

		require.NoError(t, other.Check(ctx, session.ID, alice), "inside revalidate_after it goes by the record")
		f.clock.Advance(4 * time.Minute)
		require.ErrorIs(t, other.Check(ctx, session.ID, alice), ErrSessionEnded)
		assert.Zero(t, f.provider.calls(), "the provider was not asked to refresh a session that had been signed out")

		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, "signed out", stored.EndReason)
		_, markers := f.records()
		assert.Zero(t, markers, "the marker is gone once the record holds the end")
		assert.Equal(t, []string{"refresh-token-0"}, f.owedTokens(), "and the token is owed in the record, for the next round")
		f.round(f.process())
		assert.Empty(t, f.owedTokens())
	})

	// A round on another process finds the marker sooner than its next
	// refresh of the session would: rounds are started by any request, at most
	// once a minute.
	t.Run("ARoundOnAnotherProcessAppliesItSooner", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		someoneElse := f.signIn()
		other := f.process()
		other.kick(ctx, f.clock.Now()) // a round ran on it a moment ago
		unwritable(f, f.manager)
		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))

		require.NoError(t, other.Check(ctx, session.ID, alice), "a round ran a moment ago, and the session is inside revalidate_after")
		f.clock.Advance(reconcileInterval)
		require.NoError(t, other.Check(ctx, someoneElse.ID, alice), "a request for another session starts the round")
		require.NotNil(t, f.stored(session).EndedAt)
		require.ErrorIs(t, other.Check(ctx, session.ID, alice), ErrSessionEnded, "one minute after the sign-out, not four")
		assert.Zero(t, f.provider.calls())
	})

	// The process that took the sign-out is restarted. What it remembered is
	// gone. The marker is not.
	t.Run("ARestartDoesNotBringTheSessionBack", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		unwritable(f, f.manager)
		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))

		restarted := f.process()
		f.round(restarted) // any request or sign-in after the restart
		require.NotNil(t, f.stored(session).EndedAt)
		require.ErrorIs(t, restarted.Check(ctx, session.ID, alice), ErrSessionEnded)
		assert.Zero(t, f.provider.calls())
	})

	// The same for an end a refresh decided: the provider refused, and the
	// record did not take it.
	t.Run("ARefusalIsMarkedToo", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col}
		f.manager.col = broken
		broken.failWritesAfter(1) // the claim
		f.provider.set(refuse("invalid_grant"))
		f.clock.Advance(4 * time.Minute)
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		require.Nil(t, f.stored(session).EndedAt)

		f.provider.set(f.provider.rotate()) // if it were asked again, it would be granted
		restarted := f.process()
		f.clock.Advance(refreshClaim + maxClockSkew)
		require.ErrorIs(t, restarted.Check(ctx, session.ID, alice), ErrSessionEnded)
		assert.Equal(t, 1, f.provider.calls(), "the refusal stands; the provider is not asked again")
		assert.Equal(t, "refused by the identity provider: invalid_grant", f.stored(session).EndReason)
		assert.Empty(t, f.owedTokens(), "a token the provider refused is not owed a revocation")
	})

	// A process that finds the marker and cannot write the end into the
	// record either does not go on as if there were no marker: it refuses, and
	// does not ask the provider to refresh a session that has been signed out.
	t.Run("AProcessThatCannotApplyItStillRefuses", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		other := f.process()
		other.spawn = func(func()) {} // no round runs on it: it is the refresh that meets the marker
		unwritable(f, f.manager)
		unwritable(f, other)
		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))

		f.clock.Advance(4 * time.Minute)
		require.ErrorIs(t, other.Check(ctx, session.ID, alice), ErrSessionEnded)
		assert.Zero(t, f.provider.calls())
		assert.Nil(t, f.stored(session).EndedAt)
		_, markers := f.records()
		assert.Equal(t, 1, markers, "the marker stays until the record holds the end")
	})

	// The marker carries a token that only it knows of. Another process ends
	// the session by itself, and clears the marker. The token goes into the
	// record with the end; it is not lost with the marker.
	t.Run("ATokenOnlyTheMarkerKnowsOfIsKept", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		extra, err := f.enc.Encrypt("a-token-only-the-marker-knows-of")
		require.NoError(t, err)
		require.True(t, f.manager.mark(ctx, session.ID, decision{
			reason: "the renewed session could not be stored", ifToken: "a-token-the-record-does-not-hold",
			owe: []Owed{f.manager.newOwed(extra, ClientAuthForm)}, expires: session.ExpiresAt,
		}))

		other := f.process()
		require.NoError(t, other.End(ctx, session.ID, "signed out", session.ExpiresAt))
		_, markers := f.records()
		assert.Zero(t, markers)
		assert.ElementsMatch(t, []string{"refresh-token-0", "a-token-only-the-marker-knows-of"}, f.provider.revocations())
		assert.Empty(t, f.owedTokens())
	})

	// Whether a session's end is marked cannot be read. Then it is not known
	// whether the session was signed out, and the provider is not asked to
	// renew it on a guess: the request is told to come back, not let in.
	t.Run("AMarkerThatCannotBeReadIsNotTakenForNoMarker", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col, failFor: map[string]error{endMarkerID(session.ID): errors.New("bad sector")}}
		f.manager.col = broken
		f.clock.Advance(4 * time.Minute)
		err := f.check(session)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrSessionEnded)
		assert.Zero(t, f.provider.calls())

		delete(broken.failFor, endMarkerID(session.ID))
		require.NoError(t, f.check(session))
	})

	// A marker that is there and cannot be understood says an end was
	// decided, and not how. The session ends, as for a sign-out.
	t.Run("AMarkerThatCannotBeUnderstoodEndsTheSession", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		now := f.clock.Now()
		require.NoError(t, f.col.Create(ctx, &persis.Record{ID: endMarkerID(session.ID), Data: []byte(`{"kind":"something this build does not know"}`), CreatedAt: now, UpdatedAt: now}))
		f.round(f.process())
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations())
		_, markers := f.records()
		assert.Zero(t, markers)
	})

	// A marker is removed as it was read. Between one process reading it and
	// removing it, another adds a token to it. The changed marker stays, and
	// its token is not lost: the next round puts it into the record.
	t.Run("AMarkerThatChangedWhileItWasAppliedIsNotRemoved", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		require.True(t, f.manager.mark(ctx, session.ID, decision{reason: "signed out", revoke: true, expires: session.ExpiresAt}))
		late, err := f.enc.Encrypt("a-token-added-to-the-marker-meanwhile")
		require.NoError(t, err)

		applying := f.process()
		interposed := &failingCollection{Collection: f.col}
		applying.col = interposed
		interposed.swapped = func() error {
			// Right after the end is written into the record, and before the
			// marker is removed, another process adds a token to the marker.
			interposed.swapped = nil
			require.True(t, f.manager.mark(ctx, session.ID, decision{
				reason: "refused", ifToken: "x", owe: []Owed{f.manager.newOwed(late, ClientAuthHeader)},
			}))
			return nil
		}
		f.provider.failRevocations(errProviderDown)
		f.round(applying)
		require.NotNil(t, f.stored(session).EndedAt)
		_, markers := f.records()
		require.Equal(t, 1, markers, "the marker another process changed is not the one that was applied")

		f.provider.failRevocations(nil)
		f.clock.Advance(maxOwedBackoff)
		f.round(applying)
		f.round(applying)
		assert.ElementsMatch(t, []string{"refresh-token-0", "a-token-added-to-the-marker-meanwhile"}, f.provider.revocations())
		_, markers = f.records()
		assert.Zero(t, markers)
	})

	// Two decisions about single tokens: the one a process brings is about a
	// token the record no longer holds, and the one marked beside the record
	// is about the token it does hold. The marked one is applied. The marker
	// is not removed with nothing done about it.
	t.Run("TheMarkedDecisionIsAppliedWhenItIsTheOneThatApplies", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		holds := f.stored(session).RefreshToken
		require.True(t, f.manager.mark(ctx, session.ID, decision{reason: "refused by the identity provider: invalid_grant", ifToken: holds, expires: session.ExpiresAt}))

		other := f.process()
		require.ErrorIs(t, other.conclude(ctx, session.ID, decision{reason: "something older", ifToken: "a-token-the-record-does-not-hold"}), ErrSessionEnded)
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, "refused by the identity provider: invalid_grant", stored.EndReason)
		_, markers := f.records()
		assert.Zero(t, markers)
	})

	// A marker about a refresh token the record no longer holds is about a
	// session another process has renewed since. It is removed, not applied.
	t.Run("OneThatNoLongerAppliesIsRemoved", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		require.True(t, f.manager.mark(ctx, session.ID, decision{reason: "refused", ifToken: "a-token-the-record-does-not-hold", expires: session.ExpiresAt}))
		f.round(f.process())
		_, markers := f.records()
		assert.Zero(t, markers)
		assert.Nil(t, f.stored(session).EndedAt)
		require.NoError(t, f.check(session))
	})

	// A sign-out is not replaced by a later marker about one token, and the
	// tokens that later decision brings are kept with it.
	t.Run("ASignOutIsNotReplacedByANarrowerOne", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		extra, err := f.enc.Encrypt("a-token-a-late-refresh-brought")
		require.NoError(t, err)
		require.True(t, f.manager.mark(ctx, session.ID, decision{reason: "signed out", revoke: true, expires: session.ExpiresAt}))
		require.True(t, f.manager.mark(ctx, session.ID, decision{
			reason: "refused", ifToken: "some-token", owe: []Owed{f.manager.newOwed(extra, ClientAuthForm)},
		}))
		f.round(f.process())
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, "signed out", stored.EndReason)
		assert.ElementsMatch(t, []string{"refresh-token-0", "a-token-a-late-refresh-brought"}, f.provider.revocations())
	})

	// The session's record cannot be read at all, so its token cannot be
	// revoked by anyone. The end is marked; it is applied if the record
	// becomes readable, and closed, loudly, once the session has long expired.
	t.Run("ARecordThatCannotBeRead", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col, failFor: map[string]error{session.ID: errors.New("bad sector")}}
		f.manager.col = broken

		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt), "the end is in the store, as a marker")
		_, markers := f.records()
		require.Equal(t, 1, markers)
		assert.Empty(t, f.provider.revocations(), "there is no token to revoke: it is in the record that cannot be read")

		f.clock.Advance(24 * time.Hour)
		f.round(f.manager)
		_, markers = f.records()
		require.Equal(t, 1, markers, "the hub token has only just expired")

		f.clock.Advance(purgeAfter + time.Second)
		f.round(f.manager)
		_, markers = f.records()
		assert.Zero(t, markers, "nothing can present the session any more")
	})

	t.Run("ARecordThatBecomesReadableAgain", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col, failFor: map[string]error{session.ID: errors.New("bad sector")}}
		f.manager.col = broken
		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))

		delete(broken.failFor, session.ID)
		f.round(f.process())
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations())
		_, markers := f.records()
		assert.Zero(t, markers)
	})
}

// A refresh that comes back for a session that ended meanwhile brings a token
// that must not outlive the session. It goes into the ended session's record.
func TestATokenThatCameBackForAnEndedSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, nil)
	session := f.signIn()
	started, release := f.provider.hold()
	f.clock.Advance(4 * time.Minute)

	refreshing := make(chan error, 1)
	go func() { refreshing <- f.check(session) }()
	<-started
	f.provider.failRevocations(errProviderDown)
	require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))
	release()
	require.ErrorIs(t, <-refreshing, ErrSessionEnded)

	assert.Equal(t, []string{"refresh-token-0", "refresh-token-1"}, f.owedTokens(),
		"the token the session held and the one the late refresh brought back are both owed, in its record")
	f.provider.failRevocations(nil)
	f.clock.Advance(maxOwedBackoff)
	f.round(f.process())
	assert.ElementsMatch(t, []string{"refresh-token-0", "refresh-token-1"}, f.provider.revocations())
	assert.Empty(t, f.owedTokens())
}

// A refresh comes back granted, with no new token, for a session that ended
// meanwhile on what another process took for a refusal. The token is plainly
// still good at the provider, and is owed.
func TestAGrantWithNoNewTokenForASessionThatEndedAsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, nil)
	session := f.signIn()
	f.provider.set(func(string) (Renewal, error) { return Renewal{}, nil })
	started, release := f.provider.hold()
	f.clock.Advance(4 * time.Minute)

	refreshing := make(chan error, 1)
	go func() { refreshing <- f.check(session) }()
	<-started
	_, err := f.manager.end(ctx, session.ID, decision{reason: "refused by the identity provider: invalid_grant", expires: session.ExpiresAt})
	require.NoError(t, err)
	require.Empty(t, f.stored(session).Owed, "a refused token is erased, not owed")
	release()
	require.ErrorIs(t, <-refreshing, ErrSessionEnded)
	assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations())
	assert.Empty(t, f.owedTokens())
}

// An entry is tried when it is due and not before, and a session with more
// than one stops at the first the provider does not answer.
func TestWhenAnOwedRevocationIsTried(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("NotBeforeItIsDue", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.owing("refresh-token-a")
		attempts := 0
		f.provider.mu.Lock()
		f.provider.onRevoke = func() { attempts++ }
		f.provider.revokeErr = errProviderDown
		f.provider.mu.Unlock()

		f.round(f.manager) // the first attempt; the next is due in a minute
		f.clock.Advance(owedRetryInterval)
		f.round(f.manager) // the second; the next is due in two minutes
		require.Equal(t, 2, attempts)
		require.Equal(t, f.clock.Now().Add(2*owedRetryInterval), f.stored(session).Owed[0].NextAttempt)

		f.clock.Advance(owedRetryInterval + time.Second)
		f.round(f.manager)
		assert.Equal(t, 2, attempts, "the provider may be asked again, and this one is not due")
		f.clock.Advance(owedRetryInterval)
		f.round(f.manager)
		assert.Equal(t, 3, attempts)
	})

	// Of two entries in one record, only the one that is due is tried.
	t.Run("OnlyTheOneThatIsDue", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.owing("refresh-token-a")
		later, err := f.enc.Encrypt("refresh-token-b")
		require.NoError(t, err)
		notYet := f.manager.newOwed(later, ClientAuthHeader)
		notYet.NextAttempt = f.clock.Now().Add(time.Hour)
		require.NoError(t, f.manager.appendOwed(ctx, session.ID, notYet))

		f.round(f.manager)
		assert.Equal(t, []string{"refresh-token-a"}, f.provider.revocations())
		assert.Equal(t, []string{"refresh-token-b"}, f.owedTokens())
		f.clock.Advance(time.Hour)
		f.round(f.manager)
		assert.Equal(t, []string{"refresh-token-a", "refresh-token-b"}, f.provider.revocations())
	})

	// The attempt a caller makes right after recording one is held to the
	// same two rules: only what is due, and no further once the provider has
	// left one unanswered.
	t.Run("TheAttemptRightAfterRecording", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.owing("refresh-token-a")
		later, err := f.enc.Encrypt("refresh-token-b")
		require.NoError(t, err)
		notYet := f.manager.newOwed(later, ClientAuthHeader)
		notYet.NextAttempt = f.clock.Now().Add(time.Hour)
		require.NoError(t, f.manager.appendOwed(ctx, session.ID, notYet))
		f.manager.attemptNow(ctx, session.ID)
		assert.Equal(t, []string{"refresh-token-a"}, f.provider.revocations(), "the one that is not due is not tried")

		two := f.owing("refresh-token-c")
		also, err := f.enc.Encrypt("refresh-token-d")
		require.NoError(t, err)
		require.NoError(t, f.manager.appendOwed(ctx, two.ID, f.manager.newOwed(also, ClientAuthHeader)))
		attempts := 0
		f.provider.mu.Lock()
		f.provider.onRevoke = func() { attempts++ }
		f.provider.revokeErr = errProviderDown
		f.provider.mu.Unlock()
		f.manager.attemptNow(ctx, two.ID)
		assert.Equal(t, 1, attempts, "the provider did not answer the first, and is not asked the second")
		f.manager.attemptNow(ctx, two.ID)
		assert.Equal(t, 1, attempts, "nor again at once")
	})

	t.Run("ASessionWithTwoStopsAtTheFirstUnanswered", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.owing("refresh-token-a")
		second, err := f.enc.Encrypt("refresh-token-b")
		require.NoError(t, err)
		require.NoError(t, f.manager.appendOwed(ctx, session.ID, f.manager.newOwed(second, ClientAuthHeader)))
		attempts := 0
		f.provider.mu.Lock()
		f.provider.onRevoke = func() { attempts++ }
		f.provider.revokeErr = errProviderDown
		f.provider.mu.Unlock()
		f.round(f.manager)
		assert.Equal(t, 1, attempts)
		stored := f.stored(session)
		require.Len(t, stored.Owed, 2)
		assert.Equal(t, 1, stored.Owed[0].Attempts+stored.Owed[1].Attempts, "one of the two was tried, and the round ended there")
	})

	// Two entries in one record. The provider never answers for the first.
	// The second is not left waiting behind it: an entry that was tried is
	// due later than one that was not, so the other goes first next time.
	t.Run("OneThatNeverGetsAnAnswerDoesNotBlockItsNeighbour", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.owing("refresh-token-a")
		second, err := f.enc.Encrypt("refresh-token-b")
		require.NoError(t, err)
		later := f.manager.newOwed(second, ClientAuthHeader)
		later.NextAttempt = later.NextAttempt.Add(time.Second) // due just after the first
		require.NoError(t, f.manager.appendOwed(ctx, session.ID, later))
		f.provider.mu.Lock()
		f.provider.revokeErrFor = map[string]error{"refresh-token-a": errProviderDown}
		f.provider.mu.Unlock()

		f.clock.Advance(time.Second)
		f.round(f.manager) // the first is tried, gets no answer, and the round ends
		require.Empty(t, f.provider.revocations())
		f.clock.Advance(owedRetryInterval)
		f.round(f.manager)
		assert.Equal(t, []string{"refresh-token-b"}, f.provider.revocations(), "the second came due before the first is due again")
	})
}

// A token is owed once. A sign-out makes the session's token owed; a refresh
// that then comes back granted, with no new token, shows the same token to be
// good, and does not record it a second time.
func TestATokenIsOwedOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, nil)
	session := f.signIn()
	f.provider.set(func(string) (Renewal, error) { return Renewal{}, nil })
	started, release := f.provider.hold()
	f.clock.Advance(4 * time.Minute)

	refreshing := make(chan error, 1)
	go func() { refreshing <- f.check(session) }()
	<-started
	f.provider.failRevocations(errProviderDown)
	require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))
	release()
	require.ErrorIs(t, <-refreshing, ErrSessionEnded)
	assert.Len(t, f.stored(session).Owed, 1)
	assert.Equal(t, []string{"refresh-token-0"}, f.owedTokens())
}

// An expired session is ended, so that its refresh token is revoked, whether
// or not its record owes something already; and what a round forgets or
// removes, it forgets or removes as it is, not as it was when it looked.
func TestWhatARoundDoesNotLose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A live session can owe a token: a late refresh's, when another process
	// had renewed the session. The provider never answers for that one. The
	// session then expires. Its own refresh token still becomes owed.
	t.Run("AnExpiredSessionThatAlreadyOwesSomething", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session, err := f.manager.Create(ctx, alice, "the-sessions-own-token", f.clock.Now().Add(time.Hour))
		require.NoError(t, err)
		stale, err := f.enc.Encrypt("a-token-from-a-late-refresh")
		require.NoError(t, err)
		require.NoError(t, f.manager.appendOwed(ctx, session.ID, f.manager.newOwed(stale, ClientAuthHeader)))
		f.provider.mu.Lock()
		f.provider.revokeErrFor = map[string]error{"a-token-from-a-late-refresh": errProviderDown}
		f.provider.mu.Unlock()

		f.clock.Advance(time.Hour + maxClockSkew)
		f.round(f.manager)
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, "the hub token expired", stored.EndReason)
		f.clock.Advance(maxOwedBackoff)
		f.round(f.manager)
		assert.Contains(t, f.provider.revocations(), "the-sessions-own-token")
		assert.Equal(t, []string{"a-token-from-a-late-refresh"}, f.owedTokens())
	})

	// The expiry was written by another clock, which may be ahead of the hub
	// process that reads it. A session is not ended as expired before that
	// allowance has passed.
	t.Run("ASessionIsNotEndedAsExpiredEarly", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session, err := f.manager.Create(ctx, alice, "refresh-token-a", f.clock.Now().Add(time.Hour))
		require.NoError(t, err)
		f.clock.Advance(time.Hour + maxClockSkew - time.Second)
		f.round(f.manager)
		require.Nil(t, f.stored(session).EndedAt)
		f.clock.Advance(time.Second)
		f.round(f.manager)
		require.NotNil(t, f.stored(session).EndedAt)
	})

	// A remembered end has expired and is about to be forgotten. Between the
	// round looking at it and forgetting it, a request adds a token to it.
	// It is not forgotten with that token.
	t.Run("ARememberedEndThatChangedWhileTheRoundLooked", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		first, err := f.enc.Encrypt("a-token-it-held-when-the-round-looked")
		require.NoError(t, err)
		added, err := f.enc.Encrypt("a-token-added-while-the-round-looked")
		require.NoError(t, err)
		f.manager.remember(session.ID, decision{
			reason: "signed out", revoke: true, expires: f.clock.Now().Add(-time.Minute),
			owe: []Owed{f.manager.newOwed(first, ClientAuthHeader)},
		})
		interposed := &failingCollection{Collection: f.col}
		f.manager.col = interposed
		interposed.create = nil
		created := false
		interposed.onCreate = func() {
			// The round is writing the record for the first token. A request
			// adds the second one to what is remembered.
			if !created {
				created = true
				f.manager.remember(session.ID, decision{reason: "signed out", revoke: true, owe: []Owed{f.manager.newOwed(added, ClientAuthHeader)}})
			}
		}
		f.provider.failRevocations(errProviderDown)
		f.round(f.manager)
		d, remembered := f.manager.decided(session.ID)
		require.True(t, remembered, "it changed, so it is not the one the round looked at")
		assert.Len(t, d.owe, 2)

		f.provider.failRevocations(nil)
		f.clock.Advance(maxOwedBackoff)
		f.round(f.manager)
		f.round(f.manager)
		assert.Subset(t, f.provider.revocations(), []string{"a-token-it-held-when-the-round-looked", "a-token-added-while-the-round-looked"})
	})

	// A process remembers a sign-out the store did not take. The session has
	// meanwhile been ended in its record by another process, and this one is
	// about to clear what it remembers. Between reading it and clearing it, a
	// request adds a token to it. It is not cleared with that token.
	t.Run("WhatIsRememberedChangedWhileItWasBeingCleared", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		f.manager.remember(session.ID, decision{reason: "signed out", revoke: true, expires: session.ExpiresAt})
		other := f.process()
		require.NoError(t, other.End(ctx, session.ID, "signed out", session.ExpiresAt))
		added, err := f.enc.Encrypt("a-token-added-while-it-was-being-cleared")
		require.NoError(t, err)

		interposed := &failingCollection{Collection: f.col}
		f.manager.col = interposed
		reads := 0
		interposed.read = func() {
			reads++
			// The first read looks for a marker; what is remembered is read
			// next; the second read is of the session's record.
			if reads == 2 {
				f.manager.remember(session.ID, decision{reason: "signed out", revoke: true, owe: []Owed{f.manager.newOwed(added, ClientAuthHeader)}})
			}
		}
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		d, remembered := f.manager.decided(session.ID)
		require.True(t, remembered, "what was added since is not what was read")
		require.Len(t, d.owe, 1)

		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		_, remembered = f.manager.decided(session.ID)
		assert.False(t, remembered)
		assert.Contains(t, f.provider.revocations(), "a-token-added-while-it-was-being-cleared")
	})

	// The same for a remembered decision about one refresh token that turns
	// out not to apply any more and is being dropped.
	t.Run("ADecisionAboutATokenChangedWhileItWasBeingDropped", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		stale := decision{reason: "refused", ifToken: "a-token-the-record-no-longer-holds", expires: session.ExpiresAt}
		f.manager.remember(session.ID, stale)
		added, err := f.enc.Encrypt("a-token-added-while-it-was-being-dropped")
		require.NoError(t, err)

		interposed := &failingCollection{Collection: f.col}
		f.manager.col = interposed
		reads := 0
		interposed.read = func() {
			reads++
			if reads == 2 {
				withToken := stale
				withToken.owe = []Owed{f.manager.newOwed(added, ClientAuthHeader)}
				f.manager.remember(session.ID, withToken)
			}
		}
		require.NoError(t, f.check(session), "the decision does not apply: the session was renewed since")
		// The version that was read is dropped. The one remembered since is
		// met by the look the request takes before it is answered, and its
		// token goes into the session's record.
		assert.Contains(t, f.provider.revocations(), "a-token-added-while-it-was-being-dropped")
		_, remembered := f.manager.decided(session.ID)
		assert.False(t, remembered)
		assert.Nil(t, f.stored(session).EndedAt, "and the session, which the decision was not about, goes on")
	})

	// A marker for a record that cannot be read is being closed, and its
	// tokens moved into a record of their own. Another process adds a token to
	// the marker between the round's listing and the closing. The marker that
	// is removed is the one whose tokens were moved, with the new one in it.
	t.Run("AMarkerThatChangedAfterTheListingIsClosedAsItIsNow", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col, failFor: map[string]error{session.ID: errors.New("bad sector")}}
		f.manager.col = broken
		first, err := f.enc.Encrypt("a-token-the-listing-saw")
		require.NoError(t, err)
		added, err := f.enc.Encrypt("a-token-added-after-the-listing")
		require.NoError(t, err)
		require.True(t, f.manager.mark(ctx, session.ID, decision{
			reason: "signed out", revoke: true, expires: f.clock.Now().Add(time.Hour),
			owe: []Owed{f.manager.newOwed(first, ClientAuthHeader)},
		}))
		f.clock.Advance(time.Hour + purgeAfter + time.Second)

		other := f.process()
		listed := false
		broken.read = func() {
			// The first read of the round is of this marker, after the
			// listing. Another process adds a token to it then.
			if !listed {
				listed = true
				require.True(t, other.mark(ctx, session.ID, decision{reason: "refused", ifToken: "x", owe: []Owed{other.newOwed(added, ClientAuthHeader)}}))
			}
		}
		f.round(f.manager)
		_, markers := f.records()
		require.Zero(t, markers)
		assert.Equal(t, []string{"a-token-added-after-the-listing", "a-token-the-listing-saw"}, f.owedTokens(), "both are in a record of their own")
	})
}

// Rounds are started at most once a minute on a hub process, by sign-ins as
// by requests: a burst of sign-ins does not start a burst of rounds.
func TestSignInsDoNotStartABurstOfRounds(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	started := 0
	f.manager.spawn = func(func()) { started++ }
	for range 10 {
		f.signIn()
	}
	assert.Equal(t, 1, started)
	f.clock.Advance(reconcileInterval)
	f.signIn()
	assert.Equal(t, 2, started)
}

// Nothing of a refresh token is in the clear in a record that owes one, or in
// a marker.
func TestWhatIsOwedIsStoredEncrypted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, nil)
	marked := f.signIn()
	f.owing("refresh-token-secret-a")
	extra, err := f.enc.Encrypt("refresh-token-secret-b")
	require.NoError(t, err)
	require.True(t, f.manager.mark(ctx, marked.ID, decision{reason: "signed out", revoke: true, owe: []Owed{f.manager.newOwed(extra, ClientAuthHeader)}}))

	page, err := f.col.List(ctx, persis.ListQuery{})
	require.NoError(t, err)
	require.Len(t, page.Records, 3)
	for _, rec := range page.Records {
		assert.NotContains(t, string(rec.Data), "refresh-token-secret", rec.ID)
		assert.NotContains(t, string(rec.Data), "refresh-token-0", rec.ID)
	}
}

// While the store takes no write at all, nothing can be made to last. The
// process that decided an end then refuses the session from what it
// remembers, and that memory has rules of its own.
func TestWhatAProcessRemembersWhileTheStoreTakesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// deaf makes the store take no write of any kind from a hub process.
	deaf := func(f *fixture) (broken *failingCollection, heal func()) {
		broken = &failingCollection{Collection: f.col, create: errors.New("disk full")}
		f.manager.col = broken
		healWrites := broken.failWritesAfter(0)
		return broken, func() { healWrites(); broken.create = nil }
	}

	// A sign-out is not dropped because an older decision, about a refresh
	// token the record no longer holds, turns out not to apply.
	t.Run("ASignOutOutlivesAnOlderDecisionAboutAToken", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		_, heal := deaf(f)
		require.Error(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))

		older := decision{reason: "refused", ifToken: "a-token-the-record-no-longer-holds"}
		require.ErrorIs(t, f.manager.conclude(ctx, session.ID, older), ErrSessionEnded)
		_, remembered := f.manager.decided(session.ID)
		require.True(t, remembered)

		heal()
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		assert.Equal(t, "signed out", f.stored(session).EndReason, "the sign-out is what is applied")
	})

	// The sign-out is decided while that older decision is being looked at.
	t.Run("ASignOutDecidedWhileAnOlderDecisionIsDropped", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col}
		f.manager.col = broken
		reads := 0
		broken.read = func() {
			reads++
			// The first read looks for a marker, the second reads the session.
			// The sign-out is decided between that and the dropping.
			if reads == 2 {
				f.manager.remember(session.ID, decision{reason: "signed out", revoke: true})
			}
		}
		require.NoError(t, f.manager.conclude(ctx, session.ID, decision{reason: "refused", ifToken: "a-token-the-record-no-longer-holds"}))
		_, remembered := f.manager.decided(session.ID)
		require.True(t, remembered, "the sign-out is still remembered")
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		assert.Equal(t, "signed out", f.stored(session).EndReason)
	})

	// A sign-out is decided at the very moment a refresh is storing its
	// renewal. The renewal goes in, and the request is refused all the same:
	// the session is ended, and the renewed token is owed and revoked.
	t.Run("ASignOutDecidedWhileARenewalIsBeingStored", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col}
		f.manager.col = broken
		writes := 0
		broken.swap = func() error {
			writes++
			if writes == 2 { // the first write is the claim, the second the renewal
				f.manager.remember(session.ID, decision{reason: "signed out", revoke: true})
			}
			return nil
		}
		f.clock.Advance(4 * time.Minute)
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, "signed out", stored.EndReason)
		assert.Equal(t, []string{"refresh-token-1"}, f.provider.revocations())
		assert.Empty(t, f.owedTokens())
	})

	// A refresh was at the provider when the sign-out came, and the record did
	// not take the sign-out. The refresh must not write its renewal over it,
	// and the token it brought back must not be left alive.
	t.Run("ARefreshThatComesBackAfterASignOutTheRecordDidNotTake", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col}
		f.manager.col = broken
		broken.failWrite(2) // the first write is the claim, the second the sign-out
		started, release := f.provider.hold()
		f.clock.Advance(4 * time.Minute)

		refreshing := make(chan error, 1)
		go func() { refreshing <- f.check(session) }()
		<-started
		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt), "marked beside the record")
		release()
		require.ErrorIs(t, <-refreshing, ErrSessionEnded)
		assert.Contains(t, f.provider.revocations(), "refresh-token-1", "the token the refresh brought back")

		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, "signed out", stored.EndReason)
		assert.Empty(t, f.owedTokens())
		assert.Subset(t, f.provider.revocations(), []string{"refresh-token-0", "refresh-token-1"})
		_, markers := f.records()
		assert.Zero(t, markers)
	})

	// What is remembered is written when the store takes writes again, by any
	// round, without a request for that session.
	t.Run("ItIsWrittenWhenTheStoreTakesWritesAgain", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		_, heal := deaf(f)
		require.Error(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))
		f.round(f.manager)
		require.Nil(t, f.stored(session).EndedAt, "the store still takes nothing")

		heal()
		f.round(f.manager)
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, "signed out", stored.EndReason)
		_, remembered := f.manager.decided(session.ID)
		assert.False(t, remembered)
		assert.Empty(t, f.owedTokens(), "and its token is revoked in the same round")
	})

	// It is forgotten when the session's hub token has expired: nothing can
	// present the session any more. That holds when the session could not
	// even be read, because the caller gave the expiry.
	t.Run("ItIsForgottenWhenTheHubTokenHasExpired", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken, _ := deaf(f)
		broken.fail = errors.New("disk unavailable")
		require.Error(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))
		d, remembered := f.manager.decided(session.ID)
		require.True(t, remembered)
		assert.Equal(t, session.ExpiresAt, d.expires)

		f.clock.Advance(24*time.Hour - time.Second)
		f.round(f.manager)
		_, remembered = f.manager.decided(session.ID)
		require.True(t, remembered)
		f.clock.Advance(time.Second)
		f.round(f.manager)
		_, remembered = f.manager.decided(session.ID)
		assert.False(t, remembered)
	})

	// A remembered end that brings a token of its own, one that is in no
	// record, is not forgotten with the token: the token gets a record first.
	t.Run("ATokenItBringsIsNotForgottenWithIt", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		brought, err := f.enc.Encrypt("a-token-only-this-process-knows-of")
		require.NoError(t, err)
		f.manager.remember(session.ID, decision{
			reason: "the renewed session could not be stored", ifToken: "x", expires: session.ExpiresAt,
			owe: []Owed{f.manager.newOwed(brought, ClientAuthForm)},
		})
		broken, heal := deaf(f)
		_ = broken

		f.clock.Advance(25 * time.Hour)
		f.round(f.manager)
		_, remembered := f.manager.decided(session.ID)
		require.True(t, remembered, "the store takes nothing, so the token has no record yet")

		heal()
		f.round(f.manager)
		_, remembered = f.manager.decided(session.ID)
		assert.False(t, remembered)
		assert.Contains(t, f.provider.revocations(), "a-token-only-this-process-knows-of")
	})

	// A restart in this state loses what was remembered. That is the limit:
	// nothing can be made to last in a store that takes no write.
	t.Run("ARestartLosesIt", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		deaf(f)
		require.Error(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt), "and the caller is told so")
		restarted := f.process()
		assert.NoError(t, restarted.Check(ctx, session.ID, alice),
			"the restarted process goes by the store, which never took the end; the provider was asked to revoke the token, which is what stops it at the next refresh")
		assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations())
	})
}

// A round reads the whole collection and may wait for the provider. It runs
// beside the request that started it, and the request is answered on what is
// true when it is answered.
func TestARoundRunsBesideTheRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// The provider is slow to answer a revocation. The request that started
	// the round does not wait for it.
	t.Run("TheRequestDoesNotWaitForIt", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		f.owing("refresh-token-a")
		beside, err := NewManager(Config{RevalidateAfter: 4 * time.Minute, RevalidateLimit: 5 * time.Minute, Now: f.clock.Now},
			f.col, f.enc, f.provider, nil) // as a hub runs it: rounds in their own goroutine
		require.NoError(t, err)
		reached, release := make(chan struct{}), make(chan struct{})
		f.provider.mu.Lock()
		f.provider.onRevoke = func() {
			f.provider.mu.Unlock()
			close(reached)
			<-release
			f.provider.mu.Lock()
		}
		f.provider.mu.Unlock()

		require.NoError(t, beside.Check(ctx, session.ID, alice), "answered while the round is still at the provider")
		<-reached
		require.Equal(t, []string{"refresh-token-a"}, f.owedTokens())
		close(release)
		require.Eventually(t, func() bool { return !beside.reconciling.Load() && len(f.owedTokens()) == 0 }, 10*time.Second, 5*time.Millisecond)
	})

	// The decision is made after the round is started, not before it. Here
	// the round is made to run first and to take two seconds, across the
	// session's limit: the request is not served on an answer from before.
	t.Run("TheAnswerIsNotFromBeforeTheRound", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		f.owing("refresh-token-a")
		f.provider.set(unavailable)
		f.provider.mu.Lock()
		f.provider.onRevoke = func() { f.clock.Advance(2 * time.Second) }
		f.provider.mu.Unlock()

		f.clock.Advance(4*time.Minute + 59*time.Second)
		require.ErrorIs(t, f.check(session), ErrProviderUnavailable, "five minutes and one second after the last confirmation")
	})

	// Many requests at the moment a round is due start one round, not many.
	t.Run("OneRoundIsStarted", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		started := 0
		f.manager.spawn = func(func()) { started++ }
		f.clock.Advance(reconcileInterval)
		for range 20 {
			require.NoError(t, f.check(session))
		}
		assert.Equal(t, 1, started)
		f.clock.Advance(reconcileInterval)
		require.NoError(t, f.check(session))
		assert.Equal(t, 2, started)
	})
}

// A session whose end was marked, and whose process stopped before it asked
// the provider, is found a long time later, after the hub token has expired.
// Its record is not removed with its token unrevoked.
func TestAMarkedEndFoundLongAfterwards(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("TheSessionWasNeverEndedInItsRecord", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col}
		f.manager.col = broken
		broken.failWritesAfter(0)
		f.provider.failRevocations(errProviderDown)
		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt), "marked")
		require.Empty(t, f.provider.revocations())
		f.provider.failRevocations(nil)

		f.clock.Advance(3 * 24 * time.Hour)
		restarted := f.process()
		f.round(restarted)
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt, "the record is ended, not removed")
		assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations())
		assert.Empty(t, stored.Owed)
		require.Len(t, stored.Revocations, 1)
		_, markers := f.records()
		assert.Zero(t, markers)
	})

	// The record ended long ago, and a marker beside it still carries a token
	// that is in no record. The record is not removed before the token is in
	// it.
	t.Run("AMarkerStillCarriesAToken", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		require.NoError(t, f.manager.End(ctx, session.ID, "signed out", session.ExpiresAt))
		carried, err := f.enc.Encrypt("a-token-the-marker-carries")
		require.NoError(t, err)
		f.clock.Advance(3 * 24 * time.Hour)
		require.True(t, f.manager.mark(ctx, session.ID, decision{
			reason: "the renewed session could not be stored", ifToken: "x", owe: []Owed{f.manager.newOwed(carried, ClientAuthHeader)},
		}))

		f.round(f.process())
		assert.Contains(t, f.provider.revocations(), "a-token-the-marker-carries")
		_, markers := f.records()
		assert.Zero(t, markers)
	})
}

// A refresh comes back granted with no new token for a session that ended as
// refused, and the record cannot be written. The token is not left good at
// the provider without a word: the provider is asked directly.
func TestAGrantWithNoNewTokenThatCannotBeRecorded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, nil)
	session := f.signIn()
	f.provider.set(func(string) (Renewal, error) { return Renewal{}, nil })
	started, release := f.provider.hold()
	f.clock.Advance(4 * time.Minute)

	refreshing := make(chan error, 1)
	go func() { refreshing <- f.check(session) }()
	<-started
	_, err := f.manager.end(ctx, session.ID, decision{reason: "refused by the identity provider: invalid_grant", expires: session.ExpiresAt})
	require.NoError(t, err)
	broken := &failingCollection{Collection: f.col}
	f.manager.col = broken
	broken.failWritesAfter(0)
	release()
	require.ErrorIs(t, <-refreshing, ErrSessionEnded)
	assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations(), "it could not be recorded, so the provider was asked there and then")
}
