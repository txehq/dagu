// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package oidcsession

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Two hub processes share the store. One is asking the provider; the other
// does not ask as well. Inside the limit it serves, past the limit it says
// the session cannot be confirmed now, and it never ends the session.
func TestTwoHubProcessesAskTheProviderOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, nil)
	session := f.signIn()
	f.provider.set(f.provider.once("refresh-token-0"))
	other := f.process()
	started, release := f.provider.hold()
	f.clock.Advance(4*time.Minute + 50*time.Second)

	first := make(chan error, 1)
	go func() { first <- f.check(session) }()
	<-started

	require.NoError(t, other.Check(ctx, session.ID, alice), "inside the limit the other process serves")
	assert.Equal(t, 1, f.provider.calls(), "and does not present the same refresh token")

	f.clock.Advance(15 * time.Second)
	require.ErrorIs(t, other.Check(ctx, session.ID, alice), ErrProviderUnavailable, "past the limit it does not serve")
	assert.Equal(t, 1, f.provider.calls())
	assert.Nil(t, f.stored(session).EndedAt)

	release()
	require.NoError(t, <-first)
	require.NoError(t, other.Check(ctx, session.ID, alice), "the first process's answer is the other's too")
	assert.Equal(t, 1, f.provider.calls())
	assert.Equal(t, "refresh-token-1", f.heldToken(session))
	assert.Empty(t, f.stored(session).RefreshOwner, "the claim is given up with the answer")
}

// A process that holds a claim and never answers, because it died or its call
// hangs, does not hold the session for good: the claim runs out and another
// process takes over. Whatever the first process then learns about the token
// it sent says nothing about the session the other one renewed.
func TestAClaimThatRanOutIsTakenOver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("TheLateAnswerIsARefusal", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		f.provider.set(f.provider.once("refresh-token-0"))
		other := f.process()
		started, release := f.provider.hold()
		f.clock.Advance(4 * time.Minute)

		first := make(chan error, 1)
		go func() { first <- f.check(session) }()
		<-started
		f.provider.free()

		require.NoError(t, other.Check(ctx, session.ID, alice), "the claim still holds, and the session is inside its limit")
		assert.Equal(t, 1, f.provider.calls())

		f.clock.Advance(refreshClaim)
		require.NoError(t, other.Check(ctx, session.ID, alice))
		assert.Equal(t, 2, f.provider.calls(), "the claim ran out, so the other process asked")
		assert.Equal(t, "refresh-token-1", f.heldToken(session))

		// The first process's call comes back now. The provider accepts each
		// token once, and the other process has used this one: a refusal.
		release()
		require.NoError(t, <-first, "a refusal of a token the session no longer holds does not end it")
		stored := f.stored(session)
		assert.Nil(t, stored.EndedAt)
		assert.Equal(t, "refresh-token-1", f.heldToken(session))
		assert.Empty(t, f.provider.revocations())
	})

	t.Run("TheLateAnswerIsAGrant", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		other := f.process()
		started, release := f.provider.hold()
		f.clock.Advance(4 * time.Minute)

		first := make(chan error, 1)
		go func() { first <- f.check(session) }()
		<-started
		f.provider.free()
		f.clock.Advance(refreshClaim)
		require.NoError(t, other.Check(ctx, session.ID, alice))
		require.Equal(t, "refresh-token-1", f.heldToken(session))

		release()
		require.NoError(t, <-first)
		assert.Equal(t, "refresh-token-1", f.heldToken(session), "what the other process stored stands")
		assert.Nil(t, f.stored(session).EndedAt)
		assert.Empty(t, f.provider.revocations(),
			"the late token is dropped, not revoked: at a provider that ties a session's tokens together that would end the one in use")
	})

	// The other process took the claim over and is itself still waiting for
	// the provider when the first one's grant arrives. The record still holds
	// the token the first one exchanged, so its new token goes in. The other
	// process is then refused the old token, which no longer is the session's.
	t.Run("TheLateGrantArrivesWhileTheOtherProcessIsAsking", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		f.provider.set(f.provider.once("refresh-token-0"))
		other := f.process()
		firstStarted, releaseFirst := f.provider.hold()
		f.clock.Advance(4 * time.Minute)

		first := make(chan error, 1)
		go func() { first <- f.check(session) }()
		<-firstStarted

		secondStarted, releaseSecond := f.provider.hold()
		f.clock.Advance(refreshClaim)
		second := make(chan error, 1)
		go func() { second <- other.Check(ctx, session.ID, alice) }()
		<-secondStarted

		releaseFirst()
		require.NoError(t, <-first)
		require.Equal(t, "refresh-token-1", f.heldToken(session))

		releaseSecond()
		require.NoError(t, <-second)
		assert.Nil(t, f.stored(session).EndedAt)
		assert.Equal(t, "refresh-token-1", f.heldToken(session))
		assert.Equal(t, []string{"refresh-token-0", "refresh-token-0"}, f.provider.presented())
	})
}

// Sign-out revokes the refresh token the session holds when it is ended, not
// one it held earlier.
func TestSignOutRevokesTheTokenTheSessionHolds(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	f.clock.Advance(4 * time.Minute)
	require.NoError(t, f.check(session))
	require.Equal(t, "refresh-token-1", f.heldToken(session))

	require.NoError(t, f.manager.End(context.Background(), session.ID, "signed out"))
	assert.Equal(t, []string{"refresh-token-1"}, f.provider.revocations())
}

// A sign-out the store did not take is still a sign-out: this process refuses
// the session, a refresh that was at the provider does not revive it, and the
// end is written and the tokens revoked once the store takes writes again.
func TestASignOutTheStoreDidNotTake(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("Idle", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col}
		f.manager.col = broken
		heal := broken.failWritesAfter(0)

		require.Error(t, f.manager.End(ctx, session.ID, "signed out"))
		require.Nil(t, f.stored(session).EndedAt, "the store still has the session open")
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations(), "the token is revoked without waiting for the store")

		heal()
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, "signed out", stored.EndReason)
		assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations(), "and not a second time")
	})

	// Another hub process does not know what this one decided. It goes by
	// the store, so it serves the session until it next asks the provider,
	// which refuses the token the sign-out revoked. It never serves it past
	// the limit.
	t.Run("AnotherProcessGoesByTheStoreUntilTheProviderRefuses", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		other := f.process()
		broken := &failingCollection{Collection: f.col}
		f.manager.col = broken
		broken.failWritesAfter(0)
		f.provider.set(func(token string) (Renewal, error) {
			if slices.Contains(f.provider.revocations(), token) {
				return Renewal{}, &RefusedError{Status: 400, Code: "invalid_grant"}
			}
			return Renewal{RefreshToken: "refresh-token-new"}, nil
		})

		require.Error(t, f.manager.End(ctx, session.ID, "signed out"))
		require.ErrorIs(t, f.check(session), ErrSessionEnded, "the process that took the sign-out refuses at once")
		require.NoError(t, other.Check(ctx, session.ID, alice), "the other goes by the store")

		f.clock.Advance(4 * time.Minute)
		require.ErrorIs(t, other.Check(ctx, session.ID, alice), ErrSessionEnded, "until the provider refuses the revoked token")
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, "refused by the identity provider: invalid_grant", stored.EndReason)
	})

	t.Run("DuringARefresh", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col}
		f.manager.col = broken
		heal := broken.failWritesAfter(1) // the claim
		started, release := f.provider.hold()
		f.clock.Advance(4 * time.Minute)

		refreshing := make(chan error, 1)
		go func() { refreshing <- f.check(session) }()
		<-started
		require.Error(t, f.manager.End(ctx, session.ID, "signed out"))
		release()
		require.ErrorIs(t, <-refreshing, ErrSessionEnded)
		assert.ElementsMatch(t, []string{"refresh-token-0", "refresh-token-1"}, f.provider.revocations(),
			"the token the session held and the one the refresh brought back")
		assert.Equal(t, "refresh-token-0", f.heldToken(session), "which was not stored")

		heal()
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		require.NotNil(t, f.stored(session).EndedAt)
		assert.ElementsMatch(t, []string{"refresh-token-1", "refresh-token-0"}, f.provider.revocations())
	})

	// Only the sign-out's own write failed. The refresh that was at the
	// provider comes back to a store that would take its renewal, and must
	// not write it over a sign-out this process has decided.
	t.Run("DuringARefreshWhoseWriteWouldSucceed", func(t *testing.T) {
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
		require.Error(t, f.manager.End(ctx, session.ID, "signed out"))
		release()
		require.ErrorIs(t, <-refreshing, ErrSessionEnded)
		assert.Equal(t, "refresh-token-0", f.heldToken(session), "the renewal was not stored")
		assert.ElementsMatch(t, []string{"refresh-token-0", "refresh-token-1"}, f.provider.revocations())

		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, "signed out", stored.EndReason)
		assert.ElementsMatch(t, []string{"refresh-token-1", "refresh-token-0"}, f.provider.revocations())
	})
}

// A process whose provider call got nothing gives its claim up, so that
// another process can ask without waiting for the claim to run out.
func TestAClaimIsGivenUpAfterAnOutage(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	other := f.process()
	f.provider.set(unavailable)
	f.clock.Advance(4 * time.Minute)
	require.NoError(t, f.check(session))
	stored := f.stored(session)
	assert.Empty(t, stored.RefreshOwner)
	assert.Nil(t, stored.RefreshUntil)

	f.provider.set(f.provider.rotate())
	require.NoError(t, other.Check(context.Background(), session.ID, alice))
	assert.Equal(t, 2, f.provider.calls(), "the other process asked at once")
	assert.Equal(t, "refresh-token-1", f.heldToken(session))
}

// A renewed ID token that cannot be verified, because the provider's signing
// keys cannot be fetched, is neither a confirmation nor a refusal. The
// session is not ended, it is not served past its limit, and the new refresh
// token is kept so that the next attempt can be made.
func TestAnIDTokenThatCannotBeVerifiedIsNotAnAnswer(t *testing.T) {
	t.Parallel()

	withIDToken := func(p *fakeProvider) func(string) (Renewal, error) {
		rotate := p.rotate()
		return func(token string) (Renewal, error) {
			renewal, err := rotate(token)
			renewal.IDToken = "a-renewed-id-token"
			return renewal, err
		}
	}

	t.Run("ForThisIdentity", func(t *testing.T) {
		t.Parallel()
		var mu sync.Mutex
		keysDown := true
		f := newFixture(t, func(context.Context, string) (string, string, error) {
			mu.Lock()
			defer mu.Unlock()
			if keysDown {
				return testIssuer, testSubject, ErrIDTokenUnverifiable
			}
			return testIssuer, testSubject, nil
		})
		session := f.signIn()
		f.provider.set(withIDToken(f.provider))
		confirmed := f.stored(session).LastConfirmedAt

		f.clock.Advance(4 * time.Minute)
		require.NoError(t, f.check(session), "inside the limit")
		stored := f.stored(session)
		assert.Nil(t, stored.EndedAt)
		assert.Equal(t, confirmed, stored.LastConfirmedAt, "not confirmed")
		assert.Equal(t, "refresh-token-1", f.heldToken(session), "the new refresh token is kept")

		f.clock.Advance(time.Minute)
		require.ErrorIs(t, f.check(session), ErrProviderUnavailable, "past the limit, not served and not signed out")
		assert.Nil(t, f.stored(session).EndedAt)

		mu.Lock()
		keysDown = false
		mu.Unlock()
		f.clock.Advance(defaultRetryInterval)
		require.NoError(t, f.check(session))
		assert.Equal(t, []string{"refresh-token-0", "refresh-token-1", "refresh-token-2"}, f.provider.presented())
		assert.Empty(t, f.provider.revocations())
	})

	t.Run("ForSomeoneElse", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, func(context.Context, string) (string, string, error) {
			return testIssuer, "someone-else", ErrIDTokenUnverifiable
		})
		session := f.signIn()
		f.provider.set(withIDToken(f.provider))
		f.clock.Advance(4 * time.Minute)
		require.ErrorIs(t, f.check(session), ErrSessionEnded, "a token that names another identity ends the session, verified or not")
		assert.NotNil(t, f.stored(session).EndedAt)
	})
}

// The provider granted a refresh and the store did not take the result.
func TestAGrantedRefreshThatCannotBeStored(t *testing.T) {
	t.Parallel()

	// With a new refresh token, the stored one has been used up. Sending it
	// again would be a replay, so the session ends: it is refused here at
	// once, the new token is revoked, and the end is written when the store
	// takes writes again.
	t.Run("TheProviderRotated", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		broken := &failingCollection{Collection: f.col}
		f.manager.col = broken
		heal := broken.failWritesAfter(1) // the claim

		f.clock.Advance(4 * time.Minute)
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		assert.Equal(t, []string{"refresh-token-1"}, f.provider.revocations())
		require.Nil(t, f.stored(session).EndedAt, "the store still has the session open")

		f.clock.Advance(defaultRetryInterval)
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		assert.Equal(t, []string{"refresh-token-0"}, f.provider.presented(), "the used token is not presented again")

		heal()
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		stored := f.stored(session)
		require.NotNil(t, stored.EndedAt)
		assert.Equal(t, "the renewed session could not be stored", stored.EndReason)
		assert.Empty(t, stored.RefreshToken)
	})

	// With no new refresh token nothing is lost. The request is not served on
	// a confirmation that was not recorded, and the next one asks again.
	t.Run("TheProviderDidNotRotate", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		f.provider.set(func(string) (Renewal, error) { return Renewal{}, nil })
		broken := &failingCollection{Collection: f.col}
		f.manager.col = broken
		heal := broken.failWritesAfter(1)

		f.clock.Advance(4 * time.Minute)
		err := f.check(session)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrSessionEnded)
		require.NotErrorIs(t, err, ErrProviderUnavailable)
		assert.Empty(t, f.provider.revocations())

		heal()
		require.NoError(t, f.check(session))
		assert.Equal(t, []string{"refresh-token-0", "refresh-token-0"}, f.provider.presented())
		assert.Nil(t, f.stored(session).EndedAt)
	})
}

// A refusal the store did not take is not forgotten. The next request is not
// served inside the limit as though the provider were merely unreachable.
func TestARefusalTheStoreDidNotTake(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	broken := &failingCollection{Collection: f.col}
	f.manager.col = broken
	heal := broken.failWritesAfter(1) // the claim
	f.provider.set(refuse("invalid_grant"))

	f.clock.Advance(4 * time.Minute)
	require.ErrorIs(t, f.check(session), ErrSessionEnded)
	require.Nil(t, f.stored(session).EndedAt, "the store still has the session open")

	f.provider.set(unavailable)
	f.clock.Advance(defaultRetryInterval)
	require.ErrorIs(t, f.check(session), ErrSessionEnded)
	assert.Equal(t, 1, f.provider.calls())

	heal()
	require.ErrorIs(t, f.check(session), ErrSessionEnded)
	stored := f.stored(session)
	require.NotNil(t, stored.EndedAt)
	assert.Equal(t, "refused by the identity provider: invalid_grant", stored.EndReason)
}

// A request that read the session before another request's refresh, and
// comes to refresh it afterwards, finds it confirmed and does not ask again.
func TestARefreshIsNotRepeatedByARequestThatReadBeforeIt(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	f.clock.Advance(4 * time.Minute)
	require.NoError(t, f.check(session))
	require.Equal(t, 1, f.provider.calls())

	require.NoError(t, f.manager.refresh(context.Background(), session.ID))
	assert.Equal(t, 1, f.provider.calls())
	assert.Equal(t, "refresh-token-1", f.heldToken(session))
}

// The limit is measured when the request is answered, not when it arrived: a
// provider call that got nothing and ran across the limit is not served.
func TestTheLimitIsMeasuredAfterTheProviderWasAsked(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	f.provider.set(func(token string) (Renewal, error) {
		f.clock.Advance(time.Second)
		return unavailable(token)
	})
	f.clock.Advance(4*time.Minute + 59*time.Second)
	require.ErrorIs(t, f.check(session), ErrProviderUnavailable, "five minutes to the second is past the limit")
	assert.Nil(t, f.stored(session).EndedAt)
}

// The refresh serves every request for the session, so it does not stop when
// the request that started it goes away.
func TestARefreshOutlivesTheRequestThatStartedIt(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	ctx, cancel := context.WithCancel(context.Background())
	rotate := f.provider.rotate()
	f.provider.set(func(token string) (Renewal, error) {
		cancel() // the browser went away while the provider was being asked
		return rotate(token)
	})
	f.clock.Advance(4 * time.Minute)
	_ = f.manager.Check(ctx, session.ID, alice)

	f.provider.mu.Lock()
	assert.Equal(t, []error{nil}, f.provider.ctxErrs, "the provider call was not cancelled")
	f.provider.mu.Unlock()
	assert.Equal(t, "refresh-token-1", f.heldToken(session), "and its answer was stored")
	require.NoError(t, f.check(session))
	assert.Equal(t, 1, f.provider.calls())
}
