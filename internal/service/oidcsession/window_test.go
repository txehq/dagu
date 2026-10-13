// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package oidcsession

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Window and Check are two readings of one rule. For a session a process
// confirmed itself, and for one another process confirmed, Check asks the
// provider exactly from RevalidateAt and refuses exactly from ServedUntil
// when the provider gives nothing.
func TestWindowAgreesWithCheck(t *testing.T) {
	t.Parallel()

	for name, other := range map[string]bool{"ConfirmedHere": false, "ConfirmedByAnotherProcess": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, nil)
			session := f.signIn()
			manager := f.manager
			if other {
				manager = f.process()
			}
			f.provider.set(unavailable)
			start := f.clock.Now()

			window, err := manager.Window(context.Background(), session.ID)
			require.NoError(t, err)
			skew := time.Duration(0)
			if other {
				skew = maxClockSkew
			}
			assert.Equal(t, start.Add(4*time.Minute-skew), window.RevalidateAt)
			assert.Equal(t, start.Add(5*time.Minute-skew), window.ServedUntil)

			at := func(when time.Time) (served bool, asked bool) {
				f.clock.mu.Lock()
				f.clock.now = when
				f.clock.mu.Unlock()
				// A call that got nothing is not repeated at once; forget it,
				// so that each reading stands alone.
				manager.mu.Lock()
				clear(manager.failedAt)
				manager.mu.Unlock()
				before := f.provider.calls()
				err := manager.Check(context.Background(), session.ID, alice)
				if err != nil {
					require.ErrorIs(t, err, ErrProviderUnavailable)
				}
				return err == nil, f.provider.calls() > before
			}

			served, asked := at(window.RevalidateAt.Add(-time.Nanosecond))
			assert.True(t, served)
			assert.False(t, asked, "the provider is not asked before RevalidateAt")

			served, asked = at(window.RevalidateAt)
			assert.True(t, served)
			assert.True(t, asked, "the provider is asked from RevalidateAt")

			served, _ = at(window.ServedUntil.Add(-time.Nanosecond))
			assert.True(t, served, "a request just before ServedUntil is served")

			served, asked = at(window.ServedUntil)
			assert.False(t, served, "a request at ServedUntil is refused")
			assert.True(t, asked)

			// The window did not move: the provider confirmed nothing.
			again, err := manager.Window(context.Background(), session.ID)
			require.NoError(t, err)
			assert.Equal(t, window, again)
		})
	}
}

// A confirmation moves the window, and the window asks the provider nothing.
func TestWindowFollowsAConfirmation(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()

	f.clock.Advance(4*time.Minute + 10*time.Second)
	before, err := f.manager.Window(context.Background(), session.ID)
	require.NoError(t, err)
	assert.Zero(t, f.provider.calls(), "Window does not ask the provider")
	assert.Equal(t, f.clock.Now().Add(50*time.Second), before.ServedUntil)

	require.NoError(t, f.check(session))
	require.Equal(t, 1, f.provider.calls())

	after, err := f.manager.Window(context.Background(), session.ID)
	require.NoError(t, err)
	assert.Equal(t, f.clock.Now().Add(4*time.Minute), after.RevalidateAt)
	assert.Equal(t, f.clock.Now().Add(5*time.Minute), after.ServedUntil)
}

// The hub token's expiry ends what a session serves, whatever the provider
// says, so the window ends there too.
func TestWindowEndsWithTheHubToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	expires := f.clock.Now().Add(90 * time.Second)
	session, err := f.manager.Create(context.Background(), alice, "refresh-token-0", expires)
	require.NoError(t, err)

	window, err := f.manager.Window(context.Background(), session.ID)
	require.NoError(t, err)
	assert.Equal(t, expires, window.ServedUntil)

	// At the expiry there is no window, as there is no request served.
	f.clock.Advance(90*time.Second - time.Nanosecond)
	_, err = f.manager.Window(context.Background(), session.ID)
	require.NoError(t, err)
	require.NoError(t, f.check(session))
	f.clock.Advance(time.Nanosecond)
	_, err = f.manager.Window(context.Background(), session.ID)
	require.ErrorIs(t, err, ErrSessionEnded)
	require.ErrorIs(t, f.check(session), ErrSessionEnded)
}

// A confirmation by another process moves the window as that process's clock
// is allowed for, which can put it earlier than the window before.
func TestWindowAfterAnotherProcessConfirms(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	start := f.clock.Now()
	before, err := f.manager.Window(context.Background(), session.ID)
	require.NoError(t, err)
	require.Equal(t, start.Add(5*time.Minute), before.ServedUntil)

	// Another process confirms the session four seconds later.
	f.clock.Advance(4 * time.Second)
	f.rewrite(session, func(stored *Session) {
		stored.LastConfirmedAt = f.clock.Now()
		stored.ConfirmedBy = "another-process"
	})
	after, err := f.manager.Window(context.Background(), session.ID)
	require.NoError(t, err)
	assert.Equal(t, start.Add(4*time.Second+5*time.Minute-maxClockSkew), after.ServedUntil)
	assert.True(t, after.ServedUntil.Before(before.ServedUntil), "six seconds earlier than before")

	// And Check refuses from there when the provider gives nothing.
	f.provider.set(unavailable)
	f.clock.Advance(after.ServedUntil.Sub(f.clock.Now()) - time.Nanosecond)
	require.NoError(t, f.check(session))
	f.manager.mu.Lock()
	clear(f.manager.failedAt)
	f.manager.mu.Unlock()
	f.clock.Advance(time.Nanosecond)
	require.ErrorIs(t, f.check(session), ErrProviderUnavailable)
}

// A confirmation dated in the future, beyond what clocks may differ by, is
// not trusted by Check, and its window is already over.
func TestWindowOfAConfirmationInTheFutureIsOver(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	f.provider.set(unavailable)
	f.rewrite(session, func(stored *Session) {
		stored.LastConfirmedAt = f.clock.Now().Add(time.Hour)
		stored.ConfirmedBy = "another-process"
	})

	window, err := f.manager.Window(context.Background(), session.ID)
	require.NoError(t, err)
	assert.Equal(t, f.clock.Now(), window.ServedUntil)
	assert.Equal(t, f.clock.Now(), window.RevalidateAt)
	require.ErrorIs(t, f.check(session), ErrProviderUnavailable)
}

// A session that has ended, was never there, or cannot be read has no window.
func TestWindowOfNoSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()

	_, err := f.manager.Window(context.Background(), "ffffffffffffffffffffffffffffffff")
	require.ErrorIs(t, err, ErrSessionEnded)
	_, err = f.manager.Window(context.Background(), "not an id")
	require.ErrorIs(t, err, ErrSessionEnded)

	require.NoError(t, f.manager.End(context.Background(), session.ID, "signed out", time.Time{}))
	_, err = f.manager.Window(context.Background(), session.ID)
	require.ErrorIs(t, err, ErrSessionEnded)

	other := f.signIn()
	f.manager.col = &failingCollection{Collection: f.col, fail: errors.New("disk unavailable")}
	_, err = f.manager.Window(context.Background(), other.ID)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrSessionEnded, "a store failure is not an answer")
}
