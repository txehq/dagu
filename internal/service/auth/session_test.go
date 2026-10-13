// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/auth"
	persiststore "github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingSessions is a SessionChecker that answers what the test sets and
// records what it was asked.
type recordingSessions struct {
	err   error
	asked []string
	users []string
}

func (r *recordingSessions) CheckSession(_ context.Context, sessionID string, user *auth.User) error {
	r.asked = append(r.asked, sessionID)
	r.users = append(r.users, user.ID)
	return r.err
}

type sessionFixture struct {
	svc     *Service
	store   auth.UserStore
	config  Config
	builtin *auth.User
	oidc    *auth.User
}

// restarted is the hub after a restart: a new service over the same users and
// the same signing key, with no session checker until one is set.
func (f *sessionFixture) restarted() *Service {
	return New(f.store, f.config)
}

const testSessionID = "0123456789abcdef0123456789abcdef"

func newSessionFixture(t *testing.T) *sessionFixture {
	t.Helper()
	store, err := persiststore.NewUserStore(testutil.NewMemoryBackend().Collection("users"))
	require.NoError(t, err)
	config := Config{TokenSecret: mustTokenSecret("test-secret-key-for-jwt-signing"), TokenTTL: time.Hour, BcryptCost: 4}
	svc := New(store, config)
	ctx := context.Background()

	builtin, err := svc.CreateUser(ctx, CreateUserInput{Username: "admin", Password: "password123", Role: auth.RoleAdmin})
	require.NoError(t, err)
	oidc := auth.NewUser("alice", "", auth.RoleViewer)
	oidc.AuthProvider = auth.AuthProviderOIDC
	oidc.OIDCIssuer, oidc.OIDCSubject = "https://issuer.example/realms/test", "subject-1"
	require.NoError(t, store.Create(ctx, oidc))
	return &sessionFixture{svc: svc, store: store, config: config, builtin: builtin, oidc: oidc}
}

// Without a session checker, which is the default, a token that names no
// session is validated as it always was, for every kind of user. A hub that
// never had sessions on has issued no other kind.
func TestSessionsOffChangesNothingForATokenWithoutASession(t *testing.T) {
	t.Parallel()
	f := newSessionFixture(t)
	ctx := context.Background()

	for _, user := range []*auth.User{f.builtin, f.oidc} {
		plain, err := f.svc.GenerateToken(user)
		require.NoError(t, err)
		claims, err := f.svc.ValidateToken(plain.Token)
		require.NoError(t, err)
		assert.Empty(t, claims.SessionID, "an ordinary token names no session")
		for _, svc := range []*Service{f.svc, f.restarted()} {
			got, err := svc.GetUserFromToken(ctx, plain.Token)
			require.NoError(t, err)
			assert.Equal(t, user.ID, got.ID)
		}
	}
}

// A token that names a session never becomes an ordinary token. The same
// token is followed through a hub with sessions on, the end of its session,
// a restart with sessions off, and sessions on again: once its session has
// ended nothing lets its holder in, and with sessions off it is refused
// whether its session had ended or not. A builtin user's token is the control
// and is accepted throughout.
func TestATokenThatNamesASessionIsNeverAnOrdinaryToken(t *testing.T) {
	t.Parallel()
	f := newSessionFixture(t)
	ctx := context.Background()
	sessions := &recordingSessions{}
	f.svc.SetSessionChecker(sessions)
	token, err := f.svc.GenerateSessionToken(f.oidc, testSessionID, time.Now().Add(time.Hour))
	require.NoError(t, err)
	control, err := f.svc.GenerateToken(f.builtin)
	require.NoError(t, err)

	accepts := func(svc *Service, token string, user *auth.User, when string) {
		t.Helper()
		got, err := svc.GetUserFromToken(ctx, token)
		require.NoError(t, err, when)
		assert.Equal(t, user.ID, got.ID, when)
	}
	refuses := func(svc *Service, token string, when string) {
		t.Helper()
		got, err := svc.GetUserFromToken(ctx, token)
		// A refusal, not "try again": the holder is to sign in again.
		require.ErrorIs(t, err, ErrInvalidToken, when)
		require.NotErrorIs(t, err, ErrSessionCheckUnavailable, when)
		assert.Nil(t, got, when)
	}

	accepts(f.svc, token.Token, f.oidc, "sessions on, session live")
	accepts(f.svc, control.Token, f.builtin, "sessions on")

	sessions.err = ErrInvalidToken
	refuses(f.svc, token.Token, "sessions on, session ended")
	accepts(f.svc, control.Token, f.builtin, "sessions on, another user's session ended")

	// The hub is restarted with sessions off. The token is still signed by
	// the hub's key, is not expired, and its user is not disabled.
	off := f.restarted()
	claims, err := off.ValidateToken(token.Token)
	require.NoError(t, err, "the token itself is still well formed")
	assert.Equal(t, testSessionID, claims.SessionID)
	asked := len(sessions.asked)
	refuses(off, token.Token, "sessions off after a restart, session ended")
	accepts(off, control.Token, f.builtin, "sessions off after a restart")
	assert.Len(t, sessions.asked, asked, "the old checker is not what refused it")

	// The checker taken away from a running service is the same.
	f.svc.SetSessionChecker(nil)
	refuses(f.svc, token.Token, "checker removed, session ended")
	accepts(f.svc, control.Token, f.builtin, "checker removed")

	// A session that had not ended is not exempt: with sessions off nobody
	// can say that it has not.
	live, err := off.GenerateSessionToken(f.oidc, "fedcba9876543210fedcba9876543210", time.Now().Add(time.Hour))
	require.NoError(t, err)
	refuses(off, live.Token, "sessions off, session never ended")
	builtinWithSession, err := off.GenerateSessionToken(f.builtin, testSessionID, time.Now().Add(time.Hour))
	require.NoError(t, err)
	refuses(off, builtinWithSession.Token, "sessions off: the rule is about the token, not the kind of user")

	// The OIDC user signs in again with sessions off and gets an ordinary
	// token, which works.
	again, err := off.GenerateToken(f.oidc)
	require.NoError(t, err)
	accepts(off, again.Token, f.oidc, "sessions off, a new sign-in")

	// Sessions on again, after another restart: the session is asked again
	// and has still ended.
	on := f.restarted()
	on.SetSessionChecker(sessions)
	refuses(on, token.Token, "sessions on again, session ended")
	accepts(on, control.Token, f.builtin, "sessions on again")
	assert.Greater(t, len(sessions.asked), asked, "the session is asked again")
}

// With sessions off, the order of the refusals is the usual one: a disabled
// user is told so, and a deleted user's token is a bad token.
func TestSessionsOffRefusalComesAfterTheUserChecks(t *testing.T) {
	t.Parallel()
	f := newSessionFixture(t)
	ctx := context.Background()
	token, err := f.svc.GenerateSessionToken(f.oidc, testSessionID, time.Now().Add(time.Hour))
	require.NoError(t, err)

	disabled := true
	_, err = f.svc.UpdateUser(ctx, f.oidc.ID, UpdateUserInput{IsDisabled: &disabled})
	require.NoError(t, err)
	_, err = f.svc.GetUserFromToken(ctx, token.Token)
	require.ErrorIs(t, err, ErrUserDisabled)

	require.NoError(t, f.store.Delete(ctx, f.oidc.ID))
	_, err = f.svc.GetUserFromToken(ctx, token.Token)
	require.ErrorIs(t, err, ErrInvalidToken)
}

// With sessions on, a token that names a session is good only while the
// session is, and each answer of the session is passed on as it is.
func TestSessionDecidesForATokenThatNamesOne(t *testing.T) {
	t.Parallel()
	f := newSessionFixture(t)
	ctx := context.Background()
	sessions := &recordingSessions{}
	f.svc.SetSessionChecker(sessions)
	expires := time.Now().Add(30 * time.Minute)
	token, err := f.svc.GenerateSessionToken(f.oidc, testSessionID, expires)
	require.NoError(t, err)
	assert.WithinDuration(t, expires, token.ExpiresAt, time.Second, "the token expires with its session, not at the usual lifetime")

	got, err := f.svc.GetUserFromToken(ctx, token.Token)
	require.NoError(t, err)
	assert.Equal(t, f.oidc.ID, got.ID)
	assert.Equal(t, []string{testSessionID}, sessions.asked)
	assert.Equal(t, []string{f.oidc.ID}, sessions.users)

	sessions.err = ErrInvalidToken
	_, err = f.svc.GetUserFromToken(ctx, token.Token)
	require.ErrorIs(t, err, ErrInvalidToken, "an ended session")

	sessions.err = ErrSessionCheckUnavailable
	_, err = f.svc.GetUserFromToken(ctx, token.Token)
	require.ErrorIs(t, err, ErrSessionCheckUnavailable, "an outage is not turned into a bad token")
	require.NotErrorIs(t, err, ErrInvalidToken)

	storeDown := errors.New("the session store cannot be read")
	sessions.err = storeDown
	_, err = f.svc.GetUserFromToken(ctx, token.Token)
	require.ErrorIs(t, err, ErrSessionCheckUnavailable, "a failure is not an answer: nobody is let in, and nobody is told they are signed out")
	require.NotErrorIs(t, err, ErrInvalidToken)
}

// With sessions on, an OIDC user's token that names no session is refused: it
// would never be revalidated. Every other user is as before, and the session
// checker is not asked about them.
func TestSessionsOnRefuseAnOIDCTokenWithoutASession(t *testing.T) {
	t.Parallel()
	f := newSessionFixture(t)
	ctx := context.Background()
	oidcToken, err := f.svc.GenerateToken(f.oidc)
	require.NoError(t, err)
	builtinToken, err := f.svc.GenerateToken(f.builtin)
	require.NoError(t, err)

	sessions := &recordingSessions{err: ErrInvalidToken}
	f.svc.SetSessionChecker(sessions)

	_, err = f.svc.GetUserFromToken(ctx, oidcToken.Token)
	require.ErrorIs(t, err, ErrInvalidToken)

	got, err := f.svc.GetUserFromToken(ctx, builtinToken.Token)
	require.NoError(t, err, "the builtin administrator is not subject to a session")
	assert.Equal(t, f.builtin.ID, got.ID)
	assert.Empty(t, sessions.asked)
}

// A disabled hub user is refused before the session is asked.
func TestDisabledUserIsRefusedBeforeTheSession(t *testing.T) {
	t.Parallel()
	f := newSessionFixture(t)
	ctx := context.Background()
	sessions := &recordingSessions{}
	f.svc.SetSessionChecker(sessions)
	token, err := f.svc.GenerateSessionToken(f.oidc, testSessionID, time.Now().Add(time.Hour))
	require.NoError(t, err)

	disabled := true
	_, err = f.svc.UpdateUser(ctx, f.oidc.ID, UpdateUserInput{IsDisabled: &disabled})
	require.NoError(t, err)

	_, err = f.svc.GetUserFromToken(ctx, token.Token)
	require.ErrorIs(t, err, ErrUserDisabled)
	assert.Empty(t, sessions.asked)
}

func TestGenerateSessionTokenNeedsItsParts(t *testing.T) {
	t.Parallel()
	f := newSessionFixture(t)
	_, err := f.svc.GenerateSessionToken(f.oidc, "", time.Now().Add(time.Hour))
	require.Error(t, err)
	_, err = f.svc.GenerateSessionToken(f.oidc, testSessionID, time.Time{})
	require.Error(t, err)
	assert.Equal(t, time.Hour, f.svc.TokenTTL())
}
