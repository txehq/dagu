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
	builtin *auth.User
	oidc    *auth.User
}

func newSessionFixture(t *testing.T) *sessionFixture {
	t.Helper()
	store, err := persiststore.NewUserStore(testutil.NewMemoryBackend().Collection("users"))
	require.NoError(t, err)
	svc := New(store, Config{TokenSecret: mustTokenSecret("test-secret-key-for-jwt-signing"), TokenTTL: time.Hour, BcryptCost: 4})
	ctx := context.Background()

	builtin, err := svc.CreateUser(ctx, CreateUserInput{Username: "admin", Password: "password123", Role: auth.RoleAdmin})
	require.NoError(t, err)
	oidc := auth.NewUser("alice", "", auth.RoleViewer)
	oidc.AuthProvider = auth.AuthProviderOIDC
	oidc.OIDCIssuer, oidc.OIDCSubject = "https://issuer.example/realms/test", "subject-1"
	require.NoError(t, store.Create(ctx, oidc))
	return &sessionFixture{svc: svc, builtin: builtin, oidc: oidc}
}

// Without a session checker, which is the default, a token is validated as it
// always was, whether or not it names a session.
func TestSessionsOffChangesNothing(t *testing.T) {
	t.Parallel()
	f := newSessionFixture(t)
	ctx := context.Background()

	for _, user := range []*auth.User{f.builtin, f.oidc} {
		plain, err := f.svc.GenerateToken(user)
		require.NoError(t, err)
		claims, err := f.svc.ValidateToken(plain.Token)
		require.NoError(t, err)
		assert.Empty(t, claims.SessionID, "an ordinary token names no session")
		got, err := f.svc.GetUserFromToken(ctx, plain.Token)
		require.NoError(t, err)
		assert.Equal(t, user.ID, got.ID)
	}

	withSession, err := f.svc.GenerateSessionToken(f.oidc, "0123456789abcdef0123456789abcdef", time.Now().Add(time.Hour))
	require.NoError(t, err)
	got, err := f.svc.GetUserFromToken(ctx, withSession.Token)
	require.NoError(t, err, "with sessions off, a session id in a token is not looked at")
	assert.Equal(t, f.oidc.ID, got.ID)
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
	token, err := f.svc.GenerateSessionToken(f.oidc, "0123456789abcdef0123456789abcdef", expires)
	require.NoError(t, err)
	assert.WithinDuration(t, expires, token.ExpiresAt, time.Second, "the token expires with its session, not at the usual lifetime")

	got, err := f.svc.GetUserFromToken(ctx, token.Token)
	require.NoError(t, err)
	assert.Equal(t, f.oidc.ID, got.ID)
	assert.Equal(t, []string{"0123456789abcdef0123456789abcdef"}, sessions.asked)
	assert.Equal(t, []string{f.oidc.ID}, sessions.users)

	sessions.err = ErrInvalidToken
	_, err = f.svc.GetUserFromToken(ctx, token.Token)
	require.ErrorIs(t, err, ErrInvalidToken, "an ended session")

	sessions.err = ErrIdentityProviderUnavailable
	_, err = f.svc.GetUserFromToken(ctx, token.Token)
	require.ErrorIs(t, err, ErrIdentityProviderUnavailable, "an outage is not turned into a bad token")
	require.NotErrorIs(t, err, ErrInvalidToken)

	storeDown := errors.New("the session store cannot be read")
	sessions.err = storeDown
	_, err = f.svc.GetUserFromToken(ctx, token.Token)
	require.ErrorIs(t, err, storeDown, "a failure is not an answer and lets nobody in")
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
	token, err := f.svc.GenerateSessionToken(f.oidc, "0123456789abcdef0123456789abcdef", time.Now().Add(time.Hour))
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
	_, err = f.svc.GenerateSessionToken(f.oidc, "0123456789abcdef0123456789abcdef", time.Time{})
	require.Error(t, err)
	assert.Equal(t, time.Hour, f.svc.TokenTTL())
}
