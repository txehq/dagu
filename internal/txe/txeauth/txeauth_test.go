// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
)

func TestRegistryAnswersFromTheRegistryOnly(t *testing.T) {
	w := newWorld(t)
	r := NewRegistry(w.reg)

	ok, err := r.OwnerExists(w.ctx, w.ownerA)
	require.NoError(t, err)
	require.True(t, ok)
	for _, id := range []string{"own_00000000000000000000000000", "not-an-id", "../owners/x", ""} {
		ok, err := r.OwnerExists(w.ctx, id)
		require.NoError(t, err, id)
		require.False(t, ok, id)
	}

	facts, err := r.JobFacts(w.ctx, w.job)
	require.NoError(t, err)
	require.Equal(t, authz.JobFacts{OwnerID: w.ownerA, ProjectID: w.project, MachineID: w.machine}, facts)

	owner, err := r.ProjectOwner(w.ctx, w.project)
	require.NoError(t, err)
	require.Equal(t, w.ownerA, owner)
	owner, err = r.MachineOwner(w.ctx, w.machine)
	require.NoError(t, err)
	require.Equal(t, w.ownerA, owner)
	name, err := r.OwnerDisplayName(w.ctx, w.ownerB)
	require.NoError(t, err)
	require.Equal(t, "Owner B", name)

	// A miss, and an id that is not one, are both "not registered": the
	// library then answers not found, never an owner.
	_, err = r.JobFacts(w.ctx, "job_00000000000000000000000000")
	require.ErrorIs(t, err, authz.ErrNotFound)
	_, err = r.JobFacts(w.ctx, w.project)
	require.ErrorIs(t, err, authz.ErrNotFound)
	_, err = r.ProjectOwner(w.ctx, "prj_00000000000000000000000000")
	require.ErrorIs(t, err, authz.ErrNotFound)
	_, err = r.MachineOwner(w.ctx, "../machines/x")
	require.ErrorIs(t, err, authz.ErrNotFound)

	// The library builds its resources from these lookups.
	svc, err := NewService(config.TXEConfig{}, w.dataDir, w.reg)
	require.NoError(t, err)
	res, err := svc.Store().Job(w.ctx, w.job)
	require.NoError(t, err)
	require.Equal(t, w.ownerA, res.OwnerID())
	_, err = svc.Store().Job(w.ctx, "job_00000000000000000000000000")
	require.Equal(t, authz.CodeNotFound, authz.CodeOf(err))
}

func TestClassify(t *testing.T) {
	ctx := context.Background()
	user := func(u auth.User) context.Context { return auth.WithUser(ctx, &u) }

	require.Equal(t, Caller{Kind: KindNone}, Classify(ctx))

	admin := Classify(user(auth.User{Username: "admin", Role: auth.RoleAdmin}))
	require.Equal(t, Caller{Kind: KindPlatformAdmin, Username: "admin"}, admin)
	require.False(t, admin.New())
	builtin := Classify(user(auth.User{Username: "admin", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderBuiltin}))
	require.Equal(t, KindPlatformAdmin, builtin.Kind)

	dev := Classify(user(auth.User{Username: "dev", Role: auth.RoleDeveloper}))
	require.Equal(t, Caller{Kind: KindLegacy, Username: "dev"}, dev)

	// An API key is legacy even with the administrator's role.
	keyCtx := auth.WithAPIKey(user(auth.User{Username: "apikey:cli", Role: auth.RoleAdmin}), &auth.APIKey{ID: "k", Role: auth.RoleAdmin})
	require.Equal(t, Caller{Kind: KindLegacy, Username: "apikey:cli"}, Classify(keyCtx))

	proxy := Classify(user(auth.User{Username: "p", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderProxy}))
	require.Equal(t, KindLegacy, proxy.Kind)

	// A person is whoever the provider names, whatever role the hub gave the
	// account, and is never the platform administrator.
	person := Classify(user(auth.User{Username: "alice", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderOIDC,
		OIDCIssuer: testIssuer, OIDCSubject: "subject-a"}))
	require.Equal(t, KindPerson, person.Kind)
	require.True(t, person.New())
	require.Equal(t, authn.Principal{Identity: authn.Identity{Issuer: testIssuer, Subject: "subject-a"}, Class: authn.ClassPerson}, person.Principal)

	// An OIDC account that names no identity is nobody.
	nameless := Classify(user(auth.User{Username: "x", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderOIDC}))
	require.Equal(t, KindLegacy, nameless.Kind)

	// A token comes first and carries no hub user.
	p := authn.Principal{Identity: authn.Identity{Issuer: testIssuer, Subject: "s"}, Class: authn.ClassCLI, ClientID: testCLI}
	tok := Classify(WithToken(user(auth.User{Username: "admin", Role: auth.RoleAdmin}), p))
	require.Equal(t, Caller{Kind: KindToken, Principal: p}, tok)
	require.True(t, tok.New())
}

func TestServiceConfiguration(t *testing.T) {
	w := newWorld(t)

	svc, err := NewService(config.TXEConfig{}, w.dataDir, w.reg)
	require.NoError(t, err)
	require.Equal(t, authz.ModeOff, svc.Mode())
	require.False(t, svc.AcceptsTokens())
	_, err = svc.Verify(w.ctx, "x")
	require.Error(t, err)
	svc.Run(w.ctx) // returns at once: no remote keys

	svc, err = NewService(config.TXEConfig{Authz: config.TXEAuthzConfig{Mode: "observe"}}, w.dataDir, w.reg)
	require.NoError(t, err)
	require.Equal(t, authz.ModeObserve, svc.Mode())

	_, err = NewService(config.TXEConfig{Authz: config.TXEAuthzConfig{Mode: "enforcing"}}, w.dataDir, w.reg)
	require.Error(t, err)
	_, err = NewService(config.TXEConfig{}, w.dataDir, nil)
	require.Error(t, err)

	// A key set on plain http off loopback is refused.
	_, err = NewService(config.TXEConfig{Authn: config.TXEAuthnConfig{
		Issuer: testIssuer, Audience: testAudience, JWKSURL: "http://issuer.example/certs",
		Clients: []config.TXEAuthnClient{{ID: testCLI, Class: "cli"}},
	}}, w.dataDir, w.reg)
	require.Error(t, err)
	svc, err = NewService(config.TXEConfig{Authn: config.TXEAuthnConfig{
		Issuer: testIssuer, Audience: testAudience, JWKSURL: "https://issuer.example/certs",
		Clients: []config.TXEAuthnClient{{ID: testCLI, Class: "cli"}},
	}}, w.dataDir, w.reg)
	require.NoError(t, err)
	require.True(t, svc.AcceptsTokens())
}

func tokenService(t *testing.T, w *world, keys authn.KeySource) *Service {
	t.Helper()
	svc, err := NewService(config.TXEConfig{Authn: config.TXEAuthnConfig{
		Issuer: testIssuer, Audience: testAudience, JWKSURL: "https://issuer.example/certs",
		Clients: []config.TXEAuthnClient{{ID: testCLI, Class: "cli"}, {ID: testWorker, Class: "worker"}},
	}}, w.dataDir, w.reg, WithKeySource(keys), WithClock(func() time.Time { return w.now }))
	require.NoError(t, err)
	return svc
}

func TestVerifyAndResolveTokens(t *testing.T) {
	w := newWorld(t)
	keys := authn.StaticKeys{testKeyID: {Public: &testRSAKey().PublicKey, Algorithm: "RS256"}}
	svc := tokenService(t, w, keys)

	p, err := svc.Verify(w.ctx, token(t, w.now, nil))
	require.NoError(t, err)
	require.Equal(t, authn.ClassCLI, p.Class)
	require.Equal(t, authn.Identity{Issuer: testIssuer, Subject: "subject-a"}, p.Identity)

	// A verified token that nobody bound acts for nobody.
	scope, err := svc.Scope(w.ctx, Caller{Kind: KindToken, Principal: p})
	require.NoError(t, err)
	require.Equal(t, authz.ScopeUnbound, scope.Kind())
	require.Equal(t, authz.ReasonUnbound, scope.UnboundReason())

	// Bound by the platform administrator against the person's own request,
	// the same identity's CLI acts for that owner.
	person := authn.Principal{Identity: p.Identity, Class: authn.ClassPerson}
	_, err = svc.Store().RequestBinding(w.ctx, person, authz.Shown{Username: "alice"})
	require.NoError(t, err)
	_, err = svc.Store().ApproveBinding(w.ctx, authz.PlatformAdmin("admin"), p.Identity, w.ownerA)
	require.NoError(t, err)
	scope, err = svc.Scope(w.ctx, Caller{Kind: KindToken, Principal: p})
	require.NoError(t, err)
	require.Equal(t, authz.ScopeOwner, scope.Kind())
	require.Equal(t, w.ownerA, scope.OwnerID())
	require.False(t, authz.IsHuman(scope))

	scope, err = svc.Scope(w.ctx, Caller{Kind: KindPerson, Principal: person})
	require.NoError(t, err)
	require.True(t, authz.IsHuman(scope))

	// A worker token that is not enrolled is nobody, though its identity is
	// bound.
	wp, err := svc.Verify(w.ctx, token(t, w.now, map[string]any{"azp": testWorker}))
	require.NoError(t, err)
	scope, err = svc.Scope(w.ctx, Caller{Kind: KindToken, Principal: wp})
	require.NoError(t, err)
	require.Equal(t, authz.ScopeUnbound, scope.Kind())
	require.Equal(t, authz.ReasonNotEnrolled, scope.UnboundReason())

	// A legacy caller and an unauthenticated one act for nobody; the
	// administrator is its own scope.
	for _, c := range []Caller{{Kind: KindLegacy, Username: "dev"}, {Kind: KindNone}} {
		scope, err := svc.Scope(w.ctx, c)
		require.NoError(t, err)
		require.Equal(t, authz.ScopeUnbound, scope.Kind())
	}
	scope, err = svc.Scope(w.ctx, Caller{Kind: KindPlatformAdmin, Username: "admin"})
	require.NoError(t, err)
	require.Equal(t, authz.ScopePlatformAdmin, scope.Kind())
}

func TestVerifyRefusals(t *testing.T) {
	w := newWorld(t)
	keys := authn.StaticKeys{testKeyID: {Public: &testRSAKey().PublicKey, Algorithm: "RS256"}}
	svc := tokenService(t, w, keys)

	cases := map[string]struct {
		claims map[string]any
		reason authn.Reason
	}{
		"expired":        {map[string]any{"iat": w.now.Add(-5 * time.Minute).Unix(), "exp": w.now.Unix()}, authn.ReasonExpired},
		"over 5 minutes": {map[string]any{"exp": w.now.Add(6 * time.Minute).Unix()}, authn.ReasonLifetime},
		"other issuer":   {map[string]any{"iss": "https://issuer.example/realms/other"}, authn.ReasonIssuer},
		"other audience": {map[string]any{"aud": "someone-else"}, authn.ReasonAudience},
		"unknown client": {map[string]any{"azp": "dagu-reviewer-unknown"}, authn.ReasonClient},
		"refresh token":  {map[string]any{"typ": "Refresh"}, authn.ReasonTokenType},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := svc.Verify(w.ctx, token(t, w.now, tc.claims))
			require.Equal(t, tc.reason, authn.ReasonOf(err))
		})
	}
}

type failingKeys struct{}

func (failingKeys) Key(context.Context, string) (authn.Key, error) {
	return authn.Key{}, errors.New("issuer unreachable")
}

func TestVerifyWithoutKeysSaysTheProviderIsUnavailable(t *testing.T) {
	w := newWorld(t)
	svc := tokenService(t, w, failingKeys{})
	_, err := svc.Verify(w.ctx, token(t, w.now, nil))
	require.True(t, authn.ProviderUnavailable(err))
}
