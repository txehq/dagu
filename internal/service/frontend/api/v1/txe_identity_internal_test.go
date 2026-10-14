// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

const identityIssuer = "https://issuer.example/realms/test"

type identityFixture struct {
	api   *API
	svc   *txeauth.Service
	owner string
}

func newIdentityFixture(t *testing.T, mode string) *identityFixture {
	t.Helper()
	dir := t.TempDir()
	repo := persis.NewDAGRepository(dag.NewStore(filepath.Join(dir, "dags")), persis.DAGRepositoryOptions{})
	dataDir := filepath.Join(dir, "data")
	store, err := registry.NewFileStore(dataDir, registry.WithDAGStore(registry.NewDAGStore(repo)))
	require.NoError(t, err)
	owner, err := registry.NewID(registry.PrefixOwner, time.Now())
	require.NoError(t, err)
	_, err = store.CreateOwner(context.Background(), registry.Owner{OwnerID: owner, DisplayName: "Connor Wang"},
		registry.Actor{Kind: registry.ActorSystem, ID: "test"})
	require.NoError(t, err)
	svc, err := txeauth.NewService(config.TXEConfig{Authz: config.TXEAuthzConfig{Mode: mode}}, dataDir, store)
	require.NoError(t, err)
	a := New(repo, nil, nil, nil, runtime.Manager{}, &config.Config{}, nil, nil, prometheus.NewRegistry(), nil,
		WithTxeRegistry(store), WithTxeAuth(svc), WithAuthService(struct{ AuthService }{}))
	return &identityFixture{api: a, svc: svc, owner: owner}
}

func (f *identityFixture) identity(t *testing.T, ctx context.Context) apigen.TxeIdentity {
	t.Helper()
	resp, err := f.api.GetTxeIdentity(ctx, apigen.GetTxeIdentityRequestObject{})
	require.NoError(t, err)
	out, ok := resp.(apigen.GetTxeIdentity200JSONResponse)
	require.True(t, ok)
	return apigen.TxeIdentity(out)
}

func personCtx(subject string) context.Context {
	return auth.WithUser(context.Background(), &auth.User{
		Username: "alice", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderOIDC,
		OIDCIssuer: identityIssuer, OIDCSubject: subject,
	})
}

func TestTxeIdentityPersonFromUnboundToPendingToBound(t *testing.T) {
	f := newIdentityFixture(t, "")
	ctx := personCtx("subject-a")

	// Signed in, with the hub's administrator role on the account even, and
	// bound to nobody: the person acts for nobody.
	got := f.identity(t, ctx)
	require.Equal(t, txeAuthContract, got.Contract)
	require.Equal(t, apigen.TxeIdentityAuthzModeOff, got.AuthzMode)
	require.Equal(t, apigen.TxeIdentityPrincipalClassPerson, got.Principal.Class)
	require.Equal(t, identityIssuer, *got.Principal.Issuer)
	require.Equal(t, "subject-a", *got.Principal.Subject)
	require.Nil(t, got.Principal.ClientId)
	require.Equal(t, "alice", *got.Principal.Shown.Username)
	require.Equal(t, apigen.TxeIdentityStateUnbound, got.State)
	require.Empty(t, got.Owners)
	require.Equal(t, apigen.TxeIdentityScopeKindUnbound, got.Scope.Kind)
	require.Equal(t, "unbound", *got.Scope.UnboundReason)
	require.False(t, got.PlatformAdmin)
	require.False(t, got.IsPerson)
	require.Nil(t, got.Request)

	identity := authn.Identity{Issuer: identityIssuer, Subject: "subject-a"}
	_, err := f.svc.Store().RequestBinding(ctx, authn.Principal{Identity: identity, Class: authn.ClassPerson}, authz.Shown{Username: "alice"})
	require.NoError(t, err)
	got = f.identity(t, ctx)
	require.Equal(t, apigen.TxeIdentityStatePending, got.State)
	require.NotNil(t, got.Request)
	require.Equal(t, apigen.TxeIdentityRequestStatePending, got.Request.State)
	require.Equal(t, 1, got.Request.Generation)

	_, err = f.svc.Store().ApproveBinding(ctx, authz.PlatformAdmin("admin"), identity, f.owner)
	require.NoError(t, err)
	got = f.identity(t, ctx)
	require.Equal(t, apigen.TxeIdentityStateBound, got.State)
	require.Equal(t, []apigen.TxeIdentityOwner{{OwnerId: f.owner, DisplayName: "Connor Wang"}}, got.Owners)
	require.Equal(t, apigen.TxeIdentityScopeKindOwner, got.Scope.Kind)
	require.Nil(t, got.Scope.UnboundReason)
	require.True(t, got.IsPerson)
	require.Nil(t, got.Request)

	// Another subject with the same name and email is somebody else.
	got = f.identity(t, personCtx("subject-b"))
	require.Equal(t, apigen.TxeIdentityStateUnbound, got.State)
	require.Empty(t, got.Owners)
}

func TestTxeIdentityToken(t *testing.T) {
	f := newIdentityFixture(t, "enforce")
	p := authn.Principal{Identity: authn.Identity{Issuer: identityIssuer, Subject: "subject-a"}, Class: authn.ClassCLI,
		ClientID: "dagu-cli", Expires: time.Now().Add(time.Minute)}
	ctx := txeauth.WithToken(context.Background(), p)

	got := f.identity(t, ctx)
	require.Equal(t, apigen.TxeIdentityAuthzModeEnforce, got.AuthzMode)
	require.Equal(t, apigen.TxeIdentityPrincipalClassCli, got.Principal.Class)
	require.Equal(t, "dagu-cli", *got.Principal.ClientId)
	require.Nil(t, got.Principal.Shown.Username)
	require.Equal(t, apigen.TxeIdentityStateUnbound, got.State)
	require.False(t, got.IsPerson)

	person := authn.Principal{Identity: p.Identity, Class: authn.ClassPerson}
	_, err := f.svc.Store().RequestBinding(ctx, person, authz.Shown{})
	require.NoError(t, err)
	_, err = f.svc.Store().ApproveBinding(ctx, authz.PlatformAdmin("admin"), p.Identity, f.owner)
	require.NoError(t, err)
	got = f.identity(t, ctx)
	require.Equal(t, apigen.TxeIdentityStateBound, got.State)
	require.Equal(t, f.owner, got.Owners[0].OwnerId)
	// A token acts for the owner and is never a person.
	require.False(t, got.IsPerson)

	// An expired token resolves to nobody.
	p.Expires = time.Now().Add(-time.Second)
	got = f.identity(t, txeauth.WithToken(context.Background(), p))
	require.Equal(t, apigen.TxeIdentityStateUnbound, got.State)
	require.Equal(t, "expired", *got.Scope.UnboundReason)
}

func TestTxeIdentityPlatformAdminAndLegacy(t *testing.T) {
	f := newIdentityFixture(t, "observe")

	got := f.identity(t, auth.WithUser(context.Background(), &auth.User{Username: "admin", Role: auth.RoleAdmin}))
	require.Equal(t, apigen.TxeIdentityPrincipalClassPlatformAdmin, got.Principal.Class)
	require.True(t, got.PlatformAdmin)
	require.Equal(t, apigen.TxeIdentityScopeKindPlatformAdmin, got.Scope.Kind)
	require.Equal(t, apigen.TxeIdentityStateUnbound, got.State)
	require.Empty(t, got.Owners)
	require.False(t, got.IsPerson)

	keyCtx := auth.WithAPIKey(auth.WithUser(context.Background(), &auth.User{Username: "apikey:cli", Role: auth.RoleAdmin}),
		&auth.APIKey{ID: "k", Role: auth.RoleAdmin})
	got = f.identity(t, keyCtx)
	require.Equal(t, apigen.TxeIdentityPrincipalClassLegacy, got.Principal.Class)
	require.False(t, got.PlatformAdmin)
	require.Equal(t, "legacy", *got.Scope.UnboundReason)

	got = f.identity(t, context.Background())
	require.Equal(t, apigen.TxeIdentityPrincipalClassLegacy, got.Principal.Class)
	require.Equal(t, apigen.TxeIdentityStateUnbound, got.State)
}

func TestTxeIdentityWithoutRegistry(t *testing.T) {
	a := New(nil, nil, nil, nil, runtime.Manager{}, &config.Config{}, nil, nil, prometheus.NewRegistry(), nil)
	_, err := a.GetTxeIdentity(context.Background(), apigen.GetTxeIdentityRequestObject{})
	require.ErrorIs(t, err, errTxeRegistryUnavailable)
}

func TestTxeTokenRouteAdmitsOnlyOwnerScopedRoutes(t *testing.T) {
	admit := txeTokenRoute("/api/v1")
	for _, tc := range []struct {
		method, target string
		want           bool
	}{
		{http.MethodGet, "/api/v1/txe/identity", true},
		{http.MethodGet, "/api/v1/txe/identity/", true},
		{http.MethodGet, "/api/v1/txe/identity?remoteNode=local", true},
		{http.MethodGet, "/api/v1/txe/identity?remoteNode=other", false},
		{http.MethodPost, "/api/v1/txe/jobs", true},
		{http.MethodGet, "/api/v1/txe/jobs/job_x/reviews", true},
		{http.MethodGet, "/api/v1/txe", true},
		{http.MethodGet, "/api/v1/txex", false},
		{http.MethodGet, "/api/v1/txe/../dags", true},
		{http.MethodGet, "/api/v1/dags", true},
		{http.MethodGet, "/api/v1/dag-runs/job_x/run", true},
		{http.MethodGet, "/api/v1/queues", true},
		{http.MethodGet, "/api/v1/workers", false},
		{http.MethodGet, "/api/v1/users", false},
		{http.MethodGet, "/api/v1/dagsx", false},
		{http.MethodGet, "/api/v1/txe/../users", false},
		{http.MethodGet, "/txe/identity", false},
	} {
		req := httptest.NewRequest(tc.method, tc.target, nil)
		require.Equal(t, tc.want, admit(req), tc.method+" "+tc.target)
	}
	require.True(t, txeTokenRoute("/dagu/api/v1")(httptest.NewRequest(http.MethodGet, "/dagu/api/v1/txe/identity", nil)))
}
