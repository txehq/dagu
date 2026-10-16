// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const adminSubject = "84dbbe95-0000-4000-8000-000000000001" // synthetic

func ssoPerson(issuer, subject string) *auth.User {
	return &auth.User{ID: "u-" + subject, Username: "connor", Role: auth.RoleViewer,
		AuthProvider: auth.AuthProviderOIDC, OIDCIssuer: issuer, OIDCSubject: subject}
}

// through runs ctx through TxePlatformAdminSession and reports what the next
// handler saw.
func through(t *testing.T, a *API, ctx context.Context) (txeauth.Caller, *auth.User) {
	t.Helper()
	var caller txeauth.Caller
	var user *auth.User
	h := a.TxePlatformAdminSession(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		caller = txeauth.Classify(r.Context())
		user, _ = auth.UserFromContext(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/txe/binding-requests", nil).WithContext(ctx))
	return caller, user
}

func adminFixture(t *testing.T) *identityFixture {
	t.Helper()
	f := newIdentityFixture(t, config.TXEAuthzModeEnforce)
	f.api.txePlatformAdmins = []config.TXEPlatformAdmin{{Issuer: identityIssuer, Subject: adminSubject}}
	return f
}

func TestTxePlatformAdminSession_TheListedPersonIsTheAdministrator(t *testing.T) {
	f := adminFixture(t)
	stored := ssoPerson(identityIssuer, adminSubject)

	caller, user := through(t, f.api, auth.WithUser(context.Background(), stored))

	assert.Equal(t, txeauth.KindPlatformAdmin, caller.Kind)
	assert.False(t, caller.New(), "an administrator is not held to an owner")
	require.NotNil(t, user)
	assert.Equal(t, auth.RoleAdmin, user.Role)
	// The stored account is never changed: the elevation is this request's.
	assert.Equal(t, auth.RoleViewer, stored.Role)
	assert.NotSame(t, stored, user)
}

func TestTxePlatformAdminSession_EveryoneElseKeepsOwnerIsolation(t *testing.T) {
	f := adminFixture(t)
	listed := authn.Identity{Issuer: identityIssuer, Subject: adminSubject}

	cases := map[string]struct {
		ctx  context.Context
		want txeauth.Kind
	}{
		"another person": {
			auth.WithUser(context.Background(), ssoPerson(identityIssuer, "someone-else")), txeauth.KindPerson},
		"the same username, another subject": {
			auth.WithUser(context.Background(), &auth.User{Username: "connor", AuthProvider: auth.AuthProviderOIDC,
				OIDCIssuer: identityIssuer, OIDCSubject: "impostor"}), txeauth.KindPerson},
		"the same subject under another issuer": {
			auth.WithUser(context.Background(), ssoPerson("https://other.example/realms/test", adminSubject)), txeauth.KindPerson},
		"the listed identity's provider token (the command line)": {
			txeauth.WithToken(context.Background(), authn.Principal{Identity: listed, Class: authn.ClassCLI}), txeauth.KindToken},
		"an API key whose synthetic user names the listed identity": {
			auth.WithAPIKey(auth.WithUser(context.Background(), ssoPerson(identityIssuer, adminSubject)), &auth.APIKey{ID: "k1"}), txeauth.KindLegacy},
		"a builtin account named like the listed identity": {
			auth.WithUser(context.Background(), &auth.User{Username: "connor", Role: auth.RoleViewer, OIDCIssuer: identityIssuer, OIDCSubject: adminSubject}), txeauth.KindLegacy},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			caller, user := through(t, f.api, tc.ctx)
			assert.Equal(t, tc.want, caller.Kind)
			if user != nil {
				assert.NotEqual(t, auth.RoleAdmin, user.Role)
			}
		})
	}
}

func TestTxePlatformAdminSession_AMarkForAnotherIdentityIsIgnored(t *testing.T) {
	// A context that carries the mark for the listed identity, but whose user
	// is someone else, is that someone else.
	ctx := txeauth.WithPlatformAdminSession(
		auth.WithUser(context.Background(), ssoPerson(identityIssuer, "someone-else")),
		authn.Identity{Issuer: identityIssuer, Subject: adminSubject})
	assert.Equal(t, txeauth.KindPerson, txeauth.Classify(ctx).Kind)
}

func TestTxePlatformAdminSession_AnEmptyListChangesNothing(t *testing.T) {
	f := newIdentityFixture(t, config.TXEAuthzModeEnforce)
	caller, user := through(t, f.api, auth.WithUser(context.Background(), ssoPerson(identityIssuer, adminSubject)))
	assert.Equal(t, txeauth.KindPerson, caller.Kind)
	assert.Equal(t, auth.RoleViewer, user.Role)
}

func TestTxePlatformAdminSession_RemovalTakesEffectOnTheNextRequest(t *testing.T) {
	f := adminFixture(t)
	ctx := auth.WithUser(context.Background(), ssoPerson(identityIssuer, adminSubject))
	caller, _ := through(t, f.api, ctx)
	require.Equal(t, txeauth.KindPlatformAdmin, caller.Kind)

	// The list is read when the middleware is built, which is at server start:
	// a restart with the entry removed builds it again.
	f.api.txePlatformAdmins = nil
	caller, _ = through(t, f.api, ctx)
	assert.Equal(t, txeauth.KindPerson, caller.Kind)
}

func TestTxePlatformAdminSession_ApprovesABinding(t *testing.T) {
	f := adminFixture(t)
	requester := authn.Identity{Issuer: identityIssuer, Subject: "subject-b"}
	_, err := f.svc.Store().RequestBinding(context.Background(), authn.Principal{Identity: requester, Class: authn.ClassPerson}, authz.Shown{Username: "bob"})
	require.NoError(t, err)

	approve := func(ctx context.Context) error {
		var gotErr error
		h := f.api.TxePlatformAdminSession(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, gotErr = f.api.ApproveTxeBinding(r.Context(), apigen.ApproveTxeBindingRequestObject{OwnerId: f.owner,
				Body: &apigen.ApproveTxeBindingJSONRequestBody{Issuer: identityIssuer, Subject: "subject-b", RequestGeneration: 1}})
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx))
		return gotErr
	}

	// An unlisted person may not approve.
	require.Equal(t, http.StatusForbidden, statusOf(approve(auth.WithUser(context.Background(), ssoPerson(identityIssuer, "someone-else")))))
	// The listed person may.
	require.NoError(t, approve(auth.WithUser(context.Background(), ssoPerson(identityIssuer, adminSubject))))
}

func TestTxePlatformAdminSession_PassesThePersonGateOnAnAdminRoute(t *testing.T) {
	f := adminFixture(t)
	chain := func(ctx context.Context) (int, *auth.User) {
		var seen *auth.User
		final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen, _ = auth.UserFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		h := f.api.TxePlatformAdminSession(f.api.txePersonGate("/api/v1")(f.api.txeNeutralize(final)))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil).WithContext(ctx))
		return rec.Code, seen
	}

	code, user := chain(auth.WithUser(context.Background(), ssoPerson(identityIssuer, adminSubject)))
	require.Equal(t, http.StatusOK, code)
	require.NotNil(t, user)
	assert.Equal(t, auth.RoleAdmin, user.Role, "the hub's admin routes see the administrator role")

	code, _ = chain(auth.WithUser(context.Background(), ssoPerson(identityIssuer, "someone-else")))
	assert.Equal(t, http.StatusForbidden, code, "an unlisted person is still refused off /txe")
}

// An API key the SSO administrator created and owns is not a second
// administrator: it is the same legacy caller, with its own role, as a key the
// builtin administrator creates.
func TestTxePlatformAdminSession_AKeyTheAdministratorOwnsIsNotTheAdministrator(t *testing.T) {
	f := adminFixture(t)
	admin := ssoPerson(identityIssuer, adminSubject)
	key := &auth.APIKey{ID: "k1", Name: "connor-laptop", Role: auth.RoleViewer,
		AttributionClass: auth.APIKeyAttributionUserOwned, OwnerUserID: admin.ID, CreatedBy: admin.ID}
	// What the auth middleware builds for an API key.
	synthetic := &auth.User{ID: "apikey:" + key.ID, Username: "apikey:" + key.Name, Role: key.Role}

	caller, user := through(t, f.api, auth.WithAPIKey(auth.WithUser(context.Background(), synthetic), key))
	assert.Equal(t, txeauth.KindLegacy, caller.Kind)
	require.NotNil(t, user)
	assert.Equal(t, auth.RoleViewer, user.Role)
}
