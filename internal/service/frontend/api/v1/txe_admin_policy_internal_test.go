// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// The callers requireAdmin can meet, as the request context carries them.
// Every identity here is synthetic.
func adminCallers(f *identityFixture, t *testing.T) map[string]context.Context {
	t.Helper()
	bg := context.Background()
	key := &auth.APIKey{ID: "key_01", Name: "automation", Role: auth.RoleAdmin}
	bound := authn.Identity{Issuer: identityIssuer, Subject: "subject-bound"}
	_, err := f.svc.Store().RequestBinding(bg, authn.Principal{Identity: bound, Class: authn.ClassPerson}, authz.Shown{})
	require.NoError(t, err)
	_, err = f.svc.Store().ApproveBinding(bg, authz.PlatformAdmin("admin"), bound, f.owner)
	require.NoError(t, err)
	f.api.txePlatformAdmins = []config.TXEPlatformAdmin{{Issuer: identityIssuer, Subject: adminSubject}}
	return map[string]context.Context{
		"the builtin administrator":                            auth.WithUser(bg, &auth.User{Username: "admin", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderBuiltin}),
		"a second builtin account with the administrator role": auth.WithUser(bg, &auth.User{Username: "ops", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderBuiltin}),
		"the platform administrator signed in through the identity provider": txeauth.WithPlatformAdminSession(
			auth.WithUser(bg, &auth.User{Username: "connor", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderOIDC, OIDCIssuer: identityIssuer, OIDCSubject: adminSubject}),
			authn.Identity{Issuer: identityIssuer, Subject: adminSubject}),
		"an admin-role API key":                  auth.WithAPIKey(auth.WithUser(bg, &auth.User{Username: "automation", Role: auth.RoleAdmin}), key),
		"an administrator a trusted proxy named": auth.WithUser(bg, &auth.User{Username: "proxied", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderProxy}),
		"a builtin manager":                      auth.WithUser(bg, &auth.User{Username: "manager", Role: auth.RoleManager, AuthProvider: auth.AuthProviderBuiltin}),
		// An account that says it came from the provider and names no
		// identity is nobody\'s: a legacy caller (txeauth.Classify).
		"an administrator account from the provider naming no identity": auth.WithUser(bg, &auth.User{Username: "half", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderOIDC}),
		"a person the hub gave the administrator role":                  personCtx("subject-person"),
		"a bound person the hub gave the administrator role": auth.WithUser(bg, &auth.User{
			Username: "bound", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderOIDC, OIDCIssuer: identityIssuer, OIDCSubject: "subject-bound"}),
		"an owner's command-line token": txeauth.WithToken(bg, authn.Principal{Identity: bound, Class: authn.ClassCLI, ClientID: "dagu-cli", Expires: time.Now().Add(time.Hour)}),
		"nobody":                        bg,
	}
}

// requireAdmin under each mode (TXE-6139): the hub's administrator role as
// before, and under enforce the platform administrator alone. A builtin
// account with the administrator role is the platform administrator; an
// API key, a trusted proxy's user and any other legacy administrator keep
// the routes in off and observe and lose them in enforce; a person or token
// held to its owner never has them, whatever role the hub's account
// carries; a manager and an unauthenticated request are refused as before.
func TestRequireAdminDecidesEachCallerInEachMode(t *testing.T) {
	type want struct{ off, observe, enforce error }
	legacyAdmin := want{nil, nil, errTxePlatformAdmin}
	wants := map[string]want{
		"the builtin administrator":                                          {nil, nil, nil},
		"a second builtin account with the administrator role":               {nil, nil, nil},
		"the platform administrator signed in through the identity provider": {nil, nil, nil},
		"an admin-role API key":                                              legacyAdmin,
		"an administrator a trusted proxy named":                             legacyAdmin,
		"a builtin manager":                                                  {errInsufficientPermissions, errInsufficientPermissions, errInsufficientPermissions},
		"an administrator account from the provider naming no identity":      legacyAdmin,
		"a person the hub gave the administrator role":                       {errTxePlatformAdmin, errTxePlatformAdmin, errTxePlatformAdmin},
		"a bound person the hub gave the administrator role":                 {errTxePlatformAdmin, errTxePlatformAdmin, errTxePlatformAdmin},
		"an owner's command-line token":                                      {errTxePlatformAdmin, errTxePlatformAdmin, errTxePlatformAdmin},
		"nobody":                                                             {errAuthRequired, errAuthRequired, errAuthRequired},
	}
	for _, mode := range []string{config.TXEAuthzModeOff, config.TXEAuthzModeObserve, config.TXEAuthzModeEnforce} {
		t.Run(mode, func(t *testing.T) {
			f := newIdentityFixture(t, mode)
			callers := adminCallers(f, t)
			require.Len(t, wants, len(callers))
			for name, ctx := range callers {
				w := wants[name]
				expected := map[string]error{config.TXEAuthzModeOff: w.off, config.TXEAuthzModeObserve: w.observe, config.TXEAuthzModeEnforce: w.enforce}[mode]
				got := f.api.requireAdmin(ctx)
				assert.Equal(t, expected, got, "%s in %s", name, mode)
				// The hub's records (txeHubHidden) are decided by the same
				// rule, so the two cannot disagree on who the platform
				// administrator is.
				if expected == errTxePlatformAdmin || expected == nil {
					assert.Equal(t, expected == errTxePlatformAdmin, f.api.txeHubHidden(ctx), "txeHubHidden for %s in %s", name, mode)
				}
			}
		})
	}
}

// Every write to a runtime profile goes through requireRuntimeProfileWrite
// (TXE-6139, Connor 2026-11-07). A protected profile's write is the
// administrator role's, decided as requireAdmin decides. Any other
// profile's write is the manager role and then the platform rule: in off
// and observe every manager and administrator the hub's roles admit
// writes, as before; under enforce the platform administrator alone does;
// a caller held to its owner never does; a request with no hub user is
// refused by the role check first, as before.
func TestRequireRuntimeProfileWriteIsTheManagerRoleThenThePlatformRule(t *testing.T) {
	type want struct{ off, observe, enforce error }
	legacyAdmin := want{nil, nil, errTxePlatformAdmin}
	protectedWants := map[string]want{
		"the builtin administrator":                                          {nil, nil, nil},
		"a second builtin account with the administrator role":               {nil, nil, nil},
		"the platform administrator signed in through the identity provider": {nil, nil, nil},
		"an admin-role API key":                                              legacyAdmin,
		"an administrator a trusted proxy named":                             legacyAdmin,
		"a builtin manager":                                                  {errInsufficientPermissions, errInsufficientPermissions, errInsufficientPermissions},
		"an administrator account from the provider naming no identity":      legacyAdmin,
		"a person the hub gave the administrator role":                       {errTxePlatformAdmin, errTxePlatformAdmin, errTxePlatformAdmin},
		"a bound person the hub gave the administrator role":                 {errTxePlatformAdmin, errTxePlatformAdmin, errTxePlatformAdmin},
		"an owner's command-line token":                                      {errTxePlatformAdmin, errTxePlatformAdmin, errTxePlatformAdmin},
		"nobody":                                                             {errAuthRequired, errAuthRequired, errAuthRequired},
	}
	legacy := legacyAdmin
	wants := map[string]want{
		"the builtin administrator":                                          {nil, nil, nil},
		"a second builtin account with the administrator role":               {nil, nil, nil},
		"the platform administrator signed in through the identity provider": {nil, nil, nil},
		"an admin-role API key":                                              legacy,
		"an administrator a trusted proxy named":                             legacy,
		"a builtin manager":                                                  legacy,
		"an administrator account from the provider naming no identity":      legacy,
		"a person the hub gave the administrator role":                       {errTxePlatformAdmin, errTxePlatformAdmin, errTxePlatformAdmin},
		"a bound person the hub gave the administrator role":                 {errTxePlatformAdmin, errTxePlatformAdmin, errTxePlatformAdmin},
		"an owner's command-line token":                                      {errAuthRequired, errAuthRequired, errAuthRequired},
		"nobody":                                                             {errAuthRequired, errAuthRequired, errAuthRequired},
	}
	for _, mode := range []string{config.TXEAuthzModeOff, config.TXEAuthzModeObserve, config.TXEAuthzModeEnforce} {
		t.Run(mode, func(t *testing.T) {
			f := newIdentityFixture(t, mode)
			callers := adminCallers(f, t)
			require.Len(t, wants, len(callers))
			require.Len(t, protectedWants, len(callers))
			pick := func(w want) error {
				return map[string]error{config.TXEAuthzModeOff: w.off, config.TXEAuthzModeObserve: w.observe, config.TXEAuthzModeEnforce: w.enforce}[mode]
			}
			for name, ctx := range callers {
				assert.Equal(t, pick(wants[name]), f.api.requireRuntimeProfileWrite(ctx, false), "%s writes a plain profile in %s", name, mode)
				assert.Equal(t, pick(protectedWants[name]), f.api.requireRuntimeProfileWrite(ctx, true), "%s writes a protected profile in %s", name, mode)
			}
		})
	}
}

// Without the owner model (no txe.authn), requireAdmin is the role check it
// always was, and a hub with no authentication at all asks nothing.
func TestRequireAdminWithoutOwnersIsTheRoleCheck(t *testing.T) {
	t.Parallel()
	a := &API{authService: struct{ AuthService }{}}
	assert.NoError(t, a.requireAdmin(auth.WithUser(context.Background(), &auth.User{Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderProxy})))
	assert.Equal(t, errInsufficientPermissions, a.requireAdmin(auth.WithUser(context.Background(), &auth.User{Role: auth.RoleManager})))
	assert.Equal(t, errAuthRequired, a.requireAdmin(context.Background()))
	assert.NoError(t, (&API{}).requireAdmin(context.Background()))
}

// In observe, a legacy administrator passes and what enforce would refuse is
// logged once, as a would-deny on the platform with the administer
// permission; the platform administrator and off log nothing.
func TestRequireAdminObserveLogsWhatEnforceWouldRefuse(t *testing.T) {
	logged := &lockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	key := &auth.APIKey{ID: "key_01", Name: "automation", Role: auth.RoleAdmin}
	keyCtx := auth.WithAPIKey(auth.WithUser(context.Background(), &auth.User{Username: "automation", Role: auth.RoleAdmin}), key)
	adminCtx := auth.WithUser(context.Background(), &auth.User{Username: "admin", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderBuiltin})

	observe := newIdentityFixture(t, config.TXEAuthzModeObserve)
	require.NoError(t, observe.api.requireAdmin(keyCtx))
	assert.Contains(t, logged.String(), "txe.authz: would deny")
	assert.Contains(t, logged.String(), "permission=administer")
	assert.Contains(t, logged.String(), "resource_kind=platform")
	assert.Contains(t, logged.String(), "caller=legacy")
	assert.Equal(t, 1, strings.Count(logged.String(), "would deny"), "once per decision")
	assert.NotContains(t, logged.String(), "automation", "the caller is named by class, never by its key")

	// The rule itself logs nothing: a list path asking txeHubHidden per
	// item does not flood the log, and a helper nesting the predicate adds
	// no line.
	logged.Reset()
	for range 3 {
		assert.False(t, observe.api.txeHubHidden(keyCtx))
		_, err := observe.api.txePlatformReserved(keyCtx)
		require.NoError(t, err)
	}
	assert.Empty(t, logged.String(), "the predicate is silent")

	logged.Reset()
	require.NoError(t, observe.api.requireAdmin(adminCtx))
	assert.Empty(t, logged.String(), "the platform administrator is not logged")

	off := newIdentityFixture(t, config.TXEAuthzModeOff)
	require.NoError(t, off.api.requireAdmin(keyCtx))
	assert.Empty(t, logged.String(), "off evaluates nothing")

	enforce := newIdentityFixture(t, config.TXEAuthzModeEnforce)
	assert.Equal(t, errTxePlatformAdmin, enforce.api.requireAdmin(keyCtx))
	assert.Contains(t, logged.String(), "txe.authz: denied")
}

// lockedBuffer is a log sink other goroutines may write to while the test
// reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// The owner store's outage is txeResolve's contract, the same here as for
// every owner decision (CC3's Q1 for #230): a legacy caller and the builtin
// administrator read no store, so an outage changes nothing for them in any
// mode; the platform administrator signed in through the identity provider
// is resolved through the store, so under enforce the outage is a 503 and
// under observe it is allowed and logged as an evaluation failure; a caller
// held to its owner is always under enforce.
func TestRequireAdminOnAnUnreadableOwnerStore(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	key := &auth.APIKey{ID: "key_01", Name: "automation", Role: auth.RoleAdmin}
	keyCtx := auth.WithAPIKey(auth.WithUser(context.Background(), &auth.User{Username: "automation", Role: auth.RoleAdmin}), key)
	builtinAdmin := auth.WithUser(context.Background(), &auth.User{Username: "admin", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderBuiltin})
	ssoAdmin := txeauth.WithPlatformAdminSession(
		auth.WithUser(context.Background(), &auth.User{Username: "connor", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderOIDC, OIDCIssuer: identityIssuer, OIDCSubject: adminSubject}),
		authn.Identity{Issuer: identityIssuer, Subject: adminSubject})
	token := txeauth.WithToken(context.Background(), authn.Principal{Identity: authn.Identity{Issuer: identityIssuer, Subject: "subject-x"}, Class: authn.ClassCLI, ClientID: "dagu-cli", Expires: time.Now().Add(time.Hour)})

	for _, tc := range []struct {
		mode              string
		key, builtin, sso error
		token             error
	}{
		{config.TXEAuthzModeOff, nil, nil, nil, errTxeAuthzUnavailable},
		{config.TXEAuthzModeObserve, nil, nil, nil, errTxeAuthzUnavailable},
		{config.TXEAuthzModeEnforce, errTxePlatformAdmin, nil, errTxeAuthzUnavailable, errTxeAuthzUnavailable},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newIdentityFixture(t, tc.mode)
			f.api.txePlatformAdmins = []config.TXEPlatformAdmin{{Issuer: identityIssuer, Subject: adminSubject}}
			// The store's directory is made on its first write; an empty
			// one that cannot be read is the outage.
			dir := authz.Dir(f.dataDir)
			require.NoError(t, os.MkdirAll(dir, 0o750))
			require.NoError(t, os.Chmod(dir, 0))
			t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })

			assert.Equal(t, tc.key, f.api.requireAdmin(keyCtx), "an admin-role API key")
			assert.Equal(t, tc.builtin, f.api.requireAdmin(builtinAdmin), "the builtin administrator")
			assert.Equal(t, tc.sso, f.api.requireAdmin(ssoAdmin), "the platform administrator from the identity provider")
			assert.Equal(t, tc.token, f.api.requireAdmin(token), "a command-line token")
			// txeHubHidden on the same outage: hidden exactly where
			// requireAdmin refuses.
			assert.Equal(t, tc.sso != nil, f.api.txeHubHidden(ssoAdmin))
		})
	}
}
