// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"bytes"
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	frontendauth "github.com/dagucloud/dagu/v2/internal/service/frontend/auth"
	"github.com/dagucloud/dagu/v2/internal/service/oidcsession"
)

type noRefreshProvider struct{}

func (noRefreshProvider) Establish(context.Context, string) (oidcsession.ClientAuth, oidcsession.Renewal, error) {
	return oidcsession.ClientAuthHeader, oidcsession.Renewal{}, nil
}

func (noRefreshProvider) Refresh(context.Context, string, oidcsession.ClientAuth) (oidcsession.Renewal, error) {
	return oidcsession.Renewal{}, nil
}

func (noRefreshProvider) Revoke(context.Context, string, oidcsession.ClientAuth) error {
	return nil
}

func newTestOIDCSessions(t *testing.T) *oidcsession.Manager {
	t.Helper()
	enc, err := crypto.NewEncryptor("a-test-key-that-is-long-enough-for-aes")
	require.NoError(t, err)
	sessions, err := oidcsession.NewManager(oidcsession.Config{RevalidateAfter: 4 * time.Minute, RevalidateLimit: 5 * time.Minute},
		testutil.NewMemoryBackend().Collection("oidc_sessions"), enc, noRefreshProvider{}, nil)
	require.NoError(t, err)
	return sessions
}

// The UI calls <base path>/oidc-logout exactly when it is told OIDC sessions
// are on, so the flag it is given and the route the hub registers must agree.
func TestOIDCSessionFlagAgreesWithTheSignOutRoute(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		cfg     *frontendauth.BuiltinOIDCConfig
		enabled bool
	}{
		"NoOIDC": {cfg: nil},
		"SessionsOff": {cfg: &frontendauth.BuiltinOIDCConfig{
			OAuth2Config: &oauth2.Config{}, LoginBasePath: "/dagu",
		}},
		"SessionsOn": {cfg: &frontendauth.BuiltinOIDCConfig{
			OAuth2Config: &oauth2.Config{}, LoginBasePath: "/dagu", Sessions: newTestOIDCSessions(t),
		}, enabled: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.enabled, oidcSessionsEnabled(tc.cfg))

			srv := &Server{builtinOIDCCfg: tc.cfg}
			r := chi.NewMux()
			srv.setupOIDCRoutes(r, "/dagu")

			// Without a token the handler answers 401; a missing route is 404.
			recorder := httptest.NewRecorder()
			r.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/dagu/oidc-logout", nil))
			if tc.enabled {
				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
			} else {
				assert.Equal(t, http.StatusNotFound, recorder.Code)
			}
		})
	}
}

func TestBaseTemplateTellsTheUIWhetherOIDCSessionsAreOn(t *testing.T) {
	t.Parallel()

	for _, enabled := range []bool{false, true} {
		tmpl, err := template.New("base").Funcs(defaultFunctions(&funcsConfig{
			OIDCSessionEnabled: enabled,
		})).ParseFS(assetsFS, "templates/base.gohtml")
		require.NoError(t, err)
		tmpl, err = tmpl.Parse(`{{define "content"}}{{end}}`)
		require.NoError(t, err)

		var output bytes.Buffer
		require.NoError(t, tmpl.ExecuteTemplate(&output, "base", nil))
		want := `oidcSessionEnabled: "false" === "true",`
		if enabled {
			want = `oidcSessionEnabled: "true" === "true",`
		}
		assert.Contains(t, output.String(), want)
	}
}
