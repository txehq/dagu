// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/test"
)

const (
	providerIssuer   = "https://issuer.example/realms/test"
	providerAudience = "dagu-hub"
	providerCLI      = "dagu-cli"
)

var providerKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// providerKeys publishes the provider's signing key on a loopback address,
// as the issuer's JWKS document.
func providerKeys(t *testing.T) string {
	t.Helper()
	pub := providerKey().PublicKey
	doc, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func providerToken(t *testing.T, issuedAt time.Time, lifetime time.Duration) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": providerIssuer, "aud": providerAudience, "azp": providerCLI, "sub": "subject-a", "typ": "Bearer",
		"iat": issuedAt.Unix(), "exp": issuedAt.Add(lifetime).Unix(),
	})
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(providerKey())
	require.NoError(t, err)
	return signed
}

func setupProviderTokenServer(t *testing.T) test.Server {
	t.Helper()
	jwks := providerKeys(t)
	server := test.SetupServer(t, test.WithConfigMutator(func(cfg *config.Config) {
		cfg.Server.Auth.Mode = config.AuthModeBuiltin
		cfg.Server.Auth.Builtin.Token.Secret = "jwt-secret-key"
		cfg.Server.Auth.Builtin.Token.TTL = 24 * time.Hour
		cfg.TXE.Authn = config.TXEAuthnConfig{
			Issuer: providerIssuer, Audience: providerAudience, JWKSURL: jwks + "/certs",
			Clients: []config.TXEAuthnClient{{ID: providerCLI, Class: "cli"}},
		}
	}))
	server.Client().Post("/api/v1/auth/setup", api.SetupRequest{Username: "admin", Password: "adminpass"}).
		ExpectStatus(http.StatusOK).Send(t)
	return server
}

func TestTxeIdentityOverHTTP(t *testing.T) {
	t.Parallel()
	server := setupProviderTokenServer(t)

	resp := server.Client().Post("/api/v1/auth/login", api.LoginRequest{Username: "admin", Password: "adminpass"}).
		ExpectStatus(http.StatusOK).Send(t)
	var login api.LoginResponse
	resp.Unmarshal(t, &login)

	var admin api.TxeIdentity
	server.Client().Get("/api/v1/txe/identity").WithBearerToken(login.Token).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &admin)
	require.Equal(t, api.TxeIdentityPrincipalClassPlatformAdmin, admin.Principal.Class)
	require.Equal(t, api.TxeIdentityAuthzModeOff, admin.AuthzMode)
	require.True(t, admin.PlatformAdmin)

	// A provider token is verified against the published keys, and acts
	// for nobody until it is bound.
	tok := providerToken(t, time.Now(), 5*time.Minute)
	var got api.TxeIdentity
	server.Client().Get("/api/v1/txe/identity").WithBearerToken(tok).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &got)
	require.Equal(t, api.TxeIdentityPrincipalClassCli, got.Principal.Class)
	require.Equal(t, "subject-a", *got.Principal.Subject)
	require.Equal(t, api.TxeIdentityStateUnbound, got.State)
	require.Empty(t, got.Owners)

	// Every route outside /txe refuses it, the native ones included, so it
	// inherits no global access.
	for _, path := range []string{"/api/v1/dags", "/api/v1/dag-runs", "/api/v1/users", "/api/v1/queues", "/api/v1/workers"} {
		server.Client().Get(path).WithBearerToken(tok).ExpectStatus(http.StatusForbidden).Send(t)
	}
	// On /txe it acts for nobody: it sees nothing and may change nothing.
	var jobs api.ListTxeJobs200JSONResponse
	server.Client().Get("/api/v1/txe/jobs").WithBearerToken(tok).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &jobs)
	require.Empty(t, jobs.Jobs)
	var inst api.TxeInstallation
	server.Client().Get("/api/v1/txe/installation").WithBearerToken(tok).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &inst)
	require.Empty(t, inst.Owners)

	// No grace: a token past its expiry, or minted to live longer than five
	// minutes, is refused as a token, not as a missing credential.
	server.Client().Get("/api/v1/txe/identity").WithBearerToken(providerToken(t, time.Now().Add(-6*time.Minute), 5*time.Minute)).
		ExpectStatus(http.StatusUnauthorized).Send(t)
	server.Client().Get("/api/v1/txe/identity").WithBearerToken(providerToken(t, time.Now(), 10*time.Minute)).
		ExpectStatus(http.StatusUnauthorized).Send(t)
}
