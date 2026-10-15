// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

const retiredKeyIssuer = "https://issuer.example/realms/test"

// retiredKeySetup is providerSetup with a real verifier: the issuer publishes
// one key, k1, and has retired k2.
func retiredKeySetup(t *testing.T) (Options, func(kid string, claims jwt.MapClaims) string, jwt.MapClaims) {
	t.Helper()
	published, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	retired, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	verifier, err := authn.NewVerifier(authn.Config{
		Issuer:   retiredKeyIssuer,
		Audience: "dagu",
		Clients:  map[string]authn.Class{"dagu-cli": authn.ClassCLI},
		Keys:     authn.StaticKeys{"k1": {Public: &published.PublicKey}},
		Now:      func() time.Time { return now },
	})
	require.NoError(t, err)
	_, opts := providerSetup()
	opts.ProviderTokens = verifier
	claims := jwt.MapClaims{
		"iss": retiredKeyIssuer, "sub": "s", "aud": "dagu", "azp": "dagu-cli", "typ": "Bearer",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	// k1 signs with the published key, k2 with the retired one.
	keys := map[string]*rsa.PrivateKey{"k1": published, "k2": retired}
	sign := func(kid string, c jwt.MapClaims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
		token.Header["kid"] = kid
		token.Header["typ"] = "JWT"
		signed, err := token.SignedString(keys[kid])
		require.NoError(t, err)
		return signed
	}
	return opts, sign, claims
}

func withClaim(claims jwt.MapClaims, name string, value any) jwt.MapClaims {
	out := jwt.MapClaims{}
	maps.Copy(out, claims)
	if value == nil {
		delete(out, name)
	} else {
		out[name] = value
	}
	return out
}

// A token of the configured issuer on a key the issuer no longer publishes
// is a provider token that must be renewed: 401 invalid_token, never
// accepted. The issuer is read from it only to choose that answer.
func TestMiddleware_RetiredKeyOfTheIssuerIsInvalidToken(t *testing.T) {
	opts, sign, claims := retiredKeySetup(t)

	rec, s := serveWith(t, opts, http.MethodGet, "/api/v1/txe/identity", sign("k1", claims))
	require.Equal(t, http.StatusOK, rec.Code, "control: the published key")
	require.True(t, s.tokOK)

	retired := sign("k2", claims)
	for _, path := range []string{"/api/v1/txe/identity", "/api/v1/dags", "/api/v1/txe/jobs"} {
		rec, s = serveWith(t, opts, http.MethodGet, path, retired)
		require.Equal(t, http.StatusUnauthorized, rec.Code, path)
		require.False(t, s.called, path)
		require.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`, path)
		require.Equal(t, "invalid_token", detailCode(t, rec), path)
	}
}

// Only the configured issuer's name earns that answer. A token on an
// unpublished key that names another issuer, or no issuer, or whose payload
// cannot be read, is not taken for a provider token and gets the usual
// challenge, as before.
func TestMiddleware_UnknownKeyOfAnotherIssuerFallsThrough(t *testing.T) {
	opts, sign, claims := retiredKeySetup(t)
	retired := strings.Split(sign("k2", claims), ".")
	payload := func(raw string) string {
		return retired[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(raw)) + "." + retired[2]
	}
	for name, token := range map[string]string{
		"AnotherIssuer":    sign("k2", withClaim(claims, "iss", "https://issuer.example/realms/other")),
		"IssuerOtherCase":  sign("k2", withClaim(claims, "iss", strings.ToUpper(retiredKeyIssuer))),
		"NoIssuer":         sign("k2", withClaim(claims, "iss", nil)),
		"IssuerNotText":    sign("k2", withClaim(claims, "iss", 7)),
		"PayloadNotBase64": retired[0] + ".!!!." + retired[2],
		"PayloadNotJSON":   payload("not json"),
		"PayloadTwoValues": payload(`{"iss":"` + retiredKeyIssuer + `"}{}`),
		"PayloadArray":     payload(`["` + retiredKeyIssuer + `"]`),
	} {
		rec, s := serveWith(t, opts, http.MethodGet, "/api/v1/txe/identity", token)
		require.Equal(t, http.StatusUnauthorized, rec.Code, name)
		require.False(t, s.called, name)
		require.Equal(t, `Bearer realm="restricted"`, rec.Header().Get("WWW-Authenticate"), name)
	}
}

// Hub tokens and API keys are untouched, refused or accepted as before.
func TestMiddleware_RetiredKeyLeavesHubCredentialsAlone(t *testing.T) {
	opts, _, _ := retiredKeySetup(t)
	for _, bearer := range []string{"hub-jwt", "dagu_key"} {
		rec, s := serveWith(t, opts, http.MethodGet, "/api/v1/dags", bearer)
		require.Equal(t, http.StatusOK, rec.Code, bearer)
		require.True(t, s.userOK, bearer)
		require.False(t, s.tokOK, bearer)
	}
	for _, bearer := range []string{"hub-unknown", "dagu_unknown"} {
		rec, s := serveWith(t, opts, http.MethodGet, "/api/v1/dags", bearer)
		require.Equal(t, http.StatusUnauthorized, rec.Code, bearer)
		require.False(t, s.called, bearer)
		require.NotContains(t, rec.Header().Get("WWW-Authenticate"), "invalid_token", bearer)
	}
}

// A refused provider token is logged at debug by its category only: never
// the token, its claims or the identity it names.
func TestMiddleware_ProviderRefusalIsLoggedByCategoryOnly(t *testing.T) {
	opts, sign, claims := retiredKeySetup(t)
	claims = withClaim(claims, "sub", "subject-that-must-not-be-logged")
	var buf bytes.Buffer
	ctx := logger.WithLogger(context.Background(), logger.NewLogger(logger.WithDebug(), logger.WithFormat("json"), logger.WithWriter(&buf)))

	for _, token := range []string{sign("k2", claims), sign("k1", withClaim(claims, "exp", claims["iat"]))} {
		buf.Reset()
		h := Middleware(opts)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("refused tokens reach no handler") }))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/txe/identity", nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+token)
		h.ServeHTTP(httptest.NewRecorder(), req)
		out := buf.String()
		require.Contains(t, out, "Provider token refused")
		require.Contains(t, out, `"reason"`)
		require.NotContains(t, out, token)
		for part := range strings.SplitSeq(token, ".") {
			require.NotContains(t, out, part)
		}
		require.NotContains(t, out, "subject-that-must-not-be-logged")
		require.NotContains(t, out, retiredKeyIssuer)
	}
}
