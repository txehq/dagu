// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer   = "https://issuer.example/realms/test"
	testAudience = "dagu-hub"
	testCLI      = "dagu-cli"
	testWorker   = "dagu-worker"
	testReviewer = "dagu-reviewer"
)

// RSA keys are slow to make, so the tests share a few.
var testRSAKeys = sync.OnceValue(func() []*rsa.PrivateKey {
	keys := make([]*rsa.PrivateKey, 3)
	for i := range keys {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		keys[i] = key
	}
	return keys
})

// testClock is a clock the test moves by hand.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testIssuerServer publishes a key set the test can change, break and count.
type testIssuerServer struct {
	server  *httptest.Server
	fetches atomic.Int64

	mu     sync.Mutex
	body   []byte
	status int
	delay  chan struct{}
}

func newTestIssuerServer(t *testing.T) *testIssuerServer {
	t.Helper()
	iss := &testIssuerServer{status: http.StatusOK}
	iss.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		iss.fetches.Add(1)
		iss.mu.Lock()
		body, status, delay := iss.body, iss.status, iss.delay
		iss.mu.Unlock()
		if delay != nil {
			<-delay
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(iss.server.Close)
	return iss
}

func (iss *testIssuerServer) URL() string { return iss.server.URL + "/certs" }

// Publish replaces the published key set.
func (iss *testIssuerServer) Publish(t *testing.T, keys ...map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"keys": keys})
	require.NoError(t, err)
	iss.PublishRaw(http.StatusOK, body)
}

func (iss *testIssuerServer) PublishRaw(status int, body []byte) {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	iss.status, iss.body = status, body
}

// Down makes the issuer unreachable: connections are refused.
func (iss *testIssuerServer) Down() { iss.server.Close() }

func (iss *testIssuerServer) Fetches() int { return int(iss.fetches.Load()) }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaJWK(kid string, key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
	}
}

func ecJWK(kid, crv, alg string, key *ecdsa.PublicKey) map[string]any {
	raw, err := key.Bytes()
	if err != nil {
		panic(err)
	}
	size := (len(raw) - 1) / 2
	return map[string]any{
		"kty": "EC", "kid": kid, "use": "sig", "alg": alg, "crv": crv,
		"x": b64(raw[1 : 1+size]), "y": b64(raw[1+size:]),
	}
}

func edJWK(kid string, key ed25519.PublicKey) map[string]any {
	return map[string]any{"kty": "OKP", "kid": kid, "use": "sig", "alg": "EdDSA", "crv": "Ed25519", "x": b64(key)}
}

func newECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return key
}

// accessClaims returns the claims of an access token as the provider issues
// it: issued now, valid for five minutes, for the CLI client.
func accessClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": testIssuer,
		"sub": "9f1c6d1e-0000-4000-8000-000000000001",
		"aud": []string{testAudience, "account"},
		"azp": testCLI,
		"typ": "Bearer",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		// Present in real tokens and never read by the verifier.
		"email":              "someone@example.com",
		"preferred_username": "someone",
		"name":               "Some One",
	}
}

func with(claims jwt.MapClaims, changes map[string]any) jwt.MapClaims {
	out := jwt.MapClaims{}
	maps.Copy(out, claims)
	for k, v := range changes {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

// sign makes a token with the given header fields on top of alg and kid.
func sign(t *testing.T, method jwt.SigningMethod, key crypto.PrivateKey, kid string, claims jwt.MapClaims, header map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	for k, v := range header {
		if v == nil {
			delete(token.Header, k)
			continue
		}
		token.Header[k] = v
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// signRawRS256 signs a header and a payload exactly as given, for tokens no
// JWT library would produce.
func signRawRS256(t *testing.T, key *rsa.PrivateKey, header, payload string) string {
	t.Helper()
	signingInput := b64([]byte(header)) + "." + b64([]byte(payload))
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return signingInput + "." + b64(signature)
}

func claimsJSON(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	require.NoError(t, err)
	return string(raw)
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	return sign(t, jwt.SigningMethodRS256, key, kid, claims, nil)
}

// fixture is a verifier over one static RSA key and a hand-moved clock.
type fixture struct {
	clock    *testClock
	key      *rsa.PrivateKey
	verifier *Verifier
}

func newFixture(t *testing.T, change func(*Config)) *fixture {
	t.Helper()
	f := &fixture{clock: newTestClock(), key: testRSAKeys()[0]}
	cfg := Config{
		Issuer:   testIssuer,
		Audience: testAudience,
		Clients:  map[string]Class{testCLI: ClassCLI, testWorker: ClassWorker, testReviewer: ClassReviewer},
		Keys:     StaticKeys{"k1": {Public: &f.key.PublicKey, Algorithm: "RS256"}},
		Now:      f.clock.Now,
	}
	if change != nil {
		change(&cfg)
	}
	verifier, err := NewVerifier(cfg)
	require.NoError(t, err)
	f.verifier = verifier
	return f
}

func (f *fixture) token(t *testing.T, changes map[string]any) string {
	t.Helper()
	return signRS256(t, f.key, "k1", with(accessClaims(f.clock.Now()), changes))
}
