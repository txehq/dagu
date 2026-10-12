// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// remoteFixture is a verifier whose keys come from a test issuer.
type remoteFixture struct {
	clock    *testClock
	issuer   *testIssuerServer
	keys     *RemoteKeySet
	verifier *Verifier
}

func newRemoteFixture(t *testing.T) *remoteFixture {
	t.Helper()
	f := &remoteFixture{clock: newTestClock(), issuer: newTestIssuerServer(t)}
	f.issuer.Publish(t, rsaJWK("k1", &testRSAKeys()[0].PublicKey))

	keys, err := NewRemoteKeySet(RemoteKeySetConfig{URL: f.issuer.URL(), Now: f.clock.Now, FetchTimeout: 2 * time.Second})
	require.NoError(t, err)
	f.keys = keys

	verifier, err := NewVerifier(Config{
		Issuer:   testIssuer,
		Audience: testAudience,
		Clients:  map[string]Class{testCLI: ClassCLI},
		Keys:     keys,
		Now:      f.clock.Now,
	})
	require.NoError(t, err)
	f.verifier = verifier
	return f
}

func (f *remoteFixture) token(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	return signRS256(t, key, kid, accessClaims(f.clock.Now()))
}

func (f *remoteFixture) reason(token string) Reason {
	_, err := f.verifier.Verify(context.Background(), token)
	return ReasonOf(err)
}

func TestRemoteKeysAreFetchedOnceAndCached(t *testing.T) {
	t.Parallel()
	f := newRemoteFixture(t)
	assert.Zero(t, f.issuer.Fetches(), "building a key set fetches nothing")

	token := f.token(t, testRSAKeys()[0], "k1")
	for range 20 {
		require.Empty(t, f.reason(token))
	}
	assert.Equal(t, 1, f.issuer.Fetches())

	status := f.keys.Status()
	assert.Equal(t, 1, status.Keys)
	assert.True(t, status.FetchedAt.Equal(f.clock.Now()))
	assert.Empty(t, status.LastError)
}

// Many requests arriving with an empty cache cause one fetch, not one each.
func TestRemoteKeysConcurrentColdStart(t *testing.T) {
	t.Parallel()
	f := newRemoteFixture(t)
	token := f.token(t, testRSAKeys()[0], "k1")

	const callers = 64
	reasons := make([]Reason, callers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range callers {
		wg.Go(func() {
			<-start
			reasons[i] = f.reason(token)
		})
	}
	close(start)
	wg.Wait()

	for i, reason := range reasons {
		assert.Empty(t, reason, "caller %d", i)
	}
	assert.Equal(t, 1, f.issuer.Fetches())
}

// A token that names a key nobody published can cause one fetch a minute and
// no more, however many such tokens arrive.
func TestRemoteKeysUnknownKeyRefetchIsLimited(t *testing.T) {
	t.Parallel()
	f := newRemoteFixture(t)
	require.Empty(t, f.reason(f.token(t, testRSAKeys()[0], "k1")))
	require.Equal(t, 1, f.issuer.Fetches())

	for i := range 50 {
		assert.Equal(t, ReasonUnknownKey, f.reason(f.token(t, testRSAKeys()[1], "nobody-"+string(rune('a'+i%26)))))
	}
	assert.Equal(t, 1, f.issuer.Fetches(), "the first fetch was under a minute ago")

	f.clock.Advance(time.Minute)
	for range 50 {
		assert.Equal(t, ReasonUnknownKey, f.reason(f.token(t, testRSAKeys()[1], "nobody")))
	}
	assert.Equal(t, 2, f.issuer.Fetches())
	require.Empty(t, f.reason(f.token(t, testRSAKeys()[0], "k1")), "known keys are unaffected")
}

func TestRemoteKeysRotation(t *testing.T) {
	t.Parallel()
	f := newRemoteFixture(t)
	oldKey, newKey := testRSAKeys()[0], testRSAKeys()[1]
	require.Empty(t, f.reason(f.token(t, oldKey, "k1")))

	// The issuer starts signing with a new key and still publishes the old.
	f.issuer.Publish(t, rsaJWK("k1", &oldKey.PublicKey), rsaJWK("k2", &newKey.PublicKey))
	assert.Equal(t, ReasonUnknownKey, f.reason(f.token(t, newKey, "k2")), "the refetch limit has not passed")
	f.clock.Advance(time.Minute)
	require.Empty(t, f.reason(f.token(t, newKey, "k2")))
	require.Empty(t, f.reason(f.token(t, oldKey, "k1")))
	assert.Equal(t, 2, f.issuer.Fetches())

	// The issuer withdraws the old key. It stops being trusted when the
	// cached set reaches its maximum age, without any token naming a new key.
	f.issuer.Publish(t, rsaJWK("k2", &newKey.PublicKey))
	f.clock.Advance(time.Hour - time.Second)
	require.Empty(t, f.reason(f.token(t, oldKey, "k1")), "the cached set is not old enough to replace")
	f.clock.Advance(time.Second)
	assert.Equal(t, ReasonUnknownKey, f.reason(f.token(t, oldKey, "k1")))
	require.Empty(t, f.reason(f.token(t, newKey, "k2")))
	assert.Equal(t, 3, f.issuer.Fetches())
}

// An outage does not stop a token that is still within its own lifetime, and
// it does not keep a token alive past its expiry.
func TestRemoteKeysOutageNeitherBlocksNorExtends(t *testing.T) {
	t.Parallel()
	f := newRemoteFixture(t)
	key := testRSAKeys()[0]
	token := f.token(t, key, "k1")
	require.Empty(t, f.reason(token))

	f.issuer.Down()

	f.clock.Advance(4 * time.Minute)
	require.Empty(t, f.reason(token), "four minutes into the outage the token is still its own five minutes long")
	assert.Equal(t, ReasonKeysUnavailable, f.reason(f.token(t, testRSAKeys()[1], "k2")),
		"an unknown key during an outage is the provider's failure, not the token's")

	f.clock.Advance(time.Minute - time.Nanosecond)
	require.Empty(t, f.reason(token), "the instant before expiry")
	f.clock.Advance(time.Nanosecond)
	assert.Equal(t, ReasonExpired, f.reason(token), "the outage gives no grace")

	status := f.keys.Status()
	assert.Equal(t, 1, status.Keys)
	assert.NotEmpty(t, status.LastError)
	assert.True(t, status.AttemptedAt.After(status.FetchedAt))
}

// A set that cannot be replaced is used for a bounded time and then not at
// all. Otherwise a key the issuer withdrew would stay trusted for as long as
// the fetch kept failing, and whoever held it could go on signing tokens with
// fresh times.
func TestRemoteKeysUnreplaceableSetRunsOut(t *testing.T) {
	t.Parallel()
	f := newRemoteFixture(t)
	key := testRSAKeys()[0]
	require.Empty(t, f.reason(f.token(t, key, "k1")))
	fetchedAt := f.clock.Now()
	assert.True(t, f.keys.Status().UsableUntil.Equal(fetchedAt.Add(time.Hour+MaxTokenLifetime)))

	f.issuer.Down()

	// Up to the bound, a token signed with the cached key verifies. The
	// latest token the issuer could have signed before it became unreachable
	// expires inside this window.
	f.clock.Advance(time.Hour + MaxTokenLifetime - time.Nanosecond)
	require.Empty(t, f.reason(f.token(t, key, "k1")))

	// At the bound, a token signed with that key and carrying fresh times is
	// refused, and the refusal blames the provider.
	f.clock.Advance(time.Nanosecond)
	for range 3 {
		assert.Equal(t, ReasonKeysUnavailable, f.reason(f.token(t, key, "k1")))
	}
	f.clock.Advance(24 * time.Hour)
	assert.Equal(t, ReasonKeysUnavailable, f.reason(f.token(t, key, "k1")))
}

// A set that ran out is used again as soon as a fetch replaces it.
func TestRemoteKeysRunOutSetRecovers(t *testing.T) {
	t.Parallel()
	f := newRemoteFixture(t)
	key := testRSAKeys()[0]
	require.Empty(t, f.reason(f.token(t, key, "k1")))

	f.issuer.PublishRaw(http.StatusBadGateway, nil)
	f.clock.Advance(2 * time.Hour)
	assert.Equal(t, ReasonKeysUnavailable, f.reason(f.token(t, key, "k1")))

	f.issuer.Publish(t, rsaJWK("k1", &key.PublicKey))
	assert.Equal(t, ReasonKeysUnavailable, f.reason(f.token(t, key, "k1")), "inside the refetch interval")
	f.clock.Advance(time.Minute)
	require.Empty(t, f.reason(f.token(t, key, "k1")))
	assert.Empty(t, f.keys.Status().LastError)
}

// A process that starts while the issuer is unreachable can verify nothing.
func TestRemoteKeysColdStartDuringOutage(t *testing.T) {
	t.Parallel()
	f := newRemoteFixture(t)
	f.issuer.Down()

	token := f.token(t, testRSAKeys()[0], "k1")
	for range 5 {
		_, err := f.verifier.Verify(context.Background(), token)
		require.Error(t, err)
		assert.True(t, ProviderUnavailable(err), err.Error())
	}
	assert.Zero(t, f.keys.Status().Keys)
}

// A failing issuer is asked again only after the refetch interval, and
// recovery is picked up then.
func TestRemoteKeysRecoverAfterFailure(t *testing.T) {
	t.Parallel()
	f := newRemoteFixture(t)
	key := testRSAKeys()[0]
	good := rsaJWK("k1", &key.PublicKey)

	f.issuer.PublishRaw(http.StatusServiceUnavailable, []byte("starting"))
	assert.Equal(t, ReasonKeysUnavailable, f.reason(f.token(t, key, "k1")))
	assert.Equal(t, ReasonKeysUnavailable, f.reason(f.token(t, key, "k1")))
	assert.Equal(t, 1, f.issuer.Fetches())

	f.issuer.Publish(t, good)
	assert.Equal(t, ReasonKeysUnavailable, f.reason(f.token(t, key, "k1")), "still inside the interval")
	f.clock.Advance(time.Minute)
	require.Empty(t, f.reason(f.token(t, key, "k1")))
	assert.Equal(t, 2, f.issuer.Fetches())
	assert.Empty(t, f.keys.Status().LastError)
}

// A bad document from the issuer never replaces a good cached set.
func TestRemoteKeysBadDocumentKeepsCachedKeys(t *testing.T) {
	t.Parallel()
	key := testRSAKeys()[0]
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	good := rsaJWK("k1", &key.PublicKey)

	documents := map[string]func(t *testing.T, iss *testIssuerServer){
		"ServerError": func(_ *testing.T, iss *testIssuerServer) { iss.PublishRaw(http.StatusInternalServerError, nil) },
		"Redirect": func(_ *testing.T, iss *testIssuerServer) {
			iss.PublishRaw(http.StatusFound, nil)
		},
		"NotJSON":  func(_ *testing.T, iss *testIssuerServer) { iss.PublishRaw(http.StatusOK, []byte("<html>")) },
		"EmptySet": func(t *testing.T, iss *testIssuerServer) { iss.Publish(t) },
		"TooLarge": func(_ *testing.T, iss *testIssuerServer) {
			iss.PublishRaw(http.StatusOK, []byte(strings.Repeat(" ", maxKeySetBytes+1)))
		},
		"WeakKey": func(t *testing.T, iss *testIssuerServer) { iss.Publish(t, good, rsaJWK("k2", &weak.PublicKey)) },
		"RepeatedID": func(t *testing.T, iss *testIssuerServer) {
			iss.Publish(t, good, rsaJWK("k1", &testRSAKeys()[1].PublicKey))
		},
		"BrokenModulus": func(t *testing.T, iss *testIssuerServer) {
			broken := rsaJWK("k2", &key.PublicKey)
			broken["n"] = "!!!"
			iss.Publish(t, good, broken)
		},
		"PointOffTheCurve": func(t *testing.T, iss *testIssuerServer) {
			ec := newECKey(t, elliptic.P256())
			off := ecJWK("k2", "P-256", "ES256", &ec.PublicKey)
			off["y"] = off["x"]
			iss.Publish(t, good, off)
		},
		// Keys Go's RSA code refuses must not replace a key that works.
		"EvenModulus": func(t *testing.T, iss *testIssuerServer) {
			even := rsaJWK("k1", &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537})
			iss.Publish(t, even)
		},
		"ExponentTooLarge": func(t *testing.T, iss *testIssuerServer) {
			large := rsaJWK("k1", &key.PublicKey)
			large["e"] = b64([]byte{0x80, 0x00, 0x00, 0x01})
			iss.Publish(t, large)
		},
		"ModulusTooLarge": func(t *testing.T, iss *testIssuerServer) {
			huge := new(big.Int).Lsh(big.NewInt(1), maxRSAKeyBits)
			huge.Add(huge, big.NewInt(1))
			iss.Publish(t, rsaJWK("k1", &rsa.PublicKey{N: huge, E: 65537}))
		},
		"OnlyEncryptionKeys": func(t *testing.T, iss *testIssuerServer) {
			enc := rsaJWK("k1", &key.PublicKey)
			enc["use"] = "enc"
			iss.Publish(t, enc)
		},
	}

	for name, publish := range documents {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newRemoteFixture(t)
			require.Empty(t, f.reason(f.token(t, key, "k1")))

			publish(t, f.issuer)
			f.clock.Advance(time.Hour)
			require.Empty(t, f.reason(f.token(t, key, "k1")), "the cached key stays in use")
			assert.Equal(t, 2, f.issuer.Fetches())
			assert.NotEmpty(t, f.keys.Status().LastError)
			assert.Equal(t, 1, f.keys.Status().Keys)

			// The same document on a cold start gives no key at all.
			cold := newRemoteFixture(t)
			publish(t, cold.issuer)
			assert.Equal(t, ReasonKeysUnavailable, cold.reason(cold.token(t, key, "k1")))
		})
	}
}

func TestRemoteKeysSupportedKinds(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	issuer := newTestIssuerServer(t)
	rsaKey := testRSAKeys()[0]
	p256, p384, p521 := newECKey(t, elliptic.P256()), newECKey(t, elliptic.P384()), newECKey(t, elliptic.P521())
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	encryption := rsaJWK("enc", &rsaKey.PublicKey)
	encryption["use"] = "enc"
	noUse := rsaJWK("no-use", &rsaKey.PublicKey)
	delete(noUse, "use")
	delete(noUse, "alg")
	noID := rsaJWK("", &rsaKey.PublicKey)
	issuer.Publish(t,
		rsaJWK("rsa", &rsaKey.PublicKey), noUse, encryption, noID,
		ecJWK("p256", "P-256", "ES256", &p256.PublicKey),
		ecJWK("p384", "P-384", "ES384", &p384.PublicKey),
		ecJWK("p521", "P-521", "ES512", &p521.PublicKey),
		edJWK("ed", edPublic),
		map[string]any{"kty": "EC", "kid": "other-curve", "crv": "secp256k1", "x": "AA", "y": "AA"},
		map[string]any{"kty": "OKP", "kid": "x25519", "crv": "X25519", "x": "AA"},
		map[string]any{"kty": "oct", "kid": "secret", "k": "AA"},
	)

	keys, err := NewRemoteKeySet(RemoteKeySetConfig{URL: issuer.URL(), Now: clock.Now})
	require.NoError(t, err)
	verifier, err := NewVerifier(Config{
		Issuer:     testIssuer,
		Audience:   testAudience,
		Clients:    map[string]Class{testCLI: ClassCLI},
		Algorithms: []string{"RS256", "ES256", "ES384", "ES512", "EdDSA"},
		Keys:       keys,
		Now:        clock.Now,
	})
	require.NoError(t, err)
	claims := accessClaims(clock.Now())
	reason := func(token string) Reason {
		_, err := verifier.Verify(context.Background(), token)
		return ReasonOf(err)
	}

	assert.Empty(t, reason(sign(t, jwt.SigningMethodRS256, rsaKey, "rsa", claims, nil)))
	assert.Empty(t, reason(sign(t, jwt.SigningMethodRS256, rsaKey, "no-use", claims, nil)))
	assert.Empty(t, reason(sign(t, jwt.SigningMethodES256, p256, "p256", claims, nil)))
	assert.Empty(t, reason(sign(t, jwt.SigningMethodES384, p384, "p384", claims, nil)))
	assert.Empty(t, reason(sign(t, jwt.SigningMethodES512, p521, "p521", claims, nil)))
	assert.Empty(t, reason(sign(t, jwt.SigningMethodEdDSA, edPrivate, "ed", claims, nil)))

	for _, skipped := range []string{"enc", "other-curve", "x25519", "secret"} {
		assert.Equal(t, ReasonUnknownKey, reason(sign(t, jwt.SigningMethodRS256, rsaKey, skipped, claims, nil)), skipped)
	}
	assert.Equal(t, 6, keys.Status().Keys)
	assert.Equal(t, 1, issuer.Fetches())
}

// One caller that gives up must not fail the fetch for everyone and use up
// the interval before the next attempt.
func TestRemoteKeysFetchOutlivesItsCaller(t *testing.T) {
	t.Parallel()
	f := newRemoteFixture(t)
	token := f.token(t, testRSAKeys()[0], "k1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.verifier.Verify(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, 1, f.issuer.Fetches())
	assert.Empty(t, f.keys.Status().LastError)
}

// While one caller replaces an old set, the others use the set they have.
func TestRemoteKeysStaleRefreshDelaysNobodyElse(t *testing.T) {
	t.Parallel()
	f := newRemoteFixture(t)
	key := testRSAKeys()[0]
	require.Empty(t, f.reason(f.token(t, key, "k1")))

	release := make(chan struct{})
	// Registered after the issuer's own cleanup, so it runs first and the
	// held request is let go on every path, a failed assertion included.
	letGo := sync.OnceFunc(func() { close(release) })
	t.Cleanup(letGo)
	f.issuer.mu.Lock()
	f.issuer.delay = release
	f.issuer.mu.Unlock()
	f.clock.Advance(time.Hour)
	token := f.token(t, key, "k1")

	refreshing := make(chan Reason, 1)
	go func() { refreshing <- f.reason(token) }()
	require.Eventually(t, func() bool { return f.issuer.Fetches() == 2 }, 5*time.Second, time.Millisecond)

	done := make(chan Reason, 1)
	go func() { done <- f.reason(token) }()
	select {
	case reason := <-done:
		assert.Empty(t, reason)
	case <-time.After(5 * time.Second):
		t.Fatal("a caller waited for another caller's refresh")
	}

	letGo()
	assert.Empty(t, <-refreshing)
	assert.Equal(t, 2, f.issuer.Fetches())
}

// A redirect is never followed, whatever HTTP client the caller supplies. The
// URL is checked once; a redirect could lead anywhere, plain http included.
func TestRemoteKeysNeverFollowRedirects(t *testing.T) {
	t.Parallel()
	attackerKey := testRSAKeys()[2]
	elsewhere := newTestIssuerServer(t)
	elsewhere.Publish(t, rsaJWK("k1", &attackerKey.PublicKey))

	redirecting := httptest.NewServer(http.RedirectHandler(elsewhere.URL(), http.StatusFound))
	t.Cleanup(redirecting.Close)

	for name, client := range map[string]*http.Client{
		"DefaultClient":  nil,
		"CallersClient":  {},
		"CallersPolicy":  {CheckRedirect: func(*http.Request, []*http.Request) error { return nil }},
		"CallersTimeout": {Timeout: 3 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			clock := newTestClock()
			keys, err := NewRemoteKeySet(RemoteKeySetConfig{URL: redirecting.URL, HTTPClient: client, Now: clock.Now})
			require.NoError(t, err)
			verifier, err := NewVerifier(Config{
				Issuer: testIssuer, Audience: testAudience, Clients: map[string]Class{testCLI: ClassCLI},
				Keys: keys, Now: clock.Now,
			})
			require.NoError(t, err)

			_, err = verifier.Verify(context.Background(), signRS256(t, attackerKey, "k1", accessClaims(clock.Now())))
			require.Error(t, err)
			assert.True(t, ProviderUnavailable(err), err.Error())
			assert.Zero(t, keys.Status().Keys)
		})
	}
	assert.Zero(t, elsewhere.Fetches(), "the redirect target was never asked")
}

// The caller's client is copied, so its own redirect policy is left alone.
func TestRemoteKeysLeaveTheCallersClientAlone(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	_, err := NewRemoteKeySet(RemoteKeySetConfig{URL: "https://issuer.example/certs", HTTPClient: client})
	require.NoError(t, err)
	assert.Nil(t, client.CheckRedirect)
}

func TestNewRemoteKeySetRefusesConfig(t *testing.T) {
	t.Parallel()

	for _, good := range []string{
		"https://issuer.example/realms/test/protocol/openid-connect/certs",
		"http://127.0.0.1:8080/certs",
		"http://[::1]:8080/certs",
		"http://localhost:8080/certs",
	} {
		_, err := NewRemoteKeySet(RemoteKeySetConfig{URL: good})
		require.NoError(t, err, good)
	}
	for _, bad := range []string{
		"",
		"issuer.example/certs",
		"http://issuer.example/certs",
		"http://10.0.0.5/certs",
		"ftp://issuer.example/certs",
		"https://user:pass@issuer.example/certs",
		"https://issuer.example/certs#fragment",
		"https:///certs",
	} {
		_, err := NewRemoteKeySet(RemoteKeySetConfig{URL: bad})
		require.Error(t, err, bad)
	}
	_, err := NewRemoteKeySet(RemoteKeySetConfig{URL: "https://issuer.example/certs", MinRefetchInterval: -time.Second})
	require.Error(t, err)

	// The fetch limit cannot be configured below one a minute.
	for _, interval := range []time.Duration{time.Nanosecond, time.Second, time.Minute - time.Nanosecond} {
		_, err := NewRemoteKeySet(RemoteKeySetConfig{URL: "https://issuer.example/certs", MinRefetchInterval: interval})
		require.ErrorContains(t, err, "minimum refetch interval", interval.String())
	}
	for _, interval := range []time.Duration{0, time.Minute, 10 * time.Minute} {
		_, err := NewRemoteKeySet(RemoteKeySetConfig{URL: "https://issuer.example/certs", MinRefetchInterval: interval})
		require.NoError(t, err, interval.String())
	}
}

func TestParseKeySetLimits(t *testing.T) {
	t.Parallel()
	key := &testRSAKeys()[0].PublicKey

	many := make([]map[string]any, maxKeySetKeys+1)
	for i := range many {
		many[i] = map[string]any{"kty": "oct", "kid": "k"}
	}
	body, err := json.Marshal(map[string]any{"keys": many})
	require.NoError(t, err)
	_, err = parseKeySet(body)
	require.ErrorContains(t, err, "too many keys")

	even := rsaJWK("k1", key)
	even["e"] = b64([]byte{2})
	body, err = json.Marshal(map[string]any{"keys": []any{even}})
	require.NoError(t, err)
	_, err = parseKeySet(body)
	require.ErrorContains(t, err, "exponent")

	body, err = json.Marshal(map[string]any{"keys": []any{rsaJWK("k1", key)}})
	require.NoError(t, err)
	keys, err := parseKeySet(body)
	require.NoError(t, err)
	assert.Equal(t, "RS256", keys["k1"].Algorithm)
}

func TestStaticKeys(t *testing.T) {
	t.Parallel()
	keys := StaticKeys{"k1": {Public: &testRSAKeys()[0].PublicKey}}

	_, err := keys.Key(context.Background(), "k1")
	require.NoError(t, err)
	_, err = keys.Key(context.Background(), "k2")
	assert.Equal(t, ReasonUnknownKey, ReasonOf(err))
}

// A key source that fails without saying why is the provider's failure.
type failingKeys struct{}

func (failingKeys) Key(context.Context, string) (Key, error) {
	return Key{}, context.DeadlineExceeded
}

func TestVerifyTreatsAnUnexplainedKeyFailureAsUnavailable(t *testing.T) {
	t.Parallel()
	f := newFixture(t, func(cfg *Config) { cfg.Keys = failingKeys{} })

	_, err := f.verifier.Verify(context.Background(), f.token(t, nil))
	require.Error(t, err)
	assert.True(t, ProviderUnavailable(err))
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}
