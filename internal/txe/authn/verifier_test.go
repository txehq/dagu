// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireRefused(t *testing.T, f *fixture, token string, want Reason) {
	t.Helper()
	principal, err := f.verifier.Verify(context.Background(), token)
	require.Error(t, err)
	assert.Equal(t, want, ReasonOf(err), err.Error())
	assert.Equal(t, Principal{}, principal, "a refusal returns no principal")
	// A refusal must be safe to log.
	assert.NotContains(t, err.Error(), token)
	for part := range strings.SplitSeq(token, ".") {
		if len(part) > 16 {
			assert.NotContains(t, err.Error(), part)
		}
	}
}

func TestVerifyAcceptsAnAccessTokenPerClass(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)

	for client, class := range map[string]Class{testCLI: ClassCLI, testWorker: ClassWorker, testReviewer: ClassReviewer} {
		principal, err := f.verifier.Verify(context.Background(), f.token(t, map[string]any{"azp": client}))
		require.NoError(t, err, client)

		assert.Equal(t, Identity{Issuer: testIssuer, Subject: "9f1c6d1e-0000-4000-8000-000000000001"}, principal.Identity)
		assert.Equal(t, class, principal.Class)
		assert.Equal(t, client, principal.ClientID)
		assert.True(t, principal.IssuedAt.Equal(f.clock.Now()))
		assert.True(t, principal.Expires.Equal(f.clock.Now().Add(5*time.Minute)))
		assert.False(t, principal.IsPerson(), "a bearer token never yields a person")
		assert.True(t, class.Bearer())
	}
}

// The provider's session id is reported as it is in the token, and never
// invented. Two sign-ins by one subject to one client differ only in it.
func TestVerifyReportsTheSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)

	first, err := f.verifier.Verify(context.Background(), f.token(t, map[string]any{"azp": testWorker, "sid": "session-a"}))
	require.NoError(t, err)
	second, err := f.verifier.Verify(context.Background(), f.token(t, map[string]any{"azp": testWorker, "sid": "session-b"}))
	require.NoError(t, err)
	assert.Equal(t, "session-a", first.SessionID)
	assert.Equal(t, "session-b", second.SessionID)
	assert.Equal(t, first.Identity, second.Identity)
	assert.Equal(t, first.Class, second.Class)
	assert.Equal(t, first.ClientID, second.ClientID)

	none, err := f.verifier.Verify(context.Background(), f.token(t, nil))
	require.NoError(t, err, "a token that names no session is still an access token")
	assert.Empty(t, none.SessionID)

	for name, sid := range map[string]any{"Number": 7, "List": []string{"session-a"}, "Empty": "", "Object": map[string]any{"id": "session-a"}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requireRefused(t, f, f.token(t, map[string]any{"sid": sid}), ReasonMalformed)
		})
	}
}

// Email, username and display name never identify anyone: equal ones with a
// different subject, or the same subject from a different issuer, are
// different identities.
func TestIdentityIsIssuerAndSubjectOnly(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)

	first, err := f.verifier.Verify(context.Background(), f.token(t, map[string]any{"sub": "subject-a"}))
	require.NoError(t, err)
	second, err := f.verifier.Verify(context.Background(), f.token(t, map[string]any{"sub": "subject-b"}))
	require.NoError(t, err)
	assert.NotEqual(t, first.Identity, second.Identity, "same email, username and name, different subject")

	other := newFixture(t, func(cfg *Config) { cfg.Issuer = "https://issuer.example/realms/other" })
	third, err := other.verifier.Verify(context.Background(),
		other.token(t, map[string]any{"sub": "subject-a", "iss": "https://issuer.example/realms/other"}))
	require.NoError(t, err)
	assert.NotEqual(t, first.Identity, third.Identity, "same subject, different issuer")
	assert.Equal(t, first.Subject, third.Subject)
}

func TestVerifyRefusesByClaim(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	now := f.clock.Now().Unix()

	tests := []struct {
		name    string
		changes map[string]any
		want    Reason
	}{
		{"IssuerWithTrailingSlash", map[string]any{"iss": testIssuer + "/"}, ReasonIssuer},
		{"IssuerOtherRealm", map[string]any{"iss": "https://issuer.example/realms/master"}, ReasonIssuer},
		{"IssuerOtherCase", map[string]any{"iss": strings.ToUpper(testIssuer)}, ReasonIssuer},
		{"IssuerMissing", map[string]any{"iss": nil}, ReasonIssuer},
		{"IssuerNotAString", map[string]any{"iss": 7}, ReasonIssuer},

		{"AudienceMissing", map[string]any{"aud": nil}, ReasonAudience},
		{"AudienceOther", map[string]any{"aud": "account"}, ReasonAudience},
		{"AudienceListWithoutOurs", map[string]any{"aud": []string{"account", "other"}}, ReasonAudience},
		{"AudiencePrefix", map[string]any{"aud": testAudience + "-staging"}, ReasonAudience},
		{"AudienceListWithANonString", map[string]any{"aud": []any{testAudience, 7}}, ReasonAudience},
		{"AudienceAsObject", map[string]any{"aud": map[string]any{testAudience: true}}, ReasonAudience},

		{"ClientMissing", map[string]any{"azp": nil}, ReasonClient},
		{"ClientUnknown", map[string]any{"azp": "grafana"}, ReasonClient},
		{"ClientOtherCase", map[string]any{"azp": strings.ToUpper(testCLI)}, ReasonClient},
		{"ClientNotAString", map[string]any{"azp": []string{testCLI}}, ReasonClient},

		{"SubjectMissing", map[string]any{"sub": nil}, ReasonSubject},
		{"SubjectEmpty", map[string]any{"sub": ""}, ReasonSubject},

		{"IDToken", map[string]any{"typ": "ID"}, ReasonTokenType},
		{"RefreshToken", map[string]any{"typ": "Refresh"}, ReasonTokenType},
		{"OfflineToken", map[string]any{"typ": "Offline"}, ReasonTokenType},
		{"TypeMissing", map[string]any{"typ": nil}, ReasonTokenType},
		{"TypeOtherCase", map[string]any{"typ": "bearer"}, ReasonTokenType},

		{"IssuedAtMissing", map[string]any{"iat": nil}, ReasonTimes},
		{"IssuedAtAsText", map[string]any{"iat": "now"}, ReasonTimes},
		{"IssuedAtZero", map[string]any{"iat": 0}, ReasonTimes},
		{"IssuedAtNegative", map[string]any{"iat": -5}, ReasonTimes},
		{"ExpiryMissing", map[string]any{"exp": nil}, ReasonTimes},
		{"ExpiryAsText", map[string]any{"exp": "later"}, ReasonTimes},
		{"ExpiryAbsurd", map[string]any{"exp": 1e30}, ReasonTimes},
		{"ExpiryAtIssue", map[string]any{"exp": now}, ReasonTimes},
		{"ExpiryBeforeIssue", map[string]any{"exp": now - 10}, ReasonTimes},
		{"NotBeforeAsText", map[string]any{"nbf": "soon"}, ReasonTimes},

		// The provider's realm default in the measurement was 600 s; a client
		// without the per-client setting gets such a token.
		{"LifetimeTenMinutes", map[string]any{"exp": now + 600}, ReasonLifetime},
		{"LifetimeOneSecondOver", map[string]any{"exp": now + 301}, ReasonLifetime},
		{"LifetimeOneDay", map[string]any{"exp": now + 86400}, ReasonLifetime},

		{"IssuedInTheFuture", map[string]any{"iat": now + 1, "exp": now + 200}, ReasonNotYetValid},
		{"NotValidYet", map[string]any{"nbf": now + 1}, ReasonNotYetValid},

		{"IssuedLongAgoAndExpired", map[string]any{"iat": now - 400, "exp": now - 100}, ReasonExpired},
		{"ExpiresThisInstant", map[string]any{"iat": now - 300, "exp": now}, ReasonExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			requireRefused(t, f, f.token(t, tt.changes), tt.want)
		})
	}
}

func TestVerifyLifetimeCap(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	now := f.clock.Now().Unix()

	for _, seconds := range []int64{1, 60, 299, 300} {
		_, err := f.verifier.Verify(context.Background(), f.token(t, map[string]any{"exp": now + seconds}))
		require.NoError(t, err, "%d s", seconds)
	}

	// A deployment may accept less than the cap, never more.
	short := newFixture(t, func(cfg *Config) { cfg.MaxLifetime = time.Minute })
	_, err := short.verifier.Verify(context.Background(), short.token(t, map[string]any{"exp": now + 60}))
	require.NoError(t, err)
	requireRefused(t, short, short.token(t, map[string]any{"exp": now + 61}), ReasonLifetime)
	requireRefused(t, short, short.token(t, nil), ReasonLifetime)
}

// Expiry has no leeway. The token works until the instant before it expires
// and is refused from that instant on.
func TestVerifyExpiryIsExact(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	token := f.token(t, nil)

	f.clock.Advance(5*time.Minute - time.Nanosecond)
	_, err := f.verifier.Verify(context.Background(), token)
	require.NoError(t, err, "one nanosecond before expiry")

	f.clock.Advance(time.Nanosecond)
	requireRefused(t, f, token, ReasonExpired)

	f.clock.Advance(time.Second)
	requireRefused(t, f, token, ReasonExpired)
}

// IssuedAtSkew forgives a provider clock that is ahead. It moves nothing at
// the other end: the same token still ends at its expiry exactly.
func TestVerifyIssuedAtSkewNeverExtendsExpiry(t *testing.T) {
	t.Parallel()
	f := newFixture(t, func(cfg *Config) { cfg.IssuedAtSkew = 5 * time.Second })
	now := f.clock.Now().Unix()

	ahead := f.token(t, map[string]any{"iat": now + 5, "exp": now + 305, "nbf": now + 5})
	_, err := f.verifier.Verify(context.Background(), ahead)
	require.NoError(t, err, "issued five seconds ahead, within the skew")
	requireRefused(t, f, f.token(t, map[string]any{"iat": now + 6, "exp": now + 306}), ReasonNotYetValid)
	requireRefused(t, f, f.token(t, map[string]any{"nbf": now + 6}), ReasonNotYetValid)

	f.clock.Advance(305*time.Second - time.Nanosecond)
	_, err = f.verifier.Verify(context.Background(), ahead)
	require.NoError(t, err)
	f.clock.Advance(time.Nanosecond)
	requireRefused(t, f, ahead, ReasonExpired)
}

func TestVerifyRefusesByShapeAndSignature(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	good := f.token(t, nil)
	parts := strings.Split(good, ".")
	claims := accessClaims(f.clock.Now())
	otherKey := testRSAKeys()[1]

	t.Run("Empty", func(t *testing.T) {
		t.Parallel()
		_, err := f.verifier.Verify(context.Background(), "")
		assert.Equal(t, ReasonMalformed, ReasonOf(err))
	})
	for name, token := range map[string]string{
		"NotAToken":        "not-a-token",
		"TwoParts":         parts[0] + "." + parts[1],
		"FourParts":        good + ".extra",
		"EmptySignature":   parts[0] + "." + parts[1] + ".",
		"HeaderNotBase64":  "!!!." + parts[1] + "." + parts[2],
		"HeaderNotJSON":    b64([]byte("not json")) + "." + parts[1] + "." + parts[2],
		"PayloadNotBase64": parts[0] + ".!!!." + parts[2],
		"TooLong":          parts[0] + "." + parts[1] + strings.Repeat("A", maxTokenBytes) + "." + parts[2],
		"NoKeyID":          sign(t, jwt.SigningMethodRS256, f.key, "", claims, nil),
		"CriticalHeader":   sign(t, jwt.SigningMethodRS256, f.key, "k1", claims, map[string]any{"crit": []string{"exp"}, "exp": 1}),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requireRefused(t, f, token, ReasonMalformed)
		})
	}

	t.Run("SignedByAnotherKeyUnderOurKeyID", func(t *testing.T) {
		t.Parallel()
		requireRefused(t, f, signRS256(t, otherKey, "k1", claims), ReasonSignature)
	})
	t.Run("PayloadChangedAfterSigning", func(t *testing.T) {
		t.Parallel()
		forged, err := json.Marshal(with(claims, map[string]any{"sub": "someone-else"}))
		require.NoError(t, err)
		requireRefused(t, f, parts[0]+"."+b64(forged)+"."+parts[2], ReasonSignature)
	})
	t.Run("SignatureTruncated", func(t *testing.T) {
		t.Parallel()
		requireRefused(t, f, good[:len(good)-8], ReasonSignature)
	})
	t.Run("UnknownKeyID", func(t *testing.T) {
		t.Parallel()
		requireRefused(t, f, signRS256(t, f.key, "k9", claims), ReasonUnknownKey)
	})

	t.Run("AlgorithmNone", func(t *testing.T) {
		t.Parallel()
		token := sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, "k1", claims, nil)
		// "none" leaves the signature part empty, which is not a signed JWT.
		requireRefused(t, f, token, ReasonMalformed)
		requireRefused(t, f, token+"AAAA", ReasonAlgorithm)
	})
	t.Run("SymmetricAlgorithmWithThePublishedKeyAsSecret", func(t *testing.T) {
		t.Parallel()
		secret := f.key.N.Bytes()
		requireRefused(t, f, sign(t, jwt.SigningMethodHS256, secret, "k1", claims, nil), ReasonAlgorithm)
	})
	t.Run("AlgorithmNotConfigured", func(t *testing.T) {
		t.Parallel()
		requireRefused(t, f, sign(t, jwt.SigningMethodRS512, f.key, "k1", claims, nil), ReasonAlgorithm)
	})
	t.Run("HeaderTypeOfAnotherTokenKind", func(t *testing.T) {
		t.Parallel()
		token := sign(t, jwt.SigningMethodRS256, f.key, "k1", claims, map[string]any{"typ": "dpop+jwt"})
		requireRefused(t, f, token, ReasonTokenType)
	})
	t.Run("HeaderTypeAccessTokenProfile", func(t *testing.T) {
		t.Parallel()
		token := sign(t, jwt.SigningMethodRS256, f.key, "k1", claims, map[string]any{"typ": "at+jwt"})
		_, err := f.verifier.Verify(context.Background(), token)
		require.NoError(t, err)
	})
}

// The header is read by exact field names, the way the JWT library reads it.
// A second field that differs only in case must not stand in for the real one.
func TestVerifyReadsTheHeaderExactly(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	payload := claimsJSON(t, accessClaims(f.clock.Now()))

	_, err := f.verifier.Verify(context.Background(), signRawRS256(t, f.key, `{"alg":"RS256","kid":"k1","typ":"JWT"}`, payload))
	require.NoError(t, err, "the plain header is accepted")

	for name, tt := range map[string]struct {
		header string
		want   Reason
	}{
		"KeyIDInAnotherCase":     {`{"alg":"RS256","kid":"k9","KID":"k1","typ":"JWT"}`, ReasonUnknownKey},
		"OnlyKeyIDInAnotherCase": {`{"alg":"RS256","KID":"k1","typ":"JWT"}`, ReasonMalformed},
		"TypeInAnotherCase":      {`{"alg":"RS256","kid":"k1","typ":"dpop+jwt","TYP":"JWT"}`, ReasonTokenType},
		"AlgorithmInAnotherCase": {`{"ALG":"RS256","alg":"HS256","kid":"k1"}`, ReasonAlgorithm},
		"AlgorithmAsList":        {`{"alg":["RS256"],"kid":"k1"}`, ReasonMalformed},
		"KeyIDAsNumber":          {`{"alg":"RS256","kid":1}`, ReasonMalformed},
		"TypeAsNumber":           {`{"alg":"RS256","kid":"k1","typ":1}`, ReasonMalformed},
		"CriticalAsNull":         {`{"alg":"RS256","kid":"k1","crit":null}`, ReasonMalformed},
		"SecondObjectAfterIt":    {`{"alg":"RS256","kid":"k1"}{"kid":"k2"}`, ReasonMalformed},
		"NotAnObject":            {`["RS256","k1"]`, ReasonMalformed},
		"Null":                   {`null`, ReasonMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requireRefused(t, f, signRawRS256(t, f.key, tt.header, payload), tt.want)
		})
	}
}

// The claims are one JSON object and nothing else. A correctly signed payload
// with anything after the object is refused, whatever a lenient parser would
// make of it.
func TestVerifyReadsThePayloadExactly(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	const header = `{"alg":"RS256","kid":"k1","typ":"JWT"}`
	claims := accessClaims(f.clock.Now())
	payload := claimsJSON(t, claims)

	_, err := f.verifier.Verify(context.Background(), signRawRS256(t, f.key, header, payload+" \n"))
	require.NoError(t, err, "space after the object is still one object")

	for name, raw := range map[string]string{
		"SecondObject":  payload + claimsJSON(t, with(claims, map[string]any{"sub": "someone-else"})),
		"TrailingText":  payload + "garbage",
		"TrailingComma": payload + ",",
		"List":          "[" + payload + "]",
		"Null":          "null",
		"Text":          `"` + testIssuer + `"`,
		"Empty":         " ",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requireRefused(t, f, signRawRS256(t, f.key, header, raw), ReasonMalformed)
		})
	}
}

func TestDecodeObject(t *testing.T) {
	t.Parallel()

	object, err := decodeObject([]byte(` {"a":1,"b":"x"} ` + "\n"))
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"a": json.Number("1"), "b": "x"}, object)

	for _, raw := range []string{
		``, ` `, `null`, `[]`, `"x"`, `1`,
		`{"a":1}{"a":2}`, `{"a":1} {"a":2}`, `{"a":1}x`, `{"a":1},`, `{"a":1}]`, `{"a":1} null`,
		`{"a":1`, `{a:1}`,
	} {
		_, err := decodeObject([]byte(raw))
		require.Error(t, err, "%q", raw)
	}
}

// Times are whole seconds. A fraction is refused, not rounded: rounding would
// let a token through just after its expiry, or just over the lifetime cap.
func TestVerifyRefusesTimesThatAreNotWholeSeconds(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	const header = `{"alg":"RS256","kid":"k1","typ":"JWT"}`
	now := f.clock.Now().Unix()
	issued, expires := strconv.FormatInt(now, 10), strconv.FormatInt(now+300, 10)
	payload := func(iat, exp, nbf string) string {
		raw := `{"iss":"` + testIssuer + `","sub":"s","aud":"` + testAudience + `","azp":"` + testCLI + `","typ":"Bearer","iat":` + iat + `,"exp":` + exp
		if nbf != "" {
			raw += `,"nbf":` + nbf
		}
		return raw + "}"
	}

	_, err := f.verifier.Verify(context.Background(), signRawRS256(t, f.key, header, payload(issued, expires, issued)))
	require.NoError(t, err, "whole seconds are accepted")

	for name, raw := range map[string]string{
		// These would round to an accepted 300 s lifetime, or to an expiry a
		// fraction of a second later than the whole second.
		"ExpiryJustOverTheCap":   payload(issued, expires+".0000001", ""),
		"ExpiryWithTinyFraction": payload(issued, strconv.FormatInt(now+299, 10)+".0000002", ""),
		"ExpiryWithZeroFraction": payload(issued, expires+".0", ""),
		"ExpiryAsExponent":       payload(issued, "1.7918067e9", ""),
		"IssuedAtWithFraction":   payload(issued+".5", expires, ""),
		"NotBeforeWithFraction":  payload(issued, expires, issued+".5"),
		"ExpiryAsText":           payload(issued, `"`+expires+`"`, ""),
		"ExpiryTooManyDigits":    payload(issued, "1791806700000000000000", ""),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requireRefused(t, f, signRawRS256(t, f.key, header, raw), ReasonTimes)
		})
	}
}

// A key is used only with the algorithm, and the curve, it was published for.
func TestVerifyKeyMustFitAlgorithm(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	rsaKey := testRSAKeys()[0]
	p256 := newECKey(t, elliptic.P256())
	p384 := newECKey(t, elliptic.P384())
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier, err := NewVerifier(Config{
		Issuer:     testIssuer,
		Audience:   testAudience,
		Clients:    map[string]Class{testCLI: ClassCLI},
		Algorithms: []string{"RS256", "PS256", "ES256", "ES384", "EdDSA"},
		Keys: StaticKeys{
			"rsa":       {Public: &rsaKey.PublicKey, Algorithm: "RS256"},
			"rsa-any":   {Public: &rsaKey.PublicKey},
			"p256":      {Public: &p256.PublicKey, Algorithm: "ES256"},
			"p384-any":  {Public: &p384.PublicKey},
			"ed":        {Public: edPublic, Algorithm: "EdDSA"},
			"not-a-key": {Public: "text"},
		},
		Now: clock.Now,
	})
	require.NoError(t, err)
	claims := accessClaims(clock.Now())
	verify := func(token string) Reason {
		_, err := verifier.Verify(context.Background(), token)
		return ReasonOf(err)
	}

	assert.Empty(t, verify(sign(t, jwt.SigningMethodRS256, rsaKey, "rsa", claims, nil)))
	assert.Empty(t, verify(sign(t, jwt.SigningMethodPS256, rsaKey, "rsa-any", claims, nil)))
	assert.Empty(t, verify(sign(t, jwt.SigningMethodES256, p256, "p256", claims, nil)))
	assert.Empty(t, verify(sign(t, jwt.SigningMethodES384, p384, "p384-any", claims, nil)))
	assert.Empty(t, verify(sign(t, jwt.SigningMethodEdDSA, edPrivate, "ed", claims, nil)))

	assert.Equal(t, ReasonAlgorithm, verify(sign(t, jwt.SigningMethodPS256, rsaKey, "rsa", claims, nil)),
		"a key published for RS256 is not used for PS256")
	assert.Equal(t, ReasonAlgorithm, verify(sign(t, jwt.SigningMethodES256, p256, "rsa-any", claims, nil)),
		"an RSA key is not used for an elliptic-curve algorithm")
	assert.Equal(t, ReasonAlgorithm, verify(sign(t, jwt.SigningMethodES256, p256, "p384-any", claims, nil)),
		"a P-384 key is not used for ES256")
	assert.Equal(t, ReasonAlgorithm, verify(sign(t, jwt.SigningMethodRS256, rsaKey, "ed", claims, nil)))
	assert.Equal(t, ReasonAlgorithm, verify(sign(t, jwt.SigningMethodRS256, rsaKey, "not-a-key", claims, nil)))
}

func TestNewVerifierRefusesConfig(t *testing.T) {
	t.Parallel()
	valid := func() Config {
		return Config{
			Issuer:   testIssuer,
			Audience: testAudience,
			Clients:  map[string]Class{testCLI: ClassCLI},
			Keys:     StaticKeys{},
		}
	}
	_, err := NewVerifier(valid())
	require.NoError(t, err)

	tests := []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"NoIssuer", func(c *Config) { c.Issuer = "" }, "issuer"},
		{"IssuerWithSpace", func(c *Config) { c.Issuer = testIssuer + " " }, "issuer"},
		{"NoAudience", func(c *Config) { c.Audience = "" }, "audience"},
		{"NoClients", func(c *Config) { c.Clients = nil }, "client"},
		{"EmptyClientID", func(c *Config) { c.Clients = map[string]Class{"": ClassCLI} }, "client"},
		// A token must never be able to yield a person or the administrator.
		{"ClientAsPerson", func(c *Config) { c.Clients = map[string]Class{testCLI: ClassPerson} }, `class "person"`},
		{"ClientAsAdmin", func(c *Config) { c.Clients = map[string]Class{testCLI: ClassPlatformAdmin} }, `class "platform_admin"`},
		{"ClientAsUnknownClass", func(c *Config) { c.Clients = map[string]Class{testCLI: "owner"} }, `class "owner"`},
		{"ClientWithNoClass", func(c *Config) { c.Clients = map[string]Class{testCLI: ""} }, "class"},
		{"LifetimeOverTheCap", func(c *Config) { c.MaxLifetime = MaxTokenLifetime + time.Second }, "lifetime"},
		{"NegativeLifetime", func(c *Config) { c.MaxLifetime = -time.Second }, "lifetime"},
		{"SkewOverTheCap", func(c *Config) { c.IssuedAtSkew = MaxIssuedAtSkew + time.Second }, "skew"},
		{"NegativeSkew", func(c *Config) { c.IssuedAtSkew = -time.Second }, "skew"},
		{"SymmetricAlgorithm", func(c *Config) { c.Algorithms = []string{"RS256", "HS256"} }, `"HS256"`},
		{"NoneAlgorithm", func(c *Config) { c.Algorithms = []string{"none"} }, `"none"`},
		{"NoKeys", func(c *Config) { c.Keys = nil }, "key source"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid()
			tt.change(&cfg)
			_, err := NewVerifier(cfg)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

// The verifier keeps its own copy of what it was configured with.
func TestVerifierCopiesItsConfig(t *testing.T) {
	t.Parallel()
	clients := map[string]Class{testCLI: ClassCLI}
	algorithms := []string{"RS256"}
	f := newFixture(t, func(cfg *Config) { cfg.Clients, cfg.Algorithms = clients, algorithms })

	clients["grafana"] = ClassWorker
	clients[testCLI] = ClassReviewer
	algorithms[0] = "RS512"

	principal, err := f.verifier.Verify(context.Background(), f.token(t, nil))
	require.NoError(t, err)
	assert.Equal(t, ClassCLI, principal.Class)
	requireRefused(t, f, f.token(t, map[string]any{"azp": "grafana"}), ReasonClient)
}

func TestClasses(t *testing.T) {
	t.Parallel()

	for _, class := range []Class{ClassPerson, ClassCLI, ClassWorker, ClassReviewer, ClassPlatformAdmin} {
		assert.True(t, class.Valid(), class)
	}
	assert.False(t, Class("").Valid())
	assert.False(t, Class("owner").Valid())

	assert.False(t, ClassPerson.Bearer())
	assert.False(t, ClassPlatformAdmin.Bearer())
	assert.True(t, ClassWorker.Machine())
	assert.True(t, ClassReviewer.Machine())
	assert.False(t, ClassCLI.Machine(), "a developer's CLI is not a machine")
	assert.False(t, ClassPerson.Machine())

	cli := Principal{Identity: Identity{Issuer: testIssuer, Subject: "s"}, Class: ClassCLI}
	require.NoError(t, cli.RequireClass(ClassCLI, ClassPerson))
	require.Error(t, cli.RequireClass(ClassWorker, ClassReviewer), "a CLI token cannot act as a machine")
	require.Error(t, cli.RequireClass())
	assert.False(t, cli.IsPerson())
	assert.True(t, Principal{Class: ClassPerson}.IsPerson())

	assert.True(t, Identity{}.IsZero())
	assert.True(t, Identity{Issuer: testIssuer}.IsZero())
	assert.True(t, Identity{Subject: "s"}.IsZero())
	assert.False(t, cli.IsZero())
}

func TestReasonOf(t *testing.T) {
	t.Parallel()

	assert.Empty(t, ReasonOf(nil))
	assert.Empty(t, ReasonOf(context.Canceled))
	assert.Equal(t, ReasonExpired, ReasonOf(refuse(ReasonExpired, "")))
	assert.False(t, ProviderUnavailable(refuse(ReasonExpired, "")))
	assert.False(t, ProviderUnavailable(refuse(ReasonUnknownKey, "")))
	assert.True(t, ProviderUnavailable(refuse(ReasonKeysUnavailable, "")))
}
