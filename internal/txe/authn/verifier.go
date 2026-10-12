// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// MaxTokenLifetime is the longest lifetime (exp minus iat) a verifier can
	// be configured to accept. Access ends at a token's expiry and at no other
	// moment, so this is also the longest a principal can outlive the
	// provider's refusal to renew it.
	MaxTokenLifetime = 5 * time.Minute

	// MaxIssuedAtSkew is the largest IssuedAtSkew a verifier accepts.
	MaxIssuedAtSkew = time.Minute

	// accessTokenType is the "typ" claim the provider puts in an access
	// token. Its ID tokens carry "ID" and its refresh tokens "Refresh" or
	// "Offline".
	accessTokenType = "Bearer"

	// maxTokenBytes bounds what is parsed before anything is verified.
	maxTokenBytes = 16 << 10
)

// defaultAlgorithms is used when a Config names none.
var defaultAlgorithms = []string{"RS256"}

// allowedAlgorithms are the signature algorithms a verifier can be configured
// with. Every one is asymmetric: a symmetric algorithm would let anyone who
// holds the published key sign a token.
var allowedAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
	"EdDSA",
}

// Reason says why a token was refused.
type Reason string

const (
	ReasonMalformed   Reason = "malformed"
	ReasonAlgorithm   Reason = "algorithm"
	ReasonUnknownKey  Reason = "unknown_key"
	ReasonSignature   Reason = "signature"
	ReasonTokenType   Reason = "token_type"
	ReasonIssuer      Reason = "issuer"
	ReasonAudience    Reason = "audience"
	ReasonClient      Reason = "client"
	ReasonSubject     Reason = "subject"
	ReasonTimes       Reason = "times"
	ReasonLifetime    Reason = "lifetime"
	ReasonNotYetValid Reason = "not_yet_valid"
	ReasonExpired     Reason = "expired"
	// ReasonKeysUnavailable means the signature could not be checked because
	// the issuer's keys could not be fetched and no cached key fits. It is the
	// one refusal that says nothing about the token: the caller should report
	// the provider as unavailable, not the credential as bad.
	ReasonKeysUnavailable Reason = "keys_unavailable"
)

// Error is a refused token. It never contains the token or any claim value.
type Error struct {
	Reason Reason
	detail string
	cause  error
}

func (e *Error) Error() string {
	if e.detail == "" {
		return "authn: token refused: " + string(e.Reason)
	}
	return "authn: token refused: " + string(e.Reason) + ": " + e.detail
}

func (e *Error) Unwrap() error { return e.cause }

func refuse(reason Reason, detail string) *Error {
	return &Error{Reason: reason, detail: detail}
}

// ReasonOf returns the Reason of a refusal, or "" for any other error.
func ReasonOf(err error) Reason {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Reason
	}
	return ""
}

// ProviderUnavailable reports whether err means the token could not be judged
// because the issuer's keys were unavailable.
func ProviderUnavailable(err error) bool {
	return ReasonOf(err) == ReasonKeysUnavailable
}

// Config says which tokens a Verifier accepts. Every check is exact; nothing
// is matched by prefix, pattern or case folding.
type Config struct {
	// Issuer is the "iss" claim a token must carry, character for character.
	Issuer string
	// Audience must be one of the token's "aud" values.
	Audience string
	// Clients maps each accepted authorised party ("azp") to the class its
	// tokens yield. Only bearer classes may appear.
	Clients map[string]Class
	// MaxLifetime caps exp minus iat. Zero means MaxTokenLifetime, and a
	// larger value is refused.
	MaxLifetime time.Duration
	// IssuedAtSkew is how far in the future "iat" and "nbf" may lie, to
	// absorb a difference between the provider's clock and this one. It is
	// never applied to "exp": a token is refused at its expiry exactly, and
	// nothing, an unreachable provider included, extends that.
	IssuedAtSkew time.Duration
	// Algorithms lists the accepted signature algorithms. Empty means RS256.
	Algorithms []string
	// Keys supplies the issuer's signing keys.
	Keys KeySource
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// Verifier checks provider access tokens against one Config. It is safe for
// concurrent use.
type Verifier struct {
	issuer       string
	audience     string
	clients      map[string]Class
	maxLifetime  time.Duration
	issuedAtSkew time.Duration
	algorithms   []string
	keys         KeySource
	now          func() time.Time
}

// NewVerifier validates cfg and returns a Verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Issuer != strings.TrimSpace(cfg.Issuer) {
		return nil, errors.New("authn: issuer is required and must have no surrounding space")
	}
	if cfg.Audience == "" || cfg.Audience != strings.TrimSpace(cfg.Audience) {
		return nil, errors.New("authn: audience is required and must have no surrounding space")
	}
	if len(cfg.Clients) == 0 {
		return nil, errors.New("authn: at least one client is required")
	}
	for client, class := range cfg.Clients {
		if client == "" || client != strings.TrimSpace(client) {
			return nil, errors.New("authn: a client id is empty or has surrounding space")
		}
		if !class.Bearer() {
			return nil, fmt.Errorf("authn: client %q maps to class %q, which a bearer token may not yield", client, class)
		}
	}
	maxLifetime := cfg.MaxLifetime
	if maxLifetime == 0 {
		maxLifetime = MaxTokenLifetime
	}
	if maxLifetime < 0 || maxLifetime > MaxTokenLifetime {
		return nil, fmt.Errorf("authn: maximum token lifetime must be between 0 and %s", MaxTokenLifetime)
	}
	if cfg.IssuedAtSkew < 0 || cfg.IssuedAtSkew > MaxIssuedAtSkew {
		return nil, fmt.Errorf("authn: issued-at skew must be between 0 and %s", MaxIssuedAtSkew)
	}
	algorithms := slices.Clone(cfg.Algorithms)
	if len(algorithms) == 0 {
		algorithms = slices.Clone(defaultAlgorithms)
	}
	for _, alg := range algorithms {
		if !slices.Contains(allowedAlgorithms, alg) {
			return nil, fmt.Errorf("authn: signature algorithm %q is not accepted", alg)
		}
	}
	if cfg.Keys == nil {
		return nil, errors.New("authn: a key source is required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		issuer:       cfg.Issuer,
		audience:     cfg.Audience,
		clients:      maps.Clone(cfg.Clients),
		maxLifetime:  maxLifetime,
		issuedAtSkew: cfg.IssuedAtSkew,
		algorithms:   algorithms,
		keys:         cfg.Keys,
		now:          now,
	}, nil
}

// Verify checks token and returns the principal it authenticates. Every
// refusal is an *Error.
//
// The signature is checked before any claim is read, so a token nobody signed
// learns nothing about the configuration. The clock is read once, after the
// key is in hand, so time spent fetching keys cannot let an expired token
// through.
func (v *Verifier) Verify(ctx context.Context, token string) (Principal, error) {
	header, err := v.readHeader(token)
	if err != nil {
		return Principal{}, err
	}

	key, err := v.keys.Key(ctx, header.KeyID)
	if err != nil {
		if refused, ok := errors.AsType[*Error](err); ok {
			return Principal{}, refused
		}
		return Principal{}, &Error{Reason: ReasonKeysUnavailable, detail: "the key source failed", cause: err}
	}
	if key.Algorithm != "" && key.Algorithm != header.Algorithm {
		return Principal{}, refuse(ReasonAlgorithm, "the key is published for another algorithm")
	}
	if !keyFitsAlgorithm(key.Public, header.Algorithm) {
		return Principal{}, refuse(ReasonAlgorithm, "the key cannot be used with the token's algorithm")
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{header.Algorithm}),
		jwt.WithoutClaimsValidation(),
		jwt.WithJSONNumber(),
	)
	if _, err := parser.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return key.Public, nil }); err != nil {
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return Principal{}, refuse(ReasonSignature, "")
		}
		return Principal{}, refuse(ReasonMalformed, "the token could not be parsed")
	}

	return v.checkClaims(claims, v.now())
}

type tokenHeader struct {
	Algorithm string          `json:"alg"`
	KeyID     string          `json:"kid"`
	Type      string          `json:"typ"`
	Critical  json.RawMessage `json:"crit"`
}

func (v *Verifier) readHeader(token string) (tokenHeader, error) {
	var header tokenHeader
	if len(token) == 0 || len(token) > maxTokenBytes {
		return header, refuse(ReasonMalformed, "the token is empty or too long")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return header, refuse(ReasonMalformed, "the token is not a signed JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return header, refuse(ReasonMalformed, "the token header is not base64url")
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return header, refuse(ReasonMalformed, "the token header is not JSON")
	}
	if !slices.Contains(v.algorithms, header.Algorithm) {
		return header, refuse(ReasonAlgorithm, "the token's signature algorithm is not accepted")
	}
	if header.KeyID == "" {
		return header, refuse(ReasonMalformed, "the token names no key")
	}
	if len(header.Critical) != 0 {
		return header, refuse(ReasonMalformed, "the token has critical header fields, and none is understood")
	}
	if header.Type != "" && !strings.EqualFold(header.Type, "JWT") && !strings.EqualFold(header.Type, "at+jwt") {
		return header, refuse(ReasonTokenType, "the token header does not describe an access token")
	}
	return header, nil
}

func (v *Verifier) checkClaims(claims jwt.MapClaims, now time.Time) (Principal, error) {
	if typ, _ := claims["typ"].(string); typ != accessTokenType {
		return Principal{}, refuse(ReasonTokenType, "the token is not an access token")
	}
	if issuer, _ := claims["iss"].(string); issuer != v.issuer {
		return Principal{}, refuse(ReasonIssuer, "")
	}
	if !audienceContains(claims["aud"], v.audience) {
		return Principal{}, refuse(ReasonAudience, "")
	}
	client, _ := claims["azp"].(string)
	class, known := v.clients[client]
	if client == "" || !known {
		return Principal{}, refuse(ReasonClient, "")
	}
	subject, _ := claims["sub"].(string)
	if subject == "" {
		return Principal{}, refuse(ReasonSubject, "")
	}

	issuedAt, ok := numericDate(claims["iat"])
	if !ok {
		return Principal{}, refuse(ReasonTimes, "the token has no usable issue time")
	}
	expires, ok := numericDate(claims["exp"])
	if !ok {
		return Principal{}, refuse(ReasonTimes, "the token has no usable expiry")
	}
	if !expires.After(issuedAt) {
		return Principal{}, refuse(ReasonTimes, "the token expires at or before its issue time")
	}
	if expires.Sub(issuedAt) > v.maxLifetime {
		return Principal{}, refuse(ReasonLifetime, "the token's lifetime is longer than is accepted")
	}
	if issuedAt.After(now.Add(v.issuedAtSkew)) {
		return Principal{}, refuse(ReasonNotYetValid, "the token was issued in the future")
	}
	if raw, present := claims["nbf"]; present {
		notBefore, ok := numericDate(raw)
		if !ok {
			return Principal{}, refuse(ReasonTimes, "the token's not-before time is unusable")
		}
		if notBefore.After(now.Add(v.issuedAtSkew)) {
			return Principal{}, refuse(ReasonNotYetValid, "the token is not valid yet")
		}
	}
	// No leeway and no grace: the instant of expiry is already too late.
	if !now.Before(expires) {
		return Principal{}, refuse(ReasonExpired, "")
	}

	return Principal{
		Identity: Identity{Issuer: v.issuer, Subject: subject},
		Class:    class,
		ClientID: client,
		IssuedAt: issuedAt,
		Expires:  expires,
	}, nil
}

// audienceContains reports whether an "aud" claim, a string or a list of
// strings, holds want. Any other shape holds nothing.
func audienceContains(claim any, want string) bool {
	switch aud := claim.(type) {
	case string:
		return aud == want
	case []any:
		found := false
		for _, entry := range aud {
			value, ok := entry.(string)
			if !ok {
				return false
			}
			if value == want {
				found = true
			}
		}
		return found
	default:
		return false
	}
}

// Bounds on a NumericDate. Seconds outside them are not a date anyone meant,
// and would overflow the conversion.
const (
	minNumericDate = 1
	maxNumericDate = 1 << 36
)

// numericDate reads a JSON number of seconds since the epoch.
func numericDate(claim any) (time.Time, bool) {
	number, ok := claim.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	seconds, err := number.Float64()
	if err != nil || math.IsNaN(seconds) || seconds < minNumericDate || seconds > maxNumericDate {
		return time.Time{}, false
	}
	whole := int64(seconds)
	nanos := int64((seconds - float64(whole)) * float64(time.Second))
	return time.Unix(whole, nanos), true
}

// keyFitsAlgorithm reports whether key is the kind, and for an elliptic curve
// the curve, that alg signs with. The JWT library checks the kind and not the
// curve.
func keyFitsAlgorithm(key any, alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		_, ok := key.(*rsa.PublicKey)
		return ok
	case "ES256", "ES384", "ES512":
		ec, ok := key.(*ecdsa.PublicKey)
		if !ok || ec.Curve == nil {
			return false
		}
		want := map[string]int{"ES256": 256, "ES384": 384, "ES512": 521}[alg]
		return ec.Curve.Params().BitSize == want
	case "EdDSA":
		_, ok := key.(ed25519.PublicKey)
		return ok
	default:
		return false
	}
}
