// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Key is one of the issuer's signing keys.
type Key struct {
	Public crypto.PublicKey
	// Algorithm is the algorithm the issuer publishes the key for, or "" when
	// it publishes none.
	Algorithm string
}

// KeySource finds an issuer's signing key by its id. An unknown id is an
// *Error with ReasonUnknownKey; keys that could not be fetched at all are an
// *Error with ReasonKeysUnavailable.
type KeySource interface {
	Key(ctx context.Context, keyID string) (Key, error)
}

// StaticKeys is a fixed set of keys, by key id.
type StaticKeys map[string]Key

// Key implements KeySource.
func (s StaticKeys) Key(_ context.Context, keyID string) (Key, error) {
	if key, ok := s[keyID]; ok {
		return key, nil
	}
	return Key{}, refuse(ReasonUnknownKey, "")
}

const (
	// minRefetchInterval is the least time between two fetches, whatever asks
	// for them. It is not configurable: it is what stops tokens naming unknown
	// keys from making this process fetch at will, and it has to stay well
	// inside StaleKeyGrace so that a set in its grace is retried before the
	// grace ends.
	minRefetchInterval = time.Minute

	defaultMaxKeyAge = time.Hour
	// minMaxKeyAge keeps half the maximum age well above the fetch limit, so
	// that a Refresh that is due at half age is never still inside it.
	minMaxKeyAge = 10 * time.Minute
	maxMaxKeyAge = 24 * time.Hour

	defaultFetchTimeout = 5 * time.Second
	maxFetchTimeout     = 30 * time.Second

	maxKeySetBytes = 1 << 20
	maxKeySetKeys  = 64
	minRSAKeyBits  = 2048
	maxRSAKeyBits  = 8192
	// maxRSAExponent is the largest public exponent crypto/rsa accepts.
	maxRSAExponent = 1<<31 - 1
)

// StaleKeyGrace is how long a key set that needs replacing, and could not be
// replaced, stays in use. It is as long as a token can still be alive after
// the issuer signed it: the longest lifetime, plus the most the issuer's
// clock may be ahead.
const StaleKeyGrace = MaxTokenLifetime + MaxIssuedAtSkew

// RemoteKeySetConfig configures a RemoteKeySet.
type RemoteKeySetConfig struct {
	// URL is the issuer's JWKS document. It must be https, or http on a
	// loopback address.
	URL string
	// HTTPClient fetches the document. Nil means the default client. Either
	// way no redirect is followed: the set works on a copy of the client that
	// refuses them, because the URL is checked once and a redirect could
	// leave https.
	HTTPClient *http.Client
	// MaxKeyAge is how old the cached set may get before a use tries to
	// replace it, so that a key the issuer withdrew stops being trusted. Zero
	// means one hour. It must be between ten minutes and 24 hours.
	MaxKeyAge time.Duration
	// FetchTimeout bounds one fetch. Zero means five seconds, and 30 seconds
	// is the most.
	FetchTimeout time.Duration
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// RemoteKeySet caches the keys an issuer publishes.
//
// A cached key is returned without any network call. A token naming a key
// that is not cached can cause one fetch a minute and no more.
//
// A set is replaced when it reaches its maximum age and something needs a key
// from it. Nothing runs in the background, so a set nobody uses is not
// replaced, however old it gets, unless the host calls Refresh.
//
// While the issuer cannot be reached, the last set fetched stays in use for a
// bounded time, so that an outage does not stop tokens that are still within
// their own lifetime. It never makes a token live longer: expiry is the
// verifier's check and not this cache's. The bound is StaleKeyGrace, counted
// from the later of two moments: when the set reached its maximum age, and
// when a fetch first failed. Every token the issuer signed before that moment
// has expired by the end of it.
//
// Past the bound the set is not used and every token is refused with
// ReasonKeysUnavailable until a fetch succeeds. That has a cost, and it is
// deliberate. If this process cannot reach the issuer while callers still
// can, tokens they obtain after the bound started are refused although the
// issuer would vouch for them. Without a bound, a key the issuer withdrew
// would stay trusted for as long as fetches could be made to fail, and
// whoever held it could keep signing tokens with fresh times.
//
// How firm that is depends on Refresh. Left to requests alone, a process
// nobody has asked for a key learns that a fetch fails only when the next
// request arrives, so the grace can start long after the set went stale and
// after the issuer withdrew a key. A host that calls Refresh on a timer finds
// out when the issuer stops answering. Provided it calls at least every half
// maximum key age, which once a minute always is, a fetch is tried, and
// fails, before the set reaches its maximum age. The set is then used for no
// longer than its maximum age plus StaleKeyGrace after it was last fetched,
// however idle the process is.
//
// A process that has never fetched a set can verify nothing.
type RemoteKeySet struct {
	url     string
	client  *http.Client
	maxAge  time.Duration
	timeout time.Duration
	now     func() time.Time

	// fetchMu admits one fetch at a time.
	fetchMu sync.Mutex

	mu          sync.RWMutex
	keys        map[string]Key
	fetchedAt   time.Time
	attemptedAt time.Time
	// failingSince is when a fetch first failed since the last one that
	// succeeded, or zero if the last attempt succeeded.
	failingSince time.Time
	lastErr      error
}

// NewRemoteKeySet validates cfg and returns an empty key set. It makes no
// network call.
func NewRemoteKeySet(cfg RemoteKeySetConfig) (*RemoteKeySet, error) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil || parsed.Host == "" {
		return nil, errors.New("authn: the key set URL is not a URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("authn: the key set URL must carry no credentials and no fragment")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(parsed.Hostname()) {
			return nil, errors.New("authn: the key set URL must use https unless it is on a loopback address")
		}
	default:
		return nil, errors.New("authn: the key set URL must use https")
	}

	maxAge := cfg.MaxKeyAge
	if maxAge == 0 {
		maxAge = defaultMaxKeyAge
	}
	if maxAge < minMaxKeyAge || maxAge > maxMaxKeyAge {
		return nil, fmt.Errorf("authn: the maximum key age must be between %s and %s", minMaxKeyAge, maxMaxKeyAge)
	}
	timeout := cfg.FetchTimeout
	if timeout == 0 {
		timeout = defaultFetchTimeout
	}
	if timeout < 0 || timeout > maxFetchTimeout {
		return nil, fmt.Errorf("authn: the fetch timeout must be at most %s", maxFetchTimeout)
	}

	client := http.Client{}
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &RemoteKeySet{
		url:     parsed.String(),
		client:  &client,
		maxAge:  maxAge,
		timeout: timeout,
		now:     now,
	}, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// KeySetStatus describes a RemoteKeySet for reporting.
type KeySetStatus struct {
	// Keys is the number of cached keys.
	Keys int
	// FetchedAt is when the cached set was fetched, or zero if none was.
	FetchedAt time.Time
	// AttemptedAt is when a fetch was last tried.
	AttemptedAt time.Time
	// FailingSince is when a fetch first failed since the last one that
	// succeeded, or zero if the last attempt succeeded.
	FailingSince time.Time
	// UsableUntil is when the cached set stops being used unless a fetch
	// succeeds first. It is zero while the last attempt succeeded, because
	// the set is then replaced, not dropped, when it gets old.
	UsableUntil time.Time
	// LastError describes the last attempt when it failed, and is empty when
	// it succeeded.
	LastError string
}

// Status returns the state of the cache.
func (s *RemoteKeySet) Status() KeySetStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := KeySetStatus{
		Keys:         len(s.keys),
		FetchedAt:    s.fetchedAt,
		AttemptedAt:  s.attemptedAt,
		FailingSince: s.failingSince,
	}
	if !s.fetchedAt.IsZero() && !s.failingSince.IsZero() {
		status.UsableUntil = s.graceStart().Add(StaleKeyGrace)
	}
	if s.lastErr != nil {
		status.LastError = s.lastErr.Error()
	}
	return status
}

// Refresh replaces the set when that is due, and returns the error of the
// last fetch, or nil if it succeeded. It is due when there is no set, when
// the set has reached half its maximum age, or when the last fetch failed.
// Like every fetch it happens at most once a minute, so a host may call
// Refresh as often as it likes.
//
// Calling it is optional. See RemoteKeySet for what it buys and how often it
// must be called to buy it.
func (s *RemoteKeySet) Refresh(ctx context.Context) error {
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()

	s.mu.RLock()
	due := s.fetchedAt.IsZero() || !s.failingSince.IsZero() || s.now().Sub(s.fetchedAt) >= s.maxAge/2
	s.mu.RUnlock()
	if due {
		s.refreshIfDue(ctx)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastErr
}

// Key implements KeySource.
func (s *RemoteKeySet) Key(ctx context.Context, keyID string) (Key, error) {
	key, found, stale := s.cached(keyID)
	if found && !stale {
		return key, nil
	}
	if found {
		// The set is old. One caller replaces it; the others keep using it
		// meanwhile, so an unreachable issuer delays nobody else.
		if !s.fetchMu.TryLock() {
			return key, nil
		}
		s.refreshIfDue(ctx)
		s.fetchMu.Unlock()
		if key, found, _ = s.cached(keyID); found {
			return key, nil
		}
		// The issuer withdrew the key.
		return Key{}, s.unknown()
	}

	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	// Another caller may have fetched the key while this one waited.
	if key, found, _ = s.cached(keyID); found {
		return key, nil
	}
	s.refreshIfDue(ctx)
	if key, found, _ = s.cached(keyID); found {
		return key, nil
	}
	return Key{}, s.unknown()
}

// unknown is the refusal for a key that is not in a usable set. When the last
// fetch failed, nothing can be said about the key, so the refusal blames the
// provider and not the token.
func (s *RemoteKeySet) unknown() *Error {
	s.mu.RLock()
	lastErr := s.lastErr
	s.mu.RUnlock()
	if lastErr != nil {
		return &Error{Reason: ReasonKeysUnavailable, detail: "the issuer's keys could not be fetched", cause: lastErr}
	}
	return refuse(ReasonUnknownKey, "")
}

// cached returns the cached key, and whether the set it came from is old
// enough to need replacing. A set whose grace has run out holds no key.
func (s *RemoteKeySet) cached(keyID string) (key Key, found, stale bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	stale = now.Sub(s.fetchedAt) >= s.maxAge
	if stale && !s.failingSince.IsZero() && !now.Before(s.graceStart().Add(StaleKeyGrace)) {
		return Key{}, false, false
	}
	key, found = s.keys[keyID]
	return key, found, found && stale
}

// graceStart is the later of when the set reached its maximum age and when a
// fetch first failed. The caller holds mu and has checked that a fetch is
// failing.
func (s *RemoteKeySet) graceStart() time.Time {
	start := s.fetchedAt.Add(s.maxAge)
	if s.failingSince.After(start) {
		return s.failingSince
	}
	return start
}

// refreshIfDue fetches the set unless a fetch was tried within the minimum
// interval. The caller holds fetchMu. A failed fetch leaves the cached keys
// in place.
func (s *RemoteKeySet) refreshIfDue(ctx context.Context) {
	now := s.now()
	s.mu.RLock()
	attemptedAt := s.attemptedAt
	s.mu.RUnlock()
	if !attemptedAt.IsZero() && now.Sub(attemptedAt) < minRefetchInterval {
		return
	}

	keys, err := s.fetch(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.attemptedAt = now
	s.lastErr = err
	if err != nil {
		if s.failingSince.IsZero() {
			s.failingSince = now
		}
		return
	}
	s.keys = keys
	s.fetchedAt = now
	s.failingSince = time.Time{}
}

func (s *RemoteKeySet) fetch(ctx context.Context) (map[string]Key, error) {
	// The fetch serves every caller, so one caller going away must not fail
	// it and spend the interval before the next attempt.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch key set: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch key set: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySetBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch key set: %w", err)
	}
	if len(body) > maxKeySetBytes {
		return nil, errors.New("fetch key set: the document is too large")
	}
	return parseKeySet(body)
}

type jwk struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Curve     string `json:"crv"`
	N         string `json:"n"`
	E         string `json:"e"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

// parseKeySet reads a JWKS document. Keys that are not for signatures, have
// no id or are of an unsupported kind are skipped. A document with a
// malformed signing key, a repeated key id or no usable key is refused whole,
// which leaves the previous set in place.
func parseKeySet(body []byte) (map[string]Key, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.New("key set: the document is not JSON")
	}
	if len(doc.Keys) > maxKeySetKeys {
		return nil, errors.New("key set: too many keys")
	}
	keys := make(map[string]Key, len(doc.Keys))
	for _, entry := range doc.Keys {
		if entry.KeyID == "" || (entry.Use != "" && entry.Use != "sig") {
			continue
		}
		public, supported, err := entry.publicKey()
		if err != nil {
			return nil, fmt.Errorf("key set: key %q: %w", entry.KeyID, err)
		}
		if !supported {
			continue
		}
		if _, repeated := keys[entry.KeyID]; repeated {
			return nil, fmt.Errorf("key set: key id %q appears twice", entry.KeyID)
		}
		keys[entry.KeyID] = Key{Public: public, Algorithm: entry.Algorithm}
	}
	if len(keys) == 0 {
		return nil, errors.New("key set: no usable signing key")
	}
	return keys, nil
}

func (k jwk) publicKey() (key crypto.PublicKey, supported bool, err error) {
	switch k.KeyType {
	case "RSA":
		n, err := decodeKeyField(k.N)
		if err != nil {
			return nil, true, errors.New("the modulus is unreadable")
		}
		e, err := decodeKeyField(k.E)
		if err != nil || len(e) > 4 {
			return nil, true, errors.New("the exponent is unreadable")
		}
		// A key that crypto/rsa would refuse to use must be refused here, or
		// it would replace a working key and then verify nothing.
		modulus := new(big.Int).SetBytes(n)
		exponent := new(big.Int).SetBytes(e).Int64()
		if bits := modulus.BitLen(); bits < minRSAKeyBits || bits > maxRSAKeyBits {
			return nil, true, fmt.Errorf("the key has %d bits and between %d and %d are required", bits, minRSAKeyBits, maxRSAKeyBits)
		}
		if modulus.Bit(0) == 0 {
			return nil, true, errors.New("the modulus is even")
		}
		if exponent < 3 || exponent > maxRSAExponent || exponent%2 == 0 {
			return nil, true, errors.New("the exponent is not usable")
		}
		return &rsa.PublicKey{N: modulus, E: int(exponent)}, true, nil

	case "EC":
		var curve elliptic.Curve
		switch k.Curve {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, false, nil
		}
		x, errX := decodeKeyField(k.X)
		y, errY := decodeKeyField(k.Y)
		size := (curve.Params().BitSize + 7) / 8
		if errX != nil || errY != nil || len(x) != size || len(y) != size {
			return nil, true, errors.New("the point is unreadable")
		}
		point := append(append([]byte{4}, x...), y...)
		public, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, true, errors.New("the point is not on the curve")
		}
		return public, true, nil

	case "OKP":
		if k.Curve != "Ed25519" {
			return nil, false, nil
		}
		x, err := decodeKeyField(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, true, errors.New("the key is unreadable")
		}
		return ed25519.PublicKey(x), true, nil

	default:
		return nil, false, nil
	}
}

func decodeKeyField(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty")
	}
	return base64.RawURLEncoding.DecodeString(value)
}
