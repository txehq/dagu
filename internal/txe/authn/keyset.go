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
	defaultMinRefetchInterval = time.Minute
	defaultMaxKeyAge          = time.Hour
	defaultFetchTimeout       = 5 * time.Second

	maxKeySetBytes = 1 << 20
	maxKeySetKeys  = 64
	minRSAKeyBits  = 2048
)

// RemoteKeySetConfig configures a RemoteKeySet.
type RemoteKeySetConfig struct {
	// URL is the issuer's JWKS document. It must be https, or http on a
	// loopback address.
	URL string
	// HTTPClient fetches the document. Nil means a client that follows no
	// redirect.
	HTTPClient *http.Client
	// MinRefetchInterval is the least time between two fetches, whatever asks
	// for them. A token naming an unknown key can therefore cause at most one
	// fetch in that time. Zero means one minute.
	MinRefetchInterval time.Duration
	// MaxKeyAge is how old the cached set may get before a use tries to
	// replace it, so that a key the issuer withdrew stops being trusted. Zero
	// means one hour.
	MaxKeyAge time.Duration
	// FetchTimeout bounds one fetch. Zero means five seconds.
	FetchTimeout time.Duration
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// RemoteKeySet caches the keys an issuer publishes.
//
// A cached key is returned without any network call. While the issuer cannot
// be reached, the last set fetched stays in use: an outage does not stop
// tokens that are still within their own lifetime from being verified, and it
// does not make any token live longer, because expiry is the verifier's check
// and not this cache's. A process that has never fetched a set can verify
// nothing.
type RemoteKeySet struct {
	url        string
	client     *http.Client
	minRefetch time.Duration
	maxAge     time.Duration
	timeout    time.Duration
	now        func() time.Time

	// fetchMu admits one fetch at a time.
	fetchMu sync.Mutex

	mu          sync.RWMutex
	keys        map[string]Key
	fetchedAt   time.Time
	attemptedAt time.Time
	lastErr     error
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
	if cfg.MinRefetchInterval < 0 || cfg.MaxKeyAge < 0 || cfg.FetchTimeout < 0 {
		return nil, errors.New("authn: key set intervals must not be negative")
	}

	set := &RemoteKeySet{
		url:        parsed.String(),
		client:     cfg.HTTPClient,
		minRefetch: cfg.MinRefetchInterval,
		maxAge:     cfg.MaxKeyAge,
		timeout:    cfg.FetchTimeout,
		now:        cfg.Now,
	}
	if set.client == nil {
		set.client = &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if set.minRefetch == 0 {
		set.minRefetch = defaultMinRefetchInterval
	}
	if set.maxAge == 0 {
		set.maxAge = defaultMaxKeyAge
	}
	if set.timeout == 0 {
		set.timeout = defaultFetchTimeout
	}
	if set.now == nil {
		set.now = time.Now
	}
	return set, nil
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
	// LastError describes the last attempt when it failed, and is empty when
	// it succeeded.
	LastError string
}

// Status returns the state of the cache.
func (s *RemoteKeySet) Status() KeySetStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := KeySetStatus{Keys: len(s.keys), FetchedAt: s.fetchedAt, AttemptedAt: s.attemptedAt}
	if s.lastErr != nil {
		status.LastError = s.lastErr.Error()
	}
	return status
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
		return Key{}, refuse(ReasonUnknownKey, "")
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

	s.mu.RLock()
	lastErr := s.lastErr
	s.mu.RUnlock()
	if lastErr != nil {
		return Key{}, &Error{Reason: ReasonKeysUnavailable, detail: "the issuer's keys could not be fetched", cause: lastErr}
	}
	return Key{}, refuse(ReasonUnknownKey, "")
}

// cached returns the cached key, and whether the set it came from is older
// than the maximum age.
func (s *RemoteKeySet) cached(keyID string) (key Key, found, stale bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, found = s.keys[keyID]
	stale = found && s.now().Sub(s.fetchedAt) >= s.maxAge
	return key, found, stale
}

// refreshIfDue fetches the set unless a fetch was tried within the minimum
// interval. The caller holds fetchMu. A failed fetch leaves the cached keys
// in place.
func (s *RemoteKeySet) refreshIfDue(ctx context.Context) {
	now := s.now()
	s.mu.RLock()
	attemptedAt := s.attemptedAt
	s.mu.RUnlock()
	if !attemptedAt.IsZero() && now.Sub(attemptedAt) < s.minRefetch {
		return
	}

	keys, err := s.fetch(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.attemptedAt = now
	s.lastErr = err
	if err == nil {
		s.keys = keys
		s.fetchedAt = now
	}
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
		modulus := new(big.Int).SetBytes(n)
		exponent := int(new(big.Int).SetBytes(e).Int64())
		if modulus.BitLen() < minRSAKeyBits {
			return nil, true, fmt.Errorf("the key has %d bits and at least %d are required", modulus.BitLen(), minRSAKeyBits)
		}
		if exponent < 3 || exponent%2 == 0 {
			return nil, true, errors.New("the exponent is not usable")
		}
		return &rsa.PublicKey{N: modulus, E: exponent}, true, nil

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
