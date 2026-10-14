// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package cliauthtest is an in-process OIDC provider for tests of the CLI
// sign-in. It holds no real credential and listens on loopback only.
package cliauthtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Provider is an in-process OIDC provider: discovery, keys, the
// authorization endpoint (driven by fakeBrowser), the token endpoint and
// revocation. It holds no real credential.
type Provider struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	keyID  string

	// ClientID is the public client the CLI signs in as.
	ClientID string
	// Subject and Username are who the person signs in as.
	Subject  string
	Username string

	mu sync.Mutex
	// codes maps an issued code to the request it answers.
	codes map[string]authRequest
	// lastAuth is the most recent authorization request's query.
	lastAuth url.Values
	// refreshes counts refresh grants received.
	refreshes int
	// revoked lists revoked tokens.
	revoked []string
	// refreshTokens maps a live refresh token to its subject.
	refreshTokens map[string]string
	seq           int

	// Behaviour switches, set before the call they affect.
	IssuerOverride  string                           // issuer stated in discovery
	IDNonce         func(nonce string) string        // nonce put in the ID token
	IDAudience      string                           // audience of the ID token
	IDSubject       string                           // subject of the ID token, when not subject
	AccessSubject   string                           // subject of access tokens, when not subject
	SignWith        *rsa.PrivateKey                  // key that signs tokens, when not key
	RefreshHandler  func(w http.ResponseWriter) bool // answers a refresh instead, when it returns true
	Rotate          bool                             // issue a new refresh token on renewal
	NoRevocation    bool                             // discovery names no revocation endpoint
	AccessLifetime  time.Duration
	OmitRefresh     bool
	RefreshIDToken  bool // return an ID token on renewal
	CallbackIssuer  string
	CallbackError   string
	CallbackNoState bool
}

type authRequest struct {
	challenge   string
	nonce       string
	redirectURI string
	clientID    string
}

// New starts a provider for the test.
func New(t *testing.T) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &Provider{
		t:              t,
		key:            key,
		keyID:          "k1",
		ClientID:       "dagu-cli",
		Subject:        "0f2c7d3e-subject-a",
		Username:       "alice",
		codes:          map[string]authRequest{},
		refreshTokens:  map[string]string{},
		AccessLifetime: 5 * time.Minute,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/auth", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "the fake browser drives this endpoint", http.StatusTeapot)
	})
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/revoke", f.revoke)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *Provider) Issuer() string { return f.server.URL }

func (f *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	iss := f.Issuer()
	if f.IssuerOverride != "" {
		iss = f.IssuerOverride
	}
	doc := map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                f.Issuer() + "/auth",
		"token_endpoint":                        f.Issuer() + "/token",
		"jwks_uri":                              f.Issuer() + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	if !f.NoRevocation {
		doc["revocation_endpoint"] = f.Issuer() + "/revoke"
	}
	WriteJSON(w, http.StatusOK, doc)
}

func (f *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := f.key.PublicKey
	WriteJSON(w, http.StatusOK, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": f.keyID, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// WriteJSON answers with a JSON body.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *Provider) sign(claims jwt.MapClaims) string {
	key := f.key
	if f.SignWith != nil {
		key = f.SignWith
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = f.keyID
	s, err := token.SignedString(key)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *Provider) nextID(prefix string) string {
	f.seq++
	return prefix + strconv.Itoa(f.seq)
}

// issue answers a grant with a token set for subject; nonce goes in the ID
// token when withID is set.
func (f *Provider) issue(w http.ResponseWriter, subject, nonce string, withID bool) {
	now := time.Now()
	accessSub := subject
	if f.AccessSubject != "" {
		accessSub = f.AccessSubject
	}
	access := f.sign(jwt.MapClaims{
		"iss": f.Issuer(), "sub": accessSub, "aud": "dagu-hub", "azp": f.ClientID, "typ": "Bearer",
		"iat": now.Unix(), "exp": now.Add(f.AccessLifetime).Unix(), "jti": f.nextID("at-"),
	})
	body := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(f.AccessLifetime / time.Second),
	}
	if !f.OmitRefresh {
		rt := f.nextID("refresh-")
		f.refreshTokens[rt] = subject
		body["refresh_token"] = rt
	}
	if withID {
		idSub := subject
		if f.IDSubject != "" {
			idSub = f.IDSubject
		}
		aud := f.ClientID
		if f.IDAudience != "" {
			aud = f.IDAudience
		}
		claims := jwt.MapClaims{
			"iss": f.Issuer(), "sub": idSub, "aud": aud, "azp": f.ClientID,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			"preferred_username": f.Username, "email": "alice@example.test",
		}
		if f.IDNonce != nil {
			nonce = f.IDNonce(nonce)
		}
		if nonce != "" {
			claims["nonce"] = nonce
		}
		body["id_token"] = f.sign(claims)
	}
	WriteJSON(w, http.StatusOK, body)
}

func (f *Provider) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := r.ParseForm(); err != nil || r.Method != http.MethodPost {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if r.PostForm.Get("client_id") != f.ClientID {
		WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		req, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		if !ok || req.redirectURI != r.PostForm.Get("redirect_uri") || req.clientID != f.ClientID {
			WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		if challengeS256(r.PostForm.Get("code_verifier")) != req.challenge {
			WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE"})
			return
		}
		f.issue(w, f.Subject, req.nonce, true)
	case "refresh_token":
		f.refreshes++
		if f.RefreshHandler != nil && f.RefreshHandler(w) {
			return
		}
		rt := r.PostForm.Get("refresh_token")
		subject, ok := f.refreshTokens[rt]
		if !ok {
			WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		if f.Rotate {
			delete(f.refreshTokens, rt)
		} else {
			f.OmitRefresh = true
			defer func() { f.OmitRefresh = false }()
		}
		f.issue(w, subject, "", f.RefreshIDToken)
	default:
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (f *Provider) revoke(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = r.ParseForm()
	f.revoked = append(f.revoked, r.PostForm.Get("token"))
	delete(f.refreshTokens, r.PostForm.Get("token"))
	w.WriteHeader(http.StatusOK)
}

// Browser returns an OpenBrowser function that plays the person's browser:
// it reads the authorization request, has the provider issue a code, and
// follows the redirect to the loopback listener.
func (f *Provider) Browser(t *testing.T) func(string) error {
	return func(raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		q := u.Query()
		f.mu.Lock()
		f.lastAuth = q
		code := f.nextID("code-")
		f.codes[code] = authRequest{
			challenge:   q.Get("code_challenge"),
			nonce:       q.Get("nonce"),
			redirectURI: q.Get("redirect_uri"),
			clientID:    q.Get("client_id"),
		}
		callback := url.Values{"code": {code}}
		if !f.CallbackNoState {
			callback.Set("state", q.Get("state"))
		}
		if f.CallbackIssuer != "" {
			callback.Set("iss", f.CallbackIssuer)
		}
		if f.CallbackError != "" {
			callback = url.Values{"error": {f.CallbackError}, "state": {q.Get("state")}}
		}
		f.mu.Unlock()
		go func() {
			resp, err := http.Get(q.Get("redirect_uri") + "?" + callback.Encode()) //nolint:noctx // test browser
			if err != nil {
				t.Logf("fake browser: %v", err)
				return
			}
			_ = resp.Body.Close()
		}()
		return nil
	}
}

func challengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// LastAuth is the most recent authorization request's query.
func (f *Provider) LastAuth() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAuth
}

// Refreshes counts the refresh grants received.
func (f *Provider) Refreshes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshes
}

// Revoked lists the tokens revoked.
func (f *Provider) Revoked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}
