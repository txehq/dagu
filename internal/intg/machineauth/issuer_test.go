// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package machineauth_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// issuer is the synthetic identity provider the matrix runs against: the shape
// of the in-process providers the repository's other tests use, serving real
// processes over loopback. Discovery, keys, an authorization endpoint that
// approves at once for the person named by login_hint, a token endpoint
// (authorization_code with PKCE S256, refresh_token with rotation, a client
// secret for the hub's browser client), userinfo and revocation. Two persons,
// alice and bob, one per synthetic owner. The test mints tokens with chosen
// times and revokes a client's refresh tokens directly, for the negative cases.
//
// Everything is made for one run and lives in memory. No token value is logged
// or returned to a test log: the test only ever writes tokens to owner-only
// files that the processes read.
type issuer struct {
	server         *httptest.Server
	key            *rsa.PrivateKey
	kid            string
	audience       string
	accessLifetime time.Duration
	browserClient  string
	browserSecret  string
	clients        map[string]string // id -> class

	mu       sync.Mutex
	codes    map[string]issuerCode
	refresh  map[string]issuerRefresh
	revoked  map[string]bool
	seq      int
	refreshN map[string]int
}

type issuerPerson struct{ subject, email, username, name string }

var issuerPersons = map[string]issuerPerson{
	"alice": {subject: "rig-person-alice", email: "alice@rig.test", username: "alice", name: "Alice (synthetic)"},
	"bob":   {subject: "rig-person-bob", email: "bob@rig.test", username: "bob", name: "Bob (synthetic)"},
}

type issuerCode struct {
	client, redirectURI, nonce, challenge, person string
	scopes                                        []string
	issuedAt                                      time.Time
}

type issuerRefresh struct {
	client, person string
	scopes         []string
}

// newIssuer starts the provider on loopback. clients maps provider client ids
// to their class (cli, worker, reviewer); browserClient is the hub's browser
// client, authenticated by browserSecret.
func newIssuer(t *testing.T, clients map[string]string, browserClient, browserSecret string) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &issuer{
		key: key, kid: "rig-k1", audience: "dagu-hub", accessLifetime: 5 * time.Minute,
		browserClient: browserClient, browserSecret: browserSecret, clients: clients,
		codes: map[string]issuerCode{}, refresh: map[string]issuerRefresh{}, revoked: map[string]bool{}, refreshN: map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/jwks", s.jwks)
	mux.HandleFunc("/auth", s.authorize)
	mux.HandleFunc("/token", s.token)
	mux.HandleFunc("/userinfo", s.userinfo)
	mux.HandleFunc("/revoke", s.revoke)
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func (s *issuer) url() string { return s.server.URL }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func (s *issuer) discovery(w http.ResponseWriter, _ *http.Request) {
	u := s.url()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": u, "authorization_endpoint": u + "/auth", "token_endpoint": u + "/token",
		"userinfo_endpoint": u + "/userinfo", "jwks_uri": u + "/jwks", "revocation_endpoint": u + "/revoke",
		"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
	})
}

func (s *issuer) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := s.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": s.kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (s *issuer) nextID(prefix string) string {
	s.seq++
	var b [12]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

func (s *issuer) sign(claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": s.kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *issuer) verify(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		return nil, errors.New("signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed payload")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("malformed payload")
	}
	if exp, ok := claims["exp"].(float64); !ok || time.Now().Unix() >= int64(exp) {
		return nil, errors.New("expired")
	}
	return claims, nil
}

// mintOptions shape a token for a negative case.
type mintOptions struct {
	lifetime time.Duration // zero: the issuer's
	iatShift time.Duration // negative with a short lifetime: expired; positive: not yet valid
	audience string        // empty: the issuer's
}

// accessToken signs an access token for client as person.
func (s *issuer) accessToken(client, person string, o mintOptions) (string, error) {
	p, ok := issuerPersons[person]
	if !ok {
		return "", errors.New("unknown person")
	}
	lifetime, aud := s.accessLifetime, s.audience
	if o.lifetime != 0 {
		lifetime = o.lifetime
	}
	if o.audience != "" {
		aud = o.audience
	}
	now := time.Now().Truncate(time.Second).Add(o.iatShift)
	return s.sign(map[string]any{
		"iss": s.url(), "sub": p.subject, "aud": aud, "azp": client, "typ": "Bearer",
		"iat": now.Unix(), "exp": now.Add(lifetime).Unix(), "jti": s.nextID("at-"),
	})
}

func (s *issuer) idToken(client, person, nonce string) (string, error) {
	p := issuerPersons[person]
	now := time.Now().Truncate(time.Second)
	claims := map[string]any{
		"iss": s.url(), "sub": p.subject, "aud": client, "azp": client,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"email": p.email, "email_verified": true, "preferred_username": p.username, "name": p.name,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return s.sign(claims)
}

func (s *issuer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client := q.Get("client_id")
	_, known := s.clients[client]
	redirectURI := q.Get("redirect_uri")
	if (!known && client != s.browserClient) || redirectURI == "" || q.Get("response_type") != "code" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	person := q.Get("login_hint")
	if person == "" {
		person = "alice"
	}
	if _, ok := issuerPersons[person]; !ok {
		http.Error(w, "unknown person", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge") != "" && q.Get("code_challenge_method") != "S256" {
		http.Error(w, "only S256 is supported", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	code := s.nextID("code-")
	s.codes[code] = issuerCode{client: client, redirectURI: redirectURI, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"),
		person: person, scopes: strings.Fields(q.Get("scope")), issuedAt: time.Now()}
	s.mu.Unlock()
	v := u.Query()
	v.Set("code", code)
	if st := q.Get("state"); st != "" {
		v.Set("state", st)
	}
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// clientFrom authenticates the token request's client: a public client by id
// alone, the browser client by its secret (basic or body).
func (s *issuer) clientFrom(r *http.Request) (string, bool) {
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		id, secret = u, p
	}
	if id == s.browserClient {
		return id, subtle.ConstantTimeCompare([]byte(secret), []byte(s.browserSecret)) == 1
	}
	_, ok := s.clients[id]
	return id, ok
}

func challengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func (s *issuer) tokenSet(client, person string, scopes []string, nonce string) (map[string]any, error) {
	access, err := s.accessToken(client, person, mintOptions{})
	if err != nil {
		return nil, err
	}
	body := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(s.accessLifetime / time.Second)}
	if hasScope(scopes, "openid") {
		id, err := s.idToken(client, person, nonce)
		if err != nil {
			return nil, err
		}
		body["id_token"] = id
	}
	s.mu.Lock()
	rt := s.nextID("rt-")
	s.refresh[rt] = issuerRefresh{client: client, person: person, scopes: scopes}
	s.mu.Unlock()
	body["refresh_token"] = rt
	return body, nil
}

func (s *issuer) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	client, ok := s.clientFrom(r)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.mu.Lock()
		code, found := s.codes[r.PostForm.Get("code")]
		delete(s.codes, r.PostForm.Get("code"))
		s.mu.Unlock()
		if !found || code.client != client || code.redirectURI != r.PostForm.Get("redirect_uri") || time.Since(code.issuedAt) > 2*time.Minute ||
			(code.challenge != "" && challengeS256(r.PostForm.Get("code_verifier")) != code.challenge) {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		body, err := s.tokenSet(client, code.person, code.scopes, code.nonce)
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
		writeJSON(w, http.StatusOK, body)
	case "refresh_token":
		presented := r.PostForm.Get("refresh_token")
		s.mu.Lock()
		rec, found := s.refresh[presented]
		clientRevoked := s.revoked[client]
		ok := found && rec.client == client && !clientRevoked
		if ok {
			delete(s.refresh, presented) // rotation: the presented token is spent
			s.refreshN[client]++
		}
		s.mu.Unlock()
		if !ok {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		body, err := s.tokenSet(client, rec.person, rec.scopes, "")
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
		writeJSON(w, http.StatusOK, body)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (s *issuer) userinfo(w http.ResponseWriter, r *http.Request) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	claims, err := s.verify(token)
	if !ok || !strings.EqualFold(scheme, "Bearer") || err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sub, _ := claims["sub"].(string)
	for _, p := range issuerPersons {
		if p.subject == sub {
			writeJSON(w, http.StatusOK, map[string]any{"sub": p.subject, "email": p.email, "email_verified": true, "preferred_username": p.username, "name": p.name})
			return
		}
	}
	http.Error(w, "unknown subject", http.StatusUnauthorized)
}

func (s *issuer) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	s.mu.Lock()
	delete(s.refresh, r.PostForm.Get("token"))
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// revokeClient refuses every refresh of client from now on: the provider-side
// revocation of a machine.
func (s *issuer) revokeClient(client string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[client] = true
	n := 0
	for rt, rec := range s.refresh {
		if rec.client == client {
			delete(s.refresh, rt)
			n++
		}
	}
	return n
}

// refreshes counts the refresh grants a client was given.
func (s *issuer) refreshes(client string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshN[client]
}
