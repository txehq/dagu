// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cliauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
)

// Tokens is what one sign-in or renewal returned.
type Tokens struct {
	Identity Identity
	// Username is the provider's preferred_username, for showing only.
	Username     string
	AccessToken  string
	RefreshToken string
	// Expiry is when the access token stops being usable, by this
	// machine's clock.
	Expiry time.Time
}

// Identity is who a sign-in is. Both fields are compared as exact strings.
type Identity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

// RefusedError is the provider's verdict that a grant no longer works: a 400
// or 401 from its token endpoint whose JSON body has an "error" member, such
// as invalid_grant (user disabled or deleted, session or grant ended),
// not_allowed or invalid_client. Signing in again is the only way on.
type RefusedError struct {
	Status int
	Code   string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("the identity provider refused to renew the sign-in (%d %s): run \"dagu txe login\"", e.Status, e.Code)
}

// UnverifiableError means the provider gave no verdict: it could not be
// reached, timed out, failed, limited the rate, or answered with something
// that is not an OAuth error. It never means the sign-in has ended.
type UnverifiableError struct {
	Op     string
	Status int
	Err    error
}

func (e *UnverifiableError) Error() string {
	switch {
	case e.Err != nil:
		return fmt.Sprintf("the identity provider did not answer (%s): %v", e.Op, e.Err)
	case e.Status != 0:
		return fmt.Sprintf("the identity provider did not answer (%s): HTTP %d", e.Op, e.Status)
	default:
		return fmt.Sprintf("the identity provider did not answer (%s)", e.Op)
	}
}

func (e *UnverifiableError) Unwrap() error { return e.Err }

// maxTokenResponse bounds what is read from the token endpoint.
const maxTokenResponse = 1 << 20

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// postToken sends one form request to the token endpoint and classifies the
// answer. A 2xx is decoded; a 400 or 401 with a JSON "error" is a
// *RefusedError; anything else is an *UnverifiableError.
func postToken(ctx context.Context, client *http.Client, tokenURL, op string, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, &UnverifiableError{Op: op, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return nil, &UnverifiableError{Op: op, Err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if code := oauthErrorCode(resp, body); code != "" {
			return nil, &RefusedError{Status: resp.StatusCode, Code: code}
		}
		return nil, &UnverifiableError{Op: op, Status: resp.StatusCode}
	}
	var out tokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &UnverifiableError{Op: op, Err: errors.New("the answer is not a token response")}
	}
	if out.AccessToken == "" {
		return nil, &UnverifiableError{Op: op, Err: errors.New("the answer has no access token")}
	}
	if !strings.EqualFold(out.TokenType, "bearer") {
		return nil, fmt.Errorf("%s: the provider issued a %q token, not a bearer token", op, out.TokenType)
	}
	return &out, nil
}

// oauthErrorCode returns the "error" member of a 400 or 401 JSON body, or "".
// Only those two codes are a verdict: a 5xx or 429 with the same body is the
// provider failing, not deciding.
func oauthErrorCode(resp *http.Response, body []byte) string {
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		return ""
	}
	var envelope struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return ""
	}
	return cleanCode(envelope.Error)
}

// cleanCode keeps an error code printable: RFC 6749 limits it to visible
// ASCII except the double quote and the backslash. Anything else, or a code
// over 64 bytes, is shown as "error". An empty code stays empty: it is no
// verdict.
func cleanCode(code string) string {
	if len(code) > 64 {
		return "error"
	}
	for _, r := range code {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return "error"
		}
	}
	return code
}

// Refresh renews a sign-in with its refresh token. The result keeps the
// refresh token it was given unless the provider issued a new one. When the
// provider returns an ID token it must be valid for p and name want; when it
// returns none, the access token's own issuer and subject, read without
// verification, must not name anyone else. A renewal that names someone
// else is refused and its tokens are dropped.
//
// The error is a *RefusedError, ErrIdentityChanged, ErrNotSignedIn when
// there is no refresh token, or otherwise an *UnverifiableError.
func Refresh(ctx context.Context, p Provider, want Identity, refreshToken string, client *http.Client) (*Tokens, error) {
	if refreshToken == "" {
		return nil, ErrNotSignedIn
	}
	tokens, err := refresh(ctx, p, want, refreshToken, providerClient(client))
	if err != nil {
		return nil, renewalVerdict(err)
	}
	return tokens, nil
}

// renewalVerdict keeps a refusal and a changed identity as they are. Every
// other failure gave no verdict on the grant, so it is an
// *UnverifiableError.
func renewalVerdict(err error) error {
	if _, ok := errors.AsType[*RefusedError](err); ok {
		return err
	}
	if _, ok := errors.AsType[*UnverifiableError](err); ok {
		return err
	}
	if errors.Is(err, ErrIdentityChanged) {
		return err
	}
	return &UnverifiableError{Op: "renewal", Err: err}
}

func refresh(ctx context.Context, p Provider, want Identity, refreshToken string, client *http.Client) (*Tokens, error) {
	e, err := discover(ctx, p, client)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	resp, err := postToken(ctx, client, e.tokenURL, "renewal", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {p.ClientID},
		"refresh_token": {refreshToken},
	})
	if err != nil {
		return nil, err
	}
	tokens := &Tokens{Identity: want, AccessToken: resp.AccessToken, RefreshToken: resp.RefreshToken}
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = refreshToken
	}
	if resp.IDToken != "" {
		// An ID token naming another issuer fails verification before its
		// identity could be compared; read first, it is a changed identity.
		if err := checkTokenIdentity(resp.IDToken, want); err != nil {
			return nil, err
		}
		claims, err := verifyIDToken(ctx, e, p, client, resp.IDToken, "")
		if err != nil {
			return nil, err
		}
		if claims.identity != want {
			return nil, ErrIdentityChanged
		}
		tokens.Username = claims.username
	}
	if err := checkTokenIdentity(resp.AccessToken, want); err != nil {
		return nil, err
	}
	tokens.Expiry = expiry(now, resp.ExpiresIn, resp.AccessToken)
	return tokens, nil
}

// ErrIdentityChanged reports a renewal or sign-in that names another
// identity than the one it was for.
var ErrIdentityChanged = errors.New("the identity provider returned tokens for another identity; they were discarded: run \"dagu txe login\"")

// checkTokenIdentity reads a token's iss and sub without verifying it (the
// hub verifies an access token; an ID token is verified after this) and
// refuses a token that names another identity, or names one in a form that
// is not a string. A token that is not a readable JWT, or carries neither
// claim, is accepted: the provider is not required to issue JWT access
// tokens.
func checkTokenIdentity(token string, want Identity) error {
	claims, ok := unverifiedClaims(token)
	if !ok {
		return nil
	}
	if !claims.allows("iss", want.Issuer) || !claims.allows("sub", want.Subject) {
		return ErrIdentityChanged
	}
	return nil
}

// jwtClaims is a JWT's payload, read without verification. Each claim is
// read on its own, so that one in an unexpected form (a fractional exp,
// which RFC 7519 allows) cannot hide another.
type jwtClaims map[string]json.RawMessage

func unverifiedClaims(token string) (jwtClaims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var c jwtClaims
	if err := json.Unmarshal(payload, &c); err != nil || c == nil {
		return nil, false
	}
	return c, true
}

// allows reports whether the claim is absent, empty, or the string want.
func (c jwtClaims) allows(name, want string) bool {
	raw, ok := c[name]
	if !ok {
		return true
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	return v == "" || v == want
}

// maxExpiry is beyond any real exp; a larger one is treated as absent
// rather than converted.
const maxExpiry = 1 << 40

// expiry returns the exp claim, rounded down to the second, when it is a
// positive number.
func (c jwtClaims) expiry() (time.Time, bool) {
	raw, ok := c["exp"]
	if !ok {
		return time.Time{}, false
	}
	var exp float64
	if err := json.Unmarshal(raw, &exp); err != nil || exp <= 0 || exp > maxExpiry {
		return time.Time{}, false
	}
	return time.Unix(int64(exp), 0), true
}

// expiry is the earlier of expires_in counted from when the request was
// sent and the token's own exp, when it has one. With neither, the token is
// treated as already expired, so it is renewed before every use.
func expiry(sent time.Time, expiresIn int64, accessToken string) time.Time {
	var at time.Time
	if expiresIn > 0 {
		at = sent.Add(time.Duration(expiresIn) * time.Second)
	}
	if c, ok := unverifiedClaims(accessToken); ok {
		if exp, ok := c.expiry(); ok && (at.IsZero() || exp.Before(at)) {
			at = exp
		}
	}
	if at.IsZero() {
		return sent
	}
	return at
}

type idClaims struct {
	identity Identity
	username string
}

// verifyIDToken checks an ID token's signature against the issuer's keys,
// its exact issuer, its audience, its expiry, its authorized party when it
// names one, and, when nonce is not empty, its nonce.
func verifyIDToken(ctx context.Context, e *endpoints, p Provider, client *http.Client, raw, nonce string) (*idClaims, error) {
	verifier := e.provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	token, err := verifier.Verify(oidc.ClientContext(ctx, client), raw)
	if err != nil {
		return nil, fmt.Errorf("the provider's ID token is not valid: %w", err)
	}
	var extra struct {
		AuthorizedParty   string `json:"azp"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := token.Claims(&extra); err != nil {
		return nil, fmt.Errorf("the provider's ID token is not valid: %w", err)
	}
	if extra.AuthorizedParty != "" && extra.AuthorizedParty != p.ClientID {
		return nil, errors.New("the provider's ID token was issued to another client")
	}
	if len(token.Audience) > 1 && extra.AuthorizedParty == "" {
		return nil, errors.New("the provider's ID token has several audiences and names no authorized party")
	}
	if nonce != "" && !constantTimeEqual(token.Nonce, nonce) {
		return nil, errors.New("the provider's ID token is not for this sign-in (nonce mismatch)")
	}
	if token.Subject == "" {
		return nil, errors.New("the provider's ID token names no subject")
	}
	return &idClaims{
		identity: Identity{Issuer: token.Issuer, Subject: token.Subject},
		username: extra.PreferredUsername,
	}, nil
}

// Revoke asks the provider to revoke a refresh token (RFC 7009). It reports
// whether the provider confirmed. A provider with no revocation endpoint
// gives (false, nil).
func Revoke(ctx context.Context, p Provider, refreshToken string, client *http.Client) (bool, error) {
	if refreshToken == "" {
		return false, nil
	}
	client = providerClient(client)
	e, err := discover(ctx, p, client)
	if err != nil {
		return false, err
	}
	if e.revocation == "" {
		return false, nil
	}
	form := url.Values{
		"client_id":       {p.ClientID},
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.revocation, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false, &UnverifiableError{Op: "revocation", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxTokenResponse))
	if resp.StatusCode != http.StatusOK {
		return false, &UnverifiableError{Op: "revocation", Status: resp.StatusCode}
	}
	return true, nil
}
