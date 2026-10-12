// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package oidcsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Renewal is what the provider returned for a refresh it granted.
type Renewal struct {
	// RefreshToken is the token to use next time. It is empty when the
	// provider returned none, in which case the one that was sent stays.
	RefreshToken string
	// IDToken is the raw ID token the provider returned, or "".
	IDToken string
}

// Provider is the identity provider, as far as a session needs it.
//
// Refresh has three outcomes, and telling them apart is the point of this
// package. A granted refresh returns a Renewal. A refusal returns a
// *RefusedError: the provider answered, and its answer is no. Anything else
// is any other error: the provider could not be asked, or what came back was
// not an answer, and nothing is known about the session.
//
// A provider refuses a client that sent its secret in a way it does not take
// just as it refuses a refresh token. So that a refusal is always about the
// token, the way is established once, at sign-in, by a refresh the provider
// grants, and kept with the session. Every later call for the session is
// made that way and no other.
type Provider interface {
	// Establish is asked at sign-in, with the refresh token the provider has
	// just issued. It returns the way the provider takes the client secret,
	// and a Renewal when finding that out exchanged the token. A
	// *RefusedError means the provider will not refresh the token it has just
	// issued, whichever way it is asked.
	Establish(ctx context.Context, refreshToken string) (ClientAuth, Renewal, error)
	Refresh(ctx context.Context, refreshToken string, auth ClientAuth) (Renewal, error)
	// Revoke asks the provider to end the refresh token.
	Revoke(ctx context.Context, refreshToken string, auth ClientAuth) error
}

// ErrRevocationUnsupported is what Revoke returns for a provider that has no
// revocation endpoint. Asking again later would change nothing.
var ErrRevocationUnsupported = errors.New("the identity provider has no revocation endpoint")

// ErrRevocationRefused is what Revoke returns when the provider answered and
// did not revoke: a 4xx from the revocation endpoint, other than one that
// says to come back later. The provider is there, and asking it the same
// thing again is unlikely to change its answer.
var ErrRevocationRefused = errors.New("the identity provider refused the revocation")

// RefusedError is the provider's definite refusal of a refresh: a 400 or 401
// from the token endpoint whose JSON body names an OAuth error. Code is that
// error, kept only if it is one a provider is known to send here.
type RefusedError struct {
	Status int
	Code   string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("the identity provider refused the refresh: %s (status %d)", e.Code, e.Status)
}

// knownRefusalCodes are the OAuth error codes repeated in records and logs.
// Any other code is recorded as "other": the code is the provider's text, and
// nothing the provider chose to say is repeated unless it is one of these.
var knownRefusalCodes = map[string]bool{
	"invalid_grant":          true,
	"invalid_client":         true,
	"invalid_request":        true,
	"invalid_scope":          true,
	"unauthorized_client":    true,
	"unsupported_grant_type": true,
	"not_allowed":            true,
	"access_denied":          true,
}

func refusalCode(code string) string {
	if knownRefusalCodes[code] {
		return code
	}
	return "other"
}

const (
	defaultProviderTimeout = 5 * time.Second
	maxProviderBody        = 1 << 20
)

// ClientAuth is how the hub's client secret is sent to the provider.
type ClientAuth int32

const (
	// ClientAuthDetect is the way not being known: it is established at
	// sign-in. A session never has it.
	ClientAuthDetect ClientAuth = iota
	// ClientAuthForm sends the client id and secret in the form
	// (client_secret_post).
	ClientAuthForm
	// ClientAuthHeader sends them in the Authorization header
	// (client_secret_basic).
	ClientAuthHeader
)

// HTTPProviderConfig configures an HTTPProvider.
type HTTPProviderConfig struct {
	// TokenURL is the provider's token endpoint.
	TokenURL string
	// RevocationURL is the provider's revocation endpoint (RFC 7009), or ""
	// when it has none.
	RevocationURL string
	ClientID      string
	ClientSecret  string
	// ClientAuth is how the secret is sent. The zero value establishes it at
	// sign-in.
	ClientAuth ClientAuth
	// HTTPClient makes the calls. Nil means a client with a five-second
	// timeout. Either way no redirect is followed.
	HTTPClient *http.Client
}

// HTTPProvider talks to a provider's token and revocation endpoints.
type HTTPProvider struct {
	tokenURL      string
	revocationURL string
	clientID      string
	clientSecret  string
	client        *http.Client
	// configured is the way the configuration sets, or ClientAuthDetect.
	configured ClientAuth
	// granted is the way of the last refresh the provider granted, or
	// ClientAuthDetect before there was one. It is the way a sign-in tries
	// first, and decides nothing by itself: a session's way is the one its
	// own token was granted by.
	granted atomic.Int32
}

// NewHTTPProvider validates cfg and returns a provider.
func NewHTTPProvider(cfg HTTPProviderConfig) (*HTTPProvider, error) {
	if cfg.TokenURL == "" || cfg.ClientID == "" {
		return nil, errors.New("oidcsession: a token endpoint and a client id are required")
	}
	client := http.Client{Timeout: defaultProviderTimeout}
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
	}
	// A redirect could carry the refresh token to another host.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if cfg.ClientAuth < ClientAuthDetect || cfg.ClientAuth > ClientAuthHeader {
		return nil, errors.New("oidcsession: unknown client authentication method")
	}
	provider := &HTTPProvider{
		tokenURL:      cfg.TokenURL,
		revocationURL: cfg.RevocationURL,
		clientID:      cfg.ClientID,
		clientSecret:  cfg.ClientSecret,
		client:        &client,
		configured:    cfg.ClientAuth,
	}
	return provider, nil
}

// Establish implements Provider.
//
// The refresh token was issued a moment ago, so a refusal of it is about the
// client and not about the token. It is refreshed one way, and the other if
// the provider refuses the first. The way it is granted by is the provider's,
// for this session. If neither is granted, the provider will not refresh what
// it issues, a session could never be revalidated, and the sign-in fails.
//
// The way the last refresh was granted by is tried first. It is not taken on
// trust: the provider may have been changed since.
func (p *HTTPProvider) Establish(ctx context.Context, refreshToken string) (ClientAuth, Renewal, error) {
	switch {
	case p.clientSecret == "":
		// A public client has no secret to send. It names itself in the form.
		return ClientAuthForm, Renewal{}, nil
	case p.configured != ClientAuthDetect:
		return p.configured, Renewal{}, nil
	}
	first, second := ClientAuthHeader, ClientAuthForm
	if ClientAuth(p.granted.Load()) == ClientAuthForm {
		first, second = second, first
	}
	renewal, err := p.Refresh(ctx, refreshToken, first)
	var refused *RefusedError
	switch {
	case err == nil:
		return first, renewal, nil
	case !errors.As(err, &refused):
		return ClientAuthDetect, Renewal{}, err
	}
	renewal, err = p.Refresh(ctx, refreshToken, second)
	if err != nil {
		return ClientAuthDetect, Renewal{}, err
	}
	return second, renewal, nil
}

// Refresh implements Provider. It sends the refresh token once, the way it is
// told to.
func (p *HTTPProvider) Refresh(ctx context.Context, refreshToken string, auth ClientAuth) (Renewal, error) {
	renewal, err := p.refresh(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}, auth)
	if err == nil {
		p.granted.Store(int32(auth))
	}
	return renewal, err
}

func (p *HTTPProvider) refresh(ctx context.Context, form url.Values, auth ClientAuth) (Renewal, error) {
	status, body, err := p.post(ctx, p.tokenURL, form, auth)
	if err != nil {
		return Renewal{}, err
	}

	if status == http.StatusBadRequest || status == http.StatusUnauthorized {
		var refusal struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &refusal) == nil && refusal.Error != "" {
			return Renewal{}, &RefusedError{Status: status, Code: refusalCode(refusal.Error)}
		}
		// A 400 or 401 that is not an OAuth error did not come from the
		// token endpoint's own logic: a proxy or a gateway. Nothing is known.
		return Renewal{}, fmt.Errorf("the token endpoint answered %d without an OAuth error", status)
	}
	if status != http.StatusOK {
		return Renewal{}, fmt.Errorf("the token endpoint answered %d", status)
	}

	var granted struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &granted); err != nil || granted.AccessToken == "" {
		return Renewal{}, errors.New("the token endpoint answered 200 without a token")
	}
	return Renewal{RefreshToken: granted.RefreshToken, IDToken: granted.IDToken}, nil
}

// Revoke implements Provider. With ClientAuthDetect, which is all that is
// known of a token whose session was never established, it is asked both
// ways: the form is tried when the provider has answered no to the header.
// The answer is then no only if it was no both ways. A way that got no answer
// may have been the right one, and is reported as no answer.
func (p *HTTPProvider) Revoke(ctx context.Context, refreshToken string, auth ClientAuth) error {
	if p.revocationURL == "" {
		return ErrRevocationUnsupported
	}
	err := p.revoke(ctx, refreshToken, auth)
	if errors.Is(err, ErrRevocationRefused) && auth == ClientAuthDetect && p.clientSecret != "" {
		err = p.revoke(ctx, refreshToken, ClientAuthForm)
	}
	return err
}

func (p *HTTPProvider) revoke(ctx context.Context, refreshToken string, auth ClientAuth) error {
	status, _, err := p.post(ctx, p.revocationURL, url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}}, auth)
	if err != nil {
		return err
	}
	switch {
	case status == http.StatusOK:
		return nil
	case status == http.StatusRequestTimeout, status == http.StatusTooEarly, status == http.StatusTooManyRequests:
		// Not an answer about the revocation: the provider wants it later.
		return fmt.Errorf("the revocation endpoint answered %d", status)
	case status >= 400 && status < 500:
		return fmt.Errorf("%w: the revocation endpoint answered %d", ErrRevocationRefused, status)
	default:
		return fmt.Errorf("the revocation endpoint answered %d", status)
	}
}

// post sends a form to the provider as this client. Its errors never contain
// the form, the response body or anything else the provider said: both can
// hold the refresh token.
func (p *HTTPProvider) post(ctx context.Context, endpoint string, form url.Values, auth ClientAuth) (int, []byte, error) {
	inHeader := p.clientSecret != "" && auth != ClientAuthForm
	if !inHeader {
		form.Set("client_id", p.clientID)
		if p.clientSecret != "" {
			form.Set("client_secret", p.clientSecret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, errors.New("the provider request could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if inHeader {
		req.SetBasicAuth(url.QueryEscape(p.clientID), url.QueryEscape(p.clientSecret))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		// The error text of a failed request names the URL and the cause,
		// not the body. Its type is all that is kept.
		return 0, nil, fmt.Errorf("the identity provider did not answer (%T)", errors.Unwrap(err))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBody+1))
	if err != nil || len(body) > maxProviderBody {
		return 0, nil, errors.New("the identity provider's answer could not be read")
	}
	return resp.StatusCode, body, nil
}
