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
	"sync"
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
type Provider interface {
	Refresh(ctx context.Context, refreshToken string) (Renewal, error)
	// Revoke asks the provider to end the refresh token. It is best effort.
	Revoke(ctx context.Context, refreshToken string) error
}

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

// aboutTheClient reports whether a refusal says the provider did not accept
// the client, as opposed to what the client asked for.
func aboutTheClient(refused *RefusedError) bool {
	switch refused.Code {
	case "invalid_client", "unauthorized_client", "invalid_request":
		return true
	}
	return refused.Status == http.StatusUnauthorized
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
	// ClientAuthDetect finds out which of the two ways the provider takes,
	// before any refresh token is sent: see HTTPProvider.
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
	// ClientAuth is how the secret is sent. The zero value detects it.
	ClientAuth ClientAuth
	// HTTPClient makes the calls. Nil means a client with a five-second
	// timeout. Either way no redirect is followed.
	HTTPClient *http.Client
}

// probeRefreshToken is sent as a refresh token to find out how the provider
// takes the client secret. It is not a token, and no provider issued it.
const probeRefreshToken = "dagu-client-authentication-probe" //nolint:gosec // G101: not a credential; a value no provider issued

// HTTPProvider talks to a provider's token and revocation endpoints.
//
// A refusal of a refresh has to be an answer about the refresh token and
// nothing else, whatever its code. A provider refuses a client that sent its
// secret the wrong way too, so the way has to be known before a session's
// token is sent. The sign-in's own code exchange finds it by trying, and does
// not say what it found. So with ClientAuthDetect the first call here sends a
// refresh request for a token that is not one, in the header and, if the
// provider refuses the client that way, in the form. The way the provider
// judged that request by is its way from then on. Until that is known no
// session's token is sent, and the call is reported as no answer.
type HTTPProvider struct {
	tokenURL      string
	revocationURL string
	clientID      string
	clientSecret  string
	client        *http.Client
	// clientAuth is the ClientAuth in use: the configured one, or the one a
	// provider's answer settled.
	clientAuth atomic.Int32
	// settling lets one call at a time find the provider's way.
	settling sync.Mutex
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
	}
	provider.clientAuth.Store(int32(cfg.ClientAuth))
	return provider, nil
}

// Refresh implements Provider.
func (p *HTTPProvider) Refresh(ctx context.Context, refreshToken string) (Renewal, error) {
	auth, err := p.settledClientAuth(ctx)
	if err != nil {
		return Renewal{}, err
	}
	return p.refresh(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}, auth)
}

// settledClientAuth returns the way the provider takes the client secret,
// finding it out first if it is not known. An error means it could not be
// found out now, and nothing was learned about any session.
func (p *HTTPProvider) settledClientAuth(ctx context.Context) (ClientAuth, error) {
	if auth := ClientAuth(p.clientAuth.Load()); auth != ClientAuthDetect || p.clientSecret == "" {
		return auth, nil
	}
	p.settling.Lock()
	defer p.settling.Unlock()
	if auth := ClientAuth(p.clientAuth.Load()); auth != ClientAuthDetect {
		return auth, nil
	}

	probe := func(auth ClientAuth) (acceptedClient bool, err error) {
		_, err = p.refresh(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {probeRefreshToken}}, auth)
		var refused *RefusedError
		switch {
		case err == nil:
			// A provider that grants this grants anything; it took the client.
			return true, nil
		case errors.As(err, &refused):
			return !aboutTheClient(refused), nil
		default:
			return false, err
		}
	}
	accepted, err := probe(ClientAuthHeader)
	if err != nil {
		return ClientAuthDetect, err
	}
	auth := ClientAuthHeader
	if !accepted {
		// Refused as a client in the header. If the form is taken, the form
		// is the way. If the client is refused that way too, the way is not
		// what the provider objects to: the header it is, and the refusal of
		// a session's token that follows is the provider's answer.
		accepted, err = probe(ClientAuthForm)
		if err != nil {
			return ClientAuthDetect, err
		}
		if accepted {
			auth = ClientAuthForm
		}
	}
	p.clientAuth.Store(int32(auth))
	return auth, nil
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

// Revoke implements Provider.
func (p *HTTPProvider) Revoke(ctx context.Context, refreshToken string) error {
	if p.revocationURL == "" {
		return errors.New("the identity provider has no revocation endpoint")
	}
	auth, err := p.settledClientAuth(ctx)
	if err != nil {
		return err
	}
	status, _, err := p.post(ctx, p.revocationURL, url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}}, auth)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("the revocation endpoint answered %d", status)
	}
	return nil
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
