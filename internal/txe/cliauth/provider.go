// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package cliauth signs the developer CLI in at the identity provider and
// keeps the result: a browser-assisted authorization-code flow with PKCE on a
// one-shot loopback listener, renewal with the refresh token, revocation, and
// a per-hub store of the tokens.
//
// Who a sign-in is, is the pair of issuer and subject. Email, username and
// display name are kept for showing only and are never compared.
//
// Nothing here collects a password or accepts a pasted code or token: the
// provider's own page in the system browser is the only place a person types
// anything.
package cliauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
)

// Provider is the public client the CLI signs in with. It has no secret.
type Provider struct {
	// Issuer is compared as an exact string with what the provider says it
	// is, and with every token's issuer.
	Issuer string
	// ClientID is the provider client the CLI is registered as.
	ClientID string
	// Scopes are requested at sign-in. "openid" is always requested.
	Scopes []string
}

// Validate checks the configuration before any network call.
func (p Provider) Validate() error {
	if p.ClientID == "" {
		return errors.New("a client id is required")
	}
	if strings.TrimSpace(p.ClientID) != p.ClientID {
		return errors.New("the client id must not start or end with white space")
	}
	return checkIssuer(p.Issuer)
}

func (p Provider) scopes() []string {
	scopes := []string{"openid"}
	for _, s := range p.Scopes {
		if s != "" && !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// checkIssuer requires an absolute https URL, or plain http on a loopback
// host for a provider on this machine, with no query, fragment or user info.
func checkIssuer(issuer string) error {
	if issuer == "" {
		return errors.New("an issuer is required")
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("invalid issuer: %w", err)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("invalid issuer %q: it must be an absolute URL with no user, query or fragment", issuer)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("issuer %q must use https", issuer)
	default:
		return fmt.Errorf("issuer %q must use https", issuer)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// endpoints is what discovery found.
type endpoints struct {
	provider   *oidc.Provider
	authURL    string
	tokenURL   string
	revocation string
}

const (
	// providerRequestTimeout bounds one request to the provider when the
	// caller's client sets no limit of its own.
	providerRequestTimeout = 30 * time.Second
	// maxProviderResponse bounds every body read from the provider:
	// discovery, keys, tokens and revocation.
	maxProviderResponse = 1 << 20
)

// errResponseTooLarge reports a provider answer over maxProviderResponse.
var errResponseTooLarge = errors.New("the identity provider's answer is too large")

// providerClient returns an HTTP client that never follows a redirect: the
// provider's endpoints answer directly, and a redirect could carry a request
// with a code or token to another host. Each request is bounded in time, and
// each answer in size, including the ones go-oidc reads itself.
func providerClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if c.Timeout <= 0 {
		c.Timeout = providerRequestTimeout
	}
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	if _, ok := base.(limitedTransport); !ok {
		c.Transport = limitedTransport{base: base}
	}
	return &c
}

// limitedTransport fails a response body once it passes maxProviderResponse.
type limitedTransport struct {
	base http.RoundTripper
}

func (t limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > maxProviderResponse {
		_ = resp.Body.Close()
		return nil, errResponseTooLarge
	}
	resp.Body = &limitedBody{body: resp.Body, left: maxProviderResponse}
	return resp, nil
}

type limitedBody struct {
	body io.ReadCloser
	left int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, errResponseTooLarge
	}
	// Read one byte past the limit, so that a body of exactly the limit
	// still ends cleanly.
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.body.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return 0, errResponseTooLarge
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.body.Close() }

// discover reads the provider's metadata. The issuer it states must equal
// p.Issuer exactly, and every endpoint must be acceptable the way the issuer
// is.
func discover(ctx context.Context, p Provider, client *http.Client) (*endpoints, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), p.Issuer)
	if err != nil {
		// A provider that answers with another issuer is answering, and
		// is the wrong provider: that is no outage.
		if strings.Contains(err.Error(), "issuer did not match") {
			return nil, fmt.Errorf("the provider at %s does not say it is that issuer: %w", p.Issuer, err)
		}
		return nil, &UnverifiableError{Op: "discovery", Err: err}
	}
	var meta struct {
		Revocation string `json:"revocation_endpoint"`
		JWKS       string `json:"jwks_uri"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, &UnverifiableError{Op: "discovery", Err: err}
	}
	// go-oidc fetches the signing keys from jwks_uri as given, so it is held
	// to the issuer's rule like every other endpoint.
	if meta.JWKS == "" {
		return nil, errors.New("the provider names no signing keys (jwks_uri)")
	}
	if err := checkIssuer(meta.JWKS); err != nil {
		return nil, fmt.Errorf("provider's signing keys endpoint: %w", err)
	}
	e := &endpoints{
		provider:   provider,
		authURL:    provider.Endpoint().AuthURL,
		tokenURL:   provider.Endpoint().TokenURL,
		revocation: meta.Revocation,
	}
	for name, endpoint := range map[string]string{"authorization": e.authURL, "token": e.tokenURL} {
		if err := checkIssuer(endpoint); err != nil {
			return nil, fmt.Errorf("provider's %s endpoint: %w", name, err)
		}
	}
	if e.revocation != "" {
		if err := checkIssuer(e.revocation); err != nil {
			return nil, fmt.Errorf("provider's revocation endpoint: %w", err)
		}
	}
	return e, nil
}
