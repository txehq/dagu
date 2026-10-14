// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cliauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// What a hub asks the CLI to use its sign-in for.
const (
	// HubUseIdentity: only GET /txe/identity accepts a CLI token; every
	// other call keeps the context's API key.
	HubUseIdentity = "identity"
	// HubUseAll: every call the CLI makes to the hub carries the sign-in.
	HubUseAll = "all"
)

// HubCLIPath is the hub's nonsecret description of its CLI client, relative
// to the API root.
const HubCLIPath = "/txe/auth/cli"

// HubIdentityPath is the hub's account of who a request is, relative to the
// API root.
const HubIdentityPath = "/txe/identity"

// HubConfig is what a hub publishes about signing its CLI in. It holds no
// secret: the CLI client is public.
type HubConfig struct {
	Contract int      `json:"contract"`
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes,omitempty"`
	Use      string   `json:"use"`
}

// Provider is the provider the hub names.
func (c HubConfig) Provider() Provider {
	return Provider{Issuer: c.Issuer, ClientID: c.ClientID, Scopes: c.Scopes}
}

// ErrHubNoSignIn reports a hub that does not publish a CLI client: it
// answers HubCLIPath with 401, 403, 404 or 405, or with a 200 that is not
// JSON (an older hub's web UI). Such a hub is sent no sign-in.
var ErrHubNoSignIn = errors.New("this hub does not accept CLI sign-in")

// maxHubResponse bounds what is read from the hub's small JSON answers.
const maxHubResponse = 64 << 10

// DiscoverHub reads the hub's CLI client from apiBase (the hub's API root,
// such as http://127.0.0.1:18080/api/v1). It sends no credential.
func DiscoverHub(ctx context.Context, apiBase string, client *http.Client) (*HubConfig, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+HubCLIPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read the hub's sign-in settings: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHubResponse+1))
	if err != nil {
		return nil, fmt.Errorf("read the hub's sign-in settings: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusMethodNotAllowed:
		return nil, ErrHubNoSignIn
	case resp.StatusCode == http.StatusOK && !isJSON(resp.Header.Get("Content-Type")):
		return nil, ErrHubNoSignIn
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("read the hub's sign-in settings: HTTP %d", resp.StatusCode)
	case len(body) > maxHubResponse:
		return nil, errors.New("read the hub's sign-in settings: the answer is too large")
	}
	var cfg HubConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("read the hub's sign-in settings: %w", err)
	}
	if cfg.Contract != 1 {
		return nil, fmt.Errorf("the hub's sign-in settings are contract %d; this CLI reads contract 1", cfg.Contract)
	}
	if cfg.Use != HubUseIdentity && cfg.Use != HubUseAll {
		return nil, fmt.Errorf("the hub's sign-in settings name an unknown use %q", cfg.Use)
	}
	if err := cfg.Provider().Validate(); err != nil {
		return nil, fmt.Errorf("the hub's sign-in settings: %w", err)
	}
	return &cfg, nil
}

func isJSON(contentType string) bool {
	media, _, _ := strings.Cut(contentType, ";")
	return strings.EqualFold(strings.TrimSpace(media), "application/json")
}

// Matches reports whether a sign-in was made at the provider and client the
// hub names. A sign-in made elsewhere is never sent to the hub.
func (c HubConfig) Matches(e *Entry) bool {
	return e != nil && e.Provider.Issuer == c.Issuer && e.Provider.ClientID == c.ClientID
}

// ErrHubRefusedSignIn reports that the hub refused the sign-in's token
// again after it was renewed.
var ErrHubRefusedSignIn = errors.New("the hub refused this sign-in: run \"dagu txe login\"")

// HubProviderUnavailableError reports a hub that could not check a token
// because it could not reach the identity provider. It is no verdict on the
// sign-in; the request was not served and may be sent again later.
type HubProviderUnavailableError struct {
	RetryAfter string
}

func (e *HubProviderUnavailableError) Error() string {
	msg := "the identity provider did not answer the hub, so it could not check this sign-in"
	if e.RetryAfter != "" {
		msg += "; retry after " + e.RetryAfter + " s"
	}
	return msg
}

// BearerTransport sends a hub's requests with the hub's sign-in instead of
// any credential the request carries.
//
// It sends the bearer only to the hub's own scheme and host: a redirect
// elsewhere is refused before anything is sent. When the hub answers 401
// with error="invalid_token", the token is renewed and the request sent once
// more; the hub's authentication refuses before any handler runs, so the
// first attempt did nothing. A request whose body cannot be read again is
// not resent. A second refusal is ErrHubRefusedSignIn, and nothing renews
// again. A 503 provider_unavailable is a *HubProviderUnavailableError.
type BearerTransport struct {
	// Base sends the requests. Nil means http.DefaultTransport.
	Base http.RoundTripper
	// Store holds the sign-in; Hub names it.
	Store *Store
	Hub   string
	// Provider is used for renewals. Nil means http.DefaultClient.
	Provider *http.Client
}

func (t *BearerTransport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// RoundTrip implements http.RoundTripper.
func (t *BearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		defer func() { _ = req.Body.Close() }()
	}
	if err := t.sameHub(req.URL); err != nil {
		return nil, err
	}
	ctx := req.Context()
	token, err := t.Store.AccessToken(ctx, t.Hub, t.Provider)
	if err != nil {
		return nil, err
	}
	resp, err := t.send(req, req.Body, token)
	if err != nil {
		return nil, err
	}
	if !invalidToken(resp) {
		return t.checkUnavailable(resp)
	}
	if req.Body != nil && req.GetBody == nil {
		// The body is spent and cannot be read again: the refusal stands.
		return resp, nil
	}
	discard(resp)
	renewed, err := t.Store.Renew(ctx, t.Hub, token, t.Provider)
	if err != nil {
		return nil, err
	}
	var body io.ReadCloser
	if req.GetBody != nil {
		if body, err = req.GetBody(); err != nil {
			return nil, err
		}
	}
	resp, err = t.send(req, body, renewed)
	if err != nil {
		return nil, err
	}
	if invalidToken(resp) {
		discard(resp)
		return nil, ErrHubRefusedSignIn
	}
	return t.checkUnavailable(resp)
}

// sameHub refuses any URL outside the hub's scheme and host, so a redirect
// cannot carry the token elsewhere.
func (t *BearerTransport) sameHub(u *url.URL) error {
	hub, err := url.Parse(t.Hub)
	if err != nil {
		return err
	}
	if !strings.EqualFold(u.Scheme, hub.Scheme) || !strings.EqualFold(u.Host, hub.Host) {
		return fmt.Errorf("refusing to send this hub's sign-in to %s://%s", u.Scheme, u.Host)
	}
	return nil
}

func (t *BearerTransport) send(req *http.Request, body io.ReadCloser, token string) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Body = body
	out.Header.Set("Authorization", "Bearer "+token)
	return t.base().RoundTrip(out)
}

// invalidToken reports the hub's refusal of a token: 401 with a Bearer
// challenge naming error="invalid_token".
func invalidToken(resp *http.Response) bool {
	if resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	for _, challenge := range resp.Header.Values("WWW-Authenticate") {
		lower := strings.ToLower(challenge)
		if strings.HasPrefix(lower, "bearer") && strings.Contains(lower, `error="invalid_token"`) {
			return true
		}
	}
	return false
}

// checkUnavailable turns the hub's 503 provider_unavailable into a
// *HubProviderUnavailableError and returns every other response unchanged.
func (t *BearerTransport) checkUnavailable(resp *http.Response) (*http.Response, error) {
	if resp.StatusCode != http.StatusServiceUnavailable {
		return resp, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxHubResponse))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Details struct {
			Code string `json:"code"`
		} `json:"details"`
	}
	if json.Unmarshal(data, &envelope) == nil && envelope.Details.Code == "provider_unavailable" {
		return nil, &HubProviderUnavailableError{RetryAfter: cleanRetryAfter(resp.Header.Get("Retry-After"))}
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return resp, nil
}

// cleanRetryAfter keeps a Retry-After of delay seconds and drops anything
// else, so nothing the hub sent is printed unchecked.
func cleanRetryAfter(v string) string {
	if v == "" || len(v) > 6 {
		return ""
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return v
}

func discard(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHubResponse))
	_ = resp.Body.Close()
}
