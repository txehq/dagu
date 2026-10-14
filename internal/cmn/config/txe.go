// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// TXEConfig configures who may do what to whose TXE data on this server.
type TXEConfig struct {
	Authz TXEAuthzConfig
	Authn TXEAuthnConfig
}

// TXEAuthzConfig says how owner authorization treats the credentials the
// server accepted before owners were enforced.
type TXEAuthzConfig struct {
	// Mode is off, observe or enforce. Empty is off.
	Mode string
}

// TXEAuthnConfig says which identity provider access tokens the server
// accepts as bearer credentials. With no issuer, it accepts none.
type TXEAuthnConfig struct {
	// Issuer is compared with a token's "iss" character for character.
	Issuer string
	// Audience must be one of a token's audiences.
	Audience string
	// JWKSURL is where the issuer publishes its signing keys.
	JWKSURL string
	// Clients maps each accepted provider client to the class its tokens
	// yield. A machine has one client per class.
	Clients []TXEAuthnClient
	// MaxLifetime caps a token's lifetime. Zero is the verifier's cap.
	MaxLifetime time.Duration
}

// TXEAuthnClient is one provider client and the class of caller it is.
type TXEAuthnClient struct {
	ID    string
	Class string
}

// Enabled reports whether provider access tokens are accepted.
func (c TXEAuthnConfig) Enabled() bool { return c.Issuer != "" }

const (
	// TXEAuthzModeOff is the behaviour of a server that does not enforce
	// owners.
	TXEAuthzModeOff = "off"
	// TXEAuthzModeObserve evaluates and logs what enforce would deny.
	TXEAuthzModeObserve = "observe"
	// TXEAuthzModeEnforce denies.
	TXEAuthzModeEnforce = "enforce"

	// txeAuthnMaxLifetime is the longest token lifetime that can be
	// configured. The verifier refuses anything longer as well.
	txeAuthnMaxLifetime = 5 * time.Minute
)

// txeAuthnClasses are the classes a provider token may yield. A person and
// the platform administrator are never a token.
var txeAuthnClasses = []string{"cli", "worker", "reviewer"}

const (
	txeKey              = "txe"
	txeAuthzKey         = "txe.authz"
	txeAuthzModeKey     = "txe.authz.mode"
	txeAuthnKey         = "txe.authn"
	txeAuthnIssuerKey   = "txe.authn.issuer"
	txeAuthnAudienceKey = "txe.authn.audience"
	txeAuthnJWKSKey     = "txe.authn.jwks_url"
	txeAuthnClientsKey  = "txe.authn.clients"
	txeAuthnLifetimeKey = "txe.authn.max_lifetime"
	txeAuthzModeEnv     = "TXE_AUTHZ_MODE"
	txeAuthnIssuerEnv   = "TXE_AUTHN_ISSUER"
	txeAuthnAudienceEnv = "TXE_AUTHN_AUDIENCE"
	txeAuthnJWKSEnv     = "TXE_AUTHN_JWKS_URL"
	txeAuthnLifetimeEnv = "TXE_AUTHN_MAX_LIFETIME"
)

// loadTXEConfig reads the txe section from the raw values, as the fork
// license policy is read: a value that decides who is let in is never
// converted loosely, and a key that is not known is an error rather than
// ignored.
func (l *ConfigLoader) loadTXEConfig(cfg *Config) error {
	for _, env := range []string{txeAuthzModeEnv, txeAuthnIssuerEnv, txeAuthnAudienceEnv, txeAuthnJWKSEnv, txeAuthnLifetimeEnv} {
		name := strings.ToUpper(AppSlug) + "_" + env
		if value, set := os.LookupEnv(name); set && value == "" {
			return fmt.Errorf("%s is set but empty: unset it, or give it a value", name)
		}
	}
	if err := onlyKeys(l.v.GetStringMap(txeKey), txeKey, "authz", "authn"); err != nil {
		return err
	}
	if err := onlyKeys(l.v.GetStringMap(txeAuthzKey), txeAuthzKey, "mode"); err != nil {
		return err
	}
	if err := onlyKeys(l.v.GetStringMap(txeAuthnKey), txeAuthnKey, "issuer", "audience", "jwks_url", "clients", "max_lifetime"); err != nil {
		return err
	}

	var err error
	if cfg.TXE.Authz.Mode, err = exactString(l.v.Get(txeAuthzModeKey), txeAuthzModeKey); err != nil {
		return err
	}
	if cfg.TXE.Authn.Issuer, err = exactString(l.v.Get(txeAuthnIssuerKey), txeAuthnIssuerKey); err != nil {
		return err
	}
	if cfg.TXE.Authn.Audience, err = exactString(l.v.Get(txeAuthnAudienceKey), txeAuthnAudienceKey); err != nil {
		return err
	}
	if cfg.TXE.Authn.JWKSURL, err = exactString(l.v.Get(txeAuthnJWKSKey), txeAuthnJWKSKey); err != nil {
		return err
	}
	if cfg.TXE.Authn.Clients, err = parseTXEAuthnClients(l.v.Get(txeAuthnClientsKey)); err != nil {
		return err
	}
	lifetime, err := exactString(l.v.Get(txeAuthnLifetimeKey), txeAuthnLifetimeKey)
	if err != nil {
		return err
	}
	if lifetime != "" {
		d, perr := time.ParseDuration(lifetime)
		if perr != nil {
			return fmt.Errorf("%s: %w", txeAuthnLifetimeKey, perr)
		}
		cfg.TXE.Authn.MaxLifetime = d
	}
	return nil
}

func onlyKeys(m map[string]any, section string, allowed ...string) error {
	for key := range m {
		if !slices.Contains(allowed, key) {
			return fmt.Errorf("%s: unknown key %q (allowed: %s)", section, key, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// exactString reads a value that must be written as a string. A missing value
// is "".
func exactString(v any, key string) (string, error) {
	switch s := v.(type) {
	case nil:
		return "", nil
	case string:
		return s, nil
	default:
		return "", fmt.Errorf("%s must be a string, got %v", key, v)
	}
}

func parseTXEAuthnClients(v any) ([]TXEAuthnClient, error) {
	if v == nil {
		return nil, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list of {id, class}, got %v", txeAuthnClientsKey, v)
	}
	clients := make([]TXEAuthnClient, 0, len(items))
	for i, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be {id, class}, got %v", txeAuthnClientsKey, i, item)
		}
		section := fmt.Sprintf("%s[%d]", txeAuthnClientsKey, i)
		if err := onlyKeys(entry, section, "id", "class"); err != nil {
			return nil, err
		}
		id, err := exactString(entry["id"], section+".id")
		if err != nil {
			return nil, err
		}
		class, err := exactString(entry["class"], section+".class")
		if err != nil {
			return nil, err
		}
		clients = append(clients, TXEAuthnClient{ID: id, Class: class})
	}
	return clients, nil
}

// validateTXE checks the txe section. It refuses anything that would let in
// a caller the operator did not name exactly.
func (c *Config) validateTXE() error {
	switch c.TXE.Authz.Mode {
	case "", TXEAuthzModeOff, TXEAuthzModeObserve, TXEAuthzModeEnforce:
	default:
		return fmt.Errorf("%s: unknown mode %q (off, observe or enforce)", txeAuthzModeKey, c.TXE.Authz.Mode)
	}
	if err := c.TXE.Authn.validate(); err != nil {
		return err
	}
	owners := c.TXE.Authz.Mode != "" && c.TXE.Authz.Mode != TXEAuthzModeOff
	if (owners || c.TXE.Authn.Enabled()) && c.Server.Auth.Mode != AuthModeBuiltin {
		return fmt.Errorf("%s and %s need auth.mode %q, not %q", txeAuthzModeKey, txeAuthnKey, AuthModeBuiltin, c.Server.Auth.Mode)
	}
	return nil
}

func (a TXEAuthnConfig) validate() error {
	if !a.Enabled() {
		if a.Audience != "" || a.JWKSURL != "" || len(a.Clients) > 0 || a.MaxLifetime != 0 {
			return fmt.Errorf("%s: an issuer is required when any other value is set", txeAuthnKey)
		}
		return nil
	}
	u, err := url.Parse(a.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be an absolute http(s) URL with no credentials, query or fragment", txeAuthnIssuerKey)
	}
	if a.Audience == "" {
		return fmt.Errorf("%s is required with an issuer", txeAuthnAudienceKey)
	}
	if a.JWKSURL == "" {
		return fmt.Errorf("%s is required with an issuer", txeAuthnJWKSKey)
	}
	if len(a.Clients) == 0 {
		return fmt.Errorf("%s: name at least one client with an issuer", txeAuthnClientsKey)
	}
	seen := make(map[string]bool, len(a.Clients))
	for i, client := range a.Clients {
		if client.ID == "" {
			return fmt.Errorf("%s[%d].id is required", txeAuthnClientsKey, i)
		}
		if seen[client.ID] {
			return fmt.Errorf("%s[%d]: client %q is listed twice", txeAuthnClientsKey, i, client.ID)
		}
		seen[client.ID] = true
		if !slices.Contains(txeAuthnClasses, client.Class) {
			return fmt.Errorf("%s[%d].class: %q is not a token class (%s)", txeAuthnClientsKey, i, client.Class, strings.Join(txeAuthnClasses, ", "))
		}
	}
	if a.MaxLifetime < 0 || a.MaxLifetime > txeAuthnMaxLifetime {
		return fmt.Errorf("%s must be between 0 and %s, got %s", txeAuthnLifetimeKey, txeAuthnMaxLifetime, a.MaxLifetime)
	}
	return nil
}
