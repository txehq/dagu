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

	"gopkg.in/yaml.v3"
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
	// PlatformAdmins names the people who, signed in through the browser
	// with the identity provider, act as the installation's administrator.
	// Each is matched on its exact issuer and subject; no email, username or
	// group claim is ever used. A provider token is never an administrator.
	// Removing an entry takes effect on the next request after a restart.
	PlatformAdmins []TXEPlatformAdmin
}

// TXEPlatformAdmin is one identity the configuration names a platform
// administrator.
type TXEPlatformAdmin struct {
	Issuer  string
	Subject string
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
	// IssuedAtSkew is how far in the future a token's "iat" and "nbf" may
	// lie, to absorb a provider clock a little ahead of this one, which can
	// make a token used at once name a second this clock has not reached.
	// It never applies to "exp", and the lifetime cap is measured as
	// before. Unset, it is TXEAuthnDefaultIssuedAtSkew; "0s" (parsed) turns
	// it off.
	IssuedAtSkew time.Duration
	// issuedAtSkewGiven records that the setting was given, so that one
	// without an issuer is refused whatever its value.
	issuedAtSkewGiven bool
	// CLIClient names the cli client the server advertises to the command
	// line. Empty means the only cli client, if there is exactly one.
	CLIClient string
}

// AdvertisedCLIClient returns the cli client the server tells the command
// line to sign in with, or "" when there is none to tell: no cli client, or
// several and none named.
func (c TXEAuthnConfig) AdvertisedCLIClient() string {
	if !c.Enabled() {
		return ""
	}
	if c.CLIClient != "" {
		return c.CLIClient
	}
	var found string
	for _, client := range c.Clients {
		if client.Class != "cli" {
			continue
		}
		if found != "" {
			return ""
		}
		found = client.ID
	}
	return found
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

	// TXEAuthnDefaultIssuedAtSkew is the issued-at tolerance when none is
	// configured: a small, bounded operational tolerance for the provider's
	// clock running ahead, not a measured requirement.
	TXEAuthnDefaultIssuedAtSkew = 2 * time.Second
	// txeAuthnMaxIssuedAtSkew is the largest tolerance that can be
	// configured; it is the verifier's own bound.
	txeAuthnMaxIssuedAtSkew = time.Minute
)

// txeAuthnClasses are the classes a provider token may yield. A person and
// the platform administrator are never a token.
var txeAuthnClasses = []string{"cli", "worker", "reviewer"}

const (
	txeKey               = "txe"
	txeAuthzKey          = "txe.authz"
	txeAuthzModeKey      = "txe.authz.mode"
	txeAuthzAdminsKey    = "txe.authz.platform_admins"
	txeAuthnKey          = "txe.authn"
	txeAuthnIssuerKey    = "txe.authn.issuer"
	txeAuthnAudienceKey  = "txe.authn.audience"
	txeAuthnJWKSKey      = "txe.authn.jwks_url"
	txeAuthnCLIClientKey = "txe.authn.cli_client"
	txeAuthnClientsKey   = "txe.authn.clients"
	txeAuthnLifetimeKey  = "txe.authn.max_lifetime"
	txeAuthnSkewKey      = "txe.authn.issued_at_skew"
	txeAuthzModeEnv      = "TXE_AUTHZ_MODE"
	txeAuthnIssuerEnv    = "TXE_AUTHN_ISSUER"
	txeAuthnAudienceEnv  = "TXE_AUTHN_AUDIENCE"
	txeAuthnJWKSEnv      = "TXE_AUTHN_JWKS_URL"
	txeAuthnLifetimeEnv  = "TXE_AUTHN_MAX_LIFETIME"
	txeAuthnSkewEnv      = "TXE_AUTHN_ISSUED_AT_SKEW"
)

// loadTXEConfig reads the txe section from the raw values, as the fork
// license policy is read: a value that decides who is let in is never
// converted loosely, and a key that is not known is an error rather than
// ignored.
func (l *ConfigLoader) loadTXEConfig(cfg *Config) error {
	for _, env := range []string{txeAuthzModeEnv, txeAuthnIssuerEnv, txeAuthnAudienceEnv, txeAuthnJWKSEnv, txeAuthnLifetimeEnv, txeAuthnSkewEnv} {
		name := strings.ToUpper(AppSlug) + "_" + env
		if value, set := os.LookupEnv(name); set && value == "" {
			return fmt.Errorf("%s is set but empty: unset it, or give it a value", name)
		}
	}
	switch null, err := l.txeTopLevelNull(txeKey); {
	case err != nil:
		return err
	case null:
		return fmt.Errorf("%s is empty: remove it, or give it its settings", txeKey)
	}
	// A section is a mapping or absent. A scalar in its place is refused:
	// read as an empty mapping it would switch everything off.
	for _, section := range []struct {
		key     string
		allowed []string
	}{
		{txeKey, []string{"authz", "authn"}},
		{txeAuthzKey, []string{"mode", "platform_admins"}},
		{txeAuthnKey, []string{"issuer", "audience", "jwks_url", "clients", "max_lifetime", "issued_at_skew", "cli_client"}},
	} {
		m, err := l.txeSection(section.key)
		if err != nil {
			return err
		}
		if err := onlyKeys(m, section.key, section.allowed...); err != nil {
			return err
		}
	}

	var err error
	if cfg.TXE.Authz.Mode, err = l.txeString(txeAuthzModeKey); err != nil {
		return err
	}
	if l.txeWrittenEmpty(txeAuthzAdminsKey) {
		return fmt.Errorf("%s is empty: remove it, or list the administrators", txeAuthzAdminsKey)
	}
	if cfg.TXE.Authz.PlatformAdmins, err = parseTXEPlatformAdmins(l.v.Get(txeAuthzAdminsKey)); err != nil {
		return err
	}
	if cfg.TXE.Authn.Issuer, err = l.txeString(txeAuthnIssuerKey); err != nil {
		return err
	}
	if cfg.TXE.Authn.Audience, err = l.txeString(txeAuthnAudienceKey); err != nil {
		return err
	}
	if cfg.TXE.Authn.JWKSURL, err = l.txeString(txeAuthnJWKSKey); err != nil {
		return err
	}
	if l.txeWrittenEmpty(txeAuthnClientsKey) {
		return fmt.Errorf("%s is empty: remove it, or list the clients", txeAuthnClientsKey)
	}
	if cfg.TXE.Authn.Clients, err = parseTXEAuthnClients(l.v.Get(txeAuthnClientsKey)); err != nil {
		return err
	}
	if cfg.TXE.Authn.CLIClient, err = l.txeString(txeAuthnCLIClientKey); err != nil {
		return err
	}
	lifetime, err := l.txeString(txeAuthnLifetimeKey)
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
	skew, err := l.txeString(txeAuthnSkewKey)
	if err != nil {
		return err
	}
	switch {
	case skew != "":
		d, perr := time.ParseDuration(skew)
		if perr != nil {
			return fmt.Errorf("%s: %w", txeAuthnSkewKey, perr)
		}
		cfg.TXE.Authn.IssuedAtSkew = d
		cfg.TXE.Authn.issuedAtSkewGiven = true
	case cfg.TXE.Authn.Enabled():
		cfg.TXE.Authn.IssuedAtSkew = TXEAuthnDefaultIssuedAtSkew
	}
	return nil
}

// txeSection reads a section, which must be a mapping when it is present.
func (l *ConfigLoader) txeSection(key string) (map[string]any, error) {
	switch v := l.v.Get(key).(type) {
	case nil:
		if l.txeWrittenEmpty(key) {
			return nil, fmt.Errorf("%s is empty: remove it, or give it its settings", key)
		}
		return nil, nil
	case map[string]any:
		return v, nil
	default:
		return nil, fmt.Errorf("%s must be a mapping of settings, got %v", key, v)
	}
}

// txeString reads a setting that must be a non-empty string when it is
// present. Written empty, it is refused rather than read as "not set":
// an empty mode would otherwise mean off.
func (l *ConfigLoader) txeString(key string) (string, error) {
	v := l.v.Get(key)
	if v == nil {
		if l.txeWrittenEmpty(key) {
			return "", fmt.Errorf("%s is empty: remove it, or give it a value", key)
		}
		return "", nil
	}
	s, err := exactString(v, key)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", fmt.Errorf("%s is empty: remove it, or give it a value", key)
	}
	return s, nil
}

// txeWrittenEmpty reports whether key is written with no value (YAML null),
// which the loader otherwise cannot tell from a key that is absent.
func (l *ConfigLoader) txeWrittenEmpty(key string) bool {
	if l.v.Get(key) != nil {
		return false
	}
	if l.v.IsSet(key) || l.v.InConfig(key) {
		return true
	}
	i := strings.LastIndex(key, ".")
	if i < 0 {
		// A top-level key is checked in the files, by txeTopLevelNull.
		return false
	}
	parent, ok := l.v.Get(key[:i]).(map[string]any)
	if !ok {
		return false
	}
	v, present := parent[key[i+1:]]
	return present && v == nil
}

// txeTopLevelNull reports whether a configuration file read writes key at
// its top level with no value. The loader drops such a key, so the files
// themselves are asked, with keys compared as the loader compares them,
// ignoring case. A file that can no longer be read or parsed is an error,
// never taken for one without the key.
func (l *ConfigLoader) txeTopLevelNull(key string) (bool, error) {
	for _, file := range l.txeConfigFiles {
		data, err := os.ReadFile(file) //nolint:gosec // the configuration file the loader already read
		if err != nil {
			return false, fmt.Errorf("%s: read %s again: %w", key, file, err)
		}
		var top map[string]any
		if err := yaml.Unmarshal(data, &top); err != nil {
			return false, fmt.Errorf("%s: parse %s again: %w", key, file, err)
		}
		for k, v := range top {
			if strings.EqualFold(k, key) && v == nil {
				return true, nil
			}
		}
	}
	return false, nil
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

func parseTXEPlatformAdmins(v any) ([]TXEPlatformAdmin, error) {
	if v == nil {
		return nil, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list of {issuer, subject}, got %v", txeAuthzAdminsKey, v)
	}
	if len(items) == 0 {
		// An empty list would remove every administrator silently; omit the
		// setting instead.
		return nil, fmt.Errorf("%s is empty: remove it, or list the administrators", txeAuthzAdminsKey)
	}
	admins := make([]TXEPlatformAdmin, 0, len(items))
	for i, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be {issuer, subject}, got %v", txeAuthzAdminsKey, i, item)
		}
		section := fmt.Sprintf("%s[%d]", txeAuthzAdminsKey, i)
		if err := onlyKeys(entry, section, "issuer", "subject"); err != nil {
			return nil, err
		}
		issuer, err := exactString(entry["issuer"], section+".issuer")
		if err != nil {
			return nil, err
		}
		subject, err := exactString(entry["subject"], section+".subject")
		if err != nil {
			return nil, err
		}
		admins = append(admins, TXEPlatformAdmin{Issuer: issuer, Subject: subject})
	}
	return admins, nil
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
	if err := c.validateTXEPlatformAdmins(); err != nil {
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
		if a.Audience != "" || a.JWKSURL != "" || len(a.Clients) > 0 || a.MaxLifetime != 0 || a.IssuedAtSkew != 0 || a.issuedAtSkewGiven || a.CLIClient != "" {
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
	if a.CLIClient != "" && !slices.ContainsFunc(a.Clients, func(c TXEAuthnClient) bool { return c.ID == a.CLIClient && c.Class == "cli" }) {
		return fmt.Errorf("%s: %q is not a client of class cli", txeAuthnCLIClientKey, a.CLIClient)
	}
	if a.MaxLifetime < 0 || a.MaxLifetime > txeAuthnMaxLifetime {
		return fmt.Errorf("%s must be between 0 and %s, got %s", txeAuthnLifetimeKey, txeAuthnMaxLifetime, a.MaxLifetime)
	}
	if a.IssuedAtSkew < 0 || a.IssuedAtSkew > txeAuthnMaxIssuedAtSkew {
		return fmt.Errorf("%s must be between 0 and %s, got %s", txeAuthnSkewKey, txeAuthnMaxIssuedAtSkew, a.IssuedAtSkew)
	}
	return nil
}

// validateTXEPlatformAdmins refuses an administrator entry that is incomplete,
// repeated, or could never match: the browser sign-in records the issuer of
// auth.oidc, so an entry for any other issuer names nobody.
func (c *Config) validateTXEPlatformAdmins() error {
	admins := c.TXE.Authz.PlatformAdmins
	if len(admins) == 0 {
		return nil
	}
	if c.Server.Auth.Mode != AuthModeBuiltin || !c.Server.Auth.OIDC.IsConfigured() {
		return fmt.Errorf("%s needs auth.mode %q with auth.oidc configured", txeAuthzAdminsKey, AuthModeBuiltin)
	}
	seen := make(map[TXEPlatformAdmin]bool, len(admins))
	for i, a := range admins {
		if a.Issuer == "" || a.Subject == "" {
			return fmt.Errorf("%s[%d]: issuer and subject are both required", txeAuthzAdminsKey, i)
		}
		if a.Subject != strings.TrimSpace(a.Subject) {
			return fmt.Errorf("%s[%d].subject has leading or trailing space", txeAuthzAdminsKey, i)
		}
		if a.Issuer != c.Server.Auth.OIDC.Issuer {
			return fmt.Errorf("%s[%d].issuer %q is not auth.oidc.issuer %q, so it would match no one", txeAuthzAdminsKey, i, a.Issuer, c.Server.Auth.OIDC.Issuer)
		}
		if seen[a] {
			return fmt.Errorf("%s[%d]: listed twice", txeAuthzAdminsKey, i)
		}
		seen[a] = true
	}
	return nil
}
