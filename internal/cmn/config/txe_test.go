// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const txeAuthnYAML = `
auth:
  mode: builtin
txe:
  authz:
    mode: observe
  authn:
    issuer: https://account.example/realms/master
    audience: dagu-hub
    jwks_url: https://account.example/realms/master/protocol/openid-connect/certs
    clients:
      - {id: dagu-cli, class: cli}
      - {id: dagu-worker-laptop, class: worker}
      - {id: dagu-reviewer-laptop, class: reviewer}
    max_lifetime: 240s
`

func TestLoad_TXEDefaultIsOffWithNoTokens(t *testing.T) {
	cfg := loadFromYAML(t, "")
	assert.Equal(t, "", cfg.TXE.Authz.Mode)
	assert.False(t, cfg.TXE.Authn.Enabled())
	assert.Empty(t, cfg.TXE.Authn.Clients)

	// Quoted or bare, off is the string off.
	for _, yaml := range []string{"txe:\n  authz:\n    mode: \"off\"\n", "txe:\n  authz:\n    mode: off\n"} {
		cfg = loadFromYAML(t, yaml)
		assert.Equal(t, TXEAuthzModeOff, cfg.TXE.Authz.Mode)
	}
	// Off and no tokens are allowed with authentication off.
	cfg = loadFromYAML(t, "auth:\n  mode: none\ntxe:\n  authz:\n    mode: \"off\"\n")
	assert.Equal(t, TXEAuthzModeOff, cfg.TXE.Authz.Mode)
}

func TestLoad_TXEFromYAML(t *testing.T) {
	cfg := loadFromYAML(t, txeAuthnYAML)
	assert.Equal(t, TXEAuthzModeObserve, cfg.TXE.Authz.Mode)
	assert.True(t, cfg.TXE.Authn.Enabled())
	assert.Equal(t, TXEAuthnConfig{
		Issuer:   "https://account.example/realms/master",
		Audience: "dagu-hub",
		JWKSURL:  "https://account.example/realms/master/protocol/openid-connect/certs",
		Clients: []TXEAuthnClient{
			{ID: "dagu-cli", Class: "cli"},
			{ID: "dagu-worker-laptop", Class: "worker"},
			{ID: "dagu-reviewer-laptop", Class: "reviewer"},
		},
		MaxLifetime: 240 * time.Second,
	}, cfg.TXE.Authn)
}

func TestLoad_TXEFromEnv(t *testing.T) {
	cfg := loadWithEnv(t, txeAuthnYAML, map[string]string{
		"DAGU_TXE_AUTHZ_MODE":     "enforce",
		"DAGU_TXE_AUTHN_AUDIENCE": "other-hub",
	})
	assert.Equal(t, TXEAuthzModeEnforce, cfg.TXE.Authz.Mode)
	assert.Equal(t, "other-hub", cfg.TXE.Authn.Audience)
}

func TestLoad_TXERefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml string
		want string
	}{
		"UnknownMode":      {"auth:\n  mode: builtin\ntxe:\n  authz:\n    mode: enforcing\n", "unknown mode"},
		"NotAString":       {"txe:\n  authz:\n    mode: 1\n", "must be a string"},
		"ScalarTXE":        {"txe: enforce\n", "expected a map"},
		"NullTXE":          {"txe: null\n", "is empty"},
		"BareTXE":          {"auth:\n  mode: builtin\ntxe:\n", "is empty"},
		"UpperNullTXE":     {"TXE: null\n", "is empty"},
		"MixedBareTXE":     {"auth:\n  mode: builtin\nTxe:\n", "is empty"},
		"ScalarAuthz":      {"txe:\n  authz: enforce\n", "must be a mapping"},
		"ScalarAuthn":      {"txe:\n  authn: https://a.example/r\n", "must be a mapping"},
		"EmptyModeString":  {"txe:\n  authz:\n    mode: \"\"\n", "is empty"},
		"NullMode":         {"txe:\n  authz:\n    mode:\n", "is empty"},
		"NullAuthz":        {"txe:\n  authz:\n", "is empty"},
		"EmptyIssuer":      {"auth:\n  mode: builtin\ntxe:\n  authn:\n    issuer: \"\"\n", "is empty"},
		"NullClients":      {"auth:\n  mode: builtin\ntxe:\n  authn:\n    issuer: https://a.example/r\n    clients:\n", "is empty"},
		"UnknownTXEKey":    {"txe:\n  authorization: {}\n", "unknown key"},
		"UnknownAuthzKey":  {"txe:\n  authz:\n    level: enforce\n", "unknown key"},
		"UnknownAuthnKey":  {"txe:\n  authn:\n    grace: 30m\n", "unknown key"},
		"ModeNeedsBuiltin": {"auth:\n  mode: basic\n  basic:\n    username: u\n    password: p\ntxe:\n  authz:\n    mode: observe\n", "need auth.mode"},
		"ModeWithNoAuth":   {"auth:\n  mode: none\ntxe:\n  authz:\n    mode: enforce\n", "need auth.mode"},
		"AuthnWithNoAuth": {`
auth:
  mode: none
txe:
  authn:
    issuer: https://account.example/realms/master
    audience: dagu-hub
    jwks_url: https://account.example/certs
    clients: [{id: dagu-cli, class: cli}]
`, "need auth.mode"},
		"ValuesWithoutIssuer": {"auth:\n  mode: builtin\ntxe:\n  authn:\n    audience: dagu-hub\n", "an issuer is required"},
		"IssuerNotAURL":       {"auth:\n  mode: builtin\ntxe:\n  authn:\n    issuer: account.example\n", "absolute http(s) URL"},
		"NoAudience":          {"auth:\n  mode: builtin\ntxe:\n  authn:\n    issuer: https://a.example/r\n", "audience"},
		"NoJWKS":              {"auth:\n  mode: builtin\ntxe:\n  authn:\n    issuer: https://a.example/r\n    audience: h\n", "jwks_url"},
		"NoClients":           {"auth:\n  mode: builtin\ntxe:\n  authn:\n    issuer: https://a.example/r\n    audience: h\n    jwks_url: https://a.example/k\n", "at least one client"},
		"PersonIsNotATokenClass": {`
auth:
  mode: builtin
txe:
  authn:
    issuer: https://a.example/r
    audience: h
    jwks_url: https://a.example/k
    clients: [{id: web, class: person}]
`, "not a token class"},
		"ClientTwice": {`
auth:
  mode: builtin
txe:
  authn:
    issuer: https://a.example/r
    audience: h
    jwks_url: https://a.example/k
    clients: [{id: c, class: cli}, {id: c, class: worker}]
`, "listed twice"},
		"ClientUnknownField": {`
auth:
  mode: builtin
txe:
  authn:
    issuer: https://a.example/r
    audience: h
    jwks_url: https://a.example/k
    clients: [{id: c, class: cli, secret: x}]
`, "unknown key"},
		"LifetimeOverFiveMinutes": {`
auth:
  mode: builtin
txe:
  authn:
    issuer: https://a.example/r
    audience: h
    jwks_url: https://a.example/k
    clients: [{id: c, class: cli}]
    max_lifetime: 10m
`, "between 0 and 5m0s"},
	} {
		t.Run(name, func(t *testing.T) {
			err := loadWithErrorFromYAML(t, tc.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestLoad_TXEEmptyEnvIsRefused(t *testing.T) {
	t.Setenv("DAGU_TXE_AUTHZ_MODE", "")
	err := loadWithErrorFromYAML(t, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set but empty")
}

func TestLoad_TXENullInAdminYAMLIsRefused(t *testing.T) {
	home := t.TempDir()
	configFile := filepath.Join(home, "config.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte("auth:\n  mode: builtin\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(home, "admin.yaml"), []byte("Txe: ~\n"), 0600))
	_, err := NewConfigLoader(viper.New(), WithAppHomeDir(home), WithService(ServiceServer)).Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is empty")
}

func TestTXEAdvertisedCLIClient(t *testing.T) {
	base := TXEAuthnConfig{Issuer: "https://a.example/r", Audience: "h", JWKSURL: "https://a.example/k"}
	with := func(cli string, clients ...TXEAuthnClient) TXEAuthnConfig {
		c := base
		c.Clients, c.CLIClient = clients, cli
		return c
	}
	assert.Empty(t, TXEAuthnConfig{}.AdvertisedCLIClient())
	assert.Empty(t, with("", TXEAuthnClient{ID: "w", Class: "worker"}).AdvertisedCLIClient())
	assert.Equal(t, "cli", with("", TXEAuthnClient{ID: "cli", Class: "cli"}, TXEAuthnClient{ID: "w", Class: "worker"}).AdvertisedCLIClient())
	// Several cli clients and none named: nothing is advertised.
	two := with("", TXEAuthnClient{ID: "cli-a", Class: "cli"}, TXEAuthnClient{ID: "cli-b", Class: "cli"})
	assert.Empty(t, two.AdvertisedCLIClient())
	two.CLIClient = "cli-b"
	assert.Equal(t, "cli-b", two.AdvertisedCLIClient())
	require.NoError(t, two.validate())

	bad := with("w", TXEAuthnClient{ID: "w", Class: "worker"})
	require.ErrorContains(t, bad.validate(), "not a client of class cli")
	cfg := loadFromYAML(t, txeAuthnYAML+"    cli_client: dagu-cli\n")
	assert.Equal(t, "dagu-cli", cfg.TXE.Authn.CLIClient)
}

const txeAdminsBase = `
auth:
  mode: builtin
  oidc:
    client_id: dagu-web
    client_secret: s
    client_url: https://dag.example
    issuer: https://account.example/realms/master
txe:
  authz:
    mode: observe
`

func TestLoad_TXEPlatformAdmins(t *testing.T) {
	cfg := loadFromYAML(t, txeAdminsBase+`    platform_admins:
      - {issuer: https://account.example/realms/master, subject: 84dbbe95-0000-4000-8000-000000000001}
`)
	assert.Equal(t, []TXEPlatformAdmin{{Issuer: "https://account.example/realms/master", Subject: "84dbbe95-0000-4000-8000-000000000001"}},
		cfg.TXE.Authz.PlatformAdmins)

	assert.Empty(t, loadFromYAML(t, txeAdminsBase).TXE.Authz.PlatformAdmins, "none unless listed")
}

func TestLoad_TXEPlatformAdminsRefusals(t *testing.T) {
	const iss = "https://account.example/realms/master"
	for name, tc := range map[string]struct {
		yaml string
		want string
	}{
		"Empty":           {txeAdminsBase + "    platform_admins:\n", "is empty"},
		"EmptyList":       {txeAdminsBase + "    platform_admins: []\n", "is empty"},
		"NotAList":        {txeAdminsBase + "    platform_admins: " + iss + "\n", "must be a list"},
		"NotAMapping":     {txeAdminsBase + "    platform_admins: [connor]\n", "must be {issuer, subject}"},
		"UnknownKey":      {txeAdminsBase + "    platform_admins: [{issuer: " + iss + ", subject: s, email: c@example.com}]\n", `unknown key "email"`},
		"NoSubject":       {txeAdminsBase + "    platform_admins: [{issuer: " + iss + "}]\n", "issuer and subject are both required"},
		"NoIssuer":        {txeAdminsBase + "    platform_admins: [{subject: s}]\n", "issuer and subject are both required"},
		"SubjectNotAText": {txeAdminsBase + "    platform_admins: [{issuer: " + iss + ", subject: 12}]\n", "must be a string"},
		"SpacedSubject":   {txeAdminsBase + "    platform_admins: [{issuer: " + iss + ", subject: ' s '}]\n", "leading or trailing space"},
		"OtherIssuer":     {txeAdminsBase + "    platform_admins: [{issuer: https://other.example/realms/master, subject: s}]\n", "would match no one"},
		"Twice":           {txeAdminsBase + "    platform_admins: [{issuer: " + iss + ", subject: s}, {issuer: " + iss + ", subject: s}]\n", "listed twice"},
		"NoOIDC":          {"auth:\n  mode: builtin\ntxe:\n  authz:\n    platform_admins: [{issuer: " + iss + ", subject: s}]\n", "auth.oidc configured"},
	} {
		t.Run(name, func(t *testing.T) {
			err := loadWithErrorFromYAML(t, tc.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}
