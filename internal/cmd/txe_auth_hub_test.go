// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
)

// newFreshTXEFixture is a developer's machine before its first sign-in: a TXE
// home with no context at all, no API key, no worker.
func newFreshTXEFixture(t *testing.T) *txeAuthFixture {
	t.Helper()
	keepDaguEnvironment(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	t.Setenv("HOME", base)
	t.Setenv("USERPROFILE", base)
	f := &txeAuthFixture{
		t:        t,
		contexts: filepath.Join(base, "client", "contexts"),
		data:     filepath.Join(base, "client", "data"),
		home:     filepath.Join(base, "txe-home"),
		hub:      cliauthtest.NewHub(t),
	}
	t.Setenv("TXE_DAGU_HOME", f.home)
	return f
}

func (f *txeAuthFixture) storedHub(t *testing.T) *cliContext {
	t.Helper()
	store, err := newCLIContextStore(f.data, f.contexts)
	require.NoError(t, err)
	c, err := store.Get(context.Background(), txeContextName)
	require.NoError(t, err)
	return c
}

// The hub's address, as a developer types it: no /api/v1.
func (f *txeAuthFixture) hubAddress() string { return strings.TrimSuffix(f.hub.API(), "/api/v1") }

func TestTXELoginHubOnAFreshHome(t *testing.T) {
	f := newFreshTXEFixture(t)
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)
	f.hub.Publish(p.Issuer(), p.ClientID, cliauth.HubUseAll)

	// No hub yet: login says how to name one, and creates nothing.
	_, err := f.run("login")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dagu txe login --hub")

	// One command: no API key, no token copied, the provider and client from
	// the hub's public discovery over its own address, PKCE in the browser.
	out, err := f.run("login", "--hub", f.hubAddress())
	require.NoError(t, err, out)
	assert.Contains(t, out, "Signed in.")
	assert.Contains(t, out, "access: none yet. Open "+f.hubAddress()+" in a browser")
	assert.NotContains(t, out, "eyJ", "no token is printed")
	assert.Equal(t, "S256", p.LastAuth().Get("code_challenge_method"))

	stored := f.storedHub(t)
	assert.True(t, stored.SignInOnly)
	assert.Empty(t, stored.APIKey)
	assert.Equal(t, f.hub.API(), stored.ServerURL)

	// The hub was asked with the sign-in, and nothing ever carried an API key.
	for _, r := range f.hub.Requests() {
		assert.False(t, strings.HasPrefix(r.Authorization, "Bearer dagu_"), "%s %s carried an API key", r.Method, r.Path)
		if r.Path == "/api/v1/txe/identity" {
			assert.True(t, strings.HasPrefix(r.Authorization, "Bearer ey"), "the hub is asked with the sign-in")
		}
	}

	// The account and the hub are kept: a later command uses them as is.
	who := f.json("whoami")
	assert.Equal(t, p.Subject, who["subject"])
	assert.Equal(t, f.hub.API(), who["hub"])

	// Signing in again with the same --hub is the same context.
	_, err = f.run("login", "--hub", f.hubAddress()+"/")
	require.NoError(t, err)
}

func TestTXELoginHubSaysWhenAccessIsPendingOrGranted(t *testing.T) {
	f := newFreshTXEFixture(t)
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)
	f.hub.Publish(p.Issuer(), p.ClientID, cliauth.HubUseAll)

	state := "pending"
	f.hub.Handle = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/v1/txe/identity" {
			return false
		}
		owners := []any{}
		if state == "bound" {
			owners = []any{map[string]any{"owner_id": "own_test"}}
		}
		cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"contract": 1, "authz_mode": "enforce", "state": state,
			"principal": map[string]any{"class": "cli"}, "owners": owners, "scope": map[string]any{"kind": "none"}})
		return true
	}

	out, err := f.run("login", "--hub", f.hubAddress())
	require.NoError(t, err, out)
	assert.Contains(t, out, "access: requested, waiting for the hub's administrator to approve it")

	state = "bound"
	out, err = f.run("login")
	require.NoError(t, err, out)
	assert.Contains(t, out, "access: owner own_test")
}

func TestTXELoginHubKeepsAnExistingContext(t *testing.T) {
	f := newTXEAuthFixture(t) // a worker machine: the installer's context, with its API key
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)
	f.hub.Publish(p.Issuer(), p.ClientID, cliauth.HubUseAll)

	// The same hub: the context, API key and all, is left as it was.
	_, err := f.run("login", "--hub", f.hub.API())
	require.NoError(t, err)
	stored := f.storedHub(t)
	assert.False(t, stored.SignInOnly)
	assert.Equal(t, "dagu_test_key", stored.APIKey)

	// Another hub is refused, and nothing changes.
	_, err = f.run("login", "--hub", "https://other.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already names")
	assert.Equal(t, "dagu_test_key", f.storedHub(t).APIKey)
}

func TestTXELoginHubRefusesBadAddresses(t *testing.T) {
	f := newFreshTXEFixture(t)
	for _, bad := range []string{"dag.example.com", "ftp://dag.example.com", "https://user@dag.example.com", "https://dag.example.com/?x=1"} {
		_, err := f.run("login", "--hub", bad)
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), "--hub must be", bad)
	}
}

func TestSignInOnlyContextValidation(t *testing.T) {
	store, err := newCLIContextStore(t.TempDir(), t.TempDir())
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &cliContext{Name: "dev", ServerURL: "https://dag.example.com/api/v1", SignInOnly: true}))
	got, err := store.Get(ctx, "dev")
	require.NoError(t, err)
	assert.True(t, got.SignInOnly)
	assert.Empty(t, got.APIKey)

	assert.ErrorContains(t, store.Create(ctx, &cliContext{Name: "both", ServerURL: "https://dag.example.com/api/v1", SignInOnly: true, APIKey: "dagu_x"}),
		"holds no api key")
	assert.ErrorContains(t, store.Create(ctx, &cliContext{Name: "neither", ServerURL: "https://dag.example.com/api/v1"}),
		"dagu_ prefix", "an ordinary context still needs its key")
}
