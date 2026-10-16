// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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
	assert.Contains(t, out, "access: none yet. If you have not asked, open "+f.hubAddress()+" in a browser")
	assert.Contains(t, out, "If you have, it is waiting for the hub's administrator")
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
	assert.Contains(t, err.Error(), "DAGU_CONTEXTS_DIR="+f.contexts, "the hint names the TXE home's store, not the ordinary one")
	assert.Equal(t, "dagu_test_key", f.storedHub(t).APIKey)
}

func TestTXELoginHubRefusesBadAddresses(t *testing.T) {
	f := newFreshTXEFixture(t)
	for _, bad := range []string{"dag.example.com", "ftp://dag.example.com", "https://user@dag.example.com", "https://dag.example.com/?x=1",
		"http://dag.example.com", "http://10.0.0.5:8080"} {
		_, err := f.run("login", "--hub", bad)
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), "--hub must be", bad)
	}
}

func TestTXEHubAPIRoot(t *testing.T) {
	for in, want := range map[string]string{
		"https://dag.example.com":          "https://dag.example.com/api/v1",
		"https://dag.example.com/":         "https://dag.example.com/api/v1",
		"https://dag.example.com/hub/api/": "https://dag.example.com/hub/api",
		"http://127.0.0.1:18080":           "http://127.0.0.1:18080/api/v1",
		"http://localhost:18080":           "http://localhost:18080/api/v1",
		"http://[::1]:18080":               "http://[::1]:18080/api/v1",
	} {
		got, err := txeHubAPIRoot(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
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

// Login signs in to the hub every other txe command defaults to, the "txe"
// context, whatever context the store has as current; --hub works with
// another context current, and only an explicit --context conflicts with it.
func TestTXELoginIgnoresTheStoresCurrentContext(t *testing.T) {
	f := newTXEAuthFixture(t)
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)
	f.hub.Publish(p.Issuer(), p.ClientID, cliauth.HubUseAll)
	other := cliauthtest.NewHub(t)

	store, err := newCLIContextStore(f.data, f.contexts)
	require.NoError(t, err)
	require.NoError(t, store.Create(context.Background(), &cliContext{Name: "other", ServerURL: other.API(), APIKey: "dagu_other_key"}))
	require.NoError(t, store.Use(context.Background(), "other"))

	login := f.json("login")
	assert.Equal(t, f.hub.API(), login["hub"], "login signs in to the txe hub, not the current context's")
	for _, r := range other.Requests() {
		t.Errorf("the current context's hub was contacted: %s %s", r.Method, r.Path)
	}

	_, err = f.run("login", "--hub", f.hub.API())
	require.NoError(t, err, "--hub with another context current is no conflict")

	_, err = f.run("login", "--hub", f.hub.API(), "--context", "other")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name the hub twice")
}

func TestContextUpdateKeepsASignInOnlyContext(t *testing.T) {
	newCmd := func(set map[string]string) *cobra.Command {
		c := &cobra.Command{Use: "context"}
		initFlags(c, contextManageFlags...)
		for k, v := range set {
			require.NoError(t, c.Flags().Set(k, v))
		}
		return c
	}
	current := &cliContext{Name: "txe", ServerURL: "https://dag.example.com/api/v1", SignInOnly: true}

	// A new timeout keeps it sign-in only, with no key.
	item := &cliContext{Name: "txe", TimeoutSeconds: 60}
	require.NoError(t, mergeContextUpdate(newCmd(map[string]string{"timeout": "60"}), current, item))
	assert.True(t, item.SignInOnly)
	assert.Empty(t, item.APIKey)
	assert.Equal(t, current.ServerURL, item.ServerURL)

	store, err := newCLIContextStore(t.TempDir(), t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.Create(context.Background(), current))
	require.NoError(t, store.Update(context.Background(), item), "the update validates")

	// Given a key, it becomes an ordinary context.
	keyed := &cliContext{Name: "txe", APIKey: "dagu_new_key"}
	require.NoError(t, mergeContextUpdate(newCmd(map[string]string{"api-key": "dagu_new_key"}), current, keyed))
	assert.False(t, keyed.SignInOnly)
	require.NoError(t, store.Update(context.Background(), keyed))
}
