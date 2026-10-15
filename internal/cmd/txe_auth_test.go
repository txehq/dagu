// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
)

// txeAuthFixture is a TXE home with a "txe" context for an in-process hub.
// No test reaches a real hub.
type txeAuthFixture struct {
	t        *testing.T
	contexts string
	data     string
	home     string
	hub      *cliauthtest.Hub
}

func newTXEAuthFixture(t *testing.T) *txeAuthFixture {
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
	store, err := newCLIContextStore(f.data, f.contexts)
	require.NoError(t, err)
	require.NoError(t, store.Create(context.Background(), &cliContext{Name: txeContextName, ServerURL: f.hub.API(), APIKey: "dagu_test_key"}))
	return f
}

// txeAuthRoot is the dagu root command as cmd/main.go builds it, as far as
// context selection needs.
func txeAuthRoot() *cobra.Command {
	root := &cobra.Command{Use: "dagu", SilenceErrors: true, SilenceUsage: true}
	root.PersistentFlags().String("context", "", "Context name")
	return root
}

func (f *txeAuthFixture) run(args ...string) (string, error) {
	f.t.Helper()
	var out bytes.Buffer
	root := txeAuthRoot()
	root.AddCommand(TXE())
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append(append([]string{"txe"}, args...), "--dagu-home", filepath.Dir(f.contexts), "--contexts-dir", f.contexts, "--data-dir", f.data))
	err := root.Execute()
	return out.String(), err
}

func (f *txeAuthFixture) json(args ...string) map[string]any {
	f.t.Helper()
	out, err := f.run(append(args, "--json")...)
	require.NoError(f.t, err, out)
	start := strings.Index(out, "{")
	require.GreaterOrEqual(f.t, start, 0, out)
	var v map[string]any
	require.NoError(f.t, json.Unmarshal([]byte(out[start:]), &v), out)
	return v
}

func withFakeBrowser(t *testing.T, p *cliauthtest.Provider) {
	t.Helper()
	before := txeOpenBrowser
	txeOpenBrowser = p.Browser(t)
	t.Cleanup(func() { txeOpenBrowser = before })
}

func TestTXELoginWhoamiLogout(t *testing.T) {
	f := newTXEAuthFixture(t)
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)

	_, err := f.run("whoami")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dagu txe login")

	_, err = f.run("login")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--issuer")

	login := f.json("login", "--issuer", p.Issuer(), "--client-id", p.ClientID)
	assert.Equal(t, p.Issuer(), login["issuer"])
	assert.Equal(t, p.Subject, login["subject"])
	assert.Equal(t, "alice", login["username"])
	assert.Equal(t, f.hub.API(), login["hub"])
	assert.NotContains(t, login, "replaced")

	who := f.json("whoami")
	assert.Equal(t, p.Subject, who["subject"])
	assert.Equal(t, p.ClientID, who["client_id"])

	// No token is ever printed.
	out, err := f.run("whoami")
	require.NoError(t, err)
	assert.NotContains(t, out, "eyJ")
	assert.Contains(t, out, "never used to decide access")

	// The sign-in is private to this user.
	entries, err := os.ReadDir(filepath.Join(f.home, txeSignInDir))
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(f.home, txeSignInDir, e.Name()))
		require.NoError(t, err)
		assert.NotContains(t, string(data), "eyJ", e.Name())
	}

	// Signing in again reuses the provider and keeps the same identity
	// without revoking anything: the new sign-in may share its session.
	again := f.json("login")
	assert.Equal(t, p.Subject, again["subject"])
	assert.Empty(t, p.Revoked())

	// Another account replaces the sign-in and the old one is revoked.
	first := p.Subject
	p.Subject, p.Username = "subject-b", "bob"
	switched := f.json("login", "--prompt", "select_account")
	assert.Equal(t, "subject-b", switched["subject"])
	assert.Equal(t, map[string]any{"issuer": p.Issuer(), "subject": first}, switched["replaced"])
	assert.Equal(t, true, switched["previous_revoked"])
	assert.Len(t, p.Revoked(), 1)
	assert.Equal(t, "select_account", p.LastAuth().Get("prompt"))
	assert.Equal(t, "subject-b", f.json("whoami")["subject"])

	logout := f.json("logout")
	assert.Equal(t, true, logout["revoked_at_provider"])
	assert.Equal(t, "subject-b", logout["subject"])
	assert.Len(t, p.Revoked(), 2)

	_, err = f.run("whoami")
	require.Error(t, err)
	_, err = f.run("logout")
	require.Error(t, err)
}

func TestTXELoginRefusesBadInput(t *testing.T) {
	f := newTXEAuthFixture(t)
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)

	_, err := f.run("login", "--issuer", "http://idp.example/realms/x", "--client-id", "c")
	assert.ErrorContains(t, err, "https")
	_, err = f.run("login", "--issuer", p.Issuer(), "--client-id", p.ClientID, "--prompt", "none")
	assert.ErrorContains(t, err, "unknown prompt")
	p.IDNonce = func(string) string { return "replayed" }
	_, err = f.run("login", "--issuer", p.Issuer(), "--client-id", p.ClientID)
	assert.ErrorContains(t, err, "nonce")
	_, err = f.run("whoami")
	assert.Error(t, err, "a failed sign-in stores nothing")
}

// txeProbeRemote runs a txe command that resolves the hub connection the
// way every hub command does, and returns it.
func (f *txeAuthFixture) txeProbeRemote() (*remoteClient, error) {
	f.t.Helper()
	var remote *remoteClient
	root := txeAuthRoot()
	family := TXE()
	family.AddCommand(NewCommand(&cobra.Command{Use: "probe"}, nil, func(ctx *Context, _ []string) error {
		var err error
		remote, err = txeRemote(ctx)
		return err
	}))
	root.AddCommand(family)
	root.SetArgs([]string{"txe", "probe", "--dagu-home", filepath.Dir(f.contexts), "--contexts-dir", f.contexts, "--data-dir", f.data})
	// Execute runs before remote is read: the operands of one return are
	// not evaluated in a specified order.
	err := root.Execute()
	return remote, err
}

// With no sign-in, a hub command sends the API key and asks the hub nothing
// new: not even the discovery request.
func TestTXEWithoutSignInNothingChanges(t *testing.T) {
	f := newTXEAuthFixture(t)
	p := cliauthtest.New(t)
	f.hub.Publish(p.Issuer(), p.ClientID, cliauth.HubUseAll)
	remote, err := f.txeProbeRemote()
	require.NoError(t, err)
	assert.Equal(t, "dagu_test_key", remote.apiKey)
	assert.Empty(t, f.hub.Requests())
	_, err = os.Stat(filepath.Join(f.home, txeSignInDir))
	assert.True(t, os.IsNotExist(err), "no sign-in store is created")
}

// Which credential a signed-in machine's hub commands carry follows what the
// hub publishes, decided before any call.
func TestTXESignedInCredentialFollowsTheHub(t *testing.T) {
	f := newTXEAuthFixture(t)
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)
	f.json("login", "--issuer", p.Issuer(), "--client-id", p.ClientID)

	t.Run("hub without CLI sign-in keeps the API key", func(t *testing.T) {
		remote, err := f.txeProbeRemote()
		require.NoError(t, err)
		assert.Equal(t, "dagu_test_key", remote.apiKey)
	})

	// authOf sends one request and returns the Authorization the hub got.
	authOf := func(t *testing.T, remote *remoteClient, method, path string) string {
		t.Helper()
		before := len(f.hub.Requests())
		require.NoError(t, remote.do(context.Background(), method, path, map[string]string{"request_id": "req_" + path}, nil, nil))
		reqs := f.hub.Requests()[before:]
		require.Len(t, reqs, 1)
		return reqs[0].Authorization
	}
	const apiKey = "Bearer dagu_test_key"
	isSignIn := func(t *testing.T, auth string) {
		t.Helper()
		assert.True(t, strings.HasPrefix(auth, "Bearer ey"), auth)
		assert.NotContains(t, auth, "dagu_")
	}

	t.Run("identity only keeps the API key for other calls", func(t *testing.T) {
		f.hub.Publish(p.Issuer(), p.ClientID, cliauth.HubUseIdentity)
		remote, err := f.txeProbeRemote()
		require.NoError(t, err)
		assert.Equal(t, apiKey, authOf(t, remote, http.MethodPost, "/txe/jobs"))
		isSignIn(t, authOf(t, remote, http.MethodGet, "/txe/identity"))
	})

	t.Run("txe sends the sign-in on /txe and the API key elsewhere", func(t *testing.T) {
		f.hub.Publish(p.Issuer(), p.ClientID, cliauth.HubUseTxe)
		remote, err := f.txeProbeRemote()
		require.NoError(t, err)
		isSignIn(t, authOf(t, remote, http.MethodPost, "/txe/jobs"))
		assert.Equal(t, apiKey, authOf(t, remote, http.MethodGet, "/dags"))

		// A refusal is renewed once and then reported; it never falls back
		// to the API key.
		f.hub.Decide = func(*http.Request, int) int { return http.StatusUnauthorized }
		t.Cleanup(func() { f.hub.Decide = nil })
		before := len(f.hub.Requests())
		err = remote.do(context.Background(), http.MethodPost, "/txe/jobs", map[string]string{"request_id": "req_2"}, nil, nil)
		require.ErrorIs(t, err, cliauth.ErrHubRefusedSignIn)
		reqs := f.hub.Requests()[before:]
		require.Len(t, reqs, 2)
		for _, r := range reqs {
			assert.NotContains(t, r.Authorization, "dagu_")
		}
		assert.Equal(t, reqs[0].Body, reqs[1].Body)
	})

	t.Run("all also sends it on the owner-scoped native routes", func(t *testing.T) {
		f.hub.Publish(p.Issuer(), p.ClientID, cliauth.HubUseAll)
		remote, err := f.txeProbeRemote()
		require.NoError(t, err)
		isSignIn(t, authOf(t, remote, http.MethodPost, "/txe/jobs"))
		isSignIn(t, authOf(t, remote, http.MethodGet, "/dags"))
		isSignIn(t, authOf(t, remote, http.MethodGet, "/dag-runs"))
		assert.Equal(t, apiKey, authOf(t, remote, http.MethodGet, "/workers"))
	})

	t.Run("a hub naming another provider is refused", func(t *testing.T) {
		f.hub.Publish("https://other.example/realms/x", p.ClientID, cliauth.HubUseAll)
		_, err := f.txeProbeRemote()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dagu txe login")
	})

	t.Run("a DAG step keeps the API key", func(t *testing.T) {
		f.hub.Publish(p.Issuer(), p.ClientID, cliauth.HubUseAll)
		t.Setenv("DAG_RUN_ID", "run-1")
		t.Setenv("DAG_RUN_STEP_NAME", "publish")
		before := len(f.hub.Requests())
		remote, err := f.txeProbeRemote()
		require.NoError(t, err)
		assert.Equal(t, "dagu_test_key", remote.apiKey)
		assert.Len(t, f.hub.Requests(), before, "a step asks the hub nothing new")
	})
}

func TestTXELoginTakesTheHubsClient(t *testing.T) {
	f := newTXEAuthFixture(t)
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)
	f.hub.Publish(p.Issuer(), p.ClientID, cliauth.HubUseIdentity)

	login := f.json("login")
	assert.Equal(t, p.Issuer(), login["issuer"])
	assert.Equal(t, p.ClientID, login["client_id"])

	// --scope adds to the scopes the hub names; it never drops one.
	f.hub.Advertise["scopes"] = []string{"openid", "dagu-hub"}
	f.json("login", "--scope", "offline_access")
	assert.Equal(t, "openid dagu-hub offline_access", p.LastAuth().Get("scope"))

	_, err := f.run("login", "--client-id", "another-client")
	assert.ErrorContains(t, err, "the hub's CLI client is")
	_, err = f.run("login", "--issuer", "https://other.example/realms/x")
	assert.ErrorContains(t, err, "signs its CLI in at")

	who := f.json("whoami")
	identity, ok := who["hub_identity"].(map[string]any)
	require.True(t, ok, who)
	assert.Equal(t, "unbound", identity["state"])
	principal := identity["principal"].(map[string]any)
	assert.Equal(t, p.Subject, principal["subject"])
	assert.Equal(t, "cli", principal["class"])
	var asked bool
	for _, r := range f.hub.Requests() {
		if r.Path == "/api/v1/txe/identity" {
			asked = true
			assert.True(t, strings.HasPrefix(r.Authorization, "Bearer ey"), "whoami asks with the sign-in, never the API key")
		}
	}
	assert.True(t, asked)
}

func TestTXEWhoamiWithoutHubSignIn(t *testing.T) {
	f := newTXEAuthFixture(t)
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)
	f.json("login", "--issuer", p.Issuer(), "--client-id", p.ClientID)
	who := f.json("whoami")
	assert.NotContains(t, who, "hub_identity")
	assert.Contains(t, who["hub_identity_error"], "does not accept CLI sign-in")
	for _, r := range f.hub.Requests() {
		assert.NotEqual(t, "/api/v1/txe/identity", r.Path, "the API key is never used to ask who the sign-in is")
	}
}

// Each login flag defaults on its own: repeating the issuer and client id
// keeps the scopes of the last sign-in.
func TestTXELoginKeepsScopesWithExplicitProvider(t *testing.T) {
	f := newTXEAuthFixture(t)
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)

	f.json("login", "--issuer", p.Issuer(), "--client-id", p.ClientID, "--scope", "offline_access")
	assert.Equal(t, "openid offline_access", p.LastAuth().Get("scope"))
	f.json("login", "--issuer", p.Issuer(), "--client-id", p.ClientID)
	assert.Equal(t, "openid offline_access", p.LastAuth().Get("scope"))

	// An unreadable sign-in cannot supply the provider, and does not stop a
	// login that gives it.
	dir := filepath.Join(f.home, txeSignInDir)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			require.NoError(t, os.WriteFile(filepath.Join(dir, e.Name()), []byte("{"), 0o600))
		}
	}
	_, err = f.run("login")
	require.Error(t, err)
	login := f.json("login", "--issuer", p.Issuer(), "--client-id", p.ClientID)
	assert.Equal(t, p.Subject, login["subject"])
	assert.Equal(t, "openid", p.LastAuth().Get("scope"))
}
