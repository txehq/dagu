// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
)

// txeAuthFixture is a TXE home with a "txe" context for a hub that is never
// contacted: signing in talks to the provider only.
type txeAuthFixture struct {
	t        *testing.T
	contexts string
	data     string
	home     string
}

const txeAuthTestHub = "http://127.0.0.1:18080"

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
	}
	t.Setenv("TXE_DAGU_HOME", f.home)
	store, err := newCLIContextStore(f.data, f.contexts)
	require.NoError(t, err)
	require.NoError(t, store.Create(context.Background(), &cliContext{Name: txeContextName, ServerURL: txeAuthTestHub, APIKey: "dagu_test_key"}))
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
	assert.Equal(t, txeAuthTestHub, login["hub"])
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

// Other txe commands still send the context's API key: the sign-in is not
// wired to them yet.
func TestTXESignInDoesNotChangeOtherCommands(t *testing.T) {
	f := newTXEAuthFixture(t)
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)
	f.json("login", "--issuer", p.Issuer(), "--client-id", p.ClientID)

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
	require.NoError(t, root.Execute())
	require.NotNil(t, remote)
	assert.Equal(t, "dagu_test_key", remote.apiKey)
}
