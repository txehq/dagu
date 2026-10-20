// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

const (
	stepStoreOwner   = "own_01K7A5ZQ8M3N4P5R6S7T8V9W0A"
	stepStoreMachine = "mch_01K7A5ZQ8M3N4P5R6S7T8V9W0C"
	stepStoreTunnel  = "http://127.0.0.1:18080/api/v1"
)

// stepStoreFixture is a developer signed in to the hub with no API key, on a
// machine whose worker installer has run: machine.json, and the TXE home's own
// store with the hub's context reached over the local tunnel.
type stepStoreFixture struct {
	*txeAuthFixture
	state  string
	owners []string
}

func newStepStoreFixture(t *testing.T) *stepStoreFixture {
	t.Helper()
	f := &stepStoreFixture{txeAuthFixture: newFreshTXEFixture(t), state: "bound", owners: []string{stepStoreOwner}}
	p := cliauthtest.New(t)
	withFakeBrowser(t, p)
	f.hub.Publish(p.Issuer(), p.ClientID, cliauth.HubUseAll)
	f.hub.Handle = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/v1/txe/identity" {
			return false
		}
		owners := []any{}
		for _, o := range f.owners {
			owners = append(owners, map[string]any{"owner_id": o})
		}
		cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"contract": 1, "authz_mode": "enforce", "state": f.state,
			"principal": map[string]any{"class": "cli"}, "owners": owners, "scope": map[string]any{"kind": "owner"}})
		return true
	}
	out, err := f.run("login", "--hub", f.hubAddress())
	require.NoError(t, err, out)

	require.NoError(t, os.MkdirAll(f.home, 0o700))
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q,"display_name":"test-mac"}`, stepStoreMachine, stepStoreOwner)
	require.NoError(t, os.WriteFile(filepath.Join(f.home, "machine.json"), []byte(identity), 0o600))
	return f
}

// machineStore writes the TXE home's own store with a hub context.
func (f *stepStoreFixture) machineStore(t *testing.T, c *cliContext) {
	t.Helper()
	store, err := newCLIContextStore(f.machineData(), f.machineContexts())
	require.NoError(t, err)
	require.NoError(t, store.Create(context.Background(), c))
}

func (f *stepStoreFixture) machineData() string {
	return filepath.Join(txepkg.Home{Root: f.home}.ClientDir(), "data")
}

func (f *stepStoreFixture) machineContexts() string {
	return filepath.Join(f.machineData(), "contexts")
}

type stepStoreResult struct {
	hub    txeclient.HubContext
	client *txeclient.Client
	err    error
	// env is DAGU_CONTEXTS_DIR as the command left it.
	env string
}

// stepStore runs txeStepStore inside a txe command, with the session's
// flags, as register does.
func (f *stepStoreFixture) stepStore(t *testing.T, extra ...string) stepStoreResult {
	t.Helper()
	var res stepStoreResult
	txe := TXE()
	txe.AddCommand(NewCommand(&cobra.Command{Use: "step-store-probe", Args: cobra.NoArgs}, nil, func(ctx *Context, _ []string) error {
		home, err := txepkg.DefaultHome()
		require.NoError(t, err)
		machine, err := home.Machine()
		require.NoError(t, err)
		res.hub, res.client, res.err = txeStepStore(ctx, home, machine)
		res.env = os.Getenv("DAGU_CONTEXTS_DIR")
		return nil
	}))
	root := txeAuthRoot()
	root.AddCommand(txe)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	args := append([]string{"txe", "step-store-probe", "--dagu-home", filepath.Dir(f.contexts), "--contexts-dir", f.contexts, "--data-dir", f.data}, extra...)
	root.SetArgs(args)
	require.NoError(t, root.Execute(), out.String())
	return res
}

// A job a signed-in developer registers runs its steps with the machine's own
// store, as resolved from the TXE home alone, never the developer's.
func TestTXEStepStoreGivesASignedInSessionTheMachinesStore(t *testing.T) {
	f := newStepStoreFixture(t)
	f.machineStore(t, &cliContext{Name: txeContextName, ServerURL: stepStoreTunnel, APIKey: "dagu_machine_key"})

	res := f.stepStore(t)
	require.NoError(t, res.err)
	require.NotNil(t, res.client)
	assert.Equal(t, txeclient.HubContext{
		DaguHome: txepkg.Home{Root: f.home}.ClientDir(), Name: txeContextName,
		ContextsDir: f.machineContexts(), DataDir: f.machineData(),
	}, res.hub)
	// The session's own store is put back for the rest of the command.
	assert.Equal(t, f.contexts, res.env)

	// The hub was asked who this is with the sign-in; the machine's key went
	// nowhere.
	for _, r := range f.hub.Requests() {
		assert.NotContains(t, r.Authorization, "dagu_machine_key", "%s %s", r.Method, r.Path)
	}
}

func TestTXEStepStoreRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(f *stepStoreFixture, t *testing.T)
		want  string
	}{
		"NotBoundYet": {
			setup: func(f *stepStoreFixture, t *testing.T) {
				f.machineStore(t, &cliContext{Name: txeContextName, ServerURL: stepStoreTunnel, APIKey: "dagu_machine_key"})
				f.state, f.owners = "pending", nil
			},
			want: "this sign-in is pending for no owner, not bound to owner " + stepStoreOwner,
		},
		"AnotherOwner": {
			setup: func(f *stepStoreFixture, t *testing.T) {
				f.machineStore(t, &cliContext{Name: txeContextName, ServerURL: stepStoreTunnel, APIKey: "dagu_machine_key"})
				f.owners = []string{"own_01K7A5ZQ8M3N4P5R6S7T8V9W0B"}
			},
			want: "not bound to owner " + stepStoreOwner,
		},
		"NoMachineStore": {
			setup: func(*stepStoreFixture, *testing.T) {},
			want:  "has no \"txe\" context, so a job registered with a sign-in would have nothing to run with",
		},
		"MachineStoreSignInOnly": {
			setup: func(f *stepStoreFixture, t *testing.T) {
				f.machineStore(t, &cliContext{Name: txeContextName, ServerURL: stepStoreTunnel, SignInOnly: true})
			},
			want: "holds no credential a job's steps can use",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newStepStoreFixture(t)
			tc.setup(f, t)
			res := f.stepStore(t)
			require.ErrorContains(t, res.err, tc.want)
			assert.Nil(t, res.client)
		})
	}
}

// A session whose context holds its own API key keeps rendering that context,
// whatever the machine's store holds.
func TestTXEStepStoreKeepsASessionWithItsOwnKey(t *testing.T) {
	f := newTXEAuthFixture(t)
	f.hub.Handle = func(_ http.ResponseWriter, r *http.Request) bool {
		t.Errorf("the hub was asked %s %s", r.Method, r.URL.Path)
		return false
	}
	sf := &stepStoreFixture{txeAuthFixture: f}
	require.NoError(t, os.MkdirAll(f.home, 0o700))
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q}`, stepStoreMachine, stepStoreOwner)
	require.NoError(t, os.WriteFile(filepath.Join(f.home, "machine.json"), []byte(identity), 0o600))

	res := sf.stepStore(t)
	require.NoError(t, res.err)
	assert.Nil(t, res.client)
	assert.Equal(t, filepath.Dir(f.contexts), res.hub.DaguHome)
	assert.Equal(t, f.contexts, res.hub.ContextsDir)
	assert.Equal(t, f.data, res.hub.DataDir)
	assert.Equal(t, txeContextName, res.hub.Name)
}
