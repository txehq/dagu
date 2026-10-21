// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

const (
	txeMachineTestOwner   = "own_01K7A5ZQ8M3N4P5R6S7T8V9W0X"
	txeMachineTestOther   = "own_01K7A5ZQ8M3N4P5R6S7T8V9W0Y"
	txeMachineTestMachine = "mch_01K7A5ZQ8M3N4P5R6S7T8V9W0J"
)

// txeMachineFixture is a machine whose CLI can sign in to a hub that says who
// the sign-in is and records machines.
type txeMachineFixture struct {
	*txeAuthFixture
	cli *cliauthtest.Provider

	mu sync.Mutex
	// identity is what GET /txe/identity answers.
	identity map[string]any
	// createStatus, when set, is how POST /txe/machines answers instead,
	// with createDetail as the error's details.code.
	createStatus int
	createDetail string
	// echoOwner, when set, replaces the owner the hub echoes.
	echoOwner string
	created   []map[string]any
}

func newTXEMachineFixture(t *testing.T, use string) *txeMachineFixture {
	t.Helper()
	f := &txeMachineFixture{txeAuthFixture: newTXEAuthFixture(t), cli: cliauthtest.New(t)}
	// A CLI sign-in, as the hub reports one: class cli, not a person's
	// browser sign-in.
	f.identity = map[string]any{"state": "bound", "is_person": false, "principal": map[string]any{"class": "cli"},
		"owners": []map[string]any{{"owner_id": txeMachineTestOwner}}, "scope": map[string]any{"kind": "owner"}}
	withFakeBrowser(t, f.cli)
	f.hub.Publish(f.cli.Issuer(), f.cli.ClientID, use)
	f.hub.Handle = f.serve
	return f
}

func (f *txeMachineFixture) serve(w http.ResponseWriter, r *http.Request) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/api/v1/txe/identity":
		cliauthtest.WriteJSON(w, http.StatusOK, f.identity)
		return true
	case r.URL.Path == "/api/v1/txe/machines" && r.Method == http.MethodPost:
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			cliauthtest.WriteJSON(w, http.StatusBadRequest, map[string]any{"code": "bad_request", "message": err.Error()})
			return true
		}
		f.created = append(f.created, body)
		if f.createStatus != 0 {
			cliauthtest.WriteJSON(w, f.createStatus, map[string]any{"code": "refused", "message": "refused by the test hub",
				"details": map[string]any{"code": f.createDetail}})
			return true
		}
		owner := body["owner_id"]
		if f.echoOwner != "" {
			owner = f.echoOwner
		}
		cliauthtest.WriteJSON(w, http.StatusCreated, map[string]any{"schema": 1, "machine_id": body["machine_id"], "owner_id": owner,
			"display_name": body["display_name"]})
		return true
	}
	return false
}

func (f *txeMachineFixture) creates() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.created...)
}

func (f *txeMachineFixture) machinePath() string { return filepath.Join(f.home, "machine.json") }

func (f *txeMachineFixture) writeMachine(t *testing.T, machineID, ownerID string) []byte {
	t.Helper()
	require.NoError(t, os.MkdirAll(f.home, 0o700))
	data := []byte(`{"schema":1,"machine_id":"` + machineID + `","owner_id":"` + ownerID + `","display_name":"laptop"}` + "\n")
	require.NoError(t, os.WriteFile(f.machinePath(), data, 0o600))
	return data
}

// machineRequests are the requests that reached the machine routes.
func (f *txeMachineFixture) machineRequests() []cliauthtest.Request {
	var out []cliauthtest.Request
	for _, r := range f.hub.Requests() {
		if strings.HasPrefix(r.Path, "/api/v1/txe/machines") {
			out = append(out, r)
		}
	}
	return out
}

// A fresh machine of a signed-in person: the identity is minted for the
// sign-in's owner and written first, then the hub records it with the sign-in.
func TestTXEMachineCreateMintsAndRecordsTheMachine(t *testing.T) {
	f := newTXEMachineFixture(t, cliauth.HubUseAll)
	f.json("login")

	out := f.json("machine", "create", "--display-name", "dev laptop", "--owner-id", txeMachineTestOwner)
	assert.Equal(t, true, out["identity_written"])
	assert.Equal(t, txeMachineTestOwner, out["owner_id"])

	data, err := os.ReadFile(f.machinePath())
	require.NoError(t, err)
	var identity map[string]any
	require.NoError(t, json.Unmarshal(data, &identity))
	machineID, _ := identity["machine_id"].(string)
	require.NoError(t, registry.ValidateID(registry.PrefixMachine, machineID))
	assert.Equal(t, machineID, out["machine_id"])
	assert.Equal(t, txeMachineTestOwner, identity["owner_id"])
	assert.Equal(t, "dev laptop", identity["display_name"])
	assert.EqualValues(t, 1, identity["schema"])
	assert.NotEmpty(t, identity["created_at"])
	if runtime.GOOS != "windows" {
		info, err := os.Stat(f.machinePath())
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	creates := f.creates()
	require.Len(t, creates, 1)
	assert.Equal(t, machineID, creates[0]["machine_id"])
	assert.Equal(t, txeMachineTestOwner, creates[0]["owner_id"])
	assert.Equal(t, "dev laptop", creates[0]["display_name"])
	actor, _ := creates[0]["actor"].(map[string]any)
	assert.Equal(t, "cli", actor["kind"])
	requests := f.machineRequests()
	require.Len(t, requests, 1)
	assert.True(t, strings.HasPrefix(requests[0].Authorization, "Bearer ey"), "sent with the sign-in")
	assert.NotContains(t, requests[0].Authorization, "dagu_test_key")
}

// An existing identity of the sign-in's owner is used as it is, and running
// again asks the hub again without changing the file.
func TestTXEMachineCreateKeepsAnExistingIdentity(t *testing.T) {
	f := newTXEMachineFixture(t, cliauth.HubUseTxe)
	before := f.writeMachine(t, txeMachineTestMachine, txeMachineTestOwner)
	f.json("login")

	for range 2 {
		out := f.json("machine", "create", "--display-name", "ignored")
		assert.Equal(t, false, out["identity_written"])
		assert.Equal(t, txeMachineTestMachine, out["machine_id"])
	}
	after, err := os.ReadFile(f.machinePath())
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "machine.json is never rewritten")
	creates := f.creates()
	require.Len(t, creates, 2)
	for _, c := range creates {
		assert.Equal(t, txeMachineTestMachine, c["machine_id"])
		assert.Equal(t, "laptop", c["display_name"], "the identity's name, not the flag")
	}
}

// Each refusal is made before anything is sent to the machine routes, and
// leaves machine.json as it was.
func TestTXEMachineCreateRefusesBeforeSending(t *testing.T) {
	worker := map[string]any{"state": "bound", "principal": map[string]any{"class": "worker"},
		"owners": []map[string]any{{"owner_id": txeMachineTestOwner}}}
	unbound := map[string]any{"state": "unbound", "principal": map[string]any{"class": "cli"},
		"scope": map[string]any{"kind": "unbound", "unbound_reason": "no_owner"}}
	cases := []struct {
		name     string
		use      string
		existing string // owner of an existing machine.json; empty for none
		identity map[string]any
		login    bool
		args     []string
		want     string
	}{
		{name: "no sign-in", use: cliauth.HubUseAll, want: `run "dagu txe login`},
		{name: "identity-only sign-in", use: cliauth.HubUseIdentity, login: true, want: "only to say who it is"},
		{name: "another owner's machine", use: cliauth.HubUseAll, login: true, existing: txeMachineTestOther, want: "belongs to owner " + txeMachineTestOther},
		{name: "owner assertion", use: cliauth.HubUseAll, login: true, args: []string{"--owner-id", txeMachineTestOther}, want: "is not this sign-in's owner"},
		{name: "malformed owner assertion", use: cliauth.HubUseAll, login: true, args: []string{"--owner-id", "own_x"}, want: "--owner-id"},
		{name: "a machine credential", use: cliauth.HubUseAll, login: true, identity: worker, want: `as a "worker" caller, not a person`},
		{name: "no owner", use: cliauth.HubUseAll, login: true, identity: unbound, want: "no single owner (no_owner)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTXEMachineFixture(t, tc.use)
			var before []byte
			if tc.existing != "" {
				before = f.writeMachine(t, txeMachineTestMachine, tc.existing)
			}
			if tc.login {
				_, err := f.run("login")
				require.NoError(t, err)
			}
			if tc.identity != nil {
				f.identity = tc.identity
			}
			out, err := f.run(append([]string{"machine", "create"}, tc.args...)...)
			require.Error(t, err, out)
			assert.Contains(t, err.Error(), tc.want)
			assert.Empty(t, f.machineRequests(), "nothing reached the machine routes")
			after, readErr := os.ReadFile(f.machinePath())
			if before == nil {
				assert.ErrorIs(t, readErr, os.ErrNotExist, "no identity was written")
			} else {
				require.NoError(t, readErr)
				assert.Equal(t, string(before), string(after))
			}
		})
	}
}

// A machine id the hub has under another owner is reported as such, and the
// identity file stays as it is.
func TestTXEMachineCreateReportsADuplicate(t *testing.T) {
	f := newTXEMachineFixture(t, cliauth.HubUseAll)
	before := f.writeMachine(t, txeMachineTestMachine, txeMachineTestOwner)
	f.json("login")
	f.createStatus, f.createDetail = http.StatusConflict, "duplicate"

	_, err := f.run("machine", "create")
	require.ErrorContains(t, err, "already in use")
	assert.ErrorContains(t, err, "machine.json was not changed")
	after, readErr := os.ReadFile(f.machinePath())
	require.NoError(t, readErr)
	assert.Equal(t, string(before), string(after))
}

// The hub's answer must be the machine and owner asked for.
func TestTXEMachineCreateChecksTheHubsAnswer(t *testing.T) {
	f := newTXEMachineFixture(t, cliauth.HubUseAll)
	f.writeMachine(t, txeMachineTestMachine, txeMachineTestOwner)
	f.json("login")
	f.echoOwner = txeMachineTestOther

	_, err := f.run("machine", "create")
	require.ErrorContains(t, err, "the hub answered with machine "+txeMachineTestMachine+" of owner "+txeMachineTestOther)
}

// A browser sign-in is a person's too; the hub reports it as is_person.
func TestTXEMachineCreateTakesABrowserSignIn(t *testing.T) {
	f := newTXEMachineFixture(t, cliauth.HubUseAll)
	f.identity["principal"] = map[string]any{"class": "person"}
	f.identity["is_person"] = true
	f.writeMachine(t, txeMachineTestMachine, txeMachineTestOwner)
	f.json("login")

	out := f.json("machine", "create")
	assert.Equal(t, txeMachineTestMachine, out["machine_id"])
}

// A refusal after the hub said who the sign-in is means the two answers
// disagree: each 403 says which, and names whoami.
func TestTXEMachineCreateExplainsARefusalAfterTheIdentity(t *testing.T) {
	for detail, want := range map[string]string{
		"unbound":   "acting for no owner, though it said a moment ago it acts for " + txeMachineTestOwner,
		"forbidden": "though it binds this sign-in to that owner",
	} {
		t.Run(detail, func(t *testing.T) {
			f := newTXEMachineFixture(t, cliauth.HubUseAll)
			f.writeMachine(t, txeMachineTestMachine, txeMachineTestOwner)
			f.json("login")
			f.createStatus, f.createDetail = http.StatusForbidden, detail

			_, err := f.run("machine", "create")
			require.ErrorContains(t, err, want)
			assert.ErrorContains(t, err, "dagu txe whoami")
		})
	}
}
