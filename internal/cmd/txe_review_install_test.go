// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
)

type reviewInstallFixture struct {
	hub      *fakeHub
	machines fakeMachines
	machine  txepkg.Machine
	cfg      review.DAGConfig
	opts     txeHubInstallOptions
	names    review.RenderedDAGs
}

func newReviewInstallFixture(t *testing.T) *reviewInstallFixture {
	t.Helper()
	skipOnWindows(t)
	f := newHubFixture(t)
	cfg := review.DAGConfig{
		MachineID: txeTestMachine, StateDir: "/Users/someone/txe/review", Schedule: "*/15 * * * *", AgentModel: "claude-test-model",
		AgentConfigDir: "/Users/someone/.claude-review",
		Env:            map[string]string{txepkg.EnvHome: "/Users/someone/.local/share/txe-dagu", "DAGU_HOME": "/Users/someone/.local/share/txe-dagu/client"},
	}
	dags, err := review.RenderDAGs(cfg)
	require.NoError(t, err)
	return &reviewInstallFixture{hub: f.hub, machines: f.machines, machine: f.machine, cfg: cfg,
		opts: txeHubInstallOptions{LockPath: filepath.Join(t.TempDir(), "review-install.lock")}, names: dags}
}

func (f *reviewInstallFixture) install(t *testing.T, cfg review.DAGConfig, explicit map[string]bool) (*txeReviewInstallResult, error) {
	t.Helper()
	return txeReviewInstall(t.Context(), f.hub, f.machines, f.machine, cfg, explicit, f.opts)
}

// The pair is created, the decision DAG first; installing again changes
// nothing.
func TestTXEReviewInstallCreatesThenLeavesUnchanged(t *testing.T) {
	f := newReviewInstallFixture(t)
	res, err := f.install(t, f.cfg, nil)
	require.NoError(t, err)
	assert.Equal(t, []txeReviewInstallDAG{{f.names.DecideName, txeHubCreated}, {f.names.ReviewerName, txeHubCreated}}, res.DAGs)
	assert.Equal(t, []string{"create " + f.names.DecideName, "create " + f.names.ReviewerName}, f.hub.writesSoFar())
	assert.Equal(t, f.names.Reviewer, f.hub.specs[f.names.ReviewerName])
	assert.Contains(t, res.Runnable, "connected and healthy")

	res, err = f.install(t, f.cfg, nil)
	require.NoError(t, err)
	assert.Equal(t, []txeReviewInstallDAG{{f.names.DecideName, txeHubUnchanged}, {f.names.ReviewerName, txeHubUnchanged}}, res.DAGs)
	assert.Len(t, f.hub.writesSoFar(), 2, "nothing written again")
}

func TestTXEReviewInstallDryRun(t *testing.T) {
	f := newReviewInstallFixture(t)
	f.opts.DryRun = true
	res, err := f.install(t, f.cfg, nil)
	require.NoError(t, err)
	assert.True(t, res.DryRun)
	assert.Equal(t, txeHubCreated, res.DAGs[0].Action)
	assert.Empty(t, f.hub.writesSoFar())
}

// An update never resets an installed setting whose flag was not given;
// given with the installed value it keeps it, given with another it changes
// it.
func TestTXEReviewInstallKeepsInstalledSettings(t *testing.T) {
	f := newReviewInstallFixture(t)
	_, err := f.install(t, f.cfg, nil)
	require.NoError(t, err)

	// A plain reinstall that would render the defaults: refused, nothing written.
	defaults := f.cfg
	defaults.Schedule, defaults.AgentModel = "", ""
	_, err = f.install(t, defaults, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `--schedule (installed "*/15 * * * *", this install "*/10 * * * *")`)
	assert.Contains(t, err.Error(), `--agent-model (installed "claude-test-model", this install "")`)
	assert.Len(t, f.hub.writesSoFar(), 2)

	// An explicit change of the schedule, with the model kept by repeating it.
	changed := f.cfg
	changed.Schedule = "*/30 * * * *"
	res, err := f.install(t, changed, map[string]bool{"schedule": true})
	require.NoError(t, err)
	assert.Equal(t, txeHubUnchanged, res.DAGs[0].Action, "the decision DAG has no schedule")
	assert.Equal(t, txeHubUpdated, res.DAGs[1].Action)
	assert.Contains(t, f.hub.specs[f.names.ReviewerName], `schedule: "*/30 * * * *"`)
	assert.Contains(t, f.hub.specs[f.names.ReviewerName], `model: "claude-test-model"`)

	// Another state directory, given explicitly, updates both.
	moved := changed
	moved.StateDir = "/Users/someone/txe/review2"
	res, err = f.install(t, moved, map[string]bool{"state-dir": true})
	require.NoError(t, err)
	assert.Equal(t, []string{txeHubUpdated, txeHubUpdated}, []string{res.DAGs[0].Action, res.DAGs[1].Action})
}

// A stored DAG the renderer did not write is left alone, and the other one
// of the pair is not written either.
func TestTXEReviewInstallLeavesForeignDAGs(t *testing.T) {
	foreign := map[string]string{
		"no marker": "steps:\n  - run: echo mine\n",
		// The marker's text as data, not as a line of its own.
		"marker in a description": "description: \"" + txeReviewRenderedMarker + "\"\nsteps:\n  - run: echo mine\n",
		"marker in a script":      "steps:\n  - run: |\n      echo '" + txeReviewRenderedMarker + "'\n",
		"marker indented":         "steps:\n  - run: echo mine\n  " + txeReviewRenderedMarker + "\n",
	}
	for name, spec := range foreign {
		t.Run(name, func(t *testing.T) {
			f := newReviewInstallFixture(t)
			f.hub.specs[f.names.ReviewerName] = spec
			_, err := f.install(t, f.cfg, map[string]bool{"schedule": true, "agent-model": true, "state-dir": true, "agent-config-dir": true, "txe-home": true, "review-command": true})
			require.ErrorContains(t, err, "was not written by the reviewer renderer")
			assert.Empty(t, f.hub.writesSoFar(), "the decision DAG was not written either")
		})
	}
}

// When the second write fails, the first stays, the error says so, and the
// next install finishes.
func TestTXEReviewInstallPartialFailureRecovers(t *testing.T) {
	f := newReviewInstallFixture(t)
	_, err := f.install(t, f.cfg, nil)
	require.NoError(t, err)

	moved := f.cfg
	moved.StateDir = "/Users/someone/txe/review2"
	explicit := map[string]bool{"state-dir": true}
	f.hub.putErrFor = map[string]error{f.names.ReviewerName: &remoteError{StatusCode: http.StatusForbidden, Message: "refused"}}
	res, err := f.install(t, moved, explicit)
	require.Error(t, err)
	assert.Contains(t, err.Error(), f.names.DecideName+" was already updated: run the install again to finish")
	require.NotNil(t, res)
	assert.Equal(t, []txeReviewInstallDAG{{f.names.DecideName, txeHubUpdated}}, res.DAGs)

	f.hub.putErrFor = nil
	res, err = f.install(t, moved, explicit)
	require.NoError(t, err)
	assert.Equal(t, []txeReviewInstallDAG{{f.names.DecideName, txeHubUnchanged}, {f.names.ReviewerName, txeHubUpdated}}, res.DAGs)
}

// Installing is not readiness: with an owner's sign-in no worker list is
// asked for, and the result says readiness is unknown.
func TestTXEReviewInstallReadinessIsExplicit(t *testing.T) {
	t.Run("owner sign-in", func(t *testing.T) {
		f := newReviewInstallFixture(t)
		f.hub.owner = true
		f.hub.onListWork = func() { t.Error("GET /workers was sent with an owner's sign-in") }
		res, err := f.install(t, f.cfg, nil)
		require.NoError(t, err)
		assert.Equal(t, "unknown", res.Runnable)
		assert.Empty(t, res.Worker)
		require.Len(t, res.Warnings, 1)
		assert.Contains(t, res.Warnings[0], "installed is not runnable until that worker connects")
		assert.Len(t, f.hub.writesSoFar(), 2, "installed regardless")
	})
	t.Run("no worker", func(t *testing.T) {
		f := newReviewInstallFixture(t)
		f.hub.workers = []api.Worker{}
		res, err := f.install(t, f.cfg, nil)
		require.NoError(t, err)
		assert.Equal(t, "unknown", res.Runnable)
		assert.Contains(t, res.Warnings[0], "no worker labelled")
	})
}

func TestTXEReviewInstallVerifiesTheMachine(t *testing.T) {
	f := newReviewInstallFixture(t)
	f.machines[txeTestMachine] = txeclient.Machine{MachineID: txeTestMachine, OwnerID: "own_01JTXE0000000000000000OTHR"}
	_, err := f.install(t, f.cfg, nil)
	require.ErrorContains(t, err, "owned by own_01JTXE0000000000000000OTHR")
	assert.Empty(t, f.hub.writesSoFar())

	delete(f.machines, txeTestMachine)
	_, err = f.install(t, f.cfg, nil)
	require.ErrorContains(t, err, "does not confirm machine")
}

func TestTXEReviewSettingsReadBack(t *testing.T) {
	f := newReviewInstallFixture(t)
	got, err := txeReviewSettings(f.names.Reviewer)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"schedule": "*/15 * * * *", "agent-model": "claude-test-model", "agent-config-dir": "/Users/someone/.claude-review",
		"state-dir": "/Users/someone/txe/review", "txe-home": "/Users/someone/.local/share/txe-dagu", "review-command": "dagu txe review",
	}, got)
	decide, err := txeReviewSettings(f.names.Decide)
	require.NoError(t, err)
	assert.Equal(t, "dagu txe review", decide["review-command"])
	assert.Empty(t, decide["schedule"])
	_, err = txeReviewSettings("{")
	assert.Error(t, err)
	assert.False(t, strings.Contains(f.names.Reviewer, "\n---"))
}

// reviewHubDAGs serves the DAG, machine and worker routes the install uses,
// on the in-process hub.
type reviewHubDAGs struct {
	mu      sync.Mutex
	machine string
	specs   map[string]string
	// refuse answers every DAG call 401 invalid_token, as a hub refusing
	// the sign-in does.
	refuse bool
}

func (d *reviewHubDAGs) serve(w http.ResponseWriter, r *http.Request) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if d.refuse && strings.HasPrefix(path, "/dags") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="dagu", error="invalid_token"`)
		cliauthtest.WriteJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthorized", "message": "refused", "details": map[string]string{"code": "invalid_token"}})
		return true
	}
	switch {
	case r.Method == http.MethodGet && path == "/txe/machines/"+d.machine:
		cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"machine_id": d.machine, "owner_id": txeTestOwner, "display_name": "m"})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/dags/") && strings.HasSuffix(path, "/spec"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, "/dags/"), "/spec")
		spec, ok := d.specs[name]
		if !ok {
			cliauthtest.WriteJSON(w, http.StatusNotFound, map[string]any{"code": "not_found", "message": "no such DAG"})
			return true
		}
		cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"spec": spec, "dag": map[string]any{"name": name}})
	case r.Method == http.MethodPost && path == "/dags":
		var body struct {
			Name string `json:"name"`
			Spec string `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		d.specs[body.Name] = body.Spec
		cliauthtest.WriteJSON(w, http.StatusCreated, map[string]any{"name": body.Name})
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/dags/") && strings.HasSuffix(path, "/spec"):
		var body struct {
			Spec string `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		d.specs[strings.TrimSuffix(strings.TrimPrefix(path, "/dags/"), "/spec")] = body.Spec
		cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"errors": []string{}})
	case path == "/workers":
		cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"workers": []any{}})
	default:
		return false
	}
	return true
}

func (d *reviewHubDAGs) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.specs = map[string]string{}
}

// The command writes through the machine's hub connection: the owner's
// sign-in on DAG routes when the hub takes it, the API key otherwise, and a
// refused sign-in is never retried with the API key.
func TestTXEReviewInstallCommandCredentials(t *testing.T) {
	skipOnWindows(t)
	f := newTXEAuthFixture(t)
	require.NoError(t, os.MkdirAll(f.home, 0o700))
	machine := `{"schema":1,"machine_id":"` + txeTestMachine + `","owner_id":"` + txeTestOwner + `"}`
	require.NoError(t, os.WriteFile(filepath.Join(f.home, "machine.json"), []byte(machine), 0o600))
	dags := &reviewHubDAGs{machine: txeTestMachine, specs: map[string]string{}}
	f.hub.Handle = dags.serve
	args := []string{"review", "install", "--state-dir", filepath.Join(t.TempDir(), "review state"), "--agent-model", "claude-test-model"}
	dagRequests := func(from int) []cliauthtest.Request {
		var out []cliauthtest.Request
		for _, r := range f.hub.Requests()[from:] {
			if strings.HasPrefix(r.Path, "/api/v1/dags") {
				out = append(out, r)
			}
		}
		return out
	}

	// Another machine is refused before any request.
	before := len(f.hub.Requests())
	_, err := f.run(append(args, "--machine", "mch_01JTXE0000000000000000OTHR")...)
	require.ErrorContains(t, err, "install a machine's reviewer from that machine")
	assert.Len(t, f.hub.Requests(), before)

	// No sign-in: the API key on every DAG call, as before.
	before = len(f.hub.Requests())
	out := f.json(args...)
	assert.Len(t, out["dags"], 2)
	calls := dagRequests(before)
	require.NotEmpty(t, calls)
	for _, r := range calls {
		assert.Equal(t, "Bearer dagu_test_key", r.Authorization, "%s %s", r.Method, r.Path)
	}

	// Sign in as the owner on a hub that takes the sign-in for DAGs.
	cli := cliauthtest.New(t)
	withFakeBrowser(t, cli)
	f.hub.Publish(cli.Issuer(), cli.ClientID, cliauth.HubUseAll)
	f.json("login")

	// The owner's bearer on every DAG call, and no worker list.
	dags.reset()
	before = len(f.hub.Requests())
	out = f.json(args...)
	assert.Equal(t, "unknown", out["runnable"])
	calls = dagRequests(before)
	require.NotEmpty(t, calls)
	for _, r := range calls {
		assert.True(t, strings.HasPrefix(r.Authorization, "Bearer ey"), "%s %s: %s", r.Method, r.Path, r.Authorization)
	}
	for _, r := range f.hub.Requests()[before:] {
		assert.NotEqual(t, "/api/v1/workers", r.Path, "no worker list with an owner's sign-in")
	}

	// A refused sign-in fails closed: no retry with the API key, nothing installed.
	dags.reset()
	dags.mu.Lock()
	dags.refuse = true
	dags.mu.Unlock()
	before = len(f.hub.Requests())
	_, err = f.run(args...)
	require.ErrorIs(t, err, cliauth.ErrHubRefusedSignIn)
	for _, r := range f.hub.Requests()[before:] {
		assert.NotContains(t, r.Authorization, "dagu_", "%s %s was sent with the API key", r.Method, r.Path)
	}
	assert.Empty(t, dags.specs, "nothing installed")
}
