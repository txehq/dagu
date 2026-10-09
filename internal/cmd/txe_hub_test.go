// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/dagucloud/dagu/v2/api/v1"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/probe"
)

const txeTestOwner = "own_01JTXE0000000000000000F1X3"

// fakeHub is the hub's DAG store and worker list.
type fakeHub struct {
	specs   map[string]string
	workers []api.Worker
	writes  []string
	getErr  error
	putErr  error
}

func (h *fakeHub) getDAGSpec(_ context.Context, name string) (string, bool, error) {
	if h.getErr != nil {
		return "", false, h.getErr
	}
	spec, ok := h.specs[name]
	return spec, ok, nil
}

func (h *fakeHub) createDAG(_ context.Context, name, spec string) error {
	if _, ok := h.specs[name]; ok {
		return errors.New("already exists")
	}
	h.writes = append(h.writes, "create "+name)
	h.specs[name] = spec
	return nil
}

func (h *fakeHub) updateDAGSpec(_ context.Context, name, spec string) error {
	if h.putErr != nil {
		return h.putErr
	}
	h.writes = append(h.writes, "update "+name)
	h.specs[name] = spec
	return nil
}

func (h *fakeHub) listWorkers(context.Context) ([]api.Worker, error) { return h.workers, nil }

// fakeMachines is the registry's machine lookup.
type fakeMachines map[string]txeclient.Machine

func (m fakeMachines) Machine(_ context.Context, id string) (*txeclient.Machine, error) {
	got, ok := m[id]
	if !ok {
		return nil, errors.New("machine not found")
	}
	return &got, nil
}

// hubFixture is a hub that knows this machine and has its healthy worker.
type hubFixture struct {
	hub      *fakeHub
	machines fakeMachines
	machine  txepkg.Machine
	cfg      probe.ReconcileDAGConfig
}

func newHubFixture(t *testing.T) hubFixture {
	t.Helper()
	home := txepkg.Home{Root: "/Users/someone/.local/share/txe-dagu"}
	machine := txepkg.Machine{MachineID: txeTestMachine, OwnerID: txeTestOwner}
	hub := &fakeHub{specs: map[string]string{}, workers: []api.Worker{{
		Id: txeTestMachine, HealthStatus: api.WorkerHealthStatusHealthy, Labels: map[string]string{txeHubWorkerLabel: txeTestMachine},
	}}}
	machines := fakeMachines{txeTestMachine: {MachineID: txeTestMachine, OwnerID: txeTestOwner}}
	return hubFixture{hub, machines, machine, txeHubProbeConfig(home, machine, txeclient.HubContext{})}
}

// The DAG is rendered from the TXE home's layout, with only paths and the
// context name, and the step can find that home.
func TestTXEHubProbeConfig(t *testing.T) {
	home := txepkg.Home{Root: "/Users/someone/.local/share/txe-dagu"}
	cfg := txeHubProbeConfig(home, txepkg.Machine{MachineID: txeTestMachine}, txeclient.HubContext{})
	assert.Equal(t, txeTestMachine, cfg.MachineID)
	assert.Equal(t, home.Root+"/bin/dagu", cfg.DaguBin)
	assert.Equal(t, []string{"--dagu-home", home.ClientDir(), "--context", "txe"}, cfg.StoreFlags)
	assert.Equal(t, map[string]string{"TXE_DAGU_HOME": home.Root}, cfg.Env)

	pinned := txeHubProbeConfig(home, txepkg.Machine{MachineID: txeTestMachine}, txeclient.HubContext{
		DaguHome: "/h/client", Name: "hub2", ConfigFile: "/h/config.yaml", ContextsDir: "/h/contexts", DataDir: "/h/data",
	})
	assert.Equal(t, []string{"--dagu-home", "/h/client", "--context", "hub2", "--config", "/h/config.yaml",
		"--contexts-dir", "/h/contexts", "--data-dir", "/h/data"}, pinned.StoreFlags)

	_, spec, err := probe.RenderReconcileDAG(pinned)
	require.NoError(t, err, "the renderer accepts what the installer passes")
	assert.Contains(t, string(spec), "txe.machine: \""+txeTestMachine+"\"")
}

// Absent, it is created; installed again, nothing is written; a stored copy
// from an older render is updated.
func TestTXEHubInstallCreatesThenLeavesUnchanged(t *testing.T) {
	f := newHubFixture(t)
	hub, machines, machine, cfg := f.hub, f.machines, f.machine, f.cfg
	name := probe.ReconcileDAGName(txeTestMachine)

	res, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, false)
	require.NoError(t, err)
	assert.Equal(t, txeHubCreated, res.Action)
	assert.Equal(t, name, res.DAG)
	assert.Equal(t, txeTestMachine, res.Worker)
	assert.Empty(t, res.Warnings)

	res, err = txeHubInstall(t.Context(), hub, machines, machine, cfg, false)
	require.NoError(t, err)
	assert.Equal(t, txeHubUnchanged, res.Action)
	assert.Equal(t, []string{"create " + name}, hub.writes)

	hub.specs[name] = strings.Replace(hub.specs[name], "*/15 * * * *", "*/30 * * * *", 1)
	res, err = txeHubInstall(t.Context(), hub, machines, machine, cfg, false)
	require.NoError(t, err)
	assert.Equal(t, txeHubUpdated, res.Action)
	assert.Equal(t, []string{"create " + name, "update " + name}, hub.writes)
	_, want, err := probe.RenderReconcileDAG(cfg)
	require.NoError(t, err)
	assert.Equal(t, string(want), hub.specs[name])
}

// A dry run reports the action and writes nothing.
func TestTXEHubInstallDryRun(t *testing.T) {
	f := newHubFixture(t)
	hub, machines, machine, cfg := f.hub, f.machines, f.machine, f.cfg
	res, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, true)
	require.NoError(t, err)
	assert.Equal(t, txeHubCreated, res.Action)
	assert.True(t, res.DryRun)
	assert.Empty(t, hub.writes)
	assert.Empty(t, hub.specs)
}

// A DAG of that name the renderer did not write, or one from a newer
// renderer, is left alone.
func TestTXEHubInstallLeavesForeignAndNewerDAGs(t *testing.T) {
	name := probe.ReconcileDAGName(txeTestMachine)
	for label, stored := range map[string]string{
		"not rendered": "steps:\n  - command: echo hand-written\n",
		"newer":        "# txe-probe-dag-version: 99\nsteps:\n  - command: echo newer\n",
	} {
		t.Run(label, func(t *testing.T) {
			f := newHubFixture(t)
			hub, machines, machine, cfg := f.hub, f.machines, f.machine, f.cfg
			hub.specs[name] = stored
			_, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, false)
			require.Error(t, err)
			assert.Empty(t, hub.writes)
			assert.Equal(t, stored, hub.specs[name])
		})
	}
}

// The registry must know this machine under this owner before anything is
// written.
func TestTXEHubInstallVerifiesTheMachineWithTheRegistry(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		f := newHubFixture(t)
		hub, machine, cfg := f.hub, f.machine, f.cfg
		_, err := txeHubInstall(t.Context(), hub, fakeMachines{}, machine, cfg, false)
		require.ErrorContains(t, err, "does not confirm machine")
		assert.Empty(t, hub.writes)
	})
	t.Run("another owner", func(t *testing.T) {
		f := newHubFixture(t)
		hub, machine, cfg := f.hub, f.machine, f.cfg
		machines := fakeMachines{txeTestMachine: {MachineID: txeTestMachine, OwnerID: "own_01JTXE0000000000000000ZZZZ"}}
		_, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, false)
		require.ErrorContains(t, err, "owned by")
		assert.Empty(t, hub.writes)
	})
}

// No healthy worker for the machine warns and still installs: a sleeping
// laptop's runs wait for it.
func TestTXEHubInstallWarnsWithoutAHealthyWorker(t *testing.T) {
	for label, workers := range map[string][]api.Worker{
		"none":        nil,
		"other label": {{Id: "w", HealthStatus: api.WorkerHealthStatusHealthy, Labels: map[string]string{txeHubWorkerLabel: "mch_01JTXE0000000000000000OTHR"}}},
		"unhealthy":   {{Id: txeTestMachine, HealthStatus: api.WorkerHealthStatusUnhealthy, Labels: map[string]string{txeHubWorkerLabel: txeTestMachine}}},
	} {
		t.Run(label, func(t *testing.T) {
			f := newHubFixture(t)
			hub, machines, machine, cfg := f.hub, f.machines, f.machine, f.cfg
			hub.workers = workers
			res, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, false)
			require.NoError(t, err)
			assert.Equal(t, txeHubCreated, res.Action)
			assert.Empty(t, res.Worker)
			require.Len(t, res.Warnings, 1)
			assert.Contains(t, res.Warnings[0], txeTestMachine)
			assert.Len(t, hub.writes, 1)
		})
	}
}

// A hub error, or a spec the hub could not load, fails the install.
func TestTXEHubInstallReportsHubFailures(t *testing.T) {
	name := probe.ReconcileDAGName(txeTestMachine)
	t.Run("read", func(t *testing.T) {
		f := newHubFixture(t)
		hub, machines, machine, cfg := f.hub, f.machines, f.machine, f.cfg
		hub.getErr = errors.New("hub down")
		_, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, false)
		require.ErrorContains(t, err, "hub down")
	})
	t.Run("spec rejected", func(t *testing.T) {
		f := newHubFixture(t)
		hub, machines, machine, cfg := f.hub, f.machines, f.machine, f.cfg
		hub.specs[name] = "# txe-probe-dag-version: 1\nold\n"
		hub.putErr = &remoteSpecError{Errors: []string{"bad step"}}
		_, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, false)
		require.ErrorContains(t, err, "bad step")
	})
	t.Run("credential-shaped input", func(t *testing.T) {
		f := newHubFixture(t)
		hub, machines, machine, cfg := f.hub, f.machines, f.machine, f.cfg
		cfg.Env["LINEAR_API_KEY"] = "/x"
		_, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, false)
		require.Error(t, err)
		assert.Empty(t, hub.writes)
	})
}

// The command refuses another machine's id before it reaches the hub.
func TestTXEHubInstallCommandRefusesAnotherMachine(t *testing.T) {
	keepDaguEnvironment(t)
	home := t.TempDir()
	t.Setenv("TXE_DAGU_HOME", home)
	require.NoError(t, os.WriteFile(filepath.Join(home, "machine.json"),
		[]byte(`{"schema":1,"machine_id":"`+txeTestMachine+`","owner_id":"`+txeTestOwner+`"}`), 0o600))
	root := &cobra.Command{Use: "dagu", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(TXE())
	root.SetArgs([]string{"txe", "hub", "install", "--machine", "mch_01JTXE0000000000000000OTHR"})
	err := root.Execute()
	require.ErrorContains(t, err, "this machine is "+txeTestMachine)
}
