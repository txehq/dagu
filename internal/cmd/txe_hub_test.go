// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

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
	mu         sync.Mutex
	specs      map[string]string
	workers    []api.Worker
	listErrors []string
	workersErr error
	writes     []string
	getErr     error
	putErr     error
	onCreate   func(h *fakeHub, name string) error // runs before a create, as another writer
	afterWrite func(h *fakeHub, name string)       // runs after a write, as another writer
	onListWork func()
}

func (h *fakeHub) getDAGSpec(_ context.Context, name string) (string, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.getErr != nil {
		return "", false, h.getErr
	}
	spec, ok := h.specs[name]
	return spec, ok, nil
}

func (h *fakeHub) createDAG(_ context.Context, name, spec string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.onCreate != nil {
		if err := h.onCreate(h, name); err != nil {
			return err
		}
	}
	if _, ok := h.specs[name]; ok {
		return &remoteError{StatusCode: http.StatusConflict, Message: "already exists"}
	}
	h.writes = append(h.writes, "create "+name)
	h.specs[name] = spec
	if h.afterWrite != nil {
		h.afterWrite(h, name)
	}
	return nil
}

func (h *fakeHub) updateDAGSpec(_ context.Context, name, spec string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.putErr != nil {
		return h.putErr
	}
	h.writes = append(h.writes, "update "+name)
	h.specs[name] = spec
	if h.afterWrite != nil {
		h.afterWrite(h, name)
	}
	return nil
}

func (h *fakeHub) listWorkers(context.Context) ([]api.Worker, []string, error) {
	if h.onListWork != nil {
		h.onListWork()
	}
	return h.workers, h.listErrors, h.workersErr
}

func (h *fakeHub) writesSoFar() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.writes...)
}

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
	opts     txeHubInstallOptions
}

// skipOnWindows skips a test that renders the reconcile DAG: it carries the
// worker's POSIX paths, which the renderer requires, and a TXE worker runs
// on macOS or Linux only.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the reconcile DAG renders POSIX paths for a macOS or Linux worker")
	}
}

func newHubFixture(t *testing.T) hubFixture {
	t.Helper()
	skipOnWindows(t)
	home := txepkg.Home{Root: "/Users/someone/.local/share/txe-dagu"}
	machine := txepkg.Machine{MachineID: txeTestMachine, OwnerID: txeTestOwner}
	hub := &fakeHub{specs: map[string]string{}, workers: []api.Worker{{
		Id: txeTestMachine, HealthStatus: api.WorkerHealthStatusHealthy, Labels: map[string]string{txeHubWorkerLabel: txeTestMachine},
	}}}
	machines := fakeMachines{txeTestMachine: {MachineID: txeTestMachine, OwnerID: txeTestOwner}}
	return hubFixture{hub, machines, machine, txeHubProbeConfig(home, machine, txeclient.HubContext{}),
		txeHubInstallOptions{LockPath: filepath.Join(t.TempDir(), "hub-install.lock")}}
}

// The DAG is rendered from the TXE home's layout, with only paths and the
// context name, and the step can find that home.
func TestTXEHubProbeConfig(t *testing.T) {
	skipOnWindows(t)
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

	res, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, f.opts)
	require.NoError(t, err)
	assert.Equal(t, txeHubCreated, res.Action)
	assert.Equal(t, name, res.DAG)
	assert.Equal(t, txeTestMachine, res.Worker)
	assert.Empty(t, res.Warnings)

	res, err = txeHubInstall(t.Context(), hub, machines, machine, cfg, f.opts)
	require.NoError(t, err)
	assert.Equal(t, txeHubUnchanged, res.Action)
	assert.Equal(t, []string{"create " + name}, hub.writes)

	hub.specs[name] = strings.Replace(hub.specs[name], "*/15 * * * *", "*/30 * * * *", 1)
	res, err = txeHubInstall(t.Context(), hub, machines, machine, cfg, f.opts)
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
	res, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, txeHubInstallOptions{DryRun: true})
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
			_, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, f.opts)
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
		_, err := txeHubInstall(t.Context(), hub, fakeMachines{}, machine, cfg, f.opts)
		require.ErrorContains(t, err, "does not confirm machine")
		assert.Empty(t, hub.writes)
	})
	t.Run("another owner", func(t *testing.T) {
		f := newHubFixture(t)
		hub, machine, cfg := f.hub, f.machine, f.cfg
		machines := fakeMachines{txeTestMachine: {MachineID: txeTestMachine, OwnerID: "own_01JTXE0000000000000000ZZZZ"}}
		_, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, f.opts)
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
			res, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, f.opts)
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
		_, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, f.opts)
		require.ErrorContains(t, err, "hub down")
	})
	t.Run("spec rejected", func(t *testing.T) {
		f := newHubFixture(t)
		hub, machines, machine, cfg := f.hub, f.machines, f.machine, f.cfg
		hub.specs[name] = "# txe-probe-dag-version: 1\nold\n"
		hub.putErr = &remoteSpecError{Errors: []string{"bad step"}}
		_, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, f.opts)
		require.ErrorContains(t, err, "bad step")
	})
	t.Run("credential-shaped input", func(t *testing.T) {
		f := newHubFixture(t)
		hub, machines, machine, cfg := f.hub, f.machines, f.machine, f.cfg
		cfg.Env["LINEAR_API_KEY"] = "/x"
		_, err := txeHubInstall(t.Context(), hub, machines, machine, cfg, f.opts)
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

// Two installs of this machine's DAG run one at a time: the second waits for
// the first's lock before it reaches the hub, so neither writes over the
// other's render.
func TestTXEHubInstallsAreSerialized(t *testing.T) {
	f := newHubFixture(t)
	firstIn := make(chan struct{})
	release := make(chan struct{})
	calls := 0
	var mu sync.Mutex
	f.hub.onListWork = func() {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			close(firstIn)
			<-release
		}
	}
	done := make(chan error, 2)
	go func() {
		_, err := txeHubInstall(t.Context(), f.hub, f.machines, f.machine, f.cfg, f.opts)
		done <- err
	}()
	<-firstIn
	go func() {
		_, err := txeHubInstall(t.Context(), f.hub, f.machines, f.machine, f.cfg, f.opts)
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	assert.Equal(t, 1, calls, "the second install waits for the lock before reaching the hub")
	mu.Unlock()
	close(release)
	require.NoError(t, <-done)
	require.NoError(t, <-done)
	assert.Equal(t, []string{"create " + probe.ReconcileDAGName(txeTestMachine)}, f.hub.writesSoFar(),
		"the second install found the first's DAG unchanged")
}

// A create that loses a race with another writer reads the DAG again: the
// same render is unchanged, and a foreign DAG is refused.
func TestTXEHubInstallRereadsAfterACreateConflict(t *testing.T) {
	name := probe.ReconcileDAGName(txeTestMachine)
	t.Run("same render", func(t *testing.T) {
		f := newHubFixture(t)
		_, want, err := probe.RenderReconcileDAG(f.cfg)
		require.NoError(t, err)
		f.hub.onCreate = func(h *fakeHub, n string) error {
			h.onCreate = nil
			h.specs[n] = string(want)
			return nil
		}
		res, err := txeHubInstall(t.Context(), f.hub, f.machines, f.machine, f.cfg, f.opts)
		require.NoError(t, err)
		assert.Equal(t, txeHubUnchanged, res.Action)
		assert.Empty(t, f.hub.writesSoFar())
	})
	t.Run("foreign", func(t *testing.T) {
		f := newHubFixture(t)
		f.hub.onCreate = func(h *fakeHub, n string) error {
			h.onCreate = nil
			h.specs[n] = "steps:\n  - command: echo hand-written\n"
			return nil
		}
		_, err := txeHubInstall(t.Context(), f.hub, f.machines, f.machine, f.cfg, f.opts)
		require.ErrorContains(t, err, "not rendered by the probe renderer")
		assert.Equal(t, "steps:\n  - command: echo hand-written\n", f.hub.specs[name])
	})
}

// A write that another writer replaced at once is reported, not claimed.
func TestTXEHubInstallReadsItsWriteBack(t *testing.T) {
	f := newHubFixture(t)
	f.hub.afterWrite = func(h *fakeHub, n string) { h.specs[n] = "# txe-probe-dag-version: 1\nedited\n" }
	_, err := txeHubInstall(t.Context(), f.hub, f.machines, f.machine, f.cfg, f.opts)
	require.ErrorContains(t, err, "changed while it was being created")
}

// Worker health is advisory: a coordinator the hub cannot reach, or a
// partial list, warns and installs. A hub that refuses the request fails.
func TestTXEHubInstallWorkerHealthIsAdvisory(t *testing.T) {
	t.Run("coordinator unavailable", func(t *testing.T) {
		f := newHubFixture(t)
		f.hub.workersErr = &remoteError{StatusCode: http.StatusServiceUnavailable, Message: "coordinator unavailable"}
		res, err := txeHubInstall(t.Context(), f.hub, f.machines, f.machine, f.cfg, f.opts)
		require.NoError(t, err)
		assert.Equal(t, txeHubCreated, res.Action)
		require.Len(t, res.Warnings, 1)
		assert.Contains(t, res.Warnings[0], "coordinator is unavailable")
	})
	t.Run("partial list", func(t *testing.T) {
		f := newHubFixture(t)
		f.hub.workers = nil
		f.hub.listErrors = []string{"Coordinator service not configured"}
		res, err := txeHubInstall(t.Context(), f.hub, f.machines, f.machine, f.cfg, f.opts)
		require.NoError(t, err)
		require.Len(t, res.Warnings, 1)
		assert.Contains(t, res.Warnings[0], "Coordinator service not configured")
	})
	t.Run("refused", func(t *testing.T) {
		f := newHubFixture(t)
		f.hub.workersErr = &remoteError{StatusCode: http.StatusUnauthorized, Message: "unauthorized"}
		_, err := txeHubInstall(t.Context(), f.hub, f.machines, f.machine, f.cfg, f.opts)
		require.ErrorContains(t, err, "unauthorized")
		assert.Empty(t, f.hub.writesSoFar())
	})
}
