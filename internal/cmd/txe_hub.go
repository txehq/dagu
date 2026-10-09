// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/spf13/cobra"

	api "github.com/dagucloud/dagu/v2/api/v1"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/probe"
)

var (
	txeHubMachineFlag = commandLineFlag{name: "machine", usage: "Machine id to install for; must be this machine (default: this machine)"}
	txeHubDryRunFlag  = commandLineFlag{name: "dry-run", usage: "Report what would change on the hub without changing it", isBool: true}
)

// txeHubWorkerLabel is the worker label that ties a hub DAG to the machine
// whose worker runs it.
const txeHubWorkerLabel = "txe.machine"

// Install actions.
const (
	txeHubCreated   = "created"
	txeHubUpdated   = "updated"
	txeHubUnchanged = "unchanged"
)

func init() {
	txeSubcommands = append(txeSubcommands, txeHubCommand)
}

func txeHubCommand() *cobra.Command {
	command := NewCommand(&cobra.Command{
		Use:   "hub",
		Short: "Install this machine's DAGs on the hub",
	}, nil, func(ctx *Context, _ []string) error {
		return ctx.Command.Help()
	})
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "install",
		Short: "Install or update this machine's periodic resource check on the hub",
		Long: `Install this machine's periodic reconcile DAG on the hub. The hub
schedules it, and this machine's worker runs it: it observes the reconcile
targets of the machine's jobs with the machine's own credentials and reports
them to the registry.

The DAG is rendered from this machine's TXE home: its machine id, its dagu
binary and the CLI context the check reports through. It holds paths and a
context name only, never a credential. The DAG is created when absent and
updated only when the rendered spec differs; a DAG of that name the renderer
did not write, or one from a newer renderer, is left alone.

Without a healthy worker for this machine the DAG is still installed, with a
warning: its runs wait for the worker, and overlapping ticks are skipped.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeHubMachineFlag, txeHubDryRunFlag, txeJSONFlag}, runTXEHubInstall))
	return command
}

// txeHubDAGs is the part of the hub the installer uses.
type txeHubDAGs interface {
	getDAGSpec(ctx context.Context, name string) (spec string, found bool, err error)
	createDAG(ctx context.Context, name, spec string) error
	updateDAGSpec(ctx context.Context, name, spec string) error
	listWorkers(ctx context.Context) (workers []api.Worker, listErrors []string, err error)
}

// txeHubMachines is the registry lookup the installer verifies the machine
// with.
type txeHubMachines interface {
	Machine(ctx context.Context, machineID string) (*txeclient.Machine, error)
}

// txeHubInstallResult is what one install did.
type txeHubInstallResult struct {
	DAG       string   `json:"dag"`
	MachineID string   `json:"machine_id"`
	Action    string   `json:"action"`
	DryRun    bool     `json:"dry_run"`
	Version   int      `json:"version"`
	Worker    string   `json:"worker,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

func runTXEHubInstall(ctx *Context, _ []string) error {
	machineArg, err := ctx.StringParam("machine")
	if err != nil {
		return err
	}
	dryRun, err := ctx.Command.Flags().GetBool("dry-run")
	if err != nil {
		return err
	}
	home, err := txepkg.DefaultHome()
	if err != nil {
		return err
	}
	machine, err := home.Machine()
	if err != nil {
		return err
	}
	if machineArg != "" && machineArg != machine.MachineID {
		return fmt.Errorf("this machine is %s, not %s: install a machine's DAG from that machine", machine.MachineID, machineArg)
	}
	remote, err := txeRemote(ctx)
	if err != nil {
		return err
	}
	client, err := txeClient(ctx)
	if err != nil {
		return err
	}
	cfg := txeHubProbeConfig(home, *machine, txeHubContext(ctx))
	res, err := txeHubInstall(ctx, remote, client, *machine, cfg, txeHubInstallOptions{
		DryRun:   dryRun,
		LockPath: filepath.Join(home.Root, "state", "hub-install-"+machine.MachineID+".lock"),
	})
	if err != nil {
		return err
	}
	return txeOutput(ctx, res, func(p *txePrinter) {
		verb := res.Action
		if res.DryRun {
			verb = "would be " + verb
		}
		p.f("%s: %s (txe-probe-dag-version %d)\n", res.DAG, verb, res.Version)
		if res.Worker != "" {
			p.f("worker: %s\n", res.Worker)
		}
		for _, w := range res.Warnings {
			p.f("warning: %s\n", w)
		}
	})
}

// txeHubProbeConfig renders the reconcile DAG's inputs from the TXE home the
// worker installer laid out, the binary it links at bin/dagu, and the CLI
// context this command uses, pinned as it resolved here: the check runs in a
// step, where resolving the configuration again could give other directories.
func txeHubProbeConfig(home txepkg.Home, machine txepkg.Machine, hub txeclient.HubContext) probe.ReconcileDAGConfig {
	daguHome := hub.DaguHome
	if daguHome == "" {
		daguHome = home.ClientDir()
	}
	name := hub.Name
	if name == "" {
		name = txeContextName
	}
	flags := []string{"--dagu-home", daguHome, "--context", name}
	if hub.ConfigFile != "" {
		flags = append(flags, "--config", hub.ConfigFile)
	}
	if hub.ContextsDir != "" {
		flags = append(flags, "--contexts-dir", hub.ContextsDir)
	}
	if hub.DataDir != "" {
		flags = append(flags, "--data-dir", hub.DataDir)
	}
	return probe.ReconcileDAGConfig{
		MachineID:  machine.MachineID,
		DaguBin:    filepath.Join(home.Root, "bin", "dagu"),
		StoreFlags: flags,
		Env:        map[string]string{txepkg.EnvHome: home.Root},
	}
}

// txeHubInstallLockTimeout bounds the wait for another install of this
// machine's DAG to finish.
const txeHubInstallLockTimeout = 2 * time.Minute

// txeHubInstallOptions are an install's switches.
type txeHubInstallOptions struct {
	DryRun bool
	// LockPath serializes installs of this machine's DAG. Only this
	// machine installs it: the command refuses another machine's id. The
	// hub's spec API has no compare-and-swap, so this is what keeps one
	// install from writing over another's newer render.
	LockPath string
}

// txeHubInstall verifies the machine with the registry, renders its DAG and
// creates or updates it on the hub, holding the machine's install lock.
func txeHubInstall(ctx context.Context, hub txeHubDAGs, registry txeHubMachines, machine txepkg.Machine, cfg probe.ReconcileDAGConfig, opts txeHubInstallOptions) (*txeHubInstallResult, error) {
	known, err := registry.Machine(ctx, machine.MachineID)
	if err != nil {
		return nil, fmt.Errorf("the hub registry does not confirm machine %s: %w", machine.MachineID, err)
	}
	if known.MachineID != machine.MachineID || known.OwnerID != machine.OwnerID {
		return nil, fmt.Errorf("the hub registry has machine %s owned by %s, but this machine is %s owned by %s",
			known.MachineID, known.OwnerID, machine.MachineID, machine.OwnerID)
	}
	name, spec, err := probe.RenderReconcileDAG(cfg)
	if err != nil {
		return nil, err
	}
	res := &txeHubInstallResult{DAG: name, MachineID: machine.MachineID, DryRun: opts.DryRun, Version: probe.ReconcileDAGVersion}

	if !opts.DryRun {
		unlock, err := txeHubLock(ctx, opts.LockPath)
		if err != nil {
			return nil, err
		}
		defer unlock()
	}

	worker, warning, err := txeHubMachineWorker(ctx, hub, machine.MachineID)
	if err != nil {
		return nil, err
	}
	res.Worker = worker
	if warning != "" {
		res.Warnings = append(res.Warnings, warning)
	}

	// A create that finds the DAG already there lost a race with a writer
	// outside this machine's lock: read it again and decide once more.
	for attempt := 0; ; attempt++ {
		if res.Action, err = txeHubAssess(ctx, hub, name, spec); err != nil {
			return nil, err
		}
		if opts.DryRun {
			return res, nil
		}
		switch res.Action {
		case txeHubCreated:
			err = hub.createDAG(ctx, name, string(spec))
			if txeHubRemoteStatus(err) == http.StatusConflict && attempt == 0 {
				continue
			}
		case txeHubUpdated:
			err = hub.updateDAGSpec(ctx, name, string(spec))
		case txeHubUnchanged:
			return res, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s %s on the hub: %w", res.Action, name, err)
		}
		break
	}

	// Read the write back: a hub user editing the DAG in the same moment is
	// outside this lock, and the hub would keep whichever write came last.
	stored, found, err := hub.getDAGSpec(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("read %s back from the hub: %w", name, err)
	}
	if !found || stored != string(spec) {
		return nil, fmt.Errorf("the hub's %s changed while it was being %s; run the install again", name, res.Action)
	}
	return res, nil
}

// txeHubAssess decides what installing spec as name needs: create, update or
// nothing. A stored DAG the renderer did not write, or a newer render, is
// refused.
func txeHubAssess(ctx context.Context, hub txeHubDAGs, name string, spec []byte) (string, error) {
	current, found, err := hub.getDAGSpec(ctx, name)
	if err != nil {
		return "", fmt.Errorf("read %s from the hub: %w", name, err)
	}
	switch {
	case !found:
		return txeHubCreated, nil
	case current == string(spec):
		return txeHubUnchanged, nil
	}
	installed, ok := txeHubProbeDAGVersion(current)
	if !ok {
		return "", fmt.Errorf("the hub's %s was not rendered by the probe renderer; it is left alone", name)
	}
	if installed > probe.ReconcileDAGVersion {
		return "", fmt.Errorf("the hub's %s is txe-probe-dag-version %d, newer than this client's %d; update this client", name, installed, probe.ReconcileDAGVersion)
	}
	return txeHubUpdated, nil
}

// txeHubLock takes the machine's install lock, waiting for another install
// to finish.
func txeHubLock(ctx context.Context, path string) (func(), error) {
	if path == "" {
		return nil, errors.New("no install lock path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create the install lock directory: %w", err)
	}
	lock := flock.New(path)
	lockCtx, cancel := context.WithTimeout(ctx, txeHubInstallLockTimeout)
	defer cancel()
	locked, err := lock.TryLockContext(lockCtx, 200*time.Millisecond)
	if err != nil || !locked {
		return nil, fmt.Errorf("another install of this machine's hub DAG is running (lock %s): %w", path, err)
	}
	return func() { _ = lock.Unlock() }, nil
}

// txeHubRemoteStatus is the HTTP status of a hub error, or 0.
func txeHubRemoteStatus(err error) int {
	if remoteErr, ok := errors.AsType[*remoteError](err); ok {
		return remoteErr.StatusCode
	}
	return 0
}

// txeHubMachineWorker names a healthy worker labelled for the machine, or
// returns a warning when there is none or its health cannot be established.
// A worker that sleeps, as a laptop does, is no reason to refuse: the DAG's
// runs wait for it. Only a hub that refuses the request fails the install.
func txeHubMachineWorker(ctx context.Context, hub txeHubDAGs, machineID string) (worker, warning string, err error) {
	workers, listErrors, err := hub.listWorkers(ctx)
	if txeHubRemoteStatus(err) == http.StatusServiceUnavailable {
		return "", fmt.Sprintf("the hub's coordinator is unavailable, so whether a worker for %s is connected is unknown; runs wait for one", machineID), nil
	}
	if err != nil {
		return "", "", fmt.Errorf("list the hub's workers: %w", err)
	}
	seen := ""
	for _, w := range workers {
		if w.Labels[txeHubWorkerLabel] != machineID {
			continue
		}
		if w.HealthStatus == api.WorkerHealthStatusHealthy {
			return w.Id, "", nil
		}
		seen = w.Id + " (" + string(w.HealthStatus) + ")"
	}
	switch {
	case seen != "":
		return "", fmt.Sprintf("worker %s for %s is not healthy; runs wait until it is", seen, machineID), nil
	case len(listErrors) > 0:
		return "", fmt.Sprintf("the hub could not list every worker (%s); no healthy worker for %s was seen, and runs wait for one", strings.Join(listErrors, "; "), machineID), nil
	}
	return "", fmt.Sprintf("no worker labelled %s=%s is connected; runs wait until it is", txeHubWorkerLabel, machineID), nil
}

var txeHubProbeVersionLine = regexp.MustCompile(`(?m)^# txe-probe-dag-version: ([0-9]+)$`)

// txeHubProbeDAGVersion reads the renderer's version header from a stored
// spec. ok is false when the spec has none, so it was not rendered here.
func txeHubProbeDAGVersion(spec string) (int, bool) {
	m := txeHubProbeVersionLine.FindStringSubmatch(spec)
	if m == nil {
		return 0, false
	}
	v, err := strconv.Atoi(m[1])
	return v, err == nil
}

// Compile-time checks: the remote client and the registry client serve the
// installer.
var (
	_ txeHubDAGs     = (*remoteClient)(nil)
	_ txeHubMachines = (*txeclient.Client)(nil)
)
