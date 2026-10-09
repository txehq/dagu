// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"

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
	listWorkers(ctx context.Context) ([]api.Worker, error)
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
	res, err := txeHubInstall(ctx, remote, client, *machine, cfg, dryRun)
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

// txeHubInstall verifies the machine with the registry, renders its DAG and
// creates or updates it on the hub.
func txeHubInstall(ctx context.Context, hub txeHubDAGs, registry txeHubMachines, machine txepkg.Machine, cfg probe.ReconcileDAGConfig, dryRun bool) (*txeHubInstallResult, error) {
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
	res := &txeHubInstallResult{DAG: name, MachineID: machine.MachineID, DryRun: dryRun, Version: probe.ReconcileDAGVersion}

	current, found, err := hub.getDAGSpec(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("read %s from the hub: %w", name, err)
	}
	switch {
	case !found:
		res.Action = txeHubCreated
	case current == string(spec):
		res.Action = txeHubUnchanged
	default:
		installed, ok := txeHubProbeDAGVersion(current)
		if !ok {
			return nil, fmt.Errorf("the hub's %s was not rendered by the probe renderer; it is left alone", name)
		}
		if installed > probe.ReconcileDAGVersion {
			return nil, fmt.Errorf("the hub's %s is txe-probe-dag-version %d, newer than this client's %d; update this client", name, installed, probe.ReconcileDAGVersion)
		}
		res.Action = txeHubUpdated
	}

	worker, warning, err := txeHubMachineWorker(ctx, hub, machine.MachineID)
	if err != nil {
		return nil, err
	}
	res.Worker = worker
	if warning != "" {
		res.Warnings = append(res.Warnings, warning)
	}

	if dryRun {
		return res, nil
	}
	switch res.Action {
	case txeHubCreated:
		err = hub.createDAG(ctx, name, string(spec))
	case txeHubUpdated:
		err = hub.updateDAGSpec(ctx, name, string(spec))
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s on the hub: %w", res.Action, name, err)
	}
	return res, nil
}

// txeHubMachineWorker names a healthy worker labelled for the machine, or
// returns a warning when there is none. A worker that sleeps, as a laptop
// does, is no reason to refuse: the DAG's runs wait for it.
func txeHubMachineWorker(ctx context.Context, hub txeHubDAGs, machineID string) (worker, warning string, err error) {
	workers, err := hub.listWorkers(ctx)
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
	if seen != "" {
		return "", fmt.Sprintf("worker %s for %s is not healthy; runs wait until it is", seen, machineID), nil
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
