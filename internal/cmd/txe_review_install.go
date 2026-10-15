// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
)

// txeReviewRenderedMarker is the line every reviewer and decision DAG the
// renderer writes carries. A stored DAG without it is not the renderer's,
// and the installer leaves it alone.
const txeReviewRenderedMarker = "# Rendered by `dagu txe review render`; do not edit the installed copy."

// txeReviewRenderedLine matches the marker as a whole line of its own, so the
// same text inside a description or a script does not count.
var txeReviewRenderedLine = regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(txeReviewRenderedMarker) + `\r?$`)

var txeReviewInstallMachineFlag = commandLineFlag{name: "machine", usage: "Machine id to install for; must be this machine (default: this machine)"}

func txeReviewInstallCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "install",
		Short: "Install or update this machine's reviewer and decision DAGs on the hub",
		Long: `Render this machine's reviewer and decision DAGs, as render does with the
same flags, and install them on the hub. Each is created when absent and updated
only when the render differs; a DAG of that name the renderer did not write is
left alone.

The DAGs are written through this machine's hub connection: the owner's
sign-in ("dagu txe login") on a hub that takes it for DAGs, which is what a hub
enforcing owners requires, or else the context's API key. A refused sign-in is
reported, never retried with the API key.

An update never resets a setting silently. When the installed reviewer's
schedule, agent model, agent profile, state directory, TXE home or review
command differs from what this install would render, the install stops unless
that setting's flag was given; give it with the installed value to keep it, or
with another to change it.

Both DAGs are checked before either is written, and the decision DAG is
written first, so a reviewer never points at a missing one. If the second write
fails, the first stays installed and the install says so; run it again to
finish.

Installing is not readiness: the DAGs run only when this machine's worker is
connected. The hub does not show an owner's sign-in its workers, so the output
then says that readiness is unknown.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeReviewInstallMachineFlag, txeReviewStateFlag, txeReviewScheduleFlag, txeReviewAgentDirFlag, txeReviewAgentModelFlag,
		txeReviewCommandFlag, txeReviewHomeFlag, txeHubDryRunFlag, txeJSONFlag}, runTXEReviewInstall)
}

// txeReviewInstallDAG is what one install did to one DAG.
type txeReviewInstallDAG struct {
	DAG    string `json:"dag"`
	Action string `json:"action"`
}

// txeReviewInstallResult is what one install did.
type txeReviewInstallResult struct {
	MachineID string                `json:"machine_id"`
	DryRun    bool                  `json:"dry_run"`
	DAGs      []txeReviewInstallDAG `json:"dags"`
	// Runnable says whether a worker for the machine was seen; installed is
	// not runnable until one is.
	Runnable string   `json:"runnable"`
	Worker   string   `json:"worker,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func runTXEReviewInstall(ctx *Context, _ []string) error {
	machineArg, err := ctx.StringParam(txeReviewInstallMachineFlag.name)
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
		return fmt.Errorf("this machine is %s, not %s: install a machine's reviewer from that machine", machine.MachineID, machineArg)
	}
	cfg, err := txeReviewDAGConfig(ctx, machine.MachineID)
	if err != nil {
		return err
	}
	explicit := map[string]bool{}
	for _, flag := range []string{txeReviewScheduleFlag.name, txeReviewAgentModelFlag.name, txeReviewAgentDirFlag.name,
		txeReviewStateFlag.name, txeReviewHomeFlag.name, txeReviewCommandFlag.name} {
		explicit[flag] = ctx.Command.Flags().Changed(flag)
	}
	remote, err := txeRemote(ctx)
	if err != nil {
		return err
	}
	client, err := txeClient(ctx)
	if err != nil {
		return err
	}
	res, err := txeReviewInstall(ctx, remote, client, *machine, cfg, explicit, txeHubInstallOptions{
		DryRun:   dryRun,
		LockPath: filepath.Join(home.Root, "state", "review-install-"+machine.MachineID+".lock"),
	})
	if res != nil {
		if out := txeOutput(ctx, res, func(p *txePrinter) { printReviewInstall(p, res) }); err == nil {
			err = out
		}
	}
	return err
}

func printReviewInstall(p *txePrinter, res *txeReviewInstallResult) {
	for _, d := range res.DAGs {
		verb := d.Action
		if res.DryRun {
			verb = "would be " + verb
		}
		p.f("%s: %s\n", d.DAG, verb)
	}
	p.f("runnable: %s\n", res.Runnable)
	for _, w := range res.Warnings {
		p.f("warning: %s\n", w)
	}
}

// txeReviewPlanned is one DAG's planned install.
type txeReviewPlanned struct {
	name, spec, action string
}

// txeReviewInstall verifies the machine with the registry, renders its two
// DAGs, checks both against the hub, and then writes them, the decision DAG
// first, holding the machine's review install lock. On a failed write it
// returns what was already installed with the error.
func txeReviewInstall(ctx context.Context, hub txeHubDAGs, registry txeHubMachines, machine txepkg.Machine, cfg review.DAGConfig,
	explicit map[string]bool, opts txeHubInstallOptions) (*txeReviewInstallResult, error) {
	known, err := registry.Machine(ctx, machine.MachineID)
	if err != nil {
		return nil, fmt.Errorf("the hub registry does not confirm machine %s: %w", machine.MachineID, err)
	}
	if known.MachineID != machine.MachineID || known.OwnerID != machine.OwnerID {
		return nil, fmt.Errorf("the hub registry has machine %s owned by %s, but this machine is %s owned by %s",
			known.MachineID, known.OwnerID, machine.MachineID, machine.OwnerID)
	}
	dags, err := review.RenderDAGs(cfg)
	if err != nil {
		return nil, err
	}
	res := &txeReviewInstallResult{MachineID: machine.MachineID, DryRun: opts.DryRun}
	if !opts.DryRun {
		unlock, err := txeHubLock(ctx, opts.LockPath)
		if err != nil {
			return nil, err
		}
		defer unlock()
	}

	// Both are decided before either is written, so a refusal changes
	// nothing. The decision DAG goes first: a reviewer files proposals as its
	// runs.
	plan := []txeReviewPlanned{{name: dags.DecideName, spec: dags.Decide}, {name: dags.ReviewerName, spec: dags.Reviewer}}
	for i := range plan {
		if plan[i].action, err = txeReviewAssess(ctx, hub, plan[i].name, plan[i].spec, explicit); err != nil {
			return nil, err
		}
	}

	worker, warning, err := txeHubMachineWorker(ctx, hub, machine.MachineID)
	if err != nil {
		return nil, err
	}
	res.Worker = worker
	if worker != "" {
		res.Runnable = "worker " + worker + " for " + machine.MachineID + " is connected and healthy"
	} else {
		res.Runnable = "unknown"
		res.Warnings = append(res.Warnings, warning)
	}

	for _, p := range plan {
		if opts.DryRun || p.action == txeHubUnchanged {
			res.DAGs = append(res.DAGs, txeReviewInstallDAG{DAG: p.name, Action: p.action})
			continue
		}
		action, err := txeReviewWrite(ctx, hub, p, explicit)
		if err != nil {
			for _, done := range res.DAGs {
				if done.Action != txeHubUnchanged {
					err = fmt.Errorf("%w; %s was already %s: run the install again to finish", err, done.DAG, done.Action)
				}
			}
			return res, err
		}
		res.DAGs = append(res.DAGs, txeReviewInstallDAG{DAG: p.name, Action: action})
	}
	return res, nil
}

// txeReviewWrite creates or updates one DAG and reads it back. A create that
// finds the DAG already there lost a race with a writer outside the lock: it
// is decided once more.
func txeReviewWrite(ctx context.Context, hub txeHubDAGs, p txeReviewPlanned, explicit map[string]bool) (string, error) {
	action := p.action
	for attempt := 0; ; attempt++ {
		var err error
		switch action {
		case txeHubCreated:
			err = hub.createDAG(ctx, p.name, p.spec)
			if txeHubRemoteStatus(err) == http.StatusConflict && attempt == 0 {
				if action, err = txeReviewAssess(ctx, hub, p.name, p.spec, explicit); err != nil {
					return "", err
				}
				if action == txeHubUnchanged {
					return action, nil
				}
				continue
			}
		case txeHubUpdated:
			err = hub.updateDAGSpec(ctx, p.name, p.spec)
		case txeHubUnchanged:
			return action, nil
		}
		if err != nil {
			return "", fmt.Errorf("%s %s on the hub: %w", action, p.name, err)
		}
		break
	}
	stored, found, err := hub.getDAGSpec(ctx, p.name)
	if err != nil {
		return "", fmt.Errorf("read %s back from the hub: %w", p.name, err)
	}
	if !found || stored != p.spec {
		return "", fmt.Errorf("the hub's %s changed while it was being %s; run the install again", p.name, action)
	}
	return action, nil
}

// txeReviewAssess decides what installing spec as name needs: create, update
// or nothing. A stored DAG the renderer did not write is refused, and so is an
// update that would change an installed setting whose flag was not given.
func txeReviewAssess(ctx context.Context, hub txeHubDAGs, name, spec string, explicit map[string]bool) (string, error) {
	current, found, err := hub.getDAGSpec(ctx, name)
	if err != nil {
		return "", fmt.Errorf("read %s from the hub: %w", name, err)
	}
	switch {
	case !found:
		return txeHubCreated, nil
	case current == spec:
		return txeHubUnchanged, nil
	case !txeReviewRenderedLine.MatchString(current):
		return "", fmt.Errorf("the hub's %s was not written by the reviewer renderer; it is left alone", name)
	}
	installed, err := txeReviewSettings(current)
	if err != nil {
		return "", fmt.Errorf("read the installed %s: %w", name, err)
	}
	rendered, err := txeReviewSettings(spec)
	if err != nil {
		return "", err
	}
	var kept []string
	for _, flag := range txeReviewSettingFlags {
		if installed[flag] != rendered[flag] && !explicit[flag] {
			kept = append(kept, fmt.Sprintf("--%s (installed %q, this install %q)", flag, installed[flag], rendered[flag]))
		}
	}
	if len(kept) > 0 {
		return "", fmt.Errorf("the hub's %s has settings this install would change without being asked: %s; give each flag with the installed value to keep it, or with another to change it",
			name, strings.Join(kept, ", "))
	}
	return txeHubUpdated, nil
}

// txeReviewSettingFlags are the render flags whose installed values an
// update keeps unless the flag is given, in the order they are reported.
var txeReviewSettingFlags = []string{"schedule", "agent-model", "agent-config-dir", "state-dir", "txe-home", "review-command"}

// txeReviewSettings reads, from a reviewer or decision DAG, the values the
// render flags put there, keyed by flag. A setting a DAG does not carry is "".
func txeReviewSettings(spec string) (map[string]string, error) {
	var doc struct {
		Schedule   string              `yaml:"schedule"`
		WorkingDir string              `yaml:"working_dir"`
		Env        []map[string]string `yaml:"env"`
		Steps      []struct {
			ID   string         `yaml:"id"`
			Run  string         `yaml:"run"`
			With map[string]any `yaml:"with"`
		} `yaml:"steps"`
	}
	if err := yaml.Unmarshal([]byte(spec), &doc); err != nil {
		return nil, err
	}
	env := map[string]string{}
	for _, entry := range doc.Env {
		maps.Copy(env, entry)
	}
	out := map[string]string{
		"schedule":         doc.Schedule,
		"state-dir":        doc.WorkingDir,
		"agent-config-dir": env["CLAUDE_CONFIG_DIR"],
		"txe-home":         env[txepkg.EnvHome],
	}
	for _, step := range doc.Steps {
		switch step.ID {
		case "agent":
			if model, ok := step.With["model"].(string); ok {
				out["agent-model"] = model
			}
		case "prepare", "execute":
			// The review command is the run's prefix before its subcommand.
			if i := strings.Index(step.Run, " "+step.ID+" --machine "); i > 0 {
				out["review-command"] = step.Run[:i]
			}
		}
	}
	return out, nil
}
