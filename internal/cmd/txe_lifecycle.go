// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

var (
	txeLifecycleDetailFlag = commandLineFlag{
		name:     "detail",
		usage:    "Why, for someone who never saw this conversation (required)",
		required: true,
	}
	txeLifecycleEvidenceFlag = commandLineFlag{
		name:          "evidence",
		usage:         "A run id, artifact, ticket or link that shows it; repeatable",
		isStringArray: true,
	}
	txeLifecycleActiveRunsFlag = commandLineFlag{
		name:  "active-runs",
		usage: "A run already going: finish or cancel (default: the job's retirement rule)",
	}
	txeRetireReasonFlag = commandLineFlag{
		name:         "reason",
		defaultValue: "manual",
		usage:        "Why the job stops: manual, replaced, or target_deleted (only for a confirmed deletion)",
	}
)

func init() {
	txeSubcommands = append(txeSubcommands, txeCompleteCommand, txeRetireCommand)
}

func txeCompleteCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "complete <job id>",
		Short: "Mark a job's purpose as fulfilled, so it runs no more",
		Long: `Record that a job's purpose is fulfilled. The job runs no more: no new run is
scheduled and a queued run does not start. A run already going finishes or is
cancelled as --active-runs or the job's retirement rule says. Open proposals
are closed. The job's runs, artifacts, decisions and versions are all kept.

The hub decides whether you may: it takes the change from a person or session
that may write the owner's jobs. Only a person can reactivate a completed job.`,
		Args: cobra.ExactArgs(1),
	}, []commandLineFlag{txeLifecycleDetailFlag, txeLifecycleEvidenceFlag, txeLifecycleActiveRunsFlag, txeSessionFlag, txeJSONFlag},
		func(ctx *Context, args []string) error {
			return runTXELifecycle(ctx, args[0], txeclient.LifecycleComplete, "")
		})
}

func txeRetireCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "retire <job id>",
		Short: "Stop a job that is no longer wanted, keeping its history",
		Long: `Stop a job whose purpose has not been fulfilled but which is no longer
wanted: it was replaced, its target was deleted, or it is simply no longer
needed (manual). Use "dagu txe complete" for a job whose purpose is met. An
expired job is retired by the registry itself.

The job runs no more: no new run is scheduled and a queued run does not start.
A run already going finishes or is cancelled as --active-runs or the job's
retirement rule says. Open proposals are closed. The job's runs, artifacts,
decisions and versions are all kept.

Record target_deleted only when the deletion is confirmed. An unreachable
target, a refused credential or an expired login is not a deletion.

The hub decides whether you may: it takes the change from a person or session
that may write the owner's jobs. Only a person can reactivate a retired job.`,
		Args: cobra.ExactArgs(1),
	}, []commandLineFlag{txeRetireReasonFlag, txeLifecycleDetailFlag, txeLifecycleEvidenceFlag, txeLifecycleActiveRunsFlag, txeSessionFlag, txeJSONFlag},
		func(ctx *Context, args []string) error {
			reason, err := ctx.StringParam("reason")
			if err != nil {
				return err
			}
			switch reason {
			case "manual", "replaced", "target_deleted":
			case "completed":
				return errors.New(`--reason completed: use "dagu txe complete" for a job whose purpose is met`)
			case "expired":
				return errors.New("--reason expired: the registry retires a job itself when its lifetime ends")
			default:
				return fmt.Errorf("--reason %q: use manual, replaced or target_deleted", reason)
			}
			return runTXELifecycle(ctx, args[0], txeclient.LifecycleRetire, reason)
		})
}

func runTXELifecycle(ctx *Context, jobID, op, reason string) error {
	detail, err := ctx.StringParam("detail")
	if err != nil {
		return err
	}
	if detail = strings.TrimSpace(detail); detail == "" {
		return errors.New("--detail is required: say why, for someone who never saw this conversation")
	}
	evidence, err := ctx.Command.Flags().GetStringArray(txeLifecycleEvidenceFlag.name)
	if err != nil {
		return err
	}
	policy, err := ctx.StringParam("active-runs")
	if err != nil {
		return err
	}
	if policy != "" && policy != "finish" && policy != "cancel" {
		return fmt.Errorf("--active-runs %q: use finish or cancel", policy)
	}
	session := txeSession(ctx)
	if session == "" {
		return errors.New("cannot tell which session is making this change: it is not a Claude Code session with its own identity (a Codex thread started from one inherits the parent's); pass --session or set TXE_SESSION")
	}
	actor := txeclient.Actor{Kind: txeclient.ActorKindCLI, ID: "cli", Session: session, Client: txeClientVersion()}
	// A developer's computer may have no machine identity; the change is
	// still recorded with the session that made it.
	if home, err := txepkg.DefaultHome(); err == nil {
		if machine, err := home.Machine(); err == nil {
			actor.MachineID = machine.MachineID
		}
	}
	client, err := txeClient(ctx)
	if err != nil {
		return err
	}
	job, err := client.ChangeLifecycle(ctx, jobID, txeclient.LifecycleRequest{
		Op: op, Reason: reason, Detail: detail, Evidence: evidence, ActiveRunPolicy: policy, Actor: actor,
	})
	if err != nil {
		return err
	}
	return txeOutput(ctx, map[string]any{"job": job.Raw}, func(p *txePrinter) {
		p.f("%s is %s.\n", job.JobID, job.Lifecycle)
		if r := job.Retirement; r != nil {
			p.f("Reason:       %s\n", r.Reason)
			p.f("Detail:       %s\n", r.Detail)
			for _, e := range r.Evidence {
				p.f("Evidence:     %s\n", e)
			}
			p.f("By:           %s on %s\n", txeActorName(r.Actor), r.At.UTC().Format("2006-01-02 15:04Z"))
			if r.ActiveRunPolicy != "" {
				p.f("A run going:  %s\n", r.ActiveRunPolicy)
			}
		}
		p.f("\nNo new or queued run will start. Its runs, artifacts and decisions are kept; \"dagu txe inspect %s\" shows them.\n", job.JobID)
	})
}
