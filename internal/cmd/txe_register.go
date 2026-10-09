// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
)

var (
	txeDryRunFlag = commandLineFlag{
		name:   "dry-run",
		usage:  "Validate the spec, build the package and show the DAG without registering anything",
		isBool: true,
	}
	txeExpectedVersionFlag = commandLineFlag{
		name:     "expected-version",
		usage:    "The job version this update changes; the update is refused if the job has moved on",
		required: true,
	}
)

func txeRegisterCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "register -f <job spec>",
		Short: "Register a new durable job from a job spec",
		Long: `Register a new durable job.

The files named in the spec are copied, uncommitted ones included, into a
read-only package under the TXE home, outside any worktree. The hub saves the
job's context and schedule; this machine's worker runs it from the package.

A receipt is printed only when the hub has marked the job ready. A refusal or
an interruption prints none: a refusal names the reason, an interruption names
the request id to resume.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeSpecFlag, txeDryRunFlag, txeSessionFlag, txeJSONFlag}, runTXERegister)
}

func runTXERegister(ctx *Context, _ []string) error {
	path, err := ctx.StringParam("file")
	if err != nil {
		return err
	}
	spec, err := txeclient.LoadJobSpec(path)
	if err != nil {
		return txeReportFailure(ctx, err)
	}
	registrar, err := txeRegistrar(ctx)
	if err != nil {
		return txeReportFailure(ctx, err)
	}
	dryRun, err := ctx.Command.Flags().GetBool("dry-run")
	if err != nil {
		return err
	}
	if dryRun {
		plan, err := registrar.Plan(ctx, spec)
		if err != nil {
			return txeReportFailure(ctx, err)
		}
		return txeOutput(ctx, map[string]any{
			"ok": true, "dry_run": true, "machine_id": plan.Machine.MachineID, "owner_id": plan.Machine.OwnerID,
			"project_id": plan.Project.ProjectID, "package_digest": plan.Digest, "files": plan.Manifest.Files,
			"uncommitted": plan.Manifest.Provenance.Uncommitted, "dag": plan.DAGSpec,
		}, func(p *txePrinter) {
			p.f("The spec is complete. Nothing was registered.\n\n")
			p.f("Owner:    %s\nMachine:  %s\nProject:  %s (%s)\nPackage:  %s, %d file(s)\n",
				plan.Machine.OwnerID, plan.Machine.MachineID, plan.Project.Name, plan.Project.ProjectID, plan.Digest, len(plan.Manifest.Files))
			for _, f := range plan.Manifest.Files {
				p.f("  %s\n", f.Path)
			}
			if n := len(plan.Manifest.Provenance.Uncommitted); n > 0 {
				p.f("%d packaged file(s) are not in the commit: %v\n", n, plan.Manifest.Provenance.Uncommitted)
			}
			p.f("\nDAG:\n")
			p.block(plan.DAGSpec)
		})
	}

	outcome, err := registrar.Register(ctx, spec)
	if err != nil {
		return txeReportFailure(ctx, err)
	}
	return txePrintOutcome(ctx, "Registered", outcome)
}

func txeUpdateCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "update <job id> -f <job spec> --expected-version <n>",
		Short: "Record a new version of a job",
		Long: `Record a new version of a job from a changed spec or changed files.

The update names the version it was made against. If another session has
updated the job since, it is refused and nothing changes: inspect the job,
merge the difference into the spec and try again against the new version.

Earlier versions' packages and receipts are kept.`,
		Args: cobra.ExactArgs(1),
	}, []commandLineFlag{txeSpecFlag, txeExpectedVersionFlag, txeSessionFlag, txeJSONFlag}, runTXEUpdate)
}

func runTXEUpdate(ctx *Context, args []string) error {
	path, err := ctx.StringParam("file")
	if err != nil {
		return err
	}
	raw, err := ctx.StringParam("expected-version")
	if err != nil {
		return err
	}
	expected, err := strconv.Atoi(raw)
	if err != nil || expected < 1 {
		return fmt.Errorf("--expected-version must be a positive number, got %q", raw)
	}
	spec, err := txeclient.LoadJobSpec(path)
	if err != nil {
		return txeReportFailure(ctx, err)
	}
	registrar, err := txeRegistrar(ctx)
	if err != nil {
		return txeReportFailure(ctx, err)
	}
	outcome, err := registrar.Update(ctx, args[0], expected, spec)
	if err != nil {
		return txeReportFailure(ctx, err)
	}
	return txePrintOutcome(ctx, "Updated", outcome)
}

func txeResumeCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "resume <request id>",
		Short: "Finish a registration or update that was interrupted",
		Long: `Finish a registration or update that stopped before its receipt.

The saved request is sent again exactly as it was, which the hub recognises,
so resuming never creates a second job. Any session on this machine can resume
a request; "dagu txe doctor" lists the unfinished ones.`,
		Args: cobra.ExactArgs(1),
	}, []commandLineFlag{txeSessionFlag, txeJSONFlag}, func(ctx *Context, args []string) error {
		registrar, err := txeRegistrar(ctx)
		if err != nil {
			return txeReportFailure(ctx, err)
		}
		outcome, err := registrar.Resume(ctx, args[0])
		if err != nil {
			return txeReportFailure(ctx, err)
		}
		return txePrintOutcome(ctx, "Completed", outcome)
	})
}

func txePrintOutcome(ctx *Context, verb string, outcome *txeclient.Outcome) error {
	r := outcome.Receipt
	return txeOutput(ctx, map[string]any{"ok": true, "receipt": r}, func(p *txePrinter) {
		p.f("%s %s version %d. The hub has marked it ready.\n\n", verb, r.JobID, r.Version)
		p.f("Owner:    %s\nProject:  %s\nMachine:  %s\nPackage:  %s\n          %s\nReceipt:  request %s, written %s\n",
			r.OwnerID, r.ProjectID, r.MachineID, r.PackageDigest, r.PackageDir, r.RequestID, r.WrittenAt.Format("2006-01-02 15:04:05Z07:00"))
		p.f("\nThe package no longer depends on the directory it was built from.\n")
	})
}
