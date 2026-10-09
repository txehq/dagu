// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

func txeDoctorCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use: "doctor",
		// Doctor has to run, and say so, when the hub's context is missing.
		Annotations: map[string]string{txeLocalAnnotation: "true"},
		Short:       "Check that this machine can register and run jobs",
		Long: `Check each thing registration depends on and say what is wrong with it:
the TXE home, this machine's identity, the hub and its registry, that the hub
knows this machine, and registrations left unfinished.

Run it before registering from a new session, and when a registration fails.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeSessionFlag, txeJSONFlag}, runTXEDoctor)
}

type txeCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	// Action says what to do when the check fails.
	Action string `json:"action,omitempty"`
}

type txeUnfinished struct {
	RequestID string      `json:"request_id"`
	Operation string      `json:"operation"`
	JobID     string      `json:"job_id"`
	JobKey    string      `json:"job_key"`
	Step      txepkg.Step `json:"step"`
	Session   string      `json:"session"`
	Error     string      `json:"error,omitempty"`
}

func runTXEDoctor(ctx *Context, _ []string) error {
	var checks []txeCheck
	add := func(name string, err error, detail, action string) bool {
		check := txeCheck{Name: name, OK: err == nil, Detail: detail}
		if err != nil {
			check.Detail, check.Action = err.Error(), action
		}
		checks = append(checks, check)
		return err == nil
	}

	add("cli", nil, "dagu "+config.Version, "")
	session := txeSession(ctx)
	if session == "" {
		add("session", fmt.Errorf("no session identity could be derived"), "", "pass --session or set TXE_SESSION when registering")
	} else {
		add("session", nil, session, "")
	}

	home, err := txepkg.DefaultHome()
	if !add("home", err, home.Root, "set "+txepkg.EnvHome+" to an absolute path") {
		return txeDoctorReport(ctx, checks, nil)
	}
	add("home is durable", txepkg.DefaultPathPolicy().CheckDurable(home.PackagesDir()), home.PackagesDir(),
		"move the TXE home out of the worktree or temporary directory; packages there would be lost with it")

	machine, err := home.Machine()
	if add("machine identity", err, "", "run the worker installer on this machine") {
		checks[len(checks)-1].Detail = fmt.Sprintf("%s, owner %s", machine.MachineID, machine.OwnerID)
	}

	var unfinished []txeUnfinished
	entries, err := txepkg.NewJournal(home).Pending()
	if add("registration journal", err, fmt.Sprintf("%d unfinished", len(entries)), "check the permissions of "+home.ReceiptsDir()) {
		for _, e := range entries {
			unfinished = append(unfinished, txeUnfinished{e.RequestID, e.Operation, e.JobID, e.JobKey, e.Step, e.Session, e.Error})
		}
	}
	if orphans, _ := filepath.Glob(filepath.Join(home.PackagesDir(), ".staging", "*")); len(orphans) > len(entries) {
		add("staged packages", fmt.Errorf("%d staged package(s) but %d journal entr(ies)", len(orphans), len(entries)), "",
			"a build was interrupted before it was recorded; the directories under "+filepath.Join(home.PackagesDir(), ".staging")+" without a journal entry are unreferenced")
	}

	client, err := txeClient(ctx)
	if !add("hub context", err, txeContextName, "create the context with the worker installer, or pass --context") {
		return txeDoctorReport(ctx, checks, unfinished)
	}
	health, err := client.Health(ctx)
	if !add("hub", err, "", "check that the tunnel to the hub is running") {
		return txeDoctorReport(ctx, checks, unfinished)
	}
	checks[len(checks)-1].Detail = fmt.Sprintf("%s, build %s", health.Status, health.Version)

	installation, err := client.Installation(ctx)
	if add("registry", err, "", "the hub's build has no TXE registry, or the API key was refused") {
		checks[len(checks)-1].Detail = fmt.Sprintf("schema %d, %d owner(s)", installation.Schema, len(installation.Owners))
	}
	if machine != nil {
		known, err := client.Machine(ctx, machine.MachineID)
		switch {
		case err != nil:
			add("machine on hub", err, "", "enrol this machine with the worker installer")
		case known.OwnerID != machine.OwnerID:
			add("machine on hub", fmt.Errorf("the hub records owner %s, this machine says %s", known.OwnerID, machine.OwnerID), "",
				"the identity file and the hub disagree; do not register until this is resolved")
		default:
			add("machine on hub", nil, known.DisplayName, "")
		}
	}
	return txeDoctorReport(ctx, checks, unfinished)
}

func txeDoctorReport(ctx *Context, checks []txeCheck, unfinished []txeUnfinished) error {
	failed := 0
	for _, c := range checks {
		if !c.OK {
			failed++
		}
	}
	err := txeOutput(ctx, map[string]any{"ok": failed == 0, "checks": checks, "unfinished": unfinished}, func(p *txePrinter) {
		for _, c := range checks {
			mark := "ok  "
			if !c.OK {
				mark = "FAIL"
			}
			p.f("%s  %-22s %s\n", mark, c.Name, c.Detail)
			if c.Action != "" {
				p.f("      -> %s\n", c.Action)
			}
		}
		for _, u := range unfinished {
			p.f("\nUnfinished %s %s (%s, job key %q) at step %q, started by %s\n", u.Operation, u.RequestID, u.JobID, u.JobKey, u.Step, u.Session)
			if u.Step == txepkg.StepRejected {
				p.f("      refused by the hub: %s\n      kept as a record; nothing to resume\n", u.Error)
			} else {
				p.f("      -> dagu txe resume %s\n", u.RequestID)
			}
		}
	})
	if err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	return nil
}

func txePackageCommand() *cobra.Command {
	command := NewCommand(&cobra.Command{
		Use:   "package",
		Short: "Inspect the packages this machine holds",
	}, nil, func(ctx *Context, _ []string) error {
		return ctx.Command.Help()
	})
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "verify <job id>",
		Short: "Check that a job's package is intact and independent of any worktree",
		Long: `Check a job's package on this machine before the worktree it came from is
removed: that the package exists outside any worktree or temporary directory,
that every file still matches the digest the hub holds, and that a receipt was
issued for it.

A pass means the job no longer depends on the source directory. It does not
mean the directory holds nothing else worth keeping.`,
		Args: cobra.ExactArgs(1),
	}, []commandLineFlag{txeJSONFlag}, runTXEPackageVerify))
	return command
}

func runTXEPackageVerify(ctx *Context, args []string) error {
	client, err := txeClient(ctx)
	if err != nil {
		return err
	}
	job, err := client.Job(ctx, args[0])
	if err != nil {
		return err
	}
	home, err := txepkg.DefaultHome()
	if err != nil {
		return err
	}
	pkg, err := txepkg.NewStore(home).Verify(job.JobID, job.PackageDigest)
	if err != nil {
		return fmt.Errorf("the package of %s version %d is not usable on this machine: %w", job.JobID, job.Version, err)
	}
	receipt, err := txepkg.NewJournal(home).Receipt(job.JobID, job.Version)
	if err != nil {
		return fmt.Errorf("the package is intact, but this machine has no receipt for %s version %d: %w", job.JobID, job.Version, err)
	}
	if job.Registration.State != txeclient.RegistrationReady {
		return fmt.Errorf("the package is intact, but the hub has not marked %s ready (registration is %s)", job.JobID, job.Registration.State)
	}
	sourceGone := false
	if _, statErr := os.Stat(pkg.Manifest.Provenance.SourceRoot); os.IsNotExist(statErr) {
		sourceGone = true
	}
	return txeOutput(ctx, map[string]any{
		"ok": true, "job_id": job.JobID, "version": job.Version, "package_digest": pkg.Digest, "package_dir": pkg.Dir,
		"files": len(pkg.Manifest.Files), "source_root": pkg.Manifest.Provenance.SourceRoot, "source_root_exists": !sourceGone,
		"uncommitted_at_packaging": pkg.Manifest.Provenance.Uncommitted, "receipt_request": receipt.RequestID,
	}, func(p *txePrinter) {
		p.f("%s version %d: the package is intact and the hub has marked the job ready.\n\n", job.JobID, job.Version)
		p.f("Package:  %s\n          %s (%d file(s), read-only)\n", pkg.Digest, pkg.Dir, len(pkg.Manifest.Files))
		p.f("Built from: %s", pkg.Manifest.Provenance.SourceRoot)
		if sourceGone {
			p.f(" (no longer exists)")
		}
		p.f("\n")
		if n := len(pkg.Manifest.Provenance.Uncommitted); n > 0 {
			p.f("%d packaged file(s) were not in the commit when packaged: %v\n", n, pkg.Manifest.Provenance.Uncommitted)
		}
		p.f("\nThe job does not depend on the source directory.\n")
	})
}
