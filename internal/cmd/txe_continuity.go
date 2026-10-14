// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
)

// txeStableOwner is the installation's owner, initialized in phase one.
const txeStableOwner = "own_01M4GBBMJ7A2VKXJGAADCKV7RR"

var (
	txeContinuityScanFlag = commandLineFlag{
		name: "scan",
		usage: "A directory to inventory, as <area>=<label>=<path>[=<mount>]; area is hub-data, dags, logs, artifacts or machine-home; " +
			"mount is where the service that wrote it sees it, when that is not path; repeatable",
		isStringArray: true,
	}
	txeContinuityOwnerFlag = commandLineFlag{
		name:         "owner",
		defaultValue: txeStableOwner,
		usage:        "The installation's stable owner ID",
	}
	txeContinuityOutFlag = commandLineFlag{
		name:  "out",
		usage: "Write the inventory to this new file (an existing file is not replaced)",
	}
	txeContinuityLabelFlag = commandLineFlag{
		name:  "label",
		usage: "A name for this inventory, such as the freeze point",
	}
	txeContinuityAllowOwnerFlag = commandLineFlag{
		name:          "allow-owner",
		usage:         "Another owner that may hold records; repeatable. Without it, any owner but the expected one blocks",
		isStringArray: true,
	}
	txeContinuityProgressFlag = commandLineFlag{
		name:   "progress",
		usage:  "Report the changes made while the installation was in use, instead of the strict freeze comparison",
		isBool: true,
	}
	txeContinuityReconciledFlag = commandLineFlag{
		name:  "reconciled",
		usage: "A file listing, one per line, the records (<store>/<id>) and files (<root>/<path>) a recorded step changed or added",
	}
)

func init() {
	txeSubcommands = append(txeSubcommands, txeContinuityCommand)
}

func txeContinuityCommand() *cobra.Command {
	local := map[string]string{txeLocalAnnotation: "true"}
	command := NewCommand(&cobra.Command{
		Use:   "continuity",
		Short: "Inventory a retained TXE store and check that a transition kept it",
		Long: `Inventory a retained TXE installation, check it, and compare two inventories,
so that an upgrade or a storage move can show that nothing was lost, reassigned
or broken.

These commands only read. They never read the areas that hold credentials
(users, API keys, the encryption key, tailscale, license, a CLI's client
directory and the like); those are listed as excluded. Owners come only from
owner_id fields, never from a name, an email address or a sign-in.`,
		Annotations: local,
	}, nil, func(ctx *Context, _ []string) error {
		return ctx.Command.Help()
	})
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "inventory",
		Short: "Write an inventory of the given directories",
		Long: `Scan each --scan directory and write the sealed inventory to --out, or to
standard output. Validation runs on the result: a blocking issue is reported
and the command fails after the inventory is written.

Example, at the freeze point, with the hub's PVC mounted at /data:

  dagu txe continuity inventory --label freeze-1 \
    --scan hub-data=hub-data=/data/data --scan dags=hub-dags=/data/dags \
    --scan machine-home=laptop-home=$HOME/.local/share/txe-dagu \
    --out freeze-1.json`,
		Args:        cobra.NoArgs,
		Annotations: local,
	}, []commandLineFlag{txeContinuityScanFlag, txeContinuityOwnerFlag, txeContinuityOutFlag, txeContinuityLabelFlag,
		txeContinuityAllowOwnerFlag, txeJSONFlag}, runTXEContinuityInventory))
	command.AddCommand(NewCommand(&cobra.Command{
		Use:         "validate <inventory>",
		Short:       "Check one inventory: owners, references, history, packages and artifacts",
		Args:        cobra.ExactArgs(1),
		Annotations: local,
	}, []commandLineFlag{txeContinuityAllowOwnerFlag, txeJSONFlag}, runTXEContinuityValidate))
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "compare <before> <after>",
		Short: "Compare a later inventory with an earlier one",
		Long: `Compare two inventories. By default this is the transition gate: between the
freeze inventory and the one taken after the transition, nothing may be
missing, added or changed, except what --reconciled names; a missing record or
file is never excused. With --progress it reports what changed while the
installation was in use, blocking only definite losses.`,
		Args:        cobra.ExactArgs(2),
		Annotations: local,
	}, []commandLineFlag{txeContinuityProgressFlag, txeContinuityReconciledFlag, txeJSONFlag}, runTXEContinuityCompare))
	return command
}

// parseTXEContinuityScan reads one --scan value.
func parseTXEContinuityScan(v string) (continuity.Root, error) {
	parts := strings.SplitN(v, "=", 4)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return continuity.Root{}, fmt.Errorf("--scan %q: want <area>=<label>=<path>[=<mount>]", v)
	}
	r := continuity.Root{Area: parts[0], Label: parts[1], Path: parts[2]}
	if len(parts) == 4 {
		r.Mount = parts[3]
	}
	return r, nil
}

func runTXEContinuityInventory(ctx *Context, _ []string) error {
	flags := ctx.Command.Flags()
	scans, err := flags.GetStringArray("scan")
	if err != nil {
		return err
	}
	if len(scans) == 0 {
		return errors.New("name at least one directory with --scan")
	}
	var roots []continuity.Root
	for _, v := range scans {
		r, err := parseTXEContinuityScan(v)
		if err != nil {
			return err
		}
		roots = append(roots, r)
	}
	owner, _ := flags.GetString("owner")
	label, _ := flags.GetString("label")
	out, _ := flags.GetString("out")
	inv, err := continuity.Scan(ctx, continuity.Options{Roots: roots, ExpectedOwner: owner, Label: label, Tool: "dagu txe continuity"})
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if out == "" {
		if _, err := ctx.Command.OutOrStdout().Write(data); err != nil {
			return err
		}
	} else if err := writeNewFile(out, data); err != nil {
		return err
	}
	issues := continuity.Validate(inv, txeContinuityPolicy(ctx))
	if out == "" {
		// Standard output holds the inventory; the findings go to standard
		// error.
		p := &txePrinter{w: ctx.Command.ErrOrStderr()}
		printTXEContinuityIssues(p, issues)
		if p.err != nil {
			return p.err
		}
		return txeContinuityFail(issues)
	}
	if err := txeOutput(ctx, map[string]any{"digest": inv.Digest, "counts": inv.Counts, "excluded": inv.Excluded, "issues": issues, "out": out},
		func(p *txePrinter) {
			p.f("Inventory %s written to %s.\n", inv.Digest, out)
			p.f("%d records, %d files, %d excluded areas.\n", len(inv.Records), len(inv.Files), len(inv.Excluded))
			printTXEContinuityIssues(p, issues)
		}); err != nil {
		return err
	}
	return txeContinuityFail(issues)
}

func runTXEContinuityValidate(ctx *Context, args []string) error {
	inv, err := readTXEContinuityInventory(args[0])
	if err != nil {
		return err
	}
	issues := continuity.Validate(inv, txeContinuityPolicy(ctx))
	if err := txeOutput(ctx, map[string]any{"digest": inv.Digest, "issues": issues}, func(p *txePrinter) {
		p.f("Inventory %s (%s, scanned %s).\n", inv.Digest, inv.Label, inv.ScannedAt.Format("2006-01-02T15:04:05Z07:00"))
		printTXEContinuityIssues(p, issues)
	}); err != nil {
		return err
	}
	return txeContinuityFail(issues)
}

func runTXEContinuityCompare(ctx *Context, args []string) error {
	before, err := readTXEContinuityInventory(args[0])
	if err != nil {
		return err
	}
	after, err := readTXEContinuityInventory(args[1])
	if err != nil {
		return err
	}
	flags := ctx.Command.Flags()
	progress, _ := flags.GetBool("progress")
	reconciledFile, _ := flags.GetString("reconciled")
	var rep *continuity.Report
	if progress {
		if reconciledFile != "" {
			return errors.New("--reconciled applies to the freeze comparison, not to --progress")
		}
		rep = continuity.CompareProgress(before, after)
	} else {
		reconciled, err := readTXEContinuityReconciled(reconciledFile)
		if err != nil {
			return err
		}
		rep = continuity.Compare(before, after, continuity.CompareOptions{Reconciled: reconciled})
	}
	if err := txeOutput(ctx, rep, func(p *txePrinter) {
		kind := "Freeze comparison"
		if progress {
			kind = "Progress report"
		}
		p.f("%s of %s and %s.\n", kind, rep.Before, rep.After)
		p.f("%d added, %d changed.\n", len(rep.Added), len(rep.Changed))
		for _, k := range rep.Added {
			p.f("added   %s\n", k)
		}
		for _, k := range rep.Changed {
			p.f("changed %s\n", k)
		}
		printTXEContinuityIssues(p, rep.Issues)
	}); err != nil {
		return err
	}
	return txeContinuityFail(rep.Issues)
}

func txeContinuityPolicy(ctx *Context) continuity.Policy {
	allowed, _ := ctx.Command.Flags().GetStringArray("allow-owner")
	return continuity.Policy{AllowedOwners: allowed}
}

func readTXEContinuityInventory(path string) (*continuity.Inventory, error) {
	data, err := os.ReadFile(path) //nolint:gosec // an inventory the operator names
	if err != nil {
		return nil, err
	}
	return continuity.Decode(data)
}

// readTXEContinuityReconciled reads the keys a recorded step changed, one
// per line; blank lines and lines starting with # are ignored.
func readTXEContinuityReconciled(path string) (map[string]bool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // a list the operator names
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out[line] = true
		}
	}
	return out, sc.Err()
}

// writeNewFile writes data to a file that must not exist yet.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // the operator's output path
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func printTXEContinuityIssues(p *txePrinter, issues []continuity.Issue) {
	blocking := continuity.Blocking(issues)
	p.f("%d blocking, %d other issues.\n", len(blocking), len(issues)-len(blocking))
	for _, i := range issues {
		p.f("%-5s %s %s: %s\n", i.Severity, i.Code, i.ID, i.Detail)
	}
}

func txeContinuityFail(issues []continuity.Issue) error {
	if n := len(continuity.Blocking(issues)); n > 0 {
		return fmt.Errorf("%d blocking issue(s); see above", n)
	}
	return nil
}
