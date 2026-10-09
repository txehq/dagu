// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

var (
	txeJobKeyFlag    = commandLineFlag{name: "job-key", usage: "Only the job with this key"}
	txeProjectFlag   = commandLineFlag{name: "project", usage: "Only jobs of this project id"}
	txeLifecycleFlag = commandLineFlag{name: "lifecycle", usage: "Only jobs in this lifecycle state: active, paused, needs_human, completed or retired"}
	txeMachineFlag   = commandLineFlag{name: "machine", usage: "Only jobs assigned to this machine id"}
	txeTargetFlag    = commandLineFlag{name: "target", usage: "Only jobs with a target whose kind, name or stable id contains this text"}
	txeRunsFlag      = commandLineFlag{name: "runs", defaultValue: "5", usage: "How many recent runs to show"}
)

func txeListCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:     "list",
		Aliases: []string{"discover"},
		Short:   "List registered jobs; use before registering to find an equivalent one",
		Long: `List the jobs in the registry, whichever session created them.

Before registering, look for a job that already does the work: by --job-key if
you know the name it would have, or by --target with part of the resource's
identity. Inspect a match and update it instead of registering a second job.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeJobKeyFlag, txeProjectFlag, txeLifecycleFlag, txeMachineFlag, txeTargetFlag, txeJSONFlag}, runTXEList)
}

// txeJobRow is one job with the parts of its current version a reader needs
// to tell whether it is the job they are looking for.
type txeJobRow struct {
	txeclient.Job
	Title   string             `json:"title"`
	Purpose string             `json:"purpose"`
	Targets []txeclient.Target `json:"targets,omitempty"`
}

func runTXEList(ctx *Context, _ []string) error {
	client, err := txeClient(ctx)
	if err != nil {
		return err
	}
	filter := txeclient.JobFilter{}
	for name, field := range map[string]*string{
		"job-key": &filter.JobKey, "project": &filter.ProjectID, "lifecycle": &filter.Lifecycle, "machine": &filter.MachineID,
	} {
		if *field, err = ctx.StringParam(name); err != nil {
			return err
		}
	}
	target, err := ctx.StringParam("target")
	if err != nil {
		return err
	}
	jobs, err := client.ListJobs(ctx, filter)
	if err != nil {
		return err
	}

	rows := make([]txeJobRow, 0, len(jobs))
	for _, job := range jobs {
		version, err := client.JobVersion(ctx, job.JobID, job.Version)
		if err != nil {
			return fmt.Errorf("read version %d of %s: %w", job.Version, job.JobID, err)
		}
		if target != "" && !txeTargetMatches(version.Targets, target) {
			continue
		}
		rows = append(rows, txeJobRow{Job: job, Title: version.Title, Purpose: version.Purpose, Targets: version.Targets})
	}

	return txeOutput(ctx, map[string]any{"jobs": rows}, func(p *txePrinter) {
		if len(rows) == 0 {
			p.f("%s\n", "No jobs match.")
			return
		}
		tw := tabwriter.NewWriter(p.w, 0, 4, 2, ' ', 0)
		table := &txePrinter{w: tw}
		table.f("JOB\tKEY\tVERSION\tLIFECYCLE\tREGISTRATION\tCREATED BY\tTITLE\n")
		for _, r := range rows {
			table.f("%s\t%s\t%d\t%s\t%s\t%s\t%s\n", r.JobID, r.Registration.JobKey, r.Version,
				r.Lifecycle, r.Registration.State, r.Created.By.Session, r.Title)
		}
		if table.err == nil {
			table.err = tw.Flush()
		}
		if p.err == nil {
			p.err = table.err
		}
	})
}

func txeTargetMatches(targets []txeclient.Target, text string) bool {
	text = strings.ToLower(text)
	return slices.ContainsFunc(targets, func(t txeclient.Target) bool {
		fields := []string{t.Kind, t.DisplayName, t.Environment}
		for key, value := range t.StableID {
			fields = append(fields, key+"="+value, value)
		}
		return slices.ContainsFunc(fields, func(f string) bool { return strings.Contains(strings.ToLower(f), text) })
	})
}

func txeInspectCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "inspect <job id>",
		Short: "Show a job's context, state, recent runs and local package",
		Long: `Show everything needed to understand a job without the conversation that
created it: purpose, targets, schedule, expected outcome, lifetime and review
policy; lifecycle, availability and anything waiting on a person; recent runs;
and whether this machine holds the package and receipt.`,
		Args: cobra.ExactArgs(1),
	}, []commandLineFlag{txeRunsFlag, txeJSONFlag}, runTXEInspect)
}

type txeRun struct {
	RunID      string `json:"run_id"`
	Status     string `json:"status"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

type txeLocalState struct {
	// Held is whether this machine has the job's package and it verifies.
	Held        bool   `json:"held"`
	PackageDir  string `json:"package_dir,omitempty"`
	Problem     string `json:"problem,omitempty"`
	ReceiptHeld bool   `json:"receipt_held"`
}

func runTXEInspect(ctx *Context, args []string) error {
	client, err := txeClient(ctx)
	if err != nil {
		return err
	}
	job, err := client.Job(ctx, args[0])
	if err != nil {
		return err
	}
	version, err := client.JobVersion(ctx, job.JobID, job.Version)
	if err != nil {
		return err
	}

	// Runs are Dagu's own records of the DAG named after the job.
	var runs []txeRun
	remote, err := txeRemote(ctx)
	if err != nil {
		return err
	}
	summaries, err := remote.listDAGRuns(ctx, remoteHistoryQuery{Name: job.JobID})
	if err != nil {
		if remoteErr, ok := errors.AsType[*remoteError](err); !ok || !remoteErr.NotFound() {
			return fmt.Errorf("list runs of %s: %w", job.JobID, err)
		}
	}
	limit := 5
	if raw, err := ctx.StringParam("runs"); err == nil {
		if _, scanErr := fmt.Sscanf(raw, "%d", &limit); scanErr != nil || limit < 0 {
			return fmt.Errorf("--runs must be a number, got %q", raw)
		}
	}
	for i, s := range summaries {
		if i >= limit {
			break
		}
		runs = append(runs, txeRun{RunID: s.DagRunId, Status: string(s.StatusLabel), StartedAt: s.StartedAt, FinishedAt: s.FinishedAt})
	}

	local := txeLocalPackage(job)
	return txeOutput(ctx, map[string]any{"job": job.Raw, "version": version, "runs": runs, "local": local}, func(p *txePrinter) {
		p.f("%s  %s\n\n", job.JobID, version.Title)
		p.f("Purpose:       %s\n", version.Purpose)
		p.f("Job key:       %s\nVersion:       %d (revision %d)\n", job.Registration.JobKey, job.Version, job.Revision)
		p.f("Owner:         %s\nProject:       %s\nMachine:       %s\n", job.OwnerID, job.ProjectID, job.MachineID)
		p.f("Created by:    %s on %s\nLast changed:  %s on %s\n",
			job.Created.By.Session, job.Created.At.Format("2006-01-02 15:04Z07:00"), job.Updated.By.Session, job.Updated.At.Format("2006-01-02 15:04Z07:00"))
		p.f("\nLifecycle:     %s", job.Lifecycle)
		if job.LifecycleReason != "" {
			p.f(" (%s)", job.LifecycleReason)
		}
		p.f("\nRegistration:  %s\nAvailability:  %s", job.Registration.State, job.Availability.State)
		if job.Availability.Detail != "" {
			p.f(" (%s)", job.Availability.Detail)
		}
		p.f("\n")
		if job.Retirement != nil {
			p.f("Retired:       %s at %s\n", job.Retirement.Reason, job.Retirement.At.Format("2006-01-02 15:04Z07:00"))
		}
		if job.ExpiresAt != nil {
			p.f("Expires:       %s\n", job.ExpiresAt.Format("2006-01-02 15:04Z07:00"))
		}
		p.f("Waiting on a person: %d proposal(s), %d exception(s)\n", len(job.Proposals), len(job.Exceptions))

		p.f("\nSchedule:      %s (%s), timeout %ds, missed runs: %s\n",
			version.Schedule.Cron, version.Schedule.Timezone, version.Schedule.TimeoutSec, version.Schedule.MissedRun)
		for _, t := range version.Targets {
			p.f("Target:        %s %s %v\n", t.Kind, t.DisplayName, t.StableID)
		}
		for _, c := range version.ExpectedOutcome.SuccessCriteria {
			p.f("Success means: %s\n", c)
		}
		p.f("Review:        %s; %s\n", version.ReviewPolicy.Cadence, version.ReviewPolicy.Brief)

		p.f("\nPackage:       %s\n", job.PackageDigest)
		switch {
		case local.Held:
			p.f("On this machine: %s (verified)\n", local.PackageDir)
		default:
			p.f("On this machine: not usable: %s\n", local.Problem)
		}

		p.f("\nRecent runs:\n")
		if len(runs) == 0 {
			p.f("%s\n", "  none yet")
		}
		for _, r := range runs {
			p.f("  %s  %-10s started %s  finished %s\n", r.RunID, r.Status, r.StartedAt, r.FinishedAt)
		}
	})
}

// txeLocalPackage checks whether this machine holds the job's current package
// and its receipt. It reads only; a job that runs on another machine is
// reported as not held here, which is expected.
func txeLocalPackage(job *txeclient.Job) txeLocalState {
	home, err := txepkg.DefaultHome()
	if err != nil {
		return txeLocalState{Problem: err.Error()}
	}
	state := txeLocalState{}
	if _, err := txepkg.NewJournal(home).Receipt(job.JobID, job.Version); err == nil {
		state.ReceiptHeld = true
	}
	pkg, err := txepkg.NewStore(home).Verify(job.JobID, job.PackageDigest)
	if err != nil {
		state.Problem = err.Error()
		return state
	}
	state.Held, state.PackageDir = true, pkg.Dir
	return state
}
