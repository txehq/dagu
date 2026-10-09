// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

var (
	txeArtifactJobFlag     = commandLineFlag{name: "job", usage: "Job id (default: TXE_JOB_ID)"}
	txeArtifactVersionFlag = commandLineFlag{name: "job-version", usage: "Job version the run executed (default: TXE_JOB_VERSION)"}
	txeArtifactRunFlag     = commandLineFlag{name: "run", usage: "Dagu run id (default: DAG_RUN_ID)"}
	txeArtifactDirFlag     = commandLineFlag{name: "artifact-dir", usage: "The run's native artifact directory (default: DAG_RUN_ARTIFACTS_DIR)"}
	txeArtifactAttemptFlag = commandLineFlag{name: "attempt", usage: "Dagu attempt that is executing (default: TXE_ATTEMPT_ID)"}
	txeArtifactQueuedFlag  = commandLineFlag{name: "queued-at", usage: "Queue marker the attempt was dispatched with; empty when the run was never queued (default: TXE_QUEUED_AT)"}
)

func init() {
	txeSubcommands = append(txeSubcommands, txeArtifactsCommand)
}

func txeArtifactsCommand() *cobra.Command {
	command := NewCommand(&cobra.Command{
		Use:   "artifacts",
		Short: "Record the files a job run produced",
	}, nil, func(ctx *Context, _ []string) error {
		return ctx.Command.Help()
	})
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "publish",
		Short: "Record a run's declared deliverables; the last step of a job's DAG",
		Long: `Record what a run produced. This is the last step of every job that
declares deliverables, and it takes the run's identity from the step's
environment.

Only files the job declares are read, by exact name, from the output directory
of the execution that sealed them. Each is recorded with its SHA-256 and where its bytes are. A file
declared for the hub is also copied into the run's artifact directory, under
this execution's own directory, which the worker uploads when it ends. Every file stays on this machine too.

A file is published as it is. Step output is masked for declared secrets; a
file a script writes is not, so a script must not write a credential into a
deliverable.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeArtifactJobFlag, txeArtifactVersionFlag, txeArtifactRunFlag, txeArtifactAttemptFlag, txeArtifactQueuedFlag, txeArtifactDirFlag, txeJSONFlag}, runTXEArtifactsPublish))
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "begin",
		Short: "Prepare the executing attempt's output directory; runs before a job's command",
		Long: `Give the execution of the job that is about to start an empty output
directory.

A retry of a run keeps the run id, and a retry through a queue keeps the
attempt id too: one execution is named by the attempt and its queue marker.
The job writes to the attempt's directory. What an earlier execution left
there is moved aside and kept; nothing is written over.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeArtifactJobFlag, txeArtifactRunFlag, txeArtifactAttemptFlag, txeArtifactQueuedFlag, txeJSONFlag}, runTXEArtifactsBegin))
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "seal",
		Short: "Mark the executing attempt's outputs as the run's result; runs after a job's command",
		Long: `Record that the job's command succeeded in this execution. Its output
directory is moved under the execution's reference, the digest of every file
in it is recorded, and it becomes the run's result. The publish step reads
sealed files only, and refuses one that no longer has the recorded digest.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeArtifactJobFlag, txeArtifactRunFlag, txeArtifactAttemptFlag, txeArtifactQueuedFlag, txeJSONFlag}, runTXEArtifactsSeal))
	return command
}

// txeExecution is one execution of one run of one job.
type txeExecution struct {
	jobID, runID string
	execution    txeclient.Execution
}

// txeQueuedAt reads the queue marker of the executing attempt. An empty
// marker is a value: the run was never queued. A variable that is not set at
// all is not, and means the job's DAG does not provide one.
func txeQueuedAt(ctx *Context) (string, error) {
	if ctx.Command.Flags().Changed(txeArtifactQueuedFlag.name) {
		return ctx.StringParam(txeArtifactQueuedFlag.name)
	}
	value, set := os.LookupEnv(txepkg.QueuedAtEnv)
	if !set {
		return "", fmt.Errorf("--%s is not given and %s is not set: this job's DAG was rendered by an older dagu; update the job to render it again",
			txeArtifactQueuedFlag.name, txepkg.QueuedAtEnv)
	}
	return value, nil
}

// txeExecuting reads which execution of which run of which job is running.
func txeExecuting(ctx *Context) (txeExecution, error) {
	var e txeExecution
	for _, field := range []struct {
		target    *string
		flag, env string
	}{
		{&e.jobID, "job", "TXE_JOB_ID"},
		{&e.runID, "run", "DAG_RUN_ID"},
		{&e.execution.AttemptID, "attempt", txepkg.AttemptEnv},
	} {
		value, err := txeFlagOrEnv(ctx, field.flag, field.env)
		if err != nil {
			return e, err
		}
		if value == "" {
			return e, fmt.Errorf("--%s is not set and %s is empty: this command runs as a step of a job's DAG", field.flag, field.env)
		}
		*field.target = value
	}
	queuedAt, err := txeQueuedAt(ctx)
	if err != nil {
		return e, err
	}
	e.execution.QueuedAt = queuedAt
	return e, nil
}

func runTXEArtifactsBegin(ctx *Context, _ []string) error {
	e, err := txeExecuting(ctx)
	if err != nil {
		return err
	}
	home, err := txepkg.DefaultHome()
	if err != nil {
		return err
	}
	dir, err := txeclient.Outputs{Home: home}.Begin(e.jobID, e.runID, e.execution)
	if err != nil {
		return err
	}
	return txeOutput(ctx, map[string]any{"ok": true, "job_id": e.jobID, "run_id": e.runID, "execution": e.execution.Ref(), "output_dir": dir},
		func(p *txePrinter) { p.f("execution %s writes to %s\n", e.execution.Ref(), dir) })
}

func runTXEArtifactsSeal(ctx *Context, _ []string) error {
	e, err := txeExecuting(ctx)
	if err != nil {
		return err
	}
	home, err := txepkg.DefaultHome()
	if err != nil {
		return err
	}
	seal, err := txeclient.Outputs{Home: home}.Seal(e.jobID, e.runID, e.execution)
	if err != nil {
		return err
	}
	return txeOutput(ctx, map[string]any{"ok": true, "seal": seal},
		func(p *txePrinter) {
			p.f("sealed execution %s of run %s: %d file(s)\n", seal.Ref, e.runID, len(seal.Files))
		})
}

// txeFlagOrEnv returns a flag's value, or the named variable when it is unset.
func txeFlagOrEnv(ctx *Context, flag, env string) (string, error) {
	value, err := ctx.StringParam(flag)
	if err != nil {
		return "", err
	}
	if value == "" {
		value = os.Getenv(env)
	}
	return value, nil
}

func runTXEArtifactsPublish(ctx *Context, _ []string) error {
	in := txeclient.PublishInput{}
	var version string
	for _, field := range []struct {
		target    *string
		flag, env string
		required  bool
	}{
		{&in.JobID, "job", "TXE_JOB_ID", true},
		{&version, "job-version", "TXE_JOB_VERSION", true},
		{&in.RunID, "run", "DAG_RUN_ID", true},
		{&in.Execution.AttemptID, "attempt", txepkg.AttemptEnv, true},
		{&in.ArtifactDir, "artifact-dir", "DAG_RUN_ARTIFACTS_DIR", false},
	} {
		value, err := txeFlagOrEnv(ctx, field.flag, field.env)
		if err != nil {
			return err
		}
		if value == "" && field.required {
			return fmt.Errorf("--%s is not set and %s is empty: this command runs as a step of a job's DAG", field.flag, field.env)
		}
		*field.target = value
	}
	queuedAt, err := txeQueuedAt(ctx)
	if err != nil {
		return err
	}
	in.Execution.QueuedAt = queuedAt
	number, err := strconv.Atoi(version)
	if err != nil || number < 1 {
		return fmt.Errorf("job version %q is not a positive number", version)
	}
	in.JobVersion = number

	client, err := txeClient(ctx)
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
	publisher := &txeclient.Publisher{Client: client, Home: home, Actor: txeclient.Actor{
		Kind: txeclient.ActorKindCLI, ID: "publish", MachineID: machine.MachineID, Client: txeClientVersion(),
	}}
	manifest, publishErr := publisher.Publish(ctx, in)
	if manifest == nil {
		return publishErr
	}
	if err := txeOutput(ctx, map[string]any{
		"ok": publishErr == nil, "job_id": in.JobID, "run_id": in.RunID, "manifest": manifest,
	}, func(p *txePrinter) {
		if manifest.ProducedIn != manifest.Execution {
			p.f("execution %s publishes what execution %s produced\n", manifest.Ref(), manifest.ProducedIn.Ref())
		}
		for _, a := range manifest.Artifacts {
			if a.Missing {
				p.f("missing   %s (%s)\n", a.Deliverable, a.Path)
				continue
			}
			p.f("%-9s %s (%s) %s, %d bytes\n", a.Location, a.Deliverable, a.Path, a.SHA256, a.Bytes)
		}
	}); err != nil {
		return errors.Join(publishErr, err)
	}
	return publishErr
}
