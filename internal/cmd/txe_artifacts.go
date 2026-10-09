// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

var (
	txeArtifactJobFlag     = commandLineFlag{name: "job", usage: "Job id (default: TXE_JOB_ID)"}
	txeArtifactVersionFlag = commandLineFlag{name: "job-version", usage: "Job version the run executed (default: TXE_JOB_VERSION)"}
	txeArtifactRunFlag     = commandLineFlag{name: "run", usage: "Dagu run id (default: DAG_RUN_ID)"}
	txeArtifactDirFlag     = commandLineFlag{name: "artifact-dir", usage: "The run's native artifact directory (default: DAG_RUN_ARTIFACTS_DIR)"}
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

Only files the job declares are read, by exact name, from the run's own output
directory. Each is recorded with its SHA-256 and where its bytes are. A file
declared for the hub is also copied into the run's artifact directory, which
the worker uploads when the run ends. Every file stays on this machine too.

A file is published as it is. Step output is masked for declared secrets; a
file a script writes is not, so a script must not write a credential into a
deliverable.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeArtifactJobFlag, txeArtifactVersionFlag, txeArtifactRunFlag, txeArtifactDirFlag, txeJSONFlag}, runTXEArtifactsPublish))
	return command
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
		Kind: txeclient.ActorKindCLI, ID: "publish", MachineID: machine.MachineID, Client: "dagu " + config.Version,
	}}
	manifest, publishErr := publisher.Publish(ctx, in)
	if manifest == nil {
		return publishErr
	}
	if err := txeOutput(ctx, map[string]any{
		"ok": publishErr == nil, "job_id": in.JobID, "run_id": in.RunID, "manifest": manifest,
	}, func(p *txePrinter) {
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
