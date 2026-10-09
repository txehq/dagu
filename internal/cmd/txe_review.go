// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
)

var (
	txeReviewMachineFlag     = commandLineFlag{name: "machine", usage: "Registry id of the machine this reviewer runs on", required: true}
	txeReviewRunFlag         = commandLineFlag{name: "run-id", usage: "Id of the reviewer DAG run (DAG_RUN_ID)", required: true}
	txeReviewStateFlag       = commandLineFlag{name: "state-dir", defaultValue: ".", usage: "Durable local directory for the hand-off between a run's steps"}
	txeReviewAgentClientFlag = commandLineFlag{name: "agent-client", usage: "Agent CLI name and version, recorded on the review"}
	txeReviewAgentLogFlag    = commandLineFlag{name: "agent-log", usage: "Path of the agent step's stderr log"}
	txeReviewAuthCheckFlag   = commandLineFlag{name: "auth-check", usage: "Agent CLI login status command, run only when the agent returned nothing"}
	txeReviewJobFlag         = commandLineFlag{name: "job", usage: "Job id", required: true}
	txeReviewProposalFlag    = commandLineFlag{name: "proposal", usage: "Proposal id", required: true}
	txeReviewDecisionFlag    = commandLineFlag{name: "decision", usage: "Decision id the human task was completed with", required: true}
	txeReviewOutDirFlag      = commandLineFlag{name: "out-dir", usage: "Directory to write the two DAG files into", required: true}
	txeReviewScheduleFlag    = commandLineFlag{name: "schedule", usage: "Cron of the reviewer tick (default: every 10 minutes)"}
	txeReviewAgentDirFlag    = commandLineFlag{name: "agent-config-dir", usage: "Logged-in agent profile the review agent uses, by reference"}
	txeReviewAgentModelFlag  = commandLineFlag{name: "agent-model", usage: "The model value configured in that agent profile"}
	txeReviewHomeFlag        = commandLineFlag{name: "txe-home", usage: "TXE home the steps use, when it is not the default; a step does not inherit it from the worker"}
	txeReviewCommandFlag     = commandLineFlag{name: "review-command", usage: "Command prefix the DAG steps call (default: dagu txe review)"}
)

func init() {
	txeSubcommands = append(txeSubcommands, txeReviewCommand)
}

func txeReviewCommand() *cobra.Command {
	command := NewCommand(&cobra.Command{
		Use:   "review",
		Short: "Steps of the periodic reviewer DAG",
		Long: `The steps of the reviewer and decision DAGs. They are called by those DAGs
on the job's machine, not by hand: each one is a short process that reads the
job registry on the hub, and the only thing carried between them is a hand-off
file in the state directory.`,
	}, nil, func(ctx *Context, _ []string) error {
		return ctx.Command.Help()
	})
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "prepare",
		Short: "Claim the longest overdue job and print its context packet",
		Long: `Close the decision runs of superseded proposals, then claim the job on this
machine that has been due for review longest and print its context packet as
JSON. Prints nothing when no job is due.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeReviewMachineFlag, txeReviewRunFlag, txeReviewStateFlag, txeReviewAgentClientFlag}, runTXEReviewPrepare))
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "apply",
		Short: "Apply the agent's decision, read from stdin, to the prepared review",
		Long: `Read the agent's output from stdin and apply it to the review this run
prepared: run the actions the job declares routine, file everything else as a
proposal, record the review and advance the checkpoint. An output that holds no
usable decision is recorded as an exception; it does not fail the step.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeReviewMachineFlag, txeReviewRunFlag, txeReviewStateFlag, txeReviewAgentClientFlag, txeReviewAgentLogFlag, txeReviewAuthCheckFlag}, runTXEReviewApply))
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "execute",
		Short: "Run the one effect a decision authorizes",
		Long: `Run the single effect the registry's record of a decision authorizes, under
a fresh execution claim. Anything else, including a superseded proposal or a
decision id the registry does not know, runs nothing and exits successfully.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeReviewMachineFlag, txeReviewRunFlag, txeReviewJobFlag, txeReviewProposalFlag, txeReviewDecisionFlag}, runTXEReviewExecute))
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "render",
		Short: "Write the reviewer and decision DAGs for a machine",
		Long: `Write the two DAG files a machine's reviewer needs. The installer puts them
on the hub. The agent profile is named by path and used by reference; its model
value is passed so that disabling the profile's settings does not drop it.`,
		Args:        cobra.NoArgs,
		Annotations: map[string]string{txeLocalAnnotation: "true"},
	}, []commandLineFlag{txeReviewMachineFlag, txeReviewStateFlag, txeReviewOutDirFlag, txeReviewScheduleFlag, txeReviewAgentDirFlag, txeReviewAgentModelFlag, txeReviewCommandFlag, txeReviewHomeFlag, txeJSONFlag}, runTXEReviewRender))
	return command
}

// txeReviewTransport adapts the hub client to the reviewer's transport. The
// reviewer passes a path with its query; the client takes them apart.
type txeReviewTransport struct {
	client *txeclient.Client
}

func (t txeReviewTransport) Do(ctx context.Context, method, path string, in, out any) error {
	var query url.Values
	if base, raw, found := strings.Cut(path, "?"); found {
		parsed, err := url.ParseQuery(raw)
		if err != nil {
			return fmt.Errorf("query of %s: %w", base, err)
		}
		path, query = base, parsed
	}
	err := t.client.Do(ctx, method, path, query, in, out)
	if e, ok := errors.AsType[*txeclient.Error](err); ok {
		return &review.TransportError{Status: e.Status, Code: e.Code, Message: e.Message}
	}
	return err
}

// txeReviewSteps builds the reviewer for one step process.
func txeReviewSteps(ctx *Context) (*review.Steps, error) {
	client, err := txeClient(ctx)
	if err != nil {
		return nil, err
	}
	machine, err := ctx.StringParam(txeReviewMachineFlag.name)
	if err != nil {
		return nil, err
	}
	runID, err := ctx.StringParam(txeReviewRunFlag.name)
	if err != nil {
		return nil, err
	}
	stateDir := "."
	if ctx.Command.Flags().Lookup(txeReviewStateFlag.name) != nil {
		if stateDir, err = ctx.StringParam(txeReviewStateFlag.name); err != nil {
			return nil, err
		}
	}
	if stateDir, err = filepath.Abs(stateDir); err != nil {
		return nil, err
	}
	agentClient := ""
	if ctx.Command.Flags().Lookup(txeReviewAgentClientFlag.name) != nil {
		if agentClient, err = ctx.StringParam(txeReviewAgentClientFlag.name); err != nil {
			return nil, err
		}
	}
	transport := txeReviewTransport{client: client}
	return &review.Steps{
		MachineID:   machine,
		StateDir:    stateDir,
		ArtifactDir: os.Getenv("DAG_RUN_ARTIFACTS_DIR"),
		Reviewer: &review.Reviewer{
			MachineID:   machine,
			Registry:    &review.Remote{Transport: transport, MachineID: machine, RunID: runID, AgentClient: agentClient},
			Effector:    &review.CommandEffector{},
			Opener:      &review.RunOpener{Enqueue: review.RemoteEnqueue(transport), Complete: review.RemoteComplete(transport)},
			Runs:        review.RemoteRuns(transport),
			Holder:      machine + "/" + runID,
			AgentClient: agentClient,
			DecideDAG:   review.DecideDAGName(machine),
		},
	}, nil
}

func runTXEReviewPrepare(ctx *Context, _ []string) error {
	steps, err := txeReviewSteps(ctx)
	if err != nil {
		return err
	}
	// The packet is the step's captured output and the agent's input, so it
	// is written exactly as built.
	return steps.Prepare(ctx, steps.Reviewer.Registry.(*review.Remote).RunID, ctx.Command.OutOrStdout())
}

func runTXEReviewApply(ctx *Context, _ []string) error {
	steps, err := txeReviewSteps(ctx)
	if err != nil {
		return err
	}
	agentLog, err := ctx.StringParam(txeReviewAgentLogFlag.name)
	if err != nil {
		return err
	}
	authCheck, err := ctx.StringParam(txeReviewAuthCheckFlag.name)
	if err != nil {
		return err
	}
	steps.AuthCheck = strings.Fields(authCheck)
	runID := steps.Reviewer.Registry.(*review.Remote).RunID
	return steps.Apply(ctx, runID, ctx.Command.InOrStdin(), agentLog, ctx.Command.OutOrStdout())
}

func runTXEReviewExecute(ctx *Context, _ []string) error {
	steps, err := txeReviewSteps(ctx)
	if err != nil {
		return err
	}
	job, err := ctx.StringParam(txeReviewJobFlag.name)
	if err != nil {
		return err
	}
	proposal, err := ctx.StringParam(txeReviewProposalFlag.name)
	if err != nil {
		return err
	}
	decision, err := ctx.StringParam(txeReviewDecisionFlag.name)
	if err != nil {
		return err
	}
	return steps.Execute(ctx, job, proposal, decision, ctx.Command.OutOrStdout())
}

func runTXEReviewRender(ctx *Context, _ []string) error {
	cfg := review.DAGConfig{}
	var err error
	for flag, into := range map[string]*string{
		txeReviewMachineFlag.name:    &cfg.MachineID,
		txeReviewStateFlag.name:      &cfg.StateDir,
		txeReviewScheduleFlag.name:   &cfg.Schedule,
		txeReviewAgentDirFlag.name:   &cfg.AgentConfigDir,
		txeReviewAgentModelFlag.name: &cfg.AgentModel,
		txeReviewCommandFlag.name:    &cfg.ReviewCommand,
	} {
		if *into, err = ctx.StringParam(flag); err != nil {
			return err
		}
	}
	outDir, err := ctx.StringParam(txeReviewOutDirFlag.name)
	if err != nil {
		return err
	}
	home, err := ctx.StringParam(txeReviewHomeFlag.name)
	if err != nil {
		return err
	}
	// A step on the worker inherits the worker's DAGU_HOME, which is not
	// where the CLI keeps its hub context, so the steps are given the
	// client directory explicitly instead of relying on the default.
	txeHome, err := txepkg.DefaultHome()
	if err != nil {
		return err
	}
	if home != "" {
		if !filepath.IsAbs(home) {
			return fmt.Errorf("--%s must be an absolute path", txeReviewHomeFlag.name)
		}
		txeHome = txepkg.Home{Root: filepath.Clean(home)}
	}
	cfg.Env = map[string]string{txepkg.EnvHome: txeHome.Root, "DAGU_HOME": txeHome.ClientDir()}
	if cfg.StateDir, err = filepath.Abs(cfg.StateDir); err != nil {
		return err
	}
	dags, err := review.RenderDAGs(cfg)
	if err != nil {
		return err
	}
	files := []struct{ name, doc string }{{dags.ReviewerName, dags.Reviewer}, {dags.DecideName, dags.Decide}}
	written := make([]string, 0, len(files))
	for _, f := range files {
		path := filepath.Join(outDir, f.name+".yaml")
		if err := os.WriteFile(path, []byte(f.doc), 0o600); err != nil {
			return err
		}
		written = append(written, path)
	}
	return txeOutput(ctx, map[string]any{"files": written}, func(p *txePrinter) {
		for _, path := range written {
			p.f("%s\n", path)
		}
	})
}
