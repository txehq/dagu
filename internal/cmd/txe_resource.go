// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/probe"
)

var (
	txeResourceJobFlag     = commandLineFlag{name: "job", usage: "Job id: check the pre_run targets before this job's run"}
	txeResourceVersionFlag = commandLineFlag{name: "job-version", usage: "Job version the run was rendered for (with --job)"}
	txeResourceMachineFlag = commandLineFlag{name: "machine", usage: "Machine id the check runs on; must be this machine (required)"}
	txeResourceTimeoutFlag = commandLineFlag{name: "timeout", usage: "Bound for the whole check (default 60s with --job, 9m otherwise)"}
)

// txeResourceIDPattern is a registry id: a prefix and 26 Crockford digits.
var txeResourceIDPattern = regexp.MustCompile(`^[a-z]{3}_[0-9A-HJKMNP-TV-Z]{26}$`)

func init() {
	txeSubcommands = append(txeSubcommands, txeResourceCommand)
}

func txeResourceCommand() *cobra.Command {
	command := NewCommand(&cobra.Command{
		Use:   "resource",
		Short: "Observe whether a job's external targets still exist",
	}, nil, func(ctx *Context, _ []string) error {
		return ctx.Command.Help()
	})
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "check",
		Short: "Observe targets on this machine and report them to the registry",
		Long: `Observe a job's external targets with this machine's own credentials and
report each observation to the registry, which decides what it means for the
job. A target is reported absent only when the probe proved it looked where
the target lives; a refused credential, an unreachable or wrong cluster, a
timeout or an inconclusive answer is reported as such, never as a deletion.

With --job and --job-version (the first command of a job's run), the pre_run
targets of that version are checked and the exit code says whether the job may
run: 0 run; 3 do not run (a target is gone or replaced, or the job ended); 75
do not run (a target could not be observed, or the report could not be saved).

Without --job (the machine's periodic reconcile DAG), the reconcile targets of
the machine's jobs and the targets of its unfinished reports are checked,
longest-unseen first; 75 means some were not reached or not reported.

Exit 2 means the arguments do not bind: another machine, or a missing version.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeResourceJobFlag, txeResourceVersionFlag, txeResourceMachineFlag, txeResourceTimeoutFlag}, runTXEResourceCheck))
	return command
}

// ExitCodeError ends the process with a chosen exit code. main honours it
// and only it, so an error from another command that happens to carry an
// exit code (a step's *exec.ExitError) still exits 1.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitCodeError) Unwrap() error { return e.Err }

func txeExit(code int, err error) error {
	if code == probe.ExitOK {
		return err
	}
	return &ExitCodeError{Code: code, Err: err}
}

func runTXEResourceCheck(ctx *Context, _ []string) error {
	jobID, err := ctx.StringParam("job")
	if err != nil {
		return err
	}
	versionText, err := ctx.StringParam("job-version")
	if err != nil {
		return err
	}
	machineID, err := ctx.StringParam("machine")
	if err != nil {
		return err
	}
	timeoutText, err := ctx.StringParam("timeout")
	if err != nil {
		return err
	}
	// The ids name local journal files, so they must be registry ids.
	if machineID == "" {
		return txeExit(probe.ExitUsage, errors.New("--machine is required: the check never guesses which machine it is on"))
	}
	if !txeResourceIDPattern.MatchString(machineID) || !strings.HasPrefix(machineID, "mch_") {
		return txeExit(probe.ExitUsage, fmt.Errorf("--machine %q is not a machine id", machineID))
	}
	preRun := jobID != ""
	if preRun && (!txeResourceIDPattern.MatchString(jobID) || !strings.HasPrefix(jobID, "job_")) {
		return txeExit(probe.ExitUsage, fmt.Errorf("--job %q is not a job id", jobID))
	}
	timeout := 9 * time.Minute
	if preRun {
		timeout = time.Minute
	}
	if timeoutText != "" {
		if timeout, err = time.ParseDuration(timeoutText); err != nil || timeout <= 0 {
			return txeExit(probe.ExitUsage, fmt.Errorf("--timeout %q is not a positive duration", timeoutText))
		}
	}
	version := 0
	switch {
	case preRun && versionText == "":
		return txeExit(probe.ExitUsage, errors.New("--job needs --job-version: the check binds the version the run was rendered for"))
	case preRun:
		if version, err = strconv.Atoi(versionText); err != nil || version < 1 {
			return txeExit(probe.ExitUsage, fmt.Errorf("--job-version %q is not a positive number", versionText))
		}
	case versionText != "":
		return txeExit(probe.ExitUsage, errors.New("--job-version is only meaningful with --job"))
	}

	home, err := txepkg.DefaultHome()
	if err != nil {
		return txeExit(probe.ExitInternal, err)
	}
	machine, err := home.Machine()
	if err != nil {
		return txeExit(probe.ExitInternal, err)
	}
	if machine.MachineID != machineID {
		return txeExit(probe.ExitUsage, fmt.Errorf("this machine is %s, not %s", machine.MachineID, machineID))
	}
	client, err := txeClient(ctx)
	if err != nil {
		return txeExit(probe.ExitUnobserved, err)
	}
	journal, err := probe.OpenJournal(filepath.Join(home.Root, "state", "probe", "journal-"+machineID+".json"))
	if err != nil {
		return txeExit(probe.ExitInternal, err)
	}
	check := &probe.Check{
		Registry:  probe.ClientRegistry{Client: client},
		Probes:    probe.Probes{probe.Kubernetes{}, probe.Linear{}},
		Journal:   journal,
		MachineID: machineID,
		Client:    txeClientVersion(),
		Out:       ctx.Command.OutOrStdout(),
		Evidence:  txeRunEvidence(),
	}
	deadline := time.Now().Add(timeout)
	runCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if preRun {
		code, err := check.PreRun(runCtx, jobID, version, probe.EnvCredentials{})
		return txeExit(code, err)
	}
	res, code, err := check.Periodic(runCtx, deadline, probe.LocalCredentials{Home: home}.For)
	if code != probe.ExitOK && err == nil {
		err = fmt.Errorf("%d targets not reached and %d not reported; they go first next time", res.Unfinished, res.Failed)
	}
	return txeExit(code, err)
}

// txeRunEvidence names the run execution a pre-run check belongs to, from
// the step's environment. TXE_QUEUED_AT is set and empty for a run that was
// never queued, which is a value of its own.
func txeRunEvidence() []string {
	var out []string
	if run, ok := os.LookupEnv("DAG_RUN_ID"); ok && run != "" {
		out = append(out, "dag_run_id="+run)
	}
	if attempt, ok := os.LookupEnv("TXE_ATTEMPT_ID"); ok && attempt != "" {
		out = append(out, "attempt_id="+attempt)
		if queued, ok := os.LookupEnv("TXE_QUEUED_AT"); ok {
			out = append(out, "queued_at="+queued)
		}
	}
	return out
}

// Compile-time check that the registry client satisfies the probe's needs.
var _ probe.Registry = probe.ClientRegistry{Client: (*txeclient.Client)(nil)}
