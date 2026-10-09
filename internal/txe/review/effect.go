// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/cmdutil"
)

// EffectStatus is what is known about an attempted external effect.
type EffectStatus int

const (
	// EffectApplied means the action reported success.
	EffectApplied EffectStatus = iota
	// EffectNotApplied means the action is known not to have taken effect.
	EffectNotApplied
	// EffectUnknown means the effect may or may not have happened.
	EffectUnknown
)

// EffectResult is the outcome of running or probing a declared action.
type EffectResult struct {
	Status  EffectStatus
	Receipt string
	Detail  string
}

// Effector performs declared actions on the local machine.
type Effector interface {
	// Run attempts the action's effect.
	Run(ctx context.Context, job Job, declared DeclaredAction, action Action) EffectResult
	// Probe asks the destination whether an earlier attempt took effect.
	Probe(ctx context.Context, job Job, declared DeclaredAction, action Action) EffectResult
}

const (
	defaultActionTimeout = 2 * time.Minute
	// exitNotApplied is the exit code by which an action or probe states
	// that the effect did not happen.
	exitNotApplied = 3
	maxReceiptLen  = 512
)

// CommandEffector runs declared actions as local processes. Parameters reach
// the process only as environment variables, never as shell text, so a model
// cannot inject a command through a parameter value.
type CommandEffector struct {
	// Env is the base environment; os.Environ() when nil.
	Env []string
}

var _ Effector = (*CommandEffector)(nil)

// Run implements Effector.
func (e *CommandEffector) Run(ctx context.Context, job Job, declared DeclaredAction, action Action) EffectResult {
	code, out, err := e.exec(ctx, job, declared.Command, declared, action)
	switch {
	case err == nil && code == 0:
		return EffectResult{Status: EffectApplied, Receipt: receiptFrom(out)}
	case err == nil && code == exitNotApplied:
		return EffectResult{Status: EffectNotApplied, Detail: "action reported that it did not apply"}
	case err == nil:
		detail := fmt.Sprintf("action exited with code %d", code)
		// Only a read-only action has no effect to be unsure about. Any
		// other action may have applied its effect before failing, whatever
		// its destination deduplicates, so the outcome is unknown.
		if declared.Idempotency == IdempotencyReadOnly {
			return EffectResult{Status: EffectNotApplied, Detail: detail}
		}
		return EffectResult{Status: EffectUnknown, Detail: detail}
	case errors.Is(err, errNotStarted):
		return EffectResult{Status: EffectNotApplied, Detail: err.Error()}
	default:
		if declared.Idempotency == IdempotencyReadOnly {
			return EffectResult{Status: EffectNotApplied, Detail: err.Error()}
		}
		return EffectResult{Status: EffectUnknown, Detail: err.Error()}
	}
}

// Probe implements Effector.
func (e *CommandEffector) Probe(ctx context.Context, job Job, declared DeclaredAction, action Action) EffectResult {
	if len(declared.Reconcile) == 0 {
		return EffectResult{Status: EffectUnknown, Detail: "no reconcile probe is declared"}
	}
	code, out, err := e.exec(ctx, job, declared.Reconcile, declared, action)
	switch {
	case err == nil && code == 0:
		return EffectResult{Status: EffectApplied, Receipt: receiptFrom(out)}
	case err == nil && code == exitNotApplied:
		return EffectResult{Status: EffectNotApplied, Detail: "probe found no effect"}
	case err == nil:
		return EffectResult{Status: EffectUnknown, Detail: fmt.Sprintf("probe exited with code %d", code)}
	default:
		return EffectResult{Status: EffectUnknown, Detail: err.Error()}
	}
}

var errNotStarted = errors.New("process did not start")

// exec returns the exit code and stdout of a process that ran to completion.
// err is non-nil when the process never started, was killed or timed out.
func (e *CommandEffector) exec(ctx context.Context, job Job, argv []string, declared DeclaredAction, action Action) (int, string, error) {
	if len(argv) == 0 {
		return 0, "", fmt.Errorf("%w: action %q declares no command", errNotStarted, declared.Name)
	}
	timeout := declared.Timeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// #nosec G204 -- argv comes from the job's registered policy, not from the agent.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = job.WorkingDir
	cmd.Env = append(e.baseEnv(), actionEnv(job, action)...)
	// The action runs in its own process group and the whole group is
	// killed when the deadline passes. Killing only the direct child would
	// leave a script's own children free to perform the effect after the
	// attempt was already recorded as over.
	cmdutil.SetupCommand(cmd)
	cmd.Cancel = func() error { return cmdutil.TerminateProcessGroup(cmd, cmdutil.ForceTermination()) }
	cmd.WaitDelay = 5 * time.Second
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return 0, "", fmt.Errorf("%w: %v", errNotStarted, err)
	}
	err := cmd.Wait()
	if ctx.Err() != nil {
		return 0, stdout.String(), fmt.Errorf("action %q did not finish within %s", declared.Name, timeout)
	}
	if err == nil {
		return 0, stdout.String(), nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.Exited() {
		return exitErr.ExitCode(), stdout.String(), nil
	}
	return 0, stdout.String(), fmt.Errorf("action %q ended abnormally: %v", declared.Name, err)
}

func (e *CommandEffector) baseEnv() []string {
	if e.Env != nil {
		return append([]string(nil), e.Env...)
	}
	return os.Environ()
}

func actionEnv(job Job, action Action) []string {
	env := []string{
		"TXE_JOB_ID=" + job.ID,
		"TXE_OWNER_ID=" + job.OwnerID,
		"TXE_ACTION_ID=" + action.ID,
		"TXE_ACTION_NAME=" + action.Name,
		"TXE_TARGET_ID=" + action.TargetID,
		// The destination deduplicates on this key where it supports one.
		"TXE_IDEMPOTENCY_KEY=" + action.ID,
	}
	names := make([]string, 0, len(action.Params))
	for name := range action.Params {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		env = append(env, "TXE_PARAM_"+strings.ToUpper(name)+"="+action.Params[name])
	}
	return env
}

// receiptFrom takes the last non-empty stdout line as the external receipt.
func receiptFrom(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	receipt := strings.TrimSpace(lines[len(lines)-1])
	if len(receipt) > maxReceiptLen {
		receipt = receipt[:maxReceiptLen]
	}
	return receipt
}

// Timeout is how long one attempt of the action may run.
func (a DeclaredAction) Timeout() time.Duration {
	if a.TimeoutSec > 0 {
		return time.Duration(a.TimeoutSec) * time.Second
	}
	return defaultActionTimeout
}
