// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
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
	// Admitted is true when the destination accepted the request for the
	// effect and only its result was not seen. It is what later allows the
	// effect to be recognised when it shows up: without it, something that
	// looks like the effect may be someone else's doing.
	Admitted bool
	// AdmittedRef is the execution the destination named for the admitted
	// request, when it names one.
	AdmittedRef string
	// Pending is true for an unknown outcome that later looks can still
	// settle: the admitted effect has not shown up yet and still may.
	Pending bool
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
	// The action runs as a managed process: in its own process group, which
	// is killed as a whole when the deadline passes and also when this
	// process dies. Killing only the direct child, or only while the
	// reviewer is alive, would leave a script's children free to perform
	// the effect after the attempt was recorded as over.
	cmd.Cancel = func() error { return cmdutil.TerminateProcessGroup(cmd, cmdutil.ForceTermination()) }
	cmd.WaitDelay = 5 * time.Second
	// Only the end of what the action prints is kept: the receipt is its
	// last line, and a job's command must not be able to fill the
	// reviewer's memory with what comes before it.
	stdout := tailBuffer{limit: maxActionOutput}
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	proc, err := cmdutil.StartManagedProcess(cmd)
	if err != nil {
		// A failure to contain the process comes after it was started and
		// stopped again, so it may already have acted. Only a process that
		// never existed is known to have applied nothing.
		if cmd.Process != nil {
			return 0, stdout.String(), fmt.Errorf("action %q started but could not be supervised: %v", declared.Name, err)
		}
		return 0, "", fmt.Errorf("%w: %v", errNotStarted, err)
	}
	err = proc.Wait()
	_ = proc.Release()
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

// maxActionOutput bounds what is kept of an action's standard output.
const maxActionOutput = 64 << 10

// tailBuffer keeps the last limit bytes written to it and discards what
// came before, always reporting the whole write as done so the writer is
// never blocked or failed by it.
type tailBuffer struct {
	buf   []byte
	limit int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	// Trimmed only once it has doubled, so a stream of small writes does
	// not copy the kept tail on every one of them.
	if len(b.buf) > 2*b.limit {
		b.buf = append(b.buf[:0], b.buf[len(b.buf)-b.limit:]...)
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	if len(b.buf) > b.limit {
		return string(b.buf[len(b.buf)-b.limit:])
	}
	return string(b.buf)
}
