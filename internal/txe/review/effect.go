// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
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
	// Env is the base environment of the job's commands, used exactly as
	// given. When nil it is this process's environment without what is the
	// reviewer's own; see baseEnv.
	Env []string
	// ReadCredentialFile reads the file of a job's file credential. When
	// nil the file is read as it is. Production supplies the checked read
	// the job's own machine uses for its credentials.
	ReadCredentialFile func(locator string) (string, error)
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
	if job.CredentialsRefused != "" {
		return 0, "", fmt.Errorf("%w: %s", errNotStarted, job.CredentialsRefused)
	}
	credentials, err := credentialEnv(job, e.ReadCredentialFile)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %v", errNotStarted, err)
	}
	// Order matters: later entries win. The job's declared credentials
	// replace anything of the same name that was inherited, and the action's
	// own variables come last.
	cmd.Env = append(append(e.baseEnv(), credentials...), actionEnv(job, action)...)
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

// baseEnv is the environment a job's command starts from. An environment
// given explicitly is the caller's deliberate choice and is passed as it is.
// Otherwise the command inherits this process's environment, which is the
// reviewer step's, minus what belongs to the reviewer and not to the job:
//
//   - the hub client's and the service's own settings (DAGU_*, TXE_DAGU_*, and
//     the bindings of the reviewer fixture, TXE_FIXTURE_*): the context and credentials the reviewer writes to
//     the registry with, and which registry that is. The marker that stops a job from registering work
//     under a review is kept;
//   - the review's own variables: the packet, the decision, the ids the
//     decision run passes to its step, and anything named like a parameter
//     of an action (TXE_PARAM_*), which would otherwise pass for one. The
//     action's own variables are added by the caller;
//   - the agent's profile and keys (CLAUDE_*, ANTHROPIC_*, CODEX_*,
//     OPENAI_*): the login the review agent runs under.
//
// Everything else is inherited. That includes what a job's command needs to
// reach its own resources, among it the credential references a job
// declares, which have TXE_ names of their own (TXE_KUBECONFIG,
// TXE_KUBE_CONTEXT): the TXE_ prefix as a whole is deliberately not removed.
// This removes accidental inheritance only. It is not isolation: the
// command runs as the same user and can read the same files.
func (e *CommandEffector) baseEnv() []string {
	if e.Env != nil {
		return append([]string(nil), e.Env...)
	}
	return jobEnv(os.Environ())
}

// reviewerEnvPrefixes are the variable name prefixes that belong to the
// reviewer, the service it talks to, the agent it runs, or the review.
var reviewerEnvPrefixes = []string{"DAGU_", "TXE_DAGU_", "TXE_FIXTURE_", "TXE_PARAM_", "CLAUDE_", "ANTHROPIC_", "CODEX_", "OPENAI_"}

// reviewerEnvNames are the review's own variables that have no prefix of
// their own: what the rendered DAGs hand from one step to the next, and the
// action's identity, which the caller sets afresh for each command.
var reviewerEnvNames = map[string]bool{
	"TXE_PACKET": true, "TXE_DECISION": true, "TXE_PROPOSAL_ID": true, "TXE_DECISION_ID": true,
	"TXE_JOB_ID": true, "TXE_OWNER_ID": true, "TXE_ACTION_ID": true, "TXE_ACTION_NAME": true,
	"TXE_TARGET_ID": true, "TXE_IDEMPOTENCY_KEY": true,
}

// jobEnv returns env without the reviewer's own variables.
func jobEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		// Windows treats variable names without regard to case.
		upper := strings.ToUpper(name)
		if upper != ReviewerEnv && (reviewerEnvNames[upper] || slices.ContainsFunc(reviewerEnvPrefixes, func(p string) bool { return strings.HasPrefix(upper, p) })) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// credentialEnv resolves the credentials the job declares, on this machine,
// into the variables its command reads them from. This is the deliberate way
// a credential reaches a job's command: a declared credential is supplied
// even under a name whose inherited value is removed as the reviewer's own
// (a job may declare its own OPENAI_API_KEY; it gets the declared one, never
// the review agent's).
//
// What is reported of a failure is recorded on the action and shown to the
// review agent at later reviews, so it names the reference and the kind of
// failure only: never a value, and never the locator, which says where the
// credential is kept.
//
// A file is read as it is, as the service reads it for the job's own runs.
// A variable is copied from this process's environment. A credential that
// cannot be resolved stops the command before it starts, as it stops a run:
// the error names the reference and never a value. A reference cannot name
// one of the variables that identify the action or mark the review.
// credentialNamePattern is the rule a job's registration applies to the
// name of a credential reference.
var credentialNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func credentialEnv(job Job, readFile func(string) (string, error)) ([]string, error) {
	env := make([]string, 0, len(job.CredentialRefs))
	for _, ref := range job.CredentialRefs {
		upper := strings.ToUpper(ref.Name)
		switch {
		case !credentialNamePattern.MatchString(ref.Name):
			return nil, fmt.Errorf("credential reference %q is not a variable name", ref.Name)
		case upper == ReviewerEnv || reviewerEnvNames[upper] || strings.HasPrefix(upper, "TXE_PARAM_"):
			return nil, fmt.Errorf("credential reference %s uses a name reserved for the action", ref.Name)
		}
		var value string
		switch ref.Kind {
		case CredentialFile:
			var err error
			if readFile != nil {
				// The checked reader's errors name the path; only the
				// kind of failure is reported.
				value, err = readFile(ref.Locator)
			} else {
				var raw []byte
				// #nosec G304 -- the path is the job's registered credential locator on its own machine.
				raw, err = os.ReadFile(ref.Locator)
				value = string(raw)
			}
			if err != nil {
				return nil, fmt.Errorf("credential %s: its file %s", ref.Name, unreadable(err))
			}
		case CredentialEnv:
			found, ok := os.LookupEnv(ref.Locator)
			if !ok {
				return nil, fmt.Errorf("credential %s: the variable it is copied from is not set where the reviewer runs", ref.Name)
			}
			value = found
		default:
			return nil, fmt.Errorf("credential %s: unknown kind %q", ref.Name, ref.Kind)
		}
		if strings.ContainsRune(value, 0) {
			return nil, fmt.Errorf("credential %s: its value cannot be passed in a variable", ref.Name)
		}
		env = append(env, ref.Name+"="+value)
	}
	return env, nil
}

// unreadable says why a credential's file could not be read, without the
// path the system's error carries.
func unreadable(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "does not exist"
	case errors.Is(err, os.ErrPermission):
		return "cannot be read: permission denied"
	default:
		return "cannot be read"
	}
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
