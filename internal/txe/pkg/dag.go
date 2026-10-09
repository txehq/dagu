// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// Label keys written on every job DAG. Labels are for display and filtering
// only: Dagu lowercases them, so an ID is never read back from one.
const (
	LabelSchema  = "txe.schema"
	LabelOwner   = "txe.owner"
	LabelProject = "txe.project"
	LabelJob     = "txe.job"
	LabelMachine = "txe.machine"
	LabelVersion = "txe.version"
	LabelPackage = "txe.package"
)

// Overlap policies Dagu accepts.
const (
	OverlapSkip   = "skip"
	OverlapAll    = "all"
	OverlapLatest = "latest"
)

// Schedule is when and within what bounds a job runs.
type Schedule struct {
	Cron     string
	Timezone string
	// Overlap defaults to skip.
	Overlap    string
	TimeoutSec int
	// Retry is how many times a failed run is retried; zero means never.
	Retry            int
	RetryIntervalSec int
	// CatchupWindow, such as "6h", makes the scheduler run intervals missed
	// while the hub or the machine was unavailable. Empty skips them.
	CatchupWindow string
}

// DAGSpec is everything the job's DAG is rendered from.
type DAGSpec struct {
	Title       string
	ProjectName string

	JobID     string
	OwnerID   string
	ProjectID string
	MachineID string
	Version   int

	PackageDigest string
	// WorkDir is the package's payload directory on the assigned machine.
	WorkDir string
	// OutputDir is where the job's scripts write durable results.
	OutputDir  string
	Entrypoint []string

	Schedule Schedule
	// Env are literal, non-secret settings for the job's script.
	Env            map[string]string
	CredentialRefs []CredentialRef

	// Publish, when set, adds a final step that records the run's declared
	// deliverables. Without it the run publishes nothing.
	Publish *Publish
}

// Publish describes the step that records a run's deliverables.
type Publish struct {
	// Command is the absolute path of the dagu binary on the assigned
	// machine followed by its arguments.
	Command []string
	// HomeRoot is the TXE home on the assigned machine. The step needs it
	// spelled out: a step does not inherit the worker's environment.
	HomeRoot string
	// HubArtifacts enables the run's native artifact directory, which the
	// worker uploads to the hub when the run ends.
	HubArtifacts bool
}

// publishVerb is what follows the dagu binary in a publish command.
var publishVerb = []string{"txe", "artifacts", "publish"}

// verb is the publish command with another verb of "txe artifacts" in place
// of "publish". It keeps the publish command's flags: every "dagu txe"
// command resolves the hub's context before it does anything, so a command
// without them would look for the context in another store. A job therefore
// does not execute when its results could not be recorded for lack of one.
func (p *Publish) verb(name string) []string {
	argv := []string{p.Command[0], publishVerb[0], publishVerb[1], name}
	return append(argv, p.Command[1+len(publishVerb):]...)
}

// RunOutputEnv is the variable holding the output directory of the attempt
// that is executing. Declared deliverables are read from there, by exact name.
const RunOutputEnv = "TXE_RUN_OUTPUT_DIR"

// AttemptEnv is the variable holding the Dagu attempt that is executing. A
// retry keeps the run ID; the attempt is what tells one execution of a run
// from the next.
const AttemptEnv = "TXE_ATTEMPT_ID"

// QueuedAtEnv is the variable holding the queue marker the executing attempt
// was dispatched with: empty for a run that was never queued. A retry through
// a queue keeps the attempt ID and gets a later marker, so the attempt and
// the marker together name one execution.
const QueuedAtEnv = "TXE_QUEUED_AT"

// The values Dagu replaces with the executing attempt's ID and queue marker.
const (
	attemptRef  = "${context.attempt.id}"
	queuedAtRef = "${context.attempt.queued_at}"
)

// AttemptOutputDir is where the job that is executing in an attempt writes,
// under the job's output directory.
func AttemptOutputDir(outputDir, runID, attemptID string) string {
	return filepath.Join(outputDir, "runs", runID, "attempts", attemptID)
}

// ExecutionOutputDir is where the results of an execution that succeeded are
// kept, by the execution's reference.
func ExecutionOutputDir(outputDir, runID, executionRef string) string {
	return filepath.Join(outputDir, "runs", runID, "executions", executionRef)
}

// RenderDAG returns the Dagu workflow for a job. The same input always gives
// the same bytes, so a replayed registration sends an identical definition.
//
// The DAG has no name: Dagu names it after its file, which is the job ID. The
// command is the package's entrypoint and nothing is written into the package:
// the working directory is read-only and results go to OutputDir. Each
// credential reference becomes a secret the worker resolves from its own
// machine, so no credential value appears in the definition.
func RenderDAG(s DAGSpec) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	// Steps run in the order written. Dagu's default runs steps that name no
	// dependency in parallel, which would publish before the job had written.
	line("type: chain")
	line("description: %s", quote(s.Title))
	if s.ProjectName != "" {
		line("group: %s", quote(s.ProjectName))
	}
	line("labels:")
	for _, label := range s.labels() {
		line("  - %s", quote(label))
	}
	line("worker_selector:")
	line("  %s: %s", LabelMachine, quote(s.MachineID))
	line("schedule: %s", quote("CRON_TZ="+s.Schedule.Timezone+" "+s.Schedule.Cron))
	line("overlap_policy: %s", s.overlap())
	if s.Schedule.CatchupWindow != "" {
		line("catchup_window: %s", quote(s.Schedule.CatchupWindow))
	}
	line("max_active_runs: 1")
	line("timeout_sec: %d", s.Schedule.TimeoutSec)
	line("working_dir: %s", quote(s.WorkDir))
	if s.Publish != nil && s.Publish.HubArtifacts {
		line("artifacts:")
		line("  enabled: true")
	}

	line("env:")
	line("  - TXE_JOB_ID: %s", quote(s.JobID))
	line("  - TXE_JOB_VERSION: %s", quote(fmt.Sprint(s.Version)))
	line("  - TXE_OUTPUT_DIR: %s", quote(s.OutputDir))
	// Dagu substitutes the run ID, the attempt ID and the queue marker when
	// an execution starts. The marker reaches the commands as a variable,
	// which is well formed when it is empty.
	line("  - %s: %s", AttemptEnv, quote(attemptRef))
	line("  - %s: %s", QueuedAtEnv, quote(queuedAtRef))
	line("  - %s: %s", RunOutputEnv, quote(AttemptOutputDir(s.OutputDir, "${DAG_RUN_ID}", attemptRef)))
	if s.Publish != nil {
		line("  - %s: %s", EnvHome, quote(s.Publish.HomeRoot))
	}
	names := make([]string, 0, len(s.Env))
	for name := range s.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		line("  - %s: %s", name, quote(s.Env[name]))
	}

	if len(s.CredentialRefs) > 0 {
		line("secrets:")
		for _, ref := range s.CredentialRefs {
			line("  - name: %s", ref.Name)
			line("    provider: %s", ref.Kind)
			line("    key: %s", quote(ref.Locator))
		}
	}

	line("steps:")
	line("  - name: run")
	if s.Publish == nil {
		line("    command: %s", quote(shellJoin(s.Entrypoint)))
	} else {
		// The job's command runs between two commands of the same step.
		// The first gives it an empty output directory, keeping what an
		// earlier execution left there; the last seals what the job
		// wrote, which is what the publish step reads. A failed command
		// stops the step, so nothing is sealed unless the job's command
		// succeeded.
		line("    command:")
		line("      - %s", quote(shellJoin(s.Publish.verb("begin"))))
		line("      - %s", quote(shellJoin(s.Entrypoint)))
		line("      - %s", quote(shellJoin(s.Publish.verb("seal"))))
	}
	if s.Schedule.Retry > 0 {
		line("    retry_policy:")
		line("      limit: %d", s.Schedule.Retry)
		line("      interval_sec: %d", s.Schedule.RetryIntervalSec)
	}
	if s.Publish != nil {
		line("  - name: publish")
		line("    command: %s", quote(shellJoin(s.Publish.Command)))
	}
	return []byte(b.String()), nil
}

func (s DAGSpec) labels() []string {
	digest := strings.TrimPrefix(s.PackageDigest, digestPrefix)
	return []string{
		LabelSchema + "=1",
		LabelOwner + "=" + s.OwnerID,
		LabelProject + "=" + s.ProjectID,
		LabelJob + "=" + s.JobID,
		LabelMachine + "=" + s.MachineID,
		fmt.Sprintf("%s=%d", LabelVersion, s.Version),
		LabelPackage + "=sha256-" + digest[:32],
	}
}

func (s DAGSpec) overlap() string {
	if s.Schedule.Overlap == "" {
		return OverlapSkip
	}
	return s.Schedule.Overlap
}

// reservedEnv are set by the renderer and cannot be supplied by the job.
var reservedEnv = map[string]bool{
	"TXE_JOB_ID": true, "TXE_JOB_VERSION": true, "TXE_OUTPUT_DIR": true, RunOutputEnv: true, AttemptEnv: true, QueuedAtEnv: true, EnvHome: true,
}

func (s DAGSpec) validate() error {
	for _, id := range []string{s.JobID, s.OwnerID, s.ProjectID, s.MachineID} {
		if !namePattern.MatchString(id) {
			return fmt.Errorf("render DAG: invalid id %q", id)
		}
	}
	if strings.TrimSpace(s.Title) == "" {
		return fmt.Errorf("render DAG: title is required")
	}
	if s.Version < 1 {
		return fmt.Errorf("render DAG: version must be at least 1")
	}
	if !digestPattern.MatchString(s.PackageDigest) {
		return fmt.Errorf("render DAG: invalid package digest %q", s.PackageDigest)
	}
	for name, dir := range map[string]string{"working directory": s.WorkDir, "output directory": s.OutputDir} {
		if !filepath.IsAbs(dir) {
			return fmt.Errorf("render DAG: %s %q must be absolute on the assigned machine", name, dir)
		}
	}
	if len(s.Entrypoint) == 0 {
		return fmt.Errorf("render DAG: entrypoint is required")
	}

	if p := s.Publish; p != nil {
		if len(p.Command) == 0 || !filepath.IsAbs(p.Command[0]) {
			return fmt.Errorf("render DAG: the publish command must start with the absolute path of the dagu binary")
		}
		if len(p.Command) < 1+len(publishVerb) || !slices.Equal(p.Command[1:1+len(publishVerb)], publishVerb) {
			return fmt.Errorf("render DAG: the publish command must be %q after the dagu binary", strings.Join(publishVerb, " "))
		}
		if !filepath.IsAbs(p.HomeRoot) {
			return fmt.Errorf("render DAG: the TXE home %q must be absolute", p.HomeRoot)
		}
		for i, arg := range p.Command {
			if err := literal(fmt.Sprintf("publish command argument %d", i), arg); err != nil {
				return err
			}
		}
		if err := literal("TXE home", p.HomeRoot); err != nil {
			return err
		}
	}
	if err := literal("output directory", s.OutputDir); err != nil {
		return err
	}

	sch := s.Schedule
	if len(strings.Fields(sch.Cron)) != 5 {
		return fmt.Errorf("schedule.cron must be a five-field cron expression, got %q", sch.Cron)
	}
	if sch.Timezone == "" {
		return fmt.Errorf("schedule.timezone is required: a schedule without one runs in whatever zone the hub happens to use")
	}
	if _, err := time.LoadLocation(sch.Timezone); err != nil {
		return fmt.Errorf("schedule.timezone %q is not a known time zone", sch.Timezone)
	}
	if sch.TimeoutSec <= 0 {
		return fmt.Errorf("schedule.timeout_sec is required: an unattended job must have a bound")
	}
	switch sch.Overlap {
	case "", OverlapSkip, OverlapAll, OverlapLatest:
	default:
		return fmt.Errorf("schedule.overlap must be skip, all or latest, got %q", sch.Overlap)
	}
	if sch.Retry < 0 || sch.Retry > 5 {
		return fmt.Errorf("schedule.retry must be between 0 and 5, got %d", sch.Retry)
	}
	if sch.Retry > 0 && sch.RetryIntervalSec <= 0 {
		return fmt.Errorf("schedule.retry_interval_sec is required when schedule.retry is set")
	}
	if sch.CatchupWindow != "" {
		if _, err := time.ParseDuration(sch.CatchupWindow); err != nil {
			return fmt.Errorf("schedule.catchup_window %q is not a duration such as 6h", sch.CatchupWindow)
		}
	}

	for name, value := range s.Env {
		if !envNamePattern.MatchString(name) {
			return fmt.Errorf("env name %q is not a valid variable name", name)
		}
		if reservedEnv[name] {
			return fmt.Errorf("env name %s is set by the registration and cannot be overridden", name)
		}
		if err := literal("env "+name, value); err != nil {
			return err
		}
	}
	for i, arg := range s.Entrypoint {
		if err := literal(fmt.Sprintf("entrypoint argument %d", i), arg); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, ref := range s.CredentialRefs {
		if ref.Kind != CredentialFile && ref.Kind != CredentialEnv {
			return fmt.Errorf("credential reference %s: kind must be %q or %q", ref.Name, CredentialFile, CredentialEnv)
		}
		if !envNamePattern.MatchString(ref.Name) || ref.Locator == "" {
			return fmt.Errorf("credential reference %q needs a variable name and a locator", ref.Name)
		}
		if seen[ref.Name] || reservedEnv[ref.Name] || s.Env[ref.Name] != "" {
			return fmt.Errorf("credential reference %s collides with another variable of the job", ref.Name)
		}
		seen[ref.Name] = true
		if err := literal("credential locator "+ref.Name, ref.Locator); err != nil {
			return err
		}
	}
	return nil
}

// literal refuses text Dagu would expand on the worker. A value that needs a
// dollar sign belongs in a file inside the package.
func literal(what, value string) error {
	if strings.ContainsAny(value, "$`") {
		return fmt.Errorf("%s contains $ or a backtick, which Dagu expands on the worker; keep it literal or read it from a packaged file", what)
	}
	if strings.ContainsAny(value, "\n\r\x00") {
		return fmt.Errorf("%s contains a line break", what)
	}
	return nil
}

// quote renders a YAML double-quoted scalar. JSON string syntax is a subset of
// it, and quoting every value keeps the output free of YAML's implicit types.
func quote(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

// ShellJoin renders argv as one command line, quoting each argument that
// needs it so the worker's shell passes it through unchanged.
func ShellJoin(argv []string) string { return shellJoin(argv) }

func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, arg := range argv {
		parts[i] = shellQuote(arg)
	}
	return strings.Join(parts, " ")
}

const shellSafe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./=:,@%+"

func shellQuote(arg string) string {
	if arg != "" && strings.Trim(arg, shellSafe) == "" {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}
