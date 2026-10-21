// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

// EnvReviewer is set in a periodic reviewer's environment. A reviewer reads
// and reports on jobs; it must not create or change them, or a review could
// schedule further work without anyone asking for it.
const EnvReviewer = "TXE_DAGU_REVIEWER"

// ErrReviewerSession refuses registration from inside a reviewer.
var ErrReviewerSession = errors.New("this is a reviewer session (" + EnvReviewer + "=1): it may not register or update jobs")

// ErrJobExists reports that the job key is already registered. The existing
// job is the one to inspect or update.
type ErrJobExists struct {
	JobKey string
	Job    Job
}

func (e *ErrJobExists) Error() string {
	return fmt.Sprintf("job key %q is already registered as %s (version %d, %s)",
		e.JobKey, e.Job.JobID, e.Job.Version, e.Job.Lifecycle)
}

// ErrRejected reports that the hub refused a request. Nothing was registered
// by it; the journal entry and the staged package are kept as evidence.
type ErrRejected struct {
	RequestID string
	Refusal   *Error
}

func (e *ErrRejected) Error() string {
	return fmt.Sprintf("request %s was refused: %v", e.RequestID, e.Refusal)
}

func (e *ErrRejected) Unwrap() error { return e.Refusal }

// ErrIncomplete reports a registration that stopped part-way. No receipt
// exists for it. Resuming the same request finishes it without creating a
// second job.
type ErrIncomplete struct {
	RequestID string
	Step      txepkg.Step
	Cause     error
}

func (e *ErrIncomplete) Error() string {
	return fmt.Sprintf("registration is incomplete at step %q (no receipt was issued): %v; resume with request id %s",
		e.Step, e.Cause, e.RequestID)
}

func (e *ErrIncomplete) Unwrap() error { return e.Cause }

// ErrSuperseded reports a request whose job version was replaced by a later
// one before its receipt was written. The job itself is unaffected.
type ErrSuperseded struct {
	RequestID string
	JobID     string
	Version   int
	Current   int
}

func (e *ErrSuperseded) Error() string {
	return fmt.Sprintf("request %s registered version %d of %s, but the job is now at version %d; nothing is left to resume and no receipt exists for version %d",
		e.RequestID, e.Version, e.JobID, e.Current, e.Version)
}

// Registrar registers and updates jobs from this machine. Each step is saved
// in the journal before the next begins, and a receipt is written only after
// the hub has marked the job ready.
type Registrar struct {
	Client  *Client
	Home    txepkg.Home
	Store   *txepkg.Store
	Journal *txepkg.Journal
	// Actor is recorded on every change this registrar makes.
	Actor Actor
	// NewID mints an opaque ID with the given prefix.
	NewID func(prefix string) (string, error)
	// Hub names the connection these registrations use, so that a job's
	// publish step reaches the same hub. The zero value is the TXE home's own
	// context store and its default context.
	Hub HubContext
	// StepClient is set when the job's steps reach the hub through another
	// context than the session does: Hub names it, and StepClient reads the
	// hub through it as a step would. A person's sign-in is one such session,
	// since a step never presents it. Registration then goes ahead only while
	// both reach the same registry: the steps' context must hold this
	// machine for the same owner before anything is sent, and must read the
	// job just registered, at its version and package, before it is marked
	// ready. Nil means the steps use the session's own context.
	StepClient *Client
	// HasCommands reports whether the dagu binary at the given path has each
	// of the "dagu txe" commands named. A job's DAG calls that binary on
	// this machine, so a job is not registered while the binary lacks a
	// command its DAG calls. Nil means: ask the binary itself.
	HasCommands func(ctx context.Context, dagu string, commands [][]string) error
}

// HubContext is a CLI context by reference: the flags that select the context
// store, and the context's name in it. It carries no credential.
//
// A txe command ignores DAGU_* environment variables, so its flags are all
// that decides which store a command reads. A publish step is given the
// session's flags and the two directories they resolved to, and so reads the
// store this session read.
type HubContext struct {
	// DaguHome is the --dagu-home the session used.
	DaguHome string
	// ConfigFile is the --config the session used, if any.
	ConfigFile string
	// Name is the context's name in that store.
	Name string
	// ContextsDir and DataDir are where those flags resolved to in the
	// session: the contexts, and the key they are read with. A publish step
	// is given both outright, because resolving the same configuration again
	// from a step's working directory can give other directories.
	ContextsDir string
	DataDir     string
}

// Outcome is a completed registration or update.
type Outcome struct {
	Receipt *txepkg.Receipt
	Package *txepkg.Package
	DAGSpec string
}

// Plan is what a registration would send, without sending it.
type Plan struct {
	Machine  *txepkg.Machine
	Project  *Project
	Digest   string
	Manifest txepkg.Manifest
	DAGSpec  string
}

// subject is the identity a registration acts for, read from this machine and
// checked against the hub.
type subject struct {
	machine *txepkg.Machine
	project *Project
}

// resolve reads the machine identity and checks it against the registry. A
// job is registered only for the machine the CLI runs on: that machine's
// worker is the one that will find the package on its disk.
func (r *Registrar) resolve(ctx context.Context, spec *JobSpec, provenance txepkg.Provenance) (*subject, error) {
	machine, err := r.Home.Machine()
	if err != nil {
		return nil, err
	}
	known, err := r.Client.Machine(ctx, machine.MachineID)
	if err != nil {
		if IsCode(err, CodeNotFound) {
			return nil, fmt.Errorf("the hub does not know this machine (%s); record it with \"dagu txe machine create\" first", machine.MachineID)
		}
		return nil, fmt.Errorf("look up this machine on the hub: %w", err)
	}
	if known.OwnerID != machine.OwnerID {
		return nil, fmt.Errorf("the hub records machine %s under owner %s, but this machine's identity file says %s",
			machine.MachineID, known.OwnerID, machine.OwnerID)
	}

	key, name := spec.Project.Key, spec.Project.Name
	if key == "" {
		key = provenance.Repository
	}
	if key == "" {
		return nil, errors.New("cannot tell which project this job belongs to: the source is not a git repository with an origin remote; set project.key in the job spec")
	}
	if name == "" {
		name = key[strings.Index(key, "/")+1:]
	}
	project, err := r.Client.EnsureProject(ctx, machine.OwnerID, key, name, r.Actor)
	if err != nil {
		return nil, fmt.Errorf("resolve project %s: %w", key, err)
	}
	return &subject{machine: machine, project: project}, nil
}

// version builds the registry's job version and the DAG it runs as.
func (r *Registrar) version(spec *JobSpec, who *subject, jobID string, number int, staged *txepkg.Staged) (*JobVersion, error) {
	dir, err := r.Store.PackageDir(jobID, staged.Digest)
	if err != nil {
		return nil, err
	}
	workDir := dir + string(os.PathSeparator) + txepkg.FilesDir
	expires, err := spec.expiresAt()
	if err != nil {
		return nil, err
	}

	dag, err := txepkg.RenderDAG(txepkg.DAGSpec{
		Title:         spec.Title,
		ProjectName:   who.project.Name,
		JobID:         jobID,
		OwnerID:       who.machine.OwnerID,
		ProjectID:     who.project.ProjectID,
		MachineID:     who.machine.MachineID,
		Version:       number,
		PackageDigest: staged.Digest,
		WorkDir:       workDir,
		OutputDir:     r.Home.OutputDir(jobID),
		Entrypoint:    staged.Manifest.Entrypoint,
		Schedule: txepkg.Schedule{
			Cron: spec.Schedule.Cron, Timezone: spec.Schedule.Timezone, Overlap: spec.Schedule.Overlap,
			TimeoutSec: spec.Schedule.TimeoutSec, Retry: spec.Schedule.Retry,
			RetryIntervalSec: spec.Schedule.RetryIntervalSec, CatchupWindow: spec.Schedule.CatchupWindow,
		},
		Env:            spec.Env,
		CredentialRefs: spec.CredentialRefs,
		CLI:            r.cli(),
		Publish:        r.publishStep(spec),
	})
	if err != nil {
		return nil, err
	}

	refs := make([]CredentialRef, len(spec.CredentialRefs))
	for i, ref := range spec.CredentialRefs {
		refs[i] = CredentialRef{Name: ref.Name, Kind: ref.Kind, Locator: ref.Locator}
	}
	overlap := spec.Schedule.Overlap
	if overlap == "" {
		overlap = txepkg.OverlapSkip
	}
	return &JobVersion{
		Title:   spec.Title,
		Purpose: spec.Purpose,
		Origin: Origin{
			Repo: staged.Manifest.Provenance.Repository, Commit: staged.Manifest.Provenance.Commit,
			Session: r.Actor.Session, WorktreePath: staged.Manifest.Provenance.SourceRoot, ChatRef: spec.ChatRef,
		},
		Package: Package{
			Digest: staged.Digest, Path: dir, Entrypoint: txepkg.ShellJoin(staged.Manifest.Entrypoint),
			WorkingDir: workDir, Runtime: staged.Manifest.Runtimes, CredentialRefs: refs,
		},
		DAG: DAGRef{Name: jobID, Spec: string(dag)},
		Schedule: Schedule{
			Cron: spec.Schedule.Cron, Timezone: spec.Schedule.Timezone, Overlap: overlap,
			TimeoutSec: spec.Schedule.TimeoutSec, Retry: spec.Schedule.Retry, MissedRun: spec.Schedule.missedRun(),
		},
		Targets:         spec.Targets,
		ExpectedOutcome: spec.ExpectedOutcome,
		Lifetime:        Lifetime{ExpiresAt: expires},
		RetirementRules: spec.RetirementRules,
		ReviewPolicy:    spec.ReviewPolicy,
	}, nil
}

// cli is how the job's DAG calls dagu on this machine: the installed binary
// and the context store this registration used.
func (r *Registrar) cli() txepkg.CLI {
	daguHome := r.Hub.DaguHome
	if daguHome == "" {
		daguHome = r.Home.ClientDir()
	}
	flags := []string{"--dagu-home", daguHome}
	if r.Hub.ConfigFile != "" {
		flags = append(flags, "--config", r.Hub.ConfigFile)
	}
	if r.Hub.ContextsDir != "" {
		flags = append(flags, "--contexts-dir", r.Hub.ContextsDir)
	}
	if r.Hub.DataDir != "" {
		flags = append(flags, "--data-dir", r.Hub.DataDir)
	}
	if r.Hub.Name != "" {
		flags = append(flags, "--context", r.Hub.Name)
	}
	return txepkg.CLI{Dagu: filepath.Join(r.Home.Root, "bin", "dagu"), StoreFlags: flags, HomeRoot: r.Home.Root}
}

// publishStep says how the run's deliverables are recorded, or nil when the
// job declares none.
func (r *Registrar) publishStep(spec *JobSpec) *txepkg.Publish {
	deliverables := spec.ExpectedOutcome.Deliverables
	if len(deliverables) == 0 {
		return nil
	}
	hub := false
	for _, d := range deliverables {
		hub = hub || d.Delivery == DeliveryHub
	}
	return &txepkg.Publish{HubArtifacts: hub}
}

// checkHub refuses a context store a scheduled run could not rely on. Every
// job's DAG reads it at every run, long after this session is gone: the
// resource check before the job, and the publish step after it.
func (r *Registrar) checkHub() error {
	for _, path := range []string{r.Hub.DaguHome, r.Hub.ConfigFile, r.Hub.ContextsDir, r.Hub.DataDir} {
		if path == "" {
			continue
		}
		if err := r.Store.Policy.CheckDurable(path); err != nil {
			return fmt.Errorf("the context store used for this registration cannot be used by the job's own steps: %w", err)
		}
	}
	return nil
}

// checkMachine refuses a registration whose DAG could not run on this
// machine as it is installed now: a context store a later run could not rely
// on, or a dagu that lacks a command the DAG calls.
func (r *Registrar) checkMachine(ctx context.Context, spec *JobSpec) error {
	if err := r.checkHub(); err != nil {
		return err
	}
	if err := r.checkStepHub(ctx); err != nil {
		return err
	}
	commands := [][]string{{"resource", "check"}}
	if len(spec.ExpectedOutcome.Deliverables) > 0 {
		commands = append(commands, []string{"artifacts", "begin"}, []string{"artifacts", "seal"}, []string{"artifacts", "publish"})
	}
	has := r.HasCommands
	if has == nil {
		has = HasTXECommands
	}
	dagu := r.cli().Dagu
	if err := has(ctx, dagu, commands); err != nil {
		return fmt.Errorf("the dagu this machine's jobs run (%s) cannot run this job's DAG: %w; install a dagu that has the command on this machine, then register again", dagu, err)
	}
	return nil
}

// checkStepHub refuses a registration whose steps would reach the hub through
// a context that does not hold this machine, for the same owner, as the
// session's does. Nothing has been sent yet.
func (r *Registrar) checkStepHub(ctx context.Context) error {
	if r.StepClient == nil {
		return nil
	}
	machine, err := r.Home.Machine()
	if err != nil {
		return err
	}
	theirs, err := r.StepClient.Machine(ctx, machine.MachineID)
	if err != nil {
		return fmt.Errorf("the context this machine's jobs run with (%s) cannot read machine %s: %w", r.Hub.Name, machine.MachineID, err)
	}
	ours, err := r.Client.Machine(ctx, machine.MachineID)
	if err != nil {
		return fmt.Errorf("read machine %s through this session's hub: %w", machine.MachineID, err)
	}
	if *theirs != *ours || theirs.OwnerID != machine.OwnerID {
		return fmt.Errorf("the context this machine's jobs run with (%s) and this session reach different registries: they hold machine %s for owner %s and %s, and this machine says %s",
			r.Hub.Name, machine.MachineID, theirs.OwnerID, ours.OwnerID, machine.OwnerID)
	}
	return nil
}

// checkSavedSteps refuses a journal entry whose saved DAG runs the job's
// steps with another context store than this registrar gives them. That
// covers a request begun before steps were given the machine's store, and
// one resumed from a session that reaches the hub another way.
//
// The DAG is read as YAML and compared with the shape the renderer gives it:
// a run step of this job's resource check, the artifacts begin command when
// there are deliverables, the job's own command as the request saved it, and
// the artifacts seal command; then, with deliverables, a publish step. Every
// dagu command must carry this registrar's store flags. Text elsewhere in the
// DAG, such as the title or an environment value, decides nothing.
func (r *Registrar) checkSavedSteps(entry *txepkg.Entry) error {
	var request struct {
		Version JobVersion `json:"version"`
	}
	if err := json.Unmarshal(entry.Request, &request); err != nil {
		return fmt.Errorf("read the DAG saved with request %s: %w", entry.RequestID, err)
	}
	var dag struct {
		Steps []struct {
			Name    string `yaml:"name"`
			Command any    `yaml:"command"`
		} `yaml:"steps"`
	}
	if err := yaml.Unmarshal([]byte(request.Version.DAG.Spec), &dag); err != nil {
		return fmt.Errorf("read the DAG saved with request %s: %w", entry.RequestID, err)
	}
	cli := r.cli()
	txe := func(words ...string) string {
		return txepkg.ShellJoin(append(append([]string{cli.Dagu, "txe"}, words...), cli.StoreFlags...))
	}
	check := txe("resource", "check", "--job", entry.JobID, "--job-version", strconv.Itoa(entry.Version), "--machine", entry.MachineID)
	job := request.Version.Package.Entrypoint
	plain := []string{check, job}
	delivering := []string{check, txe("artifacts", "begin"), job, txe("artifacts", "seal")}
	publish := []string{txe("artifacts", "publish")}

	matches := false
	switch len(dag.Steps) {
	case 1:
		matches = dag.Steps[0].Name == "run" && slices.Equal(commandLines(dag.Steps[0].Command), plain)
	case 2:
		matches = dag.Steps[0].Name == "run" && slices.Equal(commandLines(dag.Steps[0].Command), delivering) &&
			dag.Steps[1].Name == "publish" && slices.Equal(commandLines(dag.Steps[1].Command), publish)
	}
	if !matches {
		return fmt.Errorf("request %s was built to run its steps with another context store than this session gives them (%s), so it cannot be sent or finished from here: "+
			"finish it from a session that reaches the hub the same way, or register the job again", entry.RequestID, txepkg.ShellJoin(cli.StoreFlags))
	}
	return nil
}

// commandLines returns a step's command as the list of lines it runs: one
// line for a scalar, each item for a list of strings, and nil for anything
// else.
func commandLines(command any) []string {
	switch c := command.(type) {
	case string:
		return []string{c}
	case []any:
		lines := make([]string, 0, len(c))
		for _, item := range c {
			line, ok := item.(string)
			if !ok {
				return nil
			}
			lines = append(lines, line)
		}
		return lines
	}
	return nil
}

// checkStepJob refuses to mark a job ready unless the steps' context reads
// it as this session registered it: the same job, owner, machine, version and
// package. A hub that merely holds the same machine is not enough.
func (r *Registrar) checkStepJob(ctx context.Context, job *Job) error {
	if r.StepClient == nil {
		return nil
	}
	seen, err := r.StepClient.Job(ctx, job.JobID)
	if err != nil {
		return fmt.Errorf("the context this machine's jobs run with (%s) cannot read job %s, so its steps would reach another hub: %w", r.Hub.Name, job.JobID, err)
	}
	if seen.OwnerID != job.OwnerID || seen.MachineID != job.MachineID || seen.Version != job.Version || seen.PackageDigest != job.PackageDigest {
		return fmt.Errorf("the context this machine's jobs run with (%s) reads job %s at version %d with package %s, not version %d with %s: its steps would reach another registry",
			r.Hub.Name, job.JobID, seen.Version, seen.PackageDigest, job.Version, job.PackageDigest)
	}
	return nil
}

// HasTXECommands asks the dagu binary at the given path whether it has each
// "dagu txe" command, by reading the command's own help. A dagu without the
// command prints the help of the nearest command it does have and exits
// zero, so the exit status says nothing. What is read is the usage line: it
// names the command that answered, word for word. A mention of the command
// anywhere else in the text, or a longer command name, does not count.
func HasTXECommands(ctx context.Context, dagu string, commands [][]string) error {
	for _, words := range commands {
		name := "txe " + strings.Join(words, " ")
		probe, cancel := context.WithTimeout(ctx, 20*time.Second)
		args := append(append([]string{"txe"}, words...), "--help")
		cmd := exec.CommandContext(probe, dagu, args...) //nolint:gosec // the machine's own installed dagu
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("asking it for %q failed: %w", "dagu "+name, err)
		}
		if !usageNames(string(out), append([]string{"txe"}, words...)) {
			return fmt.Errorf("it has no %q command", "dagu "+name)
		}
	}
	return nil
}

// usageNames reports whether a help text's usage block has a line for
// exactly the command path given: the program's name, the path's words, and
// then nothing or a bracketed placeholder such as "[flags]".
func usageNames(help string, path []string) bool {
	inUsage := false
	for line := range strings.SplitSeq(help, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "Usage:":
			inUsage = true
			continue
		case !inUsage:
			continue
		case trimmed == "":
			return false // the usage block has ended
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 1+len(path) || !slices.Equal(fields[1:1+len(path)], path) {
			continue
		}
		if rest := fields[1+len(path):]; len(rest) == 0 || strings.HasPrefix(rest[0], "[") {
			return true
		}
	}
	return false
}

// ErrParamSchemaUnenforced refuses a spec that bounds an action's parameters
// on a hub whose registry does not say it enforces those bounds.
var ErrParamSchemaUnenforced = errors.New("this hub's registry does not say it checks action parameters")

// checkRegistry refuses a spec that declares something the hub's registry
// would store and not enforce. A param_schema is a bound on what a reviewer
// may pass to an action; a registry that only stores it leaves the action
// unbounded while its job says otherwise.
//
// The schemas themselves are checked here too, not only when a spec file is
// read: a spec may be built by a caller that never validated it.
func (r *Registrar) checkRegistry(ctx context.Context, spec *JobSpec) error {
	var bounded []string
	for _, a := range spec.ReviewPolicy.PermittedActions {
		if !a.ParamSchema.isMapping() {
			return fmt.Errorf("permitted action %q: param_schema must be a mapping (a JSON Schema)", a.Name)
		}
		if len(a.ParamSchema) > 0 {
			bounded = append(bounded, a.Name)
		}
	}
	if len(bounded) == 0 {
		return nil
	}
	installation, err := r.Client.Installation(ctx)
	if err != nil {
		return fmt.Errorf("ask the hub whether its registry checks action parameters: %w", err)
	}
	if !slices.Contains(installation.Capabilities, CapabilityParamSchema) {
		return fmt.Errorf("%w (its installation record lists no %q capability): it would store the param_schema of %s and check nothing against it. Upgrade the hub before registering this job",
			ErrParamSchemaUnenforced, CapabilityParamSchema, strings.Join(bounded, ", "))
	}
	return nil
}

func (r *Registrar) stage(ctx context.Context, spec *JobSpec, requestID string) (*txepkg.Staged, error) {
	provenance := txepkg.DetectProvenance(ctx, spec.SourceRoot(), spec.Package.Include)
	provenance.Session = r.Actor.Session
	return r.Store.Stage(requestID, txepkg.BuildOptions{
		SourceRoot:     spec.SourceRoot(),
		Include:        spec.Package.Include,
		Entrypoint:     spec.Package.Entrypoint,
		Runtimes:       spec.Package.Runtimes,
		CredentialRefs: spec.CredentialRefs,
		Provenance:     provenance,
	})
}

// Plan validates a spec against this machine and the hub, builds the package
// and renders the DAG, then discards the package. Nothing is registered.
func (r *Registrar) Plan(ctx context.Context, spec *JobSpec) (*Plan, error) {
	if os.Getenv(EnvReviewer) == "1" {
		return nil, ErrReviewerSession
	}
	if err := r.checkMachine(ctx, spec); err != nil {
		return nil, err
	}
	if err := r.checkRegistry(ctx, spec); err != nil {
		return nil, err
	}
	provenance := txepkg.DetectProvenance(ctx, spec.SourceRoot(), spec.Package.Include)
	who, err := r.resolve(ctx, spec, provenance)
	if err != nil {
		return nil, err
	}
	requestID, err := r.NewID("req")
	if err != nil {
		return nil, err
	}
	staged, err := r.stage(ctx, spec, requestID)
	if err != nil {
		return nil, err
	}
	// The plan's package was never referenced by a journal entry or a job.
	defer func() { _ = os.RemoveAll(staged.Dir) }()

	jobID, err := r.NewID("job")
	if err != nil {
		return nil, err
	}
	version, err := r.version(spec, who, jobID, 1, staged)
	if err != nil {
		return nil, err
	}
	return &Plan{Machine: who.machine, Project: who.project, Digest: staged.Digest, Manifest: staged.Manifest, DAGSpec: version.DAG.Spec}, nil
}

// Register creates a job from a spec. It refuses when the job key is already
// registered in the project, whether it finds that first or the hub does.
func (r *Registrar) Register(ctx context.Context, spec *JobSpec) (*Outcome, error) {
	if os.Getenv(EnvReviewer) == "1" {
		return nil, ErrReviewerSession
	}
	if err := r.checkMachine(ctx, spec); err != nil {
		return nil, err
	}
	if err := r.checkRegistry(ctx, spec); err != nil {
		return nil, err
	}
	provenance := txepkg.DetectProvenance(ctx, spec.SourceRoot(), spec.Package.Include)
	who, err := r.resolve(ctx, spec, provenance)
	if err != nil {
		return nil, err
	}

	// Look before building anything: the usual duplicate is an earlier
	// session's job, not a race.
	existing, err := r.Client.ListJobs(ctx, JobFilter{OwnerID: who.machine.OwnerID, ProjectID: who.project.ProjectID, JobKey: spec.JobKey})
	if err != nil {
		return nil, fmt.Errorf("check for an existing job: %w", err)
	}
	if len(existing) > 0 {
		return nil, &ErrJobExists{JobKey: spec.JobKey, Job: existing[0]}
	}

	jobID, err := r.NewID("job")
	if err != nil {
		return nil, err
	}
	requestID, err := r.NewID("req")
	if err != nil {
		return nil, err
	}
	staged, err := r.stage(ctx, spec, requestID)
	if err != nil {
		return nil, err
	}
	version, err := r.version(spec, who, jobID, 1, staged)
	if err != nil {
		_ = os.RemoveAll(staged.Dir)
		return nil, err
	}
	body, err := json.Marshal(RegisterRequest{
		JobID: jobID, RequestID: requestID, OwnerID: who.machine.OwnerID, ProjectID: who.project.ProjectID,
		MachineID: who.machine.MachineID, JobKey: spec.JobKey, Version: *version, Actor: r.Actor,
	})
	if err != nil {
		return nil, err
	}
	entry, err := r.Journal.Begin(txepkg.Entry{
		RequestID: requestID, Operation: txepkg.OpRegister, JobID: jobID, JobKey: spec.JobKey, Version: 1,
		MachineID: who.machine.MachineID, OwnerID: who.machine.OwnerID,
		Step: txepkg.StepStaged, PackageDigest: staged.Digest, Session: r.Actor.Session, Request: body,
	})
	if err != nil {
		return nil, err
	}
	return r.advance(ctx, entry)
}

// Update records a new version of a job when expectedVersion is its current
// version. An outdated expectedVersion is refused and changes nothing.
func (r *Registrar) Update(ctx context.Context, jobID string, expectedVersion int, spec *JobSpec) (*Outcome, error) {
	if os.Getenv(EnvReviewer) == "1" {
		return nil, ErrReviewerSession
	}
	if err := r.checkMachine(ctx, spec); err != nil {
		return nil, err
	}
	if err := r.checkRegistry(ctx, spec); err != nil {
		return nil, err
	}
	provenance := txepkg.DetectProvenance(ctx, spec.SourceRoot(), spec.Package.Include)
	who, err := r.resolve(ctx, spec, provenance)
	if err != nil {
		return nil, err
	}
	job, err := r.Client.Job(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("read job %s: %w", jobID, err)
	}
	if err := sameMachine(job, who.machine); err != nil {
		return nil, err
	}
	if job.Registration.JobKey != spec.JobKey {
		return nil, fmt.Errorf("job %s has job key %q, but the spec says %q; a job's key does not change",
			jobID, job.Registration.JobKey, spec.JobKey)
	}

	requestID, err := r.NewID("req")
	if err != nil {
		return nil, err
	}
	staged, err := r.stage(ctx, spec, requestID)
	if err != nil {
		return nil, err
	}
	version, err := r.version(spec, who, jobID, expectedVersion+1, staged)
	if err != nil {
		_ = os.RemoveAll(staged.Dir)
		return nil, err
	}
	body, err := json.Marshal(VersionRequest{RequestID: requestID, ExpectedVersion: expectedVersion, Version: *version, Actor: r.Actor})
	if err != nil {
		return nil, err
	}
	entry, err := r.Journal.Begin(txepkg.Entry{
		RequestID: requestID, Operation: txepkg.OpUpdate, JobID: jobID, JobKey: spec.JobKey, Version: expectedVersion + 1,
		MachineID: who.machine.MachineID, OwnerID: who.machine.OwnerID,
		Step: txepkg.StepStaged, PackageDigest: staged.Digest, Session: r.Actor.Session, Request: body,
	})
	if err != nil {
		return nil, err
	}
	return r.advance(ctx, entry)
}

// Resume finishes a registration or update that stopped part-way. It sends
// the saved request again, which the hub recognises as a replay, so resuming
// never creates a second job or version.
func (r *Registrar) Resume(ctx context.Context, requestID string) (*Outcome, error) {
	if os.Getenv(EnvReviewer) == "1" {
		return nil, ErrReviewerSession
	}
	entry, err := r.Journal.Get(requestID)
	if err != nil {
		return nil, err
	}
	switch entry.Step {
	case txepkg.StepRejected:
		return nil, fmt.Errorf("request %s was refused by the hub and cannot be resumed: %s", requestID, entry.Error)
	case txepkg.StepSuperseded:
		return nil, fmt.Errorf("request %s cannot be resumed: %s", requestID, entry.Error)
	case txepkg.StepStaged, txepkg.StepRegistered, txepkg.StepCommitted:
	}
	return r.advance(ctx, entry)
}

// advance carries a journal entry from its saved step to a receipt.
func (r *Registrar) advance(ctx context.Context, entry *txepkg.Entry) (*Outcome, error) {
	incomplete := func(cause error) error {
		entry.Error = cause.Error()
		if err := r.Journal.Save(entry); err != nil {
			cause = errors.Join(cause, err)
		}
		return &ErrIncomplete{RequestID: entry.RequestID, Step: entry.Step, Cause: cause}
	}

	// Every path into here, a first attempt or a resume, acts for this
	// machine: it is this machine's disk the package is on.
	machine, err := r.Home.Machine()
	if err != nil {
		return nil, err
	}
	// The check comes before anything is sent: a request built on one machine
	// must not create or change a job from another.
	if entry.MachineID != machine.MachineID || entry.OwnerID != machine.OwnerID {
		return nil, fmt.Errorf("request %s was built on machine %s for owner %s; this is machine %s of owner %s, which cannot send or finish it",
			entry.RequestID, entry.MachineID, entry.OwnerID, machine.MachineID, machine.OwnerID)
	}
	// A resumed request keeps the DAG it was built with. It is sent or
	// finished only by a session whose job steps use the same context store,
	// so that the checks below are made on the store its steps will read.
	if err := r.checkSavedSteps(entry); err != nil {
		return nil, err
	}
	if err := r.checkStepHub(ctx); err != nil {
		return nil, err
	}

	// 1. The hub saves the job version and its DAG. Before this succeeds the
	// package stays in the staging area: a refused request leaves no package
	// where a worker could run it.
	var job *Job
	if entry.Step == txepkg.StepStaged {
		if job, err = r.send(ctx, entry); err != nil {
			var refusal *Error
			if errors.As(err, &refusal) && refusal.rejectsRequest() {
				entry.Step = txepkg.StepRejected
				entry.Error = refusal.Error()
				entry.Response, _ = json.Marshal(refusal)
				if saveErr := r.Journal.Save(entry); saveErr != nil {
					return nil, errors.Join(err, saveErr)
				}
				return nil, &ErrRejected{RequestID: entry.RequestID, Refusal: refusal}
			}
			// The outcome is unknown: the request may have been saved.
			return nil, incomplete(err)
		}
		entry.Step, entry.Error, entry.Response = txepkg.StepRegistered, "", job.Raw
		if err := r.Journal.Save(entry); err != nil {
			return nil, &ErrIncomplete{RequestID: entry.RequestID, Step: entry.Step, Cause: err}
		}
	}

	if job == nil {
		var err error
		if job, err = r.Client.Job(ctx, entry.JobID); err != nil {
			return nil, incomplete(fmt.Errorf("read the job: %w", err))
		}
	}
	if err := sameMachine(job, machine); err != nil {
		return nil, incomplete(err)
	}

	// 2. The package moves to the path the DAG names. An earlier attempt may
	// already have moved it, in which case the one in place is checked.
	var pkg *txepkg.Package
	staged, stagedErr := r.Store.LoadStaged(entry.RequestID)
	switch {
	case stagedErr != nil:
		var err error
		// Adopt seals the package before verifying it: an earlier attempt may
		// have stopped between moving it and sealing it.
		if pkg, err = r.Store.Adopt(entry.JobID, entry.PackageDigest); err != nil {
			return nil, incomplete(fmt.Errorf("the package is neither staged (%w) nor in place (%w)", stagedErr, err))
		}
		// An earlier attempt may have stopped while removing its staged copy
		// of a package that was already in place.
		if err := r.Store.FinishRemoval(entry.RequestID); err != nil {
			return nil, incomplete(fmt.Errorf("the package is in place at %s, but its staged copy was not removed: %w", pkg.Dir, err))
		}
	case staged.Digest != entry.PackageDigest:
		return nil, incomplete(fmt.Errorf("the staged package has digest %s, but %s was registered", staged.Digest, entry.PackageDigest))
	default:
		var err error
		if pkg, err = r.Store.Commit(staged, entry.JobID); err != nil {
			return nil, incomplete(err)
		}
	}
	if err := os.MkdirAll(r.Home.OutputDir(entry.JobID), 0o700); err != nil {
		return nil, incomplete(fmt.Errorf("create the job's output directory: %w", err))
	}
	if entry.Step != txepkg.StepCommitted {
		entry.Step, entry.Error = txepkg.StepCommitted, ""
		if err := r.Journal.Save(entry); err != nil {
			return nil, &ErrIncomplete{RequestID: entry.RequestID, Step: entry.Step, Cause: err}
		}
	}

	// 3. The hub marks the job ready against the package now in place.
	if job.Version > entry.Version {
		return r.overtaken(ctx, entry, job, pkg, incomplete)
	}
	if job.Version != entry.Version || job.PackageDigest != entry.PackageDigest {
		return nil, incomplete(fmt.Errorf("job %s is at version %d with package %s; this request registered version %d with %s",
			entry.JobID, job.Version, job.PackageDigest, entry.Version, entry.PackageDigest))
	}
	if err := r.checkStepJob(ctx, job); err != nil {
		return nil, incomplete(err)
	}
	var size int64
	for _, f := range pkg.Manifest.Files {
		size += f.Size
	}
	receipt, err := r.Client.MarkReady(ctx, entry.JobID, ReadyRequest{
		ExpectedRevision: job.Revision,
		Package: PackageEvidence{
			Digest: pkg.Digest, Path: pkg.Dir, MachineID: machine.MachineID,
			ManifestSHA256: strings.TrimPrefix(pkg.Digest, "sha256:"), Files: len(pkg.Manifest.Files), Bytes: size,
		},
		Actor: r.Actor,
	})
	if err != nil {
		return nil, incomplete(fmt.Errorf("mark the job ready: %w", err))
	}
	if receipt.Registration != RegistrationReady {
		return nil, incomplete(fmt.Errorf("the hub answered with registration state %q, not ready", receipt.Registration))
	}

	// 4. Only now is there a receipt.
	local, err := r.Journal.Complete(entry, txepkg.Receipt{
		JobID: receipt.JobID, Version: receipt.Version, OwnerID: receipt.OwnerID, ProjectID: receipt.ProjectID,
		MachineID: receipt.MachineID, PackageDigest: receipt.PackageDigest, PackageDir: pkg.Dir,
		Session: r.Actor.Session, Service: receipt.Raw,
	})
	if err != nil {
		return nil, incomplete(err)
	}
	return outcome(entry, local, pkg), nil
}

func outcome(entry *txepkg.Entry, receipt *txepkg.Receipt, pkg *txepkg.Package) *Outcome {
	dagSpec := ""
	var sent struct {
		Version struct {
			DAG DAGRef `json:"dag"`
		} `json:"version"`
	}
	if json.Unmarshal(entry.Request, &sent) == nil {
		dagSpec = sent.Version.DAG.Spec
	}
	return &Outcome{Receipt: receipt, Package: pkg, DAGSpec: dagSpec}
}

// overtaken finishes a request whose version is no longer the job's current
// one: another session recorded a later version before this request had its
// receipt filed. The job can no longer be marked ready for this version, but
// the version may have been, with the answer lost on the way back.
//
// A receipt this request already wrote is filed. Otherwise the registry's
// history is asked: it keeps an entry for every version that became ready,
// naming the package and the DAG. If this version has one, the receipt is
// written from it. If it has none, the version never became ready, and the
// request is closed as superseded with no receipt.
func (r *Registrar) overtaken(ctx context.Context, entry *txepkg.Entry, job *Job, pkg *txepkg.Package, incomplete func(error) error) (*Outcome, error) {
	if existing, err := r.Journal.Receipt(entry.JobID, entry.Version); err == nil && existing.RequestID == entry.RequestID {
		local, err := r.Journal.Complete(entry, *existing)
		if err != nil {
			return nil, incomplete(err)
		}
		return outcome(entry, local, pkg), nil
	}

	version, err := r.Client.JobVersion(ctx, entry.JobID, entry.Version)
	if err != nil {
		return nil, incomplete(fmt.Errorf("read version %d of %s: %w", entry.Version, entry.JobID, err))
	}
	events, err := r.Client.JobEvents(ctx, entry.JobID)
	if err != nil {
		return nil, incomplete(fmt.Errorf("read the history of %s: %w", entry.JobID, err))
	}
	for _, event := range events {
		// The DAG's hash is different for every version; the package's need not be.
		if event.Kind != EventReady || version.DAG.SpecSHA256 == "" ||
			!slices.Contains(event.Evidence, entry.PackageDigest) || !slices.Contains(event.Evidence, version.DAG.SpecSHA256) {
			continue
		}
		local, err := r.Journal.Complete(entry, txepkg.Receipt{
			JobID: entry.JobID, Version: entry.Version, OwnerID: job.OwnerID, ProjectID: job.ProjectID,
			MachineID: job.MachineID, PackageDigest: entry.PackageDigest, PackageDir: pkg.Dir,
			Session: r.Actor.Session, Service: event.Raw, Recovered: "registry event " + event.EventID,
		})
		if err != nil {
			return nil, incomplete(err)
		}
		return outcome(entry, local, pkg), nil
	}

	entry.Step = txepkg.StepSuperseded
	entry.Error = fmt.Sprintf("job %s moved on to version %d, and its history has no record that version %d was ever marked ready; the package stays in place and no receipt is written for that version",
		entry.JobID, job.Version, entry.Version)
	if err := r.Journal.Save(entry); err != nil {
		return nil, err
	}
	return nil, &ErrSuperseded{RequestID: entry.RequestID, JobID: entry.JobID, Version: entry.Version, Current: job.Version}
}

// sameMachine refuses to act on a job that belongs to another machine or
// another owner. A package can only be vouched for by the machine that holds it.
func sameMachine(job *Job, machine *txepkg.Machine) error {
	if job.MachineID != machine.MachineID {
		return fmt.Errorf("job %s runs on machine %s; this is machine %s, which cannot place or vouch for its package",
			job.JobID, job.MachineID, machine.MachineID)
	}
	if job.OwnerID != machine.OwnerID {
		return fmt.Errorf("job %s belongs to owner %s, but this machine belongs to %s",
			job.JobID, job.OwnerID, machine.OwnerID)
	}
	return nil
}

// send posts the saved request exactly as it was first built, so the hub
// sees a retry as the same request.
func (r *Registrar) send(ctx context.Context, entry *txepkg.Entry) (*Job, error) {
	path := "/txe/jobs"
	if entry.Operation == txepkg.OpUpdate {
		path += "/" + url.PathEscape(entry.JobID) + "/versions"
	}
	var job Job
	if err := r.Client.Do(ctx, http.MethodPost, path, nil, entry.Request, &job); err != nil {
		return nil, err
	}
	return &job, nil
}
