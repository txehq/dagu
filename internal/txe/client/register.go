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
	"strings"

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
			return nil, fmt.Errorf("the hub does not know this machine (%s); enrol the local worker first", machine.MachineID)
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
	provenance := txepkg.DetectProvenance(ctx, spec.SourceRoot(), spec.Package.Include)
	who, err := r.resolve(ctx, spec, provenance)
	if err != nil {
		return nil, err
	}
	job, err := r.Client.Job(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("read job %s: %w", jobID, err)
	}
	if job.MachineID != who.machine.MachineID {
		return nil, fmt.Errorf("job %s runs on machine %s; update it from that machine, not from %s",
			jobID, job.MachineID, who.machine.MachineID)
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
	if entry.Step == txepkg.StepRejected {
		return nil, fmt.Errorf("request %s was refused by the hub and cannot be resumed: %s", requestID, entry.Error)
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

	// 1. The hub saves the job version and its DAG. Before this succeeds the
	// package stays in the staging area: a refused request leaves no package
	// where a worker could run it.
	var job *Job
	if entry.Step == txepkg.StepStaged {
		var err error
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

	// 2. The package moves to the path the DAG names. An earlier attempt may
	// already have moved it, in which case the one in place is checked.
	var pkg *txepkg.Package
	staged, stagedErr := r.Store.LoadStaged(entry.RequestID)
	switch {
	case stagedErr != nil:
		var err error
		if pkg, err = r.Store.Verify(entry.JobID, entry.PackageDigest); err != nil {
			return nil, incomplete(fmt.Errorf("the package is neither staged (%w) nor in place (%w)", stagedErr, err))
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
	if job == nil {
		var err error
		if job, err = r.Client.Job(ctx, entry.JobID); err != nil {
			return nil, incomplete(fmt.Errorf("read the job before marking it ready: %w", err))
		}
	}
	if job.Version != entry.Version || job.PackageDigest != entry.PackageDigest {
		return nil, incomplete(fmt.Errorf("job %s is now at version %d with package %s; this request registered version %d with %s",
			entry.JobID, job.Version, job.PackageDigest, entry.Version, entry.PackageDigest))
	}
	var size int64
	for _, f := range pkg.Manifest.Files {
		size += f.Size
	}
	receipt, err := r.Client.MarkReady(ctx, entry.JobID, ReadyRequest{
		ExpectedRevision: job.Revision,
		Package: PackageEvidence{
			Digest: pkg.Digest, Path: pkg.Dir, MachineID: job.MachineID,
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

	dagSpec := ""
	var sent struct {
		Version struct {
			DAG DAGRef `json:"dag"`
		} `json:"version"`
	}
	if json.Unmarshal(entry.Request, &sent) == nil {
		dagSpec = sent.Version.DAG.Spec
	}
	return &Outcome{Receipt: local, Package: pkg, DAGSpec: dagSpec}, nil
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
