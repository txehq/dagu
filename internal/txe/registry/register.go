// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/goccy/go-yaml"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var windowsAbsPath = regexp.MustCompile(`^([A-Za-z]:[\\/]|\\\\)`)

// machineAbsPath reports whether p is absolute on the machine that runs the
// job, which need not have the hub's operating system: a POSIX path, a
// Windows drive path or a UNC path, with no ".." segment under either
// separator.
func machineAbsPath(p string) bool {
	if !strings.HasPrefix(p, "/") && !windowsAbsPath.MatchString(p) {
		return false
	}
	return !slices.Contains(strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }), "..")
}

// Worker label that routes a job to its machine.
const machineLabel = "txe.machine"

// RegisterInput is a new job. JobID is minted by the client and RequestID
// identifies this attempt, so a retried registration is idempotent.
type RegisterInput struct {
	JobID     string
	RequestID string
	OwnerID   string
	ProjectID string
	MachineID string
	// JobKey is the creator's name for the logical job, unique per owner
	// and project. A second job with the same key is a duplicate.
	JobKey  string
	Version JobVersion
}

// Receipt is returned only once every part of a registration is saved.
type Receipt struct {
	JobID         string            `json:"job_id"`
	OwnerID       string            `json:"owner_id"`
	ProjectID     string            `json:"project_id"`
	MachineID     string            `json:"machine_id"`
	Version       int               `json:"version"`
	PackageDigest string            `json:"package_digest"`
	DAGName       string            `json:"dag_name"`
	DAGSpecSHA256 string            `json:"dag_spec_sha256"`
	Registration  RegistrationState `json:"registration"`
	Revision      int64             `json:"revision"`
	Created       Stamp             `json:"created"`
	ReadyAt       string            `json:"ready_at"`
}

func receiptOf(j *Job) *Receipt {
	r := &Receipt{
		JobID:         j.JobID,
		OwnerID:       j.OwnerID,
		ProjectID:     j.ProjectID,
		MachineID:     j.MachineID,
		Version:       j.Version,
		PackageDigest: j.PackageDigest,
		DAGName:       j.JobID,
		DAGSpecSHA256: j.DAGSpecSHA256,
		Registration:  j.Registration.State,
		Revision:      j.Revision,
		Created:       j.Created,
	}
	if j.Registration.ReadyAt != nil {
		r.ReadyAt = j.Registration.ReadyAt.Format("2006-01-02T15:04:05.000Z07:00")
	}
	return r
}

func normalizeVersion(jobID string, v *JobVersion) error {
	switch {
	case strings.TrimSpace(v.Title) == "":
		return refuse(CodeInvalid, "title is required")
	case strings.TrimSpace(v.Purpose) == "":
		return refuse(CodeInvalid, "purpose is required")
	case !digestPattern.MatchString(v.Package.Digest):
		return refuse(CodeInvalid, "package.digest must be sha256:<64 hex>")
	case !machineAbsPath(v.Package.Path):
		return refuse(CodeInvalid, "package.path must be absolute on the assigned machine")
	case v.Package.Entrypoint == "":
		return refuse(CodeInvalid, "package.entrypoint is required")
	case v.DAG.Name != "" && v.DAG.Name != jobID:
		return refuse(CodeInvalid, "dag.name must equal the job id %s", jobID)
	case strings.TrimSpace(v.DAG.Spec) == "":
		return refuse(CodeInvalid, "dag.spec is required")
	}
	for i, c := range v.Package.CredentialRefs {
		if c.Name == "" || c.Locator == "" || (c.Kind != "file" && c.Kind != "env") {
			return refuse(CodeInvalid, "package.credential_refs[%d] needs name, kind file|env and locator", i)
		}
	}
	for i, t := range v.Targets {
		if t.Kind == "" || len(t.StableID) == 0 {
			return refuse(CodeInvalid, "targets[%d] needs kind and stable_id", i)
		}
		for k, val := range t.StableID {
			if k == "" || val == "" {
				return refuse(CodeInvalid, "targets[%d].stable_id has an empty key or value", i)
			}
		}
	}
	if err := checkDeliverables(v.ExpectedOutcome.Deliverables); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, a := range v.ReviewPolicy.PermittedActions {
		if a.Name == "" || seen[a.Name] {
			return refuse(CodeInvalid, "review_policy.permitted_actions[%d] needs a unique name", i)
		}
		if IsReservedAction(a.Name) {
			return refuse(CodeInvalid, "permitted action %q uses a reserved prefix (txe., dagu.)", a.Name)
		}
		seen[a.Name] = true
		if a.TimeoutSec <= 0 {
			return refuse(CodeInvalid, "permitted action %q needs timeout_sec", a.Name)
		}
		switch a.Idempotency {
		case "", IdempotencyKeyed, IdempotencyNone, IdempotencyReadOnly:
		default:
			return refuse(CodeInvalid, "permitted action %q idempotency must be keyed, none or read_only", a.Name)
		}
		if len(bytes.TrimSpace(a.ParamSchema)) > 0 {
			if _, err := compileParamSchema(a.ParamSchema); err != nil {
				return refuse(CodeInvalid, "permitted action %q: %v", a.Name, err)
			}
		}
	}
	applyVersionDefaults(jobID, v)
	r := &v.RetirementRules
	if r.ActiveRunPolicy != ActiveRunFinish && r.ActiveRunPolicy != ActiveRunCancel {
		return refuse(CodeInvalid, "retirement_rules.active_run_policy must be finish or cancel")
	}
	for _, rule := range []string{r.OnTargetDeleted, r.OnReplacement, r.OnCompletion} {
		if rule != RuleRetire && rule != RuleReview && rule != RuleKeep {
			return refuse(CodeInvalid, "retirement rule %q must be retire, review or keep", rule)
		}
	}
	return nil
}

// applyVersionDefaults sets the defaults and derived fields registration
// stores: retirement-rule defaults, deliverable delivery, schema, job_id,
// dag.name and dag.spec_sha256. It refuses nothing.
func applyVersionDefaults(jobID string, v *JobVersion) {
	r := &v.RetirementRules
	if r.OnTargetDeleted == "" {
		r.OnTargetDeleted = RuleRetire
	}
	if r.OnReplacement == "" {
		r.OnReplacement = RuleReview
	}
	if r.OnCompletion == "" {
		r.OnCompletion = RuleRetire
	}
	if r.ActiveRunPolicy == "" {
		r.ActiveRunPolicy = ActiveRunFinish
	}
	for i := range v.ExpectedOutcome.Deliverables {
		if v.ExpectedOutcome.Deliverables[i].Delivery == "" {
			v.ExpectedOutcome.Deliverables[i].Delivery = DeliveryMachine
		}
	}
	v.Schema = SchemaVersion
	v.JobID = jobID
	v.DAG.Name = jobID
	v.DAG.SpecSHA256 = specDigest([]byte(v.DAG.Spec))
}

func specDigest(spec []byte) string {
	sum := sha256.Sum256(spec)
	return fmt.Sprintf("sha256:%x", sum)
}

// checkDAG loads the spec without saving it and checks that it routes to the
// job's machine.
func (s *Store) checkDAG(ctx context.Context, jobID, machineID string, v *JobVersion) error {
	if s.dags == nil {
		return refuse(CodeNotReady, "DAG store is not configured")
	}
	facts, err := s.dags.CheckSpec(ctx, jobID, []byte(v.DAG.Spec))
	if err != nil {
		return refuse(CodeInvalid, "dag.spec does not load: %v", err)
	}
	if facts.WorkerSelector[machineLabel] != machineID {
		return refuse(CodeInvalid, "dag.spec worker_selector %s must be %s", machineLabel, machineID)
	}
	name, err := declaredName([]byte(v.DAG.Spec))
	if err != nil {
		return refuse(CodeInvalid, "dag.spec does not parse: %v", err)
	}
	if name != "" && name != jobID {
		// Runs take the DAG's declared name; a job's runs must carry its ID,
		// which is what admission, dispatch and run control key on.
		return refuse(CodeInvalid, "dag.spec must not declare a name other than the job id %s", jobID)
	}
	return nil
}

// declaredName returns the name the entrypoint document of spec declares,
// or "" when it declares none. Later documents are local sub-DAGs and are
// named by design.
func declaredName(spec []byte) (string, error) {
	var doc map[string]any
	if err := yaml.NewDecoder(bytes.NewReader(spec)).Decode(&doc); err != nil {
		return "", err
	}
	name, ok := doc["name"]
	if !ok || name == nil {
		return "", nil
	}
	return fmt.Sprint(name), nil
}

// TargetKey is the identity of a target: its kind and stable ID, never its name.
func TargetKey(t Target) string {
	b, _ := CanonicalJSON(map[string]any{"kind": t.Kind, "stable_id": t.StableID})
	return sha256Hex(b)
}

func keyDigest(key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", sum)
}

func requestHash(v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return sha256Hex(b), nil
}

type dedupeRecord struct {
	JobID string `json:"job_id"`
}

// Register saves a new job and writes its DAG. The job is incomplete: it
// cannot run, and no receipt is issued, until MarkReady records the package
// evidence and verifies the saved DAG.
//
// The dedupe record for (owner, project, job key) arbitrates between
// concurrent registrations of the same logical job: the job whose ID it holds
// wins; every other job is marked duplicate and stays non-runnable.
// Replaying the same job ID and request ID with the same input returns the
// stored job.
func (s *Store) Register(ctx context.Context, in RegisterInput, by Actor) (*Job, error) {
	if err := s.validateRegistration(ctx, &in); err != nil {
		return nil, err
	}
	hash, err := requestHash(in)
	if err != nil {
		return nil, err
	}
	key := keyDigest(in.JobKey)
	// Index before the job exists, so a committed job is always findable by
	// its targets; an entry for a job that never commits is re-checked and
	// ignored.
	if err := s.indexTargets(ctx, in.JobID, in.Version.Targets); err != nil {
		return nil, err
	}
	job, err := s.createJob(ctx, in, key, hash, by)
	if err != nil {
		return nil, err
	}
	dedupeID := dedupePrefix + in.OwnerID + "/" + in.ProjectID + "/" + key
	err = s.createJSON(ctx, dedupeID, dedupeRecord{JobID: in.JobID})
	if err != nil && !errors.Is(err, persis.ErrConflict) {
		return nil, err
	}
	if err != nil {
		var winner dedupeRecord
		if err := s.getJSON(ctx, dedupeID, &winner); err != nil {
			return nil, err
		}
		if winner.JobID != in.JobID {
			return nil, s.markDuplicate(ctx, in.JobID, winner.JobID, by)
		}
	}
	if job.Registration.State == RegistrationIncomplete {
		if err := s.publishCurrent(ctx, in.JobID); err != nil {
			return nil, err
		}
	}
	return job, nil
}

// withDAGLock runs fn while holding the job's DAG publication lock: a
// mutex in this process and an OS file lock across processes, which the
// kernel releases only when its holder closes it or exits, so it cannot be
// taken from a live writer. Every write of a job's DAG happens under it and
// publishes the version the job has when the lock is held.
func (s *Store) withDAGLock(ctx context.Context, jobID string, fn func() error) error {
	m, _ := s.dagLocks.LoadOrStore(jobID, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	if s.lockDir == "" {
		return fn()
	}
	if err := os.MkdirAll(s.lockDir, 0o750); err != nil {
		return fmt.Errorf("registry: DAG lock %s: %w", jobID, err)
	}
	lock := flock.New(filepath.Join(s.lockDir, jobID+".lock"))
	locked, err := lock.TryLockContext(ctx, 20*time.Millisecond)
	if err != nil {
		return fmt.Errorf("registry: DAG lock %s: %w", jobID, err)
	}
	if !locked {
		return fmt.Errorf("registry: DAG lock %s was not acquired", jobID)
	}
	defer func() { _ = lock.Unlock() }()
	return fn()
}

// publishDAG makes the saved DAG match the current version of job, a
// snapshot read under withDAGLock. A version committed after that read is
// published by its own writer once the lock is free, so the saved DAG never
// goes back to an older version than one already published. It returns the
// saved spec digest.
func (s *Store) publishDAG(ctx context.Context, job *Job) (string, error) {
	v, err := s.versionOf(ctx, job, job.Version)
	if err != nil {
		return "", err
	}
	specSHA, err := s.dags.SpecSHA256(ctx, job.JobID)
	if err != nil && !errors.Is(err, persis.ErrNotFound) {
		return "", err
	}
	if specSHA == v.DAG.SpecSHA256 {
		return specSHA, nil
	}
	if err := s.dags.WriteSpec(ctx, job.JobID, []byte(v.DAG.Spec)); err != nil {
		return "", fmt.Errorf("registry: write DAG %s: %w", job.JobID, err)
	}
	return s.dags.SpecSHA256(ctx, job.JobID)
}

// publishCurrent publishes the job's current version unless the job is a
// duplicate.
func (s *Store) publishCurrent(ctx context.Context, jobID string) error {
	return s.withDAGLock(ctx, jobID, func() error {
		job, err := s.GetJob(ctx, jobID)
		if err != nil {
			return err
		}
		if job.Registration.State == RegistrationDuplicate {
			return nil
		}
		_, err = s.publishDAG(ctx, job)
		return err
	})
}

func (s *Store) markDuplicate(ctx context.Context, jobID, winnerID string, by Actor) error {
	if _, err := s.WithJobTx(ctx, jobID, by, func(tx *JobTx) error {
		if tx.Job.Registration.State == RegistrationDuplicate {
			return nil
		}
		tx.Job.Registration.State = RegistrationDuplicate
		tx.Job.Registration.DuplicateOf = winnerID
		return tx.event(Event{Kind: EventDuplicate, To: winnerID, Reason: "job key already registered"})
	}); err != nil {
		return err
	}
	winner, err := s.GetJob(ctx, winnerID)
	if err != nil {
		return err
	}
	return &Error{Code: CodeDuplicate, Message: "job key already registered as " + winnerID, Current: winner}
}

func (s *Store) validateRegistration(ctx context.Context, in *RegisterInput) error {
	if err := ValidateID(PrefixJob, in.JobID); err != nil {
		return err
	}
	if strings.TrimSpace(in.JobKey) == "" {
		return refuse(CodeInvalid, "job_key is required")
	}
	if in.RequestID == "" {
		return refuse(CodeInvalid, "request_id is required")
	}
	project, err := s.GetProject(ctx, in.ProjectID)
	if err != nil {
		return err
	}
	machine, err := s.GetMachine(ctx, in.MachineID)
	if err != nil {
		return err
	}
	if _, err := s.GetOwner(ctx, in.OwnerID); err != nil {
		return err
	}
	if project.OwnerID != in.OwnerID || machine.OwnerID != in.OwnerID {
		return refuse(CodeInvalid, "project and machine must belong to owner %s", in.OwnerID)
	}
	if err := normalizeVersion(in.JobID, &in.Version); err != nil {
		return err
	}
	return s.checkDAG(ctx, in.JobID, in.MachineID, &in.Version)
}

// createJob inserts the job aggregate with its first version and event.
func (s *Store) createJob(ctx context.Context, in RegisterInput, key, hash string, by Actor) (*Job, error) {
	now := s.clock()
	job := &Job{
		Schema:        SchemaVersion,
		JobID:         in.JobID,
		OwnerID:       in.OwnerID,
		ProjectID:     in.ProjectID,
		MachineID:     in.MachineID,
		Version:       1,
		PackageDigest: in.Version.Package.Digest,
		DAGSpecSHA256: in.Version.DAG.SpecSHA256,
		Registration: Registration{
			State:       RegistrationIncomplete,
			JobKey:      in.JobKey,
			DedupeKey:   key,
			RequestID:   in.RequestID,
			RequestHash: hash,
		},
		Lifecycle:    LifecycleActive,
		Availability: Availability{State: AvailabilityReady},
		ExpiresAt:    in.Version.Lifetime.ExpiresAt,
		Created:      Stamp{At: now, By: by},
		Updated:      Stamp{At: now, By: by},
	}
	tx := &JobTx{Job: job, store: s, now: now, actor: by, ctx: ctx}
	v := in.Version
	v.OwnerID = in.OwnerID
	v.Version = 1
	v.Created = Stamp{At: now, By: by}
	if _, err := tx.attach(kindVersions, &v, func(string) {}); err != nil {
		return nil, err
	}
	if err := tx.event(Event{Kind: EventRegistered, To: string(RegistrationIncomplete), Detail: "job key " + in.JobKey}); err != nil {
		return nil, err
	}
	job.Revision = 1
	for _, p := range tx.pending {
		if err := s.col.Create(ctx, &persis.Record{ID: p.id, Data: p.data, CreatedAt: now, UpdatedAt: now}); err != nil {
			return nil, err
		}
	}
	data, err := json.Marshal(job)
	if err != nil {
		return nil, err
	}
	err = s.col.Create(ctx, &persis.Record{ID: jobsPrefix + in.JobID, Data: data, CreatedAt: now, UpdatedAt: now})
	if err == nil {
		return job, nil
	}
	if !errors.Is(err, persis.ErrConflict) {
		return nil, err
	}
	existing, err := s.GetJob(ctx, in.JobID)
	if err != nil {
		return nil, err
	}
	if existing.Registration.RequestID != in.RequestID || existing.Registration.RequestHash != hash {
		return nil, &Error{Code: CodeDuplicate, Message: "job id " + in.JobID + " is already registered by another request", Current: existing}
	}
	return existing, nil
}

// MarkReady completes a registration: it records the client's package
// evidence and verifies that the hub's saved DAG matches the registered
// spec, rewriting it from the registered version if it is missing or
// different. It is the only path to a receipt and to a runnable job.
func (s *Store) MarkReady(ctx context.Context, jobID string, expectedRevision int64, pkg PackageEvidence, by Actor) (*Receipt, error) {
	if s.dags == nil {
		return nil, refuse(CodeNotReady, "DAG store is not configured")
	}
	if err := ValidateID(PrefixJob, jobID); err != nil {
		return nil, err
	}
	var receipt *Receipt
	// The lock spans publication and the ready commit, so the DAG verified is
	// still the saved one when the job becomes ready. Only the version of
	// the job read under the lock is published and made ready, and with an
	// expected revision nothing is written, nor a receipt returned, unless
	// that is the revision read.
	err := s.withDAGLock(ctx, jobID, func() error {
		job, err := s.GetJob(ctx, jobID)
		if err != nil {
			return err
		}
		if expectedRevision != 0 && job.Revision != expectedRevision {
			return &Error{Code: CodeVersionConflict, Message: fmt.Sprintf("job is at revision %d, not %d", job.Revision, expectedRevision), Current: job}
		}
		dedupeID := dedupePrefix + job.OwnerID + "/" + job.ProjectID + "/" + job.Registration.DedupeKey
		var winner dedupeRecord
		if err := s.getJSON(ctx, dedupeID, &winner); err != nil {
			if ErrorCode(err) == CodeNotFound {
				return refuse(CodeNotReady, "registration of %s is incomplete; repeat the registration request", jobID)
			}
			return err
		}
		if winner.JobID != jobID {
			return refuse(CodeDuplicate, "job key is registered as %s", winner.JobID)
		}
		specSHA, err := s.publishDAG(ctx, job)
		if err != nil {
			return err
		}
		if job.Registration.State == RegistrationReady && job.Registration.Package != nil && job.Registration.Package.Digest == pkg.Digest {
			receipt = receiptOf(job)
			return nil
		}
		committed, err := s.WithJobTx(ctx, jobID, by, func(tx *JobTx) error {
			j := tx.Job
			switch j.Registration.State {
			case RegistrationReady:
				return nil
			case RegistrationDuplicate:
				return refuse(CodeDuplicate, "job is a duplicate of %s", j.Registration.DuplicateOf)
			case RegistrationIncomplete:
			}
			if j.Version != job.Version {
				return &Error{Code: CodeVersionConflict, Message: "job version changed during readiness check", Current: j}
			}
			if specSHA != j.DAGSpecSHA256 {
				return &Error{Code: CodeDAGMismatch, Message: fmt.Sprintf("saved DAG spec %s does not match registered %s", specSHA, j.DAGSpecSHA256), Current: j}
			}
			v, err := tx.CurrentVersion()
			if err != nil {
				return err
			}
			switch {
			case pkg.Digest != j.PackageDigest:
				return refuse(CodeInvalid, "package evidence digest %s does not match %s", pkg.Digest, j.PackageDigest)
			case pkg.MachineID != j.MachineID:
				return refuse(CodeInvalid, "package asserted on %s, job runs on %s", pkg.MachineID, j.MachineID)
			case pkg.Path != v.Package.Path:
				return refuse(CodeInvalid, "package asserted at %s, registered at %s", pkg.Path, v.Package.Path)
			}
			pkg.AssertedAt = tx.now
			pkg.AssertedBy = by
			now := tx.now
			j.Registration.State = RegistrationReady
			j.Registration.Package = &pkg
			j.Registration.DAGVerified = true
			j.Registration.ReadyAt = &now
			return tx.event(Event{Kind: EventReady, From: string(RegistrationIncomplete), To: string(RegistrationReady), Evidence: []string{pkg.Digest, specSHA}})
		})
		if err != nil {
			return err
		}
		receipt = receiptOf(committed)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return receipt, nil
}

// UpdateVersion records a new immutable version when expectedVersion is
// current, then writes the new DAG. The job is not runnable until MarkReady
// accepts evidence for the new package, and every open proposal is
// superseded because its binding names the old version. Replaying the same
// request ID with the same input returns the current job.
func (s *Store) UpdateVersion(ctx context.Context, jobID, requestID string, expectedVersion int, v JobVersion, by Actor) (*Job, error) {
	if requestID == "" {
		return nil, refuse(CodeInvalid, "request_id is required")
	}
	if err := normalizeVersion(jobID, &v); err != nil {
		return nil, err
	}
	hash, err := requestHash([]any{expectedVersion, v})
	if err != nil {
		return nil, err
	}
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	// Indexing is idempotent and precedes the commit, so a replay after an
	// interruption also repairs it.
	if err := s.indexTargets(ctx, jobID, v.Targets); err != nil {
		return nil, err
	}
	if job.Registration.RequestID == requestID && job.Registration.RequestHash == hash {
		return job, nil
	}
	if err := s.checkDAG(ctx, jobID, job.MachineID, &v); err != nil {
		return nil, err
	}
	committed, err := s.WithJobTx(ctx, jobID, by, func(tx *JobTx) error {
		j := tx.Job
		if j.Registration.RequestID == requestID && j.Registration.RequestHash == hash {
			return nil
		}
		if j.Version != expectedVersion {
			return &Error{Code: CodeVersionConflict, Message: fmt.Sprintf("job is at version %d, not %d", j.Version, expectedVersion), Current: j}
		}
		if j.Lifecycle.Terminal() {
			return &Error{Code: CodeLifecycle, Message: "job is " + string(j.Lifecycle) + "; reactivate it first", Current: j}
		}
		if j.Registration.State == RegistrationDuplicate {
			return refuse(CodeDuplicate, "job is a duplicate of %s", j.Registration.DuplicateOf)
		}
		nv := v
		nv.OwnerID = j.OwnerID
		nv.Version = j.Version + 1
		nv.Created = Stamp{At: tx.now, By: by}
		if _, err := tx.attach(kindVersions, &nv, func(string) {}); err != nil {
			return err
		}
		from := j.Version
		j.Version = nv.Version
		j.PackageDigest = nv.Package.Digest
		j.DAGSpecSHA256 = nv.DAG.SpecSHA256
		j.ExpiresAt = nv.Lifetime.ExpiresAt
		j.Registration.State = RegistrationIncomplete
		j.Registration.RequestID = requestID
		j.Registration.RequestHash = hash
		j.Registration.Package = nil
		j.Registration.DAGVerified = false
		j.Registration.ReadyAt = nil
		tx.resolveStaleBindings()
		affected, err := tx.supersedeProposals("job version changed")
		if err != nil {
			return err
		}
		return tx.event(Event{Kind: EventVersion, From: fmt.Sprint(from), To: fmt.Sprint(nv.Version), Affected: affected})
	})
	if err != nil {
		return nil, err
	}
	if err := s.publishCurrent(ctx, jobID); err != nil {
		return nil, err
	}
	return committed, nil
}

type projectKeyRecord struct {
	ProjectID string `json:"project_id"`
}

// EnsureProject returns the owner's project for key, creating it once. Two
// concurrent first registrations from one repository get the same project.
func (s *Store) EnsureProject(ctx context.Context, ownerID, key, name string, by Actor) (*Project, error) {
	if strings.TrimSpace(key) == "" {
		return nil, refuse(CodeInvalid, "project key is required")
	}
	if _, err := s.GetOwner(ctx, ownerID); err != nil {
		return nil, err
	}
	if name == "" {
		name = key
	}
	id, err := NewID(PrefixProject, s.clock())
	if err != nil {
		return nil, err
	}
	indexID := projectKeys + ownerID + "/" + keyDigest(key)
	if err := s.createJSON(ctx, indexID, projectKeyRecord{ProjectID: id}); err != nil {
		if !errors.Is(err, persis.ErrConflict) {
			return nil, err
		}
		var winner projectKeyRecord
		if err := s.getJSON(ctx, indexID, &winner); err != nil {
			return nil, err
		}
		id = winner.ProjectID
	}
	if p, err := s.GetProject(ctx, id); err == nil {
		return p, nil
	}
	p := Project{Schema: SchemaVersion, ProjectID: id, OwnerID: ownerID, Key: key, Name: name, Created: Stamp{At: s.clock(), By: by}}
	return createIdentity(ctx, s, projectsPrefix+id, &p, func(cur *Project) bool {
		return cur.OwnerID == ownerID && cur.Key == key
	})
}

// Installation describes this registry for client compatibility checks.
type Installation struct {
	Schema int      `json:"schema"`
	Owners []*Owner `json:"owners"`
	// Capabilities names what this registry enforces, so a client can refuse
	// to rely on a registry that only stores it (see Capabilities).
	Capabilities []string `json:"capabilities"`
}

// Capabilities this registry enforces.
const (
	// CapabilityParamSchema: a permitted action's param_schema is admitted
	// at registration (refused when it cannot be enforced exactly) and the
	// params of every action attempt are validated against it before a grant.
	CapabilityParamSchema = "param_schema"
)

// Capabilities is what this registry enforces.
func Capabilities() []string { return []string{CapabilityParamSchema} }

// ApplyVersionDefaults returns v with exactly the defaults and derived
// fields registration stores (see NormalizeVersion), and no validation: a
// version stored under earlier, looser rules compares equal to the same
// input. It is for comparing what a registry stored with what a client
// would send. v is not modified.
func ApplyVersionDefaults(jobID string, v JobVersion) (JobVersion, error) {
	out, err := copyVersion(v)
	if err != nil {
		return JobVersion{}, err
	}
	applyVersionDefaults(jobID, &out)
	return out, nil
}

func copyVersion(v JobVersion) (JobVersion, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return JobVersion{}, err
	}
	var out JobVersion
	if err := json.Unmarshal(b, &out); err != nil {
		return JobVersion{}, err
	}
	return out, nil
}

// NormalizeVersion returns v as registration stores it for job jobID: the
// same defaults and derived fields (retirement-rule defaults, deliverable
// delivery, dag.name, dag.spec_sha256, schema, job_id) after the same
// structural checks of the version itself. It is not a registration
// preflight: it does not load the DAG, check that it routes to the job's
// machine, or check owners, projects and the job's current state, which
// Register and UpdateVersion also do. Fields only the registry assigns at
// commit (owner_id, version, created) are left as given. Clients compare a
// registered version with what they would register through this one
// function. v is not modified.
func NormalizeVersion(jobID string, v JobVersion) (JobVersion, error) {
	out, err := copyVersion(v)
	if err != nil {
		return JobVersion{}, err
	}
	if err := normalizeVersion(jobID, &out); err != nil {
		return JobVersion{}, err
	}
	return out, nil
}

// GetInstallation returns the registry schema and its owners.
func (s *Store) GetInstallation(ctx context.Context) (*Installation, error) {
	out := &Installation{Schema: SchemaVersion, Capabilities: Capabilities()}
	cursor := ""
	for {
		page, err := s.col.List(ctx, persis.ListQuery{Prefix: ownersPrefix, Cursor: cursor, Limit: 100})
		if err != nil {
			return nil, err
		}
		for _, rec := range page.Records {
			var o Owner
			if err := json.Unmarshal(rec.Data, &o); err != nil {
				return nil, fmt.Errorf("registry: decode %s: %w", rec.ID, err)
			}
			out.Owners = append(out.Owners, &o)
		}
		if page.NextCursor == "" {
			return out, nil
		}
		cursor = page.NextCursor
	}
}
