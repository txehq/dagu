// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/dirlock"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

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
	case !filepath.IsAbs(v.Package.Path):
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
	seen := map[string]bool{}
	for i, a := range v.ReviewPolicy.PermittedActions {
		if a.Name == "" || seen[a.Name] {
			return refuse(CodeInvalid, "review_policy.permitted_actions[%d] needs a unique name", i)
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
	}
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
	if r.ActiveRunPolicy != ActiveRunFinish && r.ActiveRunPolicy != ActiveRunCancel {
		return refuse(CodeInvalid, "retirement_rules.active_run_policy must be finish or cancel")
	}
	for _, rule := range []string{r.OnTargetDeleted, r.OnReplacement, r.OnCompletion} {
		if rule != RuleRetire && rule != RuleReview && rule != RuleKeep {
			return refuse(CodeInvalid, "retirement rule %q must be retire, review or keep", rule)
		}
	}
	v.Schema = SchemaVersion
	v.JobID = jobID
	v.DAG.Name = jobID
	v.DAG.SpecSHA256 = specDigest([]byte(v.DAG.Spec))
	return nil
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
	return nil
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
		if err := s.withDAGLock(ctx, in.JobID, func() error {
			_, _, err := s.publishDAG(ctx, in.JobID)
			return err
		}); err != nil {
			return nil, err
		}
	}
	return job, nil
}

// dagLockStale is how long a silent cross-process DAG lock is honoured;
// a holder renews it every third of that.
const dagLockStale = 30 * time.Second

// withDAGLock runs fn while holding the job's DAG publication lock. Every
// write of a job's DAG happens under it, so an older request does not
// replace the DAG a newer one published. If a stalled holder loses the
// cross-process lock anyway, publishDAG converges back to the current
// version after its write.
func (s *Store) withDAGLock(ctx context.Context, jobID string, fn func() error) error {
	m, _ := s.dagLocks.LoadOrStore(jobID, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	if s.lockDir == "" {
		return fn()
	}
	dir := filepath.Join(s.lockDir, jobID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("registry: DAG lock %s: %w", jobID, err)
	}
	lock := dirlock.New(dir, &dirlock.LockOptions{StaleThreshold: dagLockStale, RetryInterval: 20 * time.Millisecond})
	if err := lock.Lock(ctx); err != nil {
		return fmt.Errorf("registry: DAG lock %s: %w", jobID, err)
	}
	done := make(chan struct{})
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		t := time.NewTicker(dagLockStale / 3)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				_ = lock.Heartbeat(ctx)
			}
		}
	}()
	defer func() {
		close(done)
		<-renewed
		_ = lock.Unlock()
	}()
	return fn()
}

// publishDAG makes the saved DAG match the job's committed current version.
// It never writes the version a caller started from, only the one committed
// now, and after writing it re-reads both, so a writer that raced a newer
// publication writes the newer version again. It must run under withDAGLock
// and returns the job it published for and the saved spec digest.
func (s *Store) publishDAG(ctx context.Context, jobID string) (*Job, string, error) {
	for attempt := 0; ; attempt++ {
		job, err := s.GetJob(ctx, jobID)
		if err != nil {
			return nil, "", err
		}
		if job.Registration.State == RegistrationDuplicate {
			return job, "", nil
		}
		v, err := s.versionOf(ctx, job, job.Version)
		if err != nil {
			return nil, "", err
		}
		specSHA, err := s.dags.SpecSHA256(ctx, jobID)
		if err != nil && !errors.Is(err, persis.ErrNotFound) {
			return nil, "", err
		}
		if specSHA == v.DAG.SpecSHA256 {
			return job, specSHA, nil
		}
		if attempt == 5 {
			return nil, "", fmt.Errorf("registry: DAG %s keeps changing during publication", jobID)
		}
		if err := s.dags.WriteSpec(ctx, jobID, []byte(v.DAG.Spec)); err != nil {
			return nil, "", fmt.Errorf("registry: write DAG %s: %w", jobID, err)
		}
	}
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
	// still the saved one when the job becomes ready.
	err := s.withDAGLock(ctx, jobID, func() error {
		job, err := s.GetJob(ctx, jobID)
		if err != nil {
			return err
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
		published, specSHA, err := s.publishDAG(ctx, jobID)
		if err != nil {
			return err
		}
		if published.Registration.State == RegistrationReady && published.Registration.Package != nil && published.Registration.Package.Digest == pkg.Digest {
			receipt = receiptOf(published)
			return nil
		}
		// The revision names the job state the caller checked; only the
		// version of that state is made ready.
		if expectedRevision != 0 && published.Revision != expectedRevision {
			return &Error{Code: CodeVersionConflict, Message: fmt.Sprintf("job is at revision %d, not %d", published.Revision, expectedRevision), Current: published}
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
			if j.Version != published.Version {
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
		affected, err := tx.supersedeProposals("job version changed")
		if err != nil {
			return err
		}
		return tx.event(Event{Kind: EventVersion, From: fmt.Sprint(from), To: fmt.Sprint(nv.Version), Affected: affected})
	})
	if err != nil {
		return nil, err
	}
	if err := s.withDAGLock(ctx, jobID, func() error {
		_, _, err := s.publishDAG(ctx, jobID)
		return err
	}); err != nil {
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
}

// GetInstallation returns the registry schema and its owners.
func (s *Store) GetInstallation(ctx context.Context) (*Installation, error) {
	out := &Installation{Schema: SchemaVersion}
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
