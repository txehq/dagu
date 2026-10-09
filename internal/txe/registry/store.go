// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"sync"
	"time"

	"github.com/dagucloud/dagu/v2/internal/persis"
	persisfile "github.com/dagucloud/dagu/v2/internal/persis/file"
)

// Record layout inside the registry collection. Nothing is ever deleted.
//
//	owners/<own>, projects/<prj>, machines/<mch>   identity records, create-only
//	jobs/<job>                                     the job aggregate, compare-and-swap only
//	history/<job>/<kind>/<ulid>                    immutable history, create-only
//	dedupe/<own>/<prj>/<key>                        registration arbiter, create-only
//	project_keys/<own>/<key>                        project natural-key index, create-only
const (
	ownersPrefix   = "owners/"
	projectsPrefix = "projects/"
	machinesPrefix = "machines/"
	jobsPrefix     = "jobs/"
	historyPrefix  = "history/"
	dedupePrefix   = "dedupe/"
	projectKeys    = "project_keys/"
)

// History kinds, one chain each.
const (
	kindEvents    = "events"
	kindVersions  = "versions"
	kindDecisions = "decisions"
	kindReviews   = "reviews"
	kindActions   = "actions"
	kindProposals = "proposals"
)

// Dir returns the registry directory under the Dagu data directory.
func Dir(dataDir string) string {
	return filepath.Join(dataDir, "txe", "v1")
}

// DAGFacts are the parts of a loaded DAG the registry checks.
type DAGFacts struct {
	WorkerSelector map[string]string
}

// DAGStore is the hub's DAG definition store. The registry is the only
// writer of a job's DAG, so native DAG writes never carry a registration.
type DAGStore interface {
	// CheckSpec loads spec as DAG name without saving it.
	CheckSpec(ctx context.Context, name string, spec []byte) (DAGFacts, error)
	// SpecSHA256 returns "sha256:<hex>" of the saved spec, or an error
	// wrapping persis.ErrNotFound when the DAG does not exist.
	SpecSHA256(ctx context.Context, name string) (string, error)
	// WriteSpec creates or replaces the saved spec.
	WriteSpec(ctx context.Context, name string, spec []byte) error
}

// Store is the TXE job registry.
type Store struct {
	col  persis.Collection
	dags DAGStore
	runs RunControl
	now  func() time.Time
	// reauthorize re-checks a resource event reporter's permission when an
	// incomplete event is reconciled.
	reauthorize ResourceReauthorizer
	// dagLocks serializes DAG publication per job in this process; lockDir,
	// when set, extends that across processes sharing the data directory.
	dagLocks sync.Map // job ID -> *sync.Mutex
	lockDir  string
}

// Option configures a Store.
type Option func(*Store)

// WithClock overrides the store's clock (tests use a fixture clock).
func WithClock(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

// WithDAGStore supplies the hub DAG store. Registration needs it.
func WithDAGStore(d DAGStore) Option {
	return func(s *Store) { s.dags = d }
}

// New returns a registry over col.
func New(col persis.Collection, opts ...Option) (*Store, error) {
	if col == nil {
		return nil, errors.New("registry: collection is required")
	}
	s := &Store{col: col, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// NewFileStore returns a registry stored under Dir(dataDir).
func NewFileStore(dataDir string, opts ...Option) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("registry: data directory is required")
	}
	s, err := New(persisfile.NewCollection(Dir(dataDir), persisfile.WithIndentedJSON()), opts...)
	if err != nil {
		return nil, err
	}
	s.lockDir = filepath.Join(dataDir, "txe", "locks")
	return s, nil
}

func (s *Store) clock() time.Time { return s.now().UTC() }

func (s *Store) getJSON(ctx context.Context, id string, v any) error {
	rec, err := s.col.Get(ctx, id)
	if err != nil {
		if errors.Is(err, persis.ErrNotFound) {
			return refuse(CodeNotFound, "%s not found", id)
		}
		return err
	}
	if err := json.Unmarshal(rec.Data, v); err != nil {
		return fmt.Errorf("registry: decode %s: %w", id, err)
	}
	return nil
}

// createJSON inserts an immutable record. It returns persis.ErrConflict when
// the ID already exists.
func (s *Store) createJSON(ctx context.Context, id string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	now := s.clock()
	return s.col.Create(ctx, &persis.Record{ID: id, Data: data, CreatedAt: now, UpdatedAt: now})
}

// putJSON replaces an operational record that the registry itself owns.
func (s *Store) putJSON(ctx context.Context, id string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	now := s.clock()
	return s.col.Put(ctx, &persis.Record{ID: id, Data: data, CreatedAt: now, UpdatedAt: now})
}

// CreateOwner saves a new owner. The owner ID is minted by the installer.
func (s *Store) CreateOwner(ctx context.Context, o Owner, by Actor) (*Owner, error) {
	if err := ValidateID(PrefixOwner, o.OwnerID); err != nil {
		return nil, err
	}
	if o.DisplayName == "" {
		return nil, refuse(CodeInvalid, "owner display_name is required")
	}
	o.Schema = SchemaVersion
	o.Created = Stamp{At: s.clock(), By: by}
	return createIdentity(ctx, s, ownersPrefix+o.OwnerID, &o, func(cur *Owner) bool {
		return cur.DisplayName == o.DisplayName
	})
}

// GetOwner returns an owner.
func (s *Store) GetOwner(ctx context.Context, id string) (*Owner, error) {
	var o Owner
	if err := s.getJSON(ctx, ownersPrefix+id, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// CreateProject saves a new project under an existing owner.
func (s *Store) CreateProject(ctx context.Context, p Project, by Actor) (*Project, error) {
	if err := ValidateID(PrefixProject, p.ProjectID); err != nil {
		return nil, err
	}
	if _, err := s.GetOwner(ctx, p.OwnerID); err != nil {
		return nil, err
	}
	p.Schema = SchemaVersion
	p.Created = Stamp{At: s.clock(), By: by}
	return createIdentity(ctx, s, projectsPrefix+p.ProjectID, &p, func(cur *Project) bool {
		return cur.OwnerID == p.OwnerID && cur.Name == p.Name
	})
}

// GetProject returns a project.
func (s *Store) GetProject(ctx context.Context, id string) (*Project, error) {
	var p Project
	if err := s.getJSON(ctx, projectsPrefix+id, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateMachine saves a new machine under an existing owner.
func (s *Store) CreateMachine(ctx context.Context, m Machine, by Actor) (*Machine, error) {
	if err := ValidateID(PrefixMachine, m.MachineID); err != nil {
		return nil, err
	}
	if _, err := s.GetOwner(ctx, m.OwnerID); err != nil {
		return nil, err
	}
	m.Schema = SchemaVersion
	m.Created = Stamp{At: s.clock(), By: by}
	return createIdentity(ctx, s, machinesPrefix+m.MachineID, &m, func(cur *Machine) bool {
		return cur.OwnerID == m.OwnerID
	})
}

// GetMachine returns a machine.
func (s *Store) GetMachine(ctx context.Context, id string) (*Machine, error) {
	var m Machine
	if err := s.getJSON(ctx, machinesPrefix+id, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// createIdentity inserts an identity record. Replaying an identical request
// returns the stored record; a different record under the same ID is refused,
// so an ID can never be re-pointed at another owner.
func createIdentity[T any](ctx context.Context, s *Store, id string, v *T, same func(cur *T) bool) (*T, error) {
	err := s.createJSON(ctx, id, v)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, persis.ErrConflict) {
		return nil, err
	}
	var cur T
	if err := s.getJSON(ctx, id, &cur); err != nil {
		return nil, err
	}
	if same(&cur) {
		return &cur, nil
	}
	return nil, &Error{Code: CodeDuplicate, Message: id + " already exists", Current: &cur}
}

// GetJob returns the committed job aggregate.
func (s *Store) GetJob(ctx context.Context, jobID string) (*Job, error) {
	if err := ValidateID(PrefixJob, jobID); err != nil {
		return nil, err
	}
	job, _, err := s.readJob(ctx, jobID)
	return job, err
}

func (s *Store) readJob(ctx context.Context, jobID string) (*Job, []byte, error) {
	rec, err := s.col.Get(ctx, jobsPrefix+jobID)
	if err != nil {
		if errors.Is(err, persis.ErrNotFound) {
			return nil, nil, refuse(CodeNotFound, "job %s not found", jobID)
		}
		return nil, nil, err
	}
	var job Job
	if err := json.Unmarshal(rec.Data, &job); err != nil {
		return nil, nil, fmt.Errorf("registry: decode job %s: %w", jobID, err)
	}
	return &job, rec.Data, nil
}

// JobFilter selects jobs for ListJobs. Empty fields match everything.
type JobFilter struct {
	OwnerID         string
	ProjectID       string
	MachineID       string
	JobKey          string
	Lifecycle       Lifecycle
	ReviewDueBefore *time.Time
}

func (f JobFilter) match(j *Job) bool {
	switch {
	case f.OwnerID != "" && j.OwnerID != f.OwnerID,
		f.ProjectID != "" && j.ProjectID != f.ProjectID,
		f.MachineID != "" && j.MachineID != f.MachineID,
		f.JobKey != "" && j.Registration.JobKey != f.JobKey,
		f.Lifecycle != "" && j.Lifecycle != f.Lifecycle:
		return false
	}
	if f.ReviewDueBefore != nil {
		due := j.Checkpoint.NextReviewAt
		if due != nil && due.After(*f.ReviewDueBefore) {
			return false
		}
	}
	return true
}

// ListJobs returns committed job aggregates matching f, oldest first.
func (s *Store) ListJobs(ctx context.Context, f JobFilter) ([]*Job, error) {
	var out []*Job
	cursor := ""
	for {
		page, err := s.col.List(ctx, persis.ListQuery{Prefix: jobsPrefix, Cursor: cursor, Limit: 500})
		if err != nil {
			return nil, err
		}
		for _, rec := range page.Records {
			var job Job
			if err := json.Unmarshal(rec.Data, &job); err != nil {
				return nil, fmt.Errorf("registry: decode %s: %w", rec.ID, err)
			}
			if f.match(&job) {
				out = append(out, &job)
			}
		}
		if page.NextCursor == "" {
			return out, nil
		}
		cursor = page.NextCursor
	}
}

// GetVersion returns an immutable job version.
func (s *Store) GetVersion(ctx context.Context, jobID string, version int) (*JobVersion, error) {
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	return s.versionOf(ctx, job, version)
}

func (s *Store) versionOf(ctx context.Context, job *Job, version int) (*JobVersion, error) {
	if version < 1 || version > len(job.VersionRefs) {
		return nil, refuse(CodeNotFound, "job %s has no version %d", job.JobID, version)
	}
	var v JobVersion
	if err := s.getJSON(ctx, job.VersionRefs[version-1], &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// History readers. Each walks a chain from the committed head, so records
// written by a transaction that never committed are never returned.

// ListEvents returns up to limit job events, newest first.
func (s *Store) ListEvents(ctx context.Context, jobID string, limit int) ([]*Event, error) {
	return walkChain[Event](ctx, s, jobID, func(c Chains) string { return c.Events }, func(e *Event) string { return e.Prev }, limit)
}

// ListDecisions returns decisions for proposals in any state, newest first.
func (s *Store) ListDecisions(ctx context.Context, jobID string, limit int) ([]*Decision, error) {
	return walkChain[Decision](ctx, s, jobID, func(c Chains) string { return c.Decisions }, func(d *Decision) string { return d.Prev }, limit)
}

// GetDecision returns one decision by ID from the committed history.
func (s *Store) GetDecision(ctx context.Context, jobID, decisionID string) (*Decision, error) {
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	for id := job.Chains.Decisions; id != ""; {
		var d Decision
		if err := s.getJSON(ctx, id, &d); err != nil {
			return nil, fmt.Errorf("registry: history %s: %w", id, err)
		}
		if d.DecisionID == decisionID {
			return &d, nil
		}
		id = d.Prev
	}
	return nil, refuse(CodeNotFound, "decision %s not found", decisionID)
}

// ListReviews returns reviews, newest first.
func (s *Store) ListReviews(ctx context.Context, jobID string, limit int) ([]*Review, error) {
	return walkChain[Review](ctx, s, jobID, func(c Chains) string { return c.Reviews }, func(r *Review) string { return r.Prev }, limit)
}

// ListArchivedActions returns actions that left the job aggregate, newest first.
func (s *Store) ListArchivedActions(ctx context.Context, jobID string, limit int) ([]*Action, error) {
	return walkChain[Action](ctx, s, jobID, func(c Chains) string { return c.Actions }, func(a *Action) string { return a.Prev }, limit)
}

// ListArchivedProposals returns finished proposals, newest first.
func (s *Store) ListArchivedProposals(ctx context.Context, jobID string, limit int) ([]*Proposal, error) {
	return walkChain[Proposal](ctx, s, jobID, func(c Chains) string { return c.Proposals }, func(p *Proposal) string { return p.Prev }, limit)
}

func walkChain[T any](ctx context.Context, s *Store, jobID string, head func(Chains) string, prev func(*T) string, limit int) ([]*T, error) {
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	var out []*T
	for id := head(job.Chains); id != "" && (limit <= 0 || len(out) < limit); {
		var v T
		if err := s.getJSON(ctx, id, &v); err != nil {
			return nil, fmt.Errorf("registry: history %s: %w", id, err)
		}
		out = append(out, &v)
		id = prev(&v)
	}
	return out, nil
}

// pendingRecord is an immutable history record written before the aggregate
// commit that references it.
type pendingRecord struct {
	id   string
	data []byte
}

// JobTx is one atomic change to a job. Job is a private copy; the change is
// committed only if no other writer committed in between, otherwise the
// transaction function is run again on the fresh aggregate. A transaction
// function must therefore have no effect outside the JobTx.
type JobTx struct {
	Job     *Job
	store   *Store
	now     time.Time
	actor   Actor
	pending []pendingRecord
	ctx     context.Context
	changed bool
}

// Now is the transaction's clock reading.
func (tx *JobTx) Now() time.Time { return tx.now }

// Actor is the party performing the transaction.
func (tx *JobTx) Actor() Actor { return tx.actor }

// Version returns an immutable version of this job.
func (tx *JobTx) Version(v int) (*JobVersion, error) {
	return tx.store.versionOf(tx.ctx, tx.Job, v)
}

// CurrentVersion returns the job's current version.
func (tx *JobTx) CurrentVersion() (*JobVersion, error) {
	return tx.Version(tx.Job.Version)
}

// attach prepares an immutable history record of kind and links it into the
// aggregate's chain. setPrev receives the previous head before encoding.
func (tx *JobTx) attach(kind string, v any, setPrev func(prev string)) (string, error) {
	ulid, err := NewID("rec", tx.now)
	if err != nil {
		return "", err
	}
	id := historyPrefix + tx.Job.JobID + "/" + kind + "/" + ulid[len("rec_"):]
	switch kind {
	case kindEvents:
		setPrev(tx.Job.Chains.Events)
		tx.Job.Chains.Events = id
	case kindDecisions:
		setPrev(tx.Job.Chains.Decisions)
		tx.Job.Chains.Decisions = id
	case kindReviews:
		setPrev(tx.Job.Chains.Reviews)
		tx.Job.Chains.Reviews = id
	case kindActions:
		setPrev(tx.Job.Chains.Actions)
		tx.Job.Chains.Actions = id
	case kindProposals:
		setPrev(tx.Job.Chains.Proposals)
		tx.Job.Chains.Proposals = id
	case kindVersions:
		setPrev("")
		tx.Job.VersionRefs = append(tx.Job.VersionRefs, id)
	default:
		return "", fmt.Errorf("registry: unknown history kind %q", kind)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	tx.pending = append(tx.pending, pendingRecord{id: id, data: data})
	tx.changed = true
	return id, nil
}

// event appends a job history event.
func (tx *JobTx) event(e Event) error {
	id, err := NewID(PrefixEvent, tx.now)
	if err != nil {
		return err
	}
	e.EventID = id
	e.JobID = tx.Job.JobID
	e.Revision = tx.Job.Revision + 1
	e.At = tx.now
	if e.Actor.Kind == "" {
		e.Actor = tx.actor
	}
	_, err = tx.attach(kindEvents, &e, func(prev string) { e.Prev = prev })
	return err
}

// touch marks the aggregate as modified.
func (tx *JobTx) touch() { tx.changed = true }

// beforeCommit is a test hook run after history prewrites and before the
// aggregate compare-and-swap.
var beforeCommit func(jobID string) error

// WithJobTx runs fn on a private copy of the job and commits its changes in
// one compare-and-swap. On a concurrent commit it re-reads and re-runs fn.
// If fn makes no change, nothing is written and the current job is returned.
// A registry *Error from fn is returned unchanged and nothing is written.
func (s *Store) WithJobTx(ctx context.Context, jobID string, actor Actor, fn func(tx *JobTx) error) (*Job, error) {
	if err := ValidateID(PrefixJob, jobID); err != nil {
		return nil, err
	}
	backoff := 2 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		job, raw, err := s.readJob(ctx, jobID)
		if err != nil {
			return nil, err
		}
		tx := &JobTx{Job: job, store: s, now: s.clock(), actor: actor, ctx: ctx}
		tx.sweep()
		if err := fn(tx); err != nil {
			return nil, err
		}
		if !tx.changed {
			return job, nil
		}
		tx.Job.Revision++
		tx.Job.Updated = Stamp{At: tx.now, By: actor}
		committed, err := s.commit(ctx, tx, raw)
		if err == nil {
			return committed, nil
		}
		if !errors.Is(err, persis.ErrConflict) {
			return nil, err
		}
		sleep := time.Duration(rand.Int64N(int64(backoff))) //nolint:gosec // jitter
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
		backoff = min(backoff*2, time.Second)
	}
}

func (s *Store) commit(ctx context.Context, tx *JobTx, expected []byte) (*Job, error) {
	for _, p := range tx.pending {
		if err := s.col.Create(ctx, &persis.Record{ID: p.id, Data: p.data, CreatedAt: tx.now, UpdatedAt: tx.now}); err != nil {
			if errors.Is(err, persis.ErrConflict) {
				// History IDs are freshly minted; a collision is not a lost race.
				return nil, fmt.Errorf("registry: history id collision %s", p.id)
			}
			return nil, err
		}
	}
	if beforeCommit != nil {
		if err := beforeCommit(tx.Job.JobID); err != nil {
			return nil, err
		}
	}
	next, err := json.Marshal(tx.Job)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(next, expected) {
		return tx.Job, nil
	}
	if err := s.col.CompareAndSwap(ctx, jobsPrefix+tx.Job.JobID, expected, next); err != nil {
		if errors.Is(err, persis.ErrNotFound) {
			return nil, persis.ErrConflict
		}
		return nil, err
	}
	return tx.Job, nil
}
