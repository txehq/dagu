// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	// Registers step executors so DAG specs load as they do in the server.
	_ "github.com/dagucloud/dagu/v2/internal/runtime/builtin"
)

type fixture struct {
	t       *testing.T
	ctx     context.Context
	store   *Store
	dags    DAGStore
	dagsDir string
	now     time.Time
	mu      sync.Mutex
	owner   string
	project string
	machine string
}

var (
	cli    = Actor{Kind: ActorCLI, ID: "cc3-test", Session: "cc3-test"}
	person = Actor{Kind: ActorHuman, ID: "connor"}
	agent  = Actor{Kind: ActorReviewer, ID: "reviewer"}
)

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{t: t, ctx: context.Background(), now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	f.dagsDir = filepath.Join(dir, "dags")
	f.dags = NewDAGStore(persis.NewDAGRepository(dag.NewStore(f.dagsDir), persis.DAGRepositoryOptions{}))
	s, err := NewFileStore(filepath.Join(dir, "data"), WithClock(f.clock), WithDAGStore(f.dags))
	require.NoError(t, err)
	f.store = s
	f.owner = f.mint(PrefixOwner)
	f.machine = f.mint(PrefixMachine)
	_, err = s.CreateOwner(f.ctx, Owner{OwnerID: f.owner, DisplayName: "Connor Wang"}, cli)
	require.NoError(t, err)
	_, err = s.CreateMachine(f.ctx, Machine{MachineID: f.machine, OwnerID: f.owner, DisplayName: "laptop"}, cli)
	require.NoError(t, err)
	p, err := s.EnsureProject(f.ctx, f.owner, "github.com/txehq/txe", "txe", cli)
	require.NoError(t, err)
	f.project = p.ProjectID
	return f
}

func (f *fixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func (f *fixture) mint(p Prefix) string {
	id, err := NewID(p, time.Now())
	require.NoError(f.t, err)
	return id
}

func (f *fixture) spec(machine string) string {
	return fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", machine)
}

func (f *fixture) version(digestByte byte) JobVersion {
	return JobVersion{
		Title:   "volume monitor",
		Purpose: "Watch the fixture volume until it is deleted",
		Package: Package{
			Digest:     fmt.Sprintf("sha256:%064x", digestByte),
			Path:       "/Users/connor/.local/share/txe-dagu/packages/job/" + string(rune('a'+digestByte)),
			Entrypoint: "run.sh",
		},
		DAG: DAGRef{Spec: f.spec(f.machine)},
		Targets: []Target{{
			Kind:        "kubernetes.volume",
			StableID:    map[string]string{"cluster_uid": "c-1", "uid": "v-1"},
			DisplayName: "pvc-data",
		}},
		ReviewPolicy: ReviewPolicy{
			MaxAttempts: 2,
			PermittedActions: []PermittedAction{
				{Name: "diagnose", TimeoutSec: 60, Routine: true, Idempotency: IdempotencyReadOnly},
				{Name: "restart", TimeoutSec: 60, Routine: true, Idempotency: IdempotencyNone},
				{Name: "resize", TimeoutSec: 120},
			},
		},
	}
}

func (f *fixture) register(jobKey string) *Job {
	f.t.Helper()
	jobID := f.mint(PrefixJob)
	job, err := f.store.Register(f.ctx, RegisterInput{
		JobID: jobID, RequestID: "req-" + jobID, OwnerID: f.owner, ProjectID: f.project, MachineID: f.machine,
		JobKey: jobKey, Version: f.version(1),
	}, cli)
	require.NoError(f.t, err)
	return job
}

func (f *fixture) ready(jobKey string) *Job {
	f.t.Helper()
	job := f.register(jobKey)
	v, err := f.store.GetVersion(f.ctx, job.JobID, 1)
	require.NoError(f.t, err)
	_, err = f.store.MarkReady(f.ctx, job.JobID, 0, PackageEvidence{Digest: job.PackageDigest, Path: v.Package.Path, MachineID: f.machine}, cli)
	require.NoError(f.t, err)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(f.t, err)
	return got
}

func (f *fixture) tx(jobID string, actor Actor, fn func(tx *JobTx) error) (*Job, error) {
	return f.store.WithJobTx(f.ctx, jobID, actor, fn)
}

func code(t *testing.T, err error) Code {
	t.Helper()
	require.Error(t, err)
	return ErrorCode(err)
}

func TestIDs(t *testing.T) {
	id, err := NewID(PrefixJob, time.Now())
	require.NoError(t, err)
	require.NoError(t, ValidateID(PrefixJob, id))
	assert.Error(t, ValidateID(PrefixOwner, id))
	assert.Error(t, ValidateID(PrefixJob, "job_lowercase0000000000000000"))

	a, err := DerivedID(PrefixAction, "rev_x", "diagnose", map[string]any{"b": 1, "a": 2})
	require.NoError(t, err)
	b, err := DerivedID(PrefixAction, "rev_x", "diagnose", map[string]any{"a": 2, "b": 1})
	require.NoError(t, err)
	assert.Equal(t, a, b, "derived ids ignore key order")
	require.NoError(t, ValidateID(PrefixAction, a))

	c, err := CanonicalJSON(json.RawMessage(`{"z": 1.50, "a": "<x>"}`))
	require.NoError(t, err)
	assert.Equal(t, `{"a":"<x>","z":1.50}`, string(c))
}

// Registration is incomplete and non-runnable until MarkReady verifies the
// DAG the registry wrote and records package evidence.
func TestRegisterThenReady(t *testing.T) {
	f := newFixture(t)
	job := f.register("health:pvc-data")
	assert.Equal(t, RegistrationIncomplete, job.Registration.State)
	assert.False(t, job.Runnable())

	saved, err := os.ReadFile(filepath.Join(f.dagsDir, job.JobID+".yaml"))
	require.NoError(t, err)
	assert.Equal(t, f.spec(f.machine), string(saved), "the registry writes the DAG")
	assert.Equal(t, specDigest(saved), job.DAGSpecSHA256)

	_, err = f.store.MarkReady(f.ctx, job.JobID, 0, PackageEvidence{Digest: job.PackageDigest, Path: "/elsewhere", MachineID: f.machine}, cli)
	assert.Equal(t, CodeInvalid, code(t, err))

	// A DAG deleted or edited outside the registry is rewritten from the version.
	require.NoError(t, os.WriteFile(filepath.Join(f.dagsDir, job.JobID+".yaml"), []byte(f.spec(f.machine)+"# edited\n"), 0o600))
	v, err := f.store.GetVersion(f.ctx, job.JobID, 1)
	require.NoError(t, err)
	receipt, err := f.store.MarkReady(f.ctx, job.JobID, 0, PackageEvidence{Digest: job.PackageDigest, Path: v.Package.Path, MachineID: f.machine}, cli)
	require.NoError(t, err)
	assert.Equal(t, RegistrationReady, receipt.Registration)
	saved, err = os.ReadFile(filepath.Join(f.dagsDir, job.JobID+".yaml"))
	require.NoError(t, err)
	assert.Equal(t, f.spec(f.machine), string(saved))

	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.True(t, got.Runnable())
	events, err := f.store.ListEvents(f.ctx, job.JobID, 0)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, EventReady, events[0].Kind)
	assert.Equal(t, EventRegistered, events[1].Kind)
}

func TestRegisterRejectsSpecForAnotherMachine(t *testing.T) {
	f := newFixture(t)
	v := f.version(1)
	v.DAG.Spec = f.spec(f.mint(PrefixMachine))
	jobID := f.mint(PrefixJob)
	_, err := f.store.Register(f.ctx, RegisterInput{JobID: jobID, RequestID: "r", OwnerID: f.owner, ProjectID: f.project, MachineID: f.machine, JobKey: "k", Version: v}, cli)
	assert.Equal(t, CodeInvalid, code(t, err))
	_, err = f.store.GetJob(f.ctx, jobID)
	assert.Equal(t, CodeNotFound, code(t, err))
}

// IT-02: concurrent registrations of one logical job yield one runnable job;
// the others are recorded as duplicates. A replay returns the stored job.
func TestRegisterConcurrentDuplicates(t *testing.T) {
	f := newFixture(t)
	const n = 6
	ids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		ids[i] = f.mint(PrefixJob)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.store.Register(f.ctx, RegisterInput{
				JobID: ids[i], RequestID: "r", OwnerID: f.owner, ProjectID: f.project, MachineID: f.machine,
				JobKey: "collect:daily", Version: f.version(1),
			}, cli)
		}(i)
	}
	wg.Wait()
	winners := 0
	for i, err := range errs {
		if err == nil {
			winners++
			continue
		}
		assert.Equal(t, CodeDuplicate, ErrorCode(err))
		job, getErr := f.store.GetJob(f.ctx, ids[i])
		require.NoError(t, getErr)
		assert.Equal(t, RegistrationDuplicate, job.Registration.State)
		assert.False(t, job.Runnable())
	}
	assert.Equal(t, 1, winners)

	jobs, err := f.store.ListJobs(f.ctx, JobFilter{JobKey: "collect:daily"})
	require.NoError(t, err)
	assert.Len(t, jobs, n, "duplicates are retained, not deleted")

	// Replay of the same request is idempotent; a different request reusing
	// the job ID is refused.
	winner := ""
	for i, err := range errs {
		if err == nil {
			winner = ids[i]
		}
	}
	again, err := f.store.Register(f.ctx, RegisterInput{JobID: winner, RequestID: "r", OwnerID: f.owner, ProjectID: f.project, MachineID: f.machine, JobKey: "collect:daily", Version: f.version(1)}, cli)
	require.NoError(t, err)
	assert.Equal(t, int64(1), again.Revision)
	_, err = f.store.Register(f.ctx, RegisterInput{JobID: winner, RequestID: "other", OwnerID: f.owner, ProjectID: f.project, MachineID: f.machine, JobKey: "collect:daily", Version: f.version(2)}, cli)
	assert.Equal(t, CodeDuplicate, code(t, err))
}

func TestEnsureProjectConcurrent(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	got := make([]string, 8)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := f.store.EnsureProject(f.ctx, f.owner, "github.com/txehq/new", "", cli)
			if assert.NoError(t, err) {
				got[i] = p.ProjectID
			}
		}(i)
	}
	wg.Wait()
	for _, id := range got {
		assert.Equal(t, got[0], id)
	}
}

// Concurrent transactions on one job all commit; none is lost.
func TestWithJobTxRetriesConflicts(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	const n = 10
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
				return tx.Observe(Observation{State: AvailabilityWorkerOffline, Detail: fmt.Sprint(i)})
			})
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, job.Revision+n, got.Revision)
	assert.Len(t, got.Exceptions, n)
}

// A crash after history prewrites and before the aggregate commit leaves
// nothing visible, and an aborted transaction writes nothing.
func TestUncommittedHistoryIsInvisible(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	before, err := f.store.ListEvents(f.ctx, job.JobID, 0)
	require.NoError(t, err)

	beforeCommit = func(string) error { return errors.New("crash") }
	_, err = f.tx(job.JobID, person, func(tx *JobTx) error {
		return tx.Transition(Transition{Op: OpRetire, Reason: RetireManual})
	})
	beforeCommit = nil
	require.Error(t, err)

	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle)
	after, err := f.store.ListEvents(f.ctx, job.JobID, 0)
	require.NoError(t, err)
	assert.Len(t, after, len(before))

	_, err = f.tx(job.JobID, person, func(tx *JobTx) error {
		if err := tx.Transition(Transition{Op: OpPause}); err != nil {
			return err
		}
		return refuse(CodeInvalid, "abort")
	})
	assert.Equal(t, CodeInvalid, code(t, err))
	got, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, got.Lifecycle)
	assert.Equal(t, job.Revision, got.Revision)
}

func acquire(t *testing.T, f *fixture, jobID string, kind ClaimKind, ttl time.Duration) *Claim {
	t.Helper()
	var c *Claim
	_, err := f.tx(jobID, agent, func(tx *JobTx) error {
		var err error
		c, err = tx.AcquireClaim(kind, Reviewer{MachineID: f.machine}, ttl)
		return err
	})
	require.NoError(t, err)
	return c
}

func routine(t *testing.T, f *fixture, job *Job, c *Claim, name string) (string, *Grant, error) {
	t.Helper()
	review, err := ReviewID(job.JobID, job.Checkpoint.Version)
	require.NoError(t, err)
	spec := ActionSpec{Name: name, Params: json.RawMessage(`{"n":1}`)}
	actionID, err := RoutineActionID(review, spec)
	require.NoError(t, err)
	var g *Grant
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		var err error
		g, err = tx.Authorize(EffectRequest{ActionID: actionID, JobVersion: job.Version, PackageDigest: job.PackageDigest,
			Routine: &RoutineEffect{ReviewID: review, ClaimID: c.ClaimID, Fence: c.Fence, Spec: spec}})
		return err
	})
	return actionID, g, err
}

// IT-11: one live claim drives actions; a crashed reviewer's claim expires
// and is taken over with a higher fence, its late writes are refused, and
// its interrupted action is uncertain (failed when read-only), never re-run.
func TestClaimFencing(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c1 := acquire(t, f, job.JobID, ClaimReview, time.Minute)
	_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.AcquireClaim(ClaimReview, Reviewer{}, time.Minute)
		return err
	})
	assert.Equal(t, CodeClaimHeld, code(t, err))

	restartID, g1, err := routine(t, f, job, c1, "restart")
	require.NoError(t, err)
	diagID, _, err := routine(t, f, job, c1, "diagnose")
	require.NoError(t, err)
	_, _, err = routine(t, f, job, c1, "restart")
	assert.Equal(t, CodeActionExists, code(t, err), "a replayed intent is not re-run")

	f.advance(2 * time.Minute)
	c2 := acquire(t, f, job.JobID, ClaimReview, time.Minute)
	assert.Equal(t, c1.Fence+1, c2.Fence)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, ActionUncertain, got.Actions[restartID].State)
	assert.Equal(t, ActionFailed, got.Actions[diagID].State, "read-only actions are failed, not uncertain")

	// The old reviewer's late writes are refused.
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: restartID, GrantID: g1.GrantID, ClaimID: c1.ClaimID, Fence: c1.Fence, State: ActionSucceeded, Receipt: "r"})
		return err
	})
	assert.Equal(t, CodeClaimStale, code(t, err))
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.AdvanceCheckpoint(c1.ClaimID, c1.Fence, 0, Checkpoint{})
		return err
	})
	assert.Equal(t, CodeClaimStale, code(t, err))

	// The new holder reconciles with the stored grant, with an audit link.
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: restartID, GrantID: "grt_00000000000000000000000000", ClaimID: c2.ClaimID, Fence: c2.Fence, State: ActionNotApplied})
		return err
	})
	assert.Equal(t, CodeGrantInvalid, code(t, err), "possessing the action id is not enough")
	settled, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: restartID, GrantID: g1.GrantID, ClaimID: c2.ClaimID, Fence: c2.Fence, State: ActionNotApplied})
		return err
	})
	require.NoError(t, err)
	assert.Equal(t, c2.ClaimID, settled.Actions[restartID].SettledUnderClaim)

	// A failed or not-applied action may be retried within its attempt bound.
	_, g2, err := routine(t, f, job, c2, "restart")
	require.NoError(t, err)
	assert.Equal(t, 2, g2.Attempt)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: restartID, GrantID: g2.GrantID, ClaimID: c2.ClaimID, Fence: c2.Fence, State: ActionFailed})
		return err
	})
	require.NoError(t, err)
	_, _, err = routine(t, f, job, c2, "restart")
	assert.Equal(t, CodeActionExists, code(t, err), "attempts are bounded")
}

func TestRoutineAuthorizationRules(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)

	_, _, err := routine(t, f, job, c, "resize")
	assert.Equal(t, CodeNotPermitted, code(t, err), "non-routine actions need approval")

	actionID, g, err := routine(t, f, job, c, "restart")
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: c.ClaimID, Fence: c.Fence, State: ActionSucceeded})
		return err
	})
	assert.Equal(t, CodeInvalid, code(t, err), "success needs a receipt")
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: c.ClaimID, Fence: c.Fence, State: ActionSucceeded, Receipt: "pod restarted"})
		return err
	})
	require.NoError(t, err)

	// Recording the review and advancing the checkpoint ends the episode: the
	// finished action leaves the aggregate for history, and the same intent in
	// the old episode is refused.
	review, err := ReviewID(job.JobID, 0)
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		if err := tx.RecordReview(c.ClaimID, c.Fence, Review{ReviewID: review, Outcome: ReviewAct}); err != nil {
			return err
		}
		_, err := tx.AdvanceCheckpoint(c.ClaimID, c.Fence, 0, Checkpoint{LastReviewID: review})
		return err
	})
	require.NoError(t, err)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Empty(t, got.Actions)
	archived, err := f.store.ListArchivedActions(f.ctx, job.JobID, 0)
	require.NoError(t, err)
	require.Len(t, archived, 1)
	assert.Equal(t, ActionSucceeded, archived[0].State)
	reviews, err := f.store.ListReviews(f.ctx, job.JobID, 0)
	require.NoError(t, err)
	require.Len(t, reviews, 1)

	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.Authorize(EffectRequest{ActionID: actionID, JobVersion: got.Version, PackageDigest: got.PackageDigest,
			Routine: &RoutineEffect{ReviewID: review, ClaimID: c.ClaimID, Fence: c.Fence, Spec: ActionSpec{Name: "restart", Params: json.RawMessage(`{"n":1}`)}}})
		return err
	})
	assert.Equal(t, CodeClaimStale, code(t, err), "an old episode cannot act again")

	// Replaying the recorded review is a no-op.
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		return tx.RecordReview(c.ClaimID, c.Fence, Review{ReviewID: review, Outcome: ReviewAct})
	})
	require.NoError(t, err)
}

func TestGrantExpiryBecomesUncertain(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	actionID, _, err := routine(t, f, job, c, "restart")
	require.NoError(t, err)
	f.advance(61 * time.Second)
	got, err := f.tx(job.JobID, agent, func(*JobTx) error { return nil })
	require.NoError(t, err)
	assert.Equal(t, ActionUncertain, got.Actions[actionID].State)
}

func propose(t *testing.T, f *fixture, job *Job, c *Claim, verdicts ...Verdict) *Proposal {
	t.Helper()
	var p *Proposal
	_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
		var err error
		p, err = tx.PutProposal(c.ClaimID, c.Fence, Proposal{
			ProposalID: f.mint(PrefixProposal), Question: "Resize the volume?",
			Action:          ActionSpec{Name: "resize", Target: &Target{Kind: "kubernetes.volume", StableID: map[string]string{"cluster_uid": "c-1", "uid": "v-1"}}, Params: json.RawMessage(`{"size":"20Gi"}`)},
			AllowedVerdicts: verdicts,
		})
		return err
	})
	require.NoError(t, err)
	return p
}

func decide(f *fixture, job string, p *Proposal, verdict Verdict, next ProposalState, key string) (*Decision, error) {
	var d *Decision
	_, err := f.tx(job, person, func(tx *JobTx) error {
		cur := tx.Job.Proposals[p.ProposalID]
		if cur == nil {
			return refuse(CodeProposalState, "gone")
		}
		var err error
		d, err = tx.AppendDecision(Decision{DecisionID: f.mint(PrefixDecision), ProposalID: p.ProposalID, ProposalRevision: cur.Revision,
			BindingDigest: cur.BindingDigest, Verdict: verdict, IdempotencyKey: key}, next)
		return err
	})
	return d, err
}

// IT-08/IT-09/IT-10: an approval authorizes exactly one action under an
// execution claim; a rejected proposal never runs; a material change
// invalidates an approval before dispatch.
func TestApprovedActionFlow(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	rc := acquire(t, f, job.JobID, ClaimReview, time.Minute)
	p := propose(t, f, job, rc, VerdictApprove, VerdictReject)
	assert.Equal(t, job.PackageDigest, p.PackageDigest)

	_, err := decide(f, job.JobID, p, VerdictSnooze, ProposalSnoozed, "k0")
	assert.Equal(t, CodeNotPermitted, code(t, err), "verdict outside allowed_verdicts")
	d, err := decide(f, job.JobID, p, VerdictApprove, ProposalDecided, "k1")
	require.NoError(t, err)
	_, err = decide(f, job.JobID, p, VerdictApprove, ProposalDecided, "k1")
	assert.Equal(t, CodeDuplicate, code(t, err), "replayed decision is recognized")

	f.advance(2 * time.Minute)
	actionID, err := ApprovedActionID(p.ProposalID, d.DecisionID)
	require.NoError(t, err)
	authorize := func(c *Claim) (*Grant, error) {
		var g *Grant
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			var err error
			g, err = tx.Authorize(EffectRequest{ActionID: actionID, JobVersion: job.Version, PackageDigest: job.PackageDigest,
				Approved: &ApprovedEffect{ProposalID: p.ProposalID, DecisionID: d.DecisionID, ClaimID: c.ClaimID, Fence: c.Fence}})
			return err
		})
		return g, err
	}
	rc2 := acquire(t, f, job.JobID, ClaimReview, time.Minute)
	_, err = authorize(rc2)
	assert.Equal(t, CodeClaimStale, code(t, err), "approved effects need an execution claim")
	f.advance(2 * time.Minute)
	ec := acquire(t, f, job.JobID, ClaimExecution, time.Minute)
	g, err := authorize(ec)
	require.NoError(t, err)
	_, err = authorize(ec)
	assert.Equal(t, CodeActionExists, code(t, err), "one approval, one effect")
	got, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: ec.ClaimID, Fence: ec.Fence, State: ActionSucceeded, Receipt: "resized"})
		return err
	})
	require.NoError(t, err)
	assert.Empty(t, got.Proposals)
	archived, err := f.store.ListArchivedProposals(f.ctx, job.JobID, 0)
	require.NoError(t, err)
	require.Len(t, archived, 1)
	assert.Equal(t, ProposalExecuted, archived[0].State)
	decisions, err := f.store.ListDecisions(f.ctx, job.JobID, 0)
	require.NoError(t, err)
	assert.Len(t, decisions, 1)
}

func TestMaterialChangeInvalidatesApproval(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	rc := acquire(t, f, job.JobID, ClaimReview, time.Minute)
	p := propose(t, f, job, rc)
	d, err := decide(f, job.JobID, p, VerdictApprove, ProposalDecided, "")
	require.NoError(t, err)

	_, err = f.store.UpdateVersion(f.ctx, job.JobID, "upd-1", 1, f.version(2), cli)
	require.NoError(t, err)
	updated, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, 2, updated.Version)
	assert.Equal(t, RegistrationIncomplete, updated.Registration.State, "new package must be asserted")
	assert.Empty(t, updated.Proposals)
	archived, err := f.store.ListArchivedProposals(f.ctx, job.JobID, 0)
	require.NoError(t, err)
	require.Len(t, archived, 1)
	assert.Equal(t, ProposalSuperseded, archived[0].State)

	_, err = f.store.UpdateVersion(f.ctx, job.JobID, "upd-2", 1, f.version(3), cli)
	assert.Equal(t, CodeVersionConflict, code(t, err), "stale update cannot overwrite")
	_, err = f.store.UpdateVersion(f.ctx, job.JobID, "upd-1", 1, f.version(2), cli)
	require.NoError(t, err, "replayed update is idempotent")

	actionID, err := ApprovedActionID(p.ProposalID, d.DecisionID)
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.Authorize(EffectRequest{ActionID: actionID, JobVersion: updated.Version, PackageDigest: updated.PackageDigest,
			Approved: &ApprovedEffect{ProposalID: p.ProposalID, DecisionID: d.DecisionID}})
		return err
	})
	assert.Equal(t, CodeNotReady, code(t, err))
}

// IT-13: retirement stops follow-ups in the same commit, keeps history, and
// leaves in-flight effects to be reconciled; nothing but a person revives it.
func TestRetirementStopsFollowUps(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	p := propose(t, f, job, c)
	actionID, g, err := routine(t, f, job, c, "restart")
	require.NoError(t, err)

	retired, err := f.tx(job.JobID, person, func(tx *JobTx) error {
		return tx.Transition(Transition{Op: OpRetire, Reason: RetireManual, Detail: "experiment over", Evidence: []string{"chat:1"},
			Affected: []Affected{{RunID: "run-1", Disposition: DispositionAllowedToFinish}}})
	})
	require.NoError(t, err)
	assert.Equal(t, LifecycleRetired, retired.Lifecycle)
	require.NotNil(t, retired.Retirement)
	assert.Equal(t, RetireManual, retired.Retirement.Reason)
	assert.Equal(t, ActiveRunFinish, retired.Retirement.ActiveRunPolicy)
	assert.ElementsMatch(t, []Affected{
		{RunID: "run-1", Disposition: DispositionAllowedToFinish},
		{ProposalID: p.ProposalID, Disposition: DispositionSuperseded},
		{ActionID: actionID, Disposition: DispositionInFlightReconcile},
	}, retired.Retirement.Affected)
	assert.False(t, retired.Runnable())

	// Stale reviewer, decisions and new claims cannot act on or revive it.
	_, _, err = routine(t, f, job, c, "diagnose")
	assert.Equal(t, CodeLifecycle, code(t, err))
	_, err = decide(f, job.JobID, p, VerdictApprove, ProposalDecided, "")
	assert.Equal(t, CodeProposalState, code(t, err))
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.AcquireClaim(ClaimReview, Reviewer{}, time.Minute)
		return err
	})
	assert.Equal(t, CodeLifecycle, code(t, err))
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error { return tx.Transition(Transition{Op: OpResume}) })
	assert.Equal(t, CodeTransition, code(t, err))
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error { return tx.Transition(Transition{Op: OpReactivate}) })
	assert.Equal(t, CodeNotPermitted, code(t, err))
	_, err = f.store.UpdateVersion(f.ctx, job.JobID, "u", 1, f.version(2), cli)
	assert.Equal(t, CodeLifecycle, code(t, err))

	// The in-flight action's outcome is still recorded.
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: c.ClaimID, Fence: c.Fence, State: ActionSucceeded, Receipt: "done"})
		return err
	})
	require.NoError(t, err)

	revived, err := f.tx(job.JobID, person, func(tx *JobTx) error { return tx.Transition(Transition{Op: OpReactivate, Detail: "needed again"}) })
	require.NoError(t, err)
	assert.Equal(t, LifecycleActive, revived.Lifecycle)
	events, err := f.store.ListEvents(f.ctx, job.JobID, 0)
	require.NoError(t, err)
	assert.Equal(t, string(LifecycleActive), events[0].To)
	assert.Equal(t, string(LifecycleRetired), events[1].To)
	assert.Equal(t, string(RetireManual), events[1].Reason)
}

func TestReconcileClaimOnRetiredJob(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Minute)
	actionID, g, err := routine(t, f, job, c, "restart")
	require.NoError(t, err)
	_, err = f.tx(job.JobID, person, func(tx *JobTx) error {
		return tx.Transition(Transition{Op: OpComplete, Detail: "validation passed"})
	})
	require.NoError(t, err)

	f.advance(2 * time.Minute)
	rc := acquire(t, f, job.JobID, ClaimReconcile, time.Minute)
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, LifecycleCompleted, got.Lifecycle)
	assert.Equal(t, RetireCompleted, got.Retirement.Reason)
	assert.Equal(t, ActionUncertain, got.Actions[actionID].State)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.SettleAction(Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: rc.ClaimID, Fence: rc.Fence, State: ActionNotApplied})
		return err
	})
	require.NoError(t, err)
	_, _, err = routine(t, f, got, rc, "diagnose")
	assert.Equal(t, CodeLifecycle, code(t, err), "a reconcile claim never authorizes")
}

// IT-15: offline, auth and unreachable observations open exceptions but never
// change the lifecycle.
func TestObservationsNeverRetire(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	for _, st := range []AvailabilityState{AvailabilityWorkerOffline, AvailabilityAuthRequired, AvailabilityTargetUnreachable} {
		got, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			return tx.Observe(Observation{State: st, Detail: "fixture"})
		})
		require.NoError(t, err)
		assert.Equal(t, LifecycleActive, got.Lifecycle)
		assert.Equal(t, st, got.Availability.State)
	}
	got, err := f.tx(job.JobID, agent, func(tx *JobTx) error { return tx.Observe(Observation{State: AvailabilityReady}) })
	require.NoError(t, err)
	assert.Len(t, got.Exceptions, 3)
	for _, e := range got.Exceptions {
		assert.NotNil(t, e.ResolvedAt)
	}
}

// A rejected proposal leaves the aggregate, but its pending native task
// completion stays retryable and is found by decision ID.
func TestNativeResumeSurvivesClosedProposal(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Minute)
	var p *Proposal
	_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
		var err error
		p, err = tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: f.mint(PrefixProposal), Action: ActionSpec{Name: "resize"},
			NativeTask: &NativeTask{DAG: "txe-decide-x", RunID: "r1", StepID: "decide"}})
		return err
	})
	require.NoError(t, err)
	d, err := decide(f, job.JobID, p, VerdictReject, ProposalRejected, "")
	require.NoError(t, err)
	assert.Equal(t, "pending", d.NativeResume)

	got, err := f.tx(job.JobID, person, func(tx *JobTx) error {
		pending := tx.PendingNativeResumes()
		require.Len(t, pending, 1)
		assert.Equal(t, d.DecisionID, pending[0].DecisionID)
		return tx.MarkNativeResumed(d.DecisionID)
	})
	require.NoError(t, err)
	assert.Empty(t, got.NativeResumes)
	stored, err := f.store.GetDecision(f.ctx, job.JobID, d.DecisionID)
	require.NoError(t, err)
	assert.Equal(t, VerdictReject, stored.Verdict)
}
