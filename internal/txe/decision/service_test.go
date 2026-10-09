// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package decision

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/humantask"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// memDAGs is the hub DAG store, kept in memory: the registry under test is
// real and file-backed.
type memDAGs struct {
	mu    sync.Mutex
	specs map[string][]byte
}

func (m *memDAGs) CheckSpec(_ context.Context, _ string, spec []byte) (registry.DAGFacts, error) {
	for line := range strings.SplitSeq(string(spec), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "txe.machine:"); ok {
			return registry.DAGFacts{WorkerSelector: map[string]string{"txe.machine": strings.TrimSpace(v)}}, nil
		}
	}
	return registry.DAGFacts{}, nil
}

func (m *memDAGs) SpecSHA256(_ context.Context, name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	spec, ok := m.specs[name]
	if !ok {
		return "", fmt.Errorf("dag %s: %w", name, persis.ErrNotFound)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(spec)), nil
}

func (m *memDAGs) WriteSpec(_ context.Context, name string, spec []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.specs[name] = append([]byte(nil), spec...)
	return nil
}

// memRuns is Dagu's run history as the registry sees it: each recorded run's
// latest attempt. Unknown runs are not found.
type memRuns struct {
	mu       sync.Mutex
	attempts map[string]registry.RunAttempt
}

// add records runID with a failed first attempt of the DAG with digest.
func (m *memRuns) add(runID, digest string) {
	m.set(runID, registry.RunAttempt{AttemptID: runID + "-a1", SpecSHA256: digest, Status: "failed", Finished: true})
}

// set replaces runID's latest attempt, as a native retry or a later run would.
func (m *memRuns) set(runID string, a registry.RunAttempt) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts[runID] = a
}

func (m *memRuns) latest(runID string) registry.RunAttempt {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.attempts[runID]
}

func (m *memRuns) LatestAttempt(_ context.Context, _, runID string) (registry.RunAttempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attempts[runID]
	if !ok {
		return registry.RunAttempt{}, registry.ErrRunNotFound
	}
	return a, nil
}

func (m *memRuns) ActiveRuns(context.Context, string) ([]registry.RunRef, error) { return nil, nil }
func (m *memRuns) StopRun(context.Context, string, registry.RunRef) error        { return nil }
func (m *memRuns) IsSuspended(context.Context, string) (bool, error)             { return false, nil }
func (m *memRuns) SetSuspended(context.Context, string, bool) error              { return nil }
func (m *memRuns) RunFinished(context.Context, string, registry.RunRef) (bool, error) {
	return true, nil
}

// recordingTasks completes native tasks in memory and can fail on demand.
type recordingTasks struct {
	mu    sync.Mutex
	calls []humantask.CompleteRequest
	fail  error
}

func (r *recordingTasks) Complete(_ context.Context, req humantask.CompleteRequest) (humantask.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, req)
	if r.fail != nil {
		return humantask.Result{}, r.fail
	}
	return humantask.Result{DAGName: req.DAGName, DAGRunID: req.DAGRunID, StepID: req.StepID}, nil
}

type fixture struct {
	t         *testing.T
	ctx       context.Context
	store     *registry.Store
	tasks     *recordingTasks
	runs      *memRuns
	svc       *Service
	now       time.Time
	clock     *time.Time
	jobID     string
	machineID string
	version   registry.JobVersion
	proposal  *registry.Proposal
	human     registry.Actor
}

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
)

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	current := now
	clock := func() time.Time { return current }
	runs := &memRuns{attempts: map[string]registry.RunAttempt{}}
	store, err := registry.NewFileStore(t.TempDir(),
		registry.WithClock(clock), registry.WithDAGStore(&memDAGs{specs: map[string][]byte{}}), registry.WithRunControl(runs))
	if err != nil {
		t.Fatal(err)
	}
	system := registry.Actor{Kind: registry.ActorSystem, ID: "test"}
	id := func(p registry.Prefix) string {
		v, err := registry.NewID(p, now)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	ownerID, projectID, machineID, jobID := id(registry.PrefixOwner), id(registry.PrefixProject), id(registry.PrefixMachine), id(registry.PrefixJob)
	must(t, func() error {
		_, err := store.CreateOwner(ctx, registry.Owner{OwnerID: ownerID, DisplayName: "Connor"}, system)
		return err
	})
	must(t, func() error {
		_, err := store.CreateProject(ctx, registry.Project{ProjectID: projectID, OwnerID: ownerID, Key: "fixture"}, system)
		return err
	})
	must(t, func() error {
		_, err := store.CreateMachine(ctx, registry.Machine{MachineID: machineID, OwnerID: ownerID, DisplayName: "laptop"}, system)
		return err
	})

	version := registry.JobVersion{
		Title:   "Volume monitor",
		Purpose: "Watch the fixture volume",
		Package: registry.Package{Digest: digestA, Path: "/var/txe/packages/fixture", Entrypoint: "run.sh"},
		DAG:     registry.DAGRef{Spec: "steps:\n  - run: ./run.sh\nworker_selector:\n  txe.machine: " + machineID + "\n"},
		Targets: []registry.Target{{Kind: "k8s.pv", StableID: map[string]string{"uid": "pv-1"}}},
	}
	job, err := store.Register(ctx, registry.RegisterInput{
		JobID: jobID, RequestID: "req-1", OwnerID: ownerID, ProjectID: projectID,
		MachineID: machineID, JobKey: "volume-monitor", Version: version,
	}, system)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkReady(ctx, jobID, job.Revision, registry.PackageEvidence{
		Digest: digestA, Path: version.Package.Path, MachineID: machineID,
	}, system); err != nil {
		t.Fatal(err)
	}

	f := &fixture{
		t: t, ctx: ctx, store: store, now: now, clock: &current, jobID: jobID, machineID: machineID, version: version,
		tasks: &recordingTasks{},
		runs:  runs,
		human: registry.Actor{Kind: registry.ActorHuman, ID: "connor", Client: "dashboard"},
	}
	f.svc = &Service{
		Registry:          store,
		Tasks:             f.tasks,
		Now:               clock,
		AuthorizeDecision: func(context.Context, *registry.JobTx, Verdict) error { return nil },
		AuthorizeTask:     func(context.Context, string, string) error { return nil },
	}
	f.proposal = f.fileProposal("resize", true)
	return f
}

func must(t *testing.T, fn func() error) {
	t.Helper()
	if err := fn(); err != nil {
		t.Fatal(err)
	}
}

// fileProposalWith files p under a review claim, filling its ID.
func (f *fixture) fileProposalWith(p registry.Proposal) *registry.Proposal {
	f.t.Helper()
	id, err := registry.NewID(registry.PrefixProposal, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.fileProposalWithID(id, p)
}

// fileProposalWithID files p with the given ID under a review claim.
func (f *fixture) fileProposalWithID(id string, p registry.Proposal) *registry.Proposal {
	f.t.Helper()
	var err error
	p.ProposalID = id
	var filed *registry.Proposal
	_, err = f.store.WithJobTx(f.ctx, f.jobID, registry.Actor{Kind: registry.ActorReviewer, ID: "reviewer"}, func(tx *registry.JobTx) error {
		claim, err := tx.AcquireClaim(registry.ClaimReview, registry.Reviewer{MachineID: "m"}, time.Hour)
		if err != nil {
			return err
		}
		if filed, err = tx.PutProposal(claim.ClaimID, claim.Fence, p); err != nil {
			return err
		}
		return tx.ReleaseClaim(claim.ClaimID, claim.Fence)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return filed
}

// fileProposal files a proposal the way a reviewer does: under a review claim.
func (f *fixture) fileProposal(action string, native bool) *registry.Proposal {
	f.t.Helper()
	reviewer := registry.Actor{Kind: registry.ActorReviewer, ID: "reviewer"}
	proposalID, err := registry.NewID(registry.PrefixProposal, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	var filed *registry.Proposal
	_, err = f.store.WithJobTx(f.ctx, f.jobID, reviewer, func(tx *registry.JobTx) error {
		claim, err := tx.AcquireClaim(registry.ClaimReview, registry.Reviewer{MachineID: "m"}, time.Hour)
		if err != nil {
			return err
		}
		p := registry.Proposal{
			ProposalID: proposalID,
			Question:   "Resize the volume?",
			WaitingOn:  "person",
			Action: registry.ActionSpec{
				Name: action, Target: &f.version.Targets[0], Params: json.RawMessage(`{"sizeGi":20}`),
			},
		}
		if native {
			p.NativeTask = &registry.NativeTask{DAG: DecideDAGName(f.machineID), RunID: "run-" + proposalID, StepID: DecideStepID}
		}
		filed, err = tx.PutProposal(claim.ClaimID, claim.Fence, p)
		if err != nil {
			return err
		}
		return tx.ReleaseClaim(claim.ClaimID, claim.Fence)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return filed
}

// setClock moves the fixture clock used by both the registry and the service.
func (f *fixture) setClock(t time.Time) { *f.clock = t }

func (f *fixture) request(v Verdict, key string) Request {
	return Request{
		ExpectedProposalRevision: f.proposal.Revision,
		BindingDigest:            f.proposal.BindingDigest,
		Verdict:                  v,
		IdempotencyKey:           key,
	}
}

func (f *fixture) decisions() []*registry.Decision {
	f.t.Helper()
	ds, err := f.store.ListDecisions(f.ctx, f.jobID, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	return ds
}

func TestDecideApproveCompletesNativeTask(t *testing.T) {
	f := newFixture(t)
	res, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, f.request(VerdictApprove, "key-approve-1"), f.human)
	if err != nil {
		t.Fatal(err)
	}
	if res.NativeErr != nil {
		t.Fatalf("native resume: %v", res.NativeErr)
	}
	if res.Proposal == nil || res.Proposal.State != registry.ProposalDecided {
		t.Fatalf("proposal = %+v, want decided", res.Proposal)
	}
	if res.Proposal.Revision != f.proposal.Revision+1 {
		t.Fatalf("revision = %d, want %d", res.Proposal.Revision, f.proposal.Revision+1)
	}
	if res.Decision.Actor.ID != "connor" || res.Decision.NativeResume != "completed" {
		t.Fatalf("decision = %+v", res.Decision)
	}
	if len(f.tasks.calls) != 1 {
		t.Fatalf("native completions = %d, want 1", len(f.tasks.calls))
	}
	call := f.tasks.calls[0]
	if call.StepID != "decide" || call.Input.Values["decision_id"] != res.Decision.DecisionID ||
		call.Input.Values["verdict"] != "approve" {
		t.Fatalf("native completion = %+v", call)
	}
	job, err := f.store.GetJob(f.ctx, f.jobID)
	if err != nil {
		t.Fatal(err)
	}
	if got := job.Proposals[f.proposal.ProposalID].Decision; got == nil || got.NativeResume != "completed" {
		t.Fatalf("persisted native resume = %+v", got)
	}
}

// A decision bound to an older proposal revision or to a job whose package
// changed must be refused, and nothing may be recorded.
func TestDecideRefusesStaleBinding(t *testing.T) {
	f := newFixture(t)
	stale := f.request(VerdictApprove, "key-stale-01")
	stale.ExpectedProposalRevision++
	if _, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, stale, f.human); registry.ErrorCode(err) != registry.CodeStaleBinding {
		t.Fatalf("stale revision err = %v, want stale_binding", err)
	}
	wrongDigest := f.request(VerdictApprove, "key-stale-02")
	wrongDigest.BindingDigest = digestB
	if _, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, wrongDigest, f.human); registry.ErrorCode(err) != registry.CodeStaleBinding {
		t.Fatalf("wrong digest err = %v, want stale_binding", err)
	}

	changed := f.version
	changed.Package.Digest = digestB
	if _, err := f.store.UpdateVersion(f.ctx, f.jobID, "req-2", 1, changed, registry.Actor{Kind: registry.ActorCLI, ID: "cli"}); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, f.request(VerdictApprove, "key-stale-03"), f.human)
	if code := registry.ErrorCode(err); code != registry.CodeStaleBinding && code != registry.CodeProposalState {
		t.Fatalf("after material change err = %v, want stale_binding or proposal_state", err)
	}
	if n := len(f.decisions()); n != 0 {
		t.Fatalf("decisions recorded = %d, want 0", n)
	}
	if len(f.tasks.calls) != 0 {
		t.Fatalf("native task completed %d times for refused decisions", len(f.tasks.calls))
	}
}

func TestDecideReplay(t *testing.T) {
	f := newFixture(t)
	req := f.request(VerdictReject, "key-replay-1")
	first, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, req, f.human)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, req, f.human)
	if err != nil {
		t.Fatal(err)
	}
	if !again.AlreadyRecorded || again.Decision.DecisionID != first.Decision.DecisionID {
		t.Fatalf("replay = %+v, want the stored decision", again.Decision)
	}
	if n := len(f.decisions()); n != 1 {
		t.Fatalf("decisions = %d, want 1", n)
	}
	other := req
	other.Verdict, other.Instructions = VerdictRedirect, "collect events first"
	if _, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, other, f.human); registry.ErrorCode(err) != CodeIdempotencyMismatch {
		t.Fatalf("reused key err = %v, want idempotency_mismatch", err)
	}
}

func TestDecideRejectClosesProposal(t *testing.T) {
	f := newFixture(t)
	res, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, f.request(VerdictReject, "key-reject-1"), f.human)
	if err != nil {
		t.Fatal(err)
	}
	if res.Proposal != nil {
		t.Fatalf("rejected proposal still open: %+v", res.Proposal)
	}
	if res.NativeErr != nil {
		t.Fatalf("native resume after reject: %v", res.NativeErr)
	}
	// A closed proposal accepts no further decision.
	_, err = f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, f.request(VerdictApprove, "key-reject-2"), f.human)
	if registry.ErrorCode(err) != registry.CodeProposalState {
		t.Fatalf("approve after reject err = %v, want proposal_state", err)
	}
}

// The decision is authoritative before the native task: a failed completion
// leaves it stored with a pending resume, and a replay completes the task.
func TestDecideNativeFailureIsRetriedOnReplay(t *testing.T) {
	f := newFixture(t)
	f.tasks.fail = errors.New("run queue unavailable")
	req := f.request(VerdictApprove, "key-native-1")
	res, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, req, f.human)
	if err != nil {
		t.Fatal(err)
	}
	if res.NativeErr == nil || res.Decision.NativeResume != "pending" {
		t.Fatalf("decision = %+v, native err = %v; want pending resume", res.Decision, res.NativeErr)
	}
	if n := len(f.decisions()); n != 1 {
		t.Fatalf("decisions = %d, want 1 stored before native completion", n)
	}

	f.tasks.fail = nil
	res, err = f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, req, f.human)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AlreadyRecorded || res.NativeErr != nil || res.Decision.NativeResume != "completed" {
		t.Fatalf("replay = %+v, native err = %v", res.Decision, res.NativeErr)
	}
	if len(f.tasks.calls) != 2 {
		t.Fatalf("native completions = %d, want 2", len(f.tasks.calls))
	}
}

func TestDecideRetireTransitionsInSameCommit(t *testing.T) {
	f := newFixture(t)
	res, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, f.request(VerdictRetire, "key-retire-1"), f.human)
	if err != nil {
		t.Fatal(err)
	}
	if res.Job.Lifecycle != registry.LifecycleRetired {
		t.Fatalf("lifecycle = %s, want retired", res.Job.Lifecycle)
	}
	if res.Job.Retirement == nil || res.Job.Retirement.Reason != registry.RetireManual {
		t.Fatalf("retirement = %+v", res.Job.Retirement)
	}
}

func TestDecideSnooze(t *testing.T) {
	f := newFixture(t)
	req := f.request(VerdictSnooze, "key-snooze-1")
	until := f.now.Add(24 * time.Hour)
	req.SnoozeUntil = &until
	res, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, req, f.human)
	if err != nil {
		t.Fatal(err)
	}
	if res.Proposal == nil || res.Proposal.State != registry.ProposalSnoozed ||
		res.Proposal.SnoozeUntil == nil || !res.Proposal.SnoozeUntil.Equal(until) {
		t.Fatalf("proposal = %+v, want snoozed until %s", res.Proposal, until)
	}
}

// A reviewer-written locator must not let a decision complete another DAG's
// human task with the deciding person's authority.
func TestDecideRefusesForeignNativeTask(t *testing.T) {
	f := newFixture(t)
	for _, task := range []registry.NativeTask{
		{DAG: "prod-release", RunID: "r1", StepID: DecideStepID},
		{DAG: DecideDAGName(f.machineID), RunID: "r1", StepID: "approve_release"},
	} {
		f.setNativeTask(task)
		_, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, f.request(VerdictApprove, "key-foreign-"+task.StepID), f.human)
		if registry.ErrorCode(err) != CodeNativeTaskRefused {
			t.Fatalf("task %+v: err = %v, want native_task_refused", task, err)
		}
	}
	if n := len(f.decisions()); n != 0 || len(f.tasks.calls) != 0 {
		t.Fatalf("decisions = %d, completions = %d; want none", n, len(f.tasks.calls))
	}
}

func TestDecideRequiresTaskAuthorization(t *testing.T) {
	f := newFixture(t)
	denied := errors.New("no execute permission for the decide run")
	var asked string
	f.svc.AuthorizeTask = func(_ context.Context, dag, run string) error {
		asked = dag + "/" + run
		return denied
	}
	_, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, f.request(VerdictApprove, "key-authz-01"), f.human)
	if !errors.Is(err, denied) {
		t.Fatalf("err = %v, want authorization error", err)
	}
	if want := f.proposal.NativeTask.DAG + "/" + f.proposal.NativeTask.RunID; asked != want {
		t.Fatalf("authorized %q, want %q", asked, want)
	}
	if n := len(f.decisions()); n != 0 {
		t.Fatalf("decisions = %d, want 0", n)
	}
}

// setNativeTask rewrites the proposal locator directly, as a faulty or
// compromised reviewer could.
func (f *fixture) setNativeTask(task registry.NativeTask) {
	f.t.Helper()
	_, err := f.store.WithJobTx(f.ctx, f.jobID, registry.Actor{Kind: registry.ActorReviewer, ID: "reviewer"}, func(tx *registry.JobTx) error {
		p := tx.Proposal(f.proposal.ProposalID)
		p.NativeTask = &task
		tx.Job.Proposals[p.ProposalID] = p
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

// Missing authorization wiring must refuse, never allow.
func TestDecideFailsClosedWithoutAuthorizers(t *testing.T) {
	f := newFixture(t)
	f.svc.AuthorizeDecision = nil
	if _, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, f.request(VerdictApprove, "key-noauth-1"), f.human); !errors.Is(err, errNoAuthorizer) {
		t.Fatalf("without decision authorizer err = %v", err)
	}
	f.svc.AuthorizeDecision = func(context.Context, *registry.JobTx, Verdict) error { return nil }
	f.svc.AuthorizeTask = nil
	if _, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, f.request(VerdictApprove, "key-noauth-2"), f.human); !errors.Is(err, errNoAuthorizer) {
		t.Fatalf("without task authorizer err = %v", err)
	}
	if n := len(f.decisions()); n != 0 {
		t.Fatalf("decisions = %d, want 0", n)
	}
}

func TestDecideRequiresDecisionAuthorization(t *testing.T) {
	f := newFixture(t)
	denied := errors.New("not the job owner")
	f.svc.AuthorizeDecision = func(_ context.Context, tx *registry.JobTx, v Verdict) error {
		if tx.Job.JobID != f.jobID || v != VerdictReject {
			t.Fatalf("authorized job %s verdict %s", tx.Job.JobID, v)
		}
		return denied
	}
	if _, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, f.request(VerdictReject, "key-owner-01"), f.human); !errors.Is(err, denied) {
		t.Fatalf("err = %v, want denial", err)
	}
	if n := len(f.decisions()); n != 0 || len(f.tasks.calls) != 0 {
		t.Fatalf("decisions = %d, completions = %d; want none", n, len(f.tasks.calls))
	}
}

// A snooze keeps the native task open, so the decision made after it expires
// completes the task, once, with that decision.
func TestDecideSnoozeThenApproveCompletesTaskOnce(t *testing.T) {
	f := newFixture(t)
	snooze := f.request(VerdictSnooze, "key-snooze-then")
	until := f.now.Add(time.Hour)
	snooze.SnoozeUntil = &until
	res, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, snooze, f.human)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.NativeResume != "" || len(f.tasks.calls) != 0 {
		t.Fatalf("snooze native_resume = %q, completions = %d; want empty, 0", res.Decision.NativeResume, len(f.tasks.calls))
	}

	f.setClock(until.Add(time.Minute))
	approve := f.request(VerdictApprove, "key-after-snooze")
	approve.ExpectedProposalRevision = res.Proposal.Revision
	res, err = f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, approve, f.human)
	if err != nil {
		t.Fatal(err)
	}
	if res.NativeErr != nil || res.Decision.NativeResume != "completed" {
		t.Fatalf("approve after snooze = %+v, native err %v", res.Decision, res.NativeErr)
	}
	if len(f.tasks.calls) != 1 || f.tasks.calls[0].Input.Values["verdict"] != "approve" {
		t.Fatalf("native completions = %+v, want one approve", f.tasks.calls)
	}
}

// A committed snooze is recoverable by an identical replay after its expiry.
func TestDecideReplaysExpiredSnooze(t *testing.T) {
	f := newFixture(t)
	req := f.request(VerdictSnooze, "key-expired-snooze")
	until := f.now.Add(time.Hour)
	req.SnoozeUntil = &until
	first, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, req, f.human)
	if err != nil {
		t.Fatal(err)
	}
	f.setClock(until.Add(24 * time.Hour))
	again, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, req, f.human)
	if err != nil {
		t.Fatalf("replay after expiry: %v", err)
	}
	if !again.AlreadyRecorded || again.Decision.DecisionID != first.Decision.DecisionID {
		t.Fatalf("replay = %+v", again.Decision)
	}
	// A new snooze with that past expiry is still refused.
	stale := f.request(VerdictSnooze, "key-new-past-snooze")
	stale.ExpectedProposalRevision = again.Proposal.Revision
	stale.SnoozeUntil = &until
	if _, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, stale, f.human); !errors.Is(err, ErrInvalid) {
		t.Fatalf("new past snooze err = %v, want ErrInvalid", err)
	}
}

// Retry is refused on an ordinary proposal even when the proposal allows
// every verdict or names retry explicitly.
func TestDecideRefusesRetryOnUntypedProposal(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Decide(f.ctx, f.jobID, f.proposal.ProposalID, f.request(VerdictRetry, "key-retry-untyped"), f.human); registry.ErrorCode(err) != registry.CodeNotPermitted {
		t.Fatalf("retry with empty allowed verdicts: err = %v, want not_permitted", err)
	}
	explicit := f.fileProposalWith(registry.Proposal{
		Action:          registry.ActionSpec{Name: "resize", Target: &f.version.Targets[0], Params: json.RawMessage(`{"sizeGi":30}`)},
		AllowedVerdicts: []registry.Verdict{VerdictRetry, VerdictReject},
	})
	req := Request{
		ExpectedProposalRevision: explicit.Revision,
		BindingDigest:            explicit.BindingDigest,
		Verdict:                  VerdictRetry,
		IdempotencyKey:           "key-retry-explicit",
	}
	if _, err := f.svc.Decide(f.ctx, f.jobID, explicit.ProposalID, req, f.human); registry.ErrorCode(err) != registry.CodeNotPermitted {
		t.Fatalf("retry explicitly allowed: err = %v, want not_permitted", err)
	}
	if n := len(f.decisions()); n != 0 || len(f.tasks.calls) != 0 {
		t.Fatalf("decisions = %d, completions = %d; want none", n, len(f.tasks.calls))
	}
}

func (f *fixture) job() *registry.Job {
	f.t.Helper()
	j, err := f.store.GetJob(f.ctx, f.jobID)
	if err != nil {
		f.t.Fatal(err)
	}
	return j
}

// retryRequest is a request to retry runID, which the fixture records in
// Dagu's run history as a run of the job's current DAG.
func (f *fixture) retryRequest(runID, key string) RetryRequest {
	j := f.job()
	if _, ok := f.runs.attempts[runID]; !ok {
		f.runs.add(runID, j.DAGSpecSHA256)
	}
	return RetryRequest{
		RunID: runID, AttemptID: f.runs.latest(runID).AttemptID, ExpectedJobVersion: j.Version, RunSpecSHA256: j.DAGSpecSHA256,
		RunStartedAt: f.now.Add(time.Minute), IdempotencyKey: key,
	}
}

// A retry request is a decided dagu.retry_run proposal whose bound action
// the reviewer can be granted exactly once, settled with the new attempt as
// receipt.
func TestRequestRetryIsGrantedOnce(t *testing.T) {
	f := newFixture(t)
	res, err := f.svc.RequestRetry(f.ctx, f.jobID, f.retryRequest("run-0042", "key-retry-run-1"), f.human)
	if err != nil {
		t.Fatal(err)
	}
	if res.Proposal == nil || res.Proposal.State != registry.ProposalDecided || res.Proposal.Action.Name != ActionRetryRun {
		t.Fatalf("proposal = %+v, want decided %s", res.Proposal, ActionRetryRun)
	}
	if res.Decision.Verdict != VerdictRetry || res.Decision.Actor.ID != "connor" {
		t.Fatalf("decision = %+v", res.Decision)
	}
	actionID, err := registry.ApprovedActionID(res.Proposal.ProposalID, res.Decision.DecisionID)
	if err != nil {
		t.Fatal(err)
	}
	executor := registry.Actor{Kind: registry.ActorReviewer, ID: "executor"}
	grant := func() (*registry.Grant, *registry.Claim, error) {
		var g *registry.Grant
		var c *registry.Claim
		_, err := f.store.WithJobTx(f.ctx, f.jobID, executor, func(tx *registry.JobTx) error {
			var err error
			if c, err = tx.AcquireClaim(registry.ClaimExecution, registry.Reviewer{MachineID: f.machineID}, time.Hour); err != nil {
				return err
			}
			j := tx.Job
			g, err = tx.Authorize(registry.EffectRequest{ActionID: actionID, JobVersion: j.Version, PackageDigest: j.PackageDigest,
				Approved: &registry.ApprovedEffect{ProposalID: res.Proposal.ProposalID, DecisionID: res.Decision.DecisionID, ClaimID: c.ClaimID, Fence: c.Fence}})
			return err
		})
		return g, c, err
	}
	g, claim, err := grant()
	if err != nil {
		t.Fatalf("first grant: %v", err)
	}
	// The executor's native retry adds an attempt to the same run; the
	// receipt names that observed attempt.
	j := f.job()
	f.runs.set("run-0042", registry.RunAttempt{AttemptID: "run-0042-a2", SpecSHA256: j.DAGSpecSHA256, Status: "running"})
	if _, err := f.store.WithJobTx(f.ctx, f.jobID, executor, func(tx *registry.JobTx) error {
		_, err := tx.SettleAction(registry.Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: claim.ClaimID,
			Fence: claim.Fence, State: registry.ActionSucceeded, Receipt: "run-0042-a2"})
		if err != nil {
			return err
		}
		return tx.ReleaseClaim(claim.ClaimID, claim.Fence)
	}); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if _, _, err := grant(); registry.ErrorCode(err) == "" {
		t.Fatalf("second grant err = %v, want a refusal", err)
	}
	// After the retry ran, an identical request still returns its decision.
	again, err := f.svc.RequestRetry(f.ctx, f.jobID, f.retryRequest("run-0042", "key-retry-run-1"), f.human)
	if err != nil {
		t.Fatalf("replay after settlement: %v", err)
	}
	if !again.AlreadyRecorded || again.Decision.DecisionID != res.Decision.DecisionID {
		t.Fatalf("replay after settlement = %+v", again.Decision)
	}
}

func TestRequestRetryRefusesStaleRuns(t *testing.T) {
	f := newFixture(t)
	wrongSpec := f.retryRequest("run-0042", "key-stale-spec")
	wrongSpec.RunSpecSHA256 = digestB
	if _, err := f.svc.RequestRetry(f.ctx, f.jobID, wrongSpec, f.human); registry.ErrorCode(err) != CodeRunStale {
		t.Fatalf("other spec err = %v, want run_stale", err)
	}
	// Same DAG text but started before the current version existed: the
	// package may differ, so it is not retried on the new version's code.
	early := f.retryRequest("run-0041", "key-stale-time")
	early.RunStartedAt = f.now.Add(-time.Hour)
	if _, err := f.svc.RequestRetry(f.ctx, f.jobID, early, f.human); registry.ErrorCode(err) != CodeRunStale {
		t.Fatalf("earlier run err = %v, want run_stale", err)
	}
	// A run recorded in the version's creation second may be of the
	// previous version, so it is refused rather than guessed.
	sameSecond := f.retryRequest("run-0040", "key-same-second")
	sameSecond.RunStartedAt = f.now.Truncate(time.Second)
	if _, err := f.svc.RequestRetry(f.ctx, f.jobID, sameSecond, f.human); registry.ErrorCode(err) != CodeRunStale {
		t.Fatalf("run in the version's second: err = %v, want run_stale", err)
	}
	moved := f.retryRequest("run-0042", "key-stale-version")
	moved.ExpectedJobVersion++
	if _, err := f.svc.RequestRetry(f.ctx, f.jobID, moved, f.human); registry.ErrorCode(err) != registry.CodeVersionConflict {
		t.Fatalf("version err = %v, want version_conflict", err)
	}
	if n := len(f.decisions()); n != 0 {
		t.Fatalf("decisions = %d, want 0", n)
	}
}

func TestRequestRetryReplay(t *testing.T) {
	f := newFixture(t)
	req := f.retryRequest("run-0042", "key-retry-replay")
	first, err := f.svc.RequestRetry(f.ctx, f.jobID, req, f.human)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.svc.RequestRetry(f.ctx, f.jobID, req, f.human)
	if err != nil {
		t.Fatal(err)
	}
	if !again.AlreadyRecorded || again.Decision.DecisionID != first.Decision.DecisionID {
		t.Fatalf("replay = %+v", again.Decision)
	}
	other := f.retryRequest("run-0043", "key-retry-replay")
	if _, err := f.svc.RequestRetry(f.ctx, f.jobID, other, f.human); registry.ErrorCode(err) != CodeIdempotencyMismatch {
		t.Fatalf("key reused for another run err = %v, want idempotency_mismatch", err)
	}
	if n := len(f.decisions()); n != 1 {
		t.Fatalf("decisions = %d, want 1", n)
	}
}

// A reviewer-filed dagu.retry_run proposal is decided by a retry verdict.
func TestDecideRetryOnRetryRunProposal(t *testing.T) {
	f := newFixture(t)
	j := f.job()
	f.runs.add("run-0044", j.DAGSpecSHA256)
	attempt := f.runs.latest("run-0044").AttemptID
	params, _ := json.Marshal(registry.RetryRunParams{RunID: "run-0044", AttemptID: attempt, RunSpecSHA256: j.DAGSpecSHA256, PackageDigest: j.PackageDigest})
	id, err := registry.RetryProposalID("run-0044", attempt, j.Version)
	if err != nil {
		t.Fatal(err)
	}
	p := f.fileProposalWithID(id, registry.Proposal{
		Action:          registry.ActionSpec{Name: ActionRetryRun, Params: params},
		AllowedVerdicts: []registry.Verdict{VerdictRetry, VerdictReject},
	})
	req := Request{ExpectedProposalRevision: p.Revision, BindingDigest: p.BindingDigest, Verdict: VerdictRetry, IdempotencyKey: "key-run-retry-1"}
	res, err := f.svc.Decide(f.ctx, f.jobID, p.ProposalID, req, f.human)
	if err != nil {
		t.Fatal(err)
	}
	if res.Proposal == nil || res.Proposal.State != registry.ProposalDecided {
		t.Fatalf("proposal = %+v, want decided", res.Proposal)
	}
}

// grantAndSettle performs a recorded retry as the executor does: one grant
// under an execution claim, a native retry that adds attempt next to the
// run, and a settlement whose receipt is that observed attempt.
func (f *fixture) grantAndSettle(res *Result, runID, next string, nextFailed bool) error {
	f.t.Helper()
	actionID, err := registry.ApprovedActionID(res.Proposal.ProposalID, res.Decision.DecisionID)
	if err != nil {
		return err
	}
	executor := registry.Actor{Kind: registry.ActorReviewer, ID: "executor"}
	var g *registry.Grant
	var c *registry.Claim
	if _, err := f.store.WithJobTx(f.ctx, f.jobID, executor, func(tx *registry.JobTx) error {
		var err error
		if c, err = tx.AcquireClaim(registry.ClaimExecution, registry.Reviewer{MachineID: f.machineID}, time.Hour); err != nil {
			return err
		}
		j := tx.Job
		g, err = tx.Authorize(registry.EffectRequest{ActionID: actionID, JobVersion: j.Version, PackageDigest: j.PackageDigest,
			Approved: &registry.ApprovedEffect{ProposalID: res.Proposal.ProposalID, DecisionID: res.Decision.DecisionID, ClaimID: c.ClaimID, Fence: c.Fence}})
		return err
	}); err != nil {
		return err
	}
	j := f.job()
	f.runs.set(runID, registry.RunAttempt{AttemptID: next, SpecSHA256: j.DAGSpecSHA256, Status: "failed", Finished: true, Succeeded: !nextFailed})
	_, err = f.store.WithJobTx(f.ctx, f.jobID, executor, func(tx *registry.JobTx) error {
		if _, err := tx.SettleAction(registry.Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: c.ClaimID,
			Fence: c.Fence, State: registry.ActionSucceeded, Receipt: next}); err != nil {
			return err
		}
		return tx.ReleaseClaim(c.ClaimID, c.Fence)
	})
	return err
}

// A native retry keeps the run ID, so a retry is bound to the failed attempt.
// When the retried attempt fails too, a fresh decision may retry the run once
// more, while replaying the first request still returns only its decision.
func TestRequestRetryLaterAttempt(t *testing.T) {
	f := newFixture(t)
	first, err := f.svc.RequestRetry(f.ctx, f.jobID, f.retryRequest("run-0050", "key-later-1"), f.human)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.grantAndSettle(first, "run-0050", "run-0050-a2", true); err != nil {
		t.Fatalf("first retry: %v", err)
	}
	second, err := f.svc.RequestRetry(f.ctx, f.jobID, f.retryRequest("run-0050", "key-later-2"), f.human)
	if err != nil {
		t.Fatalf("retry of the failed retried attempt: %v", err)
	}
	if second.Proposal.ProposalID == first.Proposal.ProposalID {
		t.Fatal("the later attempt's retry reused the first attempt's proposal")
	}
	if err := f.grantAndSettle(second, "run-0050", "run-0050-a3", true); err != nil {
		t.Fatalf("second retry: %v", err)
	}
	replay, err := f.svc.RequestRetry(f.ctx, f.jobID, f.retryRequest("run-0050", "key-later-1"), f.human)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.AlreadyRecorded || replay.Decision.DecisionID != first.Decision.DecisionID {
		t.Fatalf("replay of the first request = %+v", replay.Decision)
	}
	if n := len(f.decisions()); n != 2 {
		t.Fatalf("decisions = %d, want 2", n)
	}
}

// A request naming an attempt that is not the run's latest, or a run whose
// latest attempt succeeded, is refused and records nothing.
func TestRequestRetryRefusesForgedAndStaleAttempts(t *testing.T) {
	f := newFixture(t)
	forged := f.retryRequest("run-0060", "key-forged")
	forged.AttemptID = "run-0060-a0"
	if _, err := f.svc.RequestRetry(f.ctx, f.jobID, forged, f.human); registry.ErrorCode(err) != registry.CodeStaleBinding {
		t.Fatalf("forged attempt err = %v, want stale_binding", err)
	}
	stale := f.retryRequest("run-0061", "key-stale-attempt")
	j := f.job()
	f.runs.set("run-0061", registry.RunAttempt{AttemptID: stale.AttemptID, SpecSHA256: j.DAGSpecSHA256, Status: "succeeded", Finished: true, Succeeded: true})
	if _, err := f.svc.RequestRetry(f.ctx, f.jobID, stale, f.human); registry.ErrorCode(err) != registry.CodeStaleBinding {
		t.Fatalf("succeeded attempt err = %v, want stale_binding", err)
	}
	if n := len(f.decisions()); n != 0 {
		t.Fatalf("decisions = %d, want 0", n)
	}
}
