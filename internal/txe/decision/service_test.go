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
	for _, line := range strings.Split(string(spec), "\n") {
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
	svc       *Service
	now       time.Time
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
	clock := func() time.Time { return now }
	store, err := registry.NewFileStore(t.TempDir(),
		registry.WithClock(clock), registry.WithDAGStore(&memDAGs{specs: map[string][]byte{}}))
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
		t: t, ctx: ctx, store: store, now: now, jobID: jobID, machineID: machineID, version: version,
		tasks: &recordingTasks{},
		human: registry.Actor{Kind: registry.ActorHuman, ID: "connor", Client: "dashboard"},
	}
	f.svc = &Service{
		Registry:          store,
		Tasks:             f.tasks,
		Now:               clock,
		AuthorizeDecision: func(context.Context, *registry.Job) error { return nil },
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
	f.svc.AuthorizeDecision = func(context.Context, *registry.Job) error { return nil }
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
	f.svc.AuthorizeDecision = func(_ context.Context, job *registry.Job) error {
		if job.JobID != f.jobID {
			t.Fatalf("authorized job %s", job.JobID)
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
