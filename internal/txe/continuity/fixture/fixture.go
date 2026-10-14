// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package fixture builds a representative synthetic retained TXE store: a
// hub data directory, a DAG directory and a machine's TXE home holding every
// kind of record a phase-one installation keeps, written through the
// registry's and the authorization store's own APIs so that each record is
// in the form those stores write.
//
// Nothing here reads or copies a real store, and no value in it is a real
// credential, path or account. The owner ID is the installation's stable
// owner ID, which is an opaque identifier, not a secret, so that the default
// owner check applies to the fixture unchanged.
package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/dagucloud/dagu/v2/internal/persis"
	persisfile "github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// StableOwner is the installation's owner ID, initialized in phase one.
const StableOwner = "own_01M4GBBMJ7A2VKXJGAADCKV7RR"

// Issuer is the synthetic identity provider the fixture's bindings name.
const Issuer = "https://idp.fixture.invalid/realms/fixture"

// Layout is where a built fixture is.
type Layout struct {
	Root        string
	DataDir     string
	DAGsDir     string
	MachineHome string
	// HubMount is the data directory path as the fixture's hub saw it; a
	// copy of DataDir is scanned with this as its mount.
	HubMount string
}

// Facts are what the fixture holds, for tests to check an inventory against.
type Facts struct {
	Owner    string
	Machine  string
	Machine2 string
	Projects []string
	// Jobs are job IDs by scenario name.
	Jobs map[string]string
	// Packages are the digests stored in the machine home, by job ID.
	Packages map[string][]string
	// Lifecycles are the lifecycle of each job ID.
	Lifecycles map[string]registry.Lifecycle
	// ActionStates count actions by state, live and archived.
	ActionStates map[registry.ActionState]int
	// ProposalStates are the states proposals were left in.
	ProposalStates map[registry.ProposalState]int
	// Artifact bytes, by path relative to the root they are under.
	HubArtifacts     []string
	MachineArtifacts []string
}

var (
	cli      = registry.Actor{Kind: registry.ActorCLI, ID: "fixture-cli", Session: "fixture-session"}
	person   = registry.Actor{Kind: registry.ActorHuman, ID: "fixture-person"}
	reviewer = registry.Actor{Kind: registry.ActorReviewer, ID: "fixture-reviewer"}
	recon    = registry.Actor{Kind: registry.ActorReconciler, ID: "fixture-reconciler"}
)

type builder struct {
	ctx    context.Context
	layout Layout
	store  *registry.Store
	runs   *runs
	mu     sync.Mutex
	now    time.Time
	facts  *Facts
	err    error
}

// Build writes the fixture under root, which must be empty or absent.
func Build(ctx context.Context, root string) (*Layout, *Facts, error) {
	if entries, err := os.ReadDir(root); err == nil && len(entries) > 0 {
		return nil, nil, fmt.Errorf("fixture: %s is not empty", root)
	}
	l := Layout{
		Root:        root,
		DataDir:     filepath.Join(root, "hub", "data"),
		DAGsDir:     filepath.Join(root, "hub", "dags"),
		MachineHome: filepath.Join(root, "machine", "txe-dagu"),
	}
	l.HubMount = l.DataDir
	for _, d := range []string{l.DataDir, l.DAGsDir, l.MachineHome} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, nil, err
		}
	}
	b := &builder{ctx: ctx, layout: l, now: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), runs: newRuns(),
		facts: &Facts{Owner: StableOwner, Jobs: map[string]string{}, Packages: map[string][]string{},
			Lifecycles: map[string]registry.Lifecycle{}, ActionStates: map[registry.ActionState]int{},
			ProposalStates: map[registry.ProposalState]int{}}}
	dags := registry.NewDAGStore(persis.NewDAGRepository(dag.NewStore(l.DAGsDir), persis.DAGRepositoryOptions{}))
	s, err := registry.NewFileStore(l.DataDir, registry.WithClock(b.clock), registry.WithDAGStore(dags), registry.WithRunControl(b.runs))
	if err != nil {
		return nil, nil, err
	}
	b.store = s
	if err := b.build(); err != nil {
		return nil, nil, err
	}
	return &l, b.facts, nil
}

func (b *builder) clock() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.now
}

func (b *builder) advance(d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = b.now.Add(d)
}

func (b *builder) mint(p registry.Prefix) string {
	id, err := registry.NewID(p, b.clock())
	if err != nil {
		panic(err)
	}
	return id
}

func (b *builder) build() error {
	ctx := b.ctx
	s := b.store
	f := b.facts
	if _, err := s.CreateOwner(ctx, registry.Owner{OwnerID: StableOwner, DisplayName: "Connor Wang", Provenance: "fixture: installer"}, cli); err != nil {
		return err
	}
	f.Machine = b.mint(registry.PrefixMachine)
	f.Machine2 = b.mint(registry.PrefixMachine)
	for _, m := range []registry.Machine{
		{MachineID: f.Machine, OwnerID: StableOwner, DisplayName: "fixture-laptop"},
		{MachineID: f.Machine2, OwnerID: StableOwner, DisplayName: "fixture-linux-worker"},
	} {
		if _, err := s.CreateMachine(ctx, m, cli); err != nil {
			return err
		}
	}
	for _, key := range []string{"github.com/fixture/app", "github.com/fixture/ops"} {
		p, err := s.EnsureProject(ctx, StableOwner, key, "", cli)
		if err != nil {
			return err
		}
		f.Projects = append(f.Projects, p.ProjectID)
	}
	if err := s.RebuildResourceIndex(ctx); err != nil {
		return err
	}
	if err := b.machineIdentity(); err != nil {
		return err
	}
	steps := []func() error{
		b.activeWithHistory,
		b.uncertainEffect,
		b.lifecycles,
		b.incompleteAndDuplicate,
		b.expired,
		b.targetDeleted,
		b.superseded,
		b.artifacts,
		b.secondMachine,
		b.uncommittedHistory,
		b.authz,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
		b.advance(time.Hour)
	}
	return b.nativeRuns()
}

func (b *builder) machineIdentity() error {
	m := txepkg.Machine{Schema: 1, MachineID: b.facts.Machine, OwnerID: StableOwner, DisplayName: "fixture-laptop"}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(b.layout.MachineHome, "machine.json"), data, 0o600)
}

// pkg writes a sealed package for job into the machine home and returns its
// digest, as the CLI's package store lays it out.
func (b *builder) pkg(jobID string, script string) (string, string, error) {
	content := []byte("#!/bin/sh\n" + script + "\n")
	sum := sha256.Sum256(content)
	files := []txepkg.File{{Path: "run.sh", Size: int64(len(content)), SHA256: "sha256:" + hex.EncodeToString(sum[:]), Executable: true}}
	m := txepkg.Manifest{Schema: txepkg.ManifestSchema, Entrypoint: []string{"run.sh"}, Files: files, ContentSHA256: hex.EncodeToString(sum[:]),
		Provenance: txepkg.Provenance{Repository: "github.com/fixture/app", SourceRoot: "/fixture/src", Session: "fixture-session"}}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", "", err
	}
	data = append(data, '\n')
	digest := txepkg.Digest(data)
	name, err := txepkg.DigestDirName(digest)
	if err != nil {
		return "", "", err
	}
	dir := filepath.Join(b.layout.MachineHome, "packages", jobID, name)
	if err := os.MkdirAll(filepath.Join(dir, txepkg.FilesDir), 0o750); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(filepath.Join(dir, txepkg.ManifestName), data, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(filepath.Join(dir, txepkg.FilesDir, "run.sh"), content, 0o700); err != nil { //nolint:gosec // a fixture script
		return "", "", err
	}
	b.facts.Packages[jobID] = append(b.facts.Packages[jobID], digest)
	return digest, dir, nil
}

func spec(machine string) string {
	return fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: ./run.sh\n", machine)
}

func (b *builder) version(machine string, mutate ...func(v *registry.JobVersion)) registry.JobVersion {
	v := registry.JobVersion{
		Title:   "fixture job",
		Purpose: "Exercise retained-data continuity",
		Origin:  registry.Origin{Repo: "github.com/fixture/app", Commit: "0000000000000000000000000000000000000000", Session: "fixture-session"},
		DAG:     registry.DAGRef{Spec: spec(machine)},
		Schedule: registry.Schedule{
			Cron: "*/30 * * * *", Timezone: "Australia/Perth", MissedRun: "skip",
		},
		Targets:         []registry.Target{{Kind: "fixture.volume", Environment: "dev", StableID: map[string]string{"uid": "vol-" + b.mint(registry.PrefixEvent)[4:12]}, DisplayName: "fixture-volume"}},
		ExpectedOutcome: registry.ExpectedOutcome{SuccessCriteria: []string{"the fixture volume is healthy"}},
		ReviewPolicy: registry.ReviewPolicy{
			MaxAttempts: 2,
			Brief:       "Review the fixture results.",
			PermittedActions: []registry.PermittedAction{
				{Name: "diagnose", TimeoutSec: 60, Routine: true, Idempotency: registry.IdempotencyReadOnly},
				{Name: "restart", TimeoutSec: 60, Routine: true, Idempotency: registry.IdempotencyNone},
				{Name: "resize", TimeoutSec: 120},
			},
		},
	}
	for _, m := range mutate {
		m(&v)
	}
	return v
}

// register registers a job and, unless incomplete, writes its package and
// marks it ready.
func (b *builder) register(name, machine, project string, ready bool, mutate ...func(v *registry.JobVersion)) (*registry.Job, error) {
	jobID := b.mint(registry.PrefixJob)
	v := b.version(machine, mutate...)
	digest, dir, err := b.pkg(jobID, "echo "+name)
	if err != nil {
		return nil, err
	}
	v.Package = registry.Package{Digest: digest, Path: dir, Entrypoint: "run.sh"}
	job, err := b.store.Register(b.ctx, registry.RegisterInput{JobID: jobID, RequestID: "req-" + jobID, OwnerID: StableOwner,
		ProjectID: project, MachineID: machine, JobKey: name, Version: v}, cli)
	if err != nil {
		return nil, fmt.Errorf("register %s: %w", name, err)
	}
	b.facts.Jobs[name] = jobID
	if !ready {
		return job, nil
	}
	if _, err := b.store.MarkReady(b.ctx, jobID, job.Revision, registry.PackageEvidence{Digest: digest, Path: dir, MachineID: machine}, cli); err != nil {
		return nil, fmt.Errorf("ready %s: %w", name, err)
	}
	return b.store.GetJob(b.ctx, jobID)
}

func (b *builder) tx(jobID string, actor registry.Actor, fn func(tx *registry.JobTx) error) (*registry.Job, error) {
	return b.store.WithJobTx(b.ctx, jobID, actor, fn)
}

func (b *builder) claim(jobID string, kind registry.ClaimKind, machine string, ttl time.Duration) (*registry.Claim, error) {
	var c *registry.Claim
	_, err := b.tx(jobID, reviewer, func(tx *registry.JobTx) error {
		var err error
		c, err = tx.AcquireClaim(kind, registry.Reviewer{MachineID: machine, DAGRunID: "fixture-review-run"}, ttl)
		return err
	})
	return c, err
}

func (b *builder) release(jobID string, c *registry.Claim) error {
	_, err := b.tx(jobID, reviewer, func(tx *registry.JobTx) error { return tx.ReleaseClaim(c.ClaimID, c.Fence) })
	return err
}

// review records a review of the job's current checkpoint and advances it.
func (b *builder) review(jobID string, c *registry.Claim, outcome registry.ReviewOutcome, runs []string) (string, error) {
	var reviewID string
	_, err := b.tx(jobID, reviewer, func(tx *registry.JobTx) error {
		j := tx.Job
		id, err := registry.ReviewID(j.JobID, j.Checkpoint.Version)
		if err != nil {
			return err
		}
		reviewID = id
		if err := tx.RecordReview(c.ClaimID, c.Fence, registry.Review{ReviewID: id, JobVersion: j.Version, CheckpointVersion: j.Checkpoint.Version,
			ClaimID: c.ClaimID, Fence: c.Fence, EvidenceRunIDs: runs, Outcome: outcome, Reasoning: "fixture review"}); err != nil {
			return err
		}
		next := b.clock().Add(30 * time.Minute)
		_, err = tx.AdvanceCheckpoint(c.ClaimID, c.Fence, j.Checkpoint.Version, registry.Checkpoint{RunCursor: runs[len(runs)-1], LastReviewID: id, NextReviewAt: &next})
		return err
	})
	return reviewID, err
}

func (b *builder) propose(job *registry.Job, c *registry.Claim, question string, verdicts ...registry.Verdict) (*registry.Proposal, error) {
	var p *registry.Proposal
	_, err := b.tx(job.JobID, reviewer, func(tx *registry.JobTx) error {
		var err error
		p, err = tx.PutProposal(c.ClaimID, c.Fence, registry.Proposal{
			ProposalID: b.mint(registry.PrefixProposal), Question: question, Rationale: "fixture",
			Action:          registry.ActionSpec{Name: "resize", Params: json.RawMessage(`{"size":"20Gi"}`)},
			AllowedVerdicts: verdicts,
		})
		return err
	})
	return p, err
}

func (b *builder) decide(jobID string, p *registry.Proposal, verdict registry.Verdict, next registry.ProposalState, mutate ...func(d *registry.Decision)) (*registry.Decision, error) {
	var d *registry.Decision
	_, err := b.tx(jobID, person, func(tx *registry.JobTx) error {
		cur := tx.Proposal(p.ProposalID)
		if cur == nil {
			return fmt.Errorf("proposal %s is gone", p.ProposalID)
		}
		in := registry.Decision{DecisionID: b.mint(registry.PrefixDecision), ProposalID: p.ProposalID, ProposalRevision: cur.Revision,
			BindingDigest: cur.BindingDigest, Verdict: verdict, IdempotencyKey: "key-" + p.ProposalID + "-" + string(verdict)}
		for _, m := range mutate {
			m(&in)
		}
		var err error
		d, err = tx.AppendDecision(in, next)
		return err
	})
	if err == nil {
		b.facts.ProposalStates[next]++
	}
	return d, err
}

// routine authorizes a routine action of the review the claim is on.
func (b *builder) routine(job *registry.Job, c *registry.Claim, name string, params string) (string, *registry.Grant, error) {
	cur, err := b.store.GetJob(b.ctx, job.JobID)
	if err != nil {
		return "", nil, err
	}
	reviewID, err := registry.ReviewID(cur.JobID, cur.Checkpoint.Version)
	if err != nil {
		return "", nil, err
	}
	spec := registry.ActionSpec{Name: name, Params: json.RawMessage(params)}
	actionID, err := registry.RoutineActionID(reviewID, spec)
	if err != nil {
		return "", nil, err
	}
	var g *registry.Grant
	_, err = b.tx(job.JobID, reviewer, func(tx *registry.JobTx) error {
		var err error
		g, err = tx.Authorize(registry.EffectRequest{ActionID: actionID, JobVersion: cur.Version, PackageDigest: cur.PackageDigest,
			Routine: &registry.RoutineEffect{ReviewID: reviewID, ClaimID: c.ClaimID, Fence: c.Fence, Spec: spec}})
		return err
	})
	return actionID, g, err
}

func (b *builder) settle(jobID, actionID string, g *registry.Grant, c *registry.Claim, state registry.ActionState, receipt string) error {
	_, err := b.tx(jobID, reviewer, func(tx *registry.JobTx) error {
		_, err := tx.SettleAction(registry.Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: c.ClaimID, Fence: c.Fence,
			State: state, Receipt: receipt, Outcome: json.RawMessage(`{"fixture":true}`)})
		return err
	})
	if err == nil {
		b.facts.ActionStates[state]++
	}
	return err
}

// activeWithHistory is an active job with two versions, reviews, a
// checkpoint, a routine action, an executed approval, a rejection, a
// redirect, a snoozed and an open proposal, and an expired claim.
func (b *builder) activeWithHistory() error {
	job, err := b.register("health-check", b.facts.Machine, b.facts.Projects[0], true)
	if err != nil {
		return err
	}
	c, err := b.claim(job.JobID, registry.ClaimReview, b.facts.Machine, time.Hour)
	if err != nil {
		return err
	}
	actionID, g, err := b.routine(job, c, "diagnose", `{"n":1}`)
	if err != nil {
		return fmt.Errorf("routine: %w", err)
	}
	if err := b.settle(job.JobID, actionID, g, c, registry.ActionSucceeded, "diagnosed"); err != nil {
		return fmt.Errorf("settle routine: %w", err)
	}
	if _, err := b.review(job.JobID, c, registry.ReviewAct, []string{"run-hc-1"}); err != nil {
		return fmt.Errorf("review: %w", err)
	}
	approve, err := b.propose(job, c, "Resize the volume?")
	if err != nil {
		return err
	}
	reject, err := b.propose(job, c, "Delete old snapshots?")
	if err != nil {
		return err
	}
	redirect, err := b.propose(job, c, "Restart the exporter?")
	if err != nil {
		return err
	}
	snooze, err := b.propose(job, c, "Rotate the logs?")
	if err != nil {
		return err
	}
	if _, err := b.propose(job, c, "Archive last month?"); err != nil {
		return err
	}
	b.facts.ProposalStates[registry.ProposalOpen]++
	if err := b.release(job.JobID, c); err != nil {
		return err
	}
	d, err := b.decide(job.JobID, approve, registry.VerdictApprove, registry.ProposalDecided)
	if err != nil {
		return fmt.Errorf("approve: %w", err)
	}
	if _, err := b.decide(job.JobID, reject, registry.VerdictReject, registry.ProposalRejected); err != nil {
		return fmt.Errorf("reject: %w", err)
	}
	if _, err := b.decide(job.JobID, redirect, registry.VerdictRedirect, registry.ProposalRejected, func(d *registry.Decision) {
		d.Instructions = "Check the exporter's config first."
	}); err != nil {
		return fmt.Errorf("redirect: %w", err)
	}
	until := b.clock().Add(48 * time.Hour)
	if _, err := b.decide(job.JobID, snooze, registry.VerdictSnooze, registry.ProposalSnoozed, func(d *registry.Decision) { d.SnoozeUntil = &until }); err != nil {
		return fmt.Errorf("snooze: %w", err)
	}
	b.advance(2 * time.Minute)
	ec, err := b.claim(job.JobID, registry.ClaimExecution, b.facts.Machine, time.Hour)
	if err != nil {
		return err
	}
	approvedID, err := registry.ApprovedActionID(approve.ProposalID, d.DecisionID)
	if err != nil {
		return err
	}
	var ag *registry.Grant
	if _, err := b.tx(job.JobID, reviewer, func(tx *registry.JobTx) error {
		var err error
		ag, err = tx.Authorize(registry.EffectRequest{ActionID: approvedID, JobVersion: job.Version, PackageDigest: job.PackageDigest,
			Approved: &registry.ApprovedEffect{ProposalID: approve.ProposalID, DecisionID: d.DecisionID, ClaimID: ec.ClaimID, Fence: ec.Fence}})
		return err
	}); err != nil {
		return fmt.Errorf("authorize approved: %w", err)
	}
	if err := b.settle(job.JobID, approvedID, ag, ec, registry.ActionSucceeded, "resized"); err != nil {
		return err
	}
	b.facts.ProposalStates[registry.ProposalExecuted]++
	if err := b.release(job.JobID, ec); err != nil {
		return err
	}
	// A claim left to expire: its holder stopped without releasing it.
	if _, err := b.claim(job.JobID, registry.ClaimReview, b.facts.Machine, time.Minute); err != nil {
		return err
	}
	b.advance(10 * time.Minute)
	// A second version, ready again.
	cur, err := b.store.GetJob(b.ctx, job.JobID)
	if err != nil {
		return err
	}
	digest, dir, err := b.pkg(job.JobID, "echo health-check v2")
	if err != nil {
		return err
	}
	v := b.version(b.facts.Machine)
	v.Package = registry.Package{Digest: digest, Path: dir, Entrypoint: "run.sh"}
	updated, err := b.store.UpdateVersion(b.ctx, job.JobID, "upd-"+job.JobID, cur.Version, v, cli)
	if err != nil {
		return fmt.Errorf("update version: %w", err)
	}
	if _, err := b.store.MarkReady(b.ctx, job.JobID, updated.Revision, registry.PackageEvidence{Digest: digest, Path: dir, MachineID: b.facts.Machine}, cli); err != nil {
		return fmt.Errorf("ready v2: %w", err)
	}
	// An exception a person still has to act on.
	_, err = b.tx(job.JobID, recon, func(tx *registry.JobTx) error {
		return tx.Observe(registry.Observation{State: registry.AvailabilityAuthRequired, Kind: "auth", Detail: "fixture credential expired"})
	})
	b.facts.Lifecycles[job.JobID] = registry.LifecycleActive
	return err
}

// uncertainEffect leaves an action whose effect is unknown, one still
// executing, one that failed and one not applied, with a live claim.
func (b *builder) uncertainEffect() error {
	job, err := b.register("data-collector", b.facts.Machine, b.facts.Projects[0], true)
	if err != nil {
		return err
	}
	c, err := b.claim(job.JobID, registry.ClaimReview, b.facts.Machine, 24*time.Hour)
	if err != nil {
		return err
	}
	for _, st := range []struct {
		params string
		state  registry.ActionState
	}{
		{`{"n":1}`, registry.ActionUncertain},
		{`{"n":2}`, registry.ActionFailed},
		{`{"n":3}`, registry.ActionNotApplied},
	} {
		id, g, err := b.routine(job, c, "restart", st.params)
		if err != nil {
			return fmt.Errorf("routine %s: %w", st.state, err)
		}
		if err := b.settle(job.JobID, id, g, c, st.state, ""); err != nil {
			return fmt.Errorf("settle %s: %w", st.state, err)
		}
	}
	if _, _, err := b.routine(job, c, "diagnose", `{"n":4}`); err != nil {
		return fmt.Errorf("executing: %w", err)
	}
	b.facts.ActionStates[registry.ActionExecuting]++
	b.facts.Lifecycles[job.JobID] = registry.LifecycleActive
	return nil
}

// lifecycles leaves a paused, a needs-human, a completed and a manually
// retired job.
func (b *builder) lifecycles() error {
	for _, tc := range []struct {
		name string
		t    registry.Transition
		want registry.Lifecycle
	}{
		{"paused", registry.Transition{Op: registry.OpPause, Detail: "fixture pause"}, registry.LifecyclePaused},
		{"needs-human", registry.Transition{Op: registry.OpNeedsHuman, Detail: "fixture question"}, registry.LifecycleNeedsHuman},
		{"validation", registry.Transition{Op: registry.OpComplete, Detail: "success criteria met", Evidence: []string{"run:fixture-v-9"}}, registry.LifecycleCompleted},
		{"manual-retire", registry.Transition{Op: registry.OpRetire, Reason: registry.RetireManual, Detail: "experiment over"}, registry.LifecycleRetired},
	} {
		job, err := b.register(tc.name, b.facts.Machine, b.facts.Projects[1], true)
		if err != nil {
			return err
		}
		if tc.name == "manual-retire" {
			b.runs.set(job.JobID, []registry.RunRef{{RunID: "run-mr-1", Running: true}})
		}
		if _, err := b.store.ChangeLifecycle(b.ctx, job.JobID, tc.t, person); err != nil {
			return fmt.Errorf("%s: %w", tc.name, err)
		}
		b.facts.Lifecycles[job.JobID] = tc.want
	}
	return nil
}

func (b *builder) incompleteAndDuplicate() error {
	if _, err := b.register("incomplete", b.facts.Machine, b.facts.Projects[1], false); err != nil {
		return err
	}
	winner, err := b.register("collector-dup", b.facts.Machine, b.facts.Projects[1], true)
	if err != nil {
		return err
	}
	jobID := b.mint(registry.PrefixJob)
	v := b.version(b.facts.Machine)
	digest, dir, err := b.pkg(jobID, "echo dup")
	if err != nil {
		return err
	}
	v.Package = registry.Package{Digest: digest, Path: dir, Entrypoint: "run.sh"}
	_, err = b.store.Register(b.ctx, registry.RegisterInput{JobID: jobID, RequestID: "req-" + jobID, OwnerID: StableOwner,
		ProjectID: b.facts.Projects[1], MachineID: b.facts.Machine, JobKey: "collector-dup", Version: v}, cli)
	if registry.ErrorCode(err) != registry.CodeDuplicate {
		return fmt.Errorf("duplicate registration: want duplicate, got %v", err)
	}
	b.facts.Jobs["duplicate"] = jobID
	b.facts.Lifecycles[winner.JobID] = registry.LifecycleActive
	return nil
}

func (b *builder) expired() error {
	expiry := b.clock().Add(time.Hour)
	job, err := b.register("expiring", b.facts.Machine, b.facts.Projects[1], true, func(v *registry.JobVersion) { v.Lifetime.ExpiresAt = &expiry })
	if err != nil {
		return err
	}
	b.advance(2 * time.Hour)
	if _, err := b.store.ReconcileExpired(b.ctx); err != nil {
		return err
	}
	b.facts.Lifecycles[job.JobID] = registry.LifecycleRetired
	return nil
}

// targetDeleted retires a job by an authoritative deletion of its target,
// leaving an unaffected control job.
func (b *builder) targetDeleted() error {
	gone := registry.Target{Kind: "fixture.volume", Environment: "dev", StableID: map[string]string{"uid": "vol-gone"}, DisplayName: "fixture-gone"}
	dependent, err := b.register("target-deleted", b.facts.Machine, b.facts.Projects[1], true, func(v *registry.JobVersion) { v.Targets = []registry.Target{gone} })
	if err != nil {
		return err
	}
	control, err := b.register("target-control", b.facts.Machine, b.facts.Projects[1], true)
	if err != nil {
		return err
	}
	if _, err := b.store.RecordResourceEvent(b.ctx, registry.ResourceEvent{Target: gone, Observation: registry.ResourceDeleted, Authoritative: true,
		Evidence: []string{"fixture: NotFound uid vol-gone"}}, recon); err != nil {
		return err
	}
	b.facts.Lifecycles[dependent.JobID] = registry.LifecycleRetired
	b.facts.Lifecycles[control.JobID] = registry.LifecycleActive
	return nil
}

// superseded leaves a proposal superseded by a version update.
func (b *builder) superseded() error {
	job, err := b.register("superseded", b.facts.Machine, b.facts.Projects[0], true)
	if err != nil {
		return err
	}
	c, err := b.claim(job.JobID, registry.ClaimReview, b.facts.Machine, time.Hour)
	if err != nil {
		return err
	}
	if _, err := b.propose(job, c, "Resize before the update?"); err != nil {
		return err
	}
	if err := b.release(job.JobID, c); err != nil {
		return err
	}
	digest, dir, err := b.pkg(job.JobID, "echo superseded v2")
	if err != nil {
		return err
	}
	v := b.version(b.facts.Machine)
	v.Package = registry.Package{Digest: digest, Path: dir, Entrypoint: "run.sh"}
	if _, err := b.store.UpdateVersion(b.ctx, job.JobID, "upd-"+job.JobID, 1, v, cli); err != nil {
		return err
	}
	// Left incomplete: the new version's package is not asserted yet.
	b.facts.ProposalStates[registry.ProposalSuperseded]++
	b.facts.Lifecycles[job.JobID] = registry.LifecycleActive
	return nil
}

// artifacts records a run's deliverables: a hub copy, a machine copy, an
// empty machine file and one the run did not produce, with the retained
// status the registry keeps of the publishing execution.
func (b *builder) artifacts() error {
	job, err := b.register("artifact-producer", b.facts.Machine, b.facts.Projects[0], true, func(v *registry.JobVersion) {
		v.ExpectedOutcome.Deliverables = []registry.Deliverable{
			{Name: "snapshot", Path: "snapshot.json", Delivery: registry.DeliveryHub, Required: true},
			{Name: "raw", Path: "raw/export.csv"},
			{Name: "empty", Path: "empty.txt"},
			{Name: "notes", Path: "notes.txt", Required: true},
		}
	})
	if err != nil {
		return err
	}
	const runID, attemptID = "run-art-1", "att-art-1"
	execRef := registry.ExecutionRef(attemptID, "")
	snapshot := []byte(`{"healthy":true}` + "\n")
	raw := []byte("a,b\n1,2\n")
	hubArchive := filepath.ToSlash(filepath.Join(b.layout.HubMount, "artifacts", job.JobID, runID, attemptID))
	latest := registry.RunAttempt{AttemptID: attemptID, SpecSHA256: job.DAGSpecSHA256, Status: "running", Running: true, ArchiveDir: hubArchive,
		Snapshot: json.RawMessage(`{"status":"running","attemptId":"att-art-1"}`)}
	manifest := registry.ArtifactManifest{AttemptID: attemptID, JobVersion: 1, Artifacts: []registry.ArtifactRecord{
		{Deliverable: "snapshot", Path: "snapshot.json", SHA256: digestOf(snapshot), Bytes: int64(len(snapshot)), Location: registry.DeliveryHub, MachineID: b.facts.Machine},
		{Deliverable: "raw", Path: "raw/export.csv", SHA256: digestOf(raw), Bytes: int64(len(raw)), Location: registry.DeliveryMachine, MachineID: b.facts.Machine},
		{Deliverable: "empty", Path: "empty.txt", SHA256: digestOf(nil), Location: registry.DeliveryMachine, MachineID: b.facts.Machine},
		{Deliverable: "notes", Path: "notes.txt", Missing: true},
	}}
	if _, err := b.tx(job.JobID, cli, func(tx *registry.JobTx) error {
		_, err := tx.RecordArtifacts(b.ctx, b.store, runID, latest, manifest)
		return err
	}); err != nil {
		return fmt.Errorf("record artifacts: %w", err)
	}
	// The bytes: the hub copy in the run's native artifact directory, the
	// machine copies in the machine's sealed execution output.
	hubRel := filepath.Join("artifacts", job.JobID, runID, attemptID, filepath.FromSlash(registry.HubCopyPath(execRef, "snapshot.json")))
	if err := writeFile(filepath.Join(b.layout.DataDir, hubRel), snapshot); err != nil {
		return err
	}
	b.facts.HubArtifacts = append(b.facts.HubArtifacts, filepath.ToSlash(hubRel))
	out := txepkg.ExecutionOutputDir(filepath.Join(b.layout.MachineHome, "outputs", job.JobID), runID, execRef)
	for name, data := range map[string][]byte{"raw/export.csv": raw, "empty.txt": nil} {
		p := filepath.Join(out, filepath.FromSlash(name))
		if err := writeFile(p, data); err != nil {
			return err
		}
		rel, _ := filepath.Rel(b.layout.MachineHome, p)
		b.facts.MachineArtifacts = append(b.facts.MachineArtifacts, filepath.ToSlash(rel))
	}
	sort.Strings(b.facts.MachineArtifacts)
	lookup := func(p string) (string, bool, error) {
		data, err := os.ReadFile(filepath.Join(b.layout.DataDir, "artifacts", job.JobID, runID, attemptID, filepath.FromSlash(p))) //nolint:gosec // fixture path
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		return digestOf(data), true, nil
	}
	if _, err := b.store.CheckHubArtifacts(b.ctx, job.JobID, runID, execRef, hubArchive, lookup, true); err != nil {
		return fmt.Errorf("check hub artifacts: %w", err)
	}
	b.facts.Lifecycles[job.JobID] = registry.LifecycleActive
	return nil
}

// secondMachine registers a job assigned to a machine whose home is not in
// the fixture: its package is on that machine.
func (b *builder) secondMachine() error {
	job, err := b.register("linux-worker-job", b.facts.Machine2, b.facts.Projects[1], true)
	if err != nil {
		return err
	}
	// The package was written to this home by register; it belongs on the
	// other machine, so it is moved out of the scanned home.
	if err := os.RemoveAll(filepath.Join(b.layout.MachineHome, "packages", job.JobID)); err != nil {
		return err
	}
	delete(b.facts.Packages, job.JobID)
	b.facts.Lifecycles[job.JobID] = registry.LifecycleActive
	return nil
}

// uncommittedHistory leaves history written by a commit that did not
// happen: a lifecycle change whose aggregate compare-and-swap lost. The
// registry never shows such records; they stay on disk as they are.
func (b *builder) uncommittedHistory() error {
	jobID := b.facts.Jobs["paused"]
	col := persisfile.NewCollection(registry.Dir(b.layout.DataDir), persisfile.WithIndentedJSON())
	ev := registry.Event{EventID: b.mint(registry.PrefixEvent), JobID: jobID, Kind: registry.EventLifecycle, From: "paused", To: "active",
		Actor: person, At: b.clock()}
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	id := "history/" + jobID + "/events/" + b.mint("rec")[4:]
	return col.Create(b.ctx, &persis.Record{ID: id, Data: data, CreatedAt: b.clock(), UpdatedAt: b.clock()})
}

// authz binds the owner's identity explicitly, and leaves a pending request
// from another person who signed in first: that grants nothing.
func (b *builder) authz() error {
	z, err := authz.New(persisfile.NewCollection(authz.Dir(b.layout.DataDir), persisfile.WithIndentedJSON()), registryFacts{b.store}, authz.WithClock(b.clock))
	if err != nil {
		return err
	}
	exp := b.clock().Add(time.Hour)
	first := authn.Principal{Identity: authn.Identity{Issuer: Issuer, Subject: "subject-other-person"}, Class: authn.ClassPerson, Expires: exp}
	if _, err := z.RequestBinding(b.ctx, first, authz.Shown{Username: "connor", Email: "connor@fixture.invalid", Name: "Connor Wang"}); err != nil {
		return fmt.Errorf("first sign-in request: %w", err)
	}
	b.advance(time.Minute)
	owner := authn.Principal{Identity: authn.Identity{Issuer: Issuer, Subject: "subject-owner"}, Class: authn.ClassPerson, Expires: b.clock().Add(time.Hour)}
	if _, err := z.RequestBinding(b.ctx, owner, authz.Shown{Username: "owner", Name: "Fixture Owner"}); err != nil {
		return fmt.Errorf("owner request: %w", err)
	}
	if _, err := z.ApproveBinding(b.ctx, authz.PlatformAdmin("fixture-admin"), owner.Identity, StableOwner); err != nil {
		return fmt.Errorf("approve: %w", err)
	}
	return nil
}

// nativeRuns writes the run files Dagu keeps for a few runs: synthetic,
// in the shape of a run directory with a status and a log.
func (b *builder) nativeRuns() error {
	for _, name := range []string{"health-check", "data-collector", "manual-retire"} {
		jobID := b.facts.Jobs[name]
		dir := filepath.Join(b.layout.DataDir, "dag-runs", jobID, "dag-runs", "2026", "09", "01", "dag-run_20260901_000000Z_run-"+name)
		if err := writeFile(filepath.Join(dir, "attempt_1", "status.jsonl"), []byte(`{"status":"succeeded","name":"`+jobID+`"}`+"\n")); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(dir, "attempt_1", "run.stdout.log"), []byte("fixture output for "+name+"\n")); err != nil {
			return err
		}
	}
	if err := writeFile(filepath.Join(b.layout.DataDir, "suspend", b.facts.Jobs["paused"]+".suspend"), nil); err != nil {
		return err
	}
	return writeFile(filepath.Join(b.layout.MachineHome, "receipts", "journal.jsonl"), []byte(`{"request":"fixture"}`+"\n"))
}

func writeFile(p string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// registryFacts answers the authorization store's questions from the
// registry.
type registryFacts struct{ s *registry.Store }

func (r registryFacts) OwnerExists(ctx context.Context, ownerID string) (bool, error) {
	_, err := r.s.GetOwner(ctx, ownerID)
	if registry.ErrorCode(err) == registry.CodeNotFound {
		return false, nil
	}
	return err == nil, err
}

func (r registryFacts) JobFacts(ctx context.Context, jobID string) (authz.JobFacts, error) {
	j, err := r.s.GetJob(ctx, jobID)
	if err != nil {
		return authz.JobFacts{}, err
	}
	return authz.JobFacts{OwnerID: j.OwnerID, ProjectID: j.ProjectID, MachineID: j.MachineID}, nil
}

func (r registryFacts) ProjectOwner(ctx context.Context, projectID string) (string, error) {
	p, err := r.s.GetProject(ctx, projectID)
	if err != nil {
		return "", err
	}
	return p.OwnerID, nil
}

func (r registryFacts) MachineOwner(ctx context.Context, machineID string) (string, error) {
	m, err := r.s.GetMachine(ctx, machineID)
	if err != nil {
		return "", err
	}
	return m.OwnerID, nil
}

// runs is the fixture's Dagu: it knows the runs the fixture says exist.
type runs struct {
	mu        sync.Mutex
	active    map[string][]registry.RunRef
	suspended map[string]bool
}

func newRuns() *runs {
	return &runs{active: map[string][]registry.RunRef{}, suspended: map[string]bool{}}
}

func (r *runs) set(dag string, refs []registry.RunRef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active[dag] = refs
}

func (r *runs) ActiveRuns(_ context.Context, dag string) ([]registry.RunRef, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]registry.RunRef(nil), r.active[dag]...), nil
}

func (r *runs) StopRun(context.Context, string, registry.RunRef) error { return nil }

func (r *runs) IsSuspended(_ context.Context, dag string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.suspended[dag], nil
}

func (r *runs) SetSuspended(_ context.Context, dag string, s bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suspended[dag] = s
	return nil
}

func (r *runs) RunFinished(context.Context, string, registry.RunRef) (bool, error) {
	return false, registry.ErrRunNotFound
}

func (r *runs) LatestAttempt(context.Context, string, string) (registry.RunAttempt, error) {
	return registry.RunAttempt{}, registry.ErrRunNotFound
}

func (r *runs) RetryExecution(context.Context, string, string, string) (registry.RetryExecution, error) {
	return registry.RetryExecution{}, registry.ErrRunNotFound
}
