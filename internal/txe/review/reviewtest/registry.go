// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

// Package reviewtest provides a reference implementation of review.Registry
// for tests and disposable fixtures. It models the contract the reviewer
// relies on -- fenced claims, compare-and-set checkpoints, an atomic
// pre-effect guard and binding-checked decisions -- and is not a store for
// real jobs: the TXE registry on the service is the only authority there.
package reviewtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/review"
)

// State is the whole fixture registry. It is exported so tests can assert on
// the durable records directly.
type State struct {
	Jobs        map[string]review.Job        `json:"jobs"`
	Checkpoints map[string]review.Checkpoint `json:"checkpoints"`
	Claims      map[string]review.Claim      `json:"claims"`
	Fences      map[string]int               `json:"fences"`
	Runs        map[string][]review.RunEvidence
	Decisions   map[string][]review.Decision
	Proposals   map[string][]review.Proposal
	Actions     map[string][]review.Action
	Reviews     map[string][]review.Review
	Exceptions  []review.Exception
	// ConsumedResolutions are escalation answers already used by a grant.
	ConsumedResolutions map[string]bool
	// Closures are the recorded attempts to close superseded proposals'
	// decision runs, by proposal id.
	Closures         map[string][]review.Closure
	ClosureAttempted map[string]time.Time
	// Transitions records every claim and checkpoint change in order.
	Transitions []string
	Seq         int
}

func newState() *State {
	return &State{
		Jobs:        map[string]review.Job{},
		Checkpoints: map[string]review.Checkpoint{},
		Claims:      map[string]review.Claim{},
		Fences:      map[string]int{},
		Runs:        map[string][]review.RunEvidence{},
		Decisions:   map[string][]review.Decision{},
		Proposals:   map[string][]review.Proposal{},
		Actions:     map[string][]review.Action{},
		Reviews:     map[string][]review.Review{},
	}
}

// Registry implements review.Registry in memory, or in one JSON file when
// Path is set so that separate processes share it.
type Registry struct {
	// Path is the backing file; empty keeps the state in memory.
	Path string
	// Now is the registry clock; time.Now when nil.
	Now func() time.Time

	mu    sync.Mutex
	state *State
}

var _ review.Registry = (*Registry)(nil)

// New returns an in-memory registry.
func New() *Registry { return &Registry{state: newState()} }

// Open returns a registry backed by the JSON file at path.
func Open(path string) *Registry { return &Registry{Path: path} }

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Update runs fn against the state as one atomic change.
func (r *Registry) Update(fn func(s *State) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Path == "" {
		if r.state == nil {
			r.state = newState()
		}
		return fn(r.state)
	}
	unlock, err := lockFile(r.Path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	s := newState()
	data, err := os.ReadFile(r.Path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, s); err != nil {
			return fmt.Errorf("decode %s: %w", r.Path, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if err := fn(s); err != nil {
		return err
	}
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.Path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.Path)
}

// View reads the state without changing it.
func (r *Registry) View(fn func(s *State)) {
	_ = r.Update(func(s *State) error { fn(s); return nil })
}

func lockFile(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *State) nextID(prefix string) string {
	s.Seq++
	return fmt.Sprintf("%s_%06d", prefix, s.Seq)
}

// BindingDigest is the fixture's stand-in for the registry's canonical
// binding function: it changes whenever the job version, package, target or
// action parameters change.
func BindingDigest(job review.Job, actionName, targetID string, params map[string]string) string {
	if params == nil {
		params = map[string]string{}
	}
	b, _ := json.Marshal([]any{job.ID, job.Version, job.PackageDigest, targetID, actionName, params})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *State) liveClaim(jobID string, now time.Time) (review.Claim, bool) {
	c, ok := s.Claims[jobID]
	if !ok || !now.Before(c.ExpiresAt) {
		return review.Claim{}, false
	}
	return c, true
}

// checkFence refuses a write from any claim that is not the job's current
// live claim.
func (s *State) checkFence(claim review.Claim, now time.Time) error {
	live, ok := s.liveClaim(claim.JobID, now)
	if !ok || live.ID != claim.ID || live.Fence != claim.Fence {
		return review.ErrStaleFence
	}
	return nil
}

// DueJobs implements review.Registry.
func (r *Registry) DueJobs(_ context.Context, machineID string, now time.Time) ([]string, error) {
	var due []string
	err := r.Update(func(s *State) error {
		for id, job := range s.Jobs {
			if job.MachineID != machineID || !job.Lifecycle.Reviewable() {
				continue
			}
			if cp := s.Checkpoints[id]; cp.NextReviewAt.After(now) {
				continue
			}
			due = append(due, id)
		}
		sort.Slice(due, func(i, j int) bool {
			a, b := s.Checkpoints[due[i]].NextReviewAt, s.Checkpoints[due[j]].NextReviewAt
			if !a.Equal(b) {
				return a.Before(b)
			}
			return due[i] < due[j]
		})
		return nil
	})
	return due, err
}

// Job implements review.Registry.
func (r *Registry) Job(_ context.Context, jobID string) (review.Job, error) {
	var job review.Job
	err := r.Update(func(s *State) error {
		j, ok := s.Jobs[jobID]
		if !ok {
			return review.ErrNotFound
		}
		job = j
		return nil
	})
	return job, err
}

// Checkpoint implements review.Registry.
func (r *Registry) Checkpoint(_ context.Context, jobID string) (review.Checkpoint, error) {
	var cp review.Checkpoint
	err := r.Update(func(s *State) error {
		cp = s.Checkpoints[jobID]
		cp.JobID = jobID
		return nil
	})
	return cp, err
}

// AcquireClaim implements review.Registry.
func (r *Registry) AcquireClaim(_ context.Context, req review.ClaimRequest) (review.Claim, error) {
	var claim review.Claim
	err := r.Update(func(s *State) error {
		now := r.now()
		if _, ok := s.Jobs[req.JobID]; !ok {
			return review.ErrNotFound
		}
		if _, held := s.liveClaim(req.JobID, now); held {
			return review.ErrClaimHeld
		}
		// A completed or retired job only admits settling what is open.
		if job := s.Jobs[req.JobID]; !job.Lifecycle.Reviewable() && req.Kind != review.ClaimReconcile {
			return &review.GuardDeniedError{Reason: review.DenyLifecycle, Detail: string(job.Lifecycle)}
		}
		if old, ok := s.Claims[req.JobID]; ok {
			s.Transitions = append(s.Transitions, fmt.Sprintf("claim %s fence %d expired", old.ID, old.Fence))
		}
		s.Fences[req.JobID]++
		claim = review.Claim{
			ID:        s.nextID("clm"),
			JobID:     req.JobID,
			Kind:      req.Kind,
			Holder:    req.Holder,
			Fence:     s.Fences[req.JobID],
			ExpiresAt: now.Add(req.TTL),
		}
		s.Claims[req.JobID] = claim
		s.Transitions = append(s.Transitions, fmt.Sprintf("claim %s fence %d granted to %s (%s)", claim.ID, claim.Fence, claim.Holder, claim.Kind))
		return nil
	})
	return claim, err
}

// ReleaseClaim implements review.Registry.
func (r *Registry) ReleaseClaim(_ context.Context, claim review.Claim) error {
	return r.Update(func(s *State) error {
		if err := s.checkFence(claim, r.now()); err != nil {
			return err
		}
		delete(s.Claims, claim.JobID)
		s.Transitions = append(s.Transitions, fmt.Sprintf("claim %s fence %d released", claim.ID, claim.Fence))
		return nil
	})
}

// RunsAfter implements review.Registry.
func (r *Registry) RunsAfter(_ context.Context, jobID, cursor string) ([]review.RunEvidence, error) {
	var out []review.RunEvidence
	err := r.Update(func(s *State) error {
		runs := s.Runs[jobID]
		start := 0
		for i, run := range runs {
			if run.RunID == cursor {
				start = i + 1
			}
		}
		out = append(out, runs[start:]...)
		return nil
	})
	return out, err
}

// DecisionsAfter implements review.Registry.
func (r *Registry) DecisionsAfter(_ context.Context, jobID, cursor string) ([]review.Decision, error) {
	var out []review.Decision
	err := r.Update(func(s *State) error {
		decisions := s.Decisions[jobID]
		start := 0
		for i, d := range decisions {
			if d.ID == cursor {
				start = i + 1
			}
		}
		out = append(out, decisions[start:]...)
		return nil
	})
	return out, err
}

// Decision implements review.Registry.
func (r *Registry) Decision(_ context.Context, jobID, decisionID string) (review.Decision, error) {
	var out review.Decision
	err := r.Update(func(s *State) error {
		for _, d := range s.Decisions[jobID] {
			if d.ID == decisionID {
				out = d
				return nil
			}
		}
		return review.ErrNotFound
	})
	return out, err
}

// Proposal implements review.Registry.
func (r *Registry) Proposal(_ context.Context, jobID, proposalID string) (review.Proposal, error) {
	var out review.Proposal
	err := r.Update(func(s *State) error {
		for _, p := range s.Proposals[jobID] {
			if p.ID == proposalID {
				out = p
				return nil
			}
		}
		return review.ErrNotFound
	})
	return out, err
}

// OpenProposals implements review.Registry.
func (r *Registry) OpenProposals(_ context.Context, jobID string) ([]review.Proposal, error) {
	var out []review.Proposal
	err := r.Update(func(s *State) error {
		for _, p := range s.Proposals[jobID] {
			if p.State == review.ProposalOpen || p.State == review.ProposalSnoozed {
				out = append(out, p)
			}
		}
		return nil
	})
	return out, err
}

// Review implements review.Registry.
func (r *Registry) Review(_ context.Context, jobID, reviewID string) (review.Review, error) {
	var out review.Review
	err := r.Update(func(s *State) error {
		for _, rev := range s.Reviews[jobID] {
			if rev.ID == reviewID {
				out = rev
				return nil
			}
		}
		return review.ErrNotFound
	})
	return out, err
}

// RequestedRetries implements review.Registry.
func (r *Registry) RequestedRetries(_ context.Context, machineID string, limit int) ([]review.RequestedRetry, error) {
	var out []review.RequestedRetry
	err := r.Update(func(s *State) error {
		for jobID, job := range s.Jobs {
			if job.MachineID != machineID || !job.Lifecycle.Reviewable() {
				continue
			}
			attempted := map[string]bool{}
			for _, a := range s.Actions[jobID] {
				attempted[a.DecisionID] = true
			}
			for _, p := range s.Proposals[jobID] {
				if p.State != review.ProposalDecided || p.ActionName != review.RetryRunAction || p.NativeTask.RunID != "" {
					continue
				}
				for _, d := range slices.Backward(s.Decisions[jobID]) {
					if d.ProposalID != p.ID {
						continue
					}
					if d.Verdict == review.VerdictRetry && !attempted[d.ID] {
						out = append(out, review.RequestedRetry{JobID: jobID, ProposalID: p.ID, DecisionID: d.ID})
					}
					break
				}
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].ProposalID < out[j].ProposalID })
		if limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		return nil
	})
	return out, err
}

// PendingClosures implements review.Registry.
func (r *Registry) PendingClosures(_ context.Context, machineID string, limit int) ([]review.Proposal, error) {
	var out []review.Proposal
	err := r.Update(func(s *State) error {
		for jobID, job := range s.Jobs {
			if job.MachineID != machineID {
				continue
			}
			for _, p := range s.Proposals[jobID] {
				if p.State == review.ProposalSuperseded && p.NativeTask.RunID != "" && !s.closed(p.ID) {
					out = append(out, p)
				}
			}
		}
		// Least recently attempted first, so a failing one moves to the
		// back instead of holding up the rest.
		sort.SliceStable(out, func(i, j int) bool {
			a, b := s.ClosureAttempted[out[i].ID], s.ClosureAttempted[out[j].ID]
			if !a.Equal(b) {
				return a.Before(b)
			}
			return out[i].ID < out[j].ID
		})
		if limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		return nil
	})
	return out, err
}

func (s *State) closed(proposalID string) bool {
	for _, c := range s.Closures[proposalID] {
		if c.Outcome != review.ClosureFailed {
			return true
		}
	}
	return false
}

// RecordClosure implements review.Registry.
func (r *Registry) RecordClosure(_ context.Context, closure review.Closure) (int, error) {
	failed := 0
	err := r.Update(func(s *State) error {
		if s.Closures == nil {
			s.Closures = map[string][]review.Closure{}
		}
		if s.ClosureAttempted == nil {
			s.ClosureAttempted = map[string]time.Time{}
		}
		s.Closures[closure.ProposalID] = append(s.Closures[closure.ProposalID], closure)
		s.ClosureAttempted[closure.ProposalID] = r.now()
		for _, c := range s.Closures[closure.ProposalID] {
			if c.Outcome == review.ClosureFailed {
				failed++
			}
		}
		return nil
	})
	return failed, err
}

// Actions implements review.Registry.
func (r *Registry) Actions(_ context.Context, jobID string) ([]review.Action, error) {
	var out []review.Action
	err := r.Update(func(s *State) error {
		out = append(out, s.Actions[jobID]...)
		return nil
	})
	return out, err
}

// BeginAction implements review.Registry: the guard and the started record
// are one atomic change.
func (r *Registry) BeginAction(_ context.Context, req review.BeginRequest) (review.Action, error) {
	var out review.Action
	err := r.Update(func(s *State) error {
		now := r.now()
		jobID := req.Claim.JobID
		if err := s.checkFence(req.Claim, now); err != nil {
			return err
		}
		for _, a := range s.Actions[jobID] {
			if a.ID == req.ActionID {
				out = a
				return review.ErrActionExists
			}
		}
		job := s.Jobs[jobID]
		if job.Lifecycle != review.LifecycleActive && job.Lifecycle != review.LifecycleNeedsHuman {
			return &review.GuardDeniedError{Reason: review.DenyLifecycle, Detail: string(job.Lifecycle)}
		}
		if job.Version != req.JobVersion {
			return &review.GuardDeniedError{Reason: review.DenyVersionChanged}
		}
		declared, ok := job.Review.Action(req.Name)
		// The reserved retry is not a job action. It exists only as an
		// approved effect, never as a routine one.
		if req.Name == review.RetryRunAction && req.DecisionID != "" {
			ok = true
		}
		if !ok {
			return &review.GuardDeniedError{Reason: review.DenyNotPermitted, Detail: "action is not declared"}
		}
		wantKind := review.ClaimReview
		if req.DecisionID != "" {
			wantKind = review.ClaimExecution
		}
		if req.Claim.Kind != wantKind {
			return &review.GuardDeniedError{Reason: review.DenyNotPermitted, Detail: "claim kind " + string(req.Claim.Kind) + " cannot authorize this effect"}
		}
		if req.DecisionID == "" {
			if !declared.Routine {
				return &review.GuardDeniedError{Reason: review.DenyNotPermitted, Detail: "action needs a human decision"}
			}
			if s.intentUnresolved(job, req.IntentKey) {
				return &review.GuardDeniedError{Reason: review.DenyIntentUnresolved}
			}
			// An owner's "retry" on an escalation permits one more attempt.
			// It is used up by this grant, so a replay cannot use it again.
			s.consumeResolution(job, req.IntentKey)
		} else if denied := s.checkDecision(job, req); denied != nil {
			return denied
		}
		out = review.Action{
			ID: req.ActionID, JobID: jobID, JobVersion: req.JobVersion,
			Name: req.Name, TargetID: req.TargetID, Params: req.Params,
			IntentKey: req.IntentKey, ReviewID: req.ReviewID,
			ProposalID: req.ProposalID, DecisionID: req.DecisionID,
			State: review.ActionExecuting, ClaimID: req.Claim.ID, StartedAt: now,
			GrantID:        s.nextID("grt"),
			GrantExpiresAt: now.Add(grantTimeout(req.Timeout)),
		}
		s.Actions[jobID] = append(s.Actions[jobID], out)
		return nil
	})
	return out, err
}

// consumeResolution marks the retry answer for an intent's escalated attempt
// as used.
func (s *State) consumeResolution(job review.Job, intent string) {
	actions := s.Actions[job.ID]
	for _, action := range slices.Backward(actions) {
		if action.IntentKey != intent {
			continue
		}
		if action.State == review.ActionEscalated {
			if s.ConsumedResolutions == nil {
				s.ConsumedResolutions = map[string]bool{}
			}
			s.ConsumedResolutions[review.UncertainProposalID(action.ID, job.Version)] = true
		}
		return
	}
}

func grantTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 2 * time.Minute
	}
	return d
}

// intentUnresolved reports whether the latest attempt of an intent still has
// an unknown effect: executing, uncertain, or escalated without a retry
// decision on its escalation for the job's current version.
func (s *State) intentUnresolved(job review.Job, intent string) bool {
	jobID := job.ID
	actions := s.Actions[jobID]
	for _, a := range slices.Backward(actions) {
		if a.IntentKey != intent {
			continue
		}
		switch a.State {
		case review.ActionExecuting, review.ActionUncertain:
			return true
		case review.ActionEscalated:
			if s.ConsumedResolutions[review.UncertainProposalID(a.ID, job.Version)] {
				return true
			}
			verdict := review.Verdict("")
			for _, d := range s.Decisions[jobID] {
				// Only an answer to the question asked about this version of
				// the job counts.
				if d.ProposalID == review.UncertainProposalID(a.ID, job.Version) {
					verdict = d.Verdict
				}
			}
			return verdict != review.VerdictRetry
		case review.ActionSucceeded, review.ActionFailed, review.ActionNotApplied:
			return false
		}
	}
	return false
}

// checkDecision requires the proposal's latest decision to be an approval
// whose binding still matches the job as it is now.
func (s *State) checkDecision(job review.Job, req review.BeginRequest) *review.GuardDeniedError {
	var proposal *review.Proposal
	for i := range s.Proposals[job.ID] {
		if s.Proposals[job.ID][i].ID == req.ProposalID {
			proposal = &s.Proposals[job.ID][i]
		}
	}
	if proposal == nil || proposal.State != review.ProposalDecided {
		return &review.GuardDeniedError{Reason: review.DenyDecisionStale, Detail: "proposal is not in a decided state"}
	}
	var latest *review.Decision
	for i := range s.Decisions[job.ID] {
		if s.Decisions[job.ID][i].ProposalID == req.ProposalID {
			latest = &s.Decisions[job.ID][i]
		}
	}
	authorizes := latest != nil && (latest.Verdict == review.VerdictApprove ||
		(latest.Verdict == review.VerdictRetry && proposal.ActionName == review.RetryRunAction))
	if latest == nil || latest.ID != req.DecisionID || !authorizes {
		return &review.GuardDeniedError{Reason: review.DenyNotApproved}
	}
	current := BindingDigest(job, proposal.ActionName, proposal.TargetID, proposal.Params)
	if latest.BindingDigest != current {
		return &review.GuardDeniedError{Reason: review.DenyDecisionStale, Detail: "binding changed after approval"}
	}
	return nil
}

var allowedTransitions = map[review.ActionState][]review.ActionState{
	review.ActionExecuting: {review.ActionSucceeded, review.ActionFailed, review.ActionUncertain},
	review.ActionUncertain: {review.ActionSucceeded, review.ActionNotApplied, review.ActionEscalated},
}

// FinishAction implements review.Registry.
func (r *Registry) FinishAction(_ context.Context, req review.FinishRequest) error {
	return r.Update(func(s *State) error {
		now := r.now()
		if err := s.checkFence(req.Claim, now); err != nil {
			return err
		}
		actions := s.Actions[req.JobID]
		for i := range actions {
			if actions[i].ID != req.ActionID {
				continue
			}
			allowed := false
			for _, to := range allowedTransitions[actions[i].State] {
				allowed = allowed || to == req.State
			}
			if actions[i].GrantID != req.GrantID {
				return fmt.Errorf("%w: wrong grant for action %s", review.ErrConflict, req.ActionID)
			}
			if !allowed {
				return fmt.Errorf("%w: action %s cannot go from %s to %s", review.ErrConflict, req.ActionID, actions[i].State, req.State)
			}
			actions[i].State = req.State
			actions[i].Receipt = req.Receipt
			actions[i].Detail = req.Detail
			actions[i].FinishedAt = now
			return nil
		}
		return review.ErrNotFound
	})
}

// CreateProposal implements review.Registry.
func (r *Registry) CreateProposal(_ context.Context, claim review.Claim, draft review.Proposal) (review.Proposal, error) {
	var out review.Proposal
	err := r.Update(func(s *State) error {
		if err := s.checkFence(claim, r.now()); err != nil {
			return err
		}
		for _, p := range s.Proposals[draft.JobID] {
			if p.ID == draft.ID {
				out = p
				return nil
			}
		}
		job := s.Jobs[draft.JobID]
		if !job.Lifecycle.Reviewable() || claim.Kind != review.ClaimReview {
			return &review.GuardDeniedError{Reason: review.DenyLifecycle, Detail: "proposals need a review claim on a live job"}
		}
		draft.State = review.ProposalOpen
		draft.BindingDigest = BindingDigest(job, draft.ActionName, draft.TargetID, draft.Params)
		s.Proposals[draft.JobID] = append(s.Proposals[draft.JobID], draft)
		out = draft
		return nil
	})
	return out, err
}

// RecordReview implements review.Registry.
func (r *Registry) RecordReview(_ context.Context, claim review.Claim, rev review.Review) error {
	return r.Update(func(s *State) error {
		if err := s.checkFence(claim, r.now()); err != nil {
			return err
		}
		for _, existing := range s.Reviews[rev.JobID] {
			if existing.ID != rev.ID {
				continue
			}
			// The first recorded review is the episode's decision. A second
			// one over other evidence must not pass as the same record.
			if !slices.Equal(existing.CoveredRuns, rev.CoveredRuns) || !slices.Equal(existing.CoveredDecisions, rev.CoveredDecisions) {
				return fmt.Errorf("%w: review %s is already recorded over other evidence", review.ErrConflict, rev.ID)
			}
			return nil
		}
		s.Reviews[rev.JobID] = append(s.Reviews[rev.JobID], rev)
		return nil
	})
}

// AdvanceCheckpoint implements review.Registry.
func (r *Registry) AdvanceCheckpoint(_ context.Context, claim review.Claim, next review.Checkpoint, expectedVersion int) error {
	return r.Update(func(s *State) error {
		if err := s.checkFence(claim, r.now()); err != nil {
			return err
		}
		current := s.Checkpoints[next.JobID]
		if current.Version != expectedVersion {
			return review.ErrConflict
		}
		s.Checkpoints[next.JobID] = next
		s.Transitions = append(s.Transitions, fmt.Sprintf("checkpoint %s %d -> %d runs<=%q decisions<=%q", next.JobID, expectedVersion, next.Version, next.RunCursor, next.DecisionCursor))
		return nil
	})
}

// DeferReview implements review.Registry.
func (r *Registry) DeferReview(_ context.Context, claim review.Claim, until time.Time) error {
	return r.Update(func(s *State) error {
		if err := s.checkFence(claim, r.now()); err != nil {
			return err
		}
		cp := s.Checkpoints[claim.JobID]
		cp.JobID = claim.JobID
		cp.NextReviewAt = until
		s.Checkpoints[claim.JobID] = cp
		return nil
	})
}

// RaiseException implements review.Registry.
func (r *Registry) RaiseException(_ context.Context, exc review.Exception) error {
	return r.Update(func(s *State) error {
		s.Exceptions = append(s.Exceptions, exc)
		return nil
	})
}

// PutJob registers or replaces a job. Replacing it with a different version,
// package or target set supersedes proposals whose binding no longer
// matches, as the registry does on a material change.
func (r *Registry) PutJob(job review.Job) error {
	return r.Update(func(s *State) error {
		s.Jobs[job.ID] = job
		proposals := s.Proposals[job.ID]
		for i := range proposals {
			p := &proposals[i]
			if p.State != review.ProposalOpen && p.State != review.ProposalSnoozed && p.State != review.ProposalDecided {
				continue
			}
			if p.BindingDigest != BindingDigest(job, p.ActionName, p.TargetID, p.Params) {
				p.State = review.ProposalSuperseded
			}
		}
		return nil
	})
}

// AddRun appends a finished run of the job's script.
func (r *Registry) AddRun(jobID string, run review.RunEvidence) error {
	return r.Update(func(s *State) error {
		s.Runs[jobID] = append(s.Runs[jobID], run)
		return nil
	})
}

// ErrVerdictNotAllowed is returned by Decide for a verdict the proposal does
// not accept.
var ErrVerdictNotAllowed = errors.New("reviewtest: verdict not allowed")

// ErrStaleBinding is returned by Decide when the human answered a proposal
// that has changed since it was shown.
var ErrStaleBinding = errors.New("reviewtest: stale binding")

// Decide records a human decision the way the dashboard does: it is refused
// when the proposal is no longer open or its binding has changed.
func (r *Registry) Decide(jobID, proposalID string, verdict review.Verdict, instructions, actor string) (review.Decision, error) {
	var out review.Decision
	err := r.Update(func(s *State) error {
		job := s.Jobs[jobID]
		proposals := s.Proposals[jobID]
		for i := range proposals {
			p := &proposals[i]
			if p.ID != proposalID {
				continue
			}
			if p.State != review.ProposalOpen && p.State != review.ProposalSnoozed {
				return fmt.Errorf("%w: proposal is %s", ErrStaleBinding, p.State)
			}
			if p.BindingDigest != BindingDigest(job, p.ActionName, p.TargetID, p.Params) {
				return ErrStaleBinding
			}
			// A verdict the proposal does not allow is refused: "retry" in
			// particular is valid on two kinds of proposal only.
			if len(p.AllowedVerdicts) > 0 && !slices.Contains(p.AllowedVerdicts, verdict) {
				return fmt.Errorf("%w: %s is not an allowed verdict for proposal %s", ErrVerdictNotAllowed, verdict, p.ID)
			}
			out = review.Decision{
				ID: s.nextID("dec"), ProposalID: proposalID, JobID: jobID,
				BindingDigest: p.BindingDigest, Verdict: verdict,
				Instructions: instructions, Actor: actor, CreatedAt: r.now(),
			}
			s.Decisions[jobID] = append(s.Decisions[jobID], out)
			// Only an approval leaves the proposal executable.
			switch {
			case verdict == review.VerdictRetry && p.ActionName == review.RetryRunAction:
				// The one case where "retry" leaves a proposal executable.
				p.State = review.ProposalDecided
				return nil
			}
			switch verdict {
			case review.VerdictApprove:
				p.State = review.ProposalDecided
			case review.VerdictSnooze:
				p.State = review.ProposalSnoozed
			case review.VerdictReject, review.VerdictRedirect, review.VerdictRetry, review.VerdictPause, review.VerdictRetire:
				p.State = review.ProposalRejected
			}
			return nil
		}
		return review.ErrNotFound
	})
	return out, err
}
