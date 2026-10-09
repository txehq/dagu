// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package decision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dagucloud/dagu/v2/internal/humantask"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// CodeIdempotencyMismatch refuses a repeated idempotency key whose decision
// content differs from the decision stored under it.
const CodeIdempotencyMismatch registry.Code = "idempotency_mismatch"

// Registry is the part of the TXE registry the service uses.
type Registry interface {
	WithJobTx(ctx context.Context, jobID string, actor registry.Actor, fn func(tx *registry.JobTx) error) (*registry.Job, error)
	ListDecisions(ctx context.Context, jobID string, limit int) ([]*registry.Decision, error)
	ListArchivedProposals(ctx context.Context, jobID string, limit int) ([]*registry.Proposal, error)
}

// TaskCompleter completes a native Dagu human task.
type TaskCompleter interface {
	Complete(ctx context.Context, request humantask.CompleteRequest) (humantask.Result, error)
}

// RunRetrier queues a native retry of a job's latest run and returns the
// retried DAG-run ID.
type RunRetrier interface {
	RetryLatest(ctx context.Context, dagName string) (string, error)
}

// Service records decisions. The decision commit is authoritative: the native
// human task is completed only after it, so a completed task always has a
// durable decision, and a failed completion is retried by replaying the same
// request.
type Service struct {
	Registry Registry
	Tasks    TaskCompleter
	Retrier  RunRetrier
	Now      func() time.Time
}

// Result is the outcome of one decision request.
type Result struct {
	Decision *registry.Decision
	// Proposal is the proposal after the decision. It is nil when the
	// decision closed the proposal and it left the job aggregate.
	Proposal *registry.Proposal
	Job      *registry.Job
	// AlreadyRecorded reports an identical earlier request.
	AlreadyRecorded bool
	// NativeErr is set when the decision is stored but its native human task
	// could not be completed yet; replaying the request retries it.
	NativeErr error
	// RetryRunID is the DAG-run retried by a retry verdict.
	RetryRunID string
	RetryErr   error
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Decide records req for proposalID of jobID on behalf of actor.
func (s *Service) Decide(ctx context.Context, jobID, proposalID string, req Request, actor registry.Actor) (*Result, error) {
	now := s.now()
	if err := req.Validate(now); err != nil {
		return nil, err
	}
	decisionID, err := registry.NewID(registry.PrefixDecision, now)
	if err != nil {
		return nil, err
	}
	effect := EffectOf(req.Verdict)

	var stored *registry.Decision
	var replayID string
	job, err := s.Registry.WithJobTx(ctx, jobID, actor, func(tx *registry.JobTx) error {
		stored, replayID = nil, ""
		if id, ok := tx.DecisionByKey(req.IdempotencyKey); ok {
			replayID = id
			return nil
		}
		d, err := tx.AppendDecision(registry.Decision{
			DecisionID:       decisionID,
			ProposalID:       proposalID,
			ProposalRevision: req.ExpectedProposalRevision,
			BindingDigest:    req.BindingDigest,
			Verdict:          req.Verdict,
			Instructions:     req.Instructions,
			SnoozeUntil:      req.SnoozeUntil,
			IdempotencyKey:   req.IdempotencyKey,
		}, effect.Proposal)
		if err != nil {
			return err
		}
		if err := applyLifecycle(tx, effect.Lifecycle, decisionID); err != nil {
			return err
		}
		stored = d
		return nil
	})
	if err != nil {
		return nil, err
	}

	result := &Result{Job: job, Proposal: job.Proposals[proposalID]}
	if replayID != "" {
		d, err := s.storedDecision(ctx, jobID, replayID)
		if err != nil {
			return nil, err
		}
		if d.ProposalID != proposalID || !req.SameAs(requestOf(d)) {
			return nil, &registry.Error{
				Code:    CodeIdempotencyMismatch,
				Message: "idempotency key was used for a different decision",
				Current: d,
			}
		}
		result.Decision, result.AlreadyRecorded = d, true
	} else {
		result.Decision = stored
		if effect.RetryRun && s.Retrier != nil {
			result.RetryRunID, result.RetryErr = s.Retrier.RetryLatest(ctx, jobID)
		}
	}

	if result.Decision.NativeResume == "pending" {
		result.NativeErr = s.resumeNative(ctx, job, result.Decision, actor)
		if result.NativeErr == nil {
			result.Decision.NativeResume = "completed"
		}
	}
	return result, nil
}

func applyLifecycle(tx *registry.JobTx, op LifecycleOp, decisionID string) error {
	detail := "human decision " + decisionID
	switch op {
	case LifecycleNone:
		return nil
	case LifecyclePause:
		return tx.Transition(registry.Transition{Op: registry.OpPause, Detail: detail, Evidence: []string{decisionID}})
	case LifecycleRetire:
		return tx.Transition(registry.Transition{
			Op: registry.OpRetire, Reason: registry.RetireManual, Detail: detail, Evidence: []string{decisionID},
		})
	}
	return fmt.Errorf("decision: unknown lifecycle op %q", op)
}

func requestOf(d *registry.Decision) *Request {
	return &Request{
		ExpectedProposalRevision: d.ProposalRevision,
		BindingDigest:            d.BindingDigest,
		Verdict:                  d.Verdict,
		Instructions:             d.Instructions,
		SnoozeUntil:              d.SnoozeUntil,
		IdempotencyKey:           d.IdempotencyKey,
	}
}

func (s *Service) storedDecision(ctx context.Context, jobID, decisionID string) (*registry.Decision, error) {
	decisions, err := s.Registry.ListDecisions(ctx, jobID, 0)
	if err != nil {
		return nil, err
	}
	for _, d := range decisions {
		if d.DecisionID == decisionID {
			return d, nil
		}
	}
	return nil, fmt.Errorf("decision: %s is indexed but not in the decision history", decisionID)
}

// nativeTask finds the native task of a proposal, open or archived.
func (s *Service) nativeTask(ctx context.Context, job *registry.Job, proposalID string) (*registry.NativeTask, error) {
	if p := job.Proposals[proposalID]; p != nil {
		return p.NativeTask, nil
	}
	archived, err := s.Registry.ListArchivedProposals(ctx, job.JobID, 0)
	if err != nil {
		return nil, err
	}
	for _, p := range archived {
		if p.ProposalID == proposalID {
			return p.NativeTask, nil
		}
	}
	return nil, nil
}

// errNoTaskCompleter reports that native completion is not configured.
var errNoTaskCompleter = errors.New("decision: native human-task completion is not configured")

func (s *Service) resumeNative(ctx context.Context, job *registry.Job, d *registry.Decision, actor registry.Actor) error {
	if s.Tasks == nil {
		return errNoTaskCompleter
	}
	task, err := s.nativeTask(ctx, job, d.ProposalID)
	if err != nil {
		return err
	}
	if task == nil {
		return fmt.Errorf("decision: proposal %s has no native task", d.ProposalID)
	}
	raw, err := json.Marshal(map[string]string{"decision_id": d.DecisionID, "verdict": string(d.Verdict)})
	if err != nil {
		return err
	}
	input, err := humantask.ParseJSONInput(raw)
	if err != nil {
		return err
	}
	if _, err := s.Tasks.Complete(ctx, humantask.CompleteRequest{
		DAGName:       task.DAG,
		DAGRunID:      task.RunID,
		StepID:        task.StepID,
		Input:         input,
		CompletedBy:   actor.ID,
		CompletedByID: actor.ID,
	}); err != nil {
		return err
	}
	_, err = s.Registry.WithJobTx(ctx, job.JobID, actor, func(tx *registry.JobTx) error {
		return tx.MarkNativeResumed(d.ProposalID, d.DecisionID)
	})
	return err
}
