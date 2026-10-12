// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package decision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	GetJob(ctx context.Context, jobID string) (*registry.Job, error)
	GetDecision(ctx context.Context, jobID, decisionID string) (*registry.Decision, error)
	ListArchivedProposals(ctx context.Context, jobID string, limit int) ([]*registry.Proposal, error)
}

// TaskCompleter completes a native Dagu human task.
type TaskCompleter interface {
	Complete(ctx context.Context, request humantask.CompleteRequest) (humantask.Result, error)
}

// DecisionAuthorizer must allow the caller to record verdict on the job as it
// is inside the decision transaction. It may run more than once, so it must
// only read.
type DecisionAuthorizer func(ctx context.Context, tx *registry.JobTx, verdict Verdict) error

// TaskAuthorizer applies the native authorization for completing the human
// task of one DAG-run on behalf of the caller.
type TaskAuthorizer func(ctx context.Context, dagName, dagRunID string) error

// DecideStepID is the step of the per-proposal decide DAG that collects the
// decision.
const DecideStepID = "decide"

// CodeNativeTaskRefused refuses a decision whose proposal points at a human
// task other than its job's decide task.
const CodeNativeTaskRefused registry.Code = "native_task_refused"

// DecideDAGName is the decide DAG of a machine. Dagu limits DAG names to 39
// characters, so the machine ID is used without its prefix.
func DecideDAGName(machineID string) string {
	return "txe-decide-" + strings.TrimPrefix(machineID, string(registry.PrefixMachine)+"_")
}

// checkNativeTask refuses a locator that does not name the job machine's
// decide task. The locator is written by a reviewer, and completing it uses
// the deciding person's authority, so it must never reach another DAG's
// human task.
func checkNativeTask(job *registry.Job, task *registry.NativeTask) error {
	if task == nil {
		return nil
	}
	if task.DAG != DecideDAGName(job.MachineID) || task.StepID != DecideStepID || task.RunID == "" {
		return &registry.Error{
			Code:    CodeNativeTaskRefused,
			Message: fmt.Sprintf("native task %s/%s/%s is not the decide task of job %s", task.DAG, task.RunID, task.StepID, job.JobID),
		}
	}
	return nil
}

// Service records decisions. The decision commit is authoritative: the native
// human task is completed only after it, so a completed task always has a
// durable decision, and a failed completion is retried by replaying the same
// request.
type Service struct {
	Registry Registry
	Tasks    TaskCompleter
	// AuthorizeDecision is required: without it every decision is refused.
	// It runs for replays too.
	AuthorizeDecision DecisionAuthorizer
	// AuthorizeTask must allow completing the native task before any
	// decision is recorded. It is required for proposals with a native task.
	AuthorizeTask TaskAuthorizer
	Now           func() time.Time
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
}

// FollowUpPending reports a stored decision whose native completion still
// has to happen.
func (r *Result) FollowUpPending() bool {
	return r.NativeErr != nil
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
	if err := req.ValidateShape(); err != nil {
		return nil, err
	}
	if s.AuthorizeDecision == nil {
		return nil, errNoAuthorizer
	}
	decisionID, err := registry.NewID(registry.PrefixDecision, now)
	if err != nil {
		return nil, err
	}
	if err := s.preflight(ctx, jobID, proposalID); err != nil {
		return nil, err
	}

	var stored *registry.Decision
	var replayID string
	job, err := s.Registry.WithJobTx(ctx, jobID, actor, func(tx *registry.JobTx) error {
		stored, replayID = nil, ""
		if err := s.AuthorizeDecision(ctx, tx, req.Verdict); err != nil {
			return err
		}
		if id, ok := tx.DecisionByKey(req.IdempotencyKey); ok {
			replayID = id
			return nil
		}
		if err := req.ValidateNew(tx.Now()); err != nil {
			return err
		}
		action := ""
		if p := tx.Proposal(proposalID); p != nil {
			if err := checkNativeTask(tx.Job, p.NativeTask); err != nil {
				return err
			}
			action = p.Action.Name
		}
		// The registry refuses verdicts with no meaning on the proposal, such
		// as retry on an ordinary action or approve on an escalation.
		effect := EffectOf(req.Verdict, action)
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
		d, err := s.Registry.GetDecision(ctx, jobID, replayID)
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
	}

	// The registry tracks a pending native completion per decision; the
	// immutable decision record keeps the state it was stored with.
	if pending := job.NativeResumes[result.Decision.DecisionID]; pending != nil {
		result.Decision.NativeResume = "pending"
		result.NativeErr = s.resumeNative(ctx, job, pending, result.Decision.Verdict, actor)
		if result.NativeErr == nil {
			result.Decision.NativeResume = "completed"
		}
	} else {
		result.Decision.NativeResume = registry.CurrentNativeResume(job, result.Decision)
	}
	return result, nil
}

// errNoAuthorizer refuses work when the caller wired no authorization.
var errNoAuthorizer = errors.New("decision: authorization is not configured")

// preflight checks the proposal's native task and the caller's right to
// complete it before anything is recorded.
func (s *Service) preflight(ctx context.Context, jobID, proposalID string) error {
	job, err := s.Registry.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	p := job.Proposals[proposalID]
	if p == nil || p.NativeTask == nil {
		return nil
	}
	return s.authorizeNative(ctx, job, p.NativeTask)
}

func (s *Service) authorizeNative(ctx context.Context, job *registry.Job, task *registry.NativeTask) error {
	if err := checkNativeTask(job, task); err != nil {
		return err
	}
	if s.AuthorizeTask == nil {
		return errNoAuthorizer
	}
	return s.AuthorizeTask(ctx, task.DAG, task.RunID)
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

// errNoTaskCompleter reports that native completion is not configured.
var errNoTaskCompleter = errors.New("decision: native human-task completion is not configured")

func (s *Service) resumeNative(ctx context.Context, job *registry.Job, pending *registry.NativeResume, verdict Verdict, actor registry.Actor) error {
	if s.Tasks == nil {
		return errNoTaskCompleter
	}
	task := pending.NativeTask
	// Authorized again on every attempt: a replay may come from another
	// person, and access may have changed since the decision.
	if err := s.authorizeNative(ctx, job, &task); err != nil {
		return err
	}
	raw, err := json.Marshal(map[string]string{"decision_id": pending.DecisionID, "verdict": string(verdict)})
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
		return tx.MarkNativeResumed(pending.DecisionID)
	})
	return err
}

// RetryRequest asks for one exact run of a job to be retried, as a person
// sees it from the dashboard.
type RetryRequest struct {
	RunID string
	// AttemptID and QueuedAt name the execution the person reviewed and asks
	// to retry. A native retry keeps the run ID and either adds an attempt or,
	// through the queue, keeps the attempt and records a later queue marker,
	// so the pair is what makes a retry request unique. QueuedAt is the stored
	// marker byte for byte, empty when the run was never queued.
	AttemptID          string
	QueuedAt           string
	ExpectedJobVersion int
	// RunSpecSHA256 is the digest of the run's DAG snapshot.
	RunSpecSHA256 string
	// RunStartedAt is when the run started; a run that predates the job's
	// current version is of an older version even when its DAG text is
	// unchanged, since the package can differ.
	RunStartedAt   time.Time
	IdempotencyKey string
}

// CodeRunStale refuses a retry of a run that is not of the job's current
// version.
const CodeRunStale registry.Code = "run_stale"

// RequestRetry records a person's request to retry one run as a
// dagu.retry_run proposal decided with retry, in one commit. The reviewer
// executes it under an execution claim through the registry's action
// journal; nothing runs here.
// ValidateShape checks the request names an execution and carries a usable
// idempotency key. It reads no state, so it runs before a replay lookup.
func (r RetryRequest) ValidateShape() error {
	if r.RunID == "" || r.AttemptID == "" {
		return fmt.Errorf("%w: run id and attempt id are required", ErrInvalid)
	}
	if !idempotencyKeyPattern.MatchString(r.IdempotencyKey) {
		return fmt.Errorf("%w: idempotencyKey must be 8-128 characters of [A-Za-z0-9._:-]", ErrInvalid)
	}
	return nil
}

func (s *Service) RequestRetry(ctx context.Context, jobID string, req RetryRequest, actor registry.Actor) (*Result, error) {
	if err := req.ValidateShape(); err != nil {
		return nil, err
	}
	if s.AuthorizeDecision == nil {
		return nil, errNoAuthorizer
	}
	var stored *registry.Decision
	var proposal *registry.Proposal
	var replayID string
	job, err := s.Registry.WithJobTx(ctx, jobID, actor, func(tx *registry.JobTx) error {
		stored, proposal, replayID = nil, nil, ""
		if err := s.AuthorizeDecision(ctx, tx, VerdictRetry); err != nil {
			return err
		}
		if id, ok := tx.DecisionByKey(req.IdempotencyKey); ok {
			replayID = id
			return nil
		}
		j := tx.Job
		if j.Version != req.ExpectedJobVersion {
			return &registry.Error{Code: registry.CodeVersionConflict,
				Message: fmt.Sprintf("job is at version %d, not %d", j.Version, req.ExpectedJobVersion), Current: j}
		}
		v, err := tx.CurrentVersion()
		if err != nil {
			return err
		}
		// Run start times have whole-second precision. A run started in the
		// second the current version was created may be of the previous
		// version, whose package can differ under identical DAG text, so it
		// is refused rather than retried on code it did not run.
		if req.RunSpecSHA256 != j.DAGSpecSHA256 || !req.RunStartedAt.After(v.Created.At.Truncate(time.Second)) {
			return &registry.Error{Code: CodeRunStale,
				Message: fmt.Sprintf("run %s is of an earlier version of this job; retrying it would run version %d's code, so start a new run instead", req.RunID, j.Version)}
		}
		p, d, err := tx.ProposeRetry(registry.RetryRunParams{
			RunID: req.RunID, AttemptID: req.AttemptID, QueuedAt: req.QueuedAt,
			RunSpecSHA256: j.DAGSpecSHA256, PackageDigest: j.PackageDigest,
		}, req.IdempotencyKey)
		if err != nil {
			return err
		}
		stored, proposal = d, p
		return nil
	})
	if err != nil {
		return nil, err
	}
	if replayID != "" {
		res, _, err := s.ReplayRetry(ctx, jobID, req, actor)
		return res, err
	}
	result := &Result{Job: job, Proposal: proposal, Decision: stored}
	result.Decision.NativeResume = registry.CurrentNativeResume(job, result.Decision)
	return result, nil
}

// ReplayRetry returns the decision an earlier retry request stored under
// req.IdempotencyKey. found is false when no decision is stored under the
// key. The stored request must be the same request: the same run, execution
// and job version, or the key is refused as reused for a different intent. A
// replay reads durable history, so it still resolves after the retry ran and
// its proposal was archived, and it needs no new-request checks on the run:
// the execution it names need not still be the latest.
func (s *Service) ReplayRetry(ctx context.Context, jobID string, req RetryRequest, actor registry.Actor) (*Result, bool, error) {
	if err := req.ValidateShape(); err != nil {
		return nil, false, err
	}
	if s.AuthorizeDecision == nil {
		return nil, false, errNoAuthorizer
	}
	var replayID string
	job, err := s.Registry.WithJobTx(ctx, jobID, actor, func(tx *registry.JobTx) error {
		replayID = ""
		if err := s.AuthorizeDecision(ctx, tx, VerdictRetry); err != nil {
			return err
		}
		if id, ok := tx.DecisionByKey(req.IdempotencyKey); ok {
			replayID = id
		}
		return nil
	})
	if err != nil || replayID == "" {
		return nil, false, err
	}
	d, err := s.Registry.GetDecision(ctx, jobID, replayID)
	if err != nil {
		return nil, true, err
	}
	p, err := s.proposalOf(ctx, job, d.ProposalID)
	if err != nil {
		return nil, true, err
	}
	// The run may have moved on since, so the stored proposal's own
	// parameters, not the run's latest execution, are the reference. A
	// stored retry that does not record its queue marker cannot be shown to
	// be the execution the request names, so it matches no request; an
	// absent marker is not read as an empty one.
	same := false
	if p != nil && d.Verdict == VerdictRetry && p.Action.Name == ActionRetryRun {
		var params struct {
			RunID     string  `json:"run_id"`
			AttemptID string  `json:"attempt_id"`
			QueuedAt  *string `json:"queued_at"`
		}
		if err := json.Unmarshal(p.Action.Params, &params); err != nil {
			return nil, true, fmt.Errorf("decision: retry proposal %s params: %w", p.ProposalID, err)
		}
		same = params.RunID == req.RunID && params.AttemptID == req.AttemptID &&
			params.QueuedAt != nil && *params.QueuedAt == req.QueuedAt && p.JobVersion == req.ExpectedJobVersion
	}
	if !same {
		return nil, true, &registry.Error{Code: CodeIdempotencyMismatch,
			Message: "idempotency key was used for a different retry request", Current: d}
	}
	d.NativeResume = registry.CurrentNativeResume(job, d)
	return &Result{Job: job, Proposal: p, Decision: d, AlreadyRecorded: true}, true, nil
}

// proposalOf returns a proposal from the job aggregate or, once finished,
// from its archived history.
func (s *Service) proposalOf(ctx context.Context, job *registry.Job, proposalID string) (*registry.Proposal, error) {
	if p := job.Proposals[proposalID]; p != nil {
		return p, nil
	}
	archived, err := s.Registry.ListArchivedProposals(ctx, job.JobID, 0)
	if err != nil {
		return nil, err
	}
	for _, p := range archived {
		if p.ProposalID == proposalID {
			return p, nil
		}
	}
	return nil, nil
}
