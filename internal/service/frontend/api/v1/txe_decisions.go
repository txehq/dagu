// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"time"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/cmn/stringutil"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/decision"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// DecideTxeProposal records a human decision on one proposal. The decision is
// bound to the proposal revision and binding digest the person reviewed and
// is stored before the proposal's native human task is completed.
func (a *API) DecideTxeProposal(ctx context.Context, req api.DecideTxeProposalRequestObject) (api.DecideTxeProposalResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	store, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	actor, err := txeDecisionActor(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	// A job the caller cannot see is not found, not forbidden, so a decision
	// attempt does not reveal that it exists.
	if _, err := a.txeVisibleJob(ctx, store, req.JobId); err != nil {
		return nil, err
	}
	svc := a.txeDecisionService(store)
	res, err := svc.Decide(ctx, req.JobId, req.ProposalId, decision.Request{
		ExpectedProposalRevision: body.ExpectedProposalRevision,
		BindingDigest:            body.BindingDigest,
		Verdict:                  registry.Verdict(body.Verdict),
		Instructions:             valueOf(body.Instructions),
		SnoozeUntil:              body.SnoozeUntil,
		IdempotencyKey:           body.IdempotencyKey,
	}, actor)
	if err != nil {
		if errors.Is(err, decision.ErrInvalid) {
			return nil, &Error{HTTPStatus: http.StatusBadRequest, Code: api.ErrorCodeBadRequest, Message: err.Error()}
		}
		return nil, txeError(err)
	}
	if res.FollowUpPending() {
		// The decision is stored; say so, and that replaying this same
		// request completes what is still outstanding.
		cause := res.NativeErr
		logger.Warn(ctx, "TXE decision stored; follow-up pending", tag.Error(cause), tag.DAG(req.JobId))
		return nil, &Error{
			HTTPStatus: http.StatusServiceUnavailable,
			Code:       api.ErrorCodeInternalError,
			Message:    "decision recorded, but its follow-up did not complete; repeat the same request to retry it: " + cause.Error(),
			Details: map[string]any{
				"code":          "follow_up_pending",
				"decision_id":   res.Decision.DecisionID,
				"native_resume": res.Decision.NativeResume,
			},
		}
	}

	out := api.DecideTxeProposal200JSONResponse{Replayed: res.AlreadyRecorded}
	if out.Decision, err = txeConvert[api.TxeDecision](res.Decision); err != nil {
		return nil, err
	}
	job, err := txeConvert[api.TxeJob](res.Job)
	if err != nil {
		return nil, err
	}
	out.Job = &job
	if res.Proposal != nil {
		p, err := txeConvert[api.TxeProposal](res.Proposal)
		if err != nil {
			return nil, err
		}
		out.Proposal = &p
	}
	return out, nil
}

// RequestTxeRunRetry records a person's request to retry one exact run of a
// job. The request becomes a decided dagu.retry_run proposal; the reviewer
// performs the retry under an execution claim through the action journal, so
// this records the decision and runs nothing.
func (a *API) RequestTxeRunRetry(ctx context.Context, req api.RequestTxeRunRetryRequestObject) (api.RequestTxeRunRetryResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	store, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	actor, err := txeDecisionActor(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	if _, err := a.txeVisibleJob(ctx, store, req.JobId); err != nil {
		return nil, err
	}
	// The person decides on the execution they reviewed, so the request must
	// name it completely: a request without it would bind whatever execution
	// is latest, one they may never have seen. An empty queued_at is a value
	// (never queued), distinct from an absent one.
	if body.AttemptId == nil || *body.AttemptId == "" || body.QueuedAt == nil {
		return nil, &Error{HTTPStatus: http.StatusBadRequest, Code: api.ErrorCodeBadRequest,
			Message: "attempt_id and queued_at of the execution you reviewed are required",
			Details: map[string]any{"code": "missing_execution"}}
	}
	retry := decision.RetryRequest{
		RunID:              req.RunId,
		AttemptID:          *body.AttemptId,
		QueuedAt:           *body.QueuedAt,
		ExpectedJobVersion: body.ExpectedJobVersion,
		IdempotencyKey:     body.IdempotencyKey,
	}
	if err := retry.ValidateShape(); err != nil {
		return nil, &Error{HTTPStatus: http.StatusBadRequest, Code: api.ErrorCodeBadRequest, Message: err.Error()}
	}
	svc := a.txeDecisionService(store)
	// An identical replay returns the stored decision before the run's
	// current state is checked: after the retry ran, the run is no longer
	// retryable, but a client recovering a lost response must still get it.
	if res, found, err := svc.ReplayRetry(ctx, req.JobId, retry, actor); found || err != nil {
		if err != nil {
			return nil, txeError(err)
		}
		return txeRetryResponse(res)
	}
	run, err := a.txeRunFacts(ctx, req.JobId, req.RunId)
	if err != nil {
		return nil, err
	}
	// If the run has moved on to another execution since the person reviewed
	// it, retrying the latest would retry one they never reviewed, so refuse
	// and let them look again. The registry checks the binding again inside
	// the commit, against the run as it is then.
	if retry.AttemptID != run.attemptID || retry.QueuedAt != run.queuedAt {
		return nil, &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
			Message: fmt.Sprintf("run %s is now at execution %s, not the execution %s you reviewed; review it again",
				req.RunId, registry.ExecutionRef(run.attemptID, run.queuedAt), registry.ExecutionRef(retry.AttemptID, retry.QueuedAt)),
			Details: map[string]any{"code": string(decision.CodeRunStale)}}
	}
	// A client that saw a different snapshot of the run is acting on stale
	// information; refuse rather than retry something else.
	if body.RunSpecSha256 != nil && *body.RunSpecSha256 != run.specSHA256 {
		return nil, &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
			Message: "the run's DAG snapshot differs from the one in the request",
			Details: map[string]any{"code": string(decision.CodeRunStale)}}
	}
	retry.RunSpecSHA256, retry.RunStartedAt = run.specSHA256, run.startedAt
	res, err := svc.RequestRetry(ctx, req.JobId, retry, actor)
	if err != nil {
		if errors.Is(err, decision.ErrInvalid) {
			return nil, &Error{HTTPStatus: http.StatusBadRequest, Code: api.ErrorCodeBadRequest, Message: err.Error()}
		}
		return nil, txeError(err)
	}
	return txeRetryResponse(res)
}

func txeRetryResponse(res *decision.Result) (api.RequestTxeRunRetryResponseObject, error) {
	out := api.RequestTxeRunRetry200JSONResponse{Replayed: res.AlreadyRecorded}
	var err error
	if out.Decision, err = txeConvert[api.TxeDecision](res.Decision); err != nil {
		return nil, err
	}
	job, err := txeConvert[api.TxeJob](res.Job)
	if err != nil {
		return nil, err
	}
	out.Job = &job
	if res.Proposal != nil {
		p, err := txeConvert[api.TxeProposal](res.Proposal)
		if err != nil {
			return nil, err
		}
		out.Proposal = &p
	}
	return out, nil
}

type txeRun struct {
	// attemptID and queuedAt name the run's latest execution, the one a
	// retry would follow.
	attemptID  string
	queuedAt   string
	specSHA256 string
	startedAt  time.Time
}

// txeRunFacts reads the run of the job's DAG that a retry names: it must
// exist, be finished and not succeeded, and the caller must be able to see
// it. Its DAG snapshot digest is computed the way run admission computes it.
func (a *API) txeRunFacts(ctx context.Context, jobID, runID string) (txeRun, error) {
	status, err := a.authorizeHumanTaskMutation(ctx, jobID, runID)
	if err != nil {
		return txeRun{}, err
	}
	if status.Name != jobID {
		return txeRun{}, &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound,
			Message: fmt.Sprintf("run %s is not a run of job %s", runID, jobID)}
	}
	if status.Status.IsActive() || status.Status.IsSuccess() {
		return txeRun{}, &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
			Message: fmt.Sprintf("run %s is %s; only a finished, unsuccessful run can be retried", runID, status.Status),
			Details: map[string]any{"code": "run_not_retryable"}}
	}
	attempt, err := a.dagRunRepository.FindAttempt(ctx, ir.NewDAGRunRef(jobID, runID))
	if err != nil {
		return txeRun{}, err
	}
	dag, err := attempt.ReadDAG(ctx)
	if err != nil {
		return txeRun{}, fmt.Errorf("read DAG snapshot of run %s: %w", runID, err)
	}
	if len(dag.YamlData) == 0 {
		return txeRun{}, &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
			Message: fmt.Sprintf("run %s has no DAG snapshot to compare with the job", runID),
			Details: map[string]any{"code": string(decision.CodeRunStale)}}
	}
	started, err := stringutil.ParseTime(status.StartedAt)
	if err != nil {
		return txeRun{}, fmt.Errorf("parse start time of run %s: %w", runID, err)
	}
	if status.AttemptID == "" {
		return txeRun{}, &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
			Message: fmt.Sprintf("run %s has no attempt identity to bind a retry to", runID),
			Details: map[string]any{"code": string(decision.CodeRunStale)}}
	}
	return txeRun{attemptID: status.AttemptID, queuedAt: status.QueuedAt, specSHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(dag.YamlData)), startedAt: started}, nil
}

// ListTxeProposalDecisions lists every decision recorded for a proposal,
// newest first, whatever the proposal's current state.
func (a *API) ListTxeProposalDecisions(ctx context.Context, req api.ListTxeProposalDecisionsRequestObject) (api.ListTxeProposalDecisionsResponseObject, error) {
	store, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	// Read on the snapshot that was authorized, like every registry history
	// read: a job the caller cannot see is not found, no decision committed
	// after the job left the caller's workspace is returned, and the
	// projection uses a job that covers every listed decision, so an
	// outstanding completion is never reported as done.
	var all []*registry.Decision
	job, err := a.txeReadHistory(ctx, store, req.JobId, func() (err error) {
		all, err = store.ListDecisions(ctx, req.JobId, 0)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := api.ListTxeProposalDecisions200JSONResponse{Decisions: []api.TxeDecision{}}
	for _, d := range all {
		if d.ProposalID != req.ProposalId {
			continue
		}
		current := *d
		current.NativeResume = registry.CurrentNativeResume(job, d)
		converted, err := txeConvert[api.TxeDecision](&current)
		if err != nil {
			return nil, err
		}
		out.Decisions = append(out.Decisions, converted)
	}
	return out, nil
}

var errTxeDecisionNotHuman = &Error{
	HTTPStatus: http.StatusForbidden,
	Code:       api.ErrorCodeForbidden,
	Message:    "a human decision must be made by a signed-in person, not an API key, agent or reviewer",
}

// txeDecisionActor attributes a decision to the authenticated person. A
// request cannot name another person or decide as an agent: an API key is
// refused whatever actor it claims, and a client-supplied actor contributes
// only its session, machine and client details.
func txeDecisionActor(ctx context.Context, in *api.TxeActor) (registry.Actor, error) {
	if _, apiKey := auth.APIKeyFromContext(ctx); apiKey {
		return registry.Actor{}, errTxeDecisionNotHuman
	}
	actor := registry.Actor{Kind: registry.ActorHuman, ID: "unauthenticated", Client: "dashboard"}
	if in != nil {
		claimed, err := txeConvert[registry.Actor](in)
		if err != nil {
			return registry.Actor{}, err
		}
		if claimed.Kind != "" && claimed.Kind != registry.ActorHuman && claimed.Kind != registry.ActorCLI {
			return registry.Actor{}, errTxeDecisionNotHuman
		}
		actor.Session, actor.MachineID = claimed.Session, claimed.MachineID
		if claimed.Client != "" {
			actor.Client = claimed.Client
		}
		if claimed.ID != "" {
			actor.ID = claimed.ID
		}
	}
	if user, ok := auth.UserFromContext(ctx); ok && user != nil {
		actor.ID = user.Username
	}
	return actor, nil
}

func (a *API) txeDecisionService(store *registry.Store) *decision.Service {
	return &decision.Service{
		Registry: store,
		Tasks:    a.humanTaskService(),
		// Deciding is executing in the job's workspace; pausing or retiring
		// the job changes it, so those verdicts need write access there.
		AuthorizeDecision: func(ctx context.Context, tx *registry.JobTx, verdict registry.Verdict) error {
			if err := a.isAllowed(config.PermissionRunDAGs); err != nil {
				return err
			}
			switch verdict {
			case registry.VerdictPause, registry.VerdictRetire:
				return a.txeRequireJobWrite(ctx, tx)
			case registry.VerdictApprove, registry.VerdictReject, registry.VerdictRedirect,
				registry.VerdictRetry, registry.VerdictSnooze:
			}
			v, err := tx.CurrentVersion()
			if err != nil {
				return err
			}
			return a.txeCheckWorkspaces(ctx, tx.Job.JobID, v.DAG.Spec, true, a.requireExecuteForWorkspace)
		},
		// The same checks as completing the task through the native
		// human-task endpoint.
		AuthorizeTask: func(ctx context.Context, dagName, dagRunID string) error {
			status, err := a.authorizeHumanTaskMutation(ctx, dagName, dagRunID)
			if err != nil {
				return err
			}
			return a.requireDAGRunStatusExecute(ctx, status)
		},
	}
}
