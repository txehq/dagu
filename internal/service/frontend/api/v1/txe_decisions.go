// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
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

// ListTxeProposalDecisions lists every decision recorded for a proposal,
// newest first, whatever the proposal's current state.
func (a *API) ListTxeProposalDecisions(ctx context.Context, req api.ListTxeProposalDecisionsRequestObject) (api.ListTxeProposalDecisionsResponseObject, error) {
	store, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	job, err := store.GetJob(ctx, req.JobId)
	if err != nil {
		return nil, txeError(err)
	}
	all, err := store.ListDecisions(ctx, req.JobId, 0)
	if err != nil {
		return nil, txeError(err)
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
