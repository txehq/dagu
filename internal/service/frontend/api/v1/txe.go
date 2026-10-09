// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// WithTxeRegistry enables the /txe endpoints backed by the TXE job registry.
func WithTxeRegistry(store *registry.Store) APIOption {
	return func(a *API) {
		a.txeRegistry = store
	}
}

var errTxeRegistryUnavailable = &Error{
	HTTPStatus: http.StatusServiceUnavailable,
	Code:       api.ErrorCodeInternalError,
	Message:    "TXE registry is not configured",
}

func (a *API) txeStore() (*registry.Store, error) {
	if a.txeRegistry == nil {
		return nil, errTxeRegistryUnavailable
	}
	return a.txeRegistry, nil
}

// txeError maps a registry refusal to an HTTP error whose details carry the
// registry code and the current record to re-read.
func txeError(err error) error {
	var re *registry.Error
	if !errors.As(err, &re) {
		return err
	}
	out := &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict, Message: re.Message,
		Details: map[string]any{"code": string(re.Code)}}
	switch re.Code {
	case registry.CodeNotFound:
		out.HTTPStatus, out.Code = http.StatusNotFound, api.ErrorCodeNotFound
	case registry.CodeInvalid:
		out.HTTPStatus, out.Code = http.StatusBadRequest, api.ErrorCodeBadRequest
	case registry.CodeVersionConflict, registry.CodeDuplicate, registry.CodeNotReady, registry.CodeLifecycle,
		registry.CodeTransition, registry.CodeClaimHeld, registry.CodeClaimStale, registry.CodeNotPermitted,
		registry.CodeStaleBinding, registry.CodeProposalState, registry.CodeActionExists, registry.CodeActionState,
		registry.CodeGrantInvalid, registry.CodeDAGMismatch:
		// Refused against current state: 409 with the record to re-read.
	}
	if re.Current != nil {
		out.Details["current"] = re.Current
	}
	return out
}

// txeConvert copies v into T through JSON. Registry records and the /txe API
// schemas share one JSON shape.
func txeConvert[T any](v any) (T, error) {
	var out T
	b, err := json.Marshal(v)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("txe: convert %T: %w", v, err)
	}
	return out, nil
}

var errTxeAPIKeyHuman = &Error{
	HTTPStatus: http.StatusForbidden,
	Code:       api.ErrorCodeForbidden,
	Message:    "an API key cannot act as a human",
}

// txeActor returns the request's actor. On an authenticated request the
// actor ID is the authenticated principal, and only a user who signed in
// (not an API key) may act as a human; kind, session, machine and client
// stay as the caller describes them. Without a body actor the principal is a
// human, or an agent for an API key. An unauthenticated server records the
// actor as sent, or the system.
func txeActor(ctx context.Context, in *api.TxeActor) (registry.Actor, error) {
	user, authed := auth.UserFromContext(ctx)
	_, apiKey := auth.APIKeyFromContext(ctx)
	if in == nil {
		switch {
		case authed && apiKey:
			return registry.Actor{Kind: registry.ActorAgent, ID: user.Username}, nil
		case authed:
			return registry.Actor{Kind: registry.ActorHuman, ID: user.Username}, nil
		}
		return registry.Actor{Kind: registry.ActorSystem, ID: "api"}, nil
	}
	actor, err := txeConvert[registry.Actor](in)
	if err != nil || !authed {
		return actor, err
	}
	if apiKey && actor.Kind == registry.ActorHuman {
		return registry.Actor{}, errTxeAPIKeyHuman
	}
	actor.ID = user.Username
	return actor, nil
}

// txeWrite prepares a write: it checks the caller may write and resolves the
// registry and actor.
func (a *API) txeWrite(ctx context.Context, in *api.TxeActor) (*registry.Store, registry.Actor, error) {
	if err := a.requireDeveloperOrAbove(ctx); err != nil {
		return nil, registry.Actor{}, err
	}
	s, err := a.txeStore()
	if err != nil {
		return nil, registry.Actor{}, err
	}
	actor, err := txeActor(ctx, in)
	return s, actor, err
}

// txeRequireSpecWrite applies the native DAG write authorization to a job's
// DAG: the caller must be able to write DAGs in the workspace the new spec
// names and, when the DAG already exists, in the workspace it is in now. A
// spec that does not parse is left to the registry to refuse.
func (a *API) txeRequireSpecWrite(ctx context.Context, jobID, spec string) error {
	if err := a.requireDAGWrite(ctx); err != nil {
		return err
	}
	return a.txeCheckWorkspaces(ctx, jobID, spec, false, a.requireDAGWriteForWorkspace)
}

// txeRequireJobWrite checks, inside the job transaction, that the caller may
// change the job as it is in that transaction: it needs write access to the
// workspace of the job's current version and of its saved DAG. It runs on
// every compare-and-swap attempt, so a concurrent move to another workspace
// is seen. It does not depend on DAG writes being enabled, so claims and
// settlements keep working under a read-only Git sync.
func (a *API) txeRequireJobWrite(ctx context.Context, tx *registry.JobTx) error {
	v, err := tx.CurrentVersion()
	if err != nil {
		return err
	}
	return a.txeCheckWorkspaces(ctx, tx.Job.JobID, v.DAG.Spec, true, a.txeRequireWorkspaceWrite)
}

// txeCheckVersion runs check on the workspaces of one committed version of
// a job and of its saved DAG. A version that does not exist yet is refused
// as a version conflict: it was not authorized, even if it is committed
// before the change is.
func (a *API) txeCheckVersion(ctx context.Context, s *registry.Store, job *registry.Job, version int, check func(context.Context, string) error) error {
	if version < 1 || version > job.Version {
		return txeError(&registry.Error{Code: registry.CodeVersionConflict, Message: fmt.Sprintf("job is at version %d, not %d", job.Version, version), Current: job})
	}
	v, err := s.GetVersion(ctx, job.JobID, version)
	if err != nil {
		return txeError(err)
	}
	return a.txeCheckWorkspaces(ctx, job.JobID, v.DAG.Spec, true, check)
}

func (a *API) txeRequireWorkspaceWrite(ctx context.Context, workspaceName string) error {
	role, ok, err := a.effectiveRoleForWorkspace(ctx, workspaceName)
	if err != nil {
		return err
	}
	if !ok || !role.CanWrite() {
		return errInsufficientPermissions
	}
	return nil
}

// txeCheckWorkspaces runs check on the workspace spec names and on the
// workspace of the job's saved DAG, if one exists. With strict, a spec that
// does not load is an error rather than left to the registry.
func (a *API) txeCheckWorkspaces(ctx context.Context, jobID, spec string, strict bool, check func(context.Context, string) error) error {
	if a.dagRepository == nil {
		return nil
	}
	dag, err := a.dagRepository.LoadSpec(ctx, []byte(spec), jobID, persis.DAGLoadOptions{AllowBuildErrors: true})
	switch {
	case err == nil:
		if err := check(ctx, dagWorkspaceName(dag)); err != nil {
			return err
		}
	case strict:
		return fmt.Errorf("txe: load DAG spec of %s: %w", jobID, err)
	}
	if registry.ValidateID(registry.PrefixJob, jobID) != nil {
		return nil
	}
	cur, err := a.dagRepository.GetDetails(ctx, jobID, persis.DAGLoadOptions{AllowBuildErrors: true})
	if err != nil {
		if errors.Is(err, persis.ErrDAGNotFound) {
			return nil
		}
		return err
	}
	return check(ctx, dagWorkspaceName(cur))
}

// txeAlreadyReady reports whether job is ready with pkg, which readiness
// returns as is.
func txeAlreadyReady(job *registry.Job, pkg registry.PackageEvidence) bool {
	r := job.Registration
	return r.State == registry.RegistrationReady && r.Package != nil && r.Package.Digest == pkg.Digest
}

func txeBody[T any](body *T) (*T, error) {
	if body == nil {
		return nil, ErrInvalidRequestBody
	}
	return body, nil
}

func txeLimit(limit *api.TxeLimit) int {
	if limit == nil {
		return 0
	}
	return *limit
}

// txeTx runs fn in a job transaction and returns the committed job.
func (a *API) txeTx(ctx context.Context, jobID string, in *api.TxeActor, fn func(tx *registry.JobTx) error) (api.TxeJob, error) {
	s, actor, err := a.txeWrite(ctx, in)
	if err != nil {
		return api.TxeJob{}, err
	}
	job, err := s.WithJobTx(ctx, jobID, actor, func(tx *registry.JobTx) error {
		if err := a.txeRequireJobWrite(ctx, tx); err != nil {
			return err
		}
		return fn(tx)
	})
	if err != nil {
		return api.TxeJob{}, txeError(err)
	}
	return txeConvert[api.TxeJob](job)
}

func (a *API) GetTxeInstallation(ctx context.Context, _ api.GetTxeInstallationRequestObject) (api.GetTxeInstallationResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	inst, err := s.GetInstallation(ctx)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeInstallation](inst)
	if out.Owners == nil {
		out.Owners = []api.TxeOwner{}
	}
	return api.GetTxeInstallation200JSONResponse(out), err
}

func (a *API) CreateTxeOwner(ctx context.Context, req api.CreateTxeOwnerRequestObject) (api.CreateTxeOwnerResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	s, actor, err := a.txeWrite(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	o, err := s.CreateOwner(ctx, registry.Owner{OwnerID: body.OwnerId, DisplayName: body.DisplayName, Provenance: valueOf(body.Provenance)}, actor)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeOwner](o)
	return api.CreateTxeOwner201JSONResponse(out), err
}

func (a *API) GetTxeOwner(ctx context.Context, req api.GetTxeOwnerRequestObject) (api.GetTxeOwnerResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	o, err := s.GetOwner(ctx, req.OwnerId)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeOwner](o)
	return api.GetTxeOwner200JSONResponse(out), err
}

func (a *API) EnsureTxeProject(ctx context.Context, req api.EnsureTxeProjectRequestObject) (api.EnsureTxeProjectResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	s, actor, err := a.txeWrite(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	p, err := s.EnsureProject(ctx, body.OwnerId, body.Key, valueOf(body.Name), actor)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeProject](p)
	return api.EnsureTxeProject200JSONResponse(out), err
}

func (a *API) GetTxeProject(ctx context.Context, req api.GetTxeProjectRequestObject) (api.GetTxeProjectResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	p, err := s.GetProject(ctx, req.ProjectId)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeProject](p)
	return api.GetTxeProject200JSONResponse(out), err
}

func (a *API) CreateTxeMachine(ctx context.Context, req api.CreateTxeMachineRequestObject) (api.CreateTxeMachineResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	s, actor, err := a.txeWrite(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	m, err := s.CreateMachine(ctx, registry.Machine{MachineID: body.MachineId, OwnerID: body.OwnerId, DisplayName: body.DisplayName}, actor)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeMachine](m)
	return api.CreateTxeMachine201JSONResponse(out), err
}

func (a *API) GetTxeMachine(ctx context.Context, req api.GetTxeMachineRequestObject) (api.GetTxeMachineResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	m, err := s.GetMachine(ctx, req.MachineId)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeMachine](m)
	return api.GetTxeMachine200JSONResponse(out), err
}

func (a *API) ListTxeJobs(ctx context.Context, req api.ListTxeJobsRequestObject) (api.ListTxeJobsResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	p := req.Params
	f := registry.JobFilter{OwnerID: valueOf(p.Owner), ProjectID: valueOf(p.Project), MachineID: valueOf(p.Machine), JobKey: valueOf(p.JobKey), ReviewDueBefore: p.ReviewDueBefore}
	if p.Lifecycle != nil {
		f.Lifecycle = registry.Lifecycle(*p.Lifecycle)
	}
	jobs, err := s.ListJobs(ctx, f)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[[]api.TxeJob](jobs)
	if out == nil {
		out = []api.TxeJob{}
	}
	return api.ListTxeJobs200JSONResponse{Jobs: out}, err
}

func (a *API) RegisterTxeJob(ctx context.Context, req api.RegisterTxeJobRequestObject) (api.RegisterTxeJobResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	s, actor, err := a.txeWrite(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	v, err := txeConvert[registry.JobVersion](body.Version)
	if err != nil {
		return nil, ErrInvalidRequestBody
	}
	if err := a.txeRequireSpecWrite(ctx, body.JobId, v.DAG.Spec); err != nil {
		return nil, err
	}
	job, err := s.Register(ctx, registry.RegisterInput{
		JobID: body.JobId, RequestID: body.RequestId, OwnerID: body.OwnerId, ProjectID: body.ProjectId,
		MachineID: body.MachineId, JobKey: body.JobKey, Version: v,
	}, actor)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeJob](job)
	return api.RegisterTxeJob201JSONResponse(out), err
}

func (a *API) GetTxeJob(ctx context.Context, req api.GetTxeJobRequestObject) (api.GetTxeJobResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	job, err := s.GetJob(ctx, req.JobId)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeJob](job)
	return api.GetTxeJob200JSONResponse(out), err
}

func (a *API) MarkTxeJobReady(ctx context.Context, req api.MarkTxeJobReadyRequestObject) (api.MarkTxeJobReadyResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	if err := a.requireDAGWrite(ctx); err != nil {
		return nil, err
	}
	s, actor, err := a.txeWrite(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	pkg, err := txeConvert[registry.PackageEvidence](body.Package)
	if err != nil {
		return nil, ErrInvalidRequestBody
	}
	// Readiness may rewrite the job's DAG, so it needs DAG write access to
	// the job's workspace. The check is bound to the revision it read: the
	// registry makes only that state's version ready.
	var receipt *registry.Receipt
	for attempt := 0; ; attempt++ {
		job, err := s.GetJob(ctx, req.JobId)
		if err != nil {
			return nil, txeError(err)
		}
		if err := a.txeCheckVersion(ctx, s, job, job.Version, a.requireDAGWriteForWorkspace); err != nil {
			return nil, err
		}
		expected := valueOf(body.ExpectedRevision)
		if expected != 0 && expected != job.Revision && !txeAlreadyReady(job, pkg) {
			return nil, txeError(&registry.Error{Code: registry.CodeVersionConflict, Message: fmt.Sprintf("job is at revision %d, not %d", job.Revision, expected), Current: job})
		}
		receipt, err = s.MarkReady(ctx, req.JobId, job.Revision, pkg, actor)
		if err == nil {
			break
		}
		if valueOf(body.ExpectedRevision) != 0 || registry.ErrorCode(err) != registry.CodeVersionConflict || attempt == 4 {
			return nil, txeError(err)
		}
	}
	out, err := txeConvert[api.TxeReceipt](receipt)
	return api.MarkTxeJobReady200JSONResponse(out), err
}

func (a *API) UpdateTxeJobVersion(ctx context.Context, req api.UpdateTxeJobVersionRequestObject) (api.UpdateTxeJobVersionResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	s, actor, err := a.txeWrite(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	v, err := txeConvert[registry.JobVersion](body.Version)
	if err != nil {
		return nil, ErrInvalidRequestBody
	}
	if err := a.txeRequireSpecWrite(ctx, req.JobId, v.DAG.Spec); err != nil {
		return nil, err
	}
	// The update is accepted only against expected_version, so that is the
	// committed version the caller must be able to write.
	cur, err := s.GetJob(ctx, req.JobId)
	if err != nil {
		return nil, txeError(err)
	}
	if err := a.txeCheckVersion(ctx, s, cur, body.ExpectedVersion, a.requireDAGWriteForWorkspace); err != nil {
		return nil, err
	}
	job, err := s.UpdateVersion(ctx, req.JobId, body.RequestId, body.ExpectedVersion, v, actor)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeJob](job)
	return api.UpdateTxeJobVersion200JSONResponse(out), err
}

func (a *API) GetTxeJobVersion(ctx context.Context, req api.GetTxeJobVersionRequestObject) (api.GetTxeJobVersionResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	v, err := s.GetVersion(ctx, req.JobId, req.Version)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeJobVersion](v)
	return api.GetTxeJobVersion200JSONResponse(out), err
}

func (a *API) TransitionTxeJob(ctx context.Context, req api.TransitionTxeJobRequestObject) (api.TransitionTxeJobResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	t := registry.Transition{Op: registry.LifecycleOp(body.Op), Detail: valueOf(body.Detail), Evidence: derefSlice(body.Evidence)}
	if body.Reason != nil {
		t.Reason = registry.RetirementReason(*body.Reason)
	}
	if body.ActiveRunPolicy != nil {
		t.ActiveRunPolicy = registry.ActiveRunPolicy(*body.ActiveRunPolicy)
	}
	job, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error { return tx.Transition(t) })
	return api.TransitionTxeJob200JSONResponse(job), err
}

func (a *API) ListTxeJobEvents(ctx context.Context, req api.ListTxeJobEventsRequestObject) (api.ListTxeJobEventsResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	events, err := s.ListEvents(ctx, req.JobId, txeLimit(req.Params.Limit))
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[[]api.TxeEvent](events)
	if out == nil {
		out = []api.TxeEvent{}
	}
	return api.ListTxeJobEvents200JSONResponse{Events: out}, err
}

func (a *API) ObserveTxeJob(ctx context.Context, req api.ObserveTxeJobRequestObject) (api.ObserveTxeJobResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	o := registry.Observation{State: registry.AvailabilityState(body.State), Kind: valueOf(body.Kind), Detail: valueOf(body.Detail), Evidence: derefSlice(body.Evidence)}
	job, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error { return tx.Observe(o) })
	return api.ObserveTxeJob200JSONResponse(job), err
}

func (a *API) AcquireTxeClaim(ctx context.Context, req api.AcquireTxeClaimRequestObject) (api.AcquireTxeClaimResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	reviewer, err := txeConvert[registry.Reviewer](body.Reviewer)
	if err != nil {
		return nil, ErrInvalidRequestBody
	}
	var claim *registry.Claim
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error {
		var err error
		claim, err = tx.AcquireClaim(registry.ClaimKind(body.Kind), reviewer, time.Duration(body.TtlSec)*time.Second)
		return err
	}); err != nil {
		return nil, err
	}
	out, err := txeConvert[api.TxeClaim](claim)
	return api.AcquireTxeClaim200JSONResponse(out), err
}

func (a *API) ReleaseTxeClaim(ctx context.Context, req api.ReleaseTxeClaimRequestObject) (api.ReleaseTxeClaimResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	job, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error { return tx.ReleaseClaim(req.ClaimId, body.Fence) })
	return api.ReleaseTxeClaim200JSONResponse(job), err
}

func (a *API) AdvanceTxeCheckpoint(ctx context.Context, req api.AdvanceTxeCheckpointRequestObject) (api.AdvanceTxeCheckpointResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	cp, err := txeConvert[registry.Checkpoint](body.Checkpoint)
	if err != nil {
		return nil, ErrInvalidRequestBody
	}
	var next *registry.Checkpoint
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error {
		var err error
		next, err = tx.AdvanceCheckpoint(body.ClaimId, body.Fence, body.ExpectedVersion, cp)
		return err
	}); err != nil {
		return nil, err
	}
	out, err := txeConvert[api.TxeCheckpoint](next)
	return api.AdvanceTxeCheckpoint200JSONResponse(out), err
}

func (a *API) DeferTxeReview(ctx context.Context, req api.DeferTxeReviewRequestObject) (api.DeferTxeReviewResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	job, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error {
		return tx.DeferReview(body.ClaimId, body.Fence, body.NextReviewAt)
	})
	return api.DeferTxeReview200JSONResponse(job), err
}

func (a *API) ListTxeReviews(ctx context.Context, req api.ListTxeReviewsRequestObject) (api.ListTxeReviewsResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	reviews, err := s.ListReviews(ctx, req.JobId, txeLimit(req.Params.Limit))
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[[]api.TxeReview](reviews)
	if out == nil {
		out = []api.TxeReview{}
	}
	return api.ListTxeReviews200JSONResponse{Reviews: out}, err
}

func (a *API) RecordTxeReview(ctx context.Context, req api.RecordTxeReviewRequestObject) (api.RecordTxeReviewResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	review, err := txeConvert[registry.Review](body.Review)
	if err != nil {
		return nil, ErrInvalidRequestBody
	}
	job, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error {
		return tx.RecordReview(body.ClaimId, body.Fence, review)
	})
	return api.RecordTxeReview200JSONResponse(job), err
}

func (a *API) ListTxeProposals(ctx context.Context, req api.ListTxeProposalsRequestObject) (api.ListTxeProposalsResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	job, err := s.GetJob(ctx, req.JobId)
	if err != nil {
		return nil, txeError(err)
	}
	finished, err := s.ListArchivedProposals(ctx, req.JobId, txeLimit(req.Params.Limit))
	if err != nil {
		return nil, txeError(err)
	}
	open := make([]*registry.Proposal, 0, len(job.Proposals))
	for _, p := range job.Proposals {
		open = append(open, p)
	}
	openOut, err := txeConvert[[]api.TxeProposal](open)
	if err != nil {
		return nil, err
	}
	finishedOut, err := txeConvert[[]api.TxeProposal](finished)
	if finishedOut == nil {
		finishedOut = []api.TxeProposal{}
	}
	return api.ListTxeProposals200JSONResponse{Open: openOut, Finished: finishedOut}, err
}

func (a *API) CreateTxeProposal(ctx context.Context, req api.CreateTxeProposalRequestObject) (api.CreateTxeProposalResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	in, err := txeConvert[registry.Proposal](body.Proposal)
	if err != nil {
		return nil, ErrInvalidRequestBody
	}
	var p *registry.Proposal
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error {
		var err error
		p, err = tx.PutProposal(body.ClaimId, body.Fence, in)
		return err
	}); err != nil {
		return nil, err
	}
	out, err := txeConvert[api.TxeProposal](p)
	return api.CreateTxeProposal200JSONResponse(out), err
}

func (a *API) ListTxeJobDecisions(ctx context.Context, req api.ListTxeJobDecisionsRequestObject) (api.ListTxeJobDecisionsResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	decisions, err := s.ListDecisions(ctx, req.JobId, txeLimit(req.Params.Limit))
	if err != nil {
		return nil, txeError(err)
	}
	// A decision record keeps the native_resume it was written with; report
	// the current state. The job is read after the decisions, so a decision
	// listed without a pending entry has had its task completed.
	job, err := s.GetJob(ctx, req.JobId)
	if err != nil {
		return nil, txeError(err)
	}
	for i, d := range decisions {
		if d.NativeResume == "" {
			continue
		}
		cp := *d
		cp.NativeResume = "completed"
		if _, pending := job.NativeResumes[d.DecisionID]; pending {
			cp.NativeResume = "pending"
		}
		decisions[i] = &cp
	}
	if since := valueOf(req.Params.Since); since != "" {
		for i, d := range decisions {
			if d.DecisionID == since {
				decisions = decisions[:i]
				break
			}
		}
	}
	out, err := txeConvert[[]api.TxeDecision](decisions)
	if out == nil {
		out = []api.TxeDecision{}
	}
	return api.ListTxeJobDecisions200JSONResponse{Decisions: out}, err
}

func (a *API) AuthorizeTxeEffect(ctx context.Context, req api.AuthorizeTxeEffectRequestObject) (api.AuthorizeTxeEffectResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	effect := registry.EffectRequest{ActionID: body.ActionId, JobVersion: body.JobVersion, PackageDigest: body.PackageDigest}
	if ap := body.Approved; ap != nil {
		effect.Approved = &registry.ApprovedEffect{ProposalID: ap.ProposalId, DecisionID: ap.DecisionId, ClaimID: ap.ClaimId, Fence: ap.Fence}
	}
	if r := body.Routine; r != nil {
		spec, err := txeConvert[registry.ActionSpec](r.Spec)
		if err != nil {
			return nil, ErrInvalidRequestBody
		}
		effect.Routine = &registry.RoutineEffect{ReviewID: r.ReviewId, ClaimID: r.ClaimId, Fence: r.Fence, Spec: spec}
	}
	var g *registry.Grant
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error {
		var err error
		g, err = tx.Authorize(effect)
		return err
	}); err != nil {
		return nil, err
	}
	out, err := txeConvert[api.TxeGrant](g)
	return api.AuthorizeTxeEffect200JSONResponse(out), err
}

func (a *API) ListTxeActions(ctx context.Context, req api.ListTxeActionsRequestObject) (api.ListTxeActionsResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	job, err := s.GetJob(ctx, req.JobId)
	if err != nil {
		return nil, txeError(err)
	}
	archived, err := s.ListArchivedActions(ctx, req.JobId, txeLimit(req.Params.Limit))
	if err != nil {
		return nil, txeError(err)
	}
	inFlight := make([]*registry.Action, 0, len(job.Actions))
	for _, act := range job.Actions {
		inFlight = append(inFlight, act)
	}
	inOut, err := txeConvert[[]api.TxeAction](inFlight)
	if err != nil {
		return nil, err
	}
	archOut, err := txeConvert[[]api.TxeAction](archived)
	if archOut == nil {
		archOut = []api.TxeAction{}
	}
	return api.ListTxeActions200JSONResponse{InFlight: inOut, Archived: archOut}, err
}

func (a *API) SettleTxeAction(ctx context.Context, req api.SettleTxeActionRequestObject) (api.SettleTxeActionResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	settlement := registry.Settlement{ActionID: req.ActionId, GrantID: body.GrantId, ClaimID: body.ClaimId, Fence: body.Fence,
		State: registry.ActionState(body.State), Receipt: valueOf(body.Receipt), Outcome: body.Outcome}
	var action *registry.Action
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error {
		var err error
		action, err = tx.SettleAction(settlement)
		return err
	}); err != nil {
		return nil, err
	}
	out, err := txeConvert[api.TxeAction](action)
	return api.SettleTxeAction200JSONResponse(out), err
}

func derefSlice[T any](p *[]T) []T {
	if p == nil {
		return nil
	}
	return *p
}
