// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"io"
	"net/http"
	"os"
	"slices"
	"time"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
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
		registry.CodeGrantInvalid, registry.CodeDAGMismatch, registry.CodeIncomplete, registry.CodeEventComplete, registry.CodeIntentUnresolved, registry.CodeReviewConflict, registry.CodeArtifactConflict:
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

// txeJobVisible refuses, as not found, a job the caller cannot see: the
// workspaces of its current version and of its saved DAG must be visible.
func (a *API) txeJobVisible(ctx context.Context, s *registry.Store, job *registry.Job) error {
	if a.authService == nil {
		return nil
	}
	v, err := s.GetVersion(ctx, job.JobID, job.Version)
	if err != nil {
		return txeError(err)
	}
	return a.txeCheckWorkspaces(ctx, job.JobID, v.DAG.Spec, true, a.requireWorkspaceVisible)
}

// txeVisibleJob returns the committed job if the caller can see it.
func (a *API) txeVisibleJob(ctx context.Context, s *registry.Store, jobID string) (*registry.Job, error) {
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		return nil, txeError(err)
	}
	if err := a.txeJobVisible(ctx, s, job); err != nil {
		return nil, err
	}
	return job, nil
}

// txeReadHistory authorizes a job and runs read, which reads its history,
// on the snapshot it authorized: if the job changed meanwhile, both are
// repeated, so no record committed after the authorization is returned.
func (a *API) txeReadHistory(ctx context.Context, s *registry.Store, jobID string, read func() error) (*registry.Job, error) {
	for range 5 {
		job, err := a.txeVisibleJob(ctx, s, jobID)
		if err != nil {
			return nil, err
		}
		if err := read(); err != nil {
			return nil, txeError(err)
		}
		after, err := s.GetJob(ctx, jobID)
		if err != nil {
			return nil, txeError(err)
		}
		if after.Revision == job.Revision {
			return job, nil
		}
	}
	return nil, &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict, Message: "job " + jobID + " kept changing while it was read; retry",
		Details: map[string]any{"code": string(registry.CodeVersionConflict)}}
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
	all, err := s.ListJobs(ctx, f)
	if err != nil {
		return nil, txeError(err)
	}
	jobs := make([]*registry.Job, 0, len(all))
	for _, job := range all {
		if a.txeJobVisible(ctx, s, job) == nil {
			jobs = append(jobs, job)
		}
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
	job, err := a.txeVisibleJob(ctx, s, req.JobId)
	if err != nil {
		return nil, err
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
		// An explicit revision must be the one authorized, except for a
		// replay of a readiness that already succeeded.
		explicit := valueOf(body.ExpectedRevision)
		pinned := explicit != 0 && !txeAlreadyReady(job, pkg)
		if pinned && explicit != job.Revision {
			return nil, txeError(&registry.Error{Code: registry.CodeVersionConflict, Message: fmt.Sprintf("job is at revision %d, not %d", job.Revision, explicit), Current: job})
		}
		receipt, err = s.MarkReady(ctx, req.JobId, job.Revision, pkg, actor)
		if err == nil {
			break
		}
		if pinned || registry.ErrorCode(err) != registry.CodeVersionConflict || attempt == 4 {
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
	if _, err := a.txeVisibleJob(ctx, s, req.JobId); err != nil {
		return nil, err
	}
	v, err := s.GetVersion(ctx, req.JobId, req.Version)
	if err != nil {
		return nil, txeError(err)
	}
	// An earlier version may name a workspace the job has since left.
	if a.authService != nil {
		if err := a.txeCheckWorkspaces(ctx, req.JobId, v.DAG.Spec, true, a.requireWorkspaceVisible); err != nil {
			return nil, err
		}
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
	s, actor, err := a.txeWrite(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	t.Authorize = func(tx *registry.JobTx) error { return a.txeRequireJobWrite(ctx, tx) }
	committed, err := s.ChangeLifecycle(ctx, req.JobId, t, actor)
	if err != nil {
		return nil, txeError(err)
	}
	job, err := txeConvert[api.TxeJob](committed)
	return api.TransitionTxeJob200JSONResponse(job), err
}

func (a *API) ListTxeJobEvents(ctx context.Context, req api.ListTxeJobEventsRequestObject) (api.ListTxeJobEventsResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	var events []*registry.Event
	if _, err := a.txeReadHistory(ctx, s, req.JobId, func() (err error) {
		events, err = s.ListEvents(ctx, req.JobId, txeLimit(req.Params.Limit))
		return err
	}); err != nil {
		return nil, err
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
	if body.Scope != nil {
		o.Scope = string(*body.Scope)
	}
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
	var reviews []*registry.Review
	if _, err := a.txeReadHistory(ctx, s, req.JobId, func() (err error) {
		reviews, err = s.ListReviews(ctx, req.JobId, txeLimit(req.Params.Limit))
		return err
	}); err != nil {
		return nil, err
	}
	out, err := txeConvert[[]api.TxeReview](reviews)
	if out == nil {
		out = []api.TxeReview{}
	}
	return api.ListTxeReviews200JSONResponse{Reviews: out}, err
}

func (a *API) GetTxeReview(ctx context.Context, req api.GetTxeReviewRequestObject) (api.GetTxeReviewResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	var review *registry.Review
	if _, err := a.txeReadHistory(ctx, s, req.JobId, func() (err error) {
		review, err = s.GetReview(ctx, req.JobId, req.ReviewId)
		return err
	}); err != nil {
		return nil, err
	}
	out, err := txeConvert[api.TxeReview](review)
	return api.GetTxeReview200JSONResponse(out), err
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
	var finished []*registry.Proposal
	job, err := a.txeReadHistory(ctx, s, req.JobId, func() (err error) {
		finished, err = s.ListArchivedProposals(ctx, req.JobId, txeLimit(req.Params.Limit))
		return err
	})
	if err != nil {
		return nil, err
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
	asc := req.Params.Order != nil && *req.Params.Order == api.ListTxeJobDecisionsParamsOrderAsc
	readLimit := txeLimit(req.Params.Limit)
	if asc {
		// Ascending pages start after the cursor, so the newest-first chain
		// is read in full and the limit applied forward from it.
		readLimit = 0
	}
	var decisions []*registry.Decision
	job, err := a.txeReadHistory(ctx, s, req.JobId, func() (err error) {
		decisions, err = s.ListDecisions(ctx, req.JobId, readLimit)
		return err
	})
	if err != nil {
		return nil, err
	}
	// A decision record keeps the native_resume it was written with; report
	// the state of the job the decisions were read from.
	for i, d := range decisions {
		cp := *d
		cp.NativeResume = registry.CurrentNativeResume(job, d)
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
	if asc {
		slices.Reverse(decisions)
		if limit := txeLimit(req.Params.Limit); limit > 0 && len(decisions) > limit {
			decisions = decisions[:limit]
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
	var archived []*registry.Action
	job, err := a.txeReadHistory(ctx, s, req.JobId, func() (err error) {
		archived, err = s.ListArchivedActions(ctx, req.JobId, txeLimit(req.Params.Limit))
		return err
	})
	if err != nil {
		return nil, err
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

// txeJobIdentity returns the registered job a loaded DAG belongs to, or ""
// for an ordinary DAG. It keys on the DAG's definition (its file stem, the
// job ID for registry-written DAGs) and refuses a job file whose declared
// name differs from it, and any other DAG claiming a job's name, so no alias
// can carry a job's run past the guard.
func txeJobIdentity(dag *ir.DAG) (string, error) {
	if dag == nil {
		return "", nil
	}
	stem := dag.SuspendFlagName()
	switch {
	case registry.IsJobDAG(stem) && dag.Name != "" && dag.Name != stem:
		return "", txeRefuseInlineJobDAG(stem)
	case registry.IsJobDAG(dag.Name) && dag.Name != stem:
		return "", txeRefuseInlineJobDAG(dag.Name)
	case registry.IsJobDAG(stem):
		return stem, nil
	}
	return "", nil
}

// txeAdmitDAG applies the registry run guard to a loaded DAG.
func (a *API) txeAdmitDAG(ctx context.Context, dag *ir.DAG) error {
	jobID, err := txeJobIdentity(dag)
	if err != nil || jobID == "" {
		return err
	}
	return a.txeAdmitJob(ctx, jobID, dag)
}

// txeAdmitJob admits running definition as jobID: the registry must admit
// the job and definition must be its current version.
func (a *API) txeAdmitJob(ctx context.Context, jobID string, definition *ir.DAG) error {
	s, err := a.txeStore()
	if err != nil {
		return err
	}
	spec := ""
	if definition != nil && len(definition.YamlData) > 0 {
		spec = fmt.Sprintf("sha256:%x", sha256.Sum256(definition.YamlData))
	}
	adm, err := s.AdmitRun(ctx, jobID, spec)
	if err != nil {
		return err
	}
	return txeRunRefused(jobID, adm)
}

// txeRefuseLocalJobRun refuses executing a registered job's run in this
// process: jobs run only through their machine's worker, where the claim is
// admitted and recorded against retirement.
func (a *API) txeRefuseLocalJobRun(dag *ir.DAG) error {
	jobID, err := txeJobIdentity(dag)
	if err != nil || jobID == "" {
		return err
	}
	if dispatch.ShouldDispatchToCoordinator(dag, a.coordinatorCli != nil, a.defaultExecMode) {
		return nil
	}
	return &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
		Message: "registered jobs run only on their machine's worker; no coordinator is available to dispatch " + jobID,
		Details: map[string]any{"code": "run_refused"}}
}

// txeRunRefused turns a refused admission into the API error.
func txeRunRefused(dagName string, adm registry.Admission) error {
	if adm.Admit {
		return nil
	}
	return &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
		Message: fmt.Sprintf("job %s does not accept runs: %s", dagName, adm.Reason),
		Details: map[string]any{"code": "run_refused", "admission": string(adm.Code)}}
}

// txeRefuseRunName refuses running a registered job's DAG under another
// name, and any DAG under a job's name: the run name is the identity the
// scheduler and coordinator guard on.
func txeRefuseRunName(dag *ir.DAG, name string) error {
	if name == "" || dag == nil {
		return nil
	}
	if registry.IsJobDAG(dag.SuspendFlagName()) && name != dag.SuspendFlagName() {
		return &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
			Message: "a registered job's DAG cannot run under another name",
			Details: map[string]any{"code": "run_refused"}}
	}
	return txeRefuseInlineJobDAG(name)
}

// txeRefuseInlineJobDAG refuses an inline spec that names itself as a
// registered job: only the registry writes job DAGs.
func txeRefuseInlineJobDAG(name string) error {
	if !registry.IsJobDAG(name) {
		return nil
	}
	return &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
		Message: "inline specs cannot use a registered job's name " + name,
		Details: map[string]any{"code": "run_refused", "admission": string(registry.AdmitUnregistered)}}
}

func (a *API) RecordTxeResourceEvent(ctx context.Context, req api.RecordTxeResourceEventRequestObject) (api.RecordTxeResourceEventResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	s, actor, err := a.txeWrite(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	target, err := txeConvert[registry.Target](body.Target)
	if err != nil {
		return nil, ErrInvalidRequestBody
	}
	ev := registry.ResourceEvent{
		EventID:       valueOf(body.EventId),
		Target:        target,
		Observation:   registry.ResourceObservation(body.Observation),
		Authoritative: valueOf(body.Authoritative),
		Detail:        valueOf(body.Detail),
		Evidence:      derefSlice(body.Evidence),
	}
	if body.ObservedAt != nil {
		ev.ObservedAt = *body.ObservedAt
	}
	// The event affects, and reports, only jobs the caller may write.
	writable := func(ctx context.Context, job *registry.Job) bool {
		return a.txeCheckVersion(ctx, s, job, job.Version, a.txeRequireWorkspaceWrite) == nil
	}
	recorded, err := s.RecordResourceEvent(ctx, ev, actor, writable)
	if err != nil {
		// A save failure after the event exists is a 409 "incomplete" that
		// carries the event, so the reporter can resume it by its event_id.
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeResourceEvent](recorded)
	return api.RecordTxeResourceEvent200JSONResponse(out), err
}

func (a *API) GetTxeResourceEvent(ctx context.Context, req api.GetTxeResourceEventRequestObject) (api.GetTxeResourceEventResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	ev, err := s.GetResourceEvent(ctx, req.EventId)
	if err != nil {
		return nil, txeError(err)
	}
	canSee := func(jobID string) bool {
		_, err := a.txeVisibleJob(ctx, s, jobID)
		return err == nil
	}
	visible := ev.Dispositions[:0]
	for _, d := range ev.Dispositions {
		if canSee(d.JobID) {
			visible = append(visible, d)
		}
	}
	ev.Dispositions = visible
	pending := ev.Pending[:0]
	for _, p := range ev.Pending {
		if canSee(p.JobID) {
			pending = append(pending, p)
		}
	}
	ev.Pending = pending
	failures := ev.Failures[:0]
	for _, f := range ev.Failures {
		if canSee(f.JobID) {
			failures = append(failures, f)
		}
	}
	ev.Failures = failures
	// The target and evidence are shown only to the reporter or to someone
	// who can see a job the event affected.
	if user, ok := auth.UserFromContext(ctx); a.authService != nil && len(visible)+len(pending) == 0 && (!ok || user.Username != ev.Reporter.ID) {
		return nil, txeError(&registry.Error{Code: registry.CodeNotFound, Message: "resource event " + req.EventId + " not found"})
	}
	out, err := txeConvert[api.TxeResourceEvent](ev)
	return api.GetTxeResourceEvent200JSONResponse(out), err
}

func (a *API) ListTxePendingClosures(ctx context.Context, req api.ListTxePendingClosuresRequestObject) (api.ListTxePendingClosuresResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	if err := registry.ValidateID(registry.PrefixMachine, req.Params.Machine); err != nil {
		return nil, txeError(err)
	}
	pending, err := s.PendingClosures(ctx, req.Params.Machine, txeLimit(req.Params.Limit), func(job *registry.Job) bool {
		return a.txeJobVisible(ctx, s, job) == nil
	})
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[[]api.TxePendingClosure](pending)
	if out == nil {
		out = []api.TxePendingClosure{}
	}
	return api.ListTxePendingClosures200JSONResponse{Closures: out}, err
}

func (a *API) RecordTxeProposalClosure(ctx context.Context, req api.RecordTxeProposalClosureRequestObject) (api.RecordTxeProposalClosureResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	var closure *registry.Closure
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error {
		var err error
		closure, err = tx.RecordClosure(ctx, s, req.ProposalId, registry.ClosureOutcome(body.Outcome), valueOf(body.Detail))
		return err
	}); err != nil {
		return nil, err
	}
	out, err := txeConvert[api.TxeClosure](closure)
	return api.RecordTxeProposalClosure200JSONResponse(out), err
}

func (a *API) RecordTxeRunArtifacts(ctx context.Context, req api.RecordTxeRunArtifactsRequestObject) (api.RecordTxeRunArtifactsResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	in, err := txeConvert[registry.ArtifactManifest](struct {
		JobVersion int                          `json:"job_version"`
		Artifacts  []api.TxeArtifactRecordInput `json:"artifacts"`
	}{body.JobVersion, body.Artifacts})
	if err != nil {
		return nil, ErrInvalidRequestBody
	}
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	runSpec, err := a.txeRunSpecDigest(ctx, req.JobId, req.RunId)
	if err != nil {
		return nil, err
	}
	var m *registry.ArtifactManifest
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, func(tx *registry.JobTx) error {
		var err error
		m, err = tx.RecordArtifacts(ctx, s, req.RunId, runSpec, in)
		return err
	}); err != nil {
		return nil, err
	}
	out, err := txeConvert[api.TxeArtifactManifest](m)
	return api.RecordTxeRunArtifacts200JSONResponse(out), err
}

func (a *API) GetTxeRunArtifacts(ctx context.Context, req api.GetTxeRunArtifactsRequestObject) (api.GetTxeRunArtifactsResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	if _, err := a.txeVisibleJob(ctx, s, req.JobId); err != nil {
		return nil, err
	}
	m, err := s.GetArtifacts(ctx, req.JobId, req.RunId)
	if err != nil {
		return nil, txeError(err)
	}
	pending := slices.ContainsFunc(m.Artifacts, func(r registry.ArtifactRecord) bool { return r.Status == registry.ArtifactPendingUpload })
	if pending && a.dagRunRepository != nil {
		// The run's native artifact directory holds the hub copies. A run the
		// hub does not know yet is left unchecked rather than failed.
		status, err := a.getDAGRunArtifactStatus(ctx, req.JobId, req.RunId)
		switch {
		case err == nil:
			ended := !status.Status.IsActive() && status.Status != ir.NotStarted
			m, err = s.CheckHubArtifacts(ctx, req.JobId, req.RunId, func(p string) (string, bool, error) {
				sha, found, err := txeArtifactDigest(status.ArchiveDir, p)
				if err != nil {
					logger.Warn(ctx, "TXE hub artifact could not be read", tag.RunID(req.RunId), tag.Error(err))
				}
				return sha, found, err
			}, ended)
			if err != nil {
				return nil, txeError(err)
			}
		case !isArtifactStatusNotFound(err):
			return nil, err
		}
	}
	out, err := txeConvert[api.TxeArtifactManifest](m)
	return api.GetTxeRunArtifacts200JSONResponse(out), err
}

// txeRunSpecDigest returns the digest of the saved DAG of a run of the job,
// in the form the registry records for a version's spec. A run the hub has
// no record of is 404: deliverables are recorded only for real runs.
func (a *API) txeRunSpecDigest(ctx context.Context, jobID, runID string) (string, error) {
	if a.dagRunRepository == nil {
		return "", &Error{HTTPStatus: http.StatusServiceUnavailable, Code: api.ErrorCodeInternalError, Message: "run history is not available"}
	}
	attempt, err := a.dagRunRepository.FindAttempt(ctx, ir.NewDAGRunRef(jobID, runID))
	if err != nil {
		if errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
			return "", &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound, Message: "job " + jobID + " has no run " + runID}
		}
		return "", err
	}
	dag, err := attempt.ReadDAG(ctx)
	if err != nil {
		return "", err
	}
	if len(dag.YamlData) == 0 {
		return "", &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict, Message: "run " + runID + " has no saved DAG to bind its deliverables to",
			Details: map[string]any{"code": string(registry.CodeStaleBinding)}}
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(dag.YamlData)), nil
}

// txeArtifactDigest returns the sha256 of the file at relPath in a run's
// native artifact directory, or found false when there is no such file.
func txeArtifactDigest(archiveDir, relPath string) (string, bool, error) {
	f, info, err := openArtifactFile(archiveDir, relPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, errArtifactUnavailable) {
			return "", false, nil
		}
		return "", false, err
	}
	defer func() { _ = f.Close() }()
	if !info.Mode().IsRegular() {
		return "", false, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", false, err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), true, nil
}
