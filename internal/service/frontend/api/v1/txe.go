// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"time"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
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
		out.Details["current"] = txePublicCurrent(re.Current)
	}
	return out
}

// txePublicCurrent is the record a refusal returns, in its API shape: a
// registry record can carry fields the API never publishes (a manifest's
// absolute archive directory), so known records are converted and a record
// that cannot be is left out.
func txePublicCurrent(current any) any {
	var (
		out any
		err error
	)
	switch c := current.(type) {
	case *registry.Job:
		out, err = txeConvert[api.TxeJob](c)
	case *registry.ArtifactManifest:
		out, err = txeConvert[api.TxeArtifactManifest](c)
	default:
		return current
	}
	if err != nil {
		return nil
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
	if a.txeOwnerOnly(ctx) {
		return a.txeOwnerWrite(ctx, in)
	}
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

// txeOwnerWrite prepares a write by a caller held to its owner: it needs an
// owner, not a role, and the owner decision is made against the record the
// write names. A token is recorded as an agent and never as a person.
func (a *API) txeOwnerWrite(ctx context.Context, in *api.TxeActor) (*registry.Store, registry.Actor, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, registry.Actor{}, err
	}
	c, err := a.txeResolve(ctx)
	if err != nil {
		return nil, registry.Actor{}, err
	}
	if c.scope.Kind() == authz.ScopeUnbound {
		return nil, registry.Actor{}, errTxeUnbound
	}
	actor, err := txeActor(ctx, in)
	if err != nil {
		return nil, registry.Actor{}, err
	}
	if c.caller.Kind == txeauth.KindToken {
		actor = txeTokenActor(c.caller, c.scope, actor)
	}
	return s, actor, nil
}

// txeRequireDAGWrite is the server's switch for DAG changes. For a caller
// held to its owner it is only the switch: the owner decision replaces the
// role check.
func (a *API) txeRequireDAGWrite(ctx context.Context) error {
	if !a.txeOwnerOnly(ctx) {
		return a.requireDAGWrite(ctx)
	}
	if !a.config.Server.Permissions[config.PermissionWriteDAGs] {
		return errPermissionDenied
	}
	if a.dagWritesDisabled {
		return errDAGWritesDisabled
	}
	return nil
}

// txeRequireSpecWrite applies the native DAG write authorization to a job's
// DAG: the caller must be able to write DAGs in the workspace the new spec
// names and, when the DAG already exists, in the workspace it is in now. A
// spec that does not parse is left to the registry to refuse.
func (a *API) txeRequireSpecWrite(ctx context.Context, jobID, spec string) error {
	if err := a.txeRequireDAGWrite(ctx); err != nil {
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
	return a.txeRequireJobChange(ctx, tx, authz.PermissionAuthor, txeNeed{})
}

// txeRequireJobChange checks, inside the job transaction, that the caller
// may exercise permission on the job's owner's data, and, for a caller the
// hub's roles still govern, that it may write the job's workspaces.
func (a *API) txeRequireJobChange(ctx context.Context, tx *registry.JobTx, permission authz.Permission, need txeNeed) error {
	if err := a.txeAuthorizeJob(ctx, tx.Job.JobID, permission, need); err != nil {
		return err
	}
	if a.txeOwnerOnly(ctx) {
		return nil
	}
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
		return txeError(a.txeVisibleRefusal(ctx, s, &registry.Error{Code: registry.CodeVersionConflict, Message: fmt.Sprintf("job is at version %d, not %d", job.Version, version), Current: job}))
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
	if a.dagRepository == nil || a.txeOwnerOnly(ctx) {
		// A caller held to its owner is authorized by the owner decision;
		// workspaces do not apply to it.
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
	if err := a.txeAuthorizeJob(ctx, job.JobID, authz.PermissionView, txeNeed{}); err != nil {
		return err
	}
	if a.authService == nil || a.txeOwnerOnly(ctx) {
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
	if registry.ErrorCode(err) == registry.CodeNotFound {
		return nil, txeJobNotFound(jobID)
	}
	if err != nil {
		return nil, txeError(err)
	}
	if err := a.txeJobVisible(ctx, s, job); err != nil {
		var apiErr *Error
		if errors.As(err, &apiErr) && apiErr.HTTPStatus == http.StatusNotFound {
			return nil, txeJobNotFound(jobID)
		}
		return nil, err
	}
	return job, nil
}

// txeJobNotFound is the one answer for a job that does not exist and for
// one the caller cannot see, so a read confirms nothing about hidden jobs.
func txeJobNotFound(jobID string) error {
	return txeError(&registry.Error{Code: registry.CodeNotFound, Message: "job " + jobID + " not found"})
}

// txeResourceEventNotFound is the one answer for a resource event that does
// not exist and for one the caller cannot see.
func txeResourceEventNotFound(eventID string) error {
	return txeError(&registry.Error{Code: registry.CodeNotFound, Message: "resource event " + eventID + " not found"})
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
func (a *API) txeTx(ctx context.Context, jobID string, in *api.TxeActor, permission authz.Permission, need txeNeed, fn func(tx *registry.JobTx) error) (api.TxeJob, error) {
	s, actor, err := a.txeWrite(ctx, in)
	if err != nil {
		return api.TxeJob{}, err
	}
	job, err := s.WithJobTx(ctx, jobID, actor, func(tx *registry.JobTx) error {
		if err := a.txeRequireJobChange(ctx, tx, permission, need); err != nil {
			return err
		}
		return fn(tx)
	})
	if err != nil {
		return api.TxeJob{}, txeError(a.txeVisibleRefusal(ctx, s, err))
	}
	return txeConvert[api.TxeJob](a.txePublicJob(ctx, s, job))
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
	// Each caller sees its own owner; only the platform administrator sees
	// every owner.
	owners := inst.Owners[:0:0]
	for _, o := range inst.Owners {
		ok, err := a.txeOwnerVisible(ctx, o.OwnerID)
		if err != nil {
			return nil, err
		}
		if ok {
			owners = append(owners, o)
		}
	}
	inst.Owners = owners
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
	// An owner is made only by the platform administrator, before a person
	// is bound to it. No sign-in or token ever makes one.
	if err := a.txeAuthorizePlatform(ctx, authz.PermissionAdminister); err != nil {
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
	switch ok, err := a.txeOwnerVisible(ctx, req.OwnerId); {
	case err != nil:
		return nil, err
	case !ok:
		return nil, txeError(&registry.Error{Code: registry.CodeNotFound, Message: "owner " + req.OwnerId + " not found"})
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
	if err := a.txeAuthorizeOwnData(ctx, body.OwnerId, authz.PermissionAuthor); err != nil {
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
	switch ok, err := a.txeAuthorizeRecord(ctx, func(st *authz.Store) (authz.Resource, error) { return st.Project(ctx, req.ProjectId) }); {
	case err != nil:
		return nil, err
	case !ok:
		return nil, txeError(&registry.Error{Code: registry.CodeNotFound, Message: "project " + req.ProjectId + " not found"})
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
	if err := a.txeAuthorizeOwnData(ctx, body.OwnerId, authz.PermissionAuthor); err != nil {
		return nil, err
	}
	m, err := s.CreateMachine(ctx, registry.Machine{MachineID: body.MachineId, OwnerID: body.OwnerId, DisplayName: body.DisplayName}, actor)
	if err != nil {
		return nil, txeError(a.txeVisibleMachineRefusal(ctx, err))
	}
	out, err := txeConvert[api.TxeMachine](m)
	return api.CreateTxeMachine201JSONResponse(out), err
}

// ListTxeMachines lists the machines the caller may see, each decided by
// owner view as GetTxeMachine decides one. A machine's own credential sees
// that machine only. The count of pending enrolment applications is given
// only to a person of the machine's owner, who may approve them.
func (a *API) ListTxeMachines(ctx context.Context, _ api.ListTxeMachinesRequestObject) (api.ListTxeMachinesResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	caller := txeauth.Classify(ctx)
	scope, err := a.txeAuth.Scope(ctx, caller)
	if err != nil {
		return nil, errTxeAuthzUnavailable
	}
	all, err := s.ListMachines(ctx, "")
	if err != nil {
		return nil, txeError(err)
	}
	now := time.Now()
	out := []api.TxeMachineSummary{}
	// The owner's enrolments, by machine and class, read once when a count
	// is first given: an application already enrolled is not pending.
	var enrolled map[string]*authz.Enrolment
	enrolledBy := func() (map[string]*authz.Enrolment, error) {
		if enrolled != nil {
			return enrolled, nil
		}
		all, err := a.txeAuth.Store().Enrolments(ctx, scope.OwnerID())
		if err != nil {
			return nil, err
		}
		enrolled = map[string]*authz.Enrolment{}
		for _, e := range all {
			enrolled[e.MachineID+"/"+string(e.Class)] = e
		}
		return enrolled, nil
	}
	for _, m := range all {
		if own := scope.MachineID(); own != "" && m.MachineID != own {
			continue
		}
		machineID := m.MachineID
		switch ok, err := a.txeAuthorizeRecord(ctx, func(st *authz.Store) (authz.Resource, error) { return st.Machine(ctx, machineID) }); {
		case err != nil:
			return nil, err
		case !ok:
			continue
		}
		item := api.TxeMachineSummary{MachineId: m.MachineID, OwnerId: m.OwnerID, DisplayName: m.DisplayName}
		switch approver, err := a.txeOwnsMachine(ctx, scope, m.MachineID, true); {
		case err != nil:
			return nil, err
		case approver:
			applications, err := a.txeAuth.Store().EnrolmentApplications(ctx, m.MachineID)
			if err != nil {
				return nil, txeAuthzError(err)
			}
			enrolments, err := enrolledBy()
			if err != nil {
				return nil, txeAuthzError(err)
			}
			pending := 0
			for _, application := range applications {
				if application.CredentialExpires.IsZero() || !now.Before(application.CredentialExpires) {
					continue
				}
				// Approved: the machine's enrolment for the class is active
				// and is this application's credential. A pending or
				// revoked enrolment approves nothing.
				if e := enrolments[application.MachineID+"/"+string(application.Class)]; e != nil && e.State == authz.StateActive &&
					e.Key.Issuer == application.Issuer && e.Key.ClientID == application.ClientID && e.Subject == application.Subject {
					continue
				}
				pending++
			}
			item.PendingApplications = &pending
		}
		out = append(out, item)
	}
	return api.ListTxeMachines200JSONResponse{Machines: out}, nil
}

func (a *API) GetTxeMachine(ctx context.Context, req api.GetTxeMachineRequestObject) (api.GetTxeMachineResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	switch ok, err := a.txeAuthorizeRecord(ctx, func(st *authz.Store) (authz.Resource, error) { return st.Machine(ctx, req.MachineId) }); {
	case err != nil:
		return nil, err
	case !ok:
		return nil, txeError(&registry.Error{Code: registry.CodeNotFound, Message: "machine " + req.MachineId + " not found"})
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
		switch err := a.txeJobVisible(ctx, s, job); {
		case err == nil:
			jobs = append(jobs, a.txePublicJob(ctx, s, job))
		case errors.Is(err, errTxeAuthzUnavailable):
			// An owner store that cannot be read is an outage, not a list
			// with jobs missing. Any other refusal hides the job, as
			// before.
			return nil, err
		}
	}
	// Ordered after the jobs the caller cannot see are left out, so where a
	// duplicate stands says nothing about a job the caller cannot see.
	out, err := txeConvert[[]api.TxeJob](registry.WinnersFirst(jobs))
	if out == nil {
		out = []api.TxeJob{}
	}
	for i := range out {
		out[i].Access = a.txeJobAccess(ctx, out[i].JobId)
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
	// A job is registered only under the caller's own owner; the registry
	// then refuses a project or machine of any other.
	if err := a.txeAuthorizeOwnData(ctx, body.OwnerId, authz.PermissionAuthor); err != nil {
		return nil, err
	}
	if err := a.txeRequireSpecWrite(ctx, body.JobId, v.DAG.Spec); err != nil {
		return nil, err
	}
	job, err := s.Register(ctx, registry.RegisterInput{
		JobID: body.JobId, RequestID: body.RequestId, OwnerID: body.OwnerId, ProjectID: body.ProjectId,
		MachineID: body.MachineId, JobKey: body.JobKey, Version: v,
	}, actor)
	if err != nil {
		return nil, txeError(a.txeVisibleRefusal(ctx, s, err))
	}
	out, err := txeConvert[api.TxeJob](a.txePublicJob(ctx, s, job))
	return api.RegisterTxeJob201JSONResponse(out), err
}

// txeCanSeeJob reports whether the caller can see job jobID.
func (a *API) txeCanSeeJob(ctx context.Context, s *registry.Store, jobID string) bool {
	_, err := a.txeVisibleJob(ctx, s, jobID)
	return err == nil
}

// txePublicJob is job as the caller may see it: a duplicate names the job
// holding its key only to a caller who can see that job.
func (a *API) txePublicJob(ctx context.Context, s *registry.Store, job *registry.Job) *registry.Job {
	if job == nil || job.Registration.DuplicateOf == "" || a.txeCanSeeJob(ctx, s, job.Registration.DuplicateOf) {
		return job
	}
	out := *job
	out.Registration.DuplicateOf = ""
	return &out
}

// txePublicEvents names a duplicate's winner in its history only to a
// caller who can see the winner.
func (a *API) txePublicEvents(ctx context.Context, s *registry.Store, events []*registry.Event) []*registry.Event {
	out := make([]*registry.Event, len(events))
	for i, e := range events {
		out[i] = e
		if e != nil && e.Kind == registry.EventDuplicate && e.To != "" && !a.txeCanSeeJob(ctx, s, e.To) {
			hidden := *e
			hidden.To = ""
			out[i] = &hidden
		}
	}
	return out
}

// txeVisibleResult returns a job record read after the caller was
// authorized only if the caller can still see it; otherwise the job is not
// found to the caller.
func (a *API) txeVisibleResult(ctx context.Context, s *registry.Store, job *registry.Job) (*registry.Job, error) {
	if err := a.txeJobVisible(ctx, s, job); err != nil {
		var apiErr *Error
		if errors.As(err, &apiErr) && apiErr.HTTPStatus == http.StatusNotFound {
			return nil, txeJobNotFound(job.JobID)
		}
		return nil, err
	}
	return job, nil
}

// txeVisibleRefusal keeps a refusal from disclosing a job the caller cannot
// see: a record read after the caller was authorized (a job moved meanwhile,
// a duplicate's winner) is returned, and named, only if it is visible now.
func (a *API) txeVisibleRefusal(ctx context.Context, s *registry.Store, err error) error {
	re, ok := errors.AsType[*registry.Error](err)
	if !ok {
		return err
	}
	switch c := re.Current.(type) {
	case *registry.Job:
		if a.txeJobVisible(ctx, s, c) != nil {
			return &registry.Error{Code: re.Code, Message: txeHiddenRefusal(re.Code)}
		}
		return &registry.Error{Code: re.Code, Message: re.Message, Current: a.txePublicJob(ctx, s, c)}
	case registry.DuplicateWinner:
		if !a.txeCanSeeJob(ctx, s, c.JobID) {
			return &registry.Error{Code: re.Code, Message: txeHiddenRefusal(re.Code)}
		}
	}
	return err
}

func txeHiddenRefusal(code registry.Code) string {
	if code == registry.CodeDuplicate {
		return "job key already registered"
	}
	return "refused against the job's current state"
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
	out, err := txeConvert[api.TxeJob](a.txePublicJob(ctx, s, job))
	out.Access = a.txeJobAccess(ctx, req.JobId)
	return api.GetTxeJob200JSONResponse(out), err
}

func (a *API) MarkTxeJobReady(ctx context.Context, req api.MarkTxeJobReadyRequestObject) (api.MarkTxeJobReadyResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	if err := a.txeRequireDAGWrite(ctx); err != nil {
		return nil, err
	}
	s, actor, err := a.txeWrite(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	if err := a.txeAuthorizeJob(ctx, req.JobId, authz.PermissionAuthor, txeNeed{}); err != nil {
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
			return nil, txeError(a.txeVisibleRefusal(ctx, s, &registry.Error{Code: registry.CodeVersionConflict, Message: fmt.Sprintf("job is at revision %d, not %d", job.Revision, explicit), Current: job}))
		}
		receipt, err = s.MarkReady(ctx, req.JobId, job.Revision, pkg, actor)
		if err == nil {
			break
		}
		if pinned || registry.ErrorCode(err) != registry.CodeVersionConflict || attempt == 4 {
			return nil, txeError(a.txeVisibleRefusal(ctx, s, err))
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
	if err := a.txeAuthorizeJob(ctx, req.JobId, authz.PermissionAuthor, txeNeed{}); err != nil {
		return nil, err
	}
	if err := a.txeRequireSpecWrite(ctx, req.JobId, v.DAG.Spec); err != nil {
		return nil, err
	}
	// The caller must be able to write the job as committed before anything
	// about it is compared: a conflict carries the job record, so it is only
	// for a caller who may write the job (a job whose DAG file is missing
	// was checked above only against the caller's own spec).
	cur, err := s.GetJob(ctx, req.JobId)
	if err != nil {
		return nil, txeError(err)
	}
	if err := a.txeCheckVersion(ctx, s, cur, cur.Version, a.requireDAGWriteForWorkspace); err != nil {
		return nil, err
	}
	// The update is accepted only against expected_version, so that is the
	// committed version the caller must be able to write too.
	if err := a.txeCheckVersion(ctx, s, cur, body.ExpectedVersion, a.requireDAGWriteForWorkspace); err != nil {
		return nil, err
	}
	job, err := s.UpdateVersion(ctx, req.JobId, body.RequestId, body.ExpectedVersion, v, actor)
	if err != nil {
		return nil, txeError(a.txeVisibleRefusal(ctx, s, err))
	}
	out, err := txeConvert[api.TxeJob](a.txePublicJob(ctx, s, job))
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
		return nil, txeError(a.txeVisibleRefusal(ctx, s, err))
	}
	// The result is re-read after the change's effects; the job may have
	// moved to a workspace the caller cannot see meanwhile.
	committed, err = a.txeVisibleResult(ctx, s, committed)
	if err != nil {
		return nil, err
	}
	job, err := txeConvert[api.TxeJob](a.txePublicJob(ctx, s, committed))
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
	out, err := txeConvert[[]api.TxeEvent](a.txePublicEvents(ctx, s, events))
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
	o.ActionID, o.Attempt, o.ClaimID, o.Fence = valueOf(body.ActionId), valueOf(body.Attempt), valueOf(body.ClaimId), valueOf(body.Fence)
	o.JobVersion = valueOf(body.JobVersion)
	job, err := a.txeTx(ctx, req.JobId, body.Actor, authz.PermissionExecute, txeNeed{}, func(tx *registry.JobTx) error { return tx.Observe(o) })
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
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, authz.PermissionExecute, txeClaimNeed(registry.ClaimKind(body.Kind)), func(tx *registry.JobTx) error {
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
	job, err := a.txeTx(ctx, req.JobId, body.Actor, authz.PermissionExecute, txeMachineNeed, func(tx *registry.JobTx) error {
		// A review claim is released only by the reviewer it belongs to.
		if c := tx.Job.Claim; c != nil && c.ClaimID == req.ClaimId && c.Kind == registry.ClaimReview {
			if err := a.txeAuthorizeJob(ctx, req.JobId, authz.PermissionExecute, txeReviewerNeed); err != nil {
				return err
			}
		}
		return tx.ReleaseClaim(req.ClaimId, body.Fence)
	})
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
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, authz.PermissionExecute, txeReviewerNeed, func(tx *registry.JobTx) error {
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
	job, err := a.txeTx(ctx, req.JobId, body.Actor, authz.PermissionExecute, txeReviewerNeed, func(tx *registry.JobTx) error {
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
	job, err := a.txeTx(ctx, req.JobId, body.Actor, authz.PermissionExecute, txeReviewerNeed, func(tx *registry.JobTx) error {
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
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, authz.PermissionExecute, txeReviewerNeed, func(tx *registry.JobTx) error {
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
	staleRetry := false
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, authz.PermissionExecute, txeMachineNeed, func(tx *registry.JobTx) error {
		var err error
		g, err = tx.Authorize(effect)
		// Reached only once the caller may write the job: an approved
		// effect refused because its run no longer binds.
		staleRetry = effect.Approved != nil && registry.ErrorCode(err) == registry.CodeStaleBinding
		return err
	}); err != nil {
		if staleRetry {
			// A decided retry whose run moved on can never be authorized: end
			// such retries (the caller's write permission is checked again),
			// so they leave the decision queue, and return the refusal.
			if _, eerr := a.txeTx(ctx, req.JobId, body.Actor, authz.PermissionExecute, txeMachineNeed, func(tx *registry.JobTx) error {
				_, err := tx.EndMovedOnRetries()
				return err
			}); eerr != nil {
				logger.Warn(ctx, "Failed to end retries whose run moved on", tag.Error(eerr))
			}
		}
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
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, authz.PermissionExecute, txeMachineNeed, func(tx *registry.JobTx) error {
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
func (a *API) txeRefuseRunName(ctx context.Context, dag *ir.DAG, name string) error {
	if name == "" || dag == nil {
		return nil
	}
	own := dag.SuspendFlagName()
	if registry.IsJobDAG(own) && name != own {
		return &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
			Message: "a registered job's DAG cannot run under another name",
			Details: map[string]any{"code": "run_refused"}}
	}
	if err := txeRefuseInlineJobDAG(name); err != nil {
		return err
	}
	// A run belongs to the owner of the name it runs under: a machine's DAG
	// does not run under another name, and no DAG runs under a machine's.
	// A caller held to its owner runs a DAG only under its own name, so
	// none of its runs lands where its owner does not reach.
	if name != own && (txeNativeOwnedName(own) || txeNativeOwnedName(name) || a.txeNativeOwnerOnly(ctx)) {
		return &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
			Message: "this DAG cannot run under another name",
			Details: map[string]any{"code": "run_refused"}}
	}
	return nil
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
		return a.txeResourceEventApplies(ctx, s, job)
	}
	recorded, err := s.RecordResourceEvent(ctx, ev, actor, writable)
	if err != nil {
		// A save failure after the event exists is a 409 "incomplete" that
		// carries only the event's ID, so the reporter can resume it.
		return nil, txeError(err)
	}
	// A reply, a replay of a completed event included, shows only the jobs
	// the caller can see now, as GET does.
	shown := cloneResourceEvent(recorded)
	a.txeShowResourceEvent(ctx, s, shown)
	out, err := txeConvert[api.TxeResourceEvent](shown)
	return api.RecordTxeResourceEvent200JSONResponse(out), err
}

// cloneResourceEvent copies ev, with its own lists, so a reply can be
// filtered without touching the stored event.
func cloneResourceEvent(ev *registry.ResourceEvent) *registry.ResourceEvent {
	out := *ev
	out.Dispositions = slices.Clone(ev.Dispositions)
	out.Pending = slices.Clone(ev.Pending)
	out.Failures = slices.Clone(ev.Failures)
	return &out
}

// txeShowResourceEvent keeps only the parts of ev about jobs the caller can
// see, and reports whether the caller may see the event at all: the target
// and evidence are shown only to the reporter or to someone who can see a
// job the event affected.
func (a *API) txeShowResourceEvent(ctx context.Context, s *registry.Store, ev *registry.ResourceEvent) bool {
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
	return a.authService == nil || len(visible)+len(pending) > 0 || a.txeIsStandingReporter(ctx, ev)
}

func (a *API) ListTxeResourceEvents(ctx context.Context, req api.ListTxeResourceEventsRequestObject) (api.ListTxeResourceEventsResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	if req.Params.Complete {
		return nil, &Error{HTTPStatus: http.StatusBadRequest, Code: api.ErrorCodeBadRequest, Message: "only incomplete events can be listed (complete=false)"}
	}
	limit := 50
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if limit < 1 || limit > 200 {
		return nil, &Error{HTTPStatus: http.StatusBadRequest, Code: api.ErrorCodeBadRequest, Message: "limit must be between 1 and 200"}
	}
	// Visibility decides the page, so neither the events nor the cursor
	// name an event the caller may not see.
	events, next, err := s.IncompleteResourceEvents(ctx, valueOf(req.Params.ReporterMachineId), valueOf(req.Params.After), limit,
		func(ev *registry.ResourceEvent) bool { return a.txeShowResourceEvent(ctx, s, ev) })
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[[]api.TxeResourceEvent](events)
	if out == nil {
		out = []api.TxeResourceEvent{}
	}
	resp := api.ListTxeResourceEvents200JSONResponse{Events: out}
	if next != "" {
		resp.NextCursor = &next
	}
	return resp, err
}

func (a *API) GetTxeResourceEvent(ctx context.Context, req api.GetTxeResourceEventRequestObject) (api.GetTxeResourceEventResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	ev, err := s.GetResourceEvent(ctx, req.EventId)
	if registry.ErrorCode(err) == registry.CodeNotFound {
		return nil, txeResourceEventNotFound(req.EventId)
	}
	if err != nil {
		return nil, txeError(err)
	}
	if !a.txeShowResourceEvent(ctx, s, ev) {
		return nil, txeResourceEventNotFound(req.EventId)
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
	if _, err := a.txeTx(ctx, req.JobId, body.Actor, authz.PermissionExecute, txeMachineNeed, func(tx *registry.JobTx) error {
		var err error
		closure, err = tx.RecordClosure(ctx, s, req.ProposalId, registry.ClosureOutcome(body.Outcome), valueOf(body.Detail))
		return err
	}); err != nil {
		return nil, err
	}
	out, err := txeConvert[api.TxeClosure](closure)
	return api.RecordTxeProposalClosure200JSONResponse(out), err
}

// txeBeforeArtifactTx, when set by a test, runs between the first owner
// decision on an artifact report and the job transaction that decides again.
var txeBeforeArtifactTx func()

func (a *API) RecordTxeRunArtifacts(ctx context.Context, req api.RecordTxeRunArtifactsRequestObject) (api.RecordTxeRunArtifactsResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	in, err := txeConvert[registry.ArtifactManifest](struct {
		AttemptID  string                       `json:"attempt_id"`
		QueuedAt   string                       `json:"queued_at"`
		ProducedIn *api.TxeExecutionId          `json:"produced_in,omitempty"`
		JobVersion int                          `json:"job_version"`
		Artifacts  []api.TxeArtifactRecordInput `json:"artifacts"`
	}{body.AttemptId, body.QueuedAt, body.ProducedIn, body.JobVersion, body.Artifacts})
	if err != nil {
		return nil, ErrInvalidRequestBody
	}
	s, actor, err := a.txeWrite(ctx, body.Actor)
	if err != nil {
		return nil, err
	}
	// Publishing is running the job: the job's owner decides it, and the
	// run's workspace below cannot stand in for that decision.
	if err := a.txeAuthorizeJob(ctx, req.JobId, authz.PermissionExecute, txeMachineNeed); err != nil {
		return nil, err
	}
	if txeBeforeArtifactTx != nil {
		txeBeforeArtifactTx()
	}
	var m *registry.ArtifactManifest
	// A run publishes in the workspace it was saved in, which may not be the
	// job's current one (the job may have moved while it ran): publishing
	// needs write access to the run's saved workspace. A caller who cannot
	// write the job is refused with the job's own denial whenever the run
	// does not authorize it, so nothing tells them which runs exist.
	if _, err := s.WithJobTx(ctx, req.JobId, actor, func(tx *registry.JobTx) error {
		jobErr := a.txeRequireJobChange(ctx, tx, authz.PermissionExecute, txeMachineNeed)
		if jobErr != nil && a.txeOwnerOnly(ctx) {
			// A caller held to its owner is authorized by the owner alone,
			// decided again in this transaction; no run's workspace stands
			// in for a refusal, a revocation since the first check or a
			// store that cannot be read.
			return jobErr
		}
		latest, status, err := a.txeLatestRunAttempt(ctx, req.JobId, req.RunId)
		if err != nil {
			if jobErr != nil {
				return jobErr
			}
			return err
		}
		if err := a.txeRequireRunWorkspaceWrite(ctx, statusWorkspaceName(status)); err != nil {
			if jobErr != nil {
				return jobErr
			}
			return err
		}
		// A report naming an earlier execution can only be a replay or a
		// conflict, and either returns that execution's manifest: it must be
		// one the caller can see, by its own saved workspace.
		if ref := registry.ExecutionRef(in.AttemptID, in.QueuedAt); ref != latest.Ref() {
			ok, err := a.txeArtifactExecutionVisible(ctx, s, req.JobId, req.RunId, ref, latest, status)
			if err != nil {
				return err
			}
			if !ok {
				return &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound,
					Message: "execution " + ref + " of run " + req.RunId + " not found"}
			}
		}
		m, err = tx.RecordArtifacts(ctx, s, req.RunId, latest, in)
		return err
	}); err != nil {
		// The publisher was authorized by the run, not the job: a refusal
		// never returns the job's record.
		if re, ok := errors.AsType[*registry.Error](err); ok {
			if _, isJob := re.Current.(*registry.Job); isJob {
				err = &registry.Error{Code: re.Code, Message: re.Message}
			}
		}
		if _, ok := errors.AsType[*Error](err); ok {
			return nil, err
		}
		return nil, txeError(err)
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
	// The run's latest attempt chooses the default manifest and tells which
	// attempt's native artifact directory is current. A run the hub does not
	// know is read without checking hub copies.
	var latest registry.RunAttempt
	var status *ir.DAGRunStatus
	if a.dagRunRepository != nil {
		latest, status, err = a.txeLatestRunAttempt(ctx, req.JobId, req.RunId)
		var apiErr *Error
		if err != nil && (!errors.As(err, &apiErr) || apiErr.HTTPStatus != http.StatusNotFound) {
			return nil, err
		}
	}
	preferred := ""
	if latest.AttemptID != "" {
		preferred = latest.Ref()
	}
	m, err := s.GetArtifacts(ctx, req.JobId, req.RunId, valueOf(req.Params.Execution), preferred)
	if err != nil {
		return nil, txeError(err)
	}
	visible := func(ref string) (bool, error) {
		return a.txeArtifactExecutionVisible(ctx, s, req.JobId, req.RunId, ref, latest, status)
	}
	if ok, err := visible(m.Execution); err != nil {
		return nil, err
	} else if !ok {
		return nil, &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound, Message: "job " + req.JobId + " has no deliverables for run " + req.RunId}
	}
	pending := slices.ContainsFunc(m.Artifacts, func(r registry.ArtifactRecord) bool { return r.Status == registry.ArtifactPendingUpload })
	if pending && status != nil {
		dir, ended, known := m.ArchiveDir, true, m.ArchiveDir != ""
		if m.Execution == preferred {
			// The current attempt: its directory is the run's, and its copies
			// count as failed only once it has ended.
			dir, ended, known = status.ArchiveDir, latest.Finished, true
		}
		if known {
			m, err = s.CheckHubArtifacts(ctx, req.JobId, req.RunId, m.Execution, dir, func(p string) (string, bool, error) {
				if dir == "" {
					return "", false, nil
				}
				sha, found, err := txeArtifactDigest(dir, p)
				if err != nil {
					logger.Warn(ctx, "TXE hub artifact could not be read", tag.RunID(req.RunId), tag.Error(err))
				}
				return sha, found, err
			}, ended)
			if err != nil {
				return nil, txeError(err)
			}
		}
	}
	all, err := s.ListArtifacts(ctx, req.JobId, req.RunId)
	if err != nil {
		return nil, txeError(err)
	}
	out, err := txeConvert[api.TxeArtifactManifest](m)
	executions := make([]string, 0, len(all))
	for _, x := range all {
		ok, err := visible(x.Execution)
		if err != nil {
			return nil, err
		}
		if ok {
			executions = append(executions, x.Execution)
		}
	}
	out.Executions = &executions
	return api.GetTxeRunArtifacts200JSONResponse(out), err
}

// txeArtifactExecutionVisible reports whether the caller can see the
// workspace one execution of a run was saved in, as the native run
// endpoints judge a run: the run's latest status for its current execution,
// else the status the registry kept when that execution published, else
// its retained native copy. An execution with none of these is not visible.
func (a *API) txeArtifactExecutionVisible(ctx context.Context, s *registry.Store, jobID, runID, ref string,
	latest registry.RunAttempt, status *ir.DAGRunStatus) (bool, error) {
	if a.authService == nil {
		return true, nil
	}
	saved := status
	if latest.AttemptID == "" || ref != latest.Ref() {
		data, err := s.GetRetainedExecution(ctx, jobID, runID, ref, registry.EvidencePublication)
		switch {
		case err == nil:
			var st ir.DAGRunStatus
			if json.Unmarshal(data, &st) != nil {
				return false, nil
			}
			saved = &st
		case registry.ErrorCode(err) != registry.CodeNotFound:
			return false, txeError(err)
		case a.dagRunRepository != nil:
			return a.txeRetainedVisible(ctx, ir.NewDAGRunRef(jobID, runID), ref)
		default:
			return false, nil
		}
	}
	if saved == nil {
		return false, nil
	}
	if err := a.txeRunStatusVisible(ctx, saved); err != nil {
		var apiErr *Error
		if errors.As(err, &apiErr) && apiErr.HTTPStatus == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// txeLatestRunAttempt returns the latest attempt of a run of the job as
// Dagu stored it, with its status. A run the hub has no record of is 404:
// deliverables are recorded only for real runs.
func (a *API) txeLatestRunAttempt(ctx context.Context, jobID, runID string) (registry.RunAttempt, *ir.DAGRunStatus, error) {
	if a.dagRunRepository == nil {
		return registry.RunAttempt{}, nil, &Error{HTTPStatus: http.StatusServiceUnavailable, Code: api.ErrorCodeInternalError, Message: "run history is not available"}
	}
	attempt, err := a.dagRunRepository.FindAttempt(ctx, ir.NewDAGRunRef(jobID, runID))
	if err != nil {
		if errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
			return registry.RunAttempt{}, nil, &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound, Message: "job " + jobID + " has no run " + runID}
		}
		return registry.RunAttempt{}, nil, err
	}
	status, err := attempt.ReadStatus(ctx)
	if err != nil {
		return registry.RunAttempt{}, nil, err
	}
	dag, err := attempt.ReadDAG(ctx)
	if err != nil {
		return registry.RunAttempt{}, nil, err
	}
	snapshot, err := json.Marshal(status)
	if err != nil {
		return registry.RunAttempt{}, nil, err
	}
	out := registry.RunAttempt{AttemptID: status.AttemptID, QueuedAt: status.QueuedAt, Status: status.Status.String(),
		Running: status.Status == ir.Running, Finished: !status.Status.IsActive() && status.Status != ir.NotStarted,
		Succeeded: status.Status.IsSuccess(), ArchiveDir: status.ArchiveDir, Snapshot: snapshot}
	if out.AttemptID == "" {
		out.AttemptID = attempt.ID()
	}
	if len(dag.YamlData) > 0 {
		out.SpecSHA256 = fmt.Sprintf("sha256:%x", sha256.Sum256(dag.YamlData))
	}
	return out, status, nil
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

func (a *API) ListTxeRunExecutions(ctx context.Context, req api.ListTxeRunExecutionsRequestObject) (api.ListTxeRunExecutionsResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	if _, err := a.txeVisibleJob(ctx, s, req.JobId); err != nil {
		return nil, err
	}
	if a.dagRunRepository == nil {
		return nil, &Error{HTTPStatus: http.StatusServiceUnavailable, Code: api.ErrorCodeInternalError, Message: "run history is not available"}
	}
	retained, err := a.dagRunRepository.ListRetainedExecutions(ctx, ir.NewDAGRunRef(req.JobId, req.RunId))
	if err != nil {
		if errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
			return nil, &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound, Message: "job " + req.JobId + " has no run " + req.RunId}
		}
		return nil, err
	}
	run := ir.NewDAGRunRef(req.JobId, req.RunId)
	visible := make([]persis.RetainedExecution, 0, len(retained))
	for _, e := range retained {
		ok, err := a.txeRetainedVisible(ctx, run, e.Execution)
		if err != nil {
			return nil, err
		}
		if ok {
			visible = append(visible, e)
		}
	}
	out, err := txeConvert[[]api.TxeRetainedExecution](visible)
	if out == nil {
		out = []api.TxeRetainedExecution{}
	}
	for i := range out {
		if out[i].Files == nil {
			out[i].Files = []api.TxeRetainedFile{}
		}
	}
	return api.ListTxeRunExecutions200JSONResponse{Executions: out}, err
}

// txeRetainedVisible reports whether the caller can see the workspace a
// retained execution ran in, read from that execution's own saved status
// (as the native run endpoints do): a job that moved to another workspace
// does not expose the runs it made in the one it left.
func (a *API) txeRetainedVisible(ctx context.Context, run ir.DAGRunRef, executionRef string) (bool, error) {
	data, err := a.dagRunRepository.ReadRetainedExecutionFile(ctx, run, executionRef, "status.json")
	if err != nil {
		if errors.Is(err, persis.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	var status ir.DAGRunStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return false, nil
	}
	if err := a.txeRunStatusVisible(ctx, &status); err != nil {
		var apiErr *Error
		if errors.As(err, &apiErr) && apiErr.HTTPStatus == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (a *API) GetTxeRunExecutionFile(ctx context.Context, req api.GetTxeRunExecutionFileRequestObject) (api.GetTxeRunExecutionFileResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	if _, err := a.txeVisibleJob(ctx, s, req.JobId); err != nil {
		return nil, err
	}
	if a.dagRunRepository == nil {
		return nil, &Error{HTTPStatus: http.StatusServiceUnavailable, Code: api.ErrorCodeInternalError, Message: "run history is not available"}
	}
	run := ir.NewDAGRunRef(req.JobId, req.RunId)
	notFound := &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound, Message: "no such retained file"}
	switch ok, err := a.txeRetainedVisible(ctx, run, req.ExecutionRef); {
	case errors.Is(err, dagrun.ErrDAGRunIDNotFound):
		return nil, notFound
	case err != nil:
		return nil, err
	case !ok:
		return nil, notFound
	}
	data, err := a.dagRunRepository.ReadRetainedExecutionFile(ctx, run, req.ExecutionRef, req.Name)
	if err != nil {
		if errors.Is(err, persis.ErrNotFound) || errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
			return nil, &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound, Message: "no such retained file"}
		}
		return nil, err
	}
	return api.GetTxeRunExecutionFile200ApplicationoctetStreamResponse{Body: bytes.NewReader(data), ContentLength: int64(len(data))}, nil
}

func (a *API) ListTxeRunAbandonments(ctx context.Context, req api.ListTxeRunAbandonmentsRequestObject) (api.ListTxeRunAbandonmentsResponseObject, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	if _, err := a.txeVisibleJob(ctx, s, req.JobId); err != nil {
		return nil, err
	}
	if a.dagRunRepository == nil {
		return nil, &Error{HTTPStatus: http.StatusServiceUnavailable, Code: api.ErrorCodeInternalError, Message: "run history is not available"}
	}
	run := ir.NewDAGRunRef(req.JobId, req.RunId)
	notFound := &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound, Message: "job " + req.JobId + " has no run " + req.RunId}
	// The run's own saved status decides its workspace, as for the run's
	// other history.
	attempt, err := a.dagRunRepository.FindAttempt(ctx, run)
	if err != nil {
		if errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
			return nil, notFound
		}
		return nil, err
	}
	status, err := attempt.ReadStatus(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.txeRunStatusVisible(ctx, status); err != nil {
		var apiErr *Error
		if errors.As(err, &apiErr) && apiErr.HTTPStatus == http.StatusNotFound {
			return nil, notFound
		}
		return nil, err
	}
	results, err := a.dagRunRepository.ListAttemptAbandonmentsStrict(ctx, run, run)
	switch {
	case errors.Is(err, dagrun.ErrDAGRunIDNotFound):
		return nil, notFound
	case errors.Is(err, persis.ErrAttemptAbandonmentUnsupported):
		// Not an empty history: without the capability nothing is known
		// about abandoned preparations, so consumers must not infer one.
		return nil, &Error{HTTPStatus: http.StatusNotImplemented, Code: api.ErrorCodeInternalError,
			Message: "this hub's run store keeps no abandonment history; abandoned preparations are unknown",
			Details: map[string]any{"code": "abandonment_history_unsupported"}}
	case err != nil:
		return nil, err
	}
	out := make([]api.TxeAbandonment, 0, len(results))
	for _, r := range results {
		if r.Err != nil {
			// The reason stays in the hub's log: it can name storage paths
			// or another run's identifiers.
			logger.Warn(ctx, "Untrusted abandonment record", tag.RunID(req.RunId), tag.AttemptID(r.AttemptID), tag.Error(r.Err))
		}
		entry, err := txeAbandonment(r)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return api.ListTxeRunAbandonments200JSONResponse{Abandonments: out}, nil
}

// txeAbandonment is one strict-listing result in the API's shape: the trusted
// record, or the attempt and an error, never attributable.
func txeAbandonment(r persis.AttemptAbandonmentResult) (api.TxeAbandonment, error) {
	if r.Err != nil || r.Record == nil {
		msg := "the abandonment record cannot be trusted (unreadable, malformed, of another attempt or inconsistent)"
		return api.TxeAbandonment{AttemptId: r.AttemptID, Attributable: false, Error: &msg}, nil
	}
	rec := r.Record
	identity := func(e *persis.ExecutionIdentity) map[string]any {
		if e == nil {
			return nil
		}
		return map[string]any{"attempt_id": e.AttemptID, "queued_at": e.QueuedAt}
	}
	m := map[string]any{
		"attempt_id": r.AttemptID, "attributable": rec.Attributable(), "outcome": rec.Outcome,
		"abandoned_execution": identity(&rec.AbandonedExecution), "predecessor_absent": rec.PredecessorAbsent,
		"reason": rec.Reason, "detail": rec.Detail, "decided_at": rec.DecidedAt, "coordinator_id": rec.CoordinatorID,
		"evidence": map[string]any{"dispatch_task": rec.Evidence.DispatchTask, "lease": rec.Evidence.Lease,
			"active_run": rec.Evidence.ActiveRun, "worker": rec.Evidence.Worker, "observed_at": rec.Evidence.ObservedAt},
	}
	if rec.ExpectedExecution != nil {
		m["expected_execution"] = identity(rec.ExpectedExecution)
	}
	if c := rec.RequestCorrelation; c != nil {
		m["request_correlation"] = map[string]any{"id": c.ID, "action_id": c.ActionID, "action_attempt": c.ActionAttempt, "binding_digest": c.BindingDigest}
	}
	return txeConvert[api.TxeAbandonment](m)
}
