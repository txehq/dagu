// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// Owner decisions on /txe (TXE-3415 contract 1, section 3).
//
// Every /txe handler asks who the caller acts for and whether that owner may
// do the thing asked. A caller that authenticated through the identity
// provider, a person or a token, is always decided as if enforcing, in every
// mode, and the hub's roles and workspaces do not apply to it: it can do
// what its owner can and nothing else. The platform administrator and the
// credentials the hub accepted before owners existed keep today's role and
// workspace checks, and are decided in txe.authz.mode on top of them: off
// does nothing, observe logs what enforce would deny, enforce denies.

var (
	errTxeUnbound = &Error{
		HTTPStatus: http.StatusForbidden,
		Code:       api.ErrorCodeForbidden,
		Message:    "this identity acts for no owner yet; ask to be bound",
		Details:    map[string]any{"code": "unbound"},
	}
	errTxeForbidden = &Error{
		HTTPStatus: http.StatusForbidden,
		Code:       api.ErrorCodeForbidden,
		Message:    "the owner of this record has not let you do this",
		Details:    map[string]any{"code": "forbidden"},
	}
	errTxeRuntimeProfile = &Error{
		HTTPStatus: http.StatusForbidden,
		Code:       api.ErrorCodeForbidden,
		Message:    "a runtime profile is the platform's to choose; start the run without one",
		Details:    map[string]any{"code": "runtime_profile_not_permitted"},
	}
)

// txeNeed says what a request needs beyond a permission.
type txeNeed struct {
	// machine requires a caller from the identity provider to be the
	// enrolled machine the job runs on.
	machine bool
	// classes, when set, are the only machine classes accepted.
	classes []authn.Class
}

// txeCall is the caller of one request, resolved once.
type txeCall struct {
	caller txeauth.Caller
	scope  authz.Scope
	mode   authz.Mode
	// failed is set when the owner store could not be read while resolving
	// the caller. The mode then decides what happens.
	failed bool
}

// ownerOnly reports whether the caller is held to its owner alone, without
// the hub's roles and workspaces.
func (c txeCall) ownerOnly() bool { return c.caller.New() }

// txeOwnerOnly reports whether the request's caller is held to its owner
// alone. Handlers skip the hub's role and workspace checks for such a caller:
// the owner decision is the whole of its authorization.
func (a *API) txeOwnerOnly(ctx context.Context) bool {
	return a.txeAuth != nil && txeauth.Classify(ctx).New()
}

// txeResolve says who the request is from and in which mode it is decided.
func (a *API) txeResolve(ctx context.Context) (txeCall, error) {
	c := txeCall{caller: txeauth.Classify(ctx), mode: authz.ModeOff}
	if a.txeAuth == nil {
		return c, nil
	}
	c.mode = a.txeAuth.Mode()
	if c.caller.New() {
		c.mode = authz.ModeEnforce
	}
	if c.mode == authz.ModeOff {
		return c, nil
	}
	scope, err := a.txeAuth.Scope(ctx, c.caller)
	if err != nil {
		if c.mode == authz.ModeEnforce {
			return c, errTxeAuthzUnavailable
		}
		c.failed = true
		a.txeLogDecision(ctx, c, "", authz.Resource{}, authz.Decision{Mode: c.mode, Evaluated: true, WouldDeny: true, Reason: authz.ReasonEvaluationFailed})
		return c, nil
	}
	c.scope = scope
	return c, nil
}

// decide asks the owner store whether the call may exercise permission on
// res. It logs every denial, would-be denial and administrator view.
func (a *API) txeDecide(ctx context.Context, c txeCall, permission authz.Permission, res authz.Resource) (bool, error) {
	if c.mode == authz.ModeOff {
		return true, nil
	}
	if c.failed {
		// Observing on a store that could not be read: allowed, already
		// logged.
		return true, nil
	}
	d, err := a.txeAuth.Store().Decide(ctx, c.mode, c.scope, permission, res)
	if !d.Allowed || d.WouldDeny || d.BreakGlass {
		a.txeLogDecision(ctx, c, permission, res, d)
	}
	if err != nil && c.mode == authz.ModeEnforce {
		return false, errTxeAuthzUnavailable
	}
	return d.Allowed, nil
}

// txeLogDecision records one decision that denied, would have denied, or let
// the platform administrator see an owner's data. It names the caller by
// class, owner and machine, never by token, email or name.
func (a *API) txeLogDecision(ctx context.Context, c txeCall, permission authz.Permission, res authz.Resource, d authz.Decision) {
	level := slog.LevelWarn
	msg := "txe.authz: denied"
	switch {
	case d.WouldDeny:
		level, msg = slog.LevelInfo, "txe.authz: would deny"
	case d.BreakGlass:
		level, msg = slog.LevelWarn, "txe.authz: platform administrator viewed an owner's data"
	}
	slog.Default().Log(ctx, level, msg,
		slog.String("mode", string(d.Mode)),
		slog.String("permission", string(permission)),
		slog.String("resource_kind", string(res.Kind())),
		slog.String("resource_id", res.ID()),
		slog.String("resource_owner", res.OwnerID()),
		slog.String("caller", string(c.caller.Kind)),
		slog.String("class", string(c.scope.Class())),
		slog.String("scope", string(c.scope.Kind())),
		slog.String("owner", c.scope.OwnerID()),
		slog.String("machine", c.scope.MachineID()),
		slog.String("reason", string(d.Reason)),
	)
}

// txeAuthorizeJob decides permission on a job for the request's caller.
//
// A job the caller may not view is not found, so no answer tells a caller
// what another owner holds. A caller from the identity provider that acts for
// nobody is refused as unbound before the job is looked at, so that answer is
// the same for every job id. A job the caller may view but not change in the
// way asked is forbidden.
func (a *API) txeAuthorizeJob(ctx context.Context, jobID string, permission authz.Permission, need txeNeed) error {
	c, err := a.txeResolve(ctx)
	if err != nil {
		return err
	}
	return a.txeAuthorizeJobFor(ctx, c, jobID, permission, need)
}

func (a *API) txeAuthorizeJobFor(ctx context.Context, c txeCall, jobID string, permission authz.Permission, need txeNeed) error {
	if c.mode == authz.ModeOff {
		return nil
	}
	if c.ownerOnly() && c.scope.Kind() == authz.ScopeUnbound {
		if permission == authz.PermissionView {
			return txeJobNotFound(jobID)
		}
		return errTxeUnbound
	}
	res, err := a.txeAuth.Store().Job(ctx, jobID)
	if err != nil {
		if authz.CodeOf(err) == authz.CodeNotFound || authz.CodeOf(err) == authz.CodeInvalid {
			return txeJobNotFound(jobID)
		}
		if c.mode == authz.ModeEnforce {
			return errTxeAuthzUnavailable
		}
		return nil
	}
	ok, err := a.txeDecide(ctx, c, permission, res)
	if err != nil {
		return err
	}
	if ok && c.ownerOnly() && need.machine && !txeMachineFits(c.scope, need) {
		ok = false
		a.txeLogDecision(ctx, c, permission, res, authz.Decision{Mode: c.mode, Evaluated: true, Reason: authz.ReasonClass})
	}
	if ok {
		return nil
	}
	if permission == authz.PermissionView {
		return txeJobNotFound(jobID)
	}
	// Refused: say forbidden only to a caller that may see the job.
	if seen, err := a.txeAuth.Store().Decide(ctx, authz.ModeEnforce, c.scope, authz.PermissionView, res); err == nil && seen.Allowed {
		return errTxeForbidden
	}
	return txeJobNotFound(jobID)
}

// txeMachineFits reports whether the scope is an enrolled machine of an
// accepted class. The owner store has already decided it is the job's own
// machine.
func txeMachineFits(scope authz.Scope, need txeNeed) bool {
	if scope.Kind() != authz.ScopeMachine {
		return false
	}
	return len(need.classes) == 0 || slices.Contains(need.classes, scope.Class())
}

// txeAuthorizeOwnData decides permission on everything the caller's own
// owner holds, for a request that creates under ownerID. A caller from the
// identity provider may name only its own owner; naming another is
// forbidden.
func (a *API) txeAuthorizeOwnData(ctx context.Context, ownerID string, permission authz.Permission) error {
	c, err := a.txeResolve(ctx)
	if err != nil {
		return err
	}
	if c.mode == authz.ModeOff {
		return nil
	}
	if c.ownerOnly() && c.scope.Kind() == authz.ScopeUnbound {
		return errTxeUnbound
	}
	res, err := authz.OwnData(c.scope)
	if err != nil || c.scope.OwnerID() != ownerID {
		// The caller acts for no owner (the administrator, a legacy
		// credential) or names another one.
		a.txeLogDecision(ctx, c, permission, res, authz.Decision{Mode: c.mode, Evaluated: true, WouldDeny: c.mode == authz.ModeObserve, Reason: authz.ReasonNotOwner})
		if c.mode == authz.ModeObserve {
			return nil
		}
		return errTxeForbidden
	}
	ok, err := a.txeDecide(ctx, c, permission, res)
	if err != nil {
		return err
	}
	if !ok {
		return errTxeForbidden
	}
	return nil
}

// txeAuthorizePlatform decides permission on the installation itself, which
// only the platform administrator administers.
func (a *API) txeAuthorizePlatform(ctx context.Context, permission authz.Permission) error {
	c, err := a.txeResolve(ctx)
	if err != nil {
		return err
	}
	ok, err := a.txeDecide(ctx, c, permission, authz.Platform())
	if err != nil {
		return err
	}
	if !ok {
		return errTxeForbidden
	}
	return nil
}

// txeOwnerVisible reports whether the caller may see an owner record: its
// own owner, or any owner for the platform administrator. A miss is the same
// as an absent owner.
func (a *API) txeOwnerVisible(ctx context.Context, ownerID string) (bool, error) {
	c, err := a.txeResolve(ctx)
	if err != nil {
		return false, err
	}
	if c.mode == authz.ModeOff || c.failed {
		return true, nil
	}
	allowed := c.scope.Kind() == authz.ScopePlatformAdmin || (c.scope.OwnerID() != "" && c.scope.OwnerID() == ownerID)
	if allowed {
		return true, nil
	}
	a.txeLogDecision(ctx, c, authz.PermissionView, authz.Resource{}, authz.Decision{Mode: c.mode, Evaluated: true, WouldDeny: c.mode == authz.ModeObserve, Reason: authz.ReasonNotOwner})
	return c.mode == authz.ModeObserve, nil
}

// txeAuthorizeRecord decides view on a project or a machine, by id, through
// the registry. A record the caller may not view is reported as not found.
func (a *API) txeAuthorizeRecord(ctx context.Context, lookup func(*authz.Store) (authz.Resource, error)) (bool, error) {
	return a.txeAuthorizeRecordWith(ctx, authz.PermissionView, lookup)
}

// txeAuthorizeRecordWith decides permission on a record found by lookup.
func (a *API) txeAuthorizeRecordWith(ctx context.Context, permission authz.Permission, lookup func(*authz.Store) (authz.Resource, error)) (bool, error) {
	c, err := a.txeResolve(ctx)
	if err != nil {
		return false, err
	}
	if c.mode == authz.ModeOff || c.failed {
		return true, nil
	}
	res, err := lookup(a.txeAuth.Store())
	if err != nil {
		if code := authz.CodeOf(err); code == authz.CodeNotFound || code == authz.CodeInvalid {
			return false, nil
		}
		if c.mode == authz.ModeEnforce {
			return false, errTxeAuthzUnavailable
		}
		return true, nil
	}
	return a.txeDecide(ctx, c, permission, res)
}

// txeTokenActor is the actor recorded for a provider token: an agent named
// by its client and subject, never a person, and for a machine, that
// machine whatever the request says.
func txeTokenActor(c txeauth.Caller, scope authz.Scope, in registry.Actor) registry.Actor {
	out := registry.Actor{Kind: in.Kind, ID: txeTokenActorID(c),
		Session: in.Session, MachineID: in.MachineID, Client: in.Client}
	switch out.Kind {
	case registry.ActorAgent, registry.ActorCLI, registry.ActorReviewer, registry.ActorReconciler:
	case registry.ActorHuman, registry.ActorSystem:
		out.Kind = registry.ActorAgent
	default:
		out.Kind = registry.ActorAgent
	}
	if m := scope.MachineID(); m != "" {
		out.MachineID = m
	}
	return out
}

var (
	// txeMachineNeed is a write only the job's own enrolled machine makes,
	// as a worker or a reviewer.
	txeMachineNeed = txeNeed{machine: true}
	// txeReviewerNeed is a write only the reviewer of the job's own machine
	// makes.
	txeReviewerNeed = txeNeed{machine: true, classes: []authn.Class{authn.ClassReviewer}}
)

// txeClaimNeed is who may take a claim of kind: a review claim only the
// reviewer of the job's machine, any other claim either of its machine's
// credentials.
func txeClaimNeed(kind registry.ClaimKind) txeNeed {
	if kind == registry.ClaimReview {
		return txeReviewerNeed
	}
	return txeMachineNeed
}

// txeRunStatusVisible applies the native visibility of a run's saved status
// to a caller the hub's workspaces govern. A caller held to its owner has
// been decided on the job already, and a run of a job is its job's.
func (a *API) txeRunStatusVisible(ctx context.Context, status *ir.DAGRunStatus) error {
	if a.txeOwnerOnly(ctx) {
		return nil
	}
	return a.requireDAGRunStatusVisible(ctx, status)
}

// txeRequireRunWorkspaceWrite is the workspace check on a run's saved
// workspace, for a caller the hub's workspaces govern.
func (a *API) txeRequireRunWorkspaceWrite(ctx context.Context, workspaceName string) error {
	if a.txeOwnerOnly(ctx) {
		return nil
	}
	return a.txeRequireWorkspaceWrite(ctx, workspaceName)
}

// txeResourceEventApplies says whether a resource event the caller reports
// may change job: its owner must let the caller change the job, as an
// author, or as the enrolled machine the job runs on. Other owners' jobs on
// the same target are left alone.
func (a *API) txeResourceEventApplies(ctx context.Context, s *registry.Store, job *registry.Job) bool {
	permission := authz.PermissionAuthor
	if c, err := a.txeResolve(ctx); err == nil && c.scope.Kind() == authz.ScopeMachine {
		permission = authz.PermissionExecute
	}
	if a.txeAuthorizeJob(ctx, job.JobID, permission, txeNeed{}) != nil {
		return false
	}
	if a.txeOwnerOnly(ctx) {
		return true
	}
	return a.txeCheckVersion(ctx, s, job, job.Version, a.txeRequireWorkspaceWrite) == nil
}

// txeCallerActorID is the actor id the registry records for the request's
// caller: a token's agent id, or the hub account.
func txeCallerActorID(ctx context.Context) string {
	c := txeauth.Classify(ctx)
	if c.Kind == txeauth.KindToken {
		return txeTokenActorID(c)
	}
	if user, ok := auth.UserFromContext(ctx); ok && user != nil {
		return user.Username
	}
	return ""
}

func txeTokenActorID(c txeauth.Caller) string {
	return "token:" + c.Principal.ClientID + ":" + c.Principal.Subject
}

// txeMachineDAGRunExists checks, for a caller held to its owner, that a run
// of a per-machine DAG exists. Whether the caller may use it is decided on
// the job the run serves, before this is asked. A run that does not exist,
// or of a DAG that is not a machine's, is not found.
func (a *API) txeMachineDAGRunExists(ctx context.Context, dagName, dagRunID string) error {
	notFound := &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound,
		Message: "dag-run ID " + dagRunID + " not found for DAG " + dagName}
	if _, ok := txeauth.MachineOfDAG(dagName); !ok || a.dagRunRepository == nil {
		return notFound
	}
	if _, err := a.dagRunRepository.FindAttempt(ctx, ir.NewDAGRunRef(dagName, dagRunID)); err != nil {
		if errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
			return notFound
		}
		return err
	}
	return nil
}

// txeJobRunStatus reads the status of a run of a job. A caller held to its
// owner has been decided on the job already, and a run of a job is its
// job's; the hub's workspaces apply to every other caller.
func (a *API) txeJobRunStatus(ctx context.Context, jobID, runID string) (*ir.DAGRunStatus, error) {
	if !a.txeOwnerOnly(ctx) {
		return a.authorizeHumanTaskMutation(ctx, jobID, runID)
	}
	notFound := &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound,
		Message: "dag-run ID " + runID + " not found for DAG " + jobID}
	if a.dagRunRepository == nil {
		return nil, notFound
	}
	attempt, err := a.dagRunRepository.FindAttempt(ctx, ir.NewDAGRunRef(jobID, runID))
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
	if status == nil {
		return nil, errors.New("failed to read DAG-run status: status data is nil")
	}
	return status, nil
}

// txeVisibleMachineRefusal keeps a refused machine creation from returning
// a machine the caller may not see: a collision with another owner's
// machine says only that the id is taken.
func (a *API) txeVisibleMachineRefusal(ctx context.Context, err error) error {
	re, ok := errors.AsType[*registry.Error](err)
	if !ok {
		return err
	}
	m, ok := re.Current.(*registry.Machine)
	if !ok {
		return err
	}
	seen, aerr := a.txeAuthorizeRecord(ctx, func(st *authz.Store) (authz.Resource, error) { return st.Machine(ctx, m.MachineID) })
	if aerr != nil {
		return aerr
	}
	if !seen {
		return &registry.Error{Code: re.Code, Message: "the machine id is already in use"}
	}
	return err
}

// txeIsStandingReporter reports whether the caller is the reporter of ev
// and still acts for someone. A reporter whose binding has since been
// revoked, or whose standing cannot be read, is not shown the event on
// that ground.
func (a *API) txeIsStandingReporter(ctx context.Context, ev *registry.ResourceEvent) bool {
	reporter := txeCallerActorID(ctx)
	if reporter == "" || reporter != ev.Reporter.ID {
		return false
	}
	c, err := a.txeResolve(ctx)
	if err != nil || c.failed {
		return false
	}
	return c.mode == authz.ModeOff || c.scope.Kind() != authz.ScopeUnbound
}
