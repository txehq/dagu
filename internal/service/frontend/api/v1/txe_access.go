// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// Bindings, shares and machine enrolments (TXE-3415 contract 1, section 4).
//
// These routes change who may act for whom, so they hold their own rules in
// every mode: the platform administrator binds and revokes identities, a
// person acting for an owner shares that owner's work and enrols that
// owner's machines, and a machine applies for itself. No other caller,
// whatever its role, reaches any of it.

// txeAccessCaller resolves the request's caller for an access route.
func (a *API) txeAccessCaller(ctx context.Context) (txeauth.Caller, authz.Scope, error) {
	if a.txeAuth == nil {
		return txeauth.Caller{}, authz.Scope{}, errTxeRegistryUnavailable
	}
	caller := txeauth.Classify(ctx)
	scope, err := a.txeAuth.Scope(ctx, caller)
	if err != nil {
		return caller, authz.Scope{}, errTxeAuthzUnavailable
	}
	return caller, scope, nil
}

// txeRequirePlatformAdmin refuses anyone but the platform administrator.
func (a *API) txeRequirePlatformAdmin(ctx context.Context) (authz.Scope, error) {
	_, scope, err := a.txeAccessCaller(ctx)
	if err != nil {
		return authz.Scope{}, err
	}
	if scope.Kind() != authz.ScopePlatformAdmin {
		return authz.Scope{}, errTxeForbidden
	}
	return scope, nil
}

// txeAuthzError maps a refusal of the owner store to the API's errors. A
// store that cannot be read is unavailable, never an answer.
func txeAuthzError(err error) error {
	e, ok := errors.AsType[*authz.Error](err)
	if !ok {
		if _, isAPI := errors.AsType[*Error](err); isAPI {
			return err
		}
		return errTxeAuthzUnavailable
	}
	out := &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict, Message: e.Message,
		Details: map[string]any{"code": string(e.Code)}}
	switch e.Code {
	case authz.CodeInvalid:
		out.HTTPStatus, out.Code = http.StatusBadRequest, api.ErrorCodeBadRequest
	case authz.CodeForbidden:
		out.HTTPStatus, out.Code = http.StatusForbidden, api.ErrorCodeForbidden
	case authz.CodeNotFound:
		out.HTTPStatus, out.Code = http.StatusNotFound, api.ErrorCodeNotFound
	case authz.CodeConflict, authz.CodeStale:
	}
	return out
}

func txeAccessNotFound(what string) error {
	return &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound, Message: what + " not found",
		Details: map[string]any{"code": string(authz.CodeNotFound)}}
}

// RequestTxeBinding records that the person signed in asks to be bound.
func (a *API) RequestTxeBinding(ctx context.Context, _ api.RequestTxeBindingRequestObject) (api.RequestTxeBindingResponseObject, error) {
	caller, _, err := a.txeAccessCaller(ctx)
	if err != nil {
		return nil, err
	}
	if caller.Kind != txeauth.KindPerson && (caller.Kind != txeauth.KindPlatformAdmin || caller.Principal.Issuer == "") {
		// The request is the proof that the subject signed in themselves: a
		// person, or a platform administrator who signed in through the
		// identity provider, never a token.
		return nil, errTxeForbidden
	}
	request, err := a.txeAuth.Store().RequestBinding(ctx, caller.Principal, authz.Shown{Username: caller.Username})
	if err != nil {
		return nil, txeAuthzError(err)
	}
	out, err := txeConvert[api.TxeBindingRequest](request)
	return api.RequestTxeBinding201JSONResponse(out), err
}

// ListTxeBindingRequests lists the requests waiting for the administrator.
func (a *API) ListTxeBindingRequests(ctx context.Context, _ api.ListTxeBindingRequestsRequestObject) (api.ListTxeBindingRequestsResponseObject, error) {
	if _, err := a.txeRequirePlatformAdmin(ctx); err != nil {
		return nil, err
	}
	requests, err := a.txeAuth.Store().PendingRequests(ctx)
	if err != nil {
		return nil, txeAuthzError(err)
	}
	out, err := txeConvert[[]api.TxeBindingRequest](requests)
	if out == nil {
		out = []api.TxeBindingRequest{}
	}
	return api.ListTxeBindingRequests200JSONResponse{Requests: out}, err
}

// ApproveTxeBinding binds an identity to an existing owner.
func (a *API) ApproveTxeBinding(ctx context.Context, req api.ApproveTxeBindingRequestObject) (api.ApproveTxeBindingResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	admin, err := a.txeRequirePlatformAdmin(ctx)
	if err != nil {
		return nil, err
	}
	b, err := a.txeAuth.Store().ApproveBindingRequest(ctx, admin, authn.Identity{Issuer: body.Issuer, Subject: body.Subject}, req.OwnerId, body.RequestGeneration)
	if err != nil {
		return nil, txeAuthzError(err)
	}
	out, err := txeBindingOut(b)
	return api.ApproveTxeBinding200JSONResponse(out), err
}

// ListTxeOwnerBindings lists the identities bound to an owner.
func (a *API) ListTxeOwnerBindings(ctx context.Context, req api.ListTxeOwnerBindingsRequestObject) (api.ListTxeOwnerBindingsResponseObject, error) {
	_, scope, err := a.txeAccessCaller(ctx)
	if err != nil {
		return nil, err
	}
	ownPerson := authz.IsHuman(scope) && scope.OwnerID() == req.OwnerId
	if scope.Kind() != authz.ScopePlatformAdmin && !ownPerson {
		return nil, txeAccessNotFound("owner " + req.OwnerId)
	}
	bindings, err := a.txeAuth.Store().Bindings(ctx, req.OwnerId)
	if err != nil {
		return nil, txeAuthzError(err)
	}
	out := make([]api.TxeBinding, 0, len(bindings))
	for _, b := range bindings {
		converted, err := txeBindingOut(b)
		if err != nil {
			return nil, err
		}
		out = append(out, converted)
	}
	return api.ListTxeOwnerBindings200JSONResponse{Bindings: out}, nil
}

// RevokeTxeBinding ends a binding.
func (a *API) RevokeTxeBinding(ctx context.Context, req api.RevokeTxeBindingRequestObject) (api.RevokeTxeBindingResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	admin, err := a.txeRequirePlatformAdmin(ctx)
	if err != nil {
		return nil, err
	}
	bindings, err := a.txeAuth.Store().Bindings(ctx, req.OwnerId)
	if err != nil {
		return nil, txeAuthzError(err)
	}
	for _, b := range bindings {
		if authz.BindingID(b.Identity()) != req.BindingId {
			continue
		}
		revoked, err := a.txeAuth.Store().RevokeBinding(ctx, admin, b.Identity(), body.Reason)
		if err != nil {
			return nil, txeAuthzError(err)
		}
		out, err := txeBindingOut(revoked)
		return api.RevokeTxeBinding200JSONResponse(out), err
	}
	return nil, txeAccessNotFound("binding " + req.BindingId)
}

func txeBindingOut(b *authz.Binding) (api.TxeBinding, error) {
	out, err := txeConvert[api.TxeBinding](b)
	out.BindingId = authz.BindingID(b.Identity())
	return out, err
}

// ListTxeShares lists the shares the caller's owner granted and received.
func (a *API) ListTxeShares(ctx context.Context, _ api.ListTxeSharesRequestObject) (api.ListTxeSharesResponseObject, error) {
	_, scope, err := a.txeAccessCaller(ctx)
	if err != nil {
		return nil, err
	}
	out := api.ListTxeShares200JSONResponse{Granted: []api.TxeShare{}, Received: []api.TxeShare{}}
	if person, ok := scope.OwnerPerson(); ok {
		scope = person
	}
	owner := scope.OwnerID()
	if owner == "" || scope.Kind() != authz.ScopeOwner {
		return out, nil
	}
	granted, err := a.txeAuth.Store().Shares(ctx, owner)
	if err != nil {
		return nil, txeAuthzError(err)
	}
	received, err := a.txeAuth.Store().SharesReceived(ctx, owner)
	if err != nil {
		return nil, txeAuthzError(err)
	}
	for _, list := range []struct {
		in  []*authz.Share
		out *[]api.TxeShare
	}{{granted, &out.Granted}, {received, &out.Received}} {
		for _, sh := range list.in {
			converted, err := a.txeShareOut(ctx, sh)
			if err != nil {
				return nil, err
			}
			*list.out = append(*list.out, converted)
		}
	}
	return out, nil
}

// GrantTxeShare lets another owner use one job or project.
func (a *API) GrantTxeShare(ctx context.Context, req api.GrantTxeShareRequestObject) (api.GrantTxeShareResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	_, scope, err := a.txeAccessCaller(ctx)
	if err != nil {
		return nil, err
	}
	if scope.Kind() == authz.ScopeUnbound {
		return nil, errTxeUnbound
	}
	permissions := make([]authz.Permission, 0, len(body.Permissions))
	for _, p := range body.Permissions {
		permissions = append(permissions, authz.Permission(p))
	}
	share, err := a.txeAuth.Store().GrantShare(ctx, scope, authz.ShareGrant{
		Resource:       authz.ResourceRef{Kind: authz.ResourceKind(body.Resource.Kind), ID: body.Resource.Id},
		GranteeOwnerID: body.GranteeOwnerId,
		Permissions:    permissions,
	})
	if err != nil {
		return nil, txeAuthzError(err)
	}
	out, err := a.txeShareOut(ctx, share)
	return api.GrantTxeShare201JSONResponse(out), err
}

// RevokeTxeShare ends one of the caller's owner's shares.
func (a *API) RevokeTxeShare(ctx context.Context, req api.RevokeTxeShareRequestObject) (api.RevokeTxeShareResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	_, scope, err := a.txeAccessCaller(ctx)
	if err != nil {
		return nil, err
	}
	if scope.Kind() == authz.ScopeUnbound {
		return nil, errTxeUnbound
	}
	if scope.OwnerID() == "" {
		return nil, txeAccessNotFound("share " + req.ShareId)
	}
	shares, err := a.txeAuth.Store().Shares(ctx, scope.OwnerID())
	if err != nil {
		return nil, txeAuthzError(err)
	}
	for _, sh := range shares {
		if authz.ShareID(sh) != req.ShareId {
			continue
		}
		revoked, err := a.txeAuth.Store().RevokeShare(ctx, scope, sh.Resource, sh.GranteeOwnerID, body.Reason)
		if err != nil {
			return nil, txeAuthzError(err)
		}
		out, err := a.txeShareOut(ctx, revoked)
		return api.RevokeTxeShare200JSONResponse(out), err
	}
	return nil, txeAccessNotFound("share " + req.ShareId)
}

func (a *API) txeShareOut(ctx context.Context, sh *authz.Share) (api.TxeShare, error) {
	out, err := txeConvert[api.TxeShare](sh)
	if err != nil {
		return out, err
	}
	out.ShareId = authz.ShareID(sh)
	out.Grantee = api.TxeIdentityOwner{OwnerId: sh.GranteeOwnerID}
	if name, err := a.txeAuth.Registry().OwnerDisplayName(ctx, sh.GranteeOwnerID); err == nil {
		out.Grantee.DisplayName = name
	}
	return out, nil
}

// ApplyTxeEnrolment records the calling machine's application.
func (a *API) ApplyTxeEnrolment(ctx context.Context, req api.ApplyTxeEnrolmentRequestObject) (api.ApplyTxeEnrolmentResponseObject, error) {
	caller, _, err := a.txeAccessCaller(ctx)
	if err != nil {
		return nil, err
	}
	if caller.Kind != txeauth.KindToken || !caller.Principal.Class.Machine() {
		return nil, errTxeForbidden
	}
	application, err := a.txeAuth.Store().ApplyForEnrolment(ctx, caller.Principal, req.MachineId)
	if err != nil {
		return nil, txeAuthzError(err)
	}
	out, err := txeConvert[api.TxeEnrolmentApplication](application)
	return api.ApplyTxeEnrolment200JSONResponse(out), err
}

// txeOwnsMachine reports whether the scope acts for the machine's owner,
// as a person when person is set. A machine that does not exist, or is
// another owner's, is the same answer.
func (a *API) txeOwnsMachine(ctx context.Context, scope authz.Scope, machineID string, person bool) (bool, error) {
	if bound, ok := scope.OwnerPerson(); ok {
		scope = bound
	}
	if scope.Kind() != authz.ScopeOwner || (person && !authz.IsHuman(scope)) {
		return false, nil
	}
	owner, err := a.txeAuth.Registry().MachineOwner(ctx, machineID)
	if errors.Is(err, authz.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, errTxeAuthzUnavailable
	}
	return owner == scope.OwnerID(), nil
}

// ListTxeEnrolmentApplications lists a machine's applications for its
// owner's person.
func (a *API) ListTxeEnrolmentApplications(ctx context.Context, req api.ListTxeEnrolmentApplicationsRequestObject) (api.ListTxeEnrolmentApplicationsResponseObject, error) {
	_, scope, err := a.txeAccessCaller(ctx)
	if err != nil {
		return nil, err
	}
	switch owns, err := a.txeOwnsMachine(ctx, scope, req.MachineId, true); {
	case err != nil:
		return nil, err
	case !owns:
		return nil, txeAccessNotFound("machine " + req.MachineId)
	}
	applications, err := a.txeAuth.Store().EnrolmentApplications(ctx, req.MachineId)
	if err != nil {
		return nil, txeAuthzError(err)
	}
	out, err := txeConvert[[]api.TxeEnrolmentApplication](applications)
	if out == nil {
		out = []api.TxeEnrolmentApplication{}
	}
	return api.ListTxeEnrolmentApplications200JSONResponse{Applications: out}, err
}

// EnrolTxeMachine enrols a machine from its application.
func (a *API) EnrolTxeMachine(ctx context.Context, req api.EnrolTxeMachineRequestObject) (api.EnrolTxeMachineResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	_, scope, err := a.txeAccessCaller(ctx)
	if err != nil {
		return nil, err
	}
	if scope.Kind() == authz.ScopeUnbound {
		return nil, errTxeUnbound
	}
	enrolment, err := a.txeAuth.Store().EnrolFromApplication(ctx, scope, req.MachineId, authn.Class(body.Class), body.ClientId,
		authn.Identity{Issuer: body.Issuer, Subject: body.Subject})
	if err != nil {
		return nil, txeAuthzError(err)
	}
	out, err := txeEnrolmentOut(enrolment)
	return api.EnrolTxeMachine200JSONResponse(out), err
}

// ListTxeEnrolments lists a machine's enrolments for its owner or the
// platform administrator.
func (a *API) ListTxeEnrolments(ctx context.Context, req api.ListTxeEnrolmentsRequestObject) (api.ListTxeEnrolmentsResponseObject, error) {
	_, scope, err := a.txeAccessCaller(ctx)
	if err != nil {
		return nil, err
	}
	owner := scope.OwnerID()
	if scope.Kind() == authz.ScopePlatformAdmin {
		o, err := a.txeAuth.Registry().MachineOwner(ctx, req.MachineId)
		if errors.Is(err, authz.ErrNotFound) {
			return nil, txeAccessNotFound("machine " + req.MachineId)
		}
		if err != nil {
			// A registry that cannot be read is an outage, not a missing
			// machine.
			return nil, errTxeAuthzUnavailable
		}
		owner = o
	} else {
		switch owns, err := a.txeOwnsMachine(ctx, scope, req.MachineId, false); {
		case err != nil:
			return nil, err
		case !owns:
			return nil, txeAccessNotFound("machine " + req.MachineId)
		}
	}
	enrolments, err := a.txeAuth.Store().Enrolments(ctx, owner)
	if err != nil {
		return nil, txeAuthzError(err)
	}
	out := []api.TxeEnrolment{}
	for _, e := range enrolments {
		if e.MachineID != req.MachineId {
			continue
		}
		converted, err := txeEnrolmentOut(e)
		if err != nil {
			return nil, err
		}
		out = append(out, converted)
	}
	return api.ListTxeEnrolments200JSONResponse{Enrolments: out}, nil
}

// RevokeTxeEnrolment ends one class of a machine's enrolment.
func (a *API) RevokeTxeEnrolment(ctx context.Context, req api.RevokeTxeEnrolmentRequestObject) (api.RevokeTxeEnrolmentResponseObject, error) {
	body, err := txeBody(req.Body)
	if err != nil {
		return nil, err
	}
	_, scope, err := a.txeAccessCaller(ctx)
	if err != nil {
		return nil, err
	}
	if scope.Kind() == authz.ScopeUnbound {
		return nil, errTxeUnbound
	}
	enrolment, err := a.txeAuth.Store().RevokeEnrolment(ctx, scope, req.MachineId, authn.Class(req.Class), body.Reason)
	if err != nil {
		return nil, txeAuthzError(err)
	}
	out, err := txeEnrolmentOut(enrolment)
	return api.RevokeTxeEnrolment200JSONResponse(out), err
}

func txeEnrolmentOut(e *authz.Enrolment) (api.TxeEnrolment, error) {
	out, err := txeConvert[api.TxeEnrolment](e)
	out.ClientId = e.Key.ClientID
	return out, err
}

// txeAccessVia names how a view decision was allowed, other than as owner.
var txeAccessVia = map[authz.Reason]api.TxeJobAccessVia{
	authz.ReasonShare:         api.TxeJobAccessViaShare,
	authz.ReasonPlatformAdmin: api.TxeJobAccessViaPlatformAdmin,
}

// txeJobAccess says how the caller reaches a job, for the UI's label. It is
// nil for a caller the owner decisions do not govern in this mode.
func (a *API) txeJobAccess(ctx context.Context, jobID string) *api.TxeJobAccess {
	c, err := a.txeResolve(ctx)
	if err != nil || c.mode == authz.ModeOff || c.failed {
		return nil
	}
	res, err := a.txeAuth.Store().Job(ctx, jobID)
	if err != nil {
		return nil
	}
	view, err := a.txeAuth.Store().Decide(ctx, authz.ModeEnforce, c.scope, authz.PermissionView, res)
	if err != nil || !view.Allowed {
		return nil
	}
	out := &api.TxeJobAccess{Via: api.TxeJobAccessViaOwner, Permissions: []api.TxeAccessPermission{}}
	if via, ok := txeAccessVia[view.Reason]; ok {
		out.Via = via
	}
	if out.Via == api.TxeJobAccessViaShare {
		out.SharedBy = &api.TxeIdentityOwner{OwnerId: view.ShareOwnerID}
		if name, err := a.txeAuth.Registry().OwnerDisplayName(ctx, view.ShareOwnerID); err == nil {
			out.SharedBy.DisplayName = name
		}
	}
	for _, p := range []authz.Permission{authz.PermissionView, authz.PermissionAuthor, authz.PermissionExecute, authz.PermissionApprove, authz.PermissionAdminister} {
		d, err := a.txeAuth.Store().Decide(ctx, authz.ModeEnforce, c.scope, p, res)
		if err == nil && d.Allowed {
			out.Permissions = append(out.Permissions, api.TxeAccessPermission(p))
		}
	}
	return out
}
