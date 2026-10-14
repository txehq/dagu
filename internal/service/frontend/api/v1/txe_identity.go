// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"path"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/service/frontend/api/pathutil"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// txeAuthContract is the version of the principal and API contract the
// server implements (TXE-3415).
const txeAuthContract = 1

// WithTxeAuth enables TXE owner authorization and, when configured, identity
// provider access tokens.
func WithTxeAuth(svc *txeauth.Service) APIOption {
	return func(a *API) {
		a.txeAuth = svc
	}
}

var errTxeAuthzUnavailable = &Error{
	HTTPStatus: http.StatusServiceUnavailable,
	Code:       api.ErrorCodeInternalError,
	Message:    "the owner store could not be read; try again shortly",
	Details:    map[string]any{"code": "authz_unavailable"},
}

// txeTokenRoutes are the routes an identity provider access token may call,
// as a method and a path under the API base. Only a route that answers for
// the caller's own owner, and no other, may be listed: every other route
// refuses such a token before its handler runs.
var txeTokenRoutes = []struct{ method, path string }{
	{http.MethodGet, "txe/identity"},
}

// txeTokenRoute says whether a request may be made with a provider token. A
// request for a remote node is never admitted: it would be forwarded with a
// credential the node knows nothing of.
func txeTokenRoute(mountedAPIPath string) func(r *http.Request) bool {
	return func(r *http.Request) bool {
		if node := r.URL.Query().Get("remoteNode"); node != "" && node != "local" {
			return false
		}
		p := pathutil.NormalizePath(r.URL.Path)
		for _, route := range txeTokenRoutes {
			if r.Method == route.method && p == pathutil.NormalizePath(path.Join(mountedAPIPath, route.path)) {
				return true
			}
		}
		return false
	}
}

// GetTxeIdentity says who the hub takes the caller to be.
func (a *API) GetTxeIdentity(ctx context.Context, _ api.GetTxeIdentityRequestObject) (api.GetTxeIdentityResponseObject, error) {
	if a.txeAuth == nil {
		return nil, errTxeRegistryUnavailable
	}
	caller := txeauth.Classify(ctx)
	scope, err := a.txeAuth.Scope(ctx, caller)
	if err != nil {
		return nil, errTxeAuthzUnavailable
	}

	out := api.TxeIdentity{
		Contract:      txeAuthContract,
		AuthzMode:     api.TxeIdentityAuthzMode(a.txeAuth.Mode()),
		Principal:     txeIdentityPrincipal(caller),
		State:         api.TxeIdentityStateUnbound,
		Owners:        []api.TxeIdentityOwner{},
		Scope:         api.TxeIdentityScope{Kind: api.TxeIdentityScopeKind(scope.Kind())},
		PlatformAdmin: caller.Kind == txeauth.KindPlatformAdmin,
		IsPerson:      authz.IsHuman(scope),
	}
	if caller.Kind == txeauth.KindLegacy || caller.Kind == txeauth.KindNone {
		out.Scope.UnboundReason = ptrOf("legacy")
	} else if reason := scope.UnboundReason(); reason != "" {
		out.Scope.UnboundReason = ptrOf(string(reason))
	}
	if machine := scope.MachineID(); machine != "" {
		out.Scope.MachineId = ptrOf(machine)
	}
	if owner := scope.OwnerID(); owner != "" {
		name, err := a.txeAuth.Registry().OwnerDisplayName(ctx, owner)
		if err != nil {
			return nil, errTxeAuthzUnavailable
		}
		out.State = api.TxeIdentityStateBound
		out.Owners = append(out.Owners, api.TxeIdentityOwner{OwnerId: owner, DisplayName: name})
	}

	// A person who acts for nobody may be waiting for approval.
	if caller.Kind == txeauth.KindPerson && scope.Kind() == authz.ScopeUnbound {
		req, err := a.txeAuth.Store().PendingRequest(ctx, caller.Principal.Identity)
		if err != nil {
			return nil, errTxeAuthzUnavailable
		}
		if req != nil {
			out.State = api.TxeIdentityStatePending
			out.Request = &api.TxeIdentityRequest{
				State:       api.TxeIdentityRequestState(req.State),
				RequestedAt: req.RequestedAt,
				Generation:  req.Generation,
			}
		}
	}
	return api.GetTxeIdentity200JSONResponse(out), nil
}

func txeIdentityPrincipal(c txeauth.Caller) api.TxeIdentityPrincipal {
	out := api.TxeIdentityPrincipal{Class: api.TxeIdentityPrincipalClassLegacy}
	if c.Username != "" {
		out.Shown.Username = ptrOf(c.Username)
	}
	switch c.Kind {
	case txeauth.KindPlatformAdmin:
		out.Class = api.TxeIdentityPrincipalClassPlatformAdmin
	case txeauth.KindPerson, txeauth.KindToken:
		out.Class = api.TxeIdentityPrincipalClass(c.Principal.Class)
		out.Issuer = ptrOf(c.Principal.Issuer)
		out.Subject = ptrOf(c.Principal.Subject)
		if c.Principal.Class != authn.ClassPerson && c.Principal.ClientID != "" {
			out.ClientId = ptrOf(c.Principal.ClientID)
		}
	case txeauth.KindLegacy, txeauth.KindNone:
	}
	return out
}
