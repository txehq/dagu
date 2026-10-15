// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path"
	"slices"
	"strings"

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

// txeTokenRoutePrefix is where an identity provider access token may call:
// every /txe route answers for the caller's owner and no other (TXE-3415
// contract 1, section 3). Every other route refuses such a token before its
// handler runs.
const txeTokenRoutePrefix = "txe"

// txeTokenUse is what GET /txe/auth/cli tells the command line about where
// its token is accepted: every route that answers by owner (/txe and the
// native DAG, run and queue routes, txeTokenRoute). Any other route refuses
// it with 403 before its handler runs.
const txeTokenUse = "all"

// txeCLIScopes are the scopes the command line asks the provider for.
var txeCLIScopes = []string{"openid"}

// GetTxeCliAuth tells the command line how to sign in. It is public: the
// answer is the server's configured issuer and cli client, nothing secret.
func (a *API) GetTxeCliAuth(_ context.Context, _ api.GetTxeCliAuthRequestObject) (api.GetTxeCliAuthResponseObject, error) {
	if a.txeAuth == nil || !a.txeAuth.AcceptsTokens() || a.config == nil {
		return nil, txeCLIAuthNotFound
	}
	client := a.config.TXE.Authn.AdvertisedCLIClient()
	if client == "" {
		return nil, txeCLIAuthNotFound
	}
	return api.GetTxeCliAuth200JSONResponse{
		Contract: txeAuthContract,
		Issuer:   a.config.TXE.Authn.Issuer,
		ClientId: client,
		Scopes:   slices.Clone(txeCLIScopes),
		Use:      txeTokenUse,
	}, nil
}

var txeCLIAuthNotFound = &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound,
	Message: "this server accepts no command-line sign-in"}

// txeTokenRoute says whether a request may be made with a provider token. A
// request for a remote node is never admitted: it would be forwarded with a
// credential the node knows nothing of.
func txeTokenRoute(mountedAPIPath string) func(r *http.Request) bool {
	root := pathutil.NormalizePath(path.Join(mountedAPIPath, txeTokenRoutePrefix))
	return func(r *http.Request) bool {
		if node := r.URL.Query().Get("remoteNode"); node != "" && node != "local" {
			return false
		}
		// Dot segments are resolved first, so a path cannot name /txe and
		// reach another route.
		p := pathutil.NormalizePath(path.Clean("/" + r.URL.Path))
		return p == root || strings.HasPrefix(p, root+"/") || txeNativeRoute(pathutil.NormalizePath(mountedAPIPath), p)
	}
}

// txePersonGate admits a person signed in through the identity provider only
// to /txe, where every route is decided by the person's owner, and to the
// read of its own session. A person never gets the Dagu role or workspace
// access its account was provisioned with (TXE-3415 contract 1, section 1),
// so every other route refuses it until that route is scoped by owner.
func (a *API) txePersonGate(mountedAPIPath string) func(http.Handler) http.Handler {
	onTxe := txeTokenRoute(mountedAPIPath)
	me := pathutil.NormalizePath(path.Join(mountedAPIPath, "auth/me"))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.txeAuth == nil || txeauth.Classify(r.Context()).Kind != txeauth.KindPerson {
				next.ServeHTTP(w, r)
				return
			}
			p := pathutil.NormalizePath(path.Clean("/" + r.URL.Path))
			if onTxe(r) || (r.Method == http.MethodGet && p == me) {
				next.ServeHTTP(w, r)
				return
			}
			writeTxePersonRefused(w)
		})
	}
}

// writeTxePersonRefused answers a person on a route that is not scoped by
// owner yet.
func writeTxePersonRefused(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": string(api.ErrorCodeForbidden),
		"message": "this route is not open to identity provider sign-ins yet", "details": map[string]string{"code": "forbidden"}})
}

// TxeOwnersEnabled reports whether owner authorization is on, so that a
// person signed in through the identity provider is told apart and held to
// its owner.
func (a *API) TxeOwnersEnabled() bool { return a != nil && a.txeAuth != nil }

// TxePersonRefused is the middleware for the server's other surfaces
// (streams, MCP, terminal): it refuses a person signed in through the
// identity provider, who may use none of them yet.
func (a *API) TxePersonRefused() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.txeAuth != nil && txeauth.Classify(r.Context()).Kind == txeauth.KindPerson {
				writeTxePersonRefused(w)
				return
			}
			next.ServeHTTP(w, r)
		})
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
