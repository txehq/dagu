// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/remotenode"
)

// errRemoteNodeRefused answers a remote-node request the local decision did
// not allow. It names no node and no address.
var errRemoteNodeRefused = &Error{
	HTTPStatus: http.StatusForbidden,
	Code:       api.ErrorCodeForbidden,
	Message:    "a request for a remote node needs a local administrator",
	Details:    map[string]any{"code": "remote_node_not_permitted"},
}

// authorizeRemoteNode is the one local decision before a remote node's
// stored credential is used (TXE-5923). That credential acts on the node with
// its own authority, whatever the local caller may do, so it is used only for
// a local administrator. Under owner enforcement only the platform
// administrator passes, and a caller held to its owner never does. It returns
// the context marked as allowed (remotenode.WithUseAuthorized), without which
// RemoteNode.ApplyAuth sends no credential.
func (a *API) authorizeRemoteNode(ctx context.Context) (context.Context, error) {
	// The platform rule decides even where the hub's roles do not apply
	// (rolesApply), which requireAdmin leaves to nobody.
	if reserved, err := a.txePlatformReserved(ctx); err != nil || reserved {
		return ctx, errRemoteNodeRefused
	}
	if err := a.requireAdmin(ctx); err != nil {
		return ctx, errRemoteNodeRefused
	}
	return remotenode.WithUseAuthorized(ctx), nil
}

// RemoteNodeAuthorization applies authorizeRemoteNode to every request that
// names a remote node (remotenode.Selected), before any proxy runs. It is
// mounted ahead of the API's proxy and the event stream's, so every route
// family, present and future, is decided the same way; a request for this
// server passes untouched.
func (a *API) RemoteNodeAuthorization() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, remote, err := remotenode.Selected(r)
			if err != nil {
				WriteErrorResponse(w, &Error{HTTPStatus: http.StatusBadRequest, Code: api.ErrorCodeBadRequest, Message: err.Error()})
				return
			}
			if !remote {
				next.ServeHTTP(w, r)
				return
			}
			ctx, err := a.authorizeRemoteNode(r.Context())
			if err != nil {
				WriteErrorResponse(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
