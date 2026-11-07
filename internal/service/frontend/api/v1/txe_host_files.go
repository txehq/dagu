// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/spec"
)

// RequireHostFileRead decides a read of a file on the hub's own host that no
// other API decision covers, such as the MCP workbook target (TXE-5923). It
// is exactly the decision for writing DAGs, the same function so the two
// cannot drift: a caller who may write DAGs can already read the host through
// a step, and one who may not (a viewer, or anyone while a read-only Git sync
// disables DAG writes) cannot. A caller held to its owner, or under enforce
// anyone but the platform administrator, reads no host file (the rule for a
// resource that belongs to no owner).
func (a *API) RequireHostFileRead(ctx context.Context) error {
	if err := a.txePlatformResourceWrite(ctx); err != nil {
		return err
	}
	return a.requireDAGWrite(ctx)
}

// errTxeHostExecution refuses a capability that runs commands on the hub's
// host to a caller owner enforcement does not let.
var errTxeHostExecution = &Error{
	HTTPStatus: http.StatusForbidden,
	Code:       api.ErrorCodeForbidden,
	Message:    "under owner enforcement only the platform administrator runs commands on this server's host",
	Details:    map[string]any{"code": "host_execution_not_permitted"},
}

// txeHostExecution decides a capability that runs commands on the hub's own
// host outside any DAG run's decision: a command notification channel, which
// runs its text when saved and tested, and the terminal (TXE-5923). The
// hub's administrator role decides as before; on top of it, under owner
// enforcement only the platform administrator passes, and a caller held to
// its owner never does. An admin-role API key, or any other administrator the
// owner model does not take for the platform administrator, is refused.
func (a *API) txeHostExecution(ctx context.Context) error {
	if reserved, err := a.txePlatformReserved(ctx); err != nil || reserved {
		return errTxeHostExecution
	}
	return nil
}

// TxeHostExecutionRefused applies txeHostExecution in front of a handler
// that authenticates by itself, such as the terminal.
func (a *API) TxeHostExecutionRefused() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := a.txeHostExecution(r.Context()); err != nil {
				WriteErrorResponse(w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// txeCloudEgress decides what leaves the hub for Dagu Cloud (TXE-5923): the
// report level, which carries every owner's runs and failures to Dagu
// Console; the remote access level, which lets calls through Dagu Cloud reach
// every owner's workflows; and the Dagu Console link both travel on, which
// sends whatever level is in effect once it is opened or approved. Under owner enforcement it is the
// platform administrator's, as the hub's other whole-hub records are
// (txeHubHidden); a caller held to its owner never makes it. Every route that
// reads or changes them, and the two setters every change goes through
// (setReportLevel, chooseRemoteAccessLevel), apply it.
func (a *API) txeCloudEgress(ctx context.Context) error {
	if a.txeHubHidden(ctx) {
		return errTxeHubRecords
	}
	return nil
}

// SpecLoadContext marks ctx for a caller who may not read the hub's own files
// (RequireHostFileRead): every spec loaded under it leaves params.schema
// references unread (spec.WithoutSchemaReferences, TXE-5923). The API applies
// it to every request (scopeSpecLoading) and the MCP server to every tool
// call, so no load path, present or future, reads a host file or fetches a
// URL for such a caller.
func (a *API) SpecLoadContext(ctx context.Context) context.Context {
	if a.RequireHostFileRead(ctx) != nil {
		return spec.WithoutSchemaReferences(ctx)
	}
	return ctx
}

// scopeSpecLoading applies SpecLoadContext to every API operation.
func (a *API) scopeSpecLoading(f api.StrictHandlerFunc, _ string) api.StrictHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		return f(a.SpecLoadContext(ctx), w, r, request)
	}
}
