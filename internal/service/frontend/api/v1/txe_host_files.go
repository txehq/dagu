// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"

	"github.com/dagucloud/dagu/v2/api/v1"
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
	if err := a.txePlatformResourceWrite(ctx); err != nil {
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
