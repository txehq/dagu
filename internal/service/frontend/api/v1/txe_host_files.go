// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import "context"

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
