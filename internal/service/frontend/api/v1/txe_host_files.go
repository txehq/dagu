// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
)

// RequireHostFileRead decides a read of a file on the hub's own host that no
// other API decision covers, such as the MCP workbook target (TXE-5923). It
// needs what writing DAGs needs, because a caller who may write DAGs can
// already read the host through a step. A caller held to its owner, or under
// enforce anyone but the platform administrator, reads no host file (the rule
// for a resource that belongs to no owner).
func (a *API) RequireHostFileRead(ctx context.Context) error {
	if err := a.txePlatformResourceWrite(ctx); err != nil {
		return err
	}
	if !a.config.Server.Permissions[config.PermissionWriteDAGs] {
		return errPermissionDenied
	}
	if a.rolesApply(ctx) {
		user, ok := auth.UserFromContext(ctx)
		if !ok {
			return errAuthRequired
		}
		if !user.Role.CanWrite() {
			return errInsufficientPermissions
		}
	}
	return nil
}
