// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/runcontrol"
)

// newJobRegistryGuard opens the TXE job registry for the scheduler, with the
// run control that lets lifecycle changes it makes (expiry) suspend DAGs and
// stop runs.
func newJobRegistryGuard(ctx *Context, manager runtime.Manager, cc coordinator.Client) (*registry.Store, error) {
	rc := &runcontrol.Control{
		DAGs:     ctx.Persistence.DAGRepository,
		Runs:     ctx.Persistence.DAGRunRepository,
		Manager:  &manager,
		ExecMode: ctx.Config.DefaultExecMode,
	}
	if cc != nil {
		rc.Coordinator = cc
	}
	return registry.NewFileStore(ctx.Config.Paths.DataDir, registry.WithRunControl(rc))
}
