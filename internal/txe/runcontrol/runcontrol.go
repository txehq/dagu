// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package runcontrol applies TXE job lifecycle changes to Dagu: it lists a
// job DAG's active runs, stops them, and sets Dagu's own suspend flag.
package runcontrol

import (
	"context"
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// Canceller asks the coordinator to cancel a distributed run.
type Canceller interface {
	RequestCancel(ctx context.Context, dagName, dagRunID string, rootRef *ir.DAGRunRef) error
}

// Control implements registry.RunControl over Dagu's repositories.
type Control struct {
	DAGs        *persis.DAGRepository
	Runs        *persis.DAGRunRepository
	Manager     *runtime.Manager
	Coordinator Canceller // nil when no coordinator is configured
	ExecMode    config.ExecutionMode
}

var _ registry.RunControl = (*Control)(nil)

// ActiveRuns lists the DAG's queued and running runs.
func (c *Control) ActiveRuns(ctx context.Context, dagName string) ([]registry.RunRef, error) {
	statuses, err := c.Runs.ListStatuses(ctx, persis.DAGRunListOptions{
		ExactName:  dagName,
		Statuses:   []ir.Status{ir.Queued, ir.Running},
		AllHistory: true,
		Unbounded:  true,
	})
	if err != nil {
		return nil, err
	}
	out := make([]registry.RunRef, 0, len(statuses))
	for _, st := range statuses {
		out = append(out, registry.RunRef{RunID: st.DAGRunID, Running: st.Status == ir.Running})
	}
	return out, nil
}

// StopRun stops a running run the way the API's terminate operation does:
// through the coordinator for a distributed run, locally otherwise.
func (c *Control) StopRun(ctx context.Context, dagName, runID string) error {
	attempt, err := c.Runs.FindAttempt(ctx, ir.NewDAGRunRef(dagName, runID))
	if err != nil {
		return err
	}
	dag, err := attempt.ReadDAG(ctx)
	if err != nil {
		return fmt.Errorf("read DAG of run %s: %w", runID, err)
	}
	if dispatch.ShouldDispatchToCoordinator(dag, c.Coordinator != nil, c.ExecMode) {
		return c.Coordinator.RequestCancel(ctx, dagName, runID, nil)
	}
	if c.Manager == nil {
		return fmt.Errorf("no local run manager to stop run %s", runID)
	}
	return c.Manager.Stop(ctx, dag, runID)
}

// SetSuspended sets Dagu's suspend flag for the DAG.
func (c *Control) SetSuspended(ctx context.Context, dagName string, suspended bool) error {
	return c.DAGs.SetSuspended(ctx, dagName, suspended)
}
