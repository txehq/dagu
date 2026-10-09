// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package runcontrol applies TXE job lifecycle changes to Dagu: it lists a
// job DAG's active runs, stops them, and sets Dagu's own suspend flag.
package runcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
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

// ActiveRuns lists the DAG's runs that are not finished: not started,
// queued, running and waiting. A waiting run is reported as running: it has
// started and the run policy applies.
func (c *Control) ActiveRuns(ctx context.Context, dagName string) ([]registry.RunRef, error) {
	statuses, err := c.Runs.ListStatuses(ctx, persis.DAGRunListOptions{
		ExactName:  dagName,
		Statuses:   []ir.Status{ir.NotStarted, ir.Queued, ir.Running, ir.Waiting},
		AllHistory: true,
		Unbounded:  true,
	})
	if err != nil {
		return nil, err
	}
	out := make([]registry.RunRef, 0, len(statuses))
	for _, st := range statuses {
		out = append(out, registry.RunRef{RunID: st.DAGRunID, Running: st.Status == ir.Running || st.Status == ir.Waiting})
	}
	return out, nil
}

// RunFinished reports whether a run has reached a terminal status.
func (c *Control) RunFinished(ctx context.Context, dagName string, run registry.RunRef) (bool, error) {
	attempt, err := c.findAttempt(ctx, dagName, run)
	if errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
		return false, registry.ErrRunNotFound
	}
	if err != nil {
		return false, err
	}
	status, err := attempt.ReadStatus(ctx)
	if err != nil {
		return false, err
	}
	return status != nil && !status.Status.IsActive() && status.Status != ir.NotStarted, nil
}

// LatestAttempt returns the run's latest attempt: its ID, the digest of its
// saved DAG, and whether it finished and succeeded.
func (c *Control) LatestAttempt(ctx context.Context, dagName, runID string) (registry.RunAttempt, error) {
	attempt, err := c.Runs.FindAttempt(ctx, ir.NewDAGRunRef(dagName, runID))
	if errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
		return registry.RunAttempt{}, registry.ErrRunNotFound
	}
	if err != nil {
		return registry.RunAttempt{}, err
	}
	status, err := attempt.ReadStatus(ctx)
	if err != nil {
		return registry.RunAttempt{}, err
	}
	dag, err := attempt.ReadDAG(ctx)
	if err != nil {
		return registry.RunAttempt{}, err
	}
	if len(dag.YamlData) == 0 {
		return registry.RunAttempt{}, fmt.Errorf("run %s has no saved DAG", runID)
	}
	id := status.AttemptID
	if id == "" {
		id = attempt.ID()
	}
	snapshot, err := json.Marshal(status)
	if err != nil {
		return registry.RunAttempt{}, err
	}
	return registry.RunAttempt{
		AttemptID:  id,
		QueuedAt:   status.QueuedAt,
		Snapshot:   snapshot,
		SpecSHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(dag.YamlData)),
		Status:     status.Status.String(),
		Running:    status.Status == ir.Running,
		ArchiveDir: status.ArchiveDir,
		Finished:   !status.Status.IsActive() && status.Status != ir.NotStarted,
		Succeeded:  status.Status.IsSuccess(),
	}, nil
}

func (c *Control) findAttempt(ctx context.Context, dagName string, run registry.RunRef) (dagrun.Attempt, error) {
	if run.RootRunID != "" {
		return c.Runs.FindSubAttempt(ctx, ir.NewDAGRunRef(run.RootName, run.RootRunID), run.RunID)
	}
	return c.Runs.FindAttempt(ctx, ir.NewDAGRunRef(dagName, run.RunID))
}

// StopRun stops a run the way the API's terminate operation does: through
// the coordinator for a distributed run, locally otherwise. A child run is
// found under its root run, and the root is passed with the cancellation.
func (c *Control) StopRun(ctx context.Context, dagName string, run registry.RunRef) error {
	var root *ir.DAGRunRef
	if run.RootRunID != "" {
		ref := ir.NewDAGRunRef(run.RootName, run.RootRunID)
		root = &ref
	}
	attempt, err := c.findAttempt(ctx, dagName, run)
	if err != nil {
		return err
	}
	dag, err := attempt.ReadDAG(ctx)
	if err != nil {
		return fmt.Errorf("read DAG of run %s: %w", run.RunID, err)
	}
	if dispatch.ShouldDispatchToCoordinator(dag, c.Coordinator != nil, c.ExecMode) {
		return c.Coordinator.RequestCancel(ctx, dagName, run.RunID, root)
	}
	if c.Manager == nil {
		return fmt.Errorf("no local run manager to stop run %s", run.RunID)
	}
	return c.Manager.Stop(ctx, dag, run.RunID)
}

// IsSuspended reports Dagu's suspend flag for the DAG.
func (c *Control) IsSuspended(ctx context.Context, dagName string) (bool, error) {
	return c.DAGs.IsSuspended(ctx, dagName)
}

// SetSuspended sets Dagu's suspend flag for the DAG.
func (c *Control) SetSuspended(ctx context.Context, dagName string, suspended bool) error {
	return c.DAGs.SetSuspended(ctx, dagName, suspended)
}
