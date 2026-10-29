// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/cmn/stringutil"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// RunAdmitter is the TXE job registry's run guard.
type RunAdmitter interface {
	AdmitClaim(ctx context.Context, dagName, specSHA256 string, run registry.RunRef) (registry.Admission, error)
	RecordDroppedRun(ctx context.Context, jobID, runID string, adm registry.Admission) error
}

// refuseUnadmittedClaim re-checks a registered job's lifecycle when a worker
// claims one of its runs. A task can wait for an offline worker long after
// the queue dispatched it, and a retirement in that window must still stop
// it. The admission is recorded on the job in the same commit that checks
// it, so a later retirement knows the run. A refused claim is removed and its
// queued attempt finalized as aborted, so it is neither executed nor offered
// again; only the task's own execution is finalized (see abortQueuedAttempt).
// executionMarker is the task's marker as the claim acknowledgment resolves
// it. Child runs are admitted on their own identity: a registered job is
// never exempt because it was called as a subworkflow. It reports whether the
// claim was refused and why.
func (h *Handler) refuseUnadmittedClaim(ctx context.Context, claimToken string, task *dispatch.DispatchTask, executionMarker string) (bool, string, error) {
	if h.runAdmitter == nil || task == nil {
		return false, "", nil
	}
	name := task.DefinitionID
	if name == "" {
		name = task.Target
	}
	if !registry.IsJobDAG(name) {
		return false, "", nil
	}
	spec := ""
	if task.Definition != "" {
		spec = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(task.Definition)))
	}
	run := registry.RunRef{RunID: task.DAGRunID}
	if task.RootDAGRunID != "" && task.RootDAGRunID != task.DAGRunID {
		run.RootName, run.RootRunID = task.RootDAGRunName, task.RootDAGRunID
	}
	adm, err := h.runAdmitter.AdmitClaim(ctx, name, spec, run)
	if err != nil {
		return false, "", fmt.Errorf("check TXE job admission: %w", err)
	}
	if adm.Admit {
		return false, "", nil
	}
	reason := fmt.Sprintf("txe: job %s %s: %s", adm.JobID, adm.Code, adm.Reason)
	storeCtx := context.WithoutCancel(ctx)
	if err := h.abortQueuedAttempt(storeCtx, task, executionMarker, reason); err != nil {
		return false, "", err
	}
	if err := h.dispatchTaskStore.DeleteClaim(storeCtx, claimToken); err != nil {
		return false, "", fmt.Errorf("remove refused claim: %w", err)
	}
	if err := h.runAdmitter.RecordDroppedRun(storeCtx, adm.JobID, task.DAGRunID, adm); err != nil {
		logger.Warn(ctx, "Failed to record refused claim on TXE job", tag.Error(err))
	}
	return true, reason, nil
}

// abortQueuedAttempt finalizes the refused task's own execution as aborted.
// It holds the root run's write lock, as recording a claim does, so it and
// the abandonment fence see one state. An abandoned execution is left alone:
// its stale claim is only removed. So is any other execution the run's
// latest visible attempt now holds: another attempt, or the same attempt
// queued again under a new queued-at marker (the rule leases follow). Before
// aborting, it closes the handle this coordinator cached for the execution.
func (h *Handler) abortQueuedAttempt(ctx context.Context, task *dispatch.DispatchTask, executionMarker, reason string) error {
	if h.dagRunRepository == nil {
		return nil
	}
	run := ir.NewDAGRunRef(task.Target, task.DAGRunID)
	root := ir.DAGRunRef{Name: task.RootDAGRunName, ID: task.RootDAGRunID}
	if root.Zero() {
		root = run
	}
	defer h.attemptWriteLocks.lock(root)()
	held := h.runLocks.lock(task.DAGRunID)
	defer h.runLocks.unlock(task.DAGRunID, held)
	if err := h.refuseAbandonedExecution(ctx, run, root, task.AttemptID, executionMarker); err != nil {
		if errors.Is(err, errAttemptAbandoned) {
			return nil
		}
		return err
	}
	var attempt dagrun.Attempt
	var err error
	if task.RootDAGRunID != "" && task.RootDAGRunID != task.DAGRunID {
		attempt, err = h.dagRunRepository.FindSubAttempt(ctx, root, task.DAGRunID)
	} else {
		attempt, err = h.dagRunRepository.FindAttempt(ctx, run)
	}
	if err != nil {
		return fmt.Errorf("find attempt of refused run: %w", err)
	}
	if attempt.ID() != task.AttemptID {
		return nil
	}
	status, err := attempt.ReadStatus(ctx)
	if err != nil {
		return fmt.Errorf("read attempt of refused run: %w", err)
	}
	if status == nil || status.AttemptID != task.AttemptID || (status.Status != ir.Queued && status.Status != ir.NotStarted) {
		return nil
	}
	if status.Status == ir.Queued && status.QueuedAt != executionMarker {
		return nil
	}
	// A handle this coordinator cached for the execution is closed first, as
	// an abandonment does, so nothing is appended through it after the abort.
	// A later status report opens the run again.
	h.closeCachedAttemptForRun(ctx, ctx, task.DAGRunID, task.AttemptID)
	// The store re-checks the attempt, its status and the marker in the same
	// write, so an execution that changed after the read is never aborted.
	aborted, swapped, err := h.dagRunRepository.CompareAndSwapLatestAttemptStatus(ctx, run, task.AttemptID, status.Status,
		func(current *ir.DAGRunStatus) error {
			if current.Status == ir.Queued && current.QueuedAt != executionMarker {
				return errExecutionReplaced
			}
			current.Status = ir.Aborted
			current.FinishedAt = stringutil.FormatTime(time.Now().UTC())
			current.Error = reason
			return nil
		}, persis.DAGRunCompareAndSwapOptions{RootDAGRun: root})
	if errors.Is(err, errExecutionReplaced) || (err == nil && !swapped) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("abort refused run: %w", err)
	}
	h.finalizeAdmissionForStatus(ctx, aborted, task.AttemptID)
	return nil
}
