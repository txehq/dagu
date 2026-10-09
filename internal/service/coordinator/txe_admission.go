// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/cmn/stringutil"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// RunAdmitter is the TXE job registry's run guard.
type RunAdmitter interface {
	AdmitClaim(ctx context.Context, dagName, specSHA256, runID string) (registry.Admission, error)
	RecordDroppedRun(ctx context.Context, jobID, runID string, adm registry.Admission) error
}

// refuseUnadmittedClaim re-checks a registered job's lifecycle when a worker
// claims one of its runs. A task can wait for an offline worker long after
// the queue dispatched it, and a retirement in that window must still stop
// it. The admission is recorded on the job in the same commit that checks
// it, so a later retirement knows the run. A refused claim is removed and its
// queued attempt finalized as aborted, so it is neither executed nor offered
// again. Child runs are admitted on their own identity: a registered job is
// never exempt because it was called as a subworkflow. It reports whether the
// claim was refused and why.
func (h *Handler) refuseUnadmittedClaim(ctx context.Context, claimToken string, task *dispatch.DispatchTask) (bool, string, error) {
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
	adm, err := h.runAdmitter.AdmitClaim(ctx, name, spec, task.DAGRunID)
	if err != nil {
		return false, "", fmt.Errorf("check TXE job admission: %w", err)
	}
	if adm.Admit {
		return false, "", nil
	}
	reason := fmt.Sprintf("txe: job %s %s: %s", adm.JobID, adm.Code, adm.Reason)
	storeCtx := context.WithoutCancel(ctx)
	if err := h.abortQueuedAttempt(storeCtx, task, reason); err != nil {
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

func (h *Handler) abortQueuedAttempt(ctx context.Context, task *dispatch.DispatchTask, reason string) error {
	if h.dagRunRepository == nil {
		return nil
	}
	held := h.runLocks.lock(task.DAGRunID)
	defer h.runLocks.unlock(task.DAGRunID, held)
	var attempt dagrun.Attempt
	var err error
	if task.RootDAGRunID != "" && task.RootDAGRunID != task.DAGRunID {
		root := ir.NewDAGRunRef(task.RootDAGRunName, task.RootDAGRunID)
		attempt, err = h.dagRunRepository.FindSubAttempt(ctx, root, task.DAGRunID)
	} else {
		attempt, err = h.dagRunRepository.FindAttempt(ctx, ir.NewDAGRunRef(task.Target, task.DAGRunID))
	}
	if err != nil {
		return fmt.Errorf("find attempt of refused run: %w", err)
	}
	status, err := attempt.ReadStatus(ctx)
	if err != nil {
		return fmt.Errorf("read attempt of refused run: %w", err)
	}
	if status == nil || (status.Status != ir.Queued && status.Status != ir.NotStarted) {
		return nil
	}
	status.Status = ir.Aborted
	status.FinishedAt = stringutil.FormatTime(time.Now().UTC())
	status.Error = reason
	if err := attempt.Write(ctx, *status); err != nil {
		return fmt.Errorf("abort refused run: %w", err)
	}
	h.finalizeAdmissionForStatus(ctx, status, attempt.ID())
	return nil
}
