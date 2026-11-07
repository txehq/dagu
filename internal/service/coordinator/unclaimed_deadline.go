// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/cmn/stringutil"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

// expireUnclaimedDispatches ends what is left of the pending tasks no worker
// claimed by their claim deadline (TXE-5923,
// coordinator.unclaimed_dispatch_timeout). The store already refuses to hand
// such a task out; this pass removes it and settles its attempt:
//
//   - An attempt the preparation journal names loses only its task record.
//     Reconciliation of the journal (the next pass) then abandons the attempt
//     with a record once it proves nothing was dispatched, exactly as for an
//     attempt whose coordinator stopped before publishing it. A crash after
//     the removal leaves the journal entry, so the abandonment still happens.
//   - An attempt the journal does not name is failed first, while it still
//     waits for a worker, and only then loses its task. A crash between the
//     two leaves an unclaimable task, and the next pass finds the run already
//     settled and removes the task.
//
// Neither path ever ends an attempt a worker holds (one with a worker, a
// lease or an active-run record) or one that is no longer its run's latest,
// and neither removes any record but the one listed.
func (h *Handler) expireUnclaimedDispatches(ctx context.Context, now time.Time) {
	if h.dispatchTaskStore == nil || h.dagRunRepository == nil {
		return
	}
	past, err := h.dispatchTaskStore.ListPastClaimDeadline(ctx, now)
	if err != nil {
		logger.Warn(ctx, "Failed to list pending dispatches past their claim deadline", tag.Error(err))
		return
	}
	if len(past) == 0 {
		return
	}
	journaled, err := h.journaledAttempts(ctx)
	if err != nil {
		// Which path an attempt takes is unknown, so none is taken.
		logger.Warn(ctx, "Left pending dispatches past their claim deadline: the preparation journal could not be read",
			tag.Error(err))
		return
	}
	pass := &unclaimedPass{now: now}
	for _, unclaimed := range past {
		if ctx.Err() != nil {
			return
		}
		h.expireUnclaimedDispatch(ctx, unclaimed, journaled, pass)
	}
}

// unclaimedPass holds what one pass reads at most once.
type unclaimedPass struct {
	now        time.Time
	queued     *queueSnapshot
	queuedRead bool
}

// journaledAttempts returns the attempts the preparation journal names, keyed
// by journaledAttemptKey; nil when this coordinator journals none.
func (h *Handler) journaledAttempts(ctx context.Context) (map[string]struct{}, error) {
	if !h.canAbandonPreparations() {
		return nil, nil
	}
	preparations, err := h.dagRunRepository.ListAttemptPreparations(ctx)
	if errors.Is(err, persis.ErrAttemptAbandonmentUnsupported) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	journaled := make(map[string]struct{}, len(preparations))
	for _, p := range preparations {
		journaled[journaledAttemptKey(p.Run.Name, p.Run.ID, p.AttemptID)] = struct{}{}
	}
	return journaled, nil
}

// journaledAttemptKey ignores the entry's queued-at marker: an entry for an
// attempt the dispatch created has none even when its task carries one.
func journaledAttemptKey(dagName, dagRunID, attemptID string) string {
	return dagName + "\x00" + dagRunID + "\x00" + attemptID
}

func (h *Handler) expireUnclaimedDispatch(ctx context.Context, unclaimed dispatch.UnclaimedDispatch, journaled map[string]struct{}, pass *unclaimedPass) {
	task := unclaimed.Task
	storeCtx := context.WithoutCancel(ctx)
	if _, ok := journaled[journaledAttemptKey(task.Target, task.DAGRunID, task.AttemptID)]; ok {
		h.dropUnclaimedTask(ctx, unclaimed, pass.now, "Removed a pending dispatch no worker claimed by its claim deadline; its attempt is abandoned with a record")
		return
	}

	held := h.runLocks.lock(task.DAGRunID)
	defer h.runLocks.unlock(task.DAGRunID, held)

	rootRef := ir.DAGRunRef{Name: task.RootDAGRunName, ID: task.RootDAGRunID}
	attempt, runStatus, err := h.resolveLatestAttempt(storeCtx, task.Target, task.DAGRunID, rootRef)
	switch {
	case errors.Is(err, dagrun.ErrDAGRunIDNotFound), errors.Is(err, dagrun.ErrNoStatusData):
		// Nothing is left to fail; only the task remains.
	case err != nil:
		logger.Warn(ctx, "Failed to read the run of a pending dispatch past its claim deadline",
			tag.RunID(task.DAGRunID), tag.Error(err))
		return
	case unclaimedAttemptWaits(task, runStatus):
		fail, err := h.unclaimedAttemptMayFail(storeCtx, task, pass)
		if err != nil {
			// Unknown is never absent: the task stays for the next pass.
			logger.Warn(ctx, "Left a pending dispatch past its claim deadline: whether its attempt is with a worker is unknown",
				tag.RunID(task.DAGRunID), tag.AttemptKey(task.AttemptKey), tag.Error(err))
			return
		}
		if fail {
			// runStatus may be the cached status other readers share.
			failed := *runStatus
			failed.Status = ir.Failed
			failed.FinishedAt = stringutil.FormatTime(pass.now)
			failed.Error = unclaimedDispatchFailure(unclaimed.Deadline)
			if err := h.writeHeldAttemptStatus(storeCtx, task.DAGRunID, attempt, failed); err != nil {
				logger.Warn(ctx, "Failed to fail the run of a pending dispatch past its claim deadline",
					tag.RunID(task.DAGRunID), tag.Error(err))
				return
			}
			h.finalizeAdmissionForStatus(storeCtx, &failed, attempt.ID())
			logger.Warn(ctx, "No worker claimed a dispatch by its claim deadline; the run failed",
				tag.RunID(task.DAGRunID), tag.AttemptKey(task.AttemptKey),
				slog.Time("claim-deadline", unclaimed.Deadline))
		}
	}
	h.dropUnclaimedTask(ctx, unclaimed, pass.now, "Removed a pending dispatch no worker claimed by its claim deadline")
}

func (h *Handler) dropUnclaimedTask(ctx context.Context, unclaimed dispatch.UnclaimedDispatch, now time.Time, msg string) {
	task := unclaimed.Task
	removed, err := h.dispatchTaskStore.DeletePastClaimDeadline(context.WithoutCancel(ctx), unclaimed, now)
	if err != nil {
		logger.Warn(ctx, "Failed to remove a pending dispatch past its claim deadline",
			tag.RunID(task.DAGRunID), tag.AttemptKey(task.AttemptKey), tag.Error(err))
		return
	}
	if removed {
		logger.Warn(ctx, msg, tag.RunID(task.DAGRunID), tag.AttemptKey(task.AttemptKey),
			slog.Time("claim-deadline", unclaimed.Deadline))
	}
}

// unclaimedAttemptWaits reports whether the run's latest attempt is the
// task's and still waits for a worker: not started, or queued as the task's
// execution, with no worker named.
func unclaimedAttemptWaits(task *dispatch.DispatchTask, runStatus *ir.DAGRunStatus) bool {
	if runStatus == nil || runStatus.WorkerID != "" {
		return false
	}
	if task.AttemptID != "" && runStatus.AttemptID != task.AttemptID {
		return false
	}
	switch runStatus.Status { //nolint:exhaustive // only an attempt that never started waits for a worker
	case ir.NotStarted:
		return true
	case ir.Queued:
		return task.ExecutionMarker == "" || runStatus.QueuedAt == task.ExecutionMarker
	default:
		return false
	}
}

// unclaimedAttemptMayFail reports whether nothing shows the attempt with a
// worker: no lease, no active-run record, and no queue still holding its run
// (a queue dispatches it again, so only its task goes). A lookup that fails
// is an error, never absence.
func (h *Handler) unclaimedAttemptMayFail(ctx context.Context, task *dispatch.DispatchTask, pass *unclaimedPass) (bool, error) {
	if h.dagRunLeaseStore != nil {
		if _, err := h.dagRunLeaseStore.Get(ctx, task.AttemptKey); err == nil {
			return false, nil
		} else if !errors.Is(err, dispatch.ErrDAGRunLeaseNotFound) {
			return false, fmt.Errorf("lease store: %w", err)
		}
	}
	if h.activeDistributedRunStore != nil {
		if _, err := h.activeDistributedRunStore.Get(ctx, task.AttemptKey); err == nil {
			return false, nil
		} else if !errors.Is(err, dispatch.ErrActiveRunNotFound) {
			return false, fmt.Errorf("active run store: %w", err)
		}
	}
	if h.queueStore != nil {
		if !pass.queuedRead {
			pass.queued, pass.queuedRead = h.readQueueSnapshot(ctx), true
		}
		run := ir.DAGRunRef{Name: task.Target, ID: task.DAGRunID}
		if err := pass.queued.refuse(run); err != nil {
			if errors.Is(err, errDispatchInFlight) {
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}

// unclaimedDispatchFailure is the run error for a dispatch no worker claimed
// by its claim deadline.
func unclaimedDispatchFailure(deadline time.Time) string {
	return fmt.Sprintf("not dispatched: no worker claimed it by its claim deadline %s "+
		"(coordinator.unclaimed_dispatch_timeout); nothing ran, so it can be started again",
		deadline.UTC().Format(time.RFC3339))
}
