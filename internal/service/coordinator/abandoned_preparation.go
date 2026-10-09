// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// abandonedPreparationMinAge is how old a preparation journal entry must be
// before reconciliation considers its attempt. It is not why an attempt is
// abandoned; the absence evidence is. It keeps reconciliation away from a
// preparation that another coordinator, for example one draining during a
// rolling replacement, may still be about to publish. The claim check below
// refuses such a publication anyway.
const abandonedPreparationMinAge = 10 * time.Minute

// errAttemptAbandoned refuses a claim of an attempt that has an abandonment
// record: it was proven never dispatched and is hidden.
var errAttemptAbandoned = errors.New("attempt was abandoned before dispatch")

// errEvidenceUnknown means a lookup could not establish absence.
var errEvidenceUnknown = errors.New("dispatch evidence unknown")

// errAbandonmentUnavailable means this coordinator is not configured to
// prove absence of dispatch at all, as without a dispatch or lease store.
var errAbandonmentUnavailable = errors.New("abandonment requires dispatch and lease stores")

// neverDispatchedEvidence establishes, for one attempt, that nothing was ever
// handed to a worker. Any lookup that fails is unknown, never absent.
func (h *Handler) neverDispatchedEvidence(ctx context.Context, attemptKey string, status *ir.DAGRunStatus) (persis.AbandonmentEvidence, error) {
	var evidence persis.AbandonmentEvidence
	if h.dispatchTaskStore == nil || h.dagRunLeaseStore == nil {
		return evidence, errAbandonmentUnavailable
	}
	if status != nil && (status.WorkerID != "" || status.Status != ir.NotStarted) {
		return evidence, fmt.Errorf("%w: attempt is %s with worker %q",
			persis.ErrAttemptNotAbandonable, status.Status, status.WorkerID)
	}
	outstanding, err := h.dispatchTaskStore.HasOutstandingAttempt(ctx, attemptKey, h.staleLeaseThreshold)
	if err != nil {
		return evidence, fmt.Errorf("%w: dispatch store: %v", errEvidenceUnknown, err)
	}
	if outstanding {
		return evidence, errors.New("a dispatch task is pending or claimed")
	}
	if _, err := h.dagRunLeaseStore.Get(ctx, attemptKey); err == nil {
		return evidence, errors.New("a lease exists")
	} else if !errors.Is(err, dispatch.ErrDAGRunLeaseNotFound) {
		return evidence, fmt.Errorf("%w: lease store: %v", errEvidenceUnknown, err)
	}
	if h.activeDistributedRunStore != nil {
		if _, err := h.activeDistributedRunStore.Get(ctx, attemptKey); err == nil {
			return evidence, errors.New("an active run record exists")
		} else if !errors.Is(err, dispatch.ErrActiveRunNotFound) {
			return evidence, fmt.Errorf("%w: active run store: %v", errEvidenceUnknown, err)
		}
	}
	evidence = persis.AbandonmentEvidence{
		DispatchTask: persis.EvidenceAbsent,
		Lease:        persis.EvidenceAbsent,
		ActiveRun:    persis.EvidenceAbsent,
		Worker:       persis.EvidenceAbsent,
		ObservedAt:   time.Now().UTC().Format(time.RFC3339Nano),
	}
	return evidence, nil
}

// abandonNeverDispatched records an attempt of a root run or of one of its
// sub-DAG runs once absence of any dispatch is proven. It holds the root
// run's write lock, which Dispatch holds from preparing an attempt to
// publishing its task and AckTaskClaim holds while recording a claim, so
// neither can interleave. detail says why, for the record. The store hides
// the attempt when the run has an earlier execution, and otherwise keeps it
// visible, marked Failed with detail.
func (h *Handler) abandonNeverDispatched(ctx context.Context, run, root ir.DAGRunRef, attemptID, detail string) (*persis.AttemptAbandonment, error) {
	if h.dagRunRepository == nil {
		return nil, persis.ErrAttemptAbandonmentUnsupported
	}
	if root.Zero() {
		root = run
	}
	defer h.attemptWriteLocks.lock(root)()
	return h.abandonExecutionLocked(ctx, run, root, attemptID, detail)
}

// abandonNeverDispatchedLocked abandons a root run's attempt; the caller holds
// the run's write lock.
func (h *Handler) abandonNeverDispatchedLocked(ctx context.Context, run ir.DAGRunRef, attemptID, detail string) (*persis.AttemptAbandonment, error) {
	return h.abandonExecutionLocked(ctx, run, run, attemptID, detail)
}

// abandonExecutionLocked abandons the attempt and, once its record is on
// disk, ends its preparation journal entry. The caller holds the root run's
// write lock.
func (h *Handler) abandonExecutionLocked(ctx context.Context, run, root ir.DAGRunRef, attemptID, detail string) (*persis.AttemptAbandonment, error) {
	ctx = context.WithoutCancel(ctx)
	h.closeCachedAttemptForRun(ctx, ctx, run.ID, attemptID)

	var status *ir.DAGRunStatus
	if attempt, err := h.findRunAttempt(ctx, run, root); err == nil && attempt.ID() == attemptID {
		if st, err := attempt.ReadStatus(ctx); err == nil {
			status = st
		}
	}
	attemptKey := ir.GenerateAttemptKey(root.Name, root.ID, run.Name, run.ID, attemptID)
	evidence, err := h.neverDispatchedEvidence(ctx, attemptKey, status)
	if err != nil {
		return nil, err
	}
	record := persis.AttemptAbandonment{
		Schema:             persis.AttemptAbandonmentSchema,
		Run:                run,
		RootRun:            root,
		AbandonedAttemptID: attemptID,
		Reason:             persis.AbandonedRetryPreparation,
		Detail:             detail,
		DecidedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		CoordinatorID:      h.owner.ID,
		Evidence:           evidence,
	}
	abandoned, err := h.dagRunRepository.AbandonAttempt(ctx, persis.AbandonAttemptRequest{DAGRun: run, RootDAGRun: root, Record: record})
	if err != nil {
		return nil, err
	}
	h.endPreparation(ctx, run, root, attemptID)
	return abandoned, nil
}

// findRunAttempt finds the latest attempt of a root run or of a sub-DAG run.
func (h *Handler) findRunAttempt(ctx context.Context, run, root ir.DAGRunRef) (dagrun.Attempt, error) {
	if run == root {
		return h.dagRunRepository.FindAttempt(ctx, run)
	}
	return h.dagRunRepository.FindSubAttempt(ctx, root, run.ID)
}

// endPreparation removes the attempt's preparation journal entry once the
// attempt was handed to a worker or abandoned. An entry left behind is
// re-examined by reconciliation, which ends it when the attempt is settled.
func (h *Handler) endPreparation(ctx context.Context, run, root ir.DAGRunRef, attemptID string) {
	err := h.dagRunRepository.EndAttemptPreparation(ctx, persis.AttemptPreparation{Run: run, RootRun: root, AttemptID: attemptID})
	if err != nil && !errors.Is(err, persis.ErrAttemptAbandonmentUnsupported) {
		logger.Warn(ctx, "Failed to end an attempt preparation",
			tag.RunID(run.ID), tag.AttemptID(attemptID), tag.Error(err))
	}
}

// reconcileAbandonedPreparations reads the preparation journal and, for each
// entry older than the bound, abandons its attempt if absence of dispatch is
// proven. A coordinator that stopped between creating an attempt and
// publishing its task leaves exactly such an entry, whether or not the
// attempt's status was ever written. An entry whose attempt is settled, as
// started, superseded or gone, is ended. The journal holds only preparations
// in flight or left behind, so each pass reads it whole and none is starved.
func (h *Handler) reconcileAbandonedPreparations(ctx context.Context, now time.Time) {
	if h.dagRunRepository == nil || h.dispatchTaskStore == nil || h.dagRunLeaseStore == nil {
		return
	}
	preparations, err := h.dagRunRepository.ListAttemptPreparations(ctx)
	if err != nil {
		if !errors.Is(err, persis.ErrAttemptAbandonmentUnsupported) {
			logger.Warn(ctx, "Failed to read the attempt preparation journal", tag.Error(err))
		}
		return
	}
	for _, p := range preparations {
		if ctx.Err() != nil {
			return
		}
		preparedAt, err := time.Parse(time.RFC3339Nano, p.PreparedAt)
		if err != nil || now.Sub(preparedAt) < abandonedPreparationMinAge {
			continue
		}
		record, err := h.abandonNeverDispatched(ctx, p.Run, p.RootRun, p.AttemptID,
			"not dispatched: no dispatch task, claim, lease or worker after the coordinator stopped")
		switch {
		case err == nil:
			logger.Warn(ctx, "Abandoned a never-dispatched attempt",
				tag.RunID(p.Run.ID), tag.AttemptID(record.AbandonedAttemptID))
		case errors.Is(err, persis.ErrAttemptNotAbandonable), errors.Is(err, dagrun.ErrDAGRunIDNotFound):
			// Settled: nothing of this preparation is left to abandon.
			h.endPreparation(ctx, p.Run, p.RootRun, p.AttemptID)
		default:
			logger.Warn(ctx, "Left a prepared attempt for review",
				tag.RunID(p.Run.ID), tag.AttemptID(p.AttemptID), tag.Error(err))
		}
	}
}

// refuseAbandonedClaim refuses a claim of an attempt's execution that was
// abandoned. A coordinator that published a task after another coordinator
// had proven its absence cannot then have it executed. A later execution of
// the same attempt, re-queued by a retry, carries another marker and is not
// refused. A record that cannot be read refuses the claim. The caller holds
// the run's write lock.
func (h *Handler) refuseAbandonedExecution(ctx context.Context, run, root ir.DAGRunRef, attemptID, executionMarker string) error {
	if h.dagRunRepository == nil {
		return nil
	}
	record, err := h.dagRunRepository.ReadAttemptAbandonment(ctx, run, root, attemptID)
	switch {
	case errors.Is(err, persis.ErrAttemptAbandonmentUnsupported), errors.Is(err, dagrun.ErrDAGRunIDNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("read abandonment record: %w", err)
	case record != nil && record.Covers(attemptID, executionMarker):
		return errAttemptAbandoned
	}
	return nil
}

// refuseAbandonedClaim is the claim check's call until the handler passes
// the task's execution marker (WIP: handler.go is frozen for TXE-3808).
func (h *Handler) refuseAbandonedClaim(ctx context.Context, run, root ir.DAGRunRef, attemptID string) error {
	return h.refuseAbandonedExecution(ctx, run, root, attemptID, "")
}

// preparationFailedError reports a failure after an attempt was created but
// before its status was written, so the attempt was never dispatched.
type preparationFailedError struct {
	run ir.DAGRunRef
	// root is the run's root; zero for a root run.
	root      ir.DAGRunRef
	attemptID string
	err       error
}

func (e *preparationFailedError) Error() string { return e.err.Error() }
func (e *preparationFailedError) Unwrap() error { return e.err }

// abandonFailedPreparation abandons the attempt a failed preparation left
// behind. The caller holds the run's write lock.
func (h *Handler) abandonFailedPreparation(ctx context.Context, prepErr error) {
	var failed *preparationFailedError
	if !errors.As(prepErr, &failed) {
		return
	}
	root := failed.root
	if root.Zero() {
		root = failed.run
	}
	if _, err := h.abandonExecutionLocked(ctx, failed.run, root, failed.attemptID,
		"not dispatched: preparing the attempt failed: "+failed.err.Error()); err != nil {
		logger.Warn(ctx, "Left an attempt whose preparation failed for review",
			tag.RunID(failed.run.ID), tag.AttemptID(failed.attemptID), tag.Error(err))
	}
}

// taskRootRef is the root run a task belongs to, the key of its run's write
// lock.
func taskRootRef(task *coordinatorv1.Task) ir.DAGRunRef {
	root := ir.DAGRunRef{Name: task.GetRootDagRunName(), ID: task.GetRootDagRunId()}
	if root.Zero() {
		root = ir.DAGRunRef{Name: task.GetTarget(), ID: task.GetDagRunId()}
	}
	return root
}

// dispatchPublishHook, when set by a test, runs in Dispatch after the attempt
// is prepared and before its task is published, with the run's write lock
// held.
var dispatchPublishHook func(task *coordinatorv1.Task)
