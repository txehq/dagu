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

// abandonedPreparationMinAge is how old a not-started attempt must be before
// reconciliation considers it. It is not why an attempt is abandoned; the
// absence evidence is. It keeps reconciliation away from a preparation that
// another coordinator, for example one draining during a rolling replacement,
// may still be about to publish. The claim check below refuses such a
// publication anyway.
const abandonedPreparationMinAge = 10 * time.Minute

// abandonedPreparationLookback is how far back reconciliation looks for runs
// left not started.
const abandonedPreparationLookback = 7 * 24 * time.Hour

// abandonedPreparationScanLimit bounds one reconciliation pass.
const abandonedPreparationScanLimit = 200

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
		return evidence, fmt.Errorf("attempt is %s with worker %q", status.Status, status.WorkerID)
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

// abandonNeverDispatched records and hides a root run's attempt once absence
// of any dispatch is proven. It holds the run's write lock, which Dispatch
// holds from preparing an attempt to publishing its task and AckTaskClaim
// holds while recording a claim, so neither can interleave. detail says why,
// for the record. The store hides the attempt when the run has an earlier
// execution, and otherwise keeps it visible, marked Failed with detail.
func (h *Handler) abandonNeverDispatched(ctx context.Context, run ir.DAGRunRef, attemptID, detail string) (*persis.AttemptAbandonment, error) {
	if h.dagRunRepository == nil {
		return nil, persis.ErrAttemptAbandonmentUnsupported
	}
	defer h.attemptWriteLocks.lock(run)()
	return h.abandonNeverDispatchedLocked(ctx, run, attemptID, detail)
}

func (h *Handler) abandonNeverDispatchedLocked(ctx context.Context, run ir.DAGRunRef, attemptID, detail string) (*persis.AttemptAbandonment, error) {
	ctx = context.WithoutCancel(ctx)
	h.closeCachedAttemptForRun(ctx, ctx, run.ID, attemptID)

	var status *ir.DAGRunStatus
	if attempt, err := h.dagRunRepository.FindAttempt(ctx, run); err == nil && attempt.ID() == attemptID {
		if st, err := attempt.ReadStatus(ctx); err == nil {
			status = st
		}
	}
	attemptKey := ir.GenerateAttemptKey(run.Name, run.ID, run.Name, run.ID, attemptID)
	evidence, err := h.neverDispatchedEvidence(ctx, attemptKey, status)
	if err != nil {
		return nil, err
	}
	record := persis.AttemptAbandonment{
		Schema:             persis.AttemptAbandonmentSchema,
		Run:                run,
		RootRun:            run,
		AbandonedAttemptID: attemptID,
		Reason:             persis.AbandonedRetryPreparation,
		Detail:             detail,
		DecidedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		CoordinatorID:      h.owner.ID,
		Evidence:           evidence,
	}
	return h.dagRunRepository.AbandonAttempt(ctx, persis.AbandonAttemptRequest{DAGRun: run, Record: record})
}

// reconcileAbandonedPreparations finds root runs whose latest attempt is
// not started, has no worker and is older than the bound, and abandons each
// one whose absence of dispatch is proven. A coordinator that stopped between
// creating an attempt and publishing its task leaves exactly this behind.
func (h *Handler) reconcileAbandonedPreparations(ctx context.Context, now time.Time) {
	if h.dagRunRepository == nil || h.dispatchTaskStore == nil || h.dagRunLeaseStore == nil {
		return
	}
	page, err := h.dagRunRepository.ListStatusesPage(ctx, persis.DAGRunListOptions{
		Statuses: []ir.Status{ir.NotStarted},
		From:     persis.NewUTC(now.Add(-abandonedPreparationLookback)),
		Limit:    abandonedPreparationScanLimit,
	})
	if err != nil {
		logger.Warn(ctx, "Failed to list not-started runs for reconciliation", tag.Error(err))
		return
	}
	for _, status := range page.Items {
		if ctx.Err() != nil {
			return
		}
		if status == nil || isSubDAGStatus(status) || status.WorkerID != "" || status.AttemptID == "" {
			continue
		}
		if status.CreatedAt == 0 || now.Sub(time.UnixMilli(status.CreatedAt)) < abandonedPreparationMinAge {
			continue
		}
		record, err := h.abandonNeverDispatched(ctx, status.DAGRun(), status.AttemptID,
			"not dispatched: no dispatch task, claim, lease or worker after the coordinator stopped")
		if err != nil {
			logger.Warn(ctx, "Left a not-started attempt for review",
				tag.RunID(status.DAGRunID), tag.AttemptID(status.AttemptID), tag.Error(err))
			continue
		}
		logger.Warn(ctx, "Abandoned a never-dispatched attempt",
			tag.RunID(status.DAGRunID), tag.AttemptID(record.AbandonedAttemptID))
	}
}

// refuseAbandonedClaim refuses a claim of an attempt that was abandoned. A
// coordinator that published a task after another coordinator had proven its
// absence cannot then have it executed. The caller holds the run's write lock.
func (h *Handler) refuseAbandonedClaim(ctx context.Context, run ir.DAGRunRef, root ir.DAGRunRef, attemptID string) error {
	if h.dagRunRepository == nil {
		return nil
	}
	records, err := h.dagRunRepository.ListAttemptAbandonments(ctx, run, root)
	switch {
	case errors.Is(err, persis.ErrAttemptAbandonmentUnsupported), errors.Is(err, dagrun.ErrDAGRunIDNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("read abandonment records: %w", err)
	}
	for _, record := range records {
		if record.AbandonedAttemptID == attemptID {
			return errAttemptAbandoned
		}
	}
	return nil
}

// preparationFailedError reports a failure after an attempt was created but
// before its status was written, so the attempt was never dispatched.
type preparationFailedError struct {
	run       ir.DAGRunRef
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
	if _, err := h.abandonNeverDispatchedLocked(ctx, failed.run, failed.attemptID,
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
