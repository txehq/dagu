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
//
// It also stays above the longest an unacknowledged dispatch can remain
// reserved: a pending task expires after the reservation TTL, and a claim
// never acknowledged is released to pending after one TTL and then expires
// after another. Both TTLs are dagrun.DefaultStaleLeaseThreshold, so the bound
// is derived from it and grows with it.
const abandonedPreparationMinAge = max(10*time.Minute, 2*dagrun.DefaultStaleLeaseThreshold+time.Minute)

// errAttemptAbandoned refuses a claim of an attempt that has an abandonment
// record: it was proven never dispatched and is hidden.
var errAttemptAbandoned = errors.New("attempt was abandoned before dispatch")

// errEvidenceUnknown means a lookup could not establish absence.
var errEvidenceUnknown = errors.New("dispatch evidence unknown")

// canAbandonPreparations reports whether this coordinator can prove absence
// of dispatch, and so journals the attempts it prepares for reconciliation.
func (h *Handler) canAbandonPreparations() bool {
	return h.dagRunRepository != nil && h.dispatchTaskStore != nil && h.dagRunLeaseStore != nil
}

// errDispatchInFlight means the attempt may be with a worker: a task is pending
// or claimed, or a lease or active-run record exists. The attempt is not
// abandoned, and its entry stays until the attempt settles: a worker that has
// acknowledged its claim reports progress, and an unacknowledged task expires.
var errDispatchInFlight = errors.New("dispatch may be in flight")

// errAbandonmentUnavailable means this coordinator is not configured to
// prove absence of dispatch at all, as without a dispatch or lease store.
var errAbandonmentUnavailable = errors.New("abandonment requires dispatch and lease stores")

// neverDispatchedEvidence establishes, for one attempt, that nothing was ever
// handed to a worker. Any lookup that fails is unknown, never absent.
//
// queuedAt names one execution of a reused attempt (empty for a newly created
// attempt): its status may then still read Queued, with exactly that marker.
func (h *Handler) neverDispatchedEvidence(ctx context.Context, attemptKey, queuedAt string, status *ir.DAGRunStatus) (persis.AbandonmentEvidence, error) {
	var evidence persis.AbandonmentEvidence
	if h.dispatchTaskStore == nil || h.dagRunLeaseStore == nil {
		return evidence, errAbandonmentUnavailable
	}
	waiting := status != nil && (status.Status == ir.NotStarted ||
		(queuedAt != "" && status.Status == ir.Queued && status.QueuedAt == queuedAt))
	if status != nil && (status.WorkerID != "" || !waiting) {
		return evidence, fmt.Errorf("%w: attempt is %s with worker %q",
			persis.ErrAttemptNotAbandonable, status.Status, status.WorkerID)
	}
	outstanding, err := h.dispatchTaskStore.HasOutstandingAttempt(ctx, attemptKey, h.staleLeaseThreshold)
	if err != nil {
		return evidence, fmt.Errorf("%w: dispatch store: %v", errEvidenceUnknown, err)
	}
	if outstanding {
		return evidence, fmt.Errorf("%w: a dispatch task is pending or claimed", errDispatchInFlight)
	}
	if _, err := h.dagRunLeaseStore.Get(ctx, attemptKey); err == nil {
		return evidence, fmt.Errorf("%w: a lease exists", errDispatchInFlight)
	} else if !errors.Is(err, dispatch.ErrDAGRunLeaseNotFound) {
		return evidence, fmt.Errorf("%w: lease store: %v", errEvidenceUnknown, err)
	}
	if h.activeDistributedRunStore != nil {
		if _, err := h.activeDistributedRunStore.Get(ctx, attemptKey); err == nil {
			return evidence, fmt.Errorf("%w: an active run record exists", errDispatchInFlight)
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

// Topology: the ordering between abandonment and a claim's acknowledgement
// rests on attemptWriteLocks, which is local to this process. It is complete
// for a single coordinator per store, the supported topology. Two coordinators
// sharing a store could interleave an acknowledgement on one with an
// abandonment on the other; that needs a cross-process fence.
//
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
	return h.abandonExecutionLocked(ctx, run, root, attemptID, "", detail, nil)
}

// abandonPreparation abandons what one preparation journal entry names: a
// newly created attempt, or one execution of a reused attempt when the entry
// carries its queued-at marker.
// queued is the pass's view of the queues; an execution whose run a queue
// still holds is left for the queue to dispatch.
func (h *Handler) abandonPreparation(ctx context.Context, p persis.AttemptPreparation, detail string, queued *queueSnapshot) (*persis.AttemptAbandonment, error) {
	root := p.RootRun
	if root.Zero() {
		root = p.Run
	}
	defer h.attemptWriteLocks.lock(root)()
	return h.abandonExecutionLocked(ctx, p.Run, root, p.AttemptID, p.QueuedAt, detail, queued)
}

// abandonExecutionLocked abandons the attempt, or with queuedAt one execution
// of a reused attempt, and once its record is on disk ends its preparation
// journal entry. The caller holds the root run's write lock.
func (h *Handler) abandonExecutionLocked(ctx context.Context, run, root ir.DAGRunRef, attemptID, queuedAt, detail string, queued *queueSnapshot) (*persis.AttemptAbandonment, error) {
	ctx = context.WithoutCancel(ctx)
	h.closeCachedAttemptForRun(ctx, ctx, run.ID, attemptID)

	var status *ir.DAGRunStatus
	if attempt, err := h.findRunAttempt(ctx, run, root); err == nil && attempt.ID() == attemptID {
		if st, err := attempt.ReadStatus(ctx); err == nil {
			status = st
		}
	}
	attemptKey := ir.GenerateAttemptKey(root.Name, root.ID, run.Name, run.ID, attemptID)
	evidence, err := h.neverDispatchedEvidence(ctx, attemptKey, queuedAt, status)
	if err != nil {
		return nil, err
	}
	if queuedAt != "" {
		if err := queued.refuse(run); err != nil {
			return nil, err
		}
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
	if queuedAt != "" {
		// One execution of a reused attempt: the store marks it Failed and
		// keeps the attempt's earlier executions and their records.
		record.Scope = persis.AbandonmentScopeExecution
		record.AbandonedExecution = persis.ExecutionIdentity{AttemptID: attemptID, QueuedAt: queuedAt}
	}
	abandoned, err := h.dagRunRepository.AbandonAttempt(ctx, persis.AbandonAttemptRequest{DAGRun: run, RootDAGRun: root, Record: record})
	if err != nil {
		return nil, err
	}
	h.endPreparation(ctx, run, root, attemptID, queuedAt)
	return abandoned, nil
}

// queueSnapshot is the set of runs some queue holds, read once per
// reconciliation pass. A dispatch that failed leaves its run's queue item, and
// the queue dispatches it again under the same journal entry, so a queued
// execution whose run a queue holds is not failed as undispatched. Every queue
// is read, so a status that does not name its queue is still covered. A run
// queued after the read is a new execution with a new marker, which the store
// refuses to abandon in this one's place. A queue or item that cannot be read
// makes the whole snapshot unknown, never empty.
type queueSnapshot struct {
	runs map[ir.DAGRunRef]struct{}
	err  error
}

// readQueueSnapshot reads every queue, or returns nil when this coordinator
// has no queue store, which skips the check.
func (h *Handler) readQueueSnapshot(ctx context.Context) *queueSnapshot {
	if h.queueStore == nil {
		return nil
	}
	snap := &queueSnapshot{runs: make(map[ir.DAGRunRef]struct{})}
	names, err := h.queueStore.QueueList(ctx)
	if err != nil {
		snap.err = err
		return snap
	}
	for _, name := range names {
		items, err := h.queueStore.List(ctx, name)
		if err != nil {
			snap.err = fmt.Errorf("queue %s: %w", name, err)
			return snap
		}
		for _, item := range items {
			ref, err := item.Data()
			if err != nil {
				snap.err = fmt.Errorf("queue %s item %s: %w", name, item.ID(), err)
				return snap
			}
			if ref != nil {
				snap.runs[*ref] = struct{}{}
			}
		}
	}
	return snap
}

// refuse reports whether an execution of run must be left because a queue may
// still dispatch it.
func (s *queueSnapshot) refuse(run ir.DAGRunRef) error {
	if s == nil {
		return nil
	}
	if s.err != nil {
		return fmt.Errorf("%w: queues: %v", errEvidenceUnknown, s.err)
	}
	if _, ok := s.runs[run]; ok {
		return fmt.Errorf("%w: the run is still in a queue", errDispatchInFlight)
	}
	return nil
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
func (h *Handler) endPreparation(ctx context.Context, run, root ir.DAGRunRef, attemptID, queuedAt string) {
	err := h.dagRunRepository.EndAttemptPreparation(ctx, persis.AttemptPreparation{Run: run, RootRun: root, AttemptID: attemptID, QueuedAt: queuedAt})
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
	if !h.canAbandonPreparations() {
		return
	}
	preparations, err := h.dagRunRepository.ListAttemptPreparations(ctx)
	if err != nil {
		if !errors.Is(err, persis.ErrAttemptAbandonmentUnsupported) {
			logger.Warn(ctx, "Failed to read the attempt preparation journal", tag.Error(err))
		}
		return
	}
	inFlight := make(map[string]struct{})
	var queued *queueSnapshot
	queuedRead := false
	for _, p := range preparations {
		if ctx.Err() != nil {
			return
		}
		preparedAt, err := time.Parse(time.RFC3339Nano, p.PreparedAt)
		if err != nil || now.Sub(preparedAt) < abandonedPreparationMinAge {
			continue
		}
		if p.QueuedAt != "" && !queuedRead {
			queued, queuedRead = h.readQueueSnapshot(ctx), true
		}
		record, err := h.abandonPreparation(ctx, p, abandonedPreparationDetail, queued)
		switch {
		case err == nil:
			logger.Warn(ctx, "Abandoned a never-dispatched attempt",
				tag.RunID(p.Run.ID), tag.AttemptID(record.AbandonedAttemptID))
		case errors.Is(err, errDispatchInFlight):
			// The attempt may be with a worker. Its entry ends once the
			// attempt settles; say so once, not on every pass.
			key := preparationKey(p)
			inFlight[key] = struct{}{}
			if !h.wasInFlight(key) {
				logger.Info(ctx, "Left a prepared attempt that may be with a worker until it settles",
					tag.RunID(p.Run.ID), tag.AttemptID(p.AttemptID), tag.Error(err))
			}
		case errors.Is(err, persis.ErrAttemptNotAbandonable), errors.Is(err, dagrun.ErrDAGRunIDNotFound):
			// Ended only once nothing of it is left to judge, decided under
			// the lock abandonments take: while the latest attempt is another
			// preparation, abandoning that one would make this the latest
			// again, so its entry stays.
			if _, err := h.dagRunRepository.EndSettledAttemptPreparation(ctx, p); err != nil &&
				!errors.Is(err, persis.ErrAttemptAbandonmentUnsupported) {
				logger.Warn(ctx, "Left an attempt preparation for the next pass",
					tag.RunID(p.Run.ID), tag.AttemptID(p.AttemptID), tag.Error(err))
			}
		default:
			logger.Warn(ctx, "Left a prepared attempt for review",
				tag.RunID(p.Run.ID), tag.AttemptID(p.AttemptID), tag.Error(err))
		}
	}
	h.inFlightPreparationsMu.Lock()
	h.inFlightPreparations = inFlight
	h.inFlightPreparationsMu.Unlock()
}

// abandonedPreparationDetail is the reason an abandoned attempt records and
// its run shows. It covers both ways a prepared attempt is never handed to a
// worker, and tells the owner the run may be started again.
const abandonedPreparationDetail = "not dispatched: no worker claimed it before its dispatch expired, " +
	"or the coordinator stopped before publishing it; nothing ran, so it can be started again"

// preparationKey identifies a journal entry for in-memory bookkeeping.
func preparationKey(p persis.AttemptPreparation) string {
	return p.RootRun.Name + "\x00" + p.RootRun.ID + "\x00" + p.Run.Name + "\x00" + p.Run.ID + "\x00" + p.AttemptID + "\x00" + p.QueuedAt
}

// wasInFlight reports whether the previous reconciliation pass found the entry
// possibly with a worker.
func (h *Handler) wasInFlight(key string) bool {
	h.inFlightPreparationsMu.Lock()
	defer h.inFlightPreparationsMu.Unlock()
	_, ok := h.inFlightPreparations[key]
	return ok
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
	record, err := h.dagRunRepository.ReadExecutionAbandonment(ctx, run, root, attemptID, executionMarker)
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
	if _, err := h.abandonExecutionLocked(ctx, failed.run, root, failed.attemptID, "",
		"not dispatched: preparing the attempt failed: "+failed.err.Error(), nil); err != nil {
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
