// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package scheduler

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	queuedomain "github.com/dagucloud/dagu/v2/internal/queue"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// RunAdmitter is the TXE job registry's run guard. Runs of registered jobs
// start only when it admits them; other DAGs are unaffected.
type RunAdmitter interface {
	AdmitRun(ctx context.Context, dagName, specSHA256 string) (registry.Admission, error)
	AdmitQueuedRetry(ctx context.Context, jobID string, q registry.QueuedRetry) (registry.Admission, error)
	RecordDroppedRun(ctx context.Context, jobID, runID string, adm registry.Admission) error
	ReconcileExpired(ctx context.Context) ([]string, error)
	ReconcileEffects(ctx context.Context) error
	ReconcileResourceEvents(ctx context.Context) error
	RebuildResourceIndex(ctx context.Context) error
}

const txeReconcileInterval = time.Minute

// enableRunAdmission makes scheduling, catch-up and retry treat a job the
// registry does not admit as suspended, and makes queue dispatch refuse its
// queued runs whatever their trigger.
func (s *Scheduler) enableRunAdmission(a RunAdmitter) {
	s.runAdmitter = a
	s.planner.cfg.IsSuspended = withRunAdmission(s.planner.cfg.IsSuspended, a)
	if s.retryScanner != nil {
		s.retryScanner.isSuspended = withRunAdmission(s.retryScanner.isSuspended, a)
	}
	s.queueProcessor.runAdmitter = a
}

// withRunAdmission reports a registered job as suspended unless the registry
// admits a run now. Errors propagate, and every caller treats them as "do not
// dispatch".
func withRunAdmission(isSuspended IsSuspendedFunc, a RunAdmitter) IsSuspendedFunc {
	return func(ctx context.Context, dagName string) (bool, error) {
		if isSuspended != nil {
			suspended, err := isSuspended(ctx, dagName)
			if err != nil || suspended {
				return suspended, err
			}
		}
		if !registry.IsJobDAG(dagName) {
			return false, nil
		}
		adm, err := a.AdmitRun(ctx, dagName, "")
		if err != nil {
			return false, err
		}
		return !adm.Admit, nil
	}
}

// specDigest is the digest the registry records for a job's DAG spec.
func specDigest(dag *ir.DAG) string {
	if dag == nil || len(dag.YamlData) == 0 {
		return ""
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(dag.YamlData))
}

// admitQueuedRun applies the registry guard to a queued run of any trigger.
// It returns false when the run must not be dispatched now; a refused run is
// finalized as aborted with the registry's reason and noted on the job, and
// a refused retry that carries a retry request is withdrawn from its queue
// instead (withdrawRefusedRetry), for the coordinator to decide, so that it
// is never read as having run.
func (d *queueDispatcher) admitQueuedRun(
	ctx context.Context,
	queueName string,
	runRef ir.DAGRunRef,
	itemID string,
	attemptID string,
	status *ir.DAGRunStatus,
	dag *ir.DAG,
) bool {
	if d.runAdmitter == nil {
		return true
	}
	name := suspendFlagName(status, dag, "")
	if !registry.IsJobDAG(name) {
		return true
	}
	adm, err := d.runAdmitter.AdmitRun(ctx, name, specDigest(dag))
	if err != nil {
		logger.Error(ctx, "Failed to check TXE job admission; leaving queued run pending", tag.Error(err))
		return false
	}
	if adm.Admit && status.TriggerType == ir.TriggerTypeRetry {
		adm, err = d.admitQueuedRetry(ctx, adm.JobID, ir.NewDAGRunRef(name, runRef.ID), status)
		if err != nil {
			logger.Error(ctx, "Failed to check TXE retry request; leaving queued run pending", tag.Error(err))
			return false
		}
	}
	if adm.Admit && d.dagExecutor != nil && !d.dagExecutor.IsDistributed(dag) {
		// Registered jobs run only through their machine's worker, where the
		// claim is admitted and recorded against retirement.
		adm = registry.Admission{JobID: adm.JobID, Code: registry.AdmitNotOnWorker, Reason: "registered jobs run only on their machine's worker"}
	}
	if adm.Admit {
		return true
	}
	reason := fmt.Sprintf("txe: job %s %s: %s", adm.JobID, adm.Code, adm.Reason)
	drop := d.dropQueuedRun
	if status.TriggerType == ir.TriggerTypeRetry && status.RetryRequest != nil {
		drop = d.withdrawRefusedRetry
	}
	if err := drop(ctx, queueName, runRef, itemID, attemptID, status, reason); err != nil {
		logger.Error(ctx, "Failed to drop queued run refused by TXE registry", tag.Error(err))
		return false
	}
	if err := d.runAdmitter.RecordDroppedRun(ctx, adm.JobID, runRef.ID, adm); err != nil {
		logger.Warn(ctx, "Failed to record dropped run on TXE job", tag.Error(err))
	}
	logger.Info(ctx, "Dropped queued run refused by TXE registry",
		slog.String("job_id", adm.JobID), slog.String("code", string(adm.Code)))
	return false
}

// admitQueuedRetry decides a queued retry of a registered job's run, which
// would run one of its executions again. It starts only for the retry
// request the hub recorded when it admitted a retry made for a person's
// approved dagu.retry_run decision (TXE-7517): a retry queued without one,
// such as by the local CLI, or with one that was not made for this run's
// retried execution, is refused. The request must name an execution of the
// run that the queued retry replaced and kept, and its ID must be the one the
// hub derives from that execution and the action attempt
// (ir.NewRetryRequest), so a request cannot be moved to another run or
// execution. The registry then binds that request to its action now, at
// dispatch, as the hub binds it at admission (registry.AdmitQueuedRetry):
// the action, attempt, version, run and execution, a grant that is still
// live, and the rerun intent.
//
// Trust boundary: this binds what a supported command can queue. It does not
// defend against anyone who can write the data dir, who can edit the
// registry and the run's status alike, or run arbitrary code on the host.
func (d *queueDispatcher) admitQueuedRetry(ctx context.Context, jobID string, run ir.DAGRunRef, status *ir.DAGRunStatus) (registry.Admission, error) {
	request := status.RetryRequest
	if request == nil {
		return registry.Admission{JobID: jobID, Code: registry.AdmitRetryUnbound,
			Reason: "a retry of a registered job's run needs the retry request of an approved decision; retry it from the job's TXE controls"}, nil
	}
	mismatch := func(reason string) (registry.Admission, error) {
		return registry.Admission{JobID: jobID, Code: registry.AdmitRetryMismatch, Reason: reason}, nil
	}
	if d.dagRunRepository == nil {
		return registry.Admission{}, errors.New("no DAG-run repository to read the retried execution from")
	}
	retained, err := d.dagRunRepository.ListRetainedExecutions(ctx, run)
	if err != nil {
		return registry.Admission{}, fmt.Errorf("list retained executions: %w", err)
	}
	var retried *persis.RetainedExecution
	for i := range retained {
		if retained[i].Execution == request.RetryOf && retained[i].AttemptID == status.AttemptID {
			retried = &retained[i]
			break
		}
	}
	if retried == nil {
		return mismatch(fmt.Sprintf("retry request %s names no execution of run %s this retry replaced", request.ID, run.ID))
	}
	derived, err := ir.NewRetryRequest(run, retried.AttemptID, retried.QueuedAt, request.ActionID, request.ActionAttempt, request.BindingDigest)
	if err != nil || derived.ID != request.ID || derived.RetryOf != request.RetryOf {
		return mismatch(fmt.Sprintf("retry request %s was not made for execution %s of run %s", request.ID, request.RetryOf, run.ID))
	}
	return d.runAdmitter.AdmitQueuedRetry(ctx, jobID, registry.QueuedRetry{
		RunID: run.ID, AttemptID: retried.AttemptID, QueuedAt: retried.QueuedAt, Request: *request,
	})
}

// withdrawRefusedRetry takes a queued retry that carries a retry request,
// and that admission refused, out of its queue without marking it aborted
// (TXE-8596). An aborted execution reads like one that started and was then
// stopped, so the retry could be recorded as having run.
//
// Nor does it record the execution as never dispatched: the queue item can
// outlive an earlier handoff of the same execution (a deletion that failed,
// or a scheduler that stopped before deleting it), and the coordinator may
// then hold a live task, lease or active run for it while its status still
// reads queued. queue.WithdrawQueuedExecution journals the execution and
// removes the item; the coordinator's reconciliation then fails it with an
// execution-scoped abandonment record only once its own stores, read under
// its lock against acknowledgement, show nothing was handed to a worker. Until
// then the retry is pending: the registry records it neither as succeeded
// (the execution is queued and journaled) nor as not applied (no record).
func (d *queueDispatcher) withdrawRefusedRetry(
	ctx context.Context,
	queueName string,
	runRef ir.DAGRunRef,
	itemID string,
	attemptID string,
	status *ir.DAGRunStatus,
	_ string,
) error {
	root := status.Root
	if root.Zero() {
		root = runRef
	}
	withdrawn, err := queuedomain.WithdrawQueuedExecution(ctx, d.dagRunRepository, d.queueStore, queueName, runRef, root, attemptID, status.QueuedAt, itemID)
	if err != nil {
		return err
	}
	switch withdrawn {
	case queuedomain.WithdrawalStale:
		logger.Info(ctx, "Removed stale queued TXE retry refused by the registry")
	case queuedomain.WithdrawalUnjournaled:
		logger.Warn(ctx, "Withdrew a refused queued TXE retry that this store cannot journal; whether it was dispatched stays unknown")
	case queuedomain.WithdrawalJournaled:
	}
	return nil
}

// startTxeReconciler keeps the registry and Dagu converged: it indexes the
// targets of jobs registered before resource events existed, then every
// interval retires jobs whose lifetime has ended, applies lifecycle effects
// that are pending or were lost, and completes resource events whose
// application was cut short.
func (s *Scheduler) startTxeReconciler(ctx context.Context) {
	if s.runAdmitter == nil {
		return
	}
	indexed := false
	ticker := time.NewTicker(txeReconcileInterval)
	defer ticker.Stop()
	for {
		if !indexed {
			if err := s.runAdmitter.RebuildResourceIndex(ctx); err != nil {
				logger.Warn(ctx, "TXE resource index rebuild incomplete; retrying next interval", tag.Error(err))
			} else {
				indexed = true
			}
		}
		retired, err := s.runAdmitter.ReconcileExpired(ctx)
		if err != nil {
			logger.Warn(ctx, "TXE expiry reconciliation incomplete", tag.Error(err))
		}
		if len(retired) > 0 {
			logger.Info(ctx, "Retired expired TXE jobs", slog.Any("job_ids", retired))
		}
		if err := s.runAdmitter.ReconcileEffects(ctx); err != nil {
			logger.Warn(ctx, "TXE lifecycle effects not all applied", tag.Error(err))
		}
		if err := s.runAdmitter.ReconcileResourceEvents(ctx); err != nil {
			logger.Warn(ctx, "TXE resource events not all applied", tag.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-s.quit:
			return
		case <-ticker.C:
		}
	}
}

// WithRunAdmitter sets the TXE registry guard used by queue dispatch.
func WithRunAdmitter(a RunAdmitter) QueueProcessorOption {
	return func(p *QueueProcessor) {
		p.runAdmitter = a
	}
}

// ErrJobRequiresWorker refuses running a registered job in the scheduler's
// process: jobs run only through their machine's worker, where the claim is
// admitted and recorded against retirement.
var ErrJobRequiresWorker = errors.New("txe: registered jobs run only on their machine's worker")

// refuseLocalJobRun is the worker-only rule at the scheduler's execution
// handoff, so scheduled starts dispatched without a queue are covered too.
func refuseLocalJobRun(dag *ir.DAG) error {
	if dag != nil && (registry.IsJobDAG(dag.SuspendFlagName()) || registry.IsJobDAG(dag.Name)) {
		return fmt.Errorf("%w: %s", ErrJobRequiresWorker, dag.SuspendFlagName())
	}
	return nil
}
