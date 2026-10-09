// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package scheduler

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// RunAdmitter is the TXE job registry's run guard. Runs of registered jobs
// start only when it admits them; other DAGs are unaffected.
type RunAdmitter interface {
	AdmitRun(ctx context.Context, dagName, specSHA256 string) (registry.Admission, error)
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
// finalized as aborted with the registry's reason and noted on the job.
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
	if adm.Admit && d.dagExecutor != nil && !d.dagExecutor.IsDistributed(dag) {
		// Registered jobs run only through their machine's worker, where the
		// claim is admitted and recorded against retirement.
		adm = registry.Admission{JobID: adm.JobID, Code: registry.AdmitNotOnWorker, Reason: "registered jobs run only on their machine's worker"}
	}
	if adm.Admit {
		return true
	}
	reason := fmt.Sprintf("txe: job %s %s: %s", adm.JobID, adm.Code, adm.Reason)
	if err := d.dropQueuedRun(ctx, queueName, runRef, itemID, attemptID, status, reason); err != nil {
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
