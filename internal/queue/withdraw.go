// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package queue

import (
	"context"
	"errors"
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

// Withdrawal is what WithdrawQueuedExecution did.
type Withdrawal int

const (
	// WithdrawalJournaled: the execution is journaled as a preparation and
	// its queue item removed. Its status is unchanged. The coordinator's
	// reconciliation decides it under its own fence (neverDispatchedEvidence
	// and abandonExecutionLocked): failed with an execution-scoped
	// abandonment record once nothing of it was ever handed to a worker,
	// left alone while a task, lease or active run may hold it.
	WithdrawalJournaled Withdrawal = iota
	// WithdrawalStale: the run's latest execution is no longer this queued
	// one, so only the stale queue item was removed.
	WithdrawalStale
	// WithdrawalUnjournaled: the store keeps no preparation journal. The
	// queue item was removed and the status left as it is: whether the
	// execution was ever dispatched stays unknown, and nothing records that
	// it was not.
	WithdrawalUnjournaled
)

// WithdrawQueuedExecution takes the queued execution marked queuedAt of
// attemptID out of its queue, as a queue does with a run it refuses to
// dispatch, without deciding whether it was ever dispatched (TXE-8596).
//
// The queue item can outlive an earlier dispatch of the same execution: a
// deletion that failed, or a scheduler that stopped before deleting it. The
// coordinator may then hold a live task, lease or active run for it while its
// status still reads queued, and only the coordinator's own stores, read
// under its lock against acknowledgement, can say. So nothing here writes the
// status, and nothing records the execution as not dispatched. The execution
// is journaled first (persis.DAGRunRepository.BeginAttemptPreparation, which
// is idempotent) and its queue item removed after, so the coordinator never
// finds the item gone and the execution unjournaled.
func WithdrawQueuedExecution(ctx context.Context, runs *persis.DAGRunRepository, queues QueueStore, queueName string, run, root ir.DAGRunRef, attemptID, queuedAt, itemID string) (Withdrawal, error) {
	if runs == nil || queues == nil {
		return 0, errors.New("withdraw queued execution: run and queue stores are required")
	}
	if itemID == "" {
		return 0, errors.New("withdraw queued execution: missing queue item ID")
	}
	if root.Zero() {
		root = run
	}
	out := WithdrawalJournaled
	_, err := runs.BeginAttemptPreparation(ctx, run, root, attemptID, queuedAt)
	switch {
	case err == nil:
	case errors.Is(err, persis.ErrAttemptNotAbandonable):
		out = WithdrawalStale
	case errors.Is(err, persis.ErrAttemptAbandonmentUnsupported):
		out = WithdrawalUnjournaled
	default:
		return 0, fmt.Errorf("journal the withdrawn queued execution: %w", err)
	}
	if _, err := queues.DeleteByItemIDs(ctx, queueName, []string{itemID}); err != nil {
		return 0, fmt.Errorf("dequeue the withdrawn queued execution: %w", err)
	}
	return out, nil
}
