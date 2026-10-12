// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package persis

import (
	"context"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

// RetryRequestState says what became of the execution a retry request
// admitted.
type RetryRequestState string

const (
	// RetryRequestAdmitted: the execution exists (current, or a retained
	// copy of one a later queued retry replaced).
	RetryRequestAdmitted RetryRequestState = "admitted"
	// RetryRequestAbandoned: the execution was a preparation the coordinator
	// abandoned; Abandonment is its record.
	RetryRequestAbandoned RetryRequestState = "abandoned"
)

// RetryRequestMatch is the execution of a run that recorded a retry request.
type RetryRequestMatch struct {
	State     RetryRequestState
	Execution ExecutionIdentity
	// Retained is true when Status is a retained copy of an execution a
	// later queued retry replaced.
	Retained    bool
	Status      ir.DAGRunStatus
	Abandonment *AttemptAbandonment
}

// DAGRunRetryRequestFinder is implemented by stores that can find the
// execution that recorded a retry request.
type DAGRunRetryRequestFinder interface {
	// FindRetryRequest returns the run's execution whose status records
	// retry request id, or ErrNotFound when none does. A status or record
	// that cannot be read is an error, never absent.
	FindRetryRequest(ctx context.Context, root, dagRun ir.DAGRunRef, id string) (*RetryRequestMatch, error)
}

// FindRetryRequest finds the root run's execution that recorded retry
// request id (see DAGRunRetryRequestFinder).
func (r *DAGRunRepository) FindRetryRequest(ctx context.Context, dagRun ir.DAGRunRef, id string) (*RetryRequestMatch, error) {
	finder, ok := r.store.(DAGRunRetryRequestFinder)
	if !ok {
		return nil, ErrAttemptAbandonmentUnsupported
	}
	return finder.FindRetryRequest(ctx, dagRun, dagRun, id)
}
