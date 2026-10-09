// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/proto/convert"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// expectedLatest returns the execution a conditional retry requires to be the
// run's latest: the previous status's (attempt, queue marker). It is nil for
// any other task.
func expectedLatest(task *coordinatorv1.Task) (*persis.ExpectedExecution, error) {
	if !task.RequireLatestIsPrevious {
		return nil, nil
	}
	if task.Operation != coordinatorv1.Operation_OPERATION_RETRY {
		return nil, fmt.Errorf("%w: a conditional dispatch must be a retry", persis.ErrLatestExecutionChanged)
	}
	prev, err := convert.ProtoToDAGRunStatus(task.PreviousStatus)
	if err != nil {
		return nil, err
	}
	if prev == nil || prev.AttemptID == "" {
		return nil, fmt.Errorf("%w: a conditional retry needs the previous execution", persis.ErrLatestExecutionChanged)
	}
	return &persis.ExpectedExecution{AttemptID: prev.AttemptID, QueuedAt: prev.QueuedAt}, nil
}
