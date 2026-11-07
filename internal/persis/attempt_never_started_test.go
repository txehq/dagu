// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package persis_test

import (
	"testing"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/stretchr/testify/assert"
)

// An attempt never started when no worker took it and it is NotStarted, or
// a direct start the coordinator held, Queued with its empty marker. A run
// the scheduler's queue holds carries a marker, and anything a worker took
// or that moved on did start.
func TestAttemptNeverStarted(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		status *ir.DAGRunStatus
		want   bool
	}{
		"no status":                   {nil, false},
		"not started":                 {&ir.DAGRunStatus{Status: ir.NotStarted}, true},
		"held direct start":           {&ir.DAGRunStatus{Status: ir.Queued}, true},
		"queued by the scheduler":     {&ir.DAGRunStatus{Status: ir.Queued, QueuedAt: "2026-11-08T01:00:00Z"}, false},
		"not started but taken":       {&ir.DAGRunStatus{Status: ir.NotStarted, WorkerID: "worker-1"}, false},
		"held direct start but taken": {&ir.DAGRunStatus{Status: ir.Queued, WorkerID: "worker-1"}, false},
		"running":                     {&ir.DAGRunStatus{Status: ir.Running}, false},
		"failed":                      {&ir.DAGRunStatus{Status: ir.Failed}, false},
	} {
		assert.Equal(t, tc.want, persis.AttemptNeverStarted(tc.status), name)
	}
}
