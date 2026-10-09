// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package worker

import (
	"context"
	"testing"

	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
	"github.com/stretchr/testify/assert"
)

// A queued retry reuses the attempt key, so a cancellation that names an
// execution marker must cancel only that execution. A directive without a
// marker keeps cancelling whatever runs under the key.
func TestProcessCancellationsScopesToExecutionMarker(t *testing.T) {
	t.Parallel()

	const key = "attempt-key"
	marker := func(s string) *string { return &s }

	tests := []struct {
		name      string
		running   string
		directive *coordinatorv1.CancelledRun
		cancelled bool
	}{
		{"earlier execution's directive spares the current one", "q2", &coordinatorv1.CancelledRun{AttemptKey: key, ExecutionMarker: marker("q1")}, false},
		{"matching marker cancels", "q2", &coordinatorv1.CancelledRun{AttemptKey: key, ExecutionMarker: marker("q2")}, true},
		{"empty marker names a direct start", "", &coordinatorv1.CancelledRun{AttemptKey: key, ExecutionMarker: marker("")}, true},
		{"empty marker spares a queued execution", "q2", &coordinatorv1.CancelledRun{AttemptKey: key, ExecutionMarker: marker("")}, false},
		{"no marker cancels by key", "q2", &coordinatorv1.CancelledRun{AttemptKey: key}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w := &Worker{
				runningTasks: map[string]*runningTaskState{
					key: {task: &coordinatorv1.RunningTask{AttemptKey: key, ExecutionMarker: tc.running}},
				},
				cancelFuncs: map[string]context.CancelFunc{key: cancel},
			}

			w.processCancellations(context.Background(), []*coordinatorv1.CancelledRun{tc.directive})
			assert.Equal(t, tc.cancelled, ctx.Err() != nil)
		})
	}
}
