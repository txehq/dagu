// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/queue"
	"github.com/stretchr/testify/require"
)

// A retry queued the moment the hub shows the failure reuses the attempt id
// and key while the first execution may still be sending its last reports.
// Those late reports must not overwrite the queued status, so the retry runs.
// The race is timing-dependent and this test does not reproduce it reliably,
// so it checks the end-to-end property only; the coordinator's
// TestExecutionMarker* tests pin the mechanism deterministically.
func TestRetry_QueuedImmediatelyAfterFailureExecutes(t *testing.T) {
	const executions = 2
	for i := range 4 {
		t.Run(fmt.Sprintf("run%d", i), func(t *testing.T) {
			counter := filepath.Join(t.TempDir(), "executions")
			f := newTestFixture(t, fmt.Sprintf(`
type: graph
name: queued-retry-marker
worker_selector:
  test: "true"
steps:
  - name: count-and-fail
    run: echo x >> %q && exit 1
`, counter))
			defer f.cleanup()

			require.NoError(t, f.enqueue())
			f.waitForQueued()
			f.startScheduler(60 * time.Second)
			failed := f.waitForStatus(ir.Failed, distrTestTimeout(30*time.Second))

			// Retry without waiting for the worker to release the run.
			var queuedAt string
			require.Eventually(t, func() bool {
				st, err := f.latestStoredStatus()
				if err != nil || st.Status != ir.Failed {
					return false
				}
				added, err := queue.EnqueueRetry(f.coord.Context, f.coord.DAGRunRepository, f.coord.QueueStore,
					f.dagWrapper.DAG, &st, queue.EnqueueRetryOptions{Processes: f.coord.ProcRepository})
				if err != nil || !added {
					return false
				}
				queued, err := f.latestStoredStatus()
				if err == nil {
					queuedAt = queued.QueuedAt
				}
				return true
			}, distrTestTimeout(20*time.Second), 50*time.Millisecond, "retry should be admitted")

			require.Eventually(t, func() bool {
				data, err := os.ReadFile(counter)
				if err != nil || bytes.Count(data, []byte("x\n")) < executions {
					return false
				}
				st, err := f.latestStoredStatus()
				return err == nil && st.Status == ir.Failed
			}, distrTestTimeout(30*time.Second), 100*time.Millisecond, "the queued retry should execute")

			final, err := f.latestStoredStatus()
			require.NoError(t, err)
			require.Equal(t, failed.AttemptID, final.AttemptID, "a queued retry reuses the attempt")
			require.NotEqual(t, failed.QueuedAt, final.QueuedAt, "the final status belongs to the retry")
			if queuedAt != "" {
				require.Equal(t, queuedAt, final.QueuedAt)
			}
		})
	}
}
