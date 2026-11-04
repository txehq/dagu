package distr_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/stretchr/testify/require"
)

// A coordinator-cancelled step gets its graceful TERM, so a trap that cleans
// up runs before the step is gone, as it does when the worker itself stops
// (TestCancellation_WorkerStopDrainsRun). TXE-4262.
func TestCancellation_CoordinatorCancelRunsTheStepsTrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell trap")
	}
	dir := t.TempDir()
	trapMarker := filepath.Join(dir, "trap")
	readyMarker := filepath.Join(dir, "ready")
	f := newTestFixture(t, fmt.Sprintf(`
name: coordinator-cancel-trap
worker_selector:
  test: "true"
max_clean_up_time_sec: 10
steps:
  - name: long
    run: |
      trap 'touch %s; exit 1' TERM
      touch %s
      sleep 30 &
      wait
`, test.ShellQuote(trapMarker), test.ShellQuote(readyMarker)))
	defer f.cleanup()
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(30 * time.Second)
	f.waitForStatus(ir.Running, 20*time.Second)
	require.Eventually(t, func() bool {
		_, err := os.Stat(readyMarker)
		return err == nil
	}, 20*time.Second, 50*time.Millisecond, "step should install its trap")

	var dagRunID string
	require.Eventually(t, func() bool {
		status, err := f.latestStatus()
		if err != nil || status.Status != ir.Running {
			return false
		}
		dagRunID = status.DAGRunID
		return dagRunID != ""
	}, 10*time.Second, 100*time.Millisecond)

	require.NoError(t, f.stop(dagRunID))
	f.waitForStatusIn([]ir.Status{ir.Aborted, ir.Failed}, 15*time.Second)
	f.waitForRunReleasedFromWorkers(dagRunID, 10*time.Second)

	require.FileExists(t, trapMarker, "the step's TERM trap should have run before the step was gone")
}
