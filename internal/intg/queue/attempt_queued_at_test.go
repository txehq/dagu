// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package queue_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmd"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/stretchr/testify/require"
)

// A run taken from the local queue by the scheduler hands its steps the queue
// marker its stored status holds, in a DAG-level variable and in a command.
func TestAttemptQueuedAtReachesQueuedLocalRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses POSIX shell commands")
	}
	out := filepath.Join(t.TempDir(), "seen")
	f := newFixture(t, `
name: queued-marker
env:
  - QUEUED_AT: "${context.attempt.queued_at}"
steps:
  - name: record
    run: printf '%s|%s|%s' "${context.attempt.id}" "$QUEUED_AT" "${context.attempt.queued_at}" > `+out+`
`)
	// Enqueued by the command, so the queued status is written the way a
	// real enqueue writes it, marker included.
	runID := "queued-marker-run"
	f.th.RunCommand(t, cmd.Enqueue(), test.CmdTest{
		Args: []string{"enqueue", "--run-id", runID, filepath.Join(f.th.Config.Paths.DAGsDir, "test.yaml")},
	})
	f.runIDs = []string{runID}
	f.StartScheduler(30 * time.Second)
	defer f.Stop()

	f.WaitForStatus(runID, ir.Succeeded, 20*time.Second)
	status := f.MustStatus(runID)
	require.NotEmpty(t, status.QueuedAt, "an enqueued run has no marker; the test proves nothing")

	seen, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Equal(t, status.AttemptID+"|"+status.QueuedAt+"|"+status.QueuedAt, string(seen))
}
