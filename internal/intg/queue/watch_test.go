// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package queue_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A DAG that watches a folder runs once for each file that arrives there,
// with the file as WATCH_FILE and WATCH_NAME, through the scheduler the
// command starts: the folder is read, the file is given time to hold
// still, and its run is queued and processed.
func TestWatchedFolderStartsARunPerFile(t *testing.T) {
	inbox := t.TempDir()
	done := filepath.Join(t.TempDir(), "done")
	require.NoError(t, os.WriteFile(filepath.Join(inbox, "already-there.txt"), []byte("old"), 0o600))

	f := newFixture(t, `
name: inbox
watch:
  path: `+yamlString(inbox)+`
  pattern: "*.txt"
  interval: 1s
steps:
  - id: keep
    action: file.copy
    with:
      source: ${WATCH_FILE}
      destination: `+yamlString(filepath.ToSlash(done)+"/${WATCH_NAME}")+`
      create_dirs: true
`).StartScheduler(60 * time.Second)
	defer f.Stop()

	// The scheduler reads the folder before the file arrives, so the file
	// already there is left alone and the new one is seen arriving.
	f.h.Wait.EventuallyEveryWithin("the folder is read", 20*time.Second, 200*time.Millisecond, func() bool {
		record, err := f.th.Backend.Collection(persis.CollectionWatchState).Get(f.th.Context, "watch")
		return err == nil && strings.Contains(string(record.Data), `"inbox"`)
	})
	require.NoError(t, os.WriteFile(filepath.Join(inbox, "order-1.txt"), []byte("new"), 0o600))

	var statuses []ir.DAGRunStatus
	f.h.Wait.EventuallyEveryWithin("the file's run finishes", 40*time.Second, 200*time.Millisecond, func() bool {
		var err error
		statuses, err = f.th.DAGRunRepository.RecentStatuses(f.th.Context, "inbox", 5)
		return err == nil && len(statuses) > 0 && statuses[0].Status != ir.Queued && statuses[0].Status != ir.Running
	})
	require.Len(t, statuses, 1, "one run for the file that arrived, none for the one already there")
	for _, node := range statuses[0].Nodes {
		assert.Empty(t, node.Error, "step %s", node.Step.Name)
	}
	assert.Equal(t, ir.Succeeded, statuses[0].Status)
	assert.Equal(t, ir.TriggerTypeFile, statuses[0].TriggerType)
	data, err := os.ReadFile(filepath.Join(done, "order-1.txt"))
	require.NoError(t, err)
	assert.Equal(t, "new", string(data))
	_, err = os.Stat(filepath.Join(done, "already-there.txt"))
	assert.True(t, os.IsNotExist(err))
}

// A file moved out of the watched folder, seen gone, and moved back
// unchanged is a second arrival: the scheduler queues a second run for it,
// under another run ID, though its size and time are what they were.
func TestWatchedFolderRunsAFileThatCameBackUnchanged(t *testing.T) {
	inbox := t.TempDir()
	away := filepath.Join(t.TempDir(), "order-1.txt")
	done := filepath.Join(t.TempDir(), "done")

	f := newFixture(t, `
name: inbox
watch:
  path: `+yamlString(inbox)+`
  interval: 1s
steps:
  - id: keep
    action: file.copy
    with:
      source: ${WATCH_FILE}
      destination: `+yamlString(filepath.ToSlash(done)+"/${WATCH_NAME}")+`
      create_dirs: true
      overwrite: true
`).StartScheduler(90 * time.Second)
	defer f.Stop()

	watchRecord := func() string {
		record, err := f.th.Backend.Collection(persis.CollectionWatchState).Get(f.th.Context, "watch")
		if err != nil {
			return ""
		}
		return string(record.Data)
	}
	finished := func(want int) []ir.DAGRunStatus {
		var statuses []ir.DAGRunStatus
		f.h.Wait.EventuallyEveryWithin("the file's runs finish", 40*time.Second, 200*time.Millisecond, func() bool {
			var err error
			statuses, err = f.th.DAGRunRepository.RecentStatuses(f.th.Context, "inbox", 5)
			if err != nil || len(statuses) < want {
				return false
			}
			for _, status := range statuses {
				if status.Status == ir.Queued || status.Status == ir.Running {
					return false
				}
			}
			return true
		})
		return statuses
	}

	f.h.Wait.EventuallyEveryWithin("the folder is read", 20*time.Second, 200*time.Millisecond, func() bool {
		return strings.Contains(watchRecord(), `"inbox"`)
	})
	path := filepath.Join(inbox, "order-1.txt")
	require.NoError(t, os.WriteFile(path, []byte("new"), 0o600))
	require.Len(t, finished(1), 1)

	require.NoError(t, os.Rename(path, away))
	f.h.Wait.EventuallyEveryWithin("the scheduler sees the file gone", 20*time.Second, 200*time.Millisecond, func() bool {
		record := watchRecord()
		return strings.Contains(record, `"inbox"`) && !strings.Contains(record, `"order-1.txt"`)
	})
	require.NoError(t, os.Rename(away, path))

	statuses := finished(2)
	require.Len(t, statuses, 2, "one run for each arrival")
	assert.NotEqual(t, statuses[0].DAGRunID, statuses[1].DAGRunID)
	for _, status := range statuses {
		assert.Equal(t, ir.Succeeded, status.Status)
		assert.Equal(t, ir.TriggerTypeFile, status.TriggerType)
	}
}

// yamlString quotes a path for YAML, backslashes included.
func yamlString(s string) string {
	return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"`
}
