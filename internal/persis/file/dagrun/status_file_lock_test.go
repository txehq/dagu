// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Two handles on one status file, as the coordinator's cached attempt and a
// store compare-and-swap (or another process) have. Compaction reads the file
// and renames a rewritten copy over it; nothing appended by the other handle
// may be lost, wherever the append falls.

func statusFileWithHistory(t *testing.T) (string, *Attempt) {
	t.Helper()
	ctx := context.Background()
	file := filepath.Join(createTempDir(t), JSONLStatusFile)
	owner, err := NewAttempt(file, nil)
	require.NoError(t, err)
	require.NoError(t, owner.Open(ctx))
	running := createTestStatus(ir.Running)
	require.NoError(t, owner.Write(ctx, running))
	// A second line makes Close compact the file.
	require.NoError(t, owner.Write(ctx, running))
	return file, owner
}

func latestStatusOf(t *testing.T, file string) ir.Status {
	t.Helper()
	reader, err := NewAttempt(file, nil)
	require.NoError(t, err)
	st, err := reader.ReadStatus(context.Background())
	require.NoError(t, err)
	return st.Status
}

// Not parallel: the hook is package state.
func TestStatusFileCompactionKeepsAppendFromInsideItsWindow(t *testing.T) {
	ctx := context.Background()
	file, owner := statusFileWithHistory(t)
	other, err := NewAttempt(file, nil)
	require.NoError(t, err)
	require.NoError(t, other.Open(ctx))

	appended := make(chan error, 1)
	completedInWindow := false
	fired := false
	compactionReadHook = func(statusFile string) {
		if statusFile != file || fired {
			return
		}
		fired = true
		// The other handle appends after compaction has read the file and
		// before it renames the rewritten copy over it.
		go func() { appended <- other.Write(ctx, createTestStatus(ir.Queued)) }()
		select {
		case err := <-appended:
			completedInWindow = true
			appended <- err
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Cleanup(func() { compactionReadHook = nil })

	require.NoError(t, owner.Close(ctx))
	require.True(t, fired, "compaction must run")
	require.NoError(t, <-appended)
	require.NoError(t, other.Close(ctx))

	assert.False(t, completedInWindow, "the append must wait for the compaction to finish")
	assert.Equal(t, ir.Queued, latestStatusOf(t, file), "the append must survive the compaction")
}

func TestStatusFileWriterReopensAfterAnotherHandleCompacts(t *testing.T) {
	ctx := context.Background()
	file, owner := statusFileWithHistory(t)
	// Opened before the compaction, so its descriptor refers to the file that
	// the compaction replaces.
	other, err := NewAttempt(file, nil)
	require.NoError(t, err)
	require.NoError(t, other.Open(ctx))

	require.NoError(t, owner.Close(ctx))
	require.NoError(t, other.Write(ctx, createTestStatus(ir.Queued)))
	require.NoError(t, other.Close(ctx))

	assert.Equal(t, ir.Queued, latestStatusOf(t, file))
}
