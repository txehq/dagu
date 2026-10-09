// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/gofrs/flock"
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
func TestStatusFileCompactionHoldsTheLockFromReadToRename(t *testing.T) {
	ctx := context.Background()
	file, owner := statusFileWithHistory(t)

	probed := false
	lockedDuringWindow := false
	compactionReadHook = func(statusFile string) {
		if statusFile != file || probed {
			return
		}
		probed = true
		probe := flock.New(statusLockPath(file))
		got, err := probe.TryLock()
		require.NoError(t, err)
		lockedDuringWindow = !got
		if got {
			_ = probe.Unlock()
		}
		_ = probe.Close()
	}
	t.Cleanup(func() { compactionReadHook = nil })

	require.NoError(t, owner.Close(ctx))
	require.True(t, probed, "compaction must run")
	assert.True(t, lockedDuringWindow, "no other handle may take the status lock between compaction's read and its rename")
}

func TestStatusFileAppendWaitsForTheLock(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	file, owner := statusFileWithHistory(t)
	t.Cleanup(func() { _ = owner.Close(ctx) })

	held := flock.New(statusLockPath(file))
	require.NoError(t, held.Lock())
	written := make(chan error, 1)
	go func() { written <- owner.Write(ctx, createTestStatus(ir.Queued)) }()
	select {
	case err := <-written:
		_ = held.Unlock()
		require.FailNow(t, "the append did not wait for the status lock", "err: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	require.NoError(t, held.Unlock())
	_ = held.Close()
	require.NoError(t, <-written)
	assert.Equal(t, ir.Queued, latestStatusOf(t, file))
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

// A replacement that cannot be opened leaves the writer on its current
// descriptor; once the replacement can be opened, the next write reopens it.
func TestStatusFileWriterRecoversFromAFailedReopen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions cannot make a file unopenable for its owner on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root opens files regardless of permissions")
	}
	t.Parallel()

	ctx := context.Background()
	file, owner := statusFileWithHistory(t)
	other, err := NewAttempt(file, nil)
	require.NoError(t, err)
	require.NoError(t, other.Open(ctx))
	t.Cleanup(func() { _ = other.Close(ctx) })
	require.NoError(t, owner.Close(ctx)) // compacts: replaces the file

	require.NoError(t, os.Chmod(file, 0o000))
	require.Error(t, other.Write(ctx, createTestStatus(ir.Queued)))
	require.NoError(t, os.Chmod(file, 0o600))

	require.NoError(t, other.Write(ctx, createTestStatus(ir.Queued)))
	assert.Equal(t, ir.Queued, latestStatusOf(t, file))
}
