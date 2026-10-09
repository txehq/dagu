// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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

// Not parallel: the hook is package state.
func TestStatusFileAppendHoldsTheLock(t *testing.T) {
	ctx := context.Background()
	file, owner := statusFileWithHistory(t)
	t.Cleanup(func() { _ = owner.Close(ctx) })

	probed := false
	lockedDuringAppend := false
	appendLockedHook = func(target string) {
		if target != file || probed {
			return
		}
		probed = true
		probe := flock.New(statusLockPath(file))
		got, err := probe.TryLock()
		require.NoError(t, err)
		lockedDuringAppend = !got
		if got {
			_ = probe.Unlock()
		}
		_ = probe.Close()
	}
	t.Cleanup(func() { appendLockedHook = nil })

	require.NoError(t, owner.Write(ctx, createTestStatus(ir.Queued)))
	require.True(t, probed, "the append must reach its locked section")
	assert.True(t, lockedDuringAppend, "no other handle may take the status lock during an append")
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

func TestStatusFileWriteIfLatest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	file, owner := statusFileWithHistory(t)
	t.Cleanup(func() { _ = owner.Close(ctx) })
	other, err := NewAttempt(file, nil)
	require.NoError(t, err)
	require.NoError(t, other.Open(ctx))
	t.Cleanup(func() { _ = other.Close(ctx) })

	expectRunning := func(latest *ir.DAGRunStatus) error {
		if latest.Status != ir.Running {
			return errStatusChanged
		}
		return nil
	}

	// Accepted: the latest status is still the one expected.
	require.NoError(t, owner.WriteIfLatest(ctx, createTestStatus(ir.Running), expectRunning))

	// Another handle changes the status; the check sees it and nothing is
	// written.
	require.NoError(t, other.Write(ctx, createTestStatus(ir.Queued)))
	err = owner.WriteIfLatest(ctx, createTestStatus(ir.Running), expectRunning)
	require.ErrorIs(t, err, errStatusChanged)
	assert.Equal(t, ir.Queued, latestStatusOf(t, file))
}

func TestStatusFileWriteIfLatestChecksUnderTheLock(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	file, owner := statusFileWithHistory(t)
	t.Cleanup(func() { _ = owner.Close(ctx) })

	lockedDuringCheck := false
	require.NoError(t, owner.WriteIfLatest(ctx, createTestStatus(ir.Running), func(*ir.DAGRunStatus) error {
		probe := flock.New(statusLockPath(file))
		got, err := probe.TryLock()
		if err != nil {
			return err
		}
		lockedDuringCheck = !got
		if got {
			_ = probe.Unlock()
		}
		return probe.Close()
	}))
	assert.True(t, lockedDuringCheck, "the check must run while the status lock is held")
}

var errStatusChanged = errors.New("status changed")

// The tail reader returns what the full parser returns: the last complete line
// that decodes.
func TestParseLatestStatusFromTailMatchesFullParse(t *testing.T) {
	t.Parallel()

	line := func(st ir.Status) string {
		data, err := json.Marshal(createTestStatus(st))
		require.NoError(t, err)
		return string(data) + "\n"
	}
	long := createTestStatus(ir.Succeeded)
	long.Error = strings.Repeat("x", 3*statusTailChunk)
	longData, err := json.Marshal(long)
	require.NoError(t, err)

	cases := map[string]string{
		"valid lines":                         line(ir.Running) + line(ir.Failed),
		"invalid last line":                   line(ir.Running) + "{not json\n",
		"partial trailing line":               line(ir.Running) + `{"status":`,
		"complete record without its newline": line(ir.Running) + strings.TrimSuffix(line(ir.Failed), "\n"),
		"blank lines":                         line(ir.Failed) + "\n\n",
		"line longer than a chunk":            line(ir.Running) + string(longData) + "\n",
		"only invalid":                        "nope\n{\n",
		"empty":                               "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			file := filepath.Join(t.TempDir(), JSONLStatusFile)
			require.NoError(t, os.WriteFile(file, []byte(content), 0o600))
			want, wantErr := parseStatusFileWithContext(context.Background(), file)
			got, gotErr := parseLatestStatusFromTail(context.Background(), file)
			if wantErr != nil {
				require.ErrorIs(t, gotErr, io.EOF)
				require.ErrorIs(t, wantErr, io.EOF)
				return
			}
			require.NoError(t, gotErr)
			assert.Equal(t, want.Status, got.Status)
			assert.Equal(t, want.Error, got.Error)
		})
	}
}

// Not parallel: the counter is package state. A conditional write over a long
// history reads only the end of the file.
func TestStatusFileWriteIfLatestReadsOnlyTheTail(t *testing.T) {
	ctx := context.Background()
	file, owner := statusFileWithHistory(t)
	t.Cleanup(func() { _ = owner.Close(ctx) })
	for range 800 {
		require.NoError(t, owner.Write(ctx, createTestStatus(ir.Running)))
	}
	info, err := os.Stat(file)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(4*statusTailChunk), "the history must span several chunks")

	var read int64
	statusTailBytesRead = func(n int64) { read = n }
	t.Cleanup(func() { statusTailBytesRead = nil })
	require.NoError(t, owner.WriteIfLatest(ctx, createTestStatus(ir.Running), func(*ir.DAGRunStatus) error { return nil }))
	assert.LessOrEqual(t, read, int64(statusTailChunk), "only the last chunk is read")
}
