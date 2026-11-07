// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package distr_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// holdFile makes path unreadable by any other handle for the rest of the
// test, as a process holding it does: it takes an exclusive byte-range lock
// over the whole file. Windows enforces such a lock against every other
// handle, the locking process's own included, so a read through another
// handle fails. (A share mode of zero on the holding handle is not relied
// on: the CI runner has let a second read-only open through.)
func holdFile(t *testing.T, path string) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	var overlapped windows.Overlapped
	require.NoError(t, windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, ^uint32(0), ^uint32(0), &overlapped))
	t.Cleanup(func() { _ = windows.UnlockFileEx(handle, 0, ^uint32(0), ^uint32(0), &overlapped) })
	_, err = os.ReadFile(path)
	require.Error(t, err, "the held file cannot be read through another handle")
}

// holdDirectory opens the directory with no sharing, as the store does while
// it renames a lock directory on release. It reports whether this Windows
// then refuses to list the directory; where it does not, the directory case
// cannot be exercised here and the file case stands for it.
func holdDirectory(t *testing.T, path string) bool {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	if _, err := os.ReadDir(path); err == nil {
		t.Logf("this Windows lists a directory held with no sharing; the directory case is not exercised")
		return false
	}
	return true
}

// The live hub holds its lock metadata: reading it is a sharing or lock
// violation. Lock metadata is passed over, so the scan still reads every
// record.
func TestStorageScanPassesOverHeldLockMetadata(t *testing.T) {
	t.Parallel()
	f := newScanFixture(t)
	holdFile(t, f.owner)
	found, err := storageFilesContaining([]string{f.root}, `"id":"run-1"`)
	require.NoError(t, err, "a held lock token does not fail the scan")
	assert.Equal(t, []string{f.record}, found)

	if holdDirectory(t, f.lockDir) {
		found, err = storageFilesContaining([]string{f.root}, `"id":"run-1"`)
		require.NoError(t, err, "a held lock directory does not fail the scan")
		assert.Equal(t, []string{f.record}, found)
	}
}

// A record held so that it cannot be read is a failure of the scan, not
// something passed over: an unread record proves nothing about its content.
// A data file named like a lock is no lock metadata either.
func TestStorageScanFailsOnHeldData(t *testing.T) {
	t.Parallel()
	f := newScanFixture(t)
	holdFile(t, f.record)
	_, err := storageFilesContaining([]string{f.root}, "anything")
	require.Error(t, err)
	assert.ErrorContains(t, err, "run-1.json")

	lookalike := filepath.Join(f.root, "artifacts", "run-1", "report.lock")
	require.NoError(t, os.MkdirAll(filepath.Dir(lookalike), 0o750))
	require.NoError(t, os.WriteFile(lookalike, []byte("x"), 0o600))
	holdFile(t, lookalike)
	_, err = storageFilesContaining([]string{filepath.Join(f.root, "artifacts")}, "anything")
	require.Error(t, err)
	assert.ErrorContains(t, err, "report.lock")
}
