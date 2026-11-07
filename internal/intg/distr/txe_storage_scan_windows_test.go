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

// holdExclusively opens path with no sharing, as a process holding a lock
// does, so that every other open of it fails with a sharing violation until
// the test ends. A directory is held the same way.
func holdExclusively(t *testing.T, path string, directory bool) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)
	var flags uint32 = windows.FILE_ATTRIBUTE_NORMAL
	if directory {
		flags = windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, flags, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	_, err = os.ReadFile(path)
	if !directory {
		require.Error(t, err, "the exclusive hold keeps others from reading the file")
	}
}

// The live hub holds its lock metadata open; on Windows that read is a
// sharing violation. Lock metadata is passed over, so the scan still reads
// every record.
func TestStorageScanPassesOverHeldLockMetadata(t *testing.T) {
	t.Parallel()
	f := newScanFixture(t)
	holdExclusively(t, f.owner, false)
	found, err := storageFilesContaining([]string{f.root}, `"id":"run-1"`)
	require.NoError(t, err, "a held lock token does not fail the scan")
	assert.Equal(t, []string{f.record}, found)

	holdExclusively(t, f.lockDir, true)
	found, err = storageFilesContaining([]string{f.root}, `"id":"run-1"`)
	require.NoError(t, err, "a held lock directory does not fail the scan")
	assert.Equal(t, []string{f.record}, found)
}

// A record held open with no sharing is a failure of the scan, not something
// passed over: an unread record proves nothing about its content.
func TestStorageScanFailsOnHeldData(t *testing.T) {
	t.Parallel()
	f := newScanFixture(t)
	holdExclusively(t, f.record, false)
	_, err := storageFilesContaining([]string{f.root}, "anything")
	require.Error(t, err)
	assert.ErrorContains(t, err, "run-1.json")

	// A data file named like a lock is not lock metadata either.
	lookalike := filepath.Join(f.root, "artifacts", "run-1", "report.lock")
	require.NoError(t, os.MkdirAll(filepath.Dir(lookalike), 0o750))
	require.NoError(t, os.WriteFile(lookalike, []byte("x"), 0o600))
	holdExclusively(t, lookalike, false)
	_, err = storageFilesContaining([]string{filepath.Join(f.root, "artifacts")}, "anything")
	require.Error(t, err)
	assert.ErrorContains(t, err, "report.lock")
}
