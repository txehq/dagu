// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/cmn/dirlock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scanFixture is a storage root laid out as the hub lays out its data: a
// regular record, and a record lock bucket with a live directory lock in it,
// as the store makes them.
type scanFixture struct {
	root   string
	record string
	lock   dirlock.DirLock
	// lockDir is the .dagu_lock directory the live lock made; owner is the
	// token file inside it.
	lockDir string
	owner   string
}

func newScanFixture(t *testing.T) *scanFixture {
	t.Helper()
	root := t.TempDir()
	record := filepath.Join(root, "distributed", "active-runs", "ab", "cd", "run-1.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(record), 0o750))
	require.NoError(t, os.WriteFile(record, []byte(`{"id":"run-1","output":"masked-*******"}`), 0o600))

	bucket := filepath.Join(root, "distributed", "active-runs", ".dagu_record_locks", "6a")
	lock := dirlock.New(bucket, nil)
	require.NoError(t, lock.TryLock(), "take the record lock as the store does")
	t.Cleanup(func() { _ = lock.Unlock() })
	lockDir := filepath.Join(bucket, dirlock.LockDirectoryName)
	owner := filepath.Join(lockDir, "owner")
	require.FileExists(t, owner, "the live lock has its owner token")
	return &scanFixture{root: root, record: record, lock: lock, lockDir: lockDir, owner: owner}
}

// The scan reads the records and finds what they hold; lock metadata is not
// what it asserts on.
func TestStorageScanFindsStoredValues(t *testing.T) {
	t.Parallel()
	f := newScanFixture(t)
	found, err := storageFilesContaining([]string{f.root}, `"id":"run-1"`)
	require.NoError(t, err)
	assert.Equal(t, []string{f.record}, found)

	// The negative control of every masking test: a value that reached a
	// regular record is reported.
	exposed := filepath.Join(f.root, "logs", "run-1", "step.stdout.log")
	require.NoError(t, os.MkdirAll(filepath.Dir(exposed), 0o750))
	require.NoError(t, os.WriteFile(exposed, []byte("token=txe-sentinel-exposed-0c3e\n"), 0o600))
	found, err = storageFilesContaining([]string{f.root}, "txe-sentinel-exposed-0c3e")
	require.NoError(t, err)
	assert.Equal(t, []string{exposed}, found)

	// A root that does not exist holds nothing.
	found, err = storageFilesContaining([]string{filepath.Join(f.root, "absent")}, "anything")
	require.NoError(t, err)
	assert.Empty(t, found)
}

// A file whose name resembles a lock but sits among the data is scanned and
// asserted on like any other.
func TestStorageScanReadsDataNamedLikeALock(t *testing.T) {
	t.Parallel()
	f := newScanFixture(t)
	for _, name := range []string{"report.lock", ".dagu_lock.txt", "status.jsonl.lock"} {
		path := filepath.Join(f.root, "artifacts", "run-1", name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, []byte("txe-sentinel-in-"+name), 0o600))
		found, err := storageFilesContaining([]string{f.root}, "txe-sentinel-in-"+name)
		require.NoError(t, err)
		assert.Equal(t, []string{path}, found, name)
	}
}
