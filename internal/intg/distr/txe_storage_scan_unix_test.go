// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package distr_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireUnprivileged skips where permissions do not bind, since root reads
// a mode-0 file.
func requireUnprivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads files whatever their mode")
	}
}

// Lock metadata the scan cannot read is passed over: the owner token of a
// live lock, and the lock directory itself.
func TestStorageScanPassesOverUnreadableLockMetadata(t *testing.T) {
	t.Parallel()
	requireUnprivileged(t)
	f := newScanFixture(t)
	require.NoError(t, os.Chmod(f.owner, 0))
	t.Cleanup(func() { _ = os.Chmod(f.owner, 0o600) })
	found, err := storageFilesContaining([]string{f.root}, `"id":"run-1"`)
	require.NoError(t, err, "an unreadable lock token does not fail the scan")
	assert.Equal(t, []string{f.record}, found)

	require.NoError(t, os.Chmod(f.lockDir, 0))
	t.Cleanup(func() { _ = os.Chmod(f.lockDir, 0o700) })
	found, err = storageFilesContaining([]string{f.root}, `"id":"run-1"`)
	require.NoError(t, err, "an unlistable lock directory does not fail the scan")
	assert.Equal(t, []string{f.record}, found)
}

// Anything else the scan cannot read fails it: an unread record proves
// nothing about its content.
func TestStorageScanFailsOnUnreadableData(t *testing.T) {
	t.Parallel()
	requireUnprivileged(t)
	f := newScanFixture(t)
	require.NoError(t, os.Chmod(f.record, 0))
	t.Cleanup(func() { _ = os.Chmod(f.record, 0o600) })
	_, err := storageFilesContaining([]string{f.root}, "anything")
	require.Error(t, err)
	assert.ErrorContains(t, err, "run-1.json")

	require.NoError(t, os.Chmod(f.record, 0o600))
	dir := filepath.Join(f.root, "logs", "run-1")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "step.stdout.log"), []byte("x"), 0o600))
	require.NoError(t, os.Chmod(dir, 0))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })
	_, err = storageFilesContaining([]string{f.root}, "anything")
	require.Error(t, err, "an unlistable data directory fails the scan")
}
