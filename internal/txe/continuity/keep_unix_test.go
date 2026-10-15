// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package continuity_test

import (
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
)

// A special file in a kept tree is pinned by its exact type and permission
// bits, and never opened.
func TestKeepPinsSpecialFiles(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	strayEntries(t, l)
	fifo := homePath(l, "dags/pipe")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	m := strayManifest()
	pin(t, m, scanKeep(t, l, m))
	before := scanKeep(t, l, m)
	require.Empty(t, continuity.Blocking(continuity.Validate(before, continuity.Policy{})), "the pipe is never opened")

	require.NoError(t, os.Chmod(fifo, 0o640))
	assert.Equal(t, map[string]int{"kept_changed": 1}, compareCodes(continuity.Compare(before, scanKeep(t, l, m), continuity.CompareOptions{})))

	// The same path and permission bits, another kind of special file.
	require.NoError(t, os.Remove(fifo))
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	assert.Empty(t, compareCodes(continuity.Compare(before, scanKeep(t, l, m), continuity.CompareOptions{})), "the same pipe again")
	require.NoError(t, os.Remove(fifo))
	require.NoError(t, os.WriteFile(fifo, nil, 0o600))
	require.NoError(t, os.Chmod(fifo, 0o600))
	got := codes(continuity.Validate(scanKeep(t, l, m), continuity.Policy{}), continuity.SeverityBlock)
	assert.Equal(t, 1, got["kept_changed"], "%v", got)
}
