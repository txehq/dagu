// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A directory replaced, between its check and its open, by a link to a
// sibling inside the same root is refused: the root would allow the link,
// but the directory opened is not the one checked.
func TestOpenSubRootRefusesADirectorySwappedInTheWindow(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "a"), 0o750))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "b"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b", "f"), []byte("b's file"), 0o600))
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()

	beforeOpenSubRoot = func(_ *os.Root, name string) {
		require.NoError(t, os.RemoveAll(filepath.Join(dir, name)))
		require.NoError(t, os.Symlink("b", filepath.Join(dir, name)))
	}
	defer func() { beforeOpenSubRoot = nil }()

	_, err = openSubRoot(root, "a", false)
	assert.ErrorIs(t, err, errNotPlain)
	_, err = readPlain(root, filepath.Join("a", "f"))
	assert.Error(t, err, "a file is not read through the swapped directory")
}
