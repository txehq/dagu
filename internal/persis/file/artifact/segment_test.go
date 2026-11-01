// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package artifact_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis/file/artifact"
)

// An upload in progress is not a result of the run.
func TestAnUploadInProgressIsNotAnEntry(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ir.ArtifactSegmentDir), 0o750))
	has, err := artifact.DirHasEntries(dir)
	require.NoError(t, err)
	assert.False(t, has)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "result.csv"), []byte("x"), 0o600))
	has, err = artifact.DirHasEntries(dir)
	require.NoError(t, err)
	assert.True(t, has)
}
