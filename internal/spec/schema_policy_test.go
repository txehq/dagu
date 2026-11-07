// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package spec

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A spec loaded under a context marked WithoutSchemaReferences leaves its
// params.schema reference unread, by any load path; unmarked, the reference
// is resolved as before (TXE-5923).
func TestWithoutSchemaReferencesLeavesTheReferenceUnread(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "absent-schema.json")
	source := []byte("params:\n  schema: " + missing + "\nsteps:\n  - run: echo hi\n")

	_, err := LoadYAML(context.Background(), source, WithName("probe"))
	require.Error(t, err, "unmarked, the reference is read and the missing file fails the load")
	require.Contains(t, err.Error(), "absent-schema")

	_, err = LoadYAML(WithoutSchemaReferences(context.Background()), source, WithName("probe"))
	require.NoError(t, err, "marked, nothing is read")
}
