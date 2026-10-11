// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

// AttemptPrepared answers for one attempt strictly: absent is false, present
// is true, and an entry that cannot be read or names another attempt is an
// error rather than absent.
func TestAttemptPreparedIsStrict(t *testing.T) {
	ctx := t.Context()
	store := NewStore(t.TempDir())
	run := ir.NewDAGRunRef("dag", "run-1")

	prepared, err := store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a1")
	require.NoError(t, err)
	assert.False(t, prepared, "nothing journaled")

	entry, err := store.beginPreparation(run, ir.DAGRunRef{}, "a1")
	require.NoError(t, err)
	prepared, err = store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a1")
	require.NoError(t, err)
	assert.True(t, prepared)
	prepared, err = store.AttemptPrepared(ctx, run, run, "a1")
	require.NoError(t, err)
	assert.True(t, prepared, "a root run is its own root")
	prepared, err = store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a2")
	require.NoError(t, err)
	assert.False(t, prepared, "another attempt")

	path := store.preparationPath(entry)
	require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))
	_, err = store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a1")
	assert.Error(t, err, "an unreadable entry")

	other := persis.AttemptPreparation{Schema: persis.AttemptPreparationSchema, Run: run, RootRun: run, AttemptID: "a9",
		PreparedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	data, err := json.Marshal(other)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	_, err = store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a1")
	assert.Error(t, err, "an entry naming another attempt")

	require.NoError(t, store.EndAttemptPreparation(ctx, entry))
	prepared, err = store.AttemptPrepared(ctx, run, ir.DAGRunRef{}, "a1")
	require.NoError(t, err)
	assert.False(t, prepared, "ended")
}
