// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// A refusal's record is returned in its API shape: a manifest's absolute
// archive directory, which the API never publishes, does not leave the hub.
func TestTxeRefusalReturnsTheAPIShape(t *testing.T) {
	manifest := &registry.ArtifactManifest{JobID: "job_x", RunID: "run-1", Execution: "e1", ArchiveDir: "/srv/dagu/artifacts/secret/run-1"}
	err := txeError(&registry.Error{Code: registry.CodeArtifactConflict, Message: "conflict", Current: manifest})
	apiErr, ok := err.(*Error)
	require.True(t, ok)
	data, mErr := json.Marshal(apiErr.Details["current"])
	require.NoError(t, mErr)
	assert.NotContains(t, string(data), "archive_dir")
	assert.NotContains(t, string(data), "/srv/dagu")
	assert.Contains(t, string(data), `"run_id":"run-1"`)

	job := &registry.Job{JobID: "job_x"}
	err = txeError(&registry.Error{Code: registry.CodeVersionConflict, Message: "conflict", Current: job})
	apiErr, ok = err.(*Error)
	require.True(t, ok)
	_, isAPIJob := apiErr.Details["current"].(api.TxeJob)
	assert.True(t, isAPIJob, "a job is returned as the API's TxeJob")

	other := registry.ExecutionPreparing{RunID: "run-1", Execution: "e1"}
	err = txeError(&registry.Error{Code: registry.CodeNotReady, Message: "preparing", Current: other})
	apiErr, ok = err.(*Error)
	require.True(t, ok)
	assert.Equal(t, other, apiErr.Details["current"], "other records unchanged")
}
