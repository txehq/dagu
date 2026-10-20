// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/api/v1"
)

// start-sync decides who may run a DAG before it reports the DAG's build
// errors: another owner's broken machine DAG is not found, not described
// (TXE-4747).
func TestTxeStartSyncDecidesBeforeBuildErrors(t *testing.T) {
	h := newSuspendHub(t)
	// B's decide DAG, beside B's reviewer DAG.
	broken := strings.Replace(h.reviewerB, "txe-reviewer-", "txe-decide-", 1)
	h.server.CreateDAGFile(t, h.server.Config.Paths.DAGsDir, broken, []byte("steps:\n  - name: s\n    run: echo s\n    depends: [nowhere]\n"))

	resp := h.server.Client().Post("/api/v1/dags/"+broken+"/start-sync", api.ExecuteDAGSyncJSONRequestBody{}).
		WithBearerToken(h.cliA).ExpectStatus(http.StatusNotFound).Send(t)
	var e api.Error
	require.NoError(t, json.Unmarshal([]byte(resp.Body), &e))
	require.NotContains(t, e.Message, "nowhere", "nothing of the definition is told")

	// The administrator, who may view it, is still told why it cannot run.
	h.server.Client().Post("/api/v1/dags/"+broken+"/start-sync", api.ExecuteDAGSyncJSONRequestBody{}).
		WithBearerToken(h.admin).Send(t)
}
