// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// Runtime profiles belong to the whole hub, so a caller held to its owner
// may not name one when it starts or enqueues its own DAG: the profile's
// values would reach a run on its machine. The request is refused before any
// run exists, in every mode. Asking for no profile, or naming none, is
// allowed, and the administrator and legacy callers are unchanged (TXE-4704).
func TestTxeOwnerCannotChooseRuntimeProfile(t *testing.T) {
	for _, mode := range []string{config.TXEAuthzModeOff, config.TXEAuthzModeObserve, config.TXEAuthzModeEnforce} {
		t.Run(mode, func(t *testing.T) {
			h := newOwnerHub(t, mode)
			h.server.Client().Post("/api/v1/profiles", api.CreateRuntimeProfileJSONRequestBody{Name: "shared"}).
				WithBearerToken(h.admin).ExpectStatus(http.StatusCreated).Send(t)
			// Owner A's machine DAG, unpinned so that it runs on this hub.
			decideA := txeauth.MachineDAGs(h.machineA)[1]
			h.server.CreateDAGFile(t, h.server.Config.Paths.DAGsDir, decideA, []byte("steps:\n  - name: s\n    run: echo s\n"))
			h.server.CreateDAGFile(t, h.server.Config.Paths.DAGsDir, "ownerless", []byte("steps:\n  - name: s\n    run: echo s\n"))

			str := func(s string) *string { return &s }
			shared := str("shared")
			for route, body := range map[string]any{
				"start":      api.ExecuteDAGJSONRequestBody{DagRunId: str("refused-start"), Profile: shared},
				"start-sync": api.ExecuteDAGSyncJSONRequestBody{DagRunId: str("refused-start-sync"), Profile: shared},
				"enqueue":    api.EnqueueDAGDAGRunJSONRequestBody{DagRunId: str("refused-enqueue"), Profile: shared},
			} {
				resp := h.server.Client().Post("/api/v1/dags/"+decideA+"/"+route, body).WithBearerToken(h.cliA).
					ExpectStatus(http.StatusForbidden).Send(t)
				var refusal api.Error
				require.NoError(t, json.Unmarshal([]byte(resp.Body), &refusal), route)
				require.NotNil(t, refusal.Details, route)
				require.Equal(t, "runtime_profile_not_permitted", (*refusal.Details)["code"], route)
				_, err := h.server.DAGRunRepository.FindAttempt(h.server.Context, ir.NewDAGRunRef(decideA, "refused-"+route))
				require.Error(t, err, "%s: no run was created", route)
			}

			// The owner's own run without a profile, or naming none, goes ahead.
			h.server.Client().Post("/api/v1/dags/"+decideA+"/enqueue", api.EnqueueDAGDAGRunJSONRequestBody{DagRunId: str("no-profile")}).
				WithBearerToken(h.cliA).ExpectStatus(http.StatusOK).Send(t)
			h.server.Client().Post("/api/v1/dags/"+decideA+"/enqueue", api.EnqueueDAGDAGRunJSONRequestBody{DagRunId: str("empty-profile"), Profile: str("")}).
				WithBearerToken(h.cliA).ExpectStatus(http.StatusOK).Send(t)

			// The administrator, and in off and observe a legacy caller,
			// still name a profile on a DAG of no owner. In enforce a legacy
			// caller sees no DAG at all.
			callers := map[string]string{"admin": h.admin}
			if mode != config.TXEAuthzModeEnforce {
				callers["legacy"] = h.legacy
			}
			for name, bearer := range callers {
				h.server.Client().Post("/api/v1/dags/ownerless/enqueue", api.EnqueueDAGDAGRunJSONRequestBody{DagRunId: str(name), Profile: shared}).
					WithBearerToken(bearer).ExpectStatus(http.StatusOK).Send(t)
				attempt, err := h.server.DAGRunRepository.FindAttempt(h.server.Context, ir.NewDAGRunRef("ownerless", name))
				require.NoError(t, err, name)
				status, err := attempt.ReadStatus(h.server.Context)
				require.NoError(t, err, name)
				require.Equal(t, "shared", status.ProfileName, name)
			}
		})
	}
}
