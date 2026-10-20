// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

const gateSpec = `steps:
  - id: decide
    action: human.task
    with:
      prompt: "Go ahead?"
      form:
        type: object
        properties:
          ok:
            type: string
        required: [ok]
  - id: after
    depends: decide
    run: echo done`

// Through the real router, in enforce: the owner's command-line token
// starts its machine's DAG, but may not complete that DAG's waiting human
// task, and neither may the platform administrator (TXE-4721).
func TestTxeOwnerTokenCannotAnswerAHumanTask(t *testing.T) {
	h := newSuspendHub(t)
	name := txeauth.MachineDAGs(h.machineA)[1]
	h.server.CreateDAGFile(t, h.server.Config.Paths.DAGsDir, name, []byte(gateSpec))
	var started api.ExecuteDAG200JSONResponse
	h.server.Client().Post("/api/v1/dags/"+name+"/start", api.ExecuteDAGJSONRequestBody{}).
		WithBearerToken(h.cliA).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &started)
	waitForStoredDAGRunStatus(t, h.server, name, started.DagRunId, 10*time.Second, func(s *ir.DAGRunStatus) bool {
		return s.Status == ir.Waiting && hasNodeWithStatus(s, "decide", ir.NodeWaiting)
	})

	for _, bearer := range []string{h.cliA, h.admin} {
		h.server.Client().Post("/api/v1/dag-runs/"+name+"/"+started.DagRunId+"/human-tasks/decide/complete", map[string]any{"ok": "yes"}).
			WithBearerToken(bearer).ExpectStatus(http.StatusForbidden).Send(t)
	}
	status := waitForStoredDAGRunStatus(t, h.server, name, started.DagRunId, time.Second, func(*ir.DAGRunStatus) bool { return true })
	if !hasNodeWithStatus(status, "decide", ir.NodeWaiting) {
		t.Fatalf("the human task must still wait: %v", status.Status)
	}
}
