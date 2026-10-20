// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// Through the real router, in enforce: the native routes S4 and S4b left to
// the hub's roles decide an owner's DAG by its owner. A legacy credential,
// whatever its role, sees no DAG (404), and the platform administrator
// views an owner's DAG but changes nothing of it (403). An ownerless DAG
// stays the administrator's (TXE-4741).
func TestTxeNativeRoutesDecideAnOwnersDAGInEnforce(t *testing.T) {
	h := newSuspendHub(t)
	// A legacy credential with the role these routes ask for.
	h.server.Client().Post("/api/v1/users", api.CreateUserRequest{Username: "legacy-manager", Password: "legacypass1", Role: api.UserRoleManager}).
		WithBearerToken(h.admin).ExpectStatus(http.StatusCreated).Send(t)
	var login api.LoginResponse
	h.server.Client().Post("/api/v1/auth/login", api.LoginRequest{Username: "legacy-manager", Password: "legacypass1"}).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &login)
	manager := login.Token

	owned := h.reviewerA
	h.server.CreateDAGFile(t, h.server.Config.Paths.DAGsDir, "plain", []byte("steps:\n  - name: s\n    run: echo s\n"))
	// call answers the status, and whether the answer is the owner check's
	// refusal: its 404 says exactly "not found", which tells it apart from
	// a route's own "nothing configured".
	call := func(method, path, bearer string, body any) (int, bool) {
		t.Helper()
		req := h.server.Client().Get(path)
		switch method {
		case http.MethodPost:
			req = h.server.Client().Post(path, body)
		case http.MethodDelete:
			req = h.server.Client().Delete(path)
		}
		resp := req.WithBearerToken(bearer).Send(t)
		var e api.Error
		_ = json.Unmarshal([]byte(resp.Body), &e)
		return resp.Response.StatusCode(), e.Message == "not found"
	}
	status := func(method, path, bearer string, body any) int {
		t.Helper()
		code, _ := call(method, path, bearer, body)
		return code
	}
	refusedAsNotFound := func(method, path, bearer string, body any) bool {
		t.Helper()
		code, owner := call(method, path, bearer, body)
		return code == http.StatusNotFound && owner
	}

	for _, route := range []struct {
		method, path string
		author       bool
	}{
		{http.MethodPost, "/api/v1/dags/%s/webhook", true},
		{http.MethodGet, "/api/v1/dags/%s/notifications", false},
		{http.MethodGet, "/api/v1/dags/%s/incidents", false},
		{http.MethodGet, "/api/v1/dags/%s/settings", false},
		{http.MethodDelete, "/api/v1/dags/%s/browser-cache", true},
	} {
		on := func(name string) string { return fmt.Sprintf(route.path, name) }
		what := route.method + " " + route.path
		require.True(t, refusedAsNotFound(route.method, on(owned), manager, map[string]any{}), "legacy: %s", what)
		require.True(t, refusedAsNotFound(route.method, on("plain"), manager, map[string]any{}), "legacy on an ownerless DAG: %s", what)
		admin, refused := call(route.method, on(owned), h.admin, map[string]any{})
		if route.author {
			require.Equal(t, http.StatusForbidden, admin, "the administrator changes nothing of an owner's DAG: %s", what)
		} else {
			require.False(t, admin == http.StatusForbidden || (admin == http.StatusNotFound && refused), "the administrator views an owner's DAG: %s answered %d", what, admin)
		}
		ownerless, refused := call(route.method, on("plain"), h.admin, map[string]any{})
		require.False(t, ownerless == http.StatusForbidden || (ownerless == http.StatusNotFound && refused), "an ownerless DAG stays the administrator's: %s answered %d", what, ownerless)
	}

	// The whole-hub webhook list shows a legacy credential no DAG's.
	var listed api.ListWebhooks200JSONResponse
	h.server.Client().Get("/api/v1/webhooks").WithBearerToken(manager).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &listed)
	require.Empty(t, listed.Webhooks)
	h.server.Client().Get("/api/v1/webhooks").WithBearerToken(h.admin).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &listed)
	require.Len(t, listed.Webhooks, 1, "the administrator's own, on the ownerless DAG")

	// A finished run of A's machine DAG: deleting it, or answering its agent
	// session, is decided by A's owner.
	decideA := txeauth.MachineDAGs(h.machineA)[1]
	h.server.CreateDAGFile(t, h.server.Config.Paths.DAGsDir, decideA, []byte("steps:\n  - name: s\n    run: echo s\n"))
	var started api.ExecuteDAG200JSONResponse
	h.server.Client().Post("/api/v1/dags/"+decideA+"/start", api.ExecuteDAGJSONRequestBody{}).
		WithBearerToken(h.cliA).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &started)
	waitForStoredDAGRunStatus(t, h.server, decideA, started.DagRunId, 10*time.Second, func(s *ir.DAGRunStatus) bool {
		return s.Status == ir.Succeeded
	})
	run := "/api/v1/dag-runs/" + decideA + "/" + started.DagRunId
	respond := run + "/steps/s/agent-interactions/i1/respond"
	require.Equal(t, http.StatusForbidden, status(http.MethodPost, respond, h.admin, map[string]any{"answer": "x"}), "the administrator answers no owner's agent")
	require.True(t, refusedAsNotFound(http.MethodPost, respond, manager, map[string]any{"answer": "x"}), "legacy")
	require.True(t, refusedAsNotFound(http.MethodDelete, run, manager, nil), "legacy deletes no owner's run")
	require.Equal(t, http.StatusForbidden, status(http.MethodDelete, run, h.admin, nil), "the administrator deletes no owner's run")
	waitForStoredDAGRunStatus(t, h.server, decideA, started.DagRunId, time.Second, func(s *ir.DAGRunStatus) bool { return s.Status == ir.Succeeded })
}
