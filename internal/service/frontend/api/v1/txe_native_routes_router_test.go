// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	filedagrun "github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
	"github.com/dagucloud/dagu/v2/internal/test"
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

	// An ordinary file that declares an owner's DAG name is that owner's on
	// these routes too.
	h.server.CreateDAGFile(t, h.server.Config.Paths.DAGsDir, "declares-owned", []byte("name: "+owned+"\nsteps:\n  - name: s\n    run: echo s\n"))
	for _, path := range []string{"/api/v1/dags/declares-owned/webhook", "/api/v1/dags/declares-owned/browser-cache"} {
		method := http.MethodPost
		if strings.HasSuffix(path, "browser-cache") {
			method = http.MethodDelete
		}
		require.Equal(t, http.StatusForbidden, status(method, path, h.admin, map[string]any{}), "a file declaring an owner's DAG name: %s", path)
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
	// Answering an agent's interaction is a person's answer, as a human task
	// is: the owner's command line does not answer it.
	require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, status(http.MethodPost, respond, h.cliA, map[string]any{"answer": "x"}),
		"the owner's cli answers no interaction")
	require.True(t, refusedAsNotFound(http.MethodPost, respond, manager, map[string]any{"answer": "x"}), "legacy")
	require.True(t, refusedAsNotFound(http.MethodDelete, run, manager, nil), "legacy deletes no owner's run")
	require.Equal(t, http.StatusForbidden, status(http.MethodDelete, run, h.admin, nil), "the administrator deletes no owner's run")
	waitForStoredDAGRunStatus(t, h.server, decideA, started.DagRunId, time.Second, func(s *ir.DAGRunStatus) bool { return s.Status == ir.Succeeded })

	// A machine's DAG file that declares an ordinary name stores its runs
	// under that name; they are still the machine's owner's.
	aliasFile := txeauth.MachineDAGs(h.machineA)[1]
	h.server.CreateDAGFile(t, h.server.Config.Paths.DAGsDir, aliasFile, []byte("name: nightly-alias\nsteps:\n  - name: s\n    run: echo s\n"))
	// The administrator does not start it (TXE-4744): its runs are stored
	// directly here.
	require.Equal(t, http.StatusForbidden, status(http.MethodPost, "/api/v1/dags/"+aliasFile+"/start", h.admin, map[string]any{}),
		"the administrator starts no alias of an owner's DAG")
	aliasLocation := filepath.Join(h.server.Config.Paths.DAGsDir, aliasFile+".yaml")
	{
		aliased := storeAliasRun(t, h.server, &ir.DAG{Name: "nightly-alias", Location: aliasLocation})
		aliasRun := "/api/v1/dag-runs/nightly-alias/" + aliased
		require.Equal(t, http.StatusForbidden, status(http.MethodDelete, aliasRun, h.admin, nil), "an alias's run is the owner's")
		require.Equal(t, http.StatusForbidden, status(http.MethodPost, aliasRun+"/steps/s/agent-interactions/i1/respond", h.admin, map[string]any{"answer": "x"}),
			"so is its agent session")
		// The S4 run routes decide it by its DAG as well (TXE-4744).
		require.Equal(t, http.StatusForbidden, status(http.MethodPost, aliasRun+"/retry", h.admin, map[string]any{"dagRunId": aliased}),
			"the administrator retries no alias's run")
		require.Equal(t, http.StatusForbidden, status(http.MethodPost, aliasRun+"/stop", h.admin, map[string]any{}),
			"nor stops one")
		require.True(t, refusedAsNotFound(http.MethodPost, aliasRun+"/stop", manager, map[string]any{}), "legacy")
	}

	// A queued run's DAG keeps its file only as SourceFile (enqueue clears
	// Location); it is still the machine's owner's.
	sourceFile := filepath.Join(h.server.Config.Paths.DAGsDir, aliasFile+".yaml")
	queued := storeAliasRun(t, h.server, &ir.DAG{Name: "nightly-alias", SourceFile: sourceFile, YamlData: []byte("steps:\n  - name: s\n    run: echo s\n")})
	require.Equal(t, http.StatusForbidden, status(http.MethodDelete, "/api/v1/dag-runs/nightly-alias/"+queued, h.admin, nil),
		"a queued alias's run is the owner's")

	// A run whose DAG cannot be read is not taken for no owner's. Its
	// workspace is read from its status, so only the owner check reads the
	// DAG.
	unread := storeAliasRun(t, h.server, &ir.DAG{Name: "nightly-alias", SourceFile: sourceFile,
		Labels: ir.NewLabels([]string{"workspace=ops"}), YamlData: []byte("steps:\n  - name: s\n    run: echo s\n")})
	removeDAGSnapshot(t, h.server, unread)
	require.Equal(t, http.StatusServiceUnavailable, status(http.MethodDelete, "/api/v1/dag-runs/nightly-alias/"+unread, h.admin, nil),
		"a run whose DAG is unreadable")

	// An ordinary DAG run as a sub-run of the alias's run: its agent
	// session is the root's owner's too.
	rootID := storeAliasRun(t, h.server, &ir.DAG{Name: "nightly-alias", SourceFile: sourceFile, YamlData: []byte("steps:\n  - name: s\n    run: echo s\n")})
	childID := storeSubRun(t, h.server, ir.NewDAGRunRef("nightly-alias", rootID), "plain-child")
	subRun := "/api/v1/dag-runs/nightly-alias/" + rootID + "/sub-dag-runs/" + childID + "/steps/s"
	require.Equal(t, http.StatusForbidden, status(http.MethodPost, subRun+"/agent-interactions/i1/respond", h.admin, map[string]any{"answer": "x"}),
		"a sub-run's agent session is its root owner's")
	require.Equal(t, http.StatusForbidden, status(http.MethodPost, subRun+"/agent-session/restart", h.admin, map[string]any{}),
		"so is restarting it")

	// Deeper: a hub DAG's run calls the alias, which calls an ordinary
	// DAG. The child's session is the owner's of the run between.
	hubRoot := storeAliasRun(t, h.server, &ir.DAG{Name: "hub-root", YamlData: []byte("steps:\n  - name: s\n    run: echo s\n")})
	hubRef := ir.NewDAGRunRef("hub-root", hubRoot)
	middle := storeSubRunOf(t, h.server, hubRef, hubRef, &ir.DAG{Name: "nightly-alias", SourceFile: sourceFile})
	leaf := storeSubRunOf(t, h.server, hubRef, ir.NewDAGRunRef("nightly-alias", middle), &ir.DAG{Name: "plain-child"})
	nested := "/api/v1/dag-runs/hub-root/" + hubRoot + "/sub-dag-runs/" + leaf + "/steps/s"
	require.Equal(t, http.StatusForbidden, status(http.MethodPost, nested+"/agent-interactions/i1/respond", h.admin, map[string]any{"answer": "x"}),
		"a sub-run within an owner's run is that owner's")
}

// storeSubRun stores a finished run of an ownerless DAG named name as a
// sub-run of root, and returns its run id.
func storeSubRun(t *testing.T, server test.Server, root ir.DAGRunRef, name string) string {
	t.Helper()
	return storeSubRunOf(t, server, root, root, &ir.DAG{Name: name})
}

// storeSubRunOf stores a finished run of dag under root, called by parent,
// and returns its run id.
func storeSubRunOf(t *testing.T, server test.Server, root, parent ir.DAGRunRef, dag *ir.DAG) string {
	t.Helper()
	ctx := context.Background()
	dag.YamlData = []byte("steps:\n  - name: s\n    run: echo s\n")
	runID := fmt.Sprintf("sub-%d", time.Now().UnixNano())
	attempt, err := server.DAGRunRepository.CreateAttempt(ctx, dag, time.Now(), runID, persis.DAGRunCreateAttemptOptions{RootDAGRun: root})
	require.NoError(t, err)
	st := ir.InitialStatus(dag)
	st.DAGRunID, st.AttemptID, st.Status = runID, attempt.ID(), ir.Succeeded
	st.Root, st.Parent = root, parent
	st.StartedAt, st.FinishedAt = time.Now().Add(-time.Minute).Format(time.RFC3339), time.Now().Format(time.RFC3339)
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, st))
	require.NoError(t, attempt.Close(ctx))
	return runID
}

// storeAliasRun stores a finished run of dag directly, as an attempt written
// from a queued DAG is, and returns its run id.
func storeAliasRun(t *testing.T, server test.Server, dag *ir.DAG) string {
	t.Helper()
	ctx := context.Background()
	runID := fmt.Sprintf("alias-%d", time.Now().UnixNano())
	attempt, err := server.DAGRunRepository.CreateAttempt(ctx, dag, time.Now(), runID, persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	st := ir.InitialStatus(dag)
	st.DAGRunID, st.AttemptID, st.Status = runID, attempt.ID(), ir.Succeeded
	st.StartedAt, st.FinishedAt = time.Now().Add(-time.Minute).Format(time.RFC3339), time.Now().Format(time.RFC3339)
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, st))
	require.NoError(t, attempt.Close(ctx))
	return runID
}

// removeDAGSnapshot deletes the DAG definition stored with the run runID.
func removeDAGSnapshot(t *testing.T, server test.Server, runID string) {
	t.Helper()
	removed := 0
	require.NoError(t, filepath.WalkDir(server.Config.Paths.DAGRunsDir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == filedagrun.DAGDefinition && strings.Contains(path, runID) {
			removed++
			return os.Remove(path)
		}
		return err
	}))
	require.Equal(t, 1, removed)
}
