// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/test"
)

// listsHub is a hub with owner authorization in enforce, served through its
// real router, holding a DAG named as a job, an ownerless DAG and a run of
// each.
type listsHub struct {
	server test.Server
	base   string
	admin  string
	legacy string
	names  []string
}

func newListsHub(t *testing.T) listsHub {
	t.Helper()
	server := setupBuiltinAuthServer(t, func(cfg *config.Config) {
		cfg.TXE.Authz.Mode = config.TXEAuthzModeEnforce
	})
	h := listsHub{server: server, admin: getAdminToken(t, server)}
	h.base = fmt.Sprintf("http://%s:%d", server.Config.Server.Host, server.Config.Server.Port)

	server.Client().Post("/api/v1/users", api.CreateUserRequest{
		Username: "legacy-operator",
		Password: "legacypass1",
		Role:     api.UserRoleOperator,
	}).WithBearerToken(h.admin).ExpectStatus(http.StatusCreated).Send(t)
	var login api.LoginResponse
	server.Client().Post("/api/v1/auth/login", api.LoginRequest{Username: "legacy-operator", Password: "legacypass1"}).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &login)
	h.legacy = login.Token

	h.names = []string{"job_01M4ZZZZZZZZZZZZZZZZZZZZZZ", "nightly-backup"}
	for _, name := range h.names {
		// Each DAG's label names it, so a label list shows whose it is.
		spec := []byte("labels:\n  - of=" + name + "\nsteps:\n  - name: s\n    run: echo s\n")
		server.CreateDAGFile(t, server.Config.Paths.DAGsDir, name, spec)
		h.addRun(t, name)
	}
	return h
}

func (h listsHub) addRun(t *testing.T, name string) {
	t.Helper()
	ctx := context.Background()
	d := &ir.DAG{Name: name, YamlData: []byte("steps:\n  - name: s\n    run: echo s\n")}
	runID := "run-" + strings.ReplaceAll(name, "_", "-")
	attempt, err := h.server.DAGRunRepository.CreateAttempt(ctx, d, time.Now(), runID, persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	status := ir.InitialStatus(d)
	status.DAGRunID, status.AttemptID, status.Status = runID, attempt.ID(), ir.Succeeded
	status.StartedAt, status.FinishedAt = time.Now().Add(-time.Minute).Format(time.RFC3339), time.Now().Format(time.RFC3339)
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, status))
	require.NoError(t, attempt.Close(ctx))
}

// mentioned reports which of the hub's DAG names appear in body, in any
// case: labels are listed lowercased.
func (h listsHub) mentioned(body string) []string {
	var out []string
	for _, name := range h.names {
		if strings.Contains(strings.ToLower(body), strings.ToLower(name)) {
			out = append(out, name)
		}
	}
	return out
}

func (h listsHub) get(t *testing.T, path, bearer string) string {
	t.Helper()
	resp := h.server.Client().Get(path).WithBearerToken(bearer).ExpectStatus(http.StatusOK).Send(t)
	return resp.Body
}

// streamFirstData subscribes to one topic of the real event stream and
// returns the first message event, which carries the topic's payload.
func (h listsHub) streamFirstData(t *testing.T, topic, bearer string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.base+"/api/v1/events/stream?topic="+url.QueryEscape(topic), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	event := ""
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:") && event == "message":
			return strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
	}
	t.Fatalf("no data event on %s: %v", topic, scanner.Err())
	return ""
}

// mcpRead calls the real MCP route's read tool for one target.
func (h listsHub) mcpRead(t *testing.T, target, bearer string) string {
	t.Helper()
	post := func(session string, body string) (int, http.Header, string) {
		req, err := http.NewRequest(http.MethodPost, h.base+"/mcp", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Content-Type", "application/json")
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, resp.Header, string(raw)
	}
	status, header, body := post("", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"lists-test","version":"0"}}}`)
	require.Equal(t, http.StatusOK, status, body)
	session := header.Get("Mcp-Session-Id")
	post(session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	call, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": "dagu_read", "arguments": map[string]any{"target": target}},
	})
	require.NoError(t, err)
	status, _, body = post(session, string(call))
	require.Equal(t, http.StatusOK, status, body)
	require.True(t, json.Valid(bytes.TrimSpace([]byte(body))), body)
	return body
}

// A legacy credential in enforce reads no DAG, owned or not, and so lists
// none, through every list surface of the real router: the REST lists, the
// event stream's list topics and MCP's list reads. The platform
// administrator, on the same routes, sees them all, so the lists are not
// empty for want of DAGs.
func TestTxeWholeHubListsLegacyInEnforceThroughTheRouter(t *testing.T) {
	h := newListsHub(t)

	surfaces := []struct {
		name string
		read func(bearer string) string
	}{
		{"GET /dags", func(b string) string { return h.get(t, "/api/v1/dags?perPage=100", b) }},
		{"GET /dag-runs", func(b string) string { return h.get(t, "/api/v1/dag-runs", b) }},
		{"GET /dag-runs/{name}", func(b string) string {
			return h.get(t, "/api/v1/dag-runs/"+h.names[0], b) + h.get(t, "/api/v1/dag-runs/"+h.names[1], b)
		}},
		{"GET /dags/labels", func(b string) string { return h.get(t, "/api/v1/dags/labels", b) }},
		{"GET /dags/tags", func(b string) string { return h.get(t, "/api/v1/dags/tags", b) }},
		{"stream dagslist", func(b string) string { return h.streamFirstData(t, "dagslist:page=1&perPage=100", b) }},
		{"stream dagruns", func(b string) string { return h.streamFirstData(t, "dagruns:limit=50", b) }},
		{"MCP dags", func(b string) string { return h.mcpRead(t, "dags", b) }},
		{"MCP runs", func(b string) string { return h.mcpRead(t, "runs", b) }},
	}
	for _, s := range surfaces {
		t.Run(s.name, func(t *testing.T) {
			require.Empty(t, h.mentioned(s.read(h.legacy)), "a legacy credential in enforce")
			require.ElementsMatch(t, h.names, h.mentioned(s.read(h.admin)), "the platform administrator")
		})
	}
}
