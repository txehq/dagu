// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/artifactpath"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/stringutil"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis/file/artifact"
)

// newHubRecordsHub is a hub in the given owner mode, served through its real
// router, holding a DAG named as a job and an ownerless DAG, each with a run
// that left an artifact, and a legacy manager.
func newHubRecordsHub(t *testing.T, mode string) listsHub {
	t.Helper()
	server := setupBuiltinAuthServer(t, func(cfg *config.Config) {
		cfg.TXE.Authz.Mode = mode
	})
	h := listsHub{server: server, admin: getAdminToken(t, server)}
	h.base = fmt.Sprintf("http://%s:%d", server.Config.Server.Host, server.Config.Server.Port)

	server.Client().Post("/api/v1/users", api.CreateUserRequest{
		Username: "legacy-manager",
		Password: "legacypass1",
		Role:     api.UserRoleManager,
	}).WithBearerToken(h.admin).ExpectStatus(http.StatusCreated).Send(t)
	var login api.LoginResponse
	server.Client().Post("/api/v1/auth/login", api.LoginRequest{Username: "legacy-manager", Password: "legacypass1"}).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &login)
	h.legacy = login.Token

	h.names = []string{"job_01M4ZZZZZZZZZZZZZZZZZZZZZZ", "nightly-backup"}
	for _, name := range h.names {
		spec := []byte("steps:\n  - name: s\n    run: echo marker-of-" + name + "\n")
		server.CreateDAGFile(t, server.Config.Paths.DAGsDir, name, spec)
		h.addRun(t, name)
		indexArtifact(t, server.Config.Paths.ArtifactDir, name)
	}
	return h
}

// indexArtifact leaves one file of a run of dagName in the artifact store, as
// a finished run does.
func indexArtifact(t *testing.T, root, dagName string) {
	t.Helper()
	at := time.Now()
	runID := "art-" + dagName
	dir, err := artifactpath.NewRunDir(context.Background(), root, "", dagName, runID, at)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "out.txt"), []byte("x"), 0o600))
	metaPath, ok := artifactpath.MetaPath(root, dir)
	require.True(t, ok)
	require.NoError(t, artifact.WriteRecord(metaPath, artifact.Record{
		Version:   artifact.RecordVersion,
		Name:      dagName,
		DAGRunID:  runID,
		Status:    ir.Succeeded,
		StartedAt: stringutil.FormatTime(at),
		Dir:       dir,
	}))
}

func (h listsHub) send(t *testing.T, path, bearer string) (int, string) {
	t.Helper()
	resp := h.server.Client().Get(path).WithBearerToken(bearer).Send(t)
	return resp.Response.StatusCode(), resp.Body
}

// Under enforce a legacy credential reads no DAG, and so the whole-hub reads
// not decided DAG by DAG show it none: DAG search and its matches, the
// artifact list, event and audit logs, and workers (TXE-4752). The platform
// administrator still reads them, and in off the legacy manager reads what
// its role gives it, as before.
func TestTxeHubRecordsLegacyInEnforceThroughTheRouter(t *testing.T) {
	lists := []struct {
		name string
		path func(h listsHub) string
	}{
		{"GET /search/dags", func(listsHub) string { return "/api/v1/search/dags?q=marker-of" }},
		{"GET /dags/search", func(listsHub) string { return "/api/v1/dags/search?q=marker-of" }},
		{"GET /artifacts", func(listsHub) string { return "/api/v1/artifacts" }},
	}
	// /dag-run-activity aggregates runs, queues and schedules across the hub
	// (upstream v2.25, TXE-5923).
	records := []string{"/api/v1/event-logs", "/api/v1/audit", "/api/v1/workers", "/api/v1/dag-run-activity"}

	t.Run("enforce", func(t *testing.T) {
		h := newHubRecordsHub(t, config.TXEAuthzModeEnforce)
		for _, l := range lists {
			t.Run(l.name, func(t *testing.T) {
				require.Empty(t, h.mentioned(h.get(t, l.path(h), h.legacy)), "a legacy credential in enforce")
				require.ElementsMatch(t, h.names, h.mentioned(h.get(t, l.path(h), h.admin)), "the platform administrator")
			})
		}
		for _, name := range h.names {
			status, _ := h.send(t, "/api/v1/search/dags/"+name+"/matches?q=marker-of", h.legacy)
			require.Equal(t, http.StatusNotFound, status, "a legacy credential in enforce reads no DAG's matches: %s", name)
			status, body := h.send(t, "/api/v1/search/dags/"+name+"/matches?q=marker-of", h.admin)
			require.Equal(t, http.StatusOK, status, body)
		}
		for _, path := range records {
			status, body := h.send(t, path, h.legacy)
			require.Equal(t, http.StatusForbidden, status, path)
			require.Contains(t, body, "hub_records_not_permitted", path)
			_, body = h.send(t, path, h.admin)
			require.NotContains(t, body, "hub_records_not_permitted", path)
		}
	})

	t.Run("off", func(t *testing.T) {
		h := newHubRecordsHub(t, config.TXEAuthzModeOff)
		for _, l := range lists {
			require.ElementsMatch(t, h.names, h.mentioned(h.get(t, l.path(h), h.legacy)), l.name)
		}
		for _, path := range records {
			_, body := h.send(t, path, h.legacy)
			require.NotContains(t, body, "hub_records_not_permitted", path)
		}
	})
}

// Upstream v2.25's foreach reads of a root run decide the run as every other
// run read does, by its DAG's owner: under enforce a legacy credential is
// refused before anything of the run is read, while the platform
// administrator reaches the run, here to learn that it has no such step
// (TXE-5923).
func TestTxeForeachReadsDecideTheRunsOwner(t *testing.T) {
	h := newHubRecordsHub(t, config.TXEAuthzModeEnforce)
	for _, name := range h.names {
		path := "/api/v1/dag-runs/" + name + "/run-" + strings.ReplaceAll(name, "_", "-") + "/steps/s/foreach"
		status, body := h.send(t, path, h.legacy)
		require.NotEqual(t, http.StatusOK, status, body)
		require.NotContains(t, body, "step s", "a legacy credential in enforce read run %s", name)
		_, body = h.send(t, path, h.admin)
		require.Contains(t, body, "step s not found in DAG", "the platform administrator reads run %s", name)
	}
}

// Upstream v2.25's calendar reads list the DAGs that use a calendar. Under
// enforce they name only what the caller's DAG lists show it: a legacy
// credential none, the platform administrator every DAG. A delete still
// counts every DAG, so a calendar in use is not deleted from under DAGs the
// caller cannot see; it names none of them (TXE-5923).
func TestTxeCalendarUsageFollowsTheOwnerScope(t *testing.T) {
	h := newHubRecordsHub(t, config.TXEAuthzModeEnforce)
	h.server.Client().Post("/api/v1/calendars", api.CreateCalendarJSONRequestBody{Name: "ops"}).
		WithBearerToken(h.admin).ExpectStatus(http.StatusCreated).Send(t)
	users := []string{"job_01M5YYYYYYYYYYYYYYYYYYYYYY", "nightly-calendar"}
	for _, name := range users {
		spec := []byte("calendar: ops\nschedule: \"0 9 * * *\"\nsteps:\n  - name: s\n    run: echo hi\n")
		h.server.CreateDAGFile(t, h.server.Config.Paths.DAGsDir, name, spec)
	}
	mentioned := func(body string) []string {
		var out []string
		for _, name := range users {
			if strings.Contains(body, name) {
				out = append(out, name)
			}
		}
		return out
	}

	status, body := h.send(t, "/api/v1/calendars/ops", h.admin)
	require.Equal(t, http.StatusOK, status, body)
	require.ElementsMatch(t, users, mentioned(body), "the platform administrator")
	status, body = h.send(t, "/api/v1/calendars/ops", h.legacy)
	require.Equal(t, http.StatusOK, status, body)
	require.Empty(t, mentioned(body), "a legacy credential in enforce")
	status, body = h.send(t, "/api/v1/calendars?includeUsage=true", h.legacy)
	require.Equal(t, http.StatusOK, status, body)
	require.NotContains(t, body, `"dagCount":2`, "a legacy credential in enforce counts no DAG")

	resp := h.server.Client().Delete("/api/v1/calendars/ops").WithBearerToken(h.legacy).Send(t)
	if resp.Response.StatusCode() == http.StatusConflict {
		require.Empty(t, mentioned(resp.Body), "a delete names no DAG the caller cannot see")
	}
	resp = h.server.Client().Delete("/api/v1/calendars/ops").WithBearerToken(h.admin).Send(t)
	require.Equal(t, http.StatusConflict, resp.Response.StatusCode(), "a calendar in use is not deleted")
	require.ElementsMatch(t, users, mentioned(resp.Body))
}

// A shared calendar decides when every owner's calendar-backed workflows run,
// so in enforce only the platform administrator creates, changes or deletes
// one; a legacy credential, even a manager, is refused before anything is
// written.
func TestTxeSharedCalendarWritesArePlatformOnly(t *testing.T) {
	h := newHubRecordsHub(t, config.TXEAuthzModeEnforce)
	h.server.Client().Post("/api/v1/calendars", api.CreateCalendarJSONRequestBody{Name: "ops"}).
		WithBearerToken(h.admin).ExpectStatus(http.StatusCreated).Send(t)

	h.server.Client().Post("/api/v1/calendars", api.CreateCalendarJSONRequestBody{Name: "rogue"}).
		WithBearerToken(h.legacy).ExpectStatus(http.StatusForbidden).Send(t)
	h.server.Client().Put("/api/v1/calendars/ops", api.UpdateCalendarJSONRequestBody{Spec: "name: ops\n"}).
		WithBearerToken(h.legacy).ExpectStatus(http.StatusForbidden).Send(t)
	h.server.Client().Delete("/api/v1/calendars/ops").
		WithBearerToken(h.legacy).ExpectStatus(http.StatusForbidden).Send(t)

	status, body := h.send(t, "/api/v1/calendars/ops", h.admin)
	require.Equal(t, http.StatusOK, status, body, "the calendar is unchanged and still there")
	status, _ = h.send(t, "/api/v1/calendars/rogue", h.admin)
	require.Equal(t, http.StatusNotFound, status, "nothing was created")
	h.server.Client().Delete("/api/v1/calendars/ops").
		WithBearerToken(h.admin).ExpectStatus(http.StatusNoContent).Send(t)
}

// Under owner enforcement a request for a remote node needs the platform
// administrator (for the builtin sign-in, an admin-role account:
// txeauth.Classify). A legacy manager, an administrator of the hub's roles
// but no platform administrator, is refused before any node is looked up,
// and the refusal names no node. The platform administrator passes the
// decision; this hub has no node of that name, so the proxy then says so
// (TXE-5923, option A).
func TestTxeRemoteNodeNeedsThePlatformAdministratorUnderEnforce(t *testing.T) {
	h := newHubRecordsHub(t, config.TXEAuthzModeEnforce)

	status, body := h.send(t, "/api/v1/dags?remoteNode=edge", h.legacy)
	require.Equal(t, http.StatusForbidden, status, body)
	require.NotContains(t, body, "edge")

	status, body = h.send(t, "/api/v1/dags?remoteNode=edge", h.admin)
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "not found", "past the decision, the proxy looks the node up")

	status, _ = h.send(t, "/api/v1/dags", h.legacy)
	require.NotEqual(t, http.StatusForbidden, status, "a request for this server is not the remote decision's")
}

// Under owner enforcement a capability that runs commands on the hub's host
// needs the platform administrator: an admin-role API key, which the owner
// model never takes for the platform administrator, can neither save a
// command notification channel nor open the terminal (TXE-5923). The
// platform administrator gets past this decision to the hub's own checks.
func TestTxeHostExecutionNeedsThePlatformAdministratorUnderEnforce(t *testing.T) {
	h := newHubRecordsHub(t, config.TXEAuthzModeEnforce)
	key := createAPIKeyForRole(t, h.server, h.admin, "legacy-admin-key", api.UserRoleAdmin)
	channel := api.NotificationChannelInput{
		Name: "host", Enabled: true, Type: api.NotificationProviderTypeCommand,
		Command: &api.NotificationCommandTarget{Command: "id"},
	}

	resp := h.server.Client().Post("/api/v1/notification-channels", channel).WithBearerToken(key).Send(t)
	require.Equal(t, http.StatusForbidden, resp.Response.StatusCode(), resp.Body)
	require.Contains(t, resp.Body, "host_execution_not_permitted")

	resp = h.server.Client().Post("/api/v1/notification-channels", channel).WithBearerToken(h.admin).Send(t)
	require.NotContains(t, resp.Body, "host_execution_not_permitted", "the platform administrator is decided by the hub's own checks")

	// The terminal takes its token from the query only.
	terminal, err := http.Get(h.base + "/api/v1/terminal/ws?token=" + key) //nolint:noctx // test request
	require.NoError(t, err)
	defer func() { _ = terminal.Body.Close() }()
	terminalBody, err := io.ReadAll(terminal.Body)
	require.NoError(t, err)
	// An API key has no terminal surface, so authentication refuses it first;
	// any other administrator the owner model does not take for the platform
	// administrator meets TxeHostExecutionRefused, the same decision as the
	// channel's above. Either way no terminal opens.
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, terminal.StatusCode, string(terminalBody))
}

// Under owner enforcement the Dagu Console report, which carries every
// owner's runs and failures, is the platform administrator's: an admin-role
// API key can neither read it nor change what it sends (TXE-5923).
func TestTxeCloudReportIsThePlatformAdministratorsUnderEnforce(t *testing.T) {
	h := newHubRecordsHub(t, config.TXEAuthzModeEnforce)
	key := createAPIKeyForRole(t, h.server, h.admin, "legacy-admin-report", api.UserRoleAdmin)

	status, body := h.send(t, "/api/v1/license/monitoring", key)
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "hub_records_not_permitted")
	resp := h.server.Client().Put("/api/v1/license/monitoring", api.UpdateLicenseMonitoringJSONRequestBody{Level: "runs"}).
		WithBearerToken(key).Send(t)
	require.Equal(t, http.StatusForbidden, resp.Response.StatusCode(), resp.Body)
	require.Contains(t, resp.Body, "hub_records_not_permitted")

	status, body = h.send(t, "/api/v1/license/monitoring", h.admin)
	require.NotContains(t, body, "hub_records_not_permitted", "the platform administrator is decided by the hub's own checks (%d)", status)
	// The connect route's report and remote access choices, and the remote
	// access route, are the same decision: refused before anything starts.
	report := api.LicenseMonitoringLevel("errors")
	resp = h.server.Client().Post("/api/v1/license/connect", api.StartLicenseConnectJSONRequestBody{Report: &report}).
		WithBearerToken(key).Send(t)
	require.Equal(t, http.StatusForbidden, resp.Response.StatusCode(), resp.Body)
	require.Contains(t, resp.Body, "hub_records_not_permitted")
	status, body = h.send(t, "/api/v1/license/remote-access", key)
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "hub_records_not_permitted")
}
