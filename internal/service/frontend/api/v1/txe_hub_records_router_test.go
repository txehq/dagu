// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
	records := []string{"/api/v1/event-logs", "/api/v1/audit", "/api/v1/workers"}

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
