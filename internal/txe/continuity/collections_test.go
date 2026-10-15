// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/persis"
	persisfile "github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
)

// Every collection the file backend can write, with a record ID it accepts.
var backendCollections = map[string]string{
	persis.CollectionAPIKeys:               "k1",
	persis.CollectionActiveDistributedRuns: "r1",
	persis.CollectionAgentSessionCleanups:  "c1",
	persis.CollectionDAGRunLeases:          "l1",
	persis.CollectionDAGSettings:           "d1",
	persis.CollectionDAGState:              "s1",
	persis.CollectionDispatchTasks:         "pending/t1",
	persis.CollectionIncidents:             "i1",
	persis.CollectionLicense:               "license",
	persis.CollectionNotifications:         "n1",
	persis.CollectionOIDCSessions:          "o1",
	persis.CollectionProfiles:              "p1",
	persis.CollectionQueue:                 "q1",
	persis.CollectionRemoteNodes:           "rn1",
	persis.CollectionSchedulerState:        "state",
	persis.CollectionSecrets:               "sec1",
	persis.CollectionUpgradeCheck:          "check",
	persis.CollectionUsers:                 "u1",
	persis.CollectionViews:                 "v1",
	persis.CollectionWebhooks:              "w1",
	persis.CollectionWorkerHeartbeats:      "h1",
	persis.CollectionWorkspaces:            "ws1",
}

// backendPaths are the data directory's paths with the loader's defaults
// (internal/cmn/config, finalizePaths).
func backendPaths(dataDir string) config.PathsConfig {
	return config.PathsConfig{
		DataDir:        dataDir,
		DAGStateDir:    filepath.Join(dataDir, "dag-state"),
		QueueDir:       filepath.Join(dataDir, "queue"),
		UsersDir:       filepath.Join(dataDir, "users"),
		APIKeysDir:     filepath.Join(dataDir, "apikeys"),
		WebhooksDir:    filepath.Join(dataDir, "webhooks"),
		RemoteNodesDir: filepath.Join(dataDir, "remote-nodes"),
		WorkspacesDir:  filepath.Join(dataDir, "workspaces"),
		ViewsDir:       filepath.Join(dataDir, "views"),
	}
}

// A hub writes its control-plane data through the file backend. A record in
// every collection the backend can write leaves the data directory fully
// classified, and the collections that hold credentials are never read.
func TestEveryBackendCollectionIsClassified(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	backend := persisfile.NewBackend(backendPaths(l.DataDir))
	const secret = "fixture-secret-value-never-read"
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for name, id := range backendCollections {
		rec := &persis.Record{ID: id, Data: []byte(`{"value":"` + secret + `"}`), CreatedAt: at, UpdatedAt: at}
		require.NoError(t, backend.Collection(name).Put(context.Background(), rec), name)
	}
	if runtime.GOOS != "windows" {
		// The credential collections cannot be read at all, so a scan that
		// opened them would fail.
		for _, dir := range []string{"secrets", "oidc_sessions"} {
			p := filepath.Join(l.DataDir, dir)
			require.NoError(t, os.Chmod(p, 0o000))
			t.Cleanup(func() { _ = os.Chmod(p, 0o750) }) //nolint:gosec // restore for cleanup
		}
	}
	inv := scan(t, l)
	assert.Empty(t, continuity.Blocking(continuity.Validate(inv, continuity.Policy{})))

	excluded := map[string]bool{}
	for _, e := range inv.Excluded {
		excluded[e.Root+"/"+e.Path] = true
	}
	for _, p := range []string{"hub-data/secrets", "hub-data/oidc_sessions", "hub-data/users", "hub-data/apikeys",
		"hub-data/webhooks", "hub-data/remote-nodes", "hub-data/license"} {
		assert.True(t, excluded[p], p)
	}
	policies := map[string]string{}
	for _, f := range inv.Files {
		if f.Root == "hub-data" {
			policies[filepath.ToSlash(filepath.Dir(f.Path))] = f.Policy
		}
	}
	for dir, want := range map[string]string{
		"dag-settings":           continuity.PolicyMutable,
		"scheduler":              continuity.PolicyMutable,
		"profiles":               continuity.PolicyMutable,
		"upgrade":                continuity.PolicyOperational,
		"agent-session-cleanups": continuity.PolicyOperational,
		"distributed/pending":    continuity.PolicyOperational,
		"distributed/workers":    continuity.PolicyOperational,
	} {
		assert.Equal(t, want, policies[dir], dir)
	}
}
