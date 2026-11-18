// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmd"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/persis"
	persisfile "github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/publicwebhook"
	schedulerfile "github.com/dagucloud/dagu/v2/internal/service/scheduler/file"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
)

// Secrets the home holds in the stores that are never read. None may appear
// in an inventory or in the public webhook store.
const (
	fHomeSecret           = "f-home-secret-value-never-read"
	publicToken           = "public-url-token-never-read-0123456789"
	publicSenderSecret    = "public-sender-secret-never-read-9876543210"
	publicWebhookDAG      = "fixture-public-dag"
	publicWebhookDelivery = "delivery-1"
)

// fHomeRecords are records of collections the release before public webhooks
// (F, 4d164866) declares, as a hub on F holds them: retained settings beside
// credential stores. The collections C added after F (public_webhooks,
// webhook_dag_claims, watch_state, dag_pins) are absent.
var fHomeRecords = map[string]persis.Record{
	persis.CollectionDAGSettings: {ID: "fixture-dag", Data: []byte(`{"dagName":"fixture-dag"}`)},
	persis.CollectionViews:       {ID: "v1", Data: []byte(`{"id":"v1","name":"fixture view"}`)},
	persis.CollectionWorkspaces:  {ID: "ws1", Data: []byte(`{"id":"ws1","name":"fixture"}`)},
	persis.CollectionUsers:       {ID: "u1", Data: []byte(`{"id":"u1","username":"fixture","passwordHash":"` + fHomeSecret + `"}`)},
	persis.CollectionAPIKeys:     {ID: "k1", Data: []byte(`{"id":"k1","keyHash":"` + fHomeSecret + `"}`)},
	persis.CollectionRemoteNodes: {ID: "rn1", Data: []byte(`{"id":"rn1","password":"` + fHomeSecret + `"}`)},
	persis.CollectionSecrets:     {ID: "sec1", Data: []byte(`{"value":"` + fHomeSecret + `"}`)},
}

// TXE-7830. The candidate (C) stores the public webhook relay's status at
// every start, so a hub home it has started on holds public-webhooks/, which
// the continuity scanner did not know: the pre-rollback inventory blocked
// with unclassified_area and a C -> F rollback could not pass its gate.
//
// This starts C itself (start-all: server, scheduler and coordinator, on
// loopback ports, with no cloud credentials and no update check) on an
// F-shaped home in temporary directories, then, as C's API and scheduler
// would, gives a webhook a public URL and logs a delivery for it, starts C
// again, and runs the real continuity inventory over the home. It checks
// that nothing blocks (so no startup writer of C leaves an unclassified
// area), that the status and the log are retained as the store writes them,
// that everything the F home retained is still there and the F records are
// byte for byte the same, and that no secret reaches the inventory or the
// public webhook store.
func TestCandidateStartOnRetainedHomeKeepsContinuity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	t.Cleanup(func() { _ = fixture.Unseal(root) })
	l, _, err := fixture.Build(context.Background(), root)
	require.NoError(t, err)
	paths := filePaths(l.DataDir)
	backend := persisfile.NewBackend(paths)
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for name, rec := range fHomeRecords {
		rec.CreatedAt, rec.UpdatedAt = at, at
		require.NoError(t, backend.Collection(name).Put(context.Background(), &rec), name)
	}
	fRecordFiles := map[string][]byte{}
	walkRegular(t, l.DataDir, func(rel string, data []byte) {
		for _, dir := range []string{"dag-settings/", "views/", "workspaces/"} {
			if strings.HasPrefix(rel, dir) {
				fRecordFiles[rel] = data
			}
		}
	})
	require.Len(t, fRecordFiles, 3)

	scanHome := func() *continuity.Inventory {
		inv, err := continuity.Scan(context.Background(), continuity.Options{
			Roots: []continuity.Root{
				{Area: continuity.AreaHubData, Path: l.DataDir, Label: "hub-data", Mount: l.HubMount},
				{Area: continuity.AreaDAGs, Path: l.DAGsDir, Label: "hub-dags"},
				{Area: continuity.AreaLogs, Path: l.LogsDir, Label: "hub-logs"},
			},
			ExpectedOwner: fixture.StableOwner, Label: "txe-7830",
		})
		require.NoError(t, err)
		return inv
	}
	fInv := scanHome()
	requireNoBlocking(t, "the F home", fInv)
	_, err = os.Stat(filepath.Join(l.DataDir, "public-webhooks"))
	require.ErrorIs(t, err, fs.ErrNotExist, "an F home has no public webhook store")

	// C runs confined: its app home is a directory of its own (--dagu-home),
	// HOME is inherited and never set, every path it writes is under the
	// test's directories, both listeners start-all opens (the web server and
	// the coordinator; it disables the scheduler's and coordinator's health
	// servers) are on loopback ports, the update check is off, and with no
	// license there is no Dagu Cloud connection. Each start is bounded: it
	// is stopped once the status is stored, and must stop within
	// startStopBound.
	homeBefore, homeSet := os.LookupEnv("HOME")
	t.Cleanup(func() {
		home, set := os.LookupEnv("HOME")
		assert.Equal(t, homeBefore, home, "HOME is unchanged")
		assert.Equal(t, homeSet, set, "HOME is unchanged")
	})
	daguHome := t.TempDir()
	cfgFile := filepath.Join(daguHome, "config.yaml")
	statusFile := filepath.Join(l.DataDir, "public-webhooks", "status.json")
	startC := func(wantStatus func(publicwebhook.Status) bool) {
		t.Helper()
		require.NoError(t, os.WriteFile(cfgFile, fmt.Appendf(nil,
			"check_updates: false\nhost: 127.0.0.1\nport: %s\ncoordinator:\n  host: 127.0.0.1\n  port: %s\n"+
				"paths:\n  dags_dir: %q\n  data_dir: %q\n  log_dir: %q\n  admin_logs_dir: %q\n",
			loopbackPort(t), loopbackPort(t), l.DAGsDir, l.DataDir, l.LogsDir, filepath.Join(daguHome, "admin-logs")), 0o600))
		th := test.SetupCommand(t)
		stored := make(chan bool, 1)
		go func() {
			deadline := time.Now().Add(commandLogWaitTimeout())
			for time.Now().Before(deadline) {
				out := th.LoggingOutput.String()
				if strings.Contains(out, "Scheduler initialization") && strings.Contains(out, "Coordinator initialization") {
					if st, ok := readStatus(statusFile); ok && wantStatus(st) {
						th.Cancel()
						stored <- true
						return
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
			th.Cancel()
			stored <- false
		}()
		exited := make(chan error, 1)
		go func() {
			exited <- th.ExecuteCommand(cmd.StartAll(), test.CmdTest{Args: []string{"start-all", "--dagu-home", daguHome, "--config", cfgFile}})
		}()
		ok := <-stored
		select {
		case err := <-exited:
			require.NoError(t, err)
		case <-time.After(startStopBound):
			t.Fatalf("C did not stop within %s of being cancelled", startStopBound)
		}
		require.True(t, ok, "C did not store the relay status; output:\n%s", th.LoggingOutput.String())
	}
	notConnected := func(st publicwebhook.Status) bool { return !st.Connected && st.Error != "" }

	// First start on the F home: C stores the relay status. Every path C's
	// startup adds is logged, for the audit of its startup writers.
	fFiles := map[string]bool{}
	walkRegular(t, l.DataDir, func(rel string, _ []byte) { fFiles[rel] = true })
	startC(notConnected)
	walkRegular(t, l.DataDir, func(rel string, _ []byte) {
		if !fFiles[rel] {
			t.Logf("C's start wrote %s", rel)
		}
	})
	requireNoBlocking(t, "the F home after C started", scanHome())

	// As C's API does, give a webhook a public URL, and as its scheduler
	// does, log a delivery for it; then start C again.
	webhooks, store, err := schedulerfile.NewPublicWebhookStores(&config.Config{Paths: paths}, backend)
	require.NoError(t, err)
	wh, err := auth.NewWebhook(publicWebhookDAG, "$2a$10$fixturehashfixturehashfixturehashfixturehashfixtur", "dagu_wh_", "admin")
	require.NoError(t, err)
	wh.Public = &auth.WebhookPublic{Token: publicToken, Sender: "github", SenderSecret: publicSenderSecret, CreatedAt: at}
	require.NoError(t, webhooks.Create(context.Background(), wh))
	require.NoError(t, store.AddDelivery(context.Background(), wh.ID, publicwebhook.Delivery{ID: publicWebhookDelivery,
		Received: at, Size: 42, Event: "push", Outcome: publicwebhook.OutcomeStarted, RunID: "run-1"}))
	require.NoError(t, store.AddMissed(context.Background(), wh.ID, 1, 0, at))
	startC(notConnected)

	inv := scanHome()
	requireNoBlocking(t, "the home C ran on", inv)

	// The status and the log are retained, as the store wrote them.
	files := map[string]continuity.File{}
	for _, f := range inv.Files {
		if f.Root == "hub-data" {
			files[f.Path] = f
		}
	}
	logRel := "public-webhooks/log/" + wh.ID + ".json"
	for _, rel := range []string{"public-webhooks/status.json", logRel} {
		f, ok := files[rel]
		if assert.True(t, ok, "%s is inventoried", rel) {
			assert.Equal(t, continuity.PolicyMutable, f.Policy, rel)
		}
	}
	st, ok := readStatus(statusFile)
	require.True(t, ok)
	assert.False(t, st.Connected)
	log, err := store.Log(context.Background(), wh.ID)
	require.NoError(t, err)
	require.Len(t, log.Deliveries, 1)
	assert.Equal(t, publicWebhookDelivery, log.Deliveries[0].ID)
	assert.Equal(t, 1, log.Missed.Expired)
	assert.Equal(t, continuity.PolicyMutable, files["webhook-dag-claims/"+publicWebhookDAG+".json"].Policy, "the DAG name's claim is retained")

	// What the F home retained is all still there, and its records are the
	// same bytes.
	assert.Empty(t, continuity.Blocking(continuity.CompareProgress(fInv, inv).Issues))
	walkRegular(t, l.DataDir, func(rel string, data []byte) {
		if want, ok := fRecordFiles[rel]; ok {
			assert.Equal(t, string(want), string(data), rel)
			delete(fRecordFiles, rel)
		}
	})
	assert.Empty(t, fRecordFiles, "F records missing after C ran")

	// Secrets: the stores that hold them are excluded and never read, and
	// no secret is in the inventory or in the public webhook store.
	excluded := map[string]bool{}
	for _, e := range inv.Excluded {
		if e.Root == "hub-data" {
			excluded[e.Path] = true
		}
	}
	for _, p := range []string{"webhooks", "users", "apikeys", "remote-nodes", "secrets", "auth"} {
		assert.True(t, excluded[p], "%s is excluded", p)
	}
	for rel := range files {
		top, _, _ := strings.Cut(rel, "/")
		assert.False(t, excluded[top], "%s is under an excluded store but was inventoried", rel)
	}
	invJSON, err := json.Marshal(inv)
	require.NoError(t, err)
	stored, err := webhooks.GetByID(context.Background(), wh.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.Public)
	require.Equal(t, publicToken, stored.Public.Token, "the token round-trips through the excluded store")
	raw, err := os.ReadFile(filepath.Join(l.DataDir, "webhooks", wh.ID+".json"))
	require.NoError(t, err)
	var forStorage auth.WebhookForStorage
	require.NoError(t, json.Unmarshal(raw, &forStorage))
	for _, secret := range []string{fHomeSecret, publicToken, publicSenderSecret, forStorage.Public.TokenEnc, forStorage.Public.SenderSecretEnc} {
		require.NotEmpty(t, secret)
		assert.False(t, bytes.Contains(invJSON, []byte(secret)), "the inventory holds a secret")
		walkRegular(t, filepath.Join(l.DataDir, "public-webhooks"), func(rel string, data []byte) {
			assert.False(t, bytes.Contains(data, []byte(secret)), "public-webhooks/%s holds a secret", rel)
		})
	}
}

// startStopBound is how long a cancelled start-all may take to stop.
const startStopBound = time.Minute

// loopbackPort returns a free port on the loopback interface.
func loopbackPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

// filePaths are a data directory's paths with the loader's defaults.
func filePaths(dataDir string) config.PathsConfig {
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

func readStatus(p string) (publicwebhook.Status, bool) {
	var st publicwebhook.Status
	data, err := os.ReadFile(p) //nolint:gosec // a test path
	if err != nil || json.Unmarshal(data, &st) != nil {
		return st, false
	}
	return st, true
}

func requireNoBlocking(t *testing.T, what string, inv *continuity.Inventory) {
	t.Helper()
	blocking := continuity.Blocking(continuity.Validate(inv, continuity.Policy{}))
	for _, i := range blocking {
		t.Errorf("%s: blocking %s %s: %s", what, i.Code, i.ID, i.Detail)
	}
	if len(blocking) > 0 {
		t.FailNow()
	}
}

// walkRegular calls fn with each regular file under root, its slash path
// relative to root and its contents; lock directories are skipped.
func walkRegular(t *testing.T, root string, fn func(rel string, data []byte)) {
	t.Helper()
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p) //nolint:gosec // a test path
		if err != nil {
			return err
		}
		fn(path.Clean(filepath.ToSlash(rel)), data)
		return nil
	}))
}
