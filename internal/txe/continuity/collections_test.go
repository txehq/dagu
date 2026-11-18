// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/cmn/dirlock"
	"github.com/dagucloud/dagu/v2/internal/persis"
	persisfile "github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/publicwebhook"
	"github.com/dagucloud/dagu/v2/internal/schedulerstate"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
)

const fixtureSecret = "fixture-secret-value-never-read"

// raw is a record written as it is: the collections whose scanner area
// digests files without decoding them (classified before TXE-7830), each
// with a record of its writer's shape.
func raw(id, data string) func(*testing.T, persis.Backend, string) {
	return func(t *testing.T, b persis.Backend, name string) {
		t.Helper()
		at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		require.NoError(t, b.Collection(name).Put(context.Background(), &persis.Record{ID: id, Data: []byte(data), CreatedAt: at, UpdatedAt: at}), name)
	}
}

// collectionWriters writes, for every collection the persis package
// declares, what its writer stores. There is no default: a collection
// added to the persis package without an entry here fails
// TestEveryBackendCollectionIsClassified, and so does one the scanner does
// not classify. The collections added after F (TXE-7830) are written by
// their own stores, and the scanner decodes them strictly.
var collectionWriters = map[string]func(t *testing.T, b persis.Backend, name string){
	persis.CollectionAPIKeys:               raw("k1", `{"id":"k1","name":"ci","keyHash":"`+fixtureSecret+`"}`),
	persis.CollectionActiveDistributedRuns: raw("r1", `{"dagRunId":"r1"}`),
	persis.CollectionAgentSessionCleanups:  raw("c1", `{"sessionId":"c1"}`),
	persis.CollectionDAGRunLeases:          raw("l1", `{"dagRunId":"l1"}`),
	persis.CollectionDAGSettings:           raw("d1", `{"dagName":"d1"}`),
	persis.CollectionDAGState:              raw("s1", `{"dagName":"s1"}`),
	persis.CollectionDispatchTasks:         raw("pending/t1", `{"id":"t1"}`),
	persis.CollectionIncidents:             raw("i1", `{"id":"i1"}`),
	persis.CollectionLicense:               raw("license", `{"key":"`+fixtureSecret+`"}`),
	persis.CollectionNotifications:         raw("n1", `{"id":"n1"}`),
	persis.CollectionOIDCSessions:          raw("o1", `{"token":"`+fixtureSecret+`"}`),
	persis.CollectionProfiles:              raw("p1", `{"name":"p1"}`),
	persis.CollectionQueue:                 raw("q1", `{"dagRunId":"q1"}`),
	persis.CollectionRemoteNodes:           raw("rn1", `{"id":"rn1","password":"`+fixtureSecret+`"}`),
	persis.CollectionSchedulerState:        raw("state", `{"version":1}`),
	persis.CollectionSecrets:               raw("sec1", `{"value":"`+fixtureSecret+`"}`),
	persis.CollectionUpgradeCheck:          raw("check", `{"latest":"v0"}`),
	persis.CollectionUsers:                 raw("u1", `{"id":"u1","passwordHash":"`+fixtureSecret+`"}`),
	persis.CollectionViews:                 raw("v1", `{"id":"v1"}`),
	persis.CollectionWebhooks:              raw("w1", `{"id":"w1","tokenHash":"`+fixtureSecret+`"}`),
	persis.CollectionWorkerHeartbeats:      raw("h1", `{"workerId":"h1"}`),
	persis.CollectionWorkspaces:            raw("ws1", `{"id":"ws1"}`),
	persis.CollectionPublicWebhooks: func(t *testing.T, b persis.Backend, name string) {
		t.Helper()
		st := store.NewPublicWebhookStore(b.Collection(name))
		at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		require.NoError(t, st.SetStatus(context.Background(), publicwebhook.Status{Holding: true, URL: "https://relay.example/h", Error: "not connected", UpdatedAt: at}))
		require.NoError(t, st.AddDelivery(context.Background(), testWebhookID, publicwebhook.Delivery{ID: "d1", Received: at, Size: 1, Event: "push", Outcome: publicwebhook.OutcomeStarted, RunID: "d1"}))
	},
	persis.CollectionWebhookDAGClaims: func(t *testing.T, b persis.Backend, name string) {
		t.Helper()
		// The claim is written by the webhook store as it creates a
		// webhook; the webhook itself goes to the excluded webhooks
		// collection.
		enc, err := crypto.NewEncryptor("fixture-key")
		require.NoError(t, err)
		ws, err := store.NewWebhookStore(b.Collection(persis.CollectionWebhooks), b.Collection(name), enc)
		require.NoError(t, err)
		wh, err := auth.NewWebhook("claimed-dag", "hash", "dagu_wh_", "admin")
		require.NoError(t, err)
		require.NoError(t, ws.Create(context.Background(), wh))
	},
	persis.CollectionWatchState: func(t *testing.T, b persis.Backend, name string) {
		t.Helper()
		at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		require.NoError(t, store.NewWatchStateStore(b.Collection(name)).SaveWatch(context.Background(), map[string]schedulerstate.WatchLedger{
			"watcher": {Path: "/srv/in", Pattern: "*.csv", Epoch: "e1", Arrivals: 1, Files: map[string]schedulerstate.WatchedFile{
				"a.csv": {FileMark: schedulerstate.FileMark{Size: 3, ModTime: at}, Arrival: 1, Unqueued: true},
			}},
		}))
	},
	persis.CollectionDAGPins: func(t *testing.T, b persis.Backend, name string) {
		t.Helper()
		pins, err := store.NewDAGPinStore(b.Collection(name))
		require.NoError(t, err)
		require.NoError(t, pins.Pin(context.Background(), "pinned-dag"))
	},
}

// persisCollections lists every collection the persis package declares, from
// its source, so that a collection added there is written, and scanned, by
// TestEveryBackendCollectionIsClassified without anyone adding it to a list
// (TXE-7830: public_webhooks, webhook_dag_claims, watch_state and dag_pins
// were added to the backend and missed by a hand-kept list).
func persisCollections(t *testing.T) []string {
	t.Helper()
	return collectionsIn(t, filepath.Join("..", "..", "persis", "collection.go"))
}

// collectionsIn lists the Collection* string constants a Go file declares.
func collectionsIn(t *testing.T, file string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	require.NoError(t, err)
	var names []string
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if !strings.HasPrefix(id.Name, "Collection") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				require.True(t, ok && lit.Kind == token.STRING, "%s is not a string literal", id.Name)
				name, err := strconv.Unquote(lit.Value)
				require.NoError(t, err)
				names = append(names, name)
			}
		}
	}
	require.NotEmpty(t, names, "no collection constants found in %s", file)
	return names
}

// withoutWriter lists the collections that have no entry in
// collectionWriters.
func withoutWriter(names []string) []string {
	var missing []string
	for _, name := range names {
		if _, ok := collectionWriters[name]; !ok {
			missing = append(missing, name)
		}
	}
	return missing
}

// The check reads the constants, not a list: a constant added to a copy of
// the persis package's collection.go is found, and has no writer, so
// TestEveryBackendCollectionIsClassified would fail on it. Today every
// declared collection has one.
func TestANewCollectionConstantIsFound(t *testing.T) {
	t.Parallel()
	assert.Empty(t, withoutWriter(persisCollections(t)))
	src, err := os.ReadFile(filepath.Join("..", "..", "persis", "collection.go"))
	require.NoError(t, err)
	// The checkout may have either line ending (CRLF on Windows); both are
	// tried, whichever this one has.
	lf := strings.ReplaceAll(string(src), "\r\n", "\n")
	for name, text := range map[string]string{"lf": lf, "crlf": strings.ReplaceAll(lf, "\n", "\r\n")} {
		added := strings.Replace(text, "const (", "const (\n\tCollectionAddedLater = \"added_later\"", 1)
		require.NotEqual(t, text, added, name)
		copyPath := filepath.Join(t.TempDir(), name+"-collection.go")
		require.NoError(t, os.WriteFile(copyPath, []byte(added), 0o600))
		names := collectionsIn(t, copyPath)
		assert.Contains(t, names, "added_later", name)
		assert.Equal(t, []string{"added_later"}, withoutWriter(names), name)
	}
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
// every collection the persis package declares leaves the data directory
// fully classified: nothing blocks, every file written is either inventoried
// or under an excluded path, and the collections that hold credentials are
// never read. A collection added to the persis package and not to the
// scanner fails here, named.
func TestEveryBackendCollectionIsClassified(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	before := map[string]bool{}
	walkFiles(t, l.DataDir, func(rel string) { before[rel] = true })
	backend := persisfile.NewBackend(backendPaths(l.DataDir))
	collections := persisCollections(t)
	declared := map[string]bool{}
	for _, name := range collections {
		declared[name] = true
	}
	for name := range collectionWriters {
		assert.True(t, declared[name], "collectionWriters names %q, which the persis package does not declare", name)
	}
	// Each written file, by the collection that wrote it.
	writtenBy := map[string]string{}
	for _, name := range collections {
		write, ok := collectionWriters[name]
		if !assert.True(t, ok, "collection %q has no entry in collectionWriters: write what its writer stores, and classify it in the scanner", name) {
			continue
		}
		write(t, backend, name)
		walkFiles(t, l.DataDir, func(rel string) {
			if !before[rel] && writtenBy[rel] == "" && !strings.Contains(rel, ".dagu_record_locks/") {
				writtenBy[rel] = name
			}
		})
	}
	written := map[string]bool{}
	for _, name := range writtenBy {
		written[name] = true
	}
	for _, name := range collections {
		assert.True(t, written[name], "collection %q wrote no file", name)
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
	// A blocking issue names the path it is about; name the collection
	// that wrote under that path.
	for _, i := range continuity.Blocking(continuity.Validate(inv, continuity.Policy{})) {
		var owners []string
		for rel, name := range writtenBy {
			if id := strings.TrimPrefix(i.ID, "hub-data/"); rel == id || strings.HasPrefix(rel, id+"/") {
				owners = append(owners, name)
			}
		}
		t.Errorf("collection %v: %s %s: %s", owners, i.Code, i.ID, i.Detail)
	}

	excluded := map[string]bool{}
	for _, e := range inv.Excluded {
		if e.Root == "hub-data" {
			excluded[e.Path] = true
		}
	}
	files := map[string]continuity.File{}
	for _, f := range inv.Files {
		if f.Root == "hub-data" {
			files[f.Path] = f
		}
	}
	underExcluded := func(rel string) bool {
		for p := rel; p != "."; p = path.Dir(p) {
			if excluded[p] {
				return true
			}
		}
		return false
	}
	for rel, name := range writtenBy {
		_, inventoried := files[rel]
		assert.True(t, inventoried || underExcluded(rel), "collection %q wrote %s, which the scan neither inventoried nor excluded", name, rel)
	}
	for _, p := range []string{"secrets", "oidc_sessions", "users", "apikeys", "webhooks", "remote-nodes", "license"} {
		assert.True(t, excluded[p], p)
	}
	policies := map[string]string{}
	for rel, f := range files {
		policies[path.Dir(rel)] = f.Policy
	}
	for dir, want := range map[string]string{
		"dag-settings":           continuity.PolicyMutable,
		"scheduler":              continuity.PolicyMutable,
		"profiles":               continuity.PolicyMutable,
		"upgrade":                continuity.PolicyOperational,
		"agent-session-cleanups": continuity.PolicyOperational,
		"distributed/pending":    continuity.PolicyOperational,
		"distributed/workers":    continuity.PolicyOperational,
		"dag-pins":               continuity.PolicyMutable,
		"watch_state":            continuity.PolicyMutable,
		"webhook-dag-claims":     continuity.PolicyMutable,
		"public-webhooks":        continuity.PolicyMutable,
		"public-webhooks/log":    continuity.PolicyMutable,
	} {
		assert.Equal(t, want, policies[dir], dir)
	}
}

// walkFiles calls fn with the slash path, relative to root, of every regular
// file under root.
func walkFiles(t *testing.T, root string, fn func(rel string)) {
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
		fn(filepath.ToSlash(rel))
		return nil
	}))
}

// The scheduler holds a directory lock under its state directory while it
// runs. The lock is the process's, not retained state: an inventory taken
// while it is held excludes it, its release does not block the freeze
// comparison, and an import leaves it behind.
func TestHeldLocksAreNotRetained(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	backend := persisfile.NewBackend(backendPaths(l.DataDir))
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, backend.Collection(persis.CollectionSchedulerState).Put(context.Background(),
		&persis.Record{ID: "state", Data: []byte(`{"version":1}`), CreatedAt: at, UpdatedAt: at}))
	lock := dirlock.New(filepath.Join(persisfile.SchedulerStateDir(backendPaths(l.DataDir)), "locks"), nil)
	require.NoError(t, lock.TryLock())
	before := scan(t, l)
	require.NoError(t, lock.Unlock())
	after := scan(t, l)

	for _, f := range before.Files {
		assert.False(t, strings.Contains(f.Path, dirlock.LockDirectoryName), f.Path)
	}
	excluded := map[string]bool{}
	for _, e := range before.Excluded {
		excluded[e.Root+"/"+e.Path] = true
	}
	assert.True(t, excluded["hub-data/scheduler/locks/"+dirlock.LockDirectoryName], "%v", before.Excluded)
	rep := continuity.Compare(before, after, continuity.CompareOptions{})
	assert.Empty(t, compareCodes(rep))
	assert.Empty(t, continuity.Blocking(continuity.CompareProgress(before, after).Issues))

	plan, err := continuity.PlanTransition(before, l.DataDir, continuity.ModeImport,
		func(_, _ string, data []byte) ([]byte, error) { return data, nil }, continuity.Policy{})
	require.NoError(t, err)
	for _, step := range plan.Steps {
		assert.False(t, strings.Contains(step.Path, dirlock.LockDirectoryName), step.Path)
	}
	assert.Contains(t, plan.NotCopied, "scheduler/locks/"+dirlock.LockDirectoryName)
	var held bool
	for _, step := range plan.Steps {
		held = held || step.Path == "scheduler/state.json"
	}
	assert.True(t, held, "the scheduler's state is copied")
}
