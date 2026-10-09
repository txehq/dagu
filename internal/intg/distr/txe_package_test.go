// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	txeTestJob     = "job_01K7A5ZQ8M3N4P5R6S7T8V9W0X"
	txeTestMachine = "mch_01K7A5ZQ8M3N4P5R6S7T8V9W0Y"
)

// txeCommitPackage packages files from a throwaway source directory, then
// deletes that directory, so the run that follows can only use the package.
func txeCommitPackage(t *testing.T, sourceFiles map[string]string, include, entrypoint []string) *txepkg.Package {
	t.Helper()
	if goruntime.GOOS == "windows" {
		t.Skip("job packages are shell scripts run by a Unix worker")
	}

	source := filepath.Join(t.TempDir(), "worktree")
	for name, body := range sourceFiles {
		p := filepath.Join(source, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o755)) //nolint:gosec // test script
	}

	// The path policy is empty because test directories are temporary.
	store := &txepkg.Store{Root: filepath.Join(t.TempDir(), "txe-home", "packages")}
	t.Cleanup(func() {
		_ = filepath.WalkDir(store.Root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(p, 0o700) //nolint:gosec // let the test directory be removed
			}
			return nil
		})
	})

	staged, err := store.Stage("req-1", txepkg.BuildOptions{SourceRoot: source, Include: include, Entrypoint: entrypoint})
	require.NoError(t, err)
	pkg, err := store.Commit(staged, txeTestJob)
	require.NoError(t, err)
	require.NoError(t, os.RemoveAll(source))

	_, err = store.Verify(txeTestJob, pkg.Digest)
	require.NoError(t, err)
	return pkg
}

// txePackageFilesContaining returns the files of a package that contain needle.
func txePackageFilesContaining(t *testing.T, pkg *txepkg.Package, needle string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(pkg.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // test directory
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(needle)) {
			found = append(found, p)
		}
		return nil
	})
	require.NoError(t, err)
	return found
}

// A job runs on the assigned worker from a read-only package after the
// directory it was packaged from is gone, and leaves the package unchanged.
func TestTXEPackage_RunsWithoutSource(t *testing.T) {
	example := filepath.Join("..", "..", "..", "txe", "skill", "examples", "healthcheck", "check.sh")
	script, err := os.ReadFile(example)
	require.NoError(t, err)
	pkg := txeCommitPackage(t, map[string]string{"check.sh": string(script)}, []string{"check.sh"}, []string{"./check.sh"})

	outputs := filepath.Join(t.TempDir(), "outputs", txeTestJob)
	target := filepath.Join(t.TempDir(), "target")
	require.NoError(t, os.WriteFile(target, []byte("vol-uid-1\n"), 0o600))

	f := newTestFixture(t, fmt.Sprintf(`
name: %s
worker_selector:
  txe.machine: %s
working_dir: %q
timeout_sec: 60
env:
  - TXE_OUTPUT_DIR: %q
  - TARGET_PATH: %q
  - TARGET_ID: vol-uid-1
steps:
  - name: run
    command: ./check.sh
`, txeTestJob, txeTestMachine, pkg.WorkDir(), outputs, target),
		withLabels(map[string]string{"txe.machine": txeTestMachine}),
		withLogPersistence(),
		withIsolatedWorker(),
	)
	defer f.cleanup()

	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(30 * time.Second)

	status := f.waitForStatus(ir.Succeeded, executionStatusTimeout())
	f.assertWorkerID(status, "worker-1")
	f.assertAllNodesSucceeded(status)
	assertLogContains(t, f.logDir(), status.Name, status.DAGRunID, "run", `"state":"healthy"`)

	// The script wrote its durable result outside the package.
	observations, err := os.ReadFile(filepath.Join(outputs, "observations.jsonl"))
	require.NoError(t, err)
	assert.Contains(t, string(observations), `"target_id":"vol-uid-1"`)

	// Running wrote nothing into the package.
	store := &txepkg.Store{Root: filepath.Dir(filepath.Dir(pkg.Dir))}
	_, err = store.Verify(txeTestJob, pkg.Digest)
	require.NoError(t, err)
}

// A credential reference is resolved by the worker from a file on its own
// machine. The value reaches the script, and never reaches the DAG, the run
// status, the logs or the package. A variable that is only in the worker's
// environment does not reach the script at all.
func TestTXEPackage_CredentialStaysOnWorker(t *testing.T) {
	const (
		credential = "txe-sentinel-credential-7f3a9c41d2"
		ambient    = "txe-sentinel-ambient-5b8e0d67a1"
	)
	t.Setenv("TXE_AMBIENT_SECRET", ambient)
	// LC_ variables are passed through, which shows the probe can see the
	// environment it is given.
	t.Setenv("LC_TXE_PROBE", "visible")

	pkg := txeCommitPackage(t, map[string]string{"probe.sh": `#!/bin/sh
set -eu
mkdir -p "$TXE_OUTPUT_DIR"
token="$(printf '%s' "$FIXTURE_TOKEN")"
if [ "$token" = "$(cat "$TOKEN_FILE")" ]; then
  echo match > "$TXE_OUTPUT_DIR/result"
fi
echo "token=$token end"
echo "ambient=${TXE_AMBIENT_SECRET:-unset}"
echo "probe=${LC_TXE_PROBE:-unset}"
`}, []string{"probe.sh"}, []string{"./probe.sh"})

	// The credential lives on the worker's machine, outside the package and
	// outside everything the hub stores.
	tokenFile := filepath.Join(t.TempDir(), "machine-credentials", "fixture-token")
	require.NoError(t, os.MkdirAll(filepath.Dir(tokenFile), 0o700))
	require.NoError(t, os.WriteFile(tokenFile, []byte(credential+"\n"), 0o600))
	outputs := filepath.Join(t.TempDir(), "outputs", txeTestJob)

	f := newTestFixture(t, fmt.Sprintf(`
name: %s
worker_selector:
  txe.machine: %s
working_dir: %q
timeout_sec: 60
env:
  - TXE_OUTPUT_DIR: %q
  - TOKEN_FILE: %q
secrets:
  - name: FIXTURE_TOKEN
    provider: file
    key: %q
steps:
  - name: run
    command: ./probe.sh
`, txeTestJob, txeTestMachine, pkg.WorkDir(), outputs, tokenFile, tokenFile),
		withLabels(map[string]string{"txe.machine": txeTestMachine}),
		withLogPersistence(),
		withIsolatedWorker(),
	)
	defer f.cleanup()

	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(30 * time.Second)

	status := f.waitForStatus(ir.Succeeded, executionStatusTimeout())
	f.assertWorkerID(status, "worker-1")

	// The script received the real value.
	result, err := os.ReadFile(filepath.Join(outputs, "result"))
	require.NoError(t, err)
	assert.Equal(t, "match\n", string(result))

	// The worker's own environment is filtered before it reaches a step.
	logPath := assertLogExists(t, f.logDir(), status.Name, status.DAGRunID, "run")
	log := getLogContent(t, logPath)
	assert.Contains(t, log, "ambient=unset")
	assert.Contains(t, log, "probe=visible")
	assert.Contains(t, log, "token=******* end")
	assert.NotContains(t, log, credential)

	// Nothing the hub holds contains the credential.
	assert.NotContains(t, string(f.dagWrapper.YamlData), credential)
	statusJSON, err := json.Marshal(status)
	require.NoError(t, err)
	assert.NotContains(t, string(statusJSON), credential)
	assert.Empty(t, hubFilesContaining(t, f, credential), "the credential was written to hub storage")

	// Neither does the package.
	assert.Empty(t, txePackageFilesContaining(t, pkg, credential))
}

// A missing credential fails the run before the script starts, and the hub's
// log for the run names the reference, so the fault can be acted on from the
// dashboard without the worker's own logs.
func TestTXEPackage_MissingCredentialIsReported(t *testing.T) {
	pkg := txeCommitPackage(t, map[string]string{"probe.sh": `#!/bin/sh
mkdir -p "$TXE_OUTPUT_DIR"
echo ran > "$TXE_OUTPUT_DIR/ran"
`}, []string{"probe.sh"}, []string{"./probe.sh"})

	missing := filepath.Join(t.TempDir(), "machine-credentials", "absent-token")
	outputs := filepath.Join(t.TempDir(), "outputs", txeTestJob)

	f := newTestFixture(t, fmt.Sprintf(`
name: %s
worker_selector:
  txe.machine: %s
working_dir: %q
timeout_sec: 60
env:
  - TXE_OUTPUT_DIR: %q
secrets:
  - name: FIXTURE_TOKEN
    provider: file
    key: %q
steps:
  - name: run
    command: ./probe.sh
`, txeTestJob, txeTestMachine, pkg.WorkDir(), outputs, missing),
		withLabels(map[string]string{"txe.machine": txeTestMachine}),
		withLogPersistence(),
		withIsolatedWorker(),
	)
	defer f.cleanup()

	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(30 * time.Second)

	status := f.waitForStatus(ir.Failed, executionStatusTimeout())

	// The run status carries no reason, so the hub's log for the run is where
	// the missing reference is named.
	var runLog string
	require.NoError(t, filepath.WalkDir(filepath.Join(f.logDir(), status.Name, status.DAGRunID), func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Name() == "scheduler.log" {
			runLog = getLogContent(t, p)
		}
		return err
	}))
	assert.Contains(t, runLog, "failed to resolve secret")
	assert.Contains(t, runLog, "FIXTURE_TOKEN")
	assert.Contains(t, runLog, "secret file not found")

	// The script never ran without its credential.
	assert.NoFileExists(t, filepath.Join(outputs, "ran"))
}

// txeFakeRegistry answers the two registry calls the publish step makes, and
// keeps the manifests it is sent.
type txeFakeRegistry struct {
	mu        sync.Mutex
	version   string // JSON of the job version, served for any version number
	manifests map[string]txeclient.ArtifactManifest
	unknown   []string
}

func (r *txeFakeRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case req.Header.Get("Authorization") != "Bearer dagu_test_key":
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":"unauthorized","message":"bad key"}`)
	case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/versions/"):
		_, _ = io.WriteString(w, r.version)
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/artifacts"):
		var manifest txeclient.ArtifactManifest
		if err := json.NewDecoder(req.Body).Decode(&manifest); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		run := strings.TrimSuffix(req.URL.Path[strings.Index(req.URL.Path, "/runs/")+len("/runs/"):], "/artifacts")
		r.manifests[run] = manifest
		_ = json.NewEncoder(w).Encode(manifest)
	default:
		r.unknown = append(r.unknown, req.Method+" "+req.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

const (
	txeHubContent     = `{"collected":"txe-marker-hub-deliverable"}`
	txeMachineContent = "txe-marker-machine-only\n"
	txeStrayContent   = "txe-marker-undeclared\n"
)

// txePublishRun is a job with deliverables, rendered and queued on a real
// coordinator with one isolated worker.
type txePublishRun struct {
	f        *testFixture
	home     txepkg.Home
	registry *txeFakeRegistry
	// workerHome is the Dagu home of the process that runs the steps. Every
	// step inherits it as DAGU_HOME. It is not the store the job was
	// registered with and holds no "txe" context.
	workerHome string
}

// txeStartPublishRun renders the job's DAG, with the publish step bound to a
// context store by the flags bind returns, and starts it.
func txeStartPublishRun(t *testing.T, bind func(home txepkg.Home, workerHome string) []string) *txePublishRun {
	t.Helper()
	pkg := txeCommitPackage(t, map[string]string{"collect.sh": `#!/bin/sh
set -eu
mkdir -p "$TXE_RUN_OUTPUT_DIR/raw"
printf '%s' '` + txeHubContent + `' > "$TXE_RUN_OUTPUT_DIR/snapshot.json"
printf 'txe-marker-machine-only\n' > "$TXE_RUN_OUTPUT_DIR/raw/export.csv"
printf 'txe-marker-undeclared\n' > "$TXE_RUN_OUTPUT_DIR/debug.log"
printf '%s' "${DAGU_HOME:-}" > "$TXE_RUN_OUTPUT_DIR/inherited-dagu-home"
echo "collected into $TXE_RUN_OUTPUT_DIR"
`}, []string{"collect.sh"}, []string{"./collect.sh"})

	// The TXE home of the worker's machine: identity, outputs, and the
	// context store the publish step's CLI uses.
	home := txepkg.Home{Root: filepath.Join(t.TempDir(), "txe-home")}
	require.NoError(t, os.MkdirAll(home.Root, 0o700))
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":"own_01K7A5ZQ8M3N4P5R6S7T8V9W0A"}`, txeTestMachine)
	require.NoError(t, os.WriteFile(filepath.Join(home.Root, "machine.json"), []byte(identity), 0o600))

	registry := &txeFakeRegistry{manifests: map[string]txeclient.ArtifactManifest{}, version: `{
		"title": "Collect", "purpose": "fixture",
		"expected_outcome": {"deliverables": [
			{"name": "snapshot", "path": "snapshot.json", "delivery": "hub", "required": true},
			{"name": "raw", "path": "raw/export.csv", "delivery": "machine"},
			{"name": "notes", "path": "notes.txt"}
		]}}`}
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)

	spec := txepkg.DAGSpec{
		Title: "Collect", JobID: txeTestJob, OwnerID: "own_01K7A5ZQ8M3N4P5R6S7T8V9W0A",
		ProjectID: "prj_01K7A5ZQ8M3N4P5R6S7T8V9W0B", MachineID: txeTestMachine, Version: 1,
		PackageDigest: pkg.Digest, WorkDir: pkg.WorkDir(), OutputDir: home.OutputDir(txeTestJob),
		Entrypoint: pkg.Manifest.Entrypoint,
		Schedule:   txepkg.Schedule{Cron: "0 2 * * *", Timezone: "Australia/Perth", TimeoutSec: 120},
		Publish: &txepkg.Publish{
			// Filled in below, once the fixture has built the binary.
			Command:      []string{"/placeholder"},
			HomeRoot:     home.Root,
			HubArtifacts: true,
		},
	}
	rendered, err := txepkg.RenderDAG(spec)
	require.NoError(t, err)

	f := newTestFixture(t, string(rendered),
		withLabels(map[string]string{"txe.machine": txeTestMachine}),
		withLogPersistence(), withArtifactPersistence(), withIsolatedWorker(),
	)
	t.Cleanup(f.cleanup)

	// The publish step runs the dagu binary built from this tree, whose path
	// is known only now. Render again with it and run that DAG.
	executable := f.coord.Config.Paths.Executable
	workerHome := filepath.Dir(f.coord.Config.Paths.DataDir)
	spec.Publish.Command = append([]string{executable, "txe", "artifacts", "publish"}, bind(home, workerHome)...)
	rendered, err = txepkg.RenderDAG(spec)
	require.NoError(t, err)
	f.dagWrapper = new(f.coord.DAG(t, string(rendered)))

	// The CLI's context, created the way an installer would: a synthetic key
	// in the TXE home's own store, and nowhere else.
	add := exec.Command(executable, "context", "add", "txe", "--server", server.URL, "--api-key", "dagu_test_key", "--dagu-home", home.ClientDir()) //nolint:gosec // the binary built by the test harness
	out, err := add.CombinedOutput()
	require.NoError(t, err, string(out))

	run := &txePublishRun{f: f, home: home, registry: registry, workerHome: workerHome}

	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(30 * time.Second)
	return run
}

// inheritedHome is the DAGU_HOME the job's own step saw.
func (r *txePublishRun) inheritedHome(t *testing.T, runID string) string {
	t.Helper()
	seen, err := os.ReadFile(filepath.Join(r.home.OutputDir(txeTestJob), "runs", runID, "inherited-dagu-home"))
	require.NoError(t, err)
	return string(seen)
}

func (r *txePublishRun) manifest(runID string) (txeclient.ArtifactManifest, bool, []string) {
	r.registry.mu.Lock()
	defer r.registry.mu.Unlock()
	manifest, ok := r.registry.manifests[runID]
	return manifest, ok, slices.Clone(r.registry.unknown)
}

// A job's rendered DAG, run on a real worker, publishes exactly the files the
// job declares. The file declared for the hub arrives there with the digest
// the manifest records; the file declared for the machine and a file nobody
// declared stay on the machine and never reach hub storage.
//
// The steps inherit the worker's own DAGU_HOME, which holds no "txe" context.
// The publish step still reaches the registry, because the store it reads is
// named by its flags.
func TestTXEPackage_PublishesSelectedDeliverables(t *testing.T) {
	run := txeStartPublishRun(t, func(home txepkg.Home, _ string) []string {
		return []string{"--dagu-home", home.ClientDir()}
	})
	f, home := run.f, run.home

	status := f.waitForStatus(ir.Succeeded, executionStatusTimeout())
	f.assertWorkerID(status, "worker-1")
	require.Len(t, status.Nodes, 2)
	f.assertAllNodesSucceeded(status)
	inherited := run.inheritedHome(t, status.DAGRunID)
	assert.Equal(t, run.workerHome, inherited, "the step did not inherit the worker's DAGU_HOME; the test proves nothing about it")
	assert.NotEqual(t, home.ClientDir(), inherited)

	// The registry was told what the run produced, with digests.
	manifest, ok, unknown := run.manifest(status.DAGRunID)
	require.True(t, ok, "no manifest was recorded for run %s", status.DAGRunID)
	assert.Empty(t, unknown)
	byName := map[string]txeclient.ArtifactRecord{}
	for _, a := range manifest.Artifacts {
		byName[a.Deliverable] = a
	}
	wantSum := sha256.Sum256([]byte(txeHubContent))
	assert.Equal(t, "hub", byName["snapshot"].Location)
	assert.Equal(t, "sha256:"+hex.EncodeToString(wantSum[:]), byName["snapshot"].SHA256)
	assert.Equal(t, "machine", byName["raw"].Location)
	assert.Equal(t, txeTestMachine, byName["raw"].MachineID)
	assert.True(t, byName["notes"].Missing)

	// The hub holds the selected file, byte for byte, and nothing else of
	// the run's output.
	require.NotEmpty(t, status.ArchiveDir)
	assertArtifactDirInTree(t, f, status.ArchiveDir)
	onHub, err := os.ReadFile(filepath.Join(status.ArchiveDir, "snapshot.json"))
	require.NoError(t, err)
	gotSum := sha256.Sum256(onHub)
	assert.Equal(t, wantSum, gotSum, "the hub copy differs from the recorded digest")
	assert.NotEmpty(t, hubFilesContaining(t, f, "txe-marker-hub-deliverable"))
	assert.Empty(t, hubFilesContaining(t, f, "txe-marker-machine-only"), "a machine-only deliverable reached hub storage")
	assert.Empty(t, hubFilesContaining(t, f, "txe-marker-undeclared"), "an undeclared file reached hub storage")
	// The key is in the client store, not in anything the hub holds.
	assert.Empty(t, hubFilesContaining(t, f, "dagu_test_key"), "the registry key reached hub storage")

	// All three files are still on the machine, in the run's own directory.
	runDir := filepath.Join(home.OutputDir(txeTestJob), "runs", status.DAGRunID)
	for name, content := range map[string]string{"snapshot.json": txeHubContent, "raw/export.csv": txeMachineContent, "debug.log": txeStrayContent} {
		local, err := os.ReadFile(filepath.Join(runDir, filepath.FromSlash(name)))
		require.NoError(t, err)
		assert.Equal(t, content, string(local))
	}
}

// With no store named at all, the publish step uses the TXE home's own, which
// the DAG names in TXE_DAGU_HOME. The worker's DAGU_HOME is not consulted.
func TestTXEPackage_PublishIgnoresWorkerHome(t *testing.T) {
	run := txeStartPublishRun(t, func(txepkg.Home, string) []string { return nil })

	status := run.f.waitForStatus(ir.Succeeded, executionStatusTimeout())
	run.f.assertAllNodesSucceeded(status)
	assert.Equal(t, run.workerHome, run.inheritedHome(t, status.DAGRunID))
	_, ok, unknown := run.manifest(status.DAGRunID)
	assert.True(t, ok, "no manifest was recorded for run %s", status.DAGRunID)
	assert.Empty(t, unknown)
}

// The store the flags name is the one that is read. Bound to the worker's own
// Dagu home, which has no "txe" context, the publish step fails: the run is
// failed on the hub, the hub's log says which context is missing, and nothing
// is recorded or uploaded. This is what an unbound step did when it took its
// store from the worker's environment.
func TestTXEPackage_PublishFailsWithoutContext(t *testing.T) {
	run := txeStartPublishRun(t, func(_ txepkg.Home, workerHome string) []string {
		return []string{"--dagu-home", workerHome}
	})
	f := run.f

	status := f.waitForStatus(ir.Failed, executionStatusTimeout())
	require.Len(t, status.Nodes, 2)
	assert.Equal(t, "publish", status.Nodes[1].Step.Name)
	assert.Contains(t, hubLog(t, f, status, "publish", "stderr"), `context "txe"`)

	_, ok, _ := run.manifest(status.DAGRunID)
	assert.False(t, ok, "a manifest was recorded without the job's context")
	assert.Empty(t, hubFilesContaining(t, f, "txe-marker-hub-deliverable"), "a deliverable was uploaded without a recorded manifest")
}
