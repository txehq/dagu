// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/queue"
	"github.com/dagucloud/dagu/v2/internal/runtime/executor"
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

// A missing credential fails the run before the script starts. The hub's
// stored status for the run classifies the failure and names the reference,
// so the fault can be acted on without reading any log; where the credential
// is kept is not in the status. The hub's log for the run names it too.
func TestTXEPackage_MissingCredentialIsReported(t *testing.T) {
	pkg := txeCommitPackage(t, map[string]string{"probe.sh": `#!/bin/sh
mkdir -p "$TXE_OUTPUT_DIR"
echo ran > "$TXE_OUTPUT_DIR/ran"
`}, []string{"probe.sh"}, []string{"./probe.sh"})

	missing := filepath.Join(t.TempDir(), "txe-locator-marker", "absent-token")
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

	// The status the hub stored, as pushed by the worker.
	require.NotNil(t, status.StartupFailure, "the hub's status does not classify the failure")
	assert.Equal(t, ir.StartupFailure{Code: ir.StartupFailureSecretUnavailable, Secret: "FIXTURE_TOKEN", Provider: "file"}, *status.StartupFailure)
	assert.Equal(t, `secret "FIXTURE_TOKEN" could not be resolved from provider "file"`, status.Error)
	statusJSON, err := json.Marshal(status)
	require.NoError(t, err)
	assert.NotContains(t, string(statusJSON), "txe-locator-marker", "the hub's status says where the credential is kept")

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
// keeps the manifests it is sent: the last one per run, and each one per run
// and execution reference.
type txeFakeRegistry struct {
	mu         sync.Mutex
	version    string // JSON of the job version, served for any version number
	manifests  map[string]txeclient.ArtifactManifest
	executions map[string]txeclient.ArtifactManifest
	unknown    []string
	// down makes the registry refuse manifests, as an unreachable hub would.
	down bool
}

func (r *txeFakeRegistry) setDown(down bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.down = down
}

// execution returns the manifest the execution a status describes published.
func (r *txeFakeRegistry) execution(status ir.DAGRunStatus) (txeclient.ArtifactManifest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	manifest, ok := r.executions[status.DAGRunID+"/"+txeExecution(status).Ref()]
	return manifest, ok
}

// txeExecution is the execution a stored status describes: its attempt and
// the queue marker the hub holds for it.
func txeExecution(status ir.DAGRunStatus) txeclient.Execution {
	return txeclient.Execution{AttemptID: status.AttemptID, QueuedAt: status.QueuedAt}
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
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/artifacts") && r.down:
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"code":"unavailable","message":"the registry is down"}`)
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/artifacts"):
		var manifest txeclient.ArtifactManifest
		if err := json.NewDecoder(req.Body).Decode(&manifest); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		run := strings.TrimSuffix(req.URL.Path[strings.Index(req.URL.Path, "/runs/")+len("/runs/"):], "/artifacts")
		r.manifests[run] = manifest
		r.executions[run+"/"+manifest.Ref()] = manifest
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
	// checkLog has one line per call of the stand-in resource check; a
	// number in checkExit makes the stand-in exit with it.
	checkLog, checkExit string
}

// checks returns the argument lines of every resource check so far.
func (r *txePublishRun) checks(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(r.checkLog)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// txePublishStore says where the CLI's "txe" context is created, when that is
// not the TXE home's own store.
type txePublishStore struct {
	// flags select the store for "dagu context add".
	flags []string
	// dir is the directory that command runs in.
	dir string
}

// txeCollectScript is the fixture job: it writes one deliverable for the hub,
// one for the machine and a file nobody declared.
const txeCollectScript = `#!/bin/sh
set -eu
mkdir -p "$TXE_RUN_OUTPUT_DIR/raw"
printf '%s' '` + txeHubContent + `' > "$TXE_RUN_OUTPUT_DIR/snapshot.json"
printf 'txe-marker-machine-only\n' > "$TXE_RUN_OUTPUT_DIR/raw/export.csv"
printf 'txe-marker-undeclared\n' > "$TXE_RUN_OUTPUT_DIR/debug.log"
printf '%s' "${DAGU_HOME:-}" > "$TXE_RUN_OUTPUT_DIR/inherited-dagu-home"
echo "collected into $TXE_RUN_OUTPUT_DIR"
`

// txeStartPublishRun renders the job's DAG, with the publish step bound to a
// context store by the flags bind returns, and starts it.
func txeStartPublishRun(t *testing.T, bind func(home txepkg.Home, workerHome string) []string, stores ...txePublishStore) *txePublishRun {
	t.Helper()
	return txeStartPublishJob(t, txeCollectScript, nil, bind, stores...)
}

// txeStartPublishJob is txeStartPublishRun for a job script and settings of
// the caller's choosing.
func txeStartPublishJob(t *testing.T, script string, env map[string]string, bind func(home txepkg.Home, workerHome string) []string, stores ...txePublishStore) *txePublishRun {
	t.Helper()
	// Queued, then run by the scheduler: the way a job's schedule runs it.
	return txeStartPublishJobWith(t, script, env, bind, func(f *testFixture) {
		require.NoError(t, f.enqueue())
		f.waitForQueued()
		f.startScheduler(30 * time.Second)
	}, stores...)
}

// txeStartPublishJobWith is txeStartPublishJob with the caller deciding how
// the run is started.
func txeStartPublishJobWith(t *testing.T, script string, env map[string]string, bind func(home txepkg.Home, workerHome string) []string, start func(*testFixture), stores ...txePublishStore) *txePublishRun {
	t.Helper()
	pkg := txeCommitPackage(t, map[string]string{"collect.sh": script}, []string{"collect.sh"}, []string{"./collect.sh"})

	// The TXE home of the worker's machine: identity, outputs, and the
	// context store the publish step's CLI uses.
	home := txepkg.Home{Root: filepath.Join(t.TempDir(), "txe-home")}
	require.NoError(t, os.MkdirAll(home.Root, 0o700))
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":"own_01K7A5ZQ8M3N4P5R6S7T8V9W0A"}`, txeTestMachine)
	require.NoError(t, os.WriteFile(filepath.Join(home.Root, "machine.json"), []byte(identity), 0o600))

	registry := &txeFakeRegistry{manifests: map[string]txeclient.ArtifactManifest{}, executions: map[string]txeclient.ArtifactManifest{}, version: `{
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
		Env:        env,
		// Filled in below, once the fixture has built the binary.
		CLI:     txepkg.CLI{Dagu: "/placeholder", HomeRoot: home.Root},
		Publish: &txepkg.Publish{HubArtifacts: true},
	}
	rendered, err := txepkg.RenderDAG(spec)
	require.NoError(t, err)

	f := newTestFixture(t, string(rendered),
		withLabels(map[string]string{"txe.machine": txeTestMachine}),
		withLogPersistence(), withArtifactPersistence(), withIsolatedWorker(),
	)
	t.Cleanup(f.cleanup)

	// The steps run the dagu binary built from this tree, whose path is
	// known only now. Render again with it and run that DAG.
	//
	// The binary has no "txe resource check" yet: that command is another
	// change. The dagu the DAG calls is therefore a wrapper that stands in
	// for that one command, recording how it was called and exiting with the
	// code the test asks for, and hands every other command to the binary.
	executable := f.coord.Config.Paths.Executable
	workerHome := filepath.Dir(f.coord.Config.Paths.DataDir)
	require.NoError(t, os.MkdirAll(filepath.Join(home.Root, "bin"), 0o700))
	checkLog, checkExit := filepath.Join(home.Root, "resource-check.log"), filepath.Join(home.Root, "resource-check.exit")
	wrapper := fmt.Sprintf(`#!/bin/sh
if [ "$1 $2 $3" = "txe resource check" ]; then
  printf '%%s\n' "$*" >> %q
  if [ -e %q ]; then exit "$(cat %q)"; fi
  exit 0
fi
exec %q "$@"
`, checkLog, checkExit, checkExit, executable)
	require.NoError(t, os.WriteFile(filepath.Join(home.Root, "bin", "dagu"), []byte(wrapper), 0o700)) //nolint:gosec // a test script
	spec.CLI.Dagu = filepath.Join(home.Root, "bin", "dagu")
	spec.CLI.StoreFlags = bind(home, workerHome)
	rendered, err = txepkg.RenderDAG(spec)
	require.NoError(t, err)
	f.dagWrapper = new(f.coord.DAG(t, string(rendered)))

	// The CLI's context, created the way an installer would: a synthetic key
	// in the TXE home's own store, and nowhere else.
	store := txePublishStore{flags: []string{"--dagu-home", home.ClientDir()}}
	if len(stores) > 0 {
		store = stores[0]
	}
	add := exec.Command(executable, append([]string{"context", "add", "txe", "--server", server.URL, "--api-key", "dagu_test_key"}, store.flags...)...) //nolint:gosec // the binary built by the test harness
	add.Dir = store.dir
	out, err := add.CombinedOutput()
	require.NoError(t, err, string(out))

	run := &txePublishRun{f: f, home: home, registry: registry, workerHome: workerHome, checkLog: checkLog, checkExit: checkExit}

	start(f)
	return run
}

// outputDir is where the results of the execution a status describes are
// kept on the machine once it has sealed them.
func (r *txePublishRun) outputDir(status ir.DAGRunStatus) string {
	return txepkg.ExecutionOutputDir(r.home.OutputDir(txeTestJob), status.DAGRunID, txeExecution(status).Ref())
}

// hubCopies is where the hub keeps the copies the execution a status
// describes published, given the artifact directory of its attempt.
func txeHubCopies(archiveDir string, status ir.DAGRunStatus) string {
	return filepath.Join(archiveDir, txeclient.HubAttemptsDir, txeExecution(status).Ref())
}

// inheritedHome is the DAGU_HOME the job's own step saw.
func (r *txePublishRun) inheritedHome(t *testing.T, status ir.DAGRunStatus) string {
	t.Helper()
	seen, err := os.ReadFile(filepath.Join(r.outputDir(status), "inherited-dagu-home"))
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
	inherited := run.inheritedHome(t, status)
	assert.Equal(t, run.workerHome, inherited, "the step did not inherit the worker's DAGU_HOME; the test proves nothing about it")
	assert.NotEqual(t, home.ClientDir(), inherited)

	// The registry was told what the run produced, with digests.
	manifest, ok, unknown := run.manifest(status.DAGRunID)
	require.True(t, ok, "no manifest was recorded for run %s", status.DAGRunID)
	assert.Empty(t, unknown)
	// The publish step named the execution the hub holds for the run: Dagu
	// gave the step its own attempt ID and queue marker.
	require.NotEmpty(t, status.AttemptID)
	require.NotEmpty(t, status.QueuedAt, "an enqueued run has no queue marker")
	assert.Equal(t, txeExecution(status), manifest.Execution)
	assert.Equal(t, txeExecution(status), manifest.ProducedIn)
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
	onHub, err := os.ReadFile(filepath.Join(txeHubCopies(status.ArchiveDir, status), "snapshot.json"))
	require.NoError(t, err)
	gotSum := sha256.Sum256(onHub)
	assert.Equal(t, wantSum, gotSum, "the hub copy differs from the recorded digest")
	assert.NotEmpty(t, hubFilesContaining(t, f, "txe-marker-hub-deliverable"))
	assert.Empty(t, hubFilesContaining(t, f, "txe-marker-machine-only"), "a machine-only deliverable reached hub storage")
	assert.Empty(t, hubFilesContaining(t, f, "txe-marker-undeclared"), "an undeclared file reached hub storage")
	// The key is in the client store, not in anything the hub holds.
	assert.Empty(t, hubFilesContaining(t, f, "dagu_test_key"), "the registry key reached hub storage")

	// All three files are still on the machine, under the execution's
	// reference, and the execution is the one sealed as the run's result.
	runDir := run.outputDir(status)
	seal, err := txeclient.Outputs{Home: home}.Sealed(txeTestJob, status.DAGRunID)
	require.NoError(t, err)
	assert.Equal(t, txeExecution(status), seal.Execution)
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
	assert.Equal(t, run.workerHome, run.inheritedHome(t, status))
	_, ok, unknown := run.manifest(status.DAGRunID)
	assert.True(t, ok, "no manifest was recorded for run %s", status.DAGRunID)
	assert.Empty(t, unknown)
}

// The store the flags name is the one that is read. Bound to the worker's own
// Dagu home, which has no "txe" context, the run fails at the first command
// of the job's step, before the job's own command: the job does not execute
// when what it produces could not be recorded. The run is failed on the hub,
// the hub's log says which context is missing, and nothing is recorded or
// uploaded. This is what an unbound step did when it took its store from the
// worker's environment.
func TestTXEPackage_PublishFailsWithoutContext(t *testing.T) {
	run := txeStartPublishRun(t, func(_ txepkg.Home, workerHome string) []string {
		return []string{"--dagu-home", workerHome}
	})
	f := run.f

	status := f.waitForStatus(ir.Failed, executionStatusTimeout())
	require.Len(t, status.Nodes, 2)
	assert.Equal(t, "run", status.Nodes[0].Step.Name)
	assert.Equal(t, ir.NodeFailed, status.Nodes[0].Status)
	assert.Contains(t, hubLog(t, f, status, "run", "stderr"), `context "txe"`)
	assert.NoDirExists(t, filepath.Join(run.home.OutputDir(txeTestJob), "runs"), "the job ran without its context")

	_, ok, _ := run.manifest(status.DAGRunID)
	assert.False(t, ok, "a manifest was recorded without the job's context")
	assert.Empty(t, hubFilesContaining(t, f, "txe-marker-hub-deliverable"), "a deliverable was uploaded without a recorded manifest")
}

// The context store was set up through a configuration whose paths are
// relative, so it sits wherever the session ran. The publish step runs in the
// package's directory, where the same configuration would name another,
// empty store. Given the two directories the session resolved, it reads the
// session's store and reaches the registry.
func TestTXEPackage_PublishUsesResolvedStore(t *testing.T) {
	base := t.TempDir()
	session := filepath.Join(base, "session")
	require.NoError(t, os.MkdirAll(session, 0o700))
	config := filepath.Join(base, "hub.yaml")
	require.NoError(t, os.WriteFile(config, []byte("paths:\n  contexts_dir: ./contexts\n  data_dir: ./data\n"), 0o600))
	flags := []string{"--dagu-home", filepath.Join(base, "hub-home"), "--config", config}

	run := txeStartPublishRun(t, func(txepkg.Home, string) []string {
		return append(slices.Clone(flags), "--contexts-dir", filepath.Join(session, "contexts"), "--data-dir", filepath.Join(session, "data"))
	}, txePublishStore{flags: flags, dir: session})

	// The relative paths did put the store in the session's directory.
	stored, err := os.ReadDir(filepath.Join(session, "contexts"))
	require.NoError(t, err)
	require.NotEmpty(t, stored, "the context was not stored under the session's directory; the test proves nothing")

	status := run.f.waitForStatus(ir.Succeeded, executionStatusTimeout())
	run.f.assertAllNodesSucceeded(status)
	_, ok, unknown := run.manifest(status.DAGRunID)
	assert.True(t, ok, "no manifest was recorded for run %s", status.DAGRunID)
	assert.Empty(t, unknown)
}

// txeRetryScript writes a snapshot that differs with every execution of the
// job's step, and fails while the control directory says so. It does not
// create its output directory: the step's first command does.
const txeRetryScript = `#!/bin/sh
set -eu
n=$(ls "$TXE_FIXTURE_CONTROL" | grep -c '^executed\.' || true)
n=$((n+1))
: > "$TXE_FIXTURE_CONTROL/executed.$n"
printf '{"collected":"txe-marker-execution-%s"}' "$n" > "$TXE_RUN_OUTPUT_DIR/snapshot.json"
if [ -e "$TXE_FIXTURE_CONTROL/fail-job" ]; then exit 7; fi
`

func txeExecutionContent(n int) string {
	return fmt.Sprintf(`{"collected":"txe-marker-execution-%d"}`, n)
}

func txeDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// txeHubAttempt is one attempt of a run as the hub stores it.
type txeHubAttempt struct {
	id, queuedAt, archiveDir string
}

// txeHubAttempts reads every attempt the hub keeps for a run from the hub's
// own run store, oldest first.
func txeHubAttempts(t *testing.T, f *testFixture, runID string) []txeHubAttempt {
	t.Helper()
	var dirs []string
	require.NoError(t, filepath.WalkDir(f.coord.Config.Paths.DAGRunsDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && strings.HasPrefix(d.Name(), "a_") && strings.Contains(filepath.Base(filepath.Dir(p)), runID) {
			dirs = append(dirs, p)
		}
		return nil
	}))
	slices.Sort(dirs)
	attempts := make([]txeHubAttempt, 0, len(dirs))
	for _, dir := range dirs {
		data, err := os.ReadFile(filepath.Join(dir, "status.jsonl"))
		require.NoError(t, err)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		var status struct {
			AttemptID  string `json:"attemptId"`
			QueuedAt   string `json:"queuedAt"`
			ArchiveDir string `json:"archiveDir"`
		}
		require.NoError(t, json.Unmarshal([]byte(lines[len(lines)-1]), &status))
		attempts = append(attempts, txeHubAttempt{id: status.AttemptID, queuedAt: status.QueuedAt, archiveDir: status.ArchiveDir})
	}
	return attempts
}

// retryDirect retries a run the way the hub's API does for a job a worker
// runs: a retry task dispatched to the coordinator. With fromStep, that step
// and everything after it run again; without, only what failed.
func (r *txePublishRun) retryDirect(t *testing.T, runID, fromStep string) {
	t.Helper()
	f := r.f
	previous, err := f.latestStatus()
	require.NoError(t, err)
	dag := f.dagWrapper.DAG
	opts := []executor.TaskOption{executor.WithWorkerSelector(dag.WorkerSelector), executor.WithPreviousStatus(&previous)}
	if fromStep != "" {
		opts = append(opts, executor.WithStep(fromStep), executor.WithIncludeDownstream(true))
	}
	task := executor.CreateTask(dag.Name, string(dag.YamlData), dispatch.DispatchOperationRetry, runID, opts...)
	require.NoError(t, f.coord.GetCoordinatorClient(t).Dispatch(f.coord.Context, dispatch.DispatchRequest{Task: task}))
}

// retryQueued retries a run the way the hub does when the retry goes through
// a queue. The call adds nothing while the previous execution is still being
// released, so it is repeated until it does; once it has added the retry, it
// is not asked again.
func (r *txePublishRun) retryQueued(t *testing.T) {
	t.Helper()
	f := r.f
	require.Eventually(t, func() bool {
		previous, err := f.latestStatus()
		if err != nil {
			return false
		}
		added, err := queue.EnqueueRetry(f.coord.Context, f.coord.DAGRunRepository, f.coord.QueueStore, f.dagWrapper.DAG, &previous,
			queue.EnqueueRetryOptions{Processes: f.coord.ProcRepository})
		return err == nil && added
	}, distrTestTimeout(20*time.Second), 200*time.Millisecond, "the retry was not queued")
}

// waitFor waits until the run's latest status on the hub satisfies done.
func (r *txePublishRun) waitFor(t *testing.T, what string, done func(ir.DAGRunStatus) bool) ir.DAGRunStatus {
	t.Helper()
	var status ir.DAGRunStatus
	require.Eventually(t, func() bool {
		latest, err := r.f.latestStatus()
		if err != nil {
			return false
		}
		status = latest
		return done(latest)
	}, distrTestTimeout(40*time.Second), 200*time.Millisecond, what)
	return status
}

func txeExecutions(t *testing.T, control string) int {
	t.Helper()
	entries, err := os.ReadDir(control)
	require.NoError(t, err)
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "executed.") {
			n++
		}
	}
	return n
}

func txeReadFile(t *testing.T, parts ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(parts...))
	require.NoError(t, err)
	return string(data)
}

// A retry keeps the run ID. When it goes to the coordinator directly, each
// retry is a new attempt, and every execution keeps what it produced: on the
// machine, in the hub's storage, and as its own manifest.
//
// Three executions of one run: the job succeeds and publishes; the job is run
// again from its step, writes other bytes, and cannot reach the registry; the
// run is retried and only the publish step runs.
func TestTXEPackage_RetryKeepsEveryExecution(t *testing.T) {
	control := t.TempDir()
	run := txeStartPublishJob(t, txeRetryScript, map[string]string{"TXE_FIXTURE_CONTROL": control},
		func(home txepkg.Home, _ string) []string { return []string{"--dagu-home", home.ClientDir()} })
	f, home := run.f, run.home
	outputs := txeclient.Outputs{Home: home}

	first := f.waitForStatus(ir.Succeeded, executionStatusTimeout())
	runID := first.DAGRunID
	require.Equal(t, 1, txeExecutions(t, control))
	manifest, ok := run.registry.execution(first)
	require.True(t, ok, "the first execution recorded no manifest")
	assert.Equal(t, txeDigest(txeExecutionContent(1)), manifest.Artifacts[0].SHA256)

	// The job runs again, from its step, and writes other bytes. The
	// registry cannot be reached, so the execution fails at publish.
	run.registry.setDown(true)
	run.retryDirect(t, runID, "run")
	second := run.waitFor(t, "the second execution did not fail", func(s ir.DAGRunStatus) bool {
		return s.DAGRunID == runID && s.AttemptID != first.AttemptID && s.Status == ir.Failed
	})
	require.Equal(t, 2, txeExecutions(t, control))
	require.NotEqual(t, txeExecution(first).Ref(), txeExecution(second).Ref())
	assert.Equal(t, txeExecutionContent(1), txeReadFile(t, run.outputDir(first), "snapshot.json"), "the retry wrote over the first execution's output")
	assert.Equal(t, txeExecutionContent(2), txeReadFile(t, run.outputDir(second), "snapshot.json"))
	seal, err := outputs.Sealed(txeTestJob, runID)
	require.NoError(t, err)
	assert.Equal(t, txeExecution(second), seal.Execution)
	_, ok = run.registry.execution(second)
	assert.False(t, ok)
	assert.Empty(t, hubFilesContaining(t, f, "txe-marker-execution-2"), "bytes reached hub storage without a recorded manifest")

	// The run is retried. The job's step succeeded, so only publish runs:
	// a third execution that publishes what the second produced.
	run.registry.setDown(false)
	run.retryDirect(t, runID, "")
	third := run.waitFor(t, "the third execution did not succeed", func(s ir.DAGRunStatus) bool {
		return s.DAGRunID == runID && s.AttemptID != second.AttemptID && s.Status == ir.Succeeded
	})
	require.Equal(t, 2, txeExecutions(t, control), "a retry of the publish step ran the job again")
	assert.NoDirExists(t, run.outputDir(third))
	manifest, ok = run.registry.execution(third)
	require.True(t, ok, "the third execution recorded no manifest")
	assert.Equal(t, txeExecution(third), manifest.Execution)
	assert.Equal(t, txeExecution(second), manifest.ProducedIn)
	assert.Equal(t, txeDigest(txeExecutionContent(2)), manifest.Artifacts[0].SHA256)

	// The hub keeps three attempts of the run. The first and the third each
	// hold their own copy; the first execution's bytes and manifest are as
	// they were.
	attempts := txeHubAttempts(t, f, runID)
	require.Len(t, attempts, 3)
	archive := map[string]string{}
	for _, a := range attempts {
		archive[a.id] = a.archiveDir
	}
	require.Contains(t, archive, first.AttemptID)
	require.Contains(t, archive, third.AttemptID)
	assert.Equal(t, txeExecutionContent(1), txeReadFile(t, txeHubCopies(archive[first.AttemptID], first), "snapshot.json"))
	assert.Equal(t, txeExecutionContent(2), txeReadFile(t, txeHubCopies(archive[third.AttemptID], third), "snapshot.json"))
	kept, ok := run.registry.execution(first)
	require.True(t, ok)
	assert.Equal(t, txeDigest(txeExecutionContent(1)), kept.Artifacts[0].SHA256)
	assert.Equal(t, txeExecutionContent(1), txeReadFile(t, run.outputDir(first), "snapshot.json"))
}

// A retry that goes through a queue executes again under the SAME attempt
// ID with a later queue marker, and the hub keeps one attempt for the run.
// Each execution is still its own: its files are kept under its own
// reference, and it publishes under its own reference.
//
// Three executions of one run and one attempt: the job fails; it succeeds
// and publish cannot reach the registry; publish alone runs and succeeds.
func TestTXEPackage_QueuedRetryKeepsEveryExecution(t *testing.T) {
	control := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(control, "fail-job"), nil, 0o600))
	run := txeStartPublishJob(t, txeRetryScript, map[string]string{"TXE_FIXTURE_CONTROL": control},
		func(home txepkg.Home, _ string) []string { return []string{"--dagu-home", home.ClientDir()} })
	f, home := run.f, run.home
	outputs := txeclient.Outputs{Home: home}
	runRoot := filepath.Join(home.OutputDir(txeTestJob), "runs")

	first := f.waitForStatus(ir.Failed, executionStatusTimeout())
	runID := first.DAGRunID
	require.Equal(t, 1, txeExecutions(t, control))
	_, err := outputs.Sealed(txeTestJob, runID)
	require.ErrorIs(t, err, txeclient.ErrNotSealed, "a failed job step sealed its outputs")

	// The job succeeds on the retry; the registry cannot be reached.
	require.NoError(t, os.Remove(filepath.Join(control, "fail-job")))
	run.registry.setDown(true)
	run.retryQueued(t)
	second := run.waitFor(t, "the second execution did not fail at publish", func(s ir.DAGRunStatus) bool {
		return s.DAGRunID == runID && s.Status == ir.Failed && txeExecutions(t, control) == 2 &&
			len(s.Nodes) == 2 && s.Nodes[0].Status == ir.NodeSucceeded
	})
	require.Equal(t, first.AttemptID, second.AttemptID, "a queued retry got a new attempt; the test's premise is gone")
	require.NotEqual(t, first.QueuedAt, second.QueuedAt, "a queued retry kept the queue marker")
	seal, err := outputs.Sealed(txeTestJob, runID)
	require.NoError(t, err)
	assert.Equal(t, txeExecution(second), seal.Execution)
	assert.Equal(t, txeExecutionContent(2), txeReadFile(t, run.outputDir(second), "snapshot.json"))
	// What the failed execution had written is kept, set aside.
	assert.Equal(t, txeExecutionContent(1), txeReadFile(t, runRoot, runID, "unsealed", first.AttemptID+".1", "snapshot.json"))
	assert.Empty(t, hubFilesContaining(t, f, "txe-marker-execution-2"), "bytes reached hub storage without a recorded manifest")

	// The publish step alone runs on the next retry: a third execution of
	// the same attempt, publishing what the second produced.
	run.registry.setDown(false)
	run.retryQueued(t)
	third := run.waitFor(t, "the third execution did not succeed", func(s ir.DAGRunStatus) bool {
		return s.DAGRunID == runID && s.Status == ir.Succeeded && s.QueuedAt != second.QueuedAt
	})
	require.Equal(t, first.AttemptID, third.AttemptID)
	require.Equal(t, 2, txeExecutions(t, control), "a retry of the publish step ran the job again")
	manifest, ok := run.registry.execution(third)
	require.True(t, ok, "no manifest was recorded")
	assert.Equal(t, txeExecution(third), manifest.Execution)
	assert.Equal(t, txeExecution(second), manifest.ProducedIn)
	assert.Equal(t, txeDigest(txeExecutionContent(2)), manifest.Artifacts[0].SHA256)

	attempts := txeHubAttempts(t, f, runID)
	require.Len(t, attempts, 1, "the hub keeps one attempt for a run retried through the queue")
	archiveDir := attempts[0].archiveDir
	assert.Equal(t, txeExecutionContent(2), txeReadFile(t, txeHubCopies(archiveDir, third), "snapshot.json"))
}

// A run that was started without being queued has an empty queue marker.
// Its steps receive the empty marker, not an unresolved reference, and the
// job seals and publishes under the reference of (attempt, empty marker).
func TestTXEPackage_UnqueuedRunPublishes(t *testing.T) {
	run := txeStartPublishJobWith(t, txeCollectScript, nil,
		func(home txepkg.Home, _ string) []string { return []string{"--dagu-home", home.ClientDir()} },
		func(f *testFixture) { require.NoError(t, f.start()) })
	f := run.f

	status := f.waitForStatus(ir.Succeeded, executionStatusTimeout())
	f.assertAllNodesSucceeded(status)
	require.Empty(t, status.QueuedAt, "the run was queued; the test proves nothing about a run that was not")
	execution := txeExecution(status)

	manifest, ok := run.registry.execution(status)
	require.True(t, ok, "no manifest was recorded for the unqueued run")
	assert.Equal(t, execution, manifest.Execution)
	assert.Empty(t, manifest.QueuedAt)
	assert.Equal(t, execution, manifest.ProducedIn)
	assert.Equal(t, txeHubContent, txeReadFile(t, run.outputDir(status), "snapshot.json"))
	assert.Equal(t, txeHubContent, txeReadFile(t, txeHubCopies(status.ArchiveDir, status), "snapshot.json"))
}

// The resource check is the first command of the job's step. It is called
// with the job, the version and the machine the DAG was rendered for and the
// store flags; when it stops, the job does not run and nothing is sealed or
// published; and it is called again whenever the job runs again, a retry
// included, but not when only the publish step is retried.
//
// The check itself is a stand-in here: what is shown is what the rendered
// step does with its exit code.
func TestTXEPackage_ResourceCheckGatesTheJob(t *testing.T) {
	control := t.TempDir()
	// Not started yet: the stand-in is told what to answer first.
	run := txeStartPublishJobWith(t, txeRetryScript, map[string]string{"TXE_FIXTURE_CONTROL": control},
		func(home txepkg.Home, _ string) []string { return []string{"--dagu-home", home.ClientDir()} },
		func(*testFixture) {})
	f, home := run.f, run.home

	// Exit 3: a target is gone. The job's command does not run.
	require.NoError(t, os.WriteFile(run.checkExit, []byte("3"), 0o600))
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(60 * time.Second)
	first := f.waitForStatus(ir.Failed, executionStatusTimeout())
	runID := first.DAGRunID
	require.Len(t, first.Nodes, 2)
	assert.Equal(t, ir.NodeFailed, first.Nodes[0].Status)
	assert.Contains(t, []ir.NodeStatus{ir.NodeNotStarted, ir.NodeAborted}, first.Nodes[1].Status, "publish ran after the check stopped the job")
	assert.Equal(t, 0, txeExecutions(t, control), "the job ran although the check said not to")
	_, err := txeclient.Outputs{Home: home}.Sealed(txeTestJob, runID)
	require.ErrorIs(t, err, txeclient.ErrNotSealed)
	assert.Empty(t, run.registry.manifests)
	checks := run.checks(t)
	require.Len(t, checks, 1)
	assert.Equal(t, "txe resource check --job "+txeTestJob+" --job-version 1 --machine "+txeTestMachine+" --dagu-home "+home.ClientDir(), checks[0])

	// Exit 75: a target cannot be observed. A retry checks again and the
	// job still does not run.
	require.NoError(t, os.WriteFile(run.checkExit, []byte("75"), 0o600))
	run.retryDirect(t, runID, "")
	second := run.waitFor(t, "the second execution did not fail", func(s ir.DAGRunStatus) bool {
		return s.DAGRunID == runID && s.AttemptID != first.AttemptID && s.Status == ir.Failed
	})
	assert.Len(t, run.checks(t), 2, "a retry of the job's step did not check again")
	assert.Equal(t, 0, txeExecutions(t, control))

	// Exit 0: the job runs, seals and publishes.
	require.NoError(t, os.Remove(run.checkExit))
	run.retryDirect(t, runID, "")
	third := run.waitFor(t, "the third execution did not succeed", func(s ir.DAGRunStatus) bool {
		return s.DAGRunID == runID && s.AttemptID != second.AttemptID && s.Status == ir.Succeeded
	})
	assert.Len(t, run.checks(t), 3)
	assert.Equal(t, 1, txeExecutions(t, control))
	_, ok := run.registry.execution(third)
	assert.True(t, ok, "the job ran and nothing was published")

	// A retry of the publish step alone does not run the job, and so does
	// not check.
	run.retryDirect(t, runID, "publish")
	run.waitFor(t, "the publish-only execution did not succeed", func(s ir.DAGRunStatus) bool {
		return s.DAGRunID == runID && s.AttemptID != third.AttemptID && s.Status == ir.Succeeded
	})
	assert.Len(t, run.checks(t), 3, "a retry of the publish step ran the resource check")
	assert.Equal(t, 1, txeExecutions(t, control))
}
