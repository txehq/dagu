// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
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
