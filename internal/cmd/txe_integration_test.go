// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/test"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	txeITOwner   = "own_01K7A5ZQ8M3N4P5R6S7T8V9W0A"
	txeITMachine = "mch_01K7A5ZQ8M3N4P5R6S7T8V9W0C"
	txeITKey     = "dagu_txeintegration123456789"
)

// txeCLI runs the built dagu binary the way a coding session does: with a
// TXE home, a session identity, and nothing else from the test's environment.
type txeCLI struct {
	t       *testing.T
	binary  string
	home    string
	userDir string
}

func (c *txeCLI) run(session string, args ...string) (string, error) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.binary, args...) //nolint:gosec // the binary built by the test harness
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + c.userDir,
		"TXE_DAGU_HOME=" + c.home,
		"TXE_SESSION=" + session,
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), err
}

func (c *txeCLI) json(session string, args ...string) (map[string]any, error) {
	c.t.Helper()
	out, err := c.run(session, append(args, "--json")...)
	var value map[string]any
	if out != "" {
		require.NoError(c.t, json.Unmarshal([]byte(out), &value), "output: %s", out)
	}
	return value, err
}

// txeDurableHome returns a TXE home that the path policy accepts: outside
// the system temporary directories and outside any working tree.
func txeDurableHome(t *testing.T) string {
	t.Helper()
	cache, err := os.UserCacheDir()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(cache, 0o700))
	home, err := os.MkdirTemp(cache, "txe-dagu-test-")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(p, 0o700) //nolint:gosec // let the test directory be removed
			}
			return nil
		})
		_ = os.RemoveAll(home)
	})
	return home
}

func txePost(t *testing.T, baseURL, path string, body any) {
	t.Helper()
	data, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+path, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+txeITKey)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var answer bytes.Buffer
	_, _ = answer.ReadFrom(resp.Body)
	require.Less(t, resp.StatusCode, 300, "POST %s: %s", path, answer.String())
}

const txeITSpec = `schema: 1
job_key: nightly-collector
title: Collect the nightly snapshot
purpose: Record a snapshot of the export directory each night so a missing export is noticed the next morning.
project:
  key: github.com/txehq/txe
  name: txehq/txe
targets:
  - kind: fixture.directory
    environment: test
    stable_id: {id: exports-0001}
schedule:
  cron: "0 2 * * *"
  timezone: Australia/Perth
  timeout_sec: 300
package:
  include: [collect.sh, lib]
  entrypoint: [./collect.sh]
env:
  SOURCE_DIR: /srv/exports
credential_refs:
  - name: FIXTURE_TOKEN
    kind: file
    locator: %s
expected_outcome:
  success_criteria: ["A snapshot exists for each night."]
  deliverables:
    - {name: snapshot, path: snapshot.json, delivery: hub, required: true}
lifetime:
  expires_at: "2027-01-31T00:00:00Z"
review_policy:
  cadence: "0 9 * * *"
  brief: Check that last night's snapshot exists.
`

// Three coding sessions use the built CLI against a real hub with the real
// job registry. One registers a job; the others find, inspect and update it;
// a second registration and an outdated update are refused; and the job
// survives the removal of the worktree it came from.
func TestTXECLIAgainstRegistry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("job packages are shell scripts run by a Unix worker")
	}
	server := test.SetupServer(t)
	baseURL := fmt.Sprintf("http://%s:%d/api/v1", server.Config.Server.Host, server.Config.Server.Port)

	cli := &txeCLI{t: t, binary: server.Config.Paths.Executable, home: txeDurableHome(t), userDir: t.TempDir()}
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q,"display_name":"test-mac"}`, txeITMachine, txeITOwner)
	require.NoError(t, os.WriteFile(filepath.Join(cli.home, "machine.json"), []byte(identity), 0o600))

	// What the worker installer does once: the hub's context, the owner and
	// the machine.
	_, err := cli.run("installer", "context", "add", "txe", "--server="+baseURL, "--api-key="+txeITKey,
		"--dagu-home="+filepath.Join(cli.home, "client"))
	require.NoError(t, err)
	actor := map[string]any{"kind": "cli", "id": "installer"}
	txePost(t, baseURL, "/txe/owners", map[string]any{"owner_id": txeITOwner, "display_name": "Connor Wang", "actor": actor})
	txePost(t, baseURL, "/txe/machines", map[string]any{"machine_id": txeITMachine, "owner_id": txeITOwner, "display_name": "test-mac", "actor": actor})

	// A worktree with an uncommitted script, a dependency and a job spec. The
	// credential it refers to lives elsewhere on the machine.
	credential := filepath.Join(cli.home, "credentials", "fixture-token")
	require.NoError(t, os.MkdirAll(filepath.Dir(credential), 0o700))
	require.NoError(t, os.WriteFile(credential, []byte("txe-sentinel-credential-it\n"), 0o600))
	worktree := filepath.Join(t.TempDir(), "worktree")
	require.NoError(t, os.MkdirAll(filepath.Join(worktree, "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(worktree, "collect.sh"), []byte("#!/bin/sh\n. ./lib/common.sh\ncollect\n"), 0o755)) //nolint:gosec // test script
	require.NoError(t, os.WriteFile(filepath.Join(worktree, "lib", "common.sh"), []byte("collect() { echo ok; }\n"), 0o644))          //nolint:gosec // test file
	spec := filepath.Join(worktree, "job.yaml")
	require.NoError(t, os.WriteFile(spec, fmt.Appendf(nil, txeITSpec, credential), 0o644)) //nolint:gosec // test file

	// Session 1: the machine is ready, then the job is registered.
	_, err = cli.run("cc1-s000001", "txe", "skill", "install")
	require.NoError(t, err)
	doctor, err := cli.json("cc1-s000001", "txe", "doctor")
	require.NoError(t, err, "doctor: %v", doctor)
	assert.Equal(t, true, doctor["ok"])

	plan, err := cli.json("cc1-s000001", "txe", "register", "-f", spec, "--dry-run")
	require.NoError(t, err)
	assert.Contains(t, plan["dag"], "type: chain")
	listed, err := cli.json("cc1-s000001", "txe", "list")
	require.NoError(t, err)
	assert.Empty(t, listed["jobs"], "a dry run registered nothing")

	registered, err := cli.json("cc1-s000001", "txe", "register", "-f", spec)
	require.NoError(t, err)
	receipt := registered["receipt"].(map[string]any)
	jobID := receipt["job_id"].(string)
	assert.Equal(t, txeITOwner, receipt["owner_id"])
	assert.Equal(t, txeITMachine, receipt["machine_id"])
	assert.EqualValues(t, 1, receipt["version"])

	// The hub wrote the DAG the client rendered, under the job's id.
	dagFile, err := os.ReadFile(filepath.Join(server.Config.Paths.DAGsDir, jobID+".yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(dagFile), `txe.machine: "`+txeITMachine+`"`)
	assert.Contains(t, string(dagFile), `key: "`+credential+`"`)
	assert.NotContains(t, string(dagFile), "txe-sentinel-credential-it")

	// Session 2 finds the job, sees who created it and who owns it.
	found, err := cli.json("cc2-s000002", "txe", "list", "--job-key", "nightly-collector")
	require.NoError(t, err)
	jobs := found["jobs"].([]any)
	require.Len(t, jobs, 1)
	row := jobs[0].(map[string]any)
	assert.Equal(t, jobID, row["job_id"])
	assert.Equal(t, txeITOwner, row["owner_id"])
	assert.Equal(t, "cc1-s000001", row["created"].(map[string]any)["by"].(map[string]any)["session"])

	inspected, err := cli.json("cc2-s000002", "txe", "inspect", jobID)
	require.NoError(t, err)
	assert.Equal(t, true, inspected["local"].(map[string]any)["held"])
	assert.Equal(t, "ready", inspected["job"].(map[string]any)["registration"].(map[string]any)["state"])

	// Session 2 registering the same job is refused, and told which job exists.
	refused, err := cli.json("cc2-s000002", "txe", "register", "-f", spec)
	require.Error(t, err)
	assert.Equal(t, "duplicate", refused["kind"])
	assert.Equal(t, jobID, refused["job_id"])

	// The worktree goes away. The job does not depend on it.
	require.NoError(t, os.RemoveAll(worktree))
	verified, err := cli.json("cc3-s000003", "txe", "package", "verify", jobID)
	require.NoError(t, err)
	assert.Equal(t, true, verified["ok"])
	assert.Equal(t, false, verified["source_root_exists"])

	// Session 3 updates the job from its own worktree.
	second := filepath.Join(t.TempDir(), "worktree-2")
	require.NoError(t, os.MkdirAll(filepath.Join(second, "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(second, "collect.sh"), []byte("#!/bin/sh\n. ./lib/common.sh\ncollect v2\n"), 0o755)) //nolint:gosec // test script
	require.NoError(t, os.WriteFile(filepath.Join(second, "lib", "common.sh"), []byte("collect() { echo ok \"$1\"; }\n"), 0o644))      //nolint:gosec // test file
	spec2 := filepath.Join(second, "job.yaml")
	require.NoError(t, os.WriteFile(spec2, fmt.Appendf(nil, txeITSpec, credential), 0o644)) //nolint:gosec // test file

	updated, err := cli.json("cc3-s000003", "txe", "update", jobID, "-f", spec2, "--expected-version", "1")
	require.NoError(t, err)
	assert.EqualValues(t, 2, updated["receipt"].(map[string]any)["version"])

	// Session 1 still believes the job is at version 1.
	stale, err := cli.json("cc1-s000001", "txe", "update", jobID, "-f", spec2, "--expected-version", "1")
	require.Error(t, err)
	assert.Equal(t, "version_conflict", stale["kind"])

	// What receipt recovery relies on: the hub's history keeps one "ready"
	// entry per version, naming that version's package and DAG hash.
	registry := txeclient.New(baseURL, txeITKey, nil)
	events, err := registry.JobEvents(context.Background(), jobID)
	require.NoError(t, err)
	hashes := map[string]bool{}
	for _, number := range []int{1, 2} {
		version, err := registry.JobVersion(context.Background(), jobID, number)
		require.NoError(t, err)
		require.NotEmpty(t, version.DAG.SpecSHA256, "version %d has no DAG hash", number)
		require.False(t, hashes[version.DAG.SpecSHA256], "two versions share a DAG hash")
		hashes[version.DAG.SpecSHA256] = true
		matches := 0
		for _, event := range events {
			if event.Kind == txeclient.EventReady && slices.Contains(event.Evidence, version.Package.Digest) && slices.Contains(event.Evidence, version.DAG.SpecSHA256) {
				matches++
			}
		}
		assert.Equal(t, 1, matches, "ready entries in the hub's history for version %d", number)
	}

	after, err := cli.json("cc1-s000001", "txe", "inspect", jobID)
	require.NoError(t, err)
	job := after["job"].(map[string]any)
	assert.EqualValues(t, 2, job["version"])
	assert.Equal(t, txeITOwner, job["owner_id"])
	assert.Equal(t, "cc3-s000003", job["updated"].(map[string]any)["by"].(map[string]any)["session"])
	assert.Equal(t, "ready", job["registration"].(map[string]any)["state"])

	// Nothing the hub stores, and nothing the CLI wrote, holds the credential.
	for _, root := range []string{server.Config.Paths.DataDir, server.Config.Paths.DAGsDir, filepath.Join(cli.home, "packages"), filepath.Join(cli.home, "receipts")} {
		require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return err
			}
			data, readErr := os.ReadFile(p) //nolint:gosec // test directory
			if readErr == nil {
				assert.False(t, strings.Contains(string(data), "txe-sentinel-credential-it"), "%s holds the credential", p)
			}
			return nil
		}))
	}
}
