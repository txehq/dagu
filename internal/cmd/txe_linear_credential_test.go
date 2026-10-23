// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const txeLinearSpec = `schema: 1
job_key: linear-credential
title: Check a Linear issue exists before each run
purpose: The run reads a Linear issue with this machine's own Linear credential first; a missing or refused credential stops the run as a login to repair on this machine, never as a deletion.
project:
  key: txe.local/linear-credential
  name: linear-credential
targets:
  - kind: linear.issue
    display_name: TXE-3412
    stable_id: {id: 00000000-0000-4000-8000-000000003412}
    existence_check: pre_run
schedule:
  cron: "0 3 * * *"
  timezone: UTC
  timeout_sec: 60
package:
  include: [run.sh]
  entrypoint: [./run.sh]
env:
  HTTPS_PROXY: http://127.0.0.1:9
credential_refs:
  - {name: LINEAR_API_KEY, kind: file, locator: %s}
expected_outcome:
  success_criteria: ["The run starts only when the Linear issue was seen."]
lifetime:
  open_ended: true
review_policy:
  cadence: "0 9 * * *"
  brief: Nothing to act on.
`

// standInLinear answers Linear's issue query: refused, or the issue exists.
type standInLinear struct {
	mu      sync.Mutex
	refuse  bool
	keys    []string
	present string
}

func (l *standInLinear) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	if l.refuse {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Authentication required, not authenticated","extensions":{"code":"AUTHENTICATION_ERROR"}}]}`))
		return
	}
	_, _ = w.Write([]byte(l.present))
}

func (l *standInLinear) set(refuse bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refuse = refuse
}

func (l *standInLinear) asked() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.keys...)
}

// IT-06: a job with a Linear target checked before each run, as a worker runs
// it. The built CLI registers the job against a hub with the real registry;
// dagu then runs the DAG the hub rendered. Its first command, the resource
// check, asks a stand-in for Linear, built into the check's binary, so nothing
// leaves the machine and no real credential is used. Should that build ever ask
// the real Linear, the job's HTTPS_PROXY, a closed local port, stops the
// request; the stand-in is on loopback, which is never proxied.
//
// A missing credential file stops the run before any step and names the
// reference. A credential Linear refuses stops the run before the job's own
// command; the hub records that a login is needed, and the job stays active
// with its history: neither is a deletion. Once Linear sees the issue again,
// the run goes ahead.
func TestTXELinearCredentialStopsTheRunNotTheJob(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("job packages are shell scripts run by a Unix worker")
	}
	linear := &standInLinear{refuse: true, present: `{"data":{"issue":{"id":"00000000-0000-4000-8000-000000003412","identifier":"TXE-3412","archivedAt":null}}}`}
	stand := httptest.NewServer(linear)
	t.Cleanup(stand.Close)

	server := test.SetupServer(t)
	baseURL := fmt.Sprintf("http://%s:%d/api/v1", server.Config.Server.Host, server.Config.Server.Port)
	userDir := t.TempDir()
	cli := &txeCLI{t: t, binary: server.Config.Paths.Executable, home: txeDurableHome(t, userDir), userDir: userDir}
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q,"display_name":"test-mac"}`, txeITMachine, txeITOwner)
	require.NoError(t, os.WriteFile(filepath.Join(cli.home, "machine.json"), []byte(identity), 0o600))

	// The dagu this machine's jobs run is a build whose check asks the
	// stand-in. Registration uses the ordinary build.
	require.NoError(t, os.MkdirAll(filepath.Join(cli.home, "bin"), 0o700))
	require.NoError(t, os.Symlink(buildDaguAskingLinearAt(t, stand.URL+"/graphql"), filepath.Join(cli.home, "bin", "dagu")))
	_, err := cli.run("installer", "context", "add", "txe", "--server="+baseURL, "--api-key="+txeITKey,
		"--dagu-home="+filepath.Join(cli.home, "client"))
	require.NoError(t, err)
	actor := map[string]any{"kind": "cli", "id": "installer"}
	txePost(t, baseURL, "/txe/owners", map[string]any{"owner_id": txeITOwner, "display_name": "Ada", "actor": actor})
	txePost(t, baseURL, "/txe/machines", map[string]any{"machine_id": txeITMachine, "owner_id": txeITOwner, "display_name": "test-mac", "actor": actor})

	const key = "txe-test-linear-key-not-real"
	credential := filepath.Join(cli.home, "credentials", "linear-key")
	require.NoError(t, os.MkdirAll(filepath.Dir(credential), 0o700))
	require.NoError(t, os.WriteFile(credential, []byte(key+"\n"), 0o600))
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\ntouch \"$TXE_OUTPUT_DIR/ran\"\n"), 0o755)) //nolint:gosec // test script
	spec := filepath.Join(dir, "job.yaml")
	require.NoError(t, os.WriteFile(spec, fmt.Appendf(nil, txeLinearSpec, credential), 0o644)) //nolint:gosec // test file
	registered, err := cli.run("cc2-s000002", "txe", "register", "-f", spec)
	require.NoError(t, err, registered)
	found, err := cli.json("cc2-s000002", "txe", "list", "--job-key", "linear-credential")
	require.NoError(t, err)
	jobs := txeJobs(t, found)
	require.Len(t, jobs, 1)
	jobID := jobs[0].(map[string]any)["job_id"].(string)

	// A hub's scheduler indexes the jobs' targets when it starts. This hub
	// has no scheduler, so the index is built here.
	store, err := registry.NewFileStore(server.Config.Paths.DataDir)
	require.NoError(t, err)
	require.NoError(t, store.RebuildResourceIndex(context.Background()))

	// One run, as a worker starts it: dagu runs the rendered DAG with nothing
	// from the test's environment.
	dag := filepath.Join(server.Config.Paths.DAGsDir, jobID+".yaml")
	run := func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, cli.binary, "start", dag) //nolint:gosec // the binary built by the test harness
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + userDir, "TXE_DAGU_HOME=" + cli.home}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	job := func() map[string]any {
		answer, err := cli.json("cc2-s000002", "txe", "inspect", jobID)
		require.NoError(t, err)
		return answer["job"].(map[string]any)
	}
	ran := filepath.Join(cli.home, "outputs", jobID, "ran")

	// The credential file is missing: nothing runs, not even the check, and
	// the error names the reference.
	require.NoError(t, os.Remove(credential))
	out, err := run()
	require.Error(t, err, out)
	assert.Contains(t, out, `failed to resolve secret "LINEAR_API_KEY" from provider "file": secret file not found`)
	assert.Empty(t, linear.asked(), "Linear is not asked without a credential")
	assert.NoFileExists(t, ran)
	assert.Equal(t, "active", job()["lifecycle"])

	// Linear refuses the credential: the check stops the run before the job's
	// command and the hub records that a login is needed.
	require.NoError(t, os.WriteFile(credential, []byte(key+"\n"), 0o600))
	out, err = run()
	require.Error(t, err, out)
	assert.Contains(t, out, "exit status 75")
	assert.Contains(t, out, `"observation":"auth_denied"`)
	assert.Contains(t, out, `"reported":true`)
	assert.NotContains(t, out, key, "the credential is never printed")
	assert.Equal(t, []string{key}, linear.asked(), "Linear was asked once, with the machine's credential")
	assert.NoFileExists(t, ran)
	refused := job()
	assert.Equal(t, "active", refused["lifecycle"], "a refused credential never retires the job")
	assert.Nil(t, refused["retirement"])
	availability := refused["availability"].(map[string]any)
	assert.Equal(t, "auth_required", availability["state"])
	assert.Equal(t, "Linear refused the key (HTTP 401)", availability["detail"])
	text, err := cli.run("cc2-s000002", "txe", "inspect", jobID)
	require.NoError(t, err)
	assert.Contains(t, text, "Availability:  auth_required (Linear refused the key (HTTP 401))")

	// The login is repaired and Linear sees the issue: the run goes ahead.
	linear.set(false)
	out, err = run()
	require.NoError(t, err, out)
	assert.FileExists(t, ran)
	recovered := job()
	assert.Equal(t, "active", recovered["lifecycle"])
	assert.Equal(t, "ready", recovered["availability"].(map[string]any)["state"])
}

// buildDaguAskingLinearAt builds dagu with the resource check's Linear API set
// to endpoint, the way only a test build can set it.
func buildDaguAskingLinearAt(t *testing.T, endpoint string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "dagu")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	//nolint:gosec // the repository's own command, into the test's directory
	cmd := exec.CommandContext(ctx, "go", "build", "-o", path,
		"-ldflags", "-X github.com/dagucloud/dagu/v2/internal/cmd.txeLinearEndpoint="+endpoint, "./cmd")
	cmd.Dir = root
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	require.NoError(t, cmd.Run(), output.String())
	return path
}
