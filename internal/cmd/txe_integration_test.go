// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/test"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/goccy/go-yaml"
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

// json runs a command with --json and decodes what it printed. It is for the
// test's own goroutine: it stops the test on output that is not JSON.
func (c *txeCLI) json(session string, args ...string) (map[string]any, error) {
	c.t.Helper()
	out, err := c.run(session, append(args, "--json")...)
	return c.decode(out), err
}

func (c *txeCLI) decode(out string) map[string]any {
	c.t.Helper()
	var value map[string]any
	if out != "" {
		require.NoError(c.t, json.Unmarshal([]byte(out), &value), "output: %s", out)
	}
	return value
}

// txeJobs returns the jobs a "txe list" answered. An answer with no jobs
// field is not an empty list.
func txeJobs(t *testing.T, answer map[string]any) []any {
	t.Helper()
	require.Contains(t, answer, "jobs", "answer: %v", answer)
	jobs, ok := answer["jobs"].([]any)
	require.True(t, ok, "jobs is not a list: %v", answer["jobs"])
	return jobs
}

// txeGate stands between the CLI and the hub and passes every request on.
// Once armed, it holds each registration request until two have arrived, so
// that both sessions have already looked the job key up and found nothing,
// and it is the registry that decides between them.
type txeGate struct {
	proxy *httputil.ReverseProxy

	mu      sync.Mutex
	armed   bool
	arrived int
	both    chan struct{}
}

func newTXEGate(t *testing.T, hub string) (*txeGate, string) {
	t.Helper()
	target, err := url.Parse(hub)
	require.NoError(t, err)
	gate := &txeGate{proxy: httputil.NewSingleHostReverseProxy(target), both: make(chan struct{})}
	front := httptest.NewServer(gate)
	t.Cleanup(front.Close)
	return gate, front.URL
}

func (g *txeGate) arm() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.armed = true
}

func (g *txeGate) registrations() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.arrived
}

func (g *txeGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/txe/jobs" {
		g.mu.Lock()
		held := g.armed
		if held {
			g.arrived++
			if g.arrived == 2 {
				close(g.both)
			}
		}
		g.mu.Unlock()
		if held {
			select {
			case <-g.both:
			case <-time.After(30 * time.Second): // the other never came; the test fails on the count
			case <-r.Context().Done():
			}
		}
	}
	g.proxy.ServeHTTP(w, r)
}

// txeDurableHome returns a TXE home that the path policy accepts: outside
// the system temporary directories and outside any working tree. The policy
// asked is the one the CLI will apply when it runs with userDir as its HOME
// and no TMPDIR, as txeCLI.run starts it. Where that policy refuses the
// place this machine offers, the test is skipped.
func txeDurableHome(t *testing.T, userDir string) string {
	t.Helper()
	cache, err := os.UserCacheDir()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(cache, 0o700))
	home, err := os.MkdirTemp(cache, "txe-dagu-test-")
	require.NoError(t, err)
	policy := txepkg.PathPolicy{TempRoots: []string{"/tmp", "/var/tmp", "/var/folders"}, HomeDir: userDir}
	if err := policy.CheckDurable(home); err != nil {
		_ = os.RemoveAll(home)
		t.Skipf("no durable place for a TXE home on this machine: %v", err)
	}
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
// a second registration and an outdated update are refused; the job survives
// the removal of the worktree it came from; of two registrations made at the
// same moment one is given the job; and a spec whose parameter bound would
// reach the registry changed registers nothing.
//
// The hub here checks no credentials, so this says nothing about who may do
// what. The sessions share one machine and one TXE home, as they do on a
// worker.
func TestTXECLIAgainstRegistry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("job packages are shell scripts run by a Unix worker")
	}
	server := test.SetupServer(t)
	gate, front := newTXEGate(t, fmt.Sprintf("http://%s:%d", server.Config.Server.Host, server.Config.Server.Port))
	baseURL := front + "/api/v1"

	userDir := t.TempDir()
	cli := &txeCLI{t: t, binary: server.Config.Paths.Executable, home: txeDurableHome(t, userDir), userDir: userDir}
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q,"display_name":"test-mac"}`, txeITMachine, txeITOwner)
	require.NoError(t, os.WriteFile(filepath.Join(cli.home, "machine.json"), []byte(identity), 0o600))

	// What the worker installer does once: the dagu the machine's jobs run,
	// the hub's context, the owner and the machine.
	require.NoError(t, os.MkdirAll(filepath.Join(cli.home, "bin"), 0o700))
	require.NoError(t, os.Symlink(cli.binary, filepath.Join(cli.home, "bin", "dagu")))
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
	assert.Empty(t, txeJobs(t, listed), "a dry run registered nothing")

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
	// The job's targets are checked first, in the step that runs the job:
	// the check is that step's first command and the job's own comes after.
	var dag struct {
		Steps []struct {
			Name    string `yaml:"name"`
			Command any    `yaml:"command"` // a list in the run step, one line in the publish step
		} `yaml:"steps"`
	}
	require.NoError(t, yaml.Unmarshal(dagFile, &dag))
	require.NotEmpty(t, dag.Steps)
	assert.Equal(t, "run", dag.Steps[0].Name)
	commands, ok := dag.Steps[0].Command.([]any)
	require.True(t, ok, "the run step's commands: %v", dag.Steps[0].Command)
	require.NotEmpty(t, commands)
	assert.Contains(t, commands[0], "txe resource check")
	assert.Contains(t, commands[0], jobID)
	own := slices.IndexFunc(commands, func(c any) bool { return strings.Contains(fmt.Sprint(c), "collect.sh") })
	assert.Positive(t, own, "the job's command comes after the check: %v", commands)
	// And it is the DAG the registry recorded for version 1.
	first, err := txeclient.New(baseURL, txeITKey, nil).JobVersion(context.Background(), jobID, 1)
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("sha256:%x", sha256.Sum256(dagFile)), first.DAG.SpecSHA256)
	assert.Contains(t, string(dagFile), `key: "`+credential+`"`)
	assert.NotContains(t, string(dagFile), "txe-sentinel-credential-it")

	// Session 2 finds the job, sees who created it and who owns it.
	found, err := cli.json("cc2-s000002", "txe", "list", "--job-key", "nightly-collector")
	require.NoError(t, err)
	jobs := txeJobs(t, found)
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

	// Two sessions register a new job at the same moment. One job exists
	// afterwards: one session holds its receipt, the other is told which job
	// exists.
	third := filepath.Join(t.TempDir(), "worktree-3")
	require.NoError(t, os.MkdirAll(filepath.Join(third, "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(third, "collect.sh"), []byte("#!/bin/sh\n. ./lib/common.sh\ncollect\n"), 0o755)) //nolint:gosec // test script
	require.NoError(t, os.WriteFile(filepath.Join(third, "lib", "common.sh"), []byte("collect() { echo ok; }\n"), 0o644))          //nolint:gosec // test file
	spec3 := filepath.Join(third, "job.yaml")
	weekly := strings.Replace(fmt.Sprintf(txeITSpec, credential), "job_key: nightly-collector", "job_key: weekly-collector", 1)
	require.NoError(t, os.WriteFile(spec3, []byte(weekly), 0o644)) //nolint:gosec // test file
	type outcome struct {
		out string
		err error
	}
	outcomes := make(chan outcome, 2)
	gate.arm()
	for _, session := range []string{"cc1-s000001", "cc2-s000002"} {
		go func() {
			out, err := cli.run(session, "txe", "register", "-f", spec3, "--json")
			outcomes <- outcome{out, err}
		}()
	}
	var won, lost []map[string]any
	for range 2 {
		o := <-outcomes
		if o.err == nil {
			won = append(won, cli.decode(o.out))
		} else {
			lost = append(lost, cli.decode(o.out))
		}
	}
	require.Equal(t, 2, gate.registrations(), "both sessions asked the registry to register the job")
	require.Len(t, won, 1, "exactly one of two simultaneous registrations is given a receipt; refused: %v", lost)
	require.Len(t, lost, 1)
	weeklyID := won[0]["receipt"].(map[string]any)["job_id"].(string)
	assert.Equal(t, "duplicate", lost[0]["kind"])
	// The refusal names the job that exists: outright when the key was
	// already taken, or as the job's current state when both requests
	// reached the registry and this one lost there.
	named := lost[0]["job_id"]
	if current, ok := lost[0]["current"].(map[string]any); ok {
		named = current["job_id"]
	}
	assert.Equal(t, weeklyID, named)
	// The registry may keep the loser's request as a record marked
	// duplicate. Only the winner's job is ready.
	found, err = cli.json("cc3-s000003", "txe", "list", "--job-key", "weekly-collector")
	require.NoError(t, err)
	var ready []any
	for _, entry := range txeJobs(t, found) {
		job := entry.(map[string]any)
		state := job["registration"].(map[string]any)["state"]
		if state == "ready" {
			ready = append(ready, job["job_id"])
		} else {
			assert.Equal(t, "duplicate", state, "job %v", job["job_id"])
		}
	}
	assert.Equal(t, []any{weeklyID}, ready)

	// A bound that would reach the registry as another number is refused
	// when the spec is read, by a dry run and by a registration alike, and
	// the hub holds no job under that key.
	bounded := strings.Replace(weekly, "job_key: weekly-collector", "job_key: bounded-collector", 1) +
		"  permitted_actions:\n    - name: rebalance\n      command: ./collect.sh\n      timeout_sec: 60\n      param_schema:\n" +
		"        type: object\n        properties:\n          share: {type: number, maximum: 0.49999999999999999}\n"
	require.NoError(t, os.WriteFile(spec3, []byte(bounded), 0o644)) //nolint:gosec // test file
	for _, args := range [][]string{{"txe", "register", "-f", spec3, "--dry-run"}, {"txe", "register", "-f", spec3}} {
		_, err := cli.run("cc1-s000001", args...)
		require.ErrorContains(t, err, "the number 0.49999999999999999 would be sent as 0.5")
	}
	bound, err := cli.json("cc1-s000001", "txe", "list", "--job-key", "bounded-collector")
	require.NoError(t, err)
	assert.Empty(t, txeJobs(t, bound))

	// The credential's content is in one file on the machine, the one the
	// spec points at. Nothing else under the TXE home holds it, and nothing
	// in the hub's data, DAG and log directories does.
	for _, root := range []string{cli.home, server.Config.Paths.DataDir, server.Config.Paths.DAGsDir, server.Config.Paths.LogDir} {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue // this hub wrote no logs to a file
		}
		require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() || p == credential {
				return err
			}
			data, err := os.ReadFile(p) //nolint:gosec // test directory
			if err != nil {
				return err
			}
			assert.False(t, strings.Contains(string(data), "txe-sentinel-credential-it"), "%s holds the credential", p)
			return nil
		}))
	}
}
