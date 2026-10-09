// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/test"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
)

// txeProcess is one real dagu process of the candidate: the hub or a worker.
type txeProcess struct {
	t    *testing.T
	name string
	cmd  *exec.Cmd
	mu   sync.Mutex
	out  bytes.Buffer
}

func (p *txeProcess) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.Write(b)
}

func (p *txeProcess) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

func (p *txeProcess) stop() {
	if p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = p.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
	}
}

func txeStartProcess(t *testing.T, name, binary string, env []string, args ...string) *txeProcess {
	t.Helper()
	p := &txeProcess{t: t, name: name}
	p.cmd = exec.Command(binary, args...) //nolint:gosec // the binary built by the test harness
	p.cmd.Env = env
	p.cmd.Stdout, p.cmd.Stderr = p, p
	require.NoError(t, p.cmd.Start(), name)
	t.Cleanup(func() {
		p.stop()
		if t.Failed() {
			out := p.output()
			if len(out) > 6000 {
				out = out[len(out)-6000:]
			}
			t.Logf("---- %s output (tail) ----\n%s", name, out)
		}
	})
	return p
}

// txeHub talks to the candidate hub's HTTP API.
type txeHub struct {
	t    *testing.T
	base string
	// bearer is the credential call sends: the CLI's API key once the hub's
	// principals exist.
	bearer string
}

func (h *txeHub) call(method, path string, body any) (int, map[string]any, string) {
	h.t.Helper()
	return h.callAs(h.bearer, method, path, body)
}

func (h *txeHub) waitUp() {
	h.t.Helper()
	require.Eventually(h.t, func() bool {
		code, _, _ := h.callAs("", http.MethodGet, "/health", nil)
		return code == http.StatusOK
	}, 60*time.Second, 300*time.Millisecond, "the hub's API did not come up")
}

// txeRunState is what the hub reports for a run.
type txeRunState struct {
	status, attemptID, queuedAt string
	nodes                       map[string]string
}

func (s txeRunState) execution() txeclient.Execution {
	return txeclient.Execution{AttemptID: s.attemptID, QueuedAt: s.queuedAt}
}

func (h *txeHub) run(jobID, runID string) (txeRunState, string) {
	h.t.Helper()
	code, value, raw := h.call(http.MethodGet, "/dag-runs/"+jobID+"/"+runID, nil)
	if code != http.StatusOK {
		return txeRunState{}, raw
	}
	details, _ := value["dagRunDetails"].(map[string]any)
	state := txeRunState{nodes: map[string]string{}}
	state.status, _ = details["statusLabel"].(string)
	state.attemptID, _ = details["attemptId"].(string)
	state.queuedAt, _ = details["queuedAt"].(string)
	nodes, _ := details["nodes"].([]any)
	for _, n := range nodes {
		node, _ := n.(map[string]any)
		step, _ := node["step"].(map[string]any)
		name, _ := step["name"].(string)
		label, _ := node["statusLabel"].(string)
		state.nodes[name] = label
	}
	return state, raw
}

// waitRun waits until the hub's view of the run satisfies done.
func (h *txeHub) waitRun(jobID, runID, what string, done func(txeRunState) bool) txeRunState {
	h.t.Helper()
	var last txeRunState
	var raw string
	ok := assert.Eventually(h.t, func() bool {
		last, raw = h.run(jobID, runID)
		return done(last)
	}, 90*time.Second, 300*time.Millisecond, what)
	if !ok {
		if len(raw) > 1500 {
			raw = raw[:1500]
		}
		h.t.Fatalf("%s; last seen: %+v\n%s", what, last, raw)
	}
	return last
}

func (h *txeHub) manifest(jobID, runID string, e txeclient.Execution) (int, map[string]any, string) {
	h.t.Helper()
	return h.call(http.MethodGet, "/txe/jobs/"+jobID+"/runs/"+runID+"/artifacts?execution="+e.Ref(), nil)
}

// txeKeep saves raw evidence under TXE_EVIDENCE_DIR when that is set: what
// the registry answered, what a command printed, what the hub holds.
func txeKeep(t *testing.T, name string, data []byte) {
	t.Helper()
	base := os.Getenv("TXE_EVIDENCE_DIR")
	if base == "" {
		return
	}
	path := filepath.Join(base, filepath.FromSlash(name))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, data, 0o644)) //nolint:gosec // evidence for people to read
}

// txeKeepHubCopies saves every file the hub holds under txe-attempts, and a
// list of their SHA-256 digests as computed here from the hub's bytes.
func txeKeepHubCopies(t *testing.T, name, artifactDir string) {
	t.Helper()
	if os.Getenv("TXE_EVIDENCE_DIR") == "" {
		return
	}
	var inventory strings.Builder
	require.NoError(t, filepath.WalkDir(artifactDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.Contains(filepath.ToSlash(path), "/"+txeclient.HubAttemptsDir+"/") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(artifactDir, path)
		fmt.Fprintf(&inventory, "%s  %d bytes  %s\n", txeSum(string(data)), len(data), filepath.ToSlash(rel))
		txeKeep(t, name+"/files/"+filepath.ToSlash(rel), data)
		return nil
	}))
	txeKeep(t, name+"/sha256-inventory.txt", []byte(inventory.String()))
}

func txeErrorCode(value map[string]any) string {
	details, _ := value["details"].(map[string]any)
	code, _ := details["code"].(string)
	return code
}

func txeRecord(t *testing.T, manifest map[string]any, deliverable string) map[string]any {
	t.Helper()
	records, _ := manifest["artifacts"].([]any)
	for _, r := range records {
		record, _ := r.(map[string]any)
		if record["deliverable"] == deliverable {
			return record
		}
	}
	t.Fatalf("no record for %s in %v", deliverable, manifest)
	return nil
}

func txeSum(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

const txeCandidateSpec = `schema: 1
job_key: candidate-collector
title: Collect a snapshot
purpose: Exercise the registry's real publication endpoint with the real publisher.
project:
  key: github.com/txehq/txe
  name: txehq/txe
targets:
  - kind: fixture.directory
    environment: test
    stable_id: {id: exports-0001}
schedule:
  cron: "0 2 1 1 *"
  timezone: Australia/Perth
  timeout_sec: 300
package:
  include: [collect.sh]
  entrypoint: [./collect.sh]
env:
  TXE_FIXTURE_CONTROL: %s
expected_outcome:
  success_criteria: ["A snapshot exists."]
  deliverables:
    - {name: snapshot, path: snapshot.json, delivery: hub, required: true}
lifetime:
  expires_at: "2027-01-31T00:00:00Z"
review_policy:
  cadence: "0 9 * * *"
  brief: Check that the snapshot exists.
`

// The candidate: this tree's publisher, renderer and resource check against
// the registry's real endpoints, with authentication on.
//
// A real hub (dagu start-all: API with the job registry, scheduler,
// coordinator) with built-in authentication, and a real worker in a process
// of its own, with its own directories. The job is registered through the
// CLI with the CLI's own API key, so the DAG the hub runs is the one the CLI
// rendered: the resource check, begin, the job, seal, then publish. Every
// manifest is the one the job's own publish step sent; every verdict read
// back is the registry's. Each retry is requested once.
func TestTXECandidateAgainstRealRegistry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("job packages are shell scripts run by a Unix worker")
	}
	if testing.Short() {
		t.Skip("starts real hub and worker processes")
	}

	apiPort, coordPort := findPort(t), findPort(t)
	hubHelper := test.SetupCommand(t, test.WithBuiltExecutable(), test.WithCoordinatorEnabled(), txeBuiltinAuth(txeRandom(t)))
	workerHelper := test.SetupCommand(t, test.WithBuiltExecutable())
	binary := hubHelper.Config.Paths.Executable
	hubConfig := hubHelper.Config.Paths.ConfigFileUsed
	hub := &txeHub{t: t, base: "http://127.0.0.1:" + apiPort + "/api/v1"}

	startHub := func() *txeProcess {
		p := txeStartProcess(t, "hub", binary, hubHelper.Config.Core.BaseEnv.AsSlice(),
			"start-all", "--config", hubConfig, "--host=127.0.0.1", "--port="+apiPort,
			"--coordinator.host=127.0.0.1", "--coordinator.advertise=127.0.0.1", "--coordinator.port="+coordPort,
			"--peer.insecure=true")
		hub.waitUp()
		return p
	}
	hubProcess := startHub()

	// Authentication. Nothing is readable without a credential; the first
	// admin and the CLI's key are created the way an installer would.
	access := &strings.Builder{}
	note := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		t.Log(line)
		access.WriteString(line + "\n")
	}
	code, _, _ := hub.callAs("", http.MethodGet, "/txe/installation", nil)
	require.Equal(t, http.StatusUnauthorized, code)
	note("no credential, GET /txe/installation: HTTP %d", code)
	who := txeBootstrapAuth(t, hub)
	hub.bearer = who.cli
	note("first admin created through POST /auth/setup; a second setup refused; CLI key: service account txe-cli, role developer, surface rest_api")

	// The machine: a TXE home, its identity, and the dagu the job's DAG
	// calls. That dagu is a wrapper around the built binary which makes the
	// publish step fail while the test says so, to get an execution whose
	// job step succeeded and whose publish did not. Every other command,
	// the resource check included, is the built binary's own.
	control := t.TempDir()
	home := txeDurableHome(t)
	cli := &txeCLI{t: t, binary: binary, home: home, userDir: t.TempDir()}
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q,"display_name":"candidate-mac"}`, txeITMachine, txeITOwner)
	require.NoError(t, os.WriteFile(filepath.Join(home, "machine.json"), []byte(identity), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "bin"), 0o700))
	wrapper := fmt.Sprintf(`#!/bin/sh
if [ "$1 $2 $3" = "txe artifacts publish" ] && [ -e %q ]; then
  echo "fixture: publish is made to fail" >&2
  exit 9
fi
exec %q "$@"
`, filepath.Join(control, "fail-publish"), binary)
	require.NoError(t, os.WriteFile(filepath.Join(home, "bin", "dagu"), []byte(wrapper), 0o700)) //nolint:gosec // a test script

	storeFlag := "--dagu-home=" + filepath.Join(home, "client")
	_, err := cli.run("installer", "context", "add", "txe", "--server="+hub.base, "--api-key="+who.cli, storeFlag)
	require.NoError(t, err)
	actor := map[string]any{"kind": "cli", "id": "installer"}
	code, _, raw := hub.call(http.MethodPost, "/txe/owners", map[string]any{"owner_id": txeITOwner, "display_name": "Connor Wang", "actor": actor})
	if code == http.StatusForbidden {
		note("CLI key, POST /txe/owners: HTTP 403; the owner and machine are created with the admin session")
		code, _, raw = hub.callAs(who.admin, http.MethodPost, "/txe/owners", map[string]any{"owner_id": txeITOwner, "display_name": "Connor Wang", "actor": actor})
		require.Less(t, code, 300, raw)
		code, _, raw = hub.callAs(who.admin, http.MethodPost, "/txe/machines", map[string]any{"machine_id": txeITMachine, "owner_id": txeITOwner, "display_name": "candidate-mac", "actor": actor})
		require.Less(t, code, 300, raw)
	} else {
		require.Less(t, code, 300, raw)
		note("CLI key, POST /txe/owners: HTTP %d", code)
		code, _, raw = hub.call(http.MethodPost, "/txe/machines", map[string]any{"machine_id": txeITMachine, "owner_id": txeITOwner, "display_name": "candidate-mac", "actor": actor})
		require.Less(t, code, 300, raw)
	}

	worktree := filepath.Join(t.TempDir(), "worktree")
	require.NoError(t, os.MkdirAll(worktree, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(worktree, "collect.sh"), []byte(`#!/bin/sh
set -eu
n=$(ls "$TXE_FIXTURE_CONTROL" | grep -c '^executed\.' || true)
n=$((n+1))
: > "$TXE_FIXTURE_CONTROL/executed.$n"
printf '{"collected":"txe-candidate-execution-%s"}' "$n" > "$TXE_RUN_OUTPUT_DIR/snapshot.json"
if [ -e "$TXE_FIXTURE_CONTROL/fail-job" ]; then exit 7; fi
`), 0o755)) //nolint:gosec // a test script
	content := func(n int) string { return fmt.Sprintf(`{"collected":"txe-candidate-execution-%d"}`, n) }
	executions := func() int {
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
	specPath := filepath.Join(worktree, "job.yaml")
	require.NoError(t, os.WriteFile(specPath, fmt.Appendf(nil, txeCandidateSpec, control), 0o644)) //nolint:gosec // test file

	registered, err := cli.json("cc2-s000001", "txe", "register", "-f", specPath)
	require.NoError(t, err, "register: %v", registered)
	receipt, _ := registered["receipt"].(map[string]any)
	jobID, _ := receipt["job_id"].(string)
	require.NotEmpty(t, jobID, "no receipt: %v", registered)
	dag, err := os.ReadFile(filepath.Join(hubHelper.Config.Paths.DAGsDir, jobID+".yaml"))
	require.NoError(t, err)
	require.Contains(t, string(dag), "txe resource check --job "+jobID+" --job-version 1 --machine "+txeITMachine)
	txeKeep(t, "registration/dag.yaml", dag)

	// Who the registry says registered the job: the key's principal, not
	// what a request body claims.
	code, job, raw := hub.call(http.MethodGet, "/txe/jobs/"+jobID, nil)
	require.Equal(t, http.StatusOK, code, raw)
	txeKeep(t, "registration/job.json", []byte(raw))
	created, _ := job["created"].(map[string]any)
	note("job %s registered with the CLI key; the registry records created.by = %v", jobID, created["by"])
	code, _, _ = hub.callAs("", http.MethodGet, "/txe/jobs/"+jobID, nil)
	assert.Equal(t, http.StatusUnauthorized, code)
	note("no credential, GET /txe/jobs/{job}: HTTP %d", code)
	code, _, _ = hub.callAs("", http.MethodPost, "/txe/jobs/"+jobID+"/runs/any-run/artifacts", map[string]any{"job_version": 1})
	assert.Equal(t, http.StatusUnauthorized, code)
	note("no credential, POST artifacts: HTTP %d", code)

	// The resource check, the built binary's own, run by hand as the job's
	// step runs it: it lets the job run on this machine, and refuses to
	// speak for another machine.
	checkEnv := func(args ...string) (string, error) {
		return cli.run("manual", append([]string{"txe", "resource", "check", storeFlag}, args...)...)
	}
	out, err := checkEnv("--job="+jobID, "--job-version=1", "--machine="+txeITMachine)
	txeKeep(t, "commands/resource-check-this-machine.txt", fmt.Appendf(nil, "error: %v\n\nstdout:\n%s", err, out))
	require.NoError(t, err, "the resource check stops a job with no pre-run target: %s", out)
	out, err = checkEnv("--job="+jobID, "--job-version=1", "--machine=mch_01K7A5ZQ8M3N4P5R6S7T8V9W0D")
	txeKeep(t, "commands/resource-check-another-machine.txt", fmt.Appendf(nil, "error: %v\n\nstdout:\n%s", err, out))
	require.Error(t, err, "the resource check answered for another machine")
	note("dagu txe resource check for this machine: exit 0; for another machine: %v", strings.SplitN(err.Error(), ":", 2)[0])

	txeStartProcess(t, "worker", binary, workerHelper.Config.Core.BaseEnv.AsSlice(),
		"worker", "--config", workerHelper.Config.Paths.ConfigFileUsed, "--worker.id=candidate-worker",
		"--worker.labels=txe.machine="+txeITMachine, "--worker.coordinators=127.0.0.1:"+coordPort,
		"--worker.health-port=0", "--peer.insecure=true")
	note("worker process: no credential configured; coordinator-worker transport is not authenticated in this configuration")

	terminal := func(s txeRunState) bool {
		return s.status == "succeeded" || s.status == "failed" || s.status == "aborted"
	}
	// publish runs the publish command by hand, as an execution, the way the
	// job's last step runs it.
	publish := func(runID string, e txeclient.Execution) (string, error) {
		return cli.run("manual", "txe", "artifacts", "publish", storeFlag,
			"--job="+jobID, "--job-version=1", "--run="+runID, "--attempt="+e.AttemptID, "--queued-at="+e.QueuedAt,
			"--artifact-dir="+t.TempDir(), "--json")
	}
	verified := func(runID string, e txeclient.Execution, producedIn txeclient.Execution, want string) map[string]any {
		t.Helper()
		var manifest map[string]any
		var rawManifest string
		require.Eventually(t, func() bool {
			code, value, raw := hub.manifest(jobID, runID, e)
			manifest, rawManifest = value, raw
			return code == http.StatusOK && txeRecord(t, value, "snapshot")["status"] == "verified"
		}, 30*time.Second, 300*time.Millisecond, "the hub did not verify the copy of execution %s: %v", e.Ref(), manifest)
		txeKeep(t, "manifests/"+runID+"/"+e.Ref()+".json", []byte(rawManifest))
		assert.Equal(t, e.AttemptID, manifest["attempt_id"])
		assert.Equal(t, e.QueuedAt, manifest["queued_at"])
		assert.Equal(t, e.Ref(), manifest["execution"])
		produced, _ := manifest["produced_in"].(map[string]any)
		assert.Equal(t, producedIn.AttemptID, produced["attempt_id"])
		assert.Equal(t, producedIn.QueuedAt, produced["queued_at"])
		assert.Equal(t, txeSum(want), txeRecord(t, manifest, "snapshot")["sha256"])
		t.Logf("registry: run %s execution %s (attempt %s, queued_at %q) produced_in %v: snapshot %s %s",
			runID, manifest["execution"], manifest["attempt_id"], manifest["queued_at"], produced["execution"],
			txeRecord(t, manifest, "snapshot")["status"], txeRecord(t, manifest, "snapshot")["sha256"])
		return manifest
	}
	// retry asks ONCE for a retry of the execution the caller saw, and
	// returns the execution the hub says it admitted.
	retry := func(runID string, seen txeRunState, extra map[string]any) txeclient.Execution {
		t.Helper()
		body := map[string]any{"dagRunId": runID, "expectedAttemptId": seen.attemptID, "expectedQueuedAt": seen.queuedAt}
		for k, v := range extra {
			body[k] = v
		}
		code, value, raw := hub.call(http.MethodPost, "/dag-runs/"+jobID+"/"+runID+"/retry", body)
		txeKeep(t, fmt.Sprintf("responses/retry-%s-after-%s.txt", runID, seen.execution().Ref()), fmt.Appendf(nil, "HTTP %d\n%s", code, raw))
		require.Equal(t, http.StatusOK, code, "the retry was not admitted: %s", raw)
		admitted := txeclient.Execution{}
		admitted.AttemptID, _ = value["attemptId"].(string)
		admitted.QueuedAt, _ = value["queuedAt"].(string)
		require.NotEmpty(t, admitted.AttemptID, "the hub did not name the execution it admitted: %s", raw)
		assert.Equal(t, admitted.Ref(), value["executionRef"], raw)
		return admitted
	}
	waitFor := func(runID string, e txeclient.Execution, what string) txeRunState {
		t.Helper()
		return hub.waitRun(jobID, runID, what, func(s txeRunState) bool { return terminal(s) && s.execution() == e })
	}

	// ---- Run A: started directly, so it has no queue marker. ----
	runA := "candidate-run-a"
	code, _, raw = hub.call(http.MethodPost, "/dags/"+jobID+"/start", map[string]any{"dagRunId": runA})
	require.Less(t, code, 300, "start: %s", raw)
	a1 := hub.waitRun(jobID, runA, "run A's first execution did not end", terminal)
	require.Equal(t, "succeeded", a1.status, "with the real resource check as its first command")
	require.Empty(t, a1.queuedAt, "a run started directly has a queue marker; the no-marker case is not exercised")
	require.Equal(t, 1, executions())
	verified(runA, a1.execution(), a1.execution(), content(1))

	// The job runs again from its step, as a new attempt, with other bytes.
	a2 := waitFor(runA, retry(runA, a1, map[string]any{"stepName": "run", "includeDownstream": true}), "run A's second execution did not end")
	require.Equal(t, "succeeded", a2.status)
	require.NotEqual(t, a1.attemptID, a2.attemptID)
	require.Equal(t, 2, executions())
	verified(runA, a2.execution(), a2.execution(), content(2))
	// The first execution's manifest and hub copy are as they were.
	verified(runA, a1.execution(), a1.execution(), content(1))

	// A retry that names an execution the run has moved on from is refused,
	// and nothing runs.
	code, value, raw := hub.call(http.MethodPost, "/dag-runs/"+jobID+"/"+runA+"/retry",
		map[string]any{"dagRunId": runA, "expectedAttemptId": a1.attemptID, "expectedQueuedAt": a1.queuedAt, "stepName": "publish"})
	txeKeep(t, "responses/retry-run-a-stale-expectation.txt", fmt.Appendf(nil, "HTTP %d\n%s", code, raw))
	assert.Equal(t, http.StatusConflict, code, raw)
	assert.Equal(t, "execution_changed", txeErrorCode(value), raw)

	// Only the publish step runs: a third attempt publishes what the second
	// produced, under its own reference.
	a3 := waitFor(runA, retry(runA, a2, map[string]any{"stepName": "publish"}), "run A's third execution did not end")
	require.Equal(t, "succeeded", a3.status)
	require.Equal(t, 2, executions(), "a retry of the publish step ran the job again")
	a3Manifest := verified(runA, a3.execution(), a2.execution(), content(2))

	code, listing, raw := hub.call(http.MethodGet, "/txe/jobs/"+jobID+"/runs/"+runA+"/artifacts", nil)
	require.Equal(t, http.StatusOK, code, raw)
	t.Logf("run A executions listed by the registry: %v", listing["executions"])
	txeKeep(t, "manifests/"+runA+"/default.json", []byte(raw))

	// The same report again, after the run ended, is taken as a replay.
	out, err = publish(runA, a3.execution())
	txeKeep(t, "commands/replay-run-a-execution-3.txt", fmt.Appendf(nil, "error: %v\n\nstdout:\n%s", err, out))
	require.NoError(t, err, "an identical replay was refused: %s", out)
	t.Logf("identical replay of execution %s after the run ended: accepted", a3.execution().Ref())

	// Another report for an execution that has one is refused.
	record := txeRecord(t, a3Manifest, "snapshot")
	changed := map[string]any{
		"job_version": 1, "attempt_id": a3.attemptID, "queued_at": a3.queuedAt,
		"produced_in": map[string]any{"attempt_id": a2.attemptID, "queued_at": a2.queuedAt},
		"artifacts": []any{map[string]any{
			"deliverable": "snapshot", "path": "snapshot.json", "sha256": txeSum("other bytes"), "bytes": 11,
			"location": "hub", "machine_id": record["machine_id"],
		}},
		"actor": map[string]any{"kind": "cli", "id": "publish", "machine_id": txeITMachine},
	}
	code, value, raw = hub.call(http.MethodPost, "/txe/jobs/"+jobID+"/runs/"+runA+"/artifacts", changed)
	txeKeep(t, "responses/changed-report-run-a-execution-3.txt", fmt.Appendf(nil, "HTTP %d\n%s", code, raw))
	assert.Equal(t, http.StatusConflict, code, raw)
	assert.Equal(t, "artifact_conflict", txeErrorCode(value), raw)
	t.Logf("registry: another report for execution %s: HTTP %d %s", a3.execution().Ref(), code, txeErrorCode(value))

	// A first report from an execution the run never had is refused.
	out, err = publish(runA, txeclient.Execution{AttemptID: a1.attemptID, QueuedAt: "2026-01-01T00:00:00Z"})
	txeKeep(t, "commands/never-latest-run-a.txt", fmt.Appendf(nil, "error: %v\n\nstdout:\n%s", err, out))
	require.Error(t, err, "a publication from an execution that is not the latest was recorded: %s", out)
	assert.Contains(t, err.Error(), "stale_binding")

	// ---- Run B: queued, then retried through the queue. ----
	// A retry goes through the queue when the hub has a queue for the job's
	// DAG. The job's ID is known only now, so the hub is restarted with it.
	hubProcess.stop()
	data, err := os.ReadFile(hubConfig)
	require.NoError(t, err)
	var config map[string]any
	require.NoError(t, yaml.Unmarshal(data, &config))
	config["queues"] = map[string]any{"enabled": true, "config": []any{map[string]any{"name": jobID, "max_active_runs": 1}}}
	data, err = yaml.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(hubConfig, data, 0o600))
	startHub()
	code, _, _ = hub.call(http.MethodGet, "/txe/jobs/"+jobID, nil)
	require.Equal(t, http.StatusOK, code, "the CLI's key did not survive the hub's restart")

	runB := "candidate-run-b"
	require.NoError(t, os.WriteFile(filepath.Join(control, "fail-job"), nil, 0o600))
	code, _, raw = hub.call(http.MethodPost, "/dags/"+jobID+"/enqueue", map[string]any{"dagRunId": runB})
	require.Less(t, code, 300, "enqueue: %s", raw)
	b1 := hub.waitRun(jobID, runB, "run B's first execution did not fail", func(s txeRunState) bool { return s.status == "failed" })
	require.NotEmpty(t, b1.queuedAt, "an enqueued run has no queue marker")
	require.Equal(t, 3, executions())

	// The job succeeds on the queued retry; its publish step is made to
	// fail. The retry is requested once.
	require.NoError(t, os.Remove(filepath.Join(control, "fail-job")))
	require.NoError(t, os.WriteFile(filepath.Join(control, "fail-publish"), nil, 0o600))
	b2 := waitFor(runB, retry(runB, b1, nil), "run B's second execution did not end")
	require.Equal(t, "failed", b2.status)
	require.Equal(t, "succeeded", b2.nodes["run"])
	require.Equal(t, b1.attemptID, b2.attemptID, "a queued retry got a new attempt; the queued case is not exercised")
	require.NotEqual(t, b1.queuedAt, b2.queuedAt)
	require.Equal(t, 4, executions())
	code, _, raw = hub.manifest(jobID, runB, b2.execution())
	require.Equal(t, http.StatusNotFound, code, "an execution whose publish failed has a manifest: %s", raw)

	// The publish step alone runs on the next queued retry, requested once.
	require.NoError(t, os.Remove(filepath.Join(control, "fail-publish")))
	b3 := waitFor(runB, retry(runB, b2, nil), "run B's third execution did not end")
	require.Equal(t, "succeeded", b3.status)
	require.Equal(t, b1.attemptID, b3.attemptID)
	require.Equal(t, 4, executions(), "a queued retry of the publish step ran the job again")
	verified(runB, b3.execution(), b2.execution(), content(4))

	// The second execution never published. Its publication arriving now,
	// late, is refused: it does not become the latest execution's.
	out, err = publish(runB, b2.execution())
	txeKeep(t, "commands/late-run-b-execution-2.txt", fmt.Appendf(nil, "error: %v\n\nstdout:\n%s", err, out))
	require.Error(t, err, "a late publication was recorded: %s", out)
	assert.Contains(t, err.Error(), "stale_binding")
	_, listing, raw = hub.call(http.MethodGet, "/txe/jobs/"+jobID+"/runs/"+runB+"/artifacts", nil)
	t.Logf("run B executions listed by the registry: %v; hub executions b1=%s b2=%s b3=%s (one attempt %s)",
		listing["executions"], b1.execution().Ref(), b2.execution().Ref(), b3.execution().Ref(), b1.attemptID)
	txeKeep(t, "manifests/"+runB+"/default.json", []byte(raw))
	code, _, raw = hub.manifest(jobID, runB, b2.execution())
	assert.Equal(t, http.StatusNotFound, code, raw)
	txeKeep(t, "responses/manifest-of-run-b-execution-2.txt", fmt.Appendf(nil, "HTTP %d\n%s", code, raw))
	_, _, raw = hub.call(http.MethodGet, "/txe/jobs/"+jobID, nil)
	txeKeep(t, "responses/job-at-end.json", []byte(raw))
	txeKeepHubCopies(t, "hub-copies", hubHelper.Config.Paths.ArtifactDir)
	txeKeep(t, "access.txt", []byte(access.String()))
}
