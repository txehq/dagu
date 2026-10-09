// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
}

func (h *txeHub) call(method, path string, body any) (int, map[string]any, string) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(h.t, err)
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.base+path, reader)
	require.NoError(h.t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var value map[string]any
	_ = json.Unmarshal(raw, &value)
	return resp.StatusCode, value, string(raw)
}

func (h *txeHub) waitUp() {
	h.t.Helper()
	require.Eventually(h.t, func() bool {
		code, _, _ := h.call(http.MethodGet, "/txe/installation", nil)
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

// The candidate: this tree's publisher against the registry's real endpoint.
//
// A real hub (dagu start-all: API with the job registry, scheduler,
// coordinator) and a real worker in a process of its own, with its own
// directories. The job is registered through the CLI, so the DAG the hub
// runs is the one the CLI rendered. Every manifest is the one the job's own
// publish step sent; every verdict read back is the registry's.
func TestTXECandidateAgainstRealRegistry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("job packages are shell scripts run by a Unix worker")
	}
	if testing.Short() {
		t.Skip("starts real hub and worker processes")
	}

	apiPort, coordPort := findPort(t), findPort(t)
	hubHelper := test.SetupCommand(t, test.WithBuiltExecutable(), test.WithCoordinatorEnabled())
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

	// The machine: a TXE home, its identity, and the dagu the job's DAG
	// calls. That dagu is a wrapper around the built binary which makes the
	// publish step fail while the test says so, to get an execution whose
	// job step succeeded and whose publish did not.
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

	_, err := cli.run("installer", "context", "add", "txe", "--server="+hub.base, "--api-key="+txeITKey,
		"--dagu-home="+filepath.Join(home, "client"))
	require.NoError(t, err)
	actor := map[string]any{"kind": "cli", "id": "installer"}
	code, _, raw := hub.call(http.MethodPost, "/txe/owners", map[string]any{"owner_id": txeITOwner, "display_name": "Connor Wang", "actor": actor})
	require.Less(t, code, 300, raw)
	code, _, raw = hub.call(http.MethodPost, "/txe/machines", map[string]any{"machine_id": txeITMachine, "owner_id": txeITOwner, "display_name": "candidate-mac", "actor": actor})
	require.Less(t, code, 300, raw)

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
	t.Logf("job %s registered; the hub wrote %s.yaml", jobID, jobID)

	startWorker := func() *txeProcess {
		return txeStartProcess(t, "worker", binary, workerHelper.Config.Core.BaseEnv.AsSlice(),
			"worker", "--config", workerHelper.Config.Paths.ConfigFileUsed, "--worker.id=candidate-worker",
			"--worker.labels=txe.machine="+txeITMachine, "--worker.coordinators=127.0.0.1:"+coordPort,
			"--worker.health-port=0", "--peer.insecure=true")
	}
	startWorker()

	terminal := func(s txeRunState) bool {
		return s.status == "succeeded" || s.status == "failed" || s.status == "aborted"
	}
	// publish runs the publish command by hand, as an execution, the way the
	// job's last step runs it.
	publish := func(runID string, e txeclient.Execution) (string, error) {
		return cli.run("manual", "txe", "artifacts", "publish", "--dagu-home="+filepath.Join(home, "client"),
			"--job="+jobID, "--job-version=1", "--run="+runID, "--attempt="+e.AttemptID, "--queued-at="+e.QueuedAt,
			"--artifact-dir="+t.TempDir(), "--json")
	}
	verified := func(runID string, e txeclient.Execution, producedIn txeclient.Execution, want string) map[string]any {
		t.Helper()
		var manifest map[string]any
		require.Eventually(t, func() bool {
			code, value, _ := hub.manifest(jobID, runID, e)
			manifest = value
			return code == http.StatusOK && txeRecord(t, value, "snapshot")["status"] == "verified"
		}, 30*time.Second, 300*time.Millisecond, "the hub did not verify the copy of execution %s: %v", e.Ref(), manifest)
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

	// ---- Run A: started directly, so it has no queue marker. ----
	runA := "candidate-run-a"
	code, _, raw = hub.call(http.MethodPost, "/dags/"+jobID+"/start", map[string]any{"dagRunId": runA})
	require.Less(t, code, 300, "start: %s", raw)
	a1 := hub.waitRun(jobID, runA, "run A's first execution did not end", terminal)
	require.Equal(t, "succeeded", a1.status)
	require.Empty(t, a1.queuedAt, "a run started directly has a queue marker; the no-marker case is not exercised")
	require.Equal(t, 1, executions())
	verified(runA, a1.execution(), a1.execution(), content(1))

	// The job runs again from its step, as a new attempt, with other bytes.
	code, _, raw = hub.call(http.MethodPost, "/dag-runs/"+jobID+"/"+runA+"/retry",
		map[string]any{"dagRunId": runA, "stepName": "run", "includeDownstream": true})
	require.Less(t, code, 300, "retry from the job step: %s", raw)
	a2 := hub.waitRun(jobID, runA, "run A's second execution did not end", func(s txeRunState) bool {
		return terminal(s) && s.attemptID != a1.attemptID
	})
	require.Equal(t, "succeeded", a2.status)
	require.Equal(t, 2, executions())
	verified(runA, a2.execution(), a2.execution(), content(2))
	// The first execution's manifest and hub copy are as they were.
	verified(runA, a1.execution(), a1.execution(), content(1))

	// Only the publish step runs: a third attempt publishes what the second
	// produced, under its own reference.
	code, _, raw = hub.call(http.MethodPost, "/dag-runs/"+jobID+"/"+runA+"/retry",
		map[string]any{"dagRunId": runA, "stepName": "publish"})
	require.Less(t, code, 300, "retry of the publish step: %s", raw)
	a3 := hub.waitRun(jobID, runA, "run A's third execution did not end", func(s txeRunState) bool {
		return terminal(s) && s.attemptID != a2.attemptID
	})
	require.Equal(t, "succeeded", a3.status)
	require.Equal(t, 2, executions(), "a retry of the publish step ran the job again")
	a3Manifest := verified(runA, a3.execution(), a2.execution(), content(2))

	code, listing, raw := hub.call(http.MethodGet, "/txe/jobs/"+jobID+"/runs/"+runA+"/artifacts", nil)
	require.Equal(t, http.StatusOK, code, raw)
	t.Logf("run A executions listed by the registry: %v", listing["executions"])

	// The same report again, after the run ended, is taken as a replay.
	out, err := publish(runA, a3.execution())
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
	code, value, raw := hub.call(http.MethodPost, "/txe/jobs/"+jobID+"/runs/"+runA+"/artifacts", changed)
	assert.Equal(t, http.StatusConflict, code, raw)
	assert.Equal(t, "artifact_conflict", txeErrorCode(value), raw)
	t.Logf("registry: another report for execution %s: HTTP %d %s", a3.execution().Ref(), code, txeErrorCode(value))

	// A first report from an execution the run never had is refused.
	out, err = publish(runA, txeclient.Execution{AttemptID: a1.attemptID, QueuedAt: "2026-01-01T00:00:00Z"})
	require.Error(t, err, "a publication from an execution that is not the latest was recorded: %s", out)
	assert.Contains(t, err.Error(), "stale_binding")
	t.Logf("publish as an execution run A never had: %v", err)

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

	runB := "candidate-run-b"
	require.NoError(t, os.WriteFile(filepath.Join(control, "fail-job"), nil, 0o600))
	code, _, raw = hub.call(http.MethodPost, "/dags/"+jobID+"/enqueue", map[string]any{"dagRunId": runB})
	require.Less(t, code, 300, "enqueue: %s", raw)
	b1 := hub.waitRun(jobID, runB, "run B's first execution did not fail", func(s txeRunState) bool { return s.status == "failed" })
	require.NotEmpty(t, b1.queuedAt, "an enqueued run has no queue marker")
	require.Equal(t, 3, executions())

	// The job succeeds on the queued retry; its publish step is made to fail.
	retryQueued := func(after txeRunState, what string, done func(txeRunState) bool) txeRunState {
		t.Helper()
		var state txeRunState
		// The hub can lose a queued retry that is admitted just as the
		// earlier execution ends (TXE-3772). The request is repeated until
		// the run has moved on to another queue marker.
		require.Eventually(t, func() bool {
			state, _ = hub.run(jobID, runB)
			if state.queuedAt != after.queuedAt {
				return true
			}
			if state.status == "failed" {
				code, _, raw := hub.call(http.MethodPost, "/dag-runs/"+jobID+"/"+runB+"/retry", map[string]any{"dagRunId": runB})
				if code >= 300 {
					t.Logf("queued retry not admitted yet: %d %s", code, raw)
				}
			}
			return false
		}, 60*time.Second, 2*time.Second, "the queued retry never took effect")
		return hub.waitRun(jobID, runB, what, func(s txeRunState) bool { return s.queuedAt != after.queuedAt && done(s) })
	}
	require.NoError(t, os.Remove(filepath.Join(control, "fail-job")))
	require.NoError(t, os.WriteFile(filepath.Join(control, "fail-publish"), nil, 0o600))
	b2 := retryQueued(b1, "run B's second execution did not fail at publish", func(s txeRunState) bool {
		return s.status == "failed" && s.nodes["run"] == "succeeded"
	})
	require.Equal(t, b1.attemptID, b2.attemptID, "a queued retry got a new attempt; the queued case is not exercised")
	require.Equal(t, 4, executions())
	code, _, raw = hub.manifest(jobID, runB, b2.execution())
	require.Equal(t, http.StatusNotFound, code, "an execution whose publish failed has a manifest: %s", raw)

	// The publish step alone runs on the next queued retry.
	require.NoError(t, os.Remove(filepath.Join(control, "fail-publish")))
	b3 := retryQueued(b2, "run B's third execution did not succeed", func(s txeRunState) bool { return s.status == "succeeded" })
	require.Equal(t, b1.attemptID, b3.attemptID)
	require.Equal(t, 4, executions(), "a queued retry of the publish step ran the job again")
	verified(runB, b3.execution(), b2.execution(), content(4))

	// The second execution never published. Its publication arriving now,
	// late, is refused: it does not become the latest execution's.
	out, err = publish(runB, b2.execution())
	require.Error(t, err, "a late publication was recorded: %s", out)
	assert.Contains(t, err.Error(), "stale_binding")
	t.Logf("late publish as run B's second execution %s: %v", b2.execution().Ref(), err)
	_, listing, _ = hub.call(http.MethodGet, "/txe/jobs/"+jobID+"/runs/"+runB+"/artifacts", nil)
	t.Logf("run B executions listed by the registry: %v; hub executions b1=%s b2=%s b3=%s (one attempt %s)",
		listing["executions"], b1.execution().Ref(), b2.execution().Ref(), b3.execution().Ref(), b1.attemptID)
	code, _, raw = hub.manifest(jobID, runB, b2.execution())
	assert.Equal(t, http.StatusNotFound, code, raw)
}
