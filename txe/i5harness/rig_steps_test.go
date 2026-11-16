// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package i5harness_test

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeHub answers the harness's observation port (127.0.0.1:28980) with fixed
// replies, so a step's own gate can be tested without a hub.
func fakeHub(t *testing.T, routes map[string]func(w http.ResponseWriter, r *http.Request)) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:28980")
	if err != nil {
		t.Skipf("the harness's frontend port is busy: %v", err)
	}
	mux := http.NewServeMux()
	for pattern, h := range routes {
		mux.HandleFunc(pattern, h)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func reply(status int, body any) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// initialisedRig is a fake rig after init, with the identities up would write.
func initialisedRig(t *testing.T) fakeRig {
	t.Helper()
	f := newFakeRig(t)
	out, code := f.init(t)
	require.Equal(t, 0, code, out)
	write(t, filepath.Join(f.root, "ids.env"), "OWNER=own_X\nMACHINE=mch_01M00000000000000000000000\nJOB=job_X\nRUN=run_X\n")
	write(t, filepath.Join(f.root, "person-token"), "synthetic")
	return f
}

func mark(t *testing.T, f fakeRig, steps ...string) {
	t.Helper()
	for _, s := range steps {
		write(t, filepath.Join(f.root, "control", "step-"+s), "test\n")
	}
}

func proposalRoutes(decision func(http.ResponseWriter, *http.Request)) map[string]func(http.ResponseWriter, *http.Request) {
	return map[string]func(http.ResponseWriter, *http.Request){
		"GET /api/v1/txe/jobs/job_X/proposals": reply(200, map[string]any{"open": []any{map[string]any{
			"proposal_id": "prp_1", "revision": 1, "binding_digest": "d", "native_task": map[string]any{"run_id": "t1"}}}, "finished": []any{}}),
		"GET /api/v1/dag-runs/txe-decide-01M00000000000000000000000/t1": reply(200, map[string]any{"dagRunDetails": map[string]any{"statusLabel": "waiting"}}),
		"POST /api/v1/txe/jobs/job_X/proposals/prp_1/decisions":         decision,
	}
}

// A refused decision is kept as evidence and leaves the step open: the person
// with authority must see it, and nothing claims the decision was made.
func TestRigDecideMarksOnlyACompletedDecision(t *testing.T) {
	f := initialisedRig(t)
	mark(t, f, "tick1")
	fakeHub(t, proposalRoutes(reply(409, map[string]any{"code": "binding_stale"})))
	out, code := rig(t, "decide", "--rig", f.root, "--proposal", "prp_1", "--verdict", "retry", "--authority", "msg_test")
	assert.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "did not complete the decision (HTTP 409)")
	assert.NoFileExists(t, filepath.Join(f.root, "control", "step-decided"))
	assert.FileExists(t, filepath.Join(f.root, "evidence", "decision", "decision-response-1.txt"))
	assert.FileExists(t, filepath.Join(f.root, "evidence", "decision", "authority.json"))
}

func TestRigDecideRecordsAnAcceptedDecision(t *testing.T) {
	f := initialisedRig(t)
	mark(t, f, "tick1")
	calls := 0
	fakeHub(t, proposalRoutes(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			reply(503, map[string]any{"code": "follow_up_pending"})(w, r)
			return
		}
		reply(200, map[string]any{"decision": "recorded"})(w, r)
	}))
	out, code := rig(t, "decide", "--rig", f.root, "--proposal", "prp_1", "--verdict", "retry", "--authority", "msg_test")
	require.Equal(t, 0, code, out)
	assert.Equal(t, 2, calls, "a pending follow-up is replayed with the same request")
	assert.FileExists(t, filepath.Join(f.root, "control", "step-decided"))
	var auth map[string]string
	raw, err := os.ReadFile(filepath.Join(f.root, "evidence", "decision", "authority.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &auth))
	assert.Equal(t, "msg_test", auth["authority"])
}

// proofRig is a rig after a decision on prp_1, with a sealed run in place.
func proofRig(t *testing.T) (f fakeRig, runDir string) {
	t.Helper()
	f = initialisedRig(t)
	mark(t, f, "decided")
	write(t, filepath.Join(f.root, "evidence", "decision", "authority.json"), `{"authority":"msg_test","proposal":"prp_1","verdict":"retry"}`)
	seals, runDir := sealedRun(t)
	raw, err := os.ReadFile(seals)
	require.NoError(t, err)
	write(t, filepath.Join(f.root, "evidence", "loss", "seals.json"), string(raw))
	write(t, filepath.Join(f.root, "control", "run-dir"), runDir)
	write(t, filepath.Join(f.root, "control", "counter"), "1\n")
	write(t, filepath.Join(f.root, "evidence", "loss", "counter-after-loss"), "1\n")
	return f, runDir
}

// sealedSha is the sha256 sealedRun records for result.json.
func sealedSha(t *testing.T, runDir string) string {
	t.Helper()
	var s struct {
		Seals []struct {
			Files []struct{ Sha256 string } `json:"files"`
		} `json:"seals"`
	}
	raw, err := os.ReadFile(filepath.Join(runDir, "seals.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &s))
	return s.Seals[0].Files[0].Sha256
}

// published is the hub's view after a publish-only recovery of a1-e1 as b1-e2.
func published(status, runStep, digest string) (run, artifacts any) {
	run = map[string]any{"dagRunDetails": map[string]any{
		"statusLabel": status, "executionRef": "b1-e2", "retryRequest": map[string]any{"retryOf": "a1-e1"},
		"nodes": []any{
			map[string]any{"step": map[string]any{"name": "run"}, "statusLabel": runStep},
			map[string]any{"step": map[string]any{"name": "publish"}, "statusLabel": status},
		}}}
	artifacts = map[string]any{"execution": "b1-e2", "produced_in": map[string]any{"execution": "a1-e1"},
		"artifacts": []any{map[string]any{"path": "result.json", "sha256": digest, "status": "verified"}}}
	return run, artifacts
}

func proofRoutes(actions, run, artifacts any) map[string]func(http.ResponseWriter, *http.Request) {
	ok := reply(200, map[string]any{"ok": true})
	return map[string]func(http.ResponseWriter, *http.Request){
		"GET /api/v1/txe/jobs/job_X/actions":              reply(200, actions),
		"GET /api/v1/dag-runs/job_X/run_X":                reply(200, run),
		"GET /api/v1/dag-runs/job_X/run_X/attempts":       ok,
		"GET /api/v1/txe/jobs/job_X/runs/run_X/artifacts": reply(200, artifacts),
		"GET /api/v1/txe/jobs/job_X/events":               ok,
	}
}

func liveWorker(t *testing.T, f fakeRig) {
	t.Helper()
	pidfile := filepath.Join(f.root, "control", "worker.pid")
	out, code := tool(t, "procs.py", "start", "--pidfile", pidfile, "--log", filepath.Join(f.root, "logs", "w.log"), "--", "/bin/sleep", "300")
	require.Equal(t, 0, code, out)
	t.Cleanup(func() { _, _ = tool(t, "procs.py", "stop", "--pidfile", pidfile, "--timeout", "5") })
}

// A succeeded action only says the retry was dispatched: proof also needs the
// admitted execution to finish and to have published the sealed bytes.
func TestRigProofNeedsThePublicationItself(t *testing.T) {
	for name, tc := range map[string]struct {
		status, runStep string
		digestOK        bool
		want            string
	}{
		"still running":  {"running", "failed", true, "did not finish"},
		"publish failed": {"failed", "failed", true, "the admitted execution ended 'failed'"},
		"job ran again":  {"succeeded", "succeeded", true, "the job ran again"},
		"other bytes":    {"succeeded", "failed", false, "published 'sha256:other'"},
	} {
		t.Run(name, func(t *testing.T) {
			f, runDir := proofRig(t)
			liveWorker(t, f)
			digest := "sha256:other"
			if tc.digestOK {
				digest = sealedSha(t, runDir)
			}
			run, art := published(tc.status, tc.runStep, digest)
			fakeHub(t, proofRoutes(succeededAction, run, art))
			out, code := rigEnv(t, []string{"I5_POLL_LIMIT=2"}, "proof", "--rig", f.root)
			assert.NotEqual(t, 0, code, out)
			assert.Contains(t, out, tc.want)
			assert.NoFileExists(t, filepath.Join(f.root, "control", "step-proof"))
		})
	}
}

var succeededAction = map[string]any{"in_flight": []any{}, "archived": []any{map[string]any{
	"action_id": "act_1", "proposal_id": "prp_1", "state": "succeeded",
	"outcome": map[string]any{"admitted": true, "admitted_execution": "b1-e2"}}}}

func TestRigProofPassesOnlyWithEveryInvariant(t *testing.T) {
	f, runDir := proofRig(t)
	liveWorker(t, f)
	run, art := published("succeeded", "failed", sealedSha(t, runDir))
	fakeHub(t, proofRoutes(succeededAction, run, art))
	out, code := rig(t, "proof", "--rig", f.root)
	require.Equal(t, 0, code, out)
	assert.FileExists(t, filepath.Join(f.root, "control", "step-proof"))
}

// proof keeps its evidence but fails, unmarked, when the action did not
// succeed, the sealed bytes changed, or the worker is not the process that ran
// the fixture.
func TestRigProofFailsWhenAnInvariantBreaks(t *testing.T) {
	f, runDir := proofRig(t)
	require.NoError(t, os.WriteFile(filepath.Join(runDir, "executions", "a1-e1", "result.json"), []byte("changed"), 0o644))
	write(t, filepath.Join(f.root, "control", "worker.pid"), `{"pid": 999999, "pgid": 999999, "lstart": "x", "comm": "dagu", "token": "t"}`)
	run, art := published("failed", "failed", "sha256:x")
	fakeHub(t, proofRoutes(map[string]any{"in_flight": []any{}, "archived": []any{map[string]any{
		"action_id": "act_1", "proposal_id": "prp_1", "state": "escalated", "outcome": map[string]any{}}}}, run, art))
	out, code := rigEnv(t, []string{"I5_POLL_LIMIT=2"}, "proof", "--rig", f.root)
	assert.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "the action for prp_1 did not succeed")
	assert.Contains(t, out, "the sealed bytes changed")
	assert.Contains(t, out, "the worker is not the process that ran the fixture")
	assert.NoFileExists(t, filepath.Join(f.root, "control", "step-proof"))
	assert.FileExists(t, filepath.Join(f.root, "evidence", "proof", "seal-bytes-after.txt"))
}

func TestActionsState(t *testing.T) {
	dir := t.TempDir()
	check := func(doc any) int {
		b, _ := json.Marshal(doc)
		_, code := tool(t, "actions.py", write(t, filepath.Join(dir, "a.json"), string(b)), "prp_1")
		return code
	}
	action := func(bucket, state string, admitted bool) any {
		return map[string]any{bucket: []any{map[string]any{"proposal_id": "prp_1", "state": state,
			"outcome": map[string]any{"admitted": admitted, "admitted_execution": map[bool]string{true: "b1-e2"}[admitted]}}}}
	}
	assert.Equal(t, 0, check(succeededAction))
	assert.Equal(t, 3, check(map[string]any{"archived": []any{}, "in_flight": []any{}}), "no action yet")
	assert.Equal(t, 3, check(action("in_flight", "uncertain", true)), "still settling")
	assert.Equal(t, 2, check(action("archived", "failed", false)))
	assert.Equal(t, 2, check(action("archived", "succeeded", false)), "succeeded without an admitted execution")
	two := map[string]any{"archived": []any{
		map[string]any{"proposal_id": "prp_1", "state": "succeeded"}, map[string]any{"proposal_id": "prp_1", "state": "failed"}}}
	assert.Equal(t, 2, check(two), "two actions for one proposal")
}

// up can fail at a preflight gate after starting the hub and before writing
// ids.env; down must still stop what was started.
func TestRigDownWithoutIdentitiesStopsWhatRuns(t *testing.T) {
	f := newFakeRig(t)
	out, code := f.init(t)
	require.Equal(t, 0, code, out)
	hubPid := filepath.Join(f.root, "control", "hub.pid")
	out, code = tool(t, "procs.py", "start", "--pidfile", hubPid, "--log", filepath.Join(f.root, "logs", "hub.log"), "--", "/bin/sleep", "300")
	require.Equal(t, 0, code, out)
	out, code = rig(t, "down", "--rig", f.root)
	require.Equal(t, 0, code, out)
	assert.FileExists(t, hubPid+".stopped")
	assert.FileExists(t, filepath.Join(f.root, "control", "step-down"))
}

func TestCheckSealHasSeal(t *testing.T) {
	dir := t.TempDir()
	begun := write(t, filepath.Join(dir, "begun.json"), `{"schema":1,"begun":[{"attempt_id":"a1"}]}`)
	_, code := tool(t, "check_seal.py", "--has-seal", begun)
	assert.Equal(t, 1, code, "a begun execution without a seal is not sealed")
	seals, _ := sealedRun(t)
	_, code = tool(t, "check_seal.py", "--has-seal", seals)
	assert.Equal(t, 0, code)
	_, code = tool(t, "check_seal.py", "--has-seal", filepath.Join(dir, "missing.json"))
	assert.Equal(t, 1, code)
}

func TestCheckProof(t *testing.T) {
	seals, runDir := sealedRun(t)
	dir := t.TempDir()
	check := func(run, art any, before, now string) (string, int) {
		rb, _ := json.Marshal(run)
		ab, _ := json.Marshal(art)
		return tool(t, "check_proof.py", "--run", write(t, filepath.Join(dir, "run.json"), string(rb)),
			"--artifacts", write(t, filepath.Join(dir, "art.json"), string(ab)), "--seals", seals, "--admitted", "b1-e2",
			"--counter-at-loss", write(t, filepath.Join(dir, "c1"), before), "--counter-now", write(t, filepath.Join(dir, "c2"), now))
	}
	run, art := published("succeeded", "failed", sealedSha(t, runDir))
	out, code := check(run, art, "1\n", "1\n")
	require.Equal(t, 0, code, out)

	out, code = check(run, art, "1\n", "2\n")
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "counter moved from 1 to 2")

	wrongRetry, _ := published("succeeded", "failed", sealedSha(t, runDir))
	wrongRetry.(map[string]any)["dagRunDetails"].(map[string]any)["retryRequest"] = map[string]any{"retryOf": "zz-zz"}
	out, code = check(wrongRetry, art, "1\n", "1\n")
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "retryRequest.retryOf is 'zz-zz'")

	_, extra := published("succeeded", "failed", sealedSha(t, runDir))
	files := extra.(map[string]any)["artifacts"].([]any)
	extra.(map[string]any)["artifacts"] = append(files, map[string]any{"path": "other.json", "sha256": "sha256:o"})
	out, code = check(run, extra, "1\n", "1\n")
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "not sealed")

	queued, _ := published("queued", "failed", sealedSha(t, runDir))
	_, code = check(queued, art, "1\n", "1\n")
	assert.Equal(t, 3, code, "a queued admitted execution is pending, not failed")
}
