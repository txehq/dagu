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

// proof keeps its evidence but fails, unmarked, when the sealed bytes changed
// or the worker is not the process that ran the fixture.
func TestRigProofFailsWhenAnInvariantBreaks(t *testing.T) {
	f := initialisedRig(t)
	mark(t, f, "decided")
	seals, runDir := sealedRun(t)
	require.NoError(t, os.MkdirAll(filepath.Join(f.root, "evidence", "loss"), 0o755))
	raw, err := os.ReadFile(seals)
	require.NoError(t, err)
	write(t, filepath.Join(f.root, "evidence", "loss", "seals.json"), string(raw))
	write(t, filepath.Join(f.root, "control", "run-dir"), runDir)
	write(t, filepath.Join(f.root, "control", "counter"), "1\n")
	require.NoError(t, os.WriteFile(filepath.Join(runDir, "executions", "a1-e1", "result.json"), []byte("changed"), 0o644))
	write(t, filepath.Join(f.root, "control", "worker.pid"), `{"pid": 999999, "pgid": 999999, "lstart": "x", "comm": "dagu", "token": "t"}`)
	ok := reply(200, map[string]any{"state": "succeeded"})
	fakeHub(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /api/v1/txe/jobs/job_X/actions":              ok,
		"GET /api/v1/dag-runs/job_X/run_X":                ok,
		"GET /api/v1/dag-runs/job_X/run_X/attempts":       ok,
		"GET /api/v1/txe/jobs/job_X/runs/run_X/artifacts": ok,
		"GET /api/v1/txe/jobs/job_X/events":               ok,
	})
	out, code := rig(t, "proof", "--rig", f.root)
	assert.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "the sealed bytes changed")
	assert.Contains(t, out, "the worker is not the process that ran the fixture")
	assert.NoFileExists(t, filepath.Join(f.root, "control", "step-proof"))
	assert.FileExists(t, filepath.Join(f.root, "evidence", "proof", "seal-bytes-after.txt"))
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
