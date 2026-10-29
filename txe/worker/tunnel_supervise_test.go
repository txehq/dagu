// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package worker_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeForward stands in for `kubectl port-forward` (TXE-5398). It serves the UI and coordinator
// ports in the mode named by its mode file, read on every connection:
//
//	ok            health 200, and the coordinator port answers the HTTP/2 preface with SETTINGS
//	dead-streams  every new connection is accepted and closed, as kubectl does when it cannot
//	              create a stream; the worker's existing connection is healthy (no log lines)
//	dead-all      the same, and the worker logs a heartbeat failure every 0.2 s
//	http-dead     health is closed, the coordinator still answers; the worker logs failures
//	flapping      new connections fail as in dead-streams; the worker's heartbeats fail and
//	              succeed in turn (a failure line, then the client's recovery line, every 0.2 s)
//	exit:N        exit with code N
//
// The worker log lines are SIMULATED: they copy the worker's message text and format, but no
// real worker writes them here.
//
// It records each signal it gets in its signal file, ends on SIGTERM unless the file "stubborn"
// exists beside the mode file, and writes its pid to the pid file.
const fakeForward = `
import datetime, os, signal, socket, sys, threading, time
mode_file, sig_file, pid_file, worker_log, ui, coord = sys.argv[1:7]
d = os.path.dirname(mode_file)
open(pid_file, "w").write(str(os.getpid()))
def on_signal(n, _f):
    with open(sig_file, "a") as f:
        f.write(f"{n}\n")
    if not os.path.exists(os.path.join(d, "stubborn")):
        os._exit(0)
for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(s, on_signal)
def mode():
    return open(mode_file).read().strip()
def serve(port, kind):
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", int(port))); ls.listen(16)
    while True:
        c, _ = ls.accept()
        m = mode()
        try:
            if m == "ok" or (m == "http-dead" and kind == "h2"):
                if kind == "http":
                    c.recv(4096)
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                else:
                    c.recv(64)
                    c.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
                    time.sleep(0.05)
        finally:
            c.close()
for port, kind in ((ui, "http"), (coord, "h2")):
    threading.Thread(target=serve, args=(port, kind), daemon=True).start()
while True:
    m = mode()
    if m.startswith("exit:"):
        sys.exit(int(m[5:]))
    if m in ("dead-all", "http-dead", "flapping"):
        with open(worker_log, "a") as f:
            t = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="milliseconds")
            f.write(f'time={t} level=WARN msg="Heartbeat send failed; will retry with backoff" worker-id=mch_x err="context deadline exceeded"\n')
            if m == "flapping":
                f.write(f'time={t} level=INFO msg="CoordinatorCli connection recovered" previous-consecutive-failures=1\n')
    time.sleep(0.2)
`

// syncBuffer is the supervisor's output, read by the test while the process still writes it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type supervised struct {
	dir, modeFile, sigFile, pidFile, state string
	cmd                                    *exec.Cmd
	stderr                                 *syncBuffer
	done                                   chan error
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

func supervisorScript(t *testing.T) string {
	t.Helper()
	agentsScript(t) // skips where the worker scripts do not run
	script, err := filepath.Abs("tunnel-supervise.py")
	require.NoError(t, err)
	return script
}

// startSupervised runs the supervisor over the fake forward with short timings: rounds every
// 0.2 s, a 1.5 s required unhealthy time, and the worker's failures counted with a 0.6 s gap.
func startSupervised(t *testing.T, mode string, extra ...string) *supervised {
	t.Helper()
	script := supervisorScript(t)
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	s := &supervised{dir: t.TempDir()}
	s.modeFile = filepath.Join(s.dir, "mode")
	s.sigFile = filepath.Join(s.dir, "signals")
	s.pidFile = filepath.Join(s.dir, "pid")
	s.state = filepath.Join(s.dir, "supervise-state.json")
	fake := filepath.Join(s.dir, "fake-kubectl.py")
	workerLog := filepath.Join(s.dir, "worker.log")
	require.NoError(t, os.WriteFile(fake, []byte(fakeForward), 0o600))
	s.setMode(t, mode)
	ui, coord := freePort(t), freePort(t)
	args := []string{"-I", script, "--ui-port", fmt.Sprint(ui), "--coord-port", fmt.Sprint(coord),
		"--worker-log", workerLog, "--state", s.state,
		"--interval", "0.2", "--grace", "0.3", "--probe-timeout", "0.3", "--unhealthy-after", "1.5",
		"--worker-gap", "0.6", "--kill-timeout", "0.5"}
	args = append(args, extra...)
	args = append(args, "--", py, "-I", fake, s.modeFile, s.sigFile, s.pidFile, workerLog, fmt.Sprint(ui), fmt.Sprint(coord))
	s.cmd = exec.Command(py, args...)
	s.stderr = &syncBuffer{}
	s.cmd.Stdout, s.cmd.Stderr = s.stderr, s.stderr
	s.cmd.Env = []string{"PATH=/usr/bin:/bin"}
	require.NoError(t, s.cmd.Start())
	s.done = make(chan error, 1)
	go func() { s.done <- s.cmd.Wait() }()
	t.Cleanup(func() {
		_ = s.cmd.Process.Kill()
		if pid := s.childPid(); pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	require.Eventually(t, func() bool { return s.childPid() > 0 }, 5*time.Second, 20*time.Millisecond)
	return s
}

func (s *supervised) setMode(t *testing.T, mode string) {
	t.Helper()
	require.NoError(t, os.WriteFile(s.modeFile+".tmp", []byte(mode), 0o600))
	require.NoError(t, os.Rename(s.modeFile+".tmp", s.modeFile))
}

func (s *supervised) childPid() int {
	b, err := os.ReadFile(s.pidFile)
	if err != nil {
		return 0
	}
	var pid int
	_, _ = fmt.Sscan(string(b), &pid)
	return pid
}

func (s *supervised) signals() string {
	b, _ := os.ReadFile(s.sigFile)
	return string(b)
}

// exit waits for the supervisor and returns its exit code, or fails after limit.
func (s *supervised) exit(t *testing.T, limit time.Duration) int {
	t.Helper()
	select {
	case err := <-s.done:
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			return ee.ExitCode()
		}
		require.NoError(t, err)
		return 0
	case <-time.After(limit):
		t.Fatalf("supervisor still running after %s; output:\n%s", limit, s.stderr)
		return -1
	}
}

func (s *supervised) stillRunning(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case err := <-s.done:
		t.Fatalf("supervisor exited (%v); output:\n%s", err, s.stderr)
	case <-time.After(d):
	}
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// A working forward is never replaced, and a SIGTERM to the supervisor (launchctl bootout or
// kickstart) is passed to kubectl.
func TestTunnelSuperviseLeavesAHealthyForward(t *testing.T) {
	s := startSupervised(t, "ok")
	s.stillRunning(t, 3*time.Second)
	require.NoError(t, s.cmd.Process.Signal(syscall.SIGTERM))
	assert.Equal(t, 0, s.exit(t, 5*time.Second), "the supervisor exits with kubectl's code (the fake exits 0)")
	assert.Equal(t, fmt.Sprintf("%d\n", syscall.SIGTERM), s.signals())
	assert.NotContains(t, s.stderr.String(), "replacing")
	assert.NoFileExists(t, s.state)
}

// The forward is alive but every new stream fails, and the worker's heartbeats fail too: the
// supervisor ends kubectl and exits 75 so that launchd starts a fresh forward, and not before
// the required unhealthy time has passed since the first failed round.
func TestTunnelSuperviseReplacesADeadForward(t *testing.T) {
	s := startSupervised(t, "ok")
	time.Sleep(600 * time.Millisecond)
	start := time.Now()
	s.setMode(t, "dead-all")
	assert.Equal(t, 75, s.exit(t, 10*time.Second))
	assert.GreaterOrEqual(t, time.Since(start), 1500*time.Millisecond)
	assert.Equal(t, fmt.Sprintf("%d\n", syscall.SIGTERM), s.signals())
	assert.False(t, alive(s.childPid()), "kubectl is left running")
	out := s.stderr.String()
	assert.Contains(t, out, "tunnel-supervise: ")
	assert.Contains(t, out, "replacing the forward: new streams failing for")
	assert.NotContains(t, out, s.dir, "a supervisor line names a path")
	var state map[string][]float64
	b, err := os.ReadFile(s.state)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &state))
	assert.Len(t, state["restarts"], 1)
}

// New streams fail while the worker's existing connection keeps working (no heartbeat failure):
// replacing kubectl would cut that connection, so the forward is left alone.
func TestTunnelSuperviseKeepsAForwardTheWorkerStillUses(t *testing.T) {
	s := startSupervised(t, "dead-streams")
	s.stillRunning(t, 4*time.Second)
	assert.Contains(t, s.stderr.String(), "new streams through the forward are failing")
	assert.NotContains(t, s.stderr.String(), "replacing")
}

// New streams fail, and the worker's heartbeats fail often but keep succeeding in between (its
// client logs a recovery after each): the existing connection still works at times, so the
// failures are not uninterrupted and the forward is left alone (root's review of e0e1d0ddf).
func TestTunnelSuperviseKeepsAForwardWhileTheWorkerSometimesSucceeds(t *testing.T) {
	s := startSupervised(t, "flapping")
	s.stillRunning(t, 4*time.Second)
	assert.Contains(t, s.stderr.String(), "new streams through the forward are failing")
	assert.NotContains(t, s.stderr.String(), "replacing")
}

// Health fails but the coordinator still answers a new connection, while the worker's
// heartbeats fail (a stall of the hub's API, not of the forward): a new stream works, so the
// forward's connection is alive and replacing it cannot help. It is left alone.
func TestTunnelSuperviseNeedsBothProbesToFail(t *testing.T) {
	s := startSupervised(t, "http-dead")
	s.stillRunning(t, 4*time.Second)
	assert.NotContains(t, s.stderr.String(), "failing")
	assert.NotContains(t, s.stderr.String(), "replacing")
}

// Each replacement in the last hour doubles the required unhealthy time.
func TestTunnelSuperviseBacksOffAfterARecentReplacement(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	require.NoError(t, os.WriteFile(state, []byte(fmt.Sprintf(`{"restarts": [%d]}`, time.Now().Unix()-60)), 0o600))
	s := startSupervised(t, "ok", "--state", state)
	time.Sleep(600 * time.Millisecond)
	start := time.Now()
	s.setMode(t, "dead-all")
	assert.Equal(t, 75, s.exit(t, 15*time.Second))
	assert.GreaterOrEqual(t, time.Since(start), 3000*time.Millisecond)
}

// A kubectl that ignores SIGTERM is killed after the kill timeout: nothing is left behind.
func TestTunnelSuperviseKillsAStubbornForward(t *testing.T) {
	s := startSupervised(t, "ok")
	require.NoError(t, os.WriteFile(filepath.Join(s.dir, "stubborn"), nil, 0o600))
	s.setMode(t, "dead-all")
	assert.Equal(t, 75, s.exit(t, 10*time.Second))
	assert.Equal(t, fmt.Sprintf("%d\n", syscall.SIGTERM), s.signals())
	assert.Eventually(t, func() bool { return !alive(s.childPid()) }, 2*time.Second, 20*time.Millisecond)
}

// kubectl ending by itself ends the supervisor with its code, as the agent did before.
func TestTunnelSupervisePassesKubectlsExit(t *testing.T) {
	s := startSupervised(t, "ok")
	s.setMode(t, "exit:3")
	assert.Equal(t, 3, s.exit(t, 5*time.Second))
}

// The decision itself, on an injected monotonic and wall clock: 30 s rounds, 90 s required.
func TestTunnelSuperviseVerdictBoundaries(t *testing.T) {
	script := supervisorScript(t)
	program := `
import importlib.util, json, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("ts", sys.argv[1]); ts = importlib.util.module_from_spec(spec); spec.loader.exec_module(ts)
W = 1_000_000.0
def run(rounds, restarts=()):
    v = ts.Verdict(90, 600, list(restarts))
    return [bool(v.observe(m, W + m, ok, None if ws is None else W + ws)) for m, ok, ws in rounds]
out = {
  # three failed 30 s rounds span only 60 s: no replacement until 90 s after the first
  "at_60": run([(0, False, -100), (30, False, -100), (60, False, -100)]),
  "at_89": run([(0, False, -100), (89.9, False, -100)]),
  "at_90": run([(0, False, -100), (90, False, -100)]),
  # a working round in between starts the count again
  "reset": run([(0, False, -100), (45, True, None), (90, False, -100), (179, False, -100), (180, False, -100)]),
  # the worker has been failing for only 80 s
  "worker_short": run([(0, False, -100), (90, False, 10)]),
  # no worker signal (healthy, or the log unreadable): never
  "no_worker": run([(0, False, None), (600, False, None)]),
  # one replacement 10 min ago: 180 s required
  "backoff": run([(0, False, -1000), (179, False, -1000), (180, False, -1000)], restarts=[W - 600]),
  # many recent replacements: capped at 600 s
  "cap": run([(0, False, -1000), (600, False, -1000)], restarts=[W - 60] * 5),
}
print(json.dumps(out))
`
	stdout, stderr, err := python(t, "-c", program, script)
	require.NoError(t, err, stderr)
	var got map[string][]bool
	require.NoError(t, json.Unmarshal([]byte(stdout), &got))
	assert.Equal(t, []bool{false, false, false}, got["at_60"])
	assert.Equal(t, []bool{false, false}, got["at_89"])
	assert.Equal(t, []bool{false, true}, got["at_90"])
	assert.Equal(t, []bool{false, false, false, false, true}, got["reset"])
	assert.Equal(t, []bool{false, false}, got["worker_short"])
	assert.Equal(t, []bool{false, false}, got["no_worker"])
	assert.Equal(t, []bool{false, false, true}, got["backoff"])
	assert.Equal(t, []bool{false, true}, got["cap"])
}

// The worker's episode of failed coordinator calls is read from its log: the heartbeat failures
// since its client last logged a recovery (or the worker last started), only while the latest is
// recent. Successes are silent, so a short gap between failure lines is not continuity: one
// recovery line in between ends the episode. Anything unreadable is no signal. Lines are
// SIMULATED in the worker's text and JSON formats.
func TestTunnelSuperviseReadsTheWorkersHeartbeatFailures(t *testing.T) {
	script := supervisorScript(t)
	dir := t.TempDir()
	fail := func(ts string) string {
		return `time=` + ts + ` level=WARN msg="Heartbeat send failed; will retry with backoff" worker-id=mch_x err="context deadline exceeded"`
	}
	recovered := func(ts string) string {
		return `time=` + ts + ` level=INFO msg="CoordinatorCli connection recovered" previous-consecutive-failures=2`
	}
	write := func(name string, lines ...string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600))
		return path
	}
	logs := map[string]string{
		// uninterrupted: the episode starts at the first failure after the recovery
		"steady": write("steady.log",
			fail("2026-10-29T15:10:00.000+08:00"),
			recovered("2026-10-29T15:12:00.000+08:00"),
			`time=2026-10-29T15:15:00.000+08:00 level=INFO msg="Task execution completed successfully"`,
			fail("2026-10-29T07:16:04.291Z"), // UTC as Go writes it
			// the worker's JSON log format (log_format: json)
			`{"time":"2026-10-29T15:16:27.000+08:00","level":"WARN","msg":"Heartbeat send failed; will retry with backoff","worker-id":"mch_x"}`,
			`{"time":"2026-10-29T15:16:40.000+08:00","level":"WARN","msg":"Heartbeat send failed (another message)"}`,
			fail("2026-10-29T07:16:40"), // no offset: cannot be placed, ignored
			fail("2026-10-29T15:16:50.000+08:00")),
		// failures every 30 s, each followed by a recovery within a second: never uninterrupted
		"flapping": write("flapping.log",
			fail("2026-10-29T15:15:00.000+08:00"), recovered("2026-10-29T15:15:01.000+08:00"),
			fail("2026-10-29T15:15:30.000+08:00"), recovered("2026-10-29T15:15:31.000+08:00"),
			fail("2026-10-29T15:16:00.000+08:00"), recovered("2026-10-29T15:16:01.000+08:00"),
			fail("2026-10-29T15:16:30.000+08:00"), recovered("2026-10-29T15:16:31.000+08:00"),
			fail("2026-10-29T15:16:50.000+08:00")),
		// the same in the JSON format
		"flapping_json": write("flapping.json.log",
			`{"time":"2026-10-29T07:15:00Z","level":"WARN","msg":"Heartbeat send failed; will retry with backoff"}`,
			`{"time":"2026-10-29T07:16:31Z","level":"INFO","msg":"CoordinatorCli connection recovered","previous-consecutive-failures":3}`,
			`{"time":"2026-10-29T07:16:50Z","level":"WARN","msg":"Heartbeat send failed; will retry with backoff"}`),
		// a worker restart in between: its new client starts clean, so the episode restarts
		"restarted": write("restarted.log",
			fail("2026-10-29T15:15:00.000+08:00"),
			`time=2026-10-29T15:16:10.000+08:00 level=INFO msg="Starting worker" worker-id=mch_x max-concurrency=100`,
			fail("2026-10-29T15:16:20.000+08:00"),
			fail("2026-10-29T15:16:50.000+08:00")),
		// the text format with debug: the source sits between level and msg, for failures and recoveries alike
		"debug": write("debug.log",
			`time=2026-10-29T15:15:00.000+08:00 level=WARN source=/src/internal/service/worker/worker.go:673 msg="Heartbeat send failed; will retry with backoff"`,
			`time=2026-10-29T15:16:10.000+08:00 level=INFO source="/Users/some one/dagu/internal/service/coordinator/client.go:1054" msg="CoordinatorCli connection recovered" previous-consecutive-failures=1`,
			`time=2026-10-29T15:16:20.000+08:00 level=WARN source=/src/internal/service/worker/worker.go:673 msg="Heartbeat send failed; will retry with backoff"`,
			`time=2026-10-29T15:16:50.000+08:00 level=WARN source=/src/internal/service/worker/worker.go:673 msg="Heartbeat send failed; will retry with backoff"`),
		// a silent stretch longer than the gap: not shown to be one episode
		"gap": write("gap.log",
			fail("2026-10-29T15:14:00.000+08:00"),
			fail("2026-10-29T15:16:20.000+08:00"),
			fail("2026-10-29T15:16:50.000+08:00")),
	}
	program := `
import datetime, importlib.util, json, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("ts", sys.argv[1]); ts = importlib.util.module_from_spec(spec); spec.loader.exec_module(ts)
at = lambda s: datetime.datetime.fromisoformat(s).timestamp()
def since(path, now):
    v = ts.worker_unhealthy_since(path, at(now), 45)
    return None if v is None else datetime.datetime.fromtimestamp(v, datetime.timezone.utc).isoformat()
logs = json.loads(sys.argv[2])
out = {k: since(p, "2026-10-29T07:17:00+00:00") for k, p in logs.items()}
out["stale"] = since(logs["steady"], "2026-10-29T07:18:00+00:00")
out["missing"] = since(logs["steady"] + ".absent", "2026-10-29T07:17:00+00:00")
print(json.dumps(out))
`
	arg, err := json.Marshal(logs)
	require.NoError(t, err)
	stdout, stderr, err := python(t, "-c", program, script, string(arg))
	require.NoError(t, err, stderr)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &got))
	assert.Equal(t, "2026-10-29T07:16:04.291000+00:00", got["steady"])
	assert.Equal(t, "2026-10-29T07:16:50+00:00", got["flapping"], "only the failure after the last recovery counts")
	assert.Equal(t, "2026-10-29T07:16:50+00:00", got["flapping_json"])
	assert.Equal(t, "2026-10-29T07:16:20+00:00", got["restarted"])
	assert.Equal(t, "2026-10-29T07:16:20+00:00", got["debug"], "the recovery with a source is read too")
	assert.Equal(t, "2026-10-29T07:16:20+00:00", got["gap"])
	assert.Nil(t, got["stale"])
	assert.Nil(t, got["missing"])
}

// The supervisor follows the worker's log across rounds (TXE-5398 review of 3a3c24570): an episode
// is kept however much else is logged between rounds, a replaced or truncated file starts over
// with no episode, and a line cut across two reads is read whole. Lines are SIMULATED.
func TestTunnelSuperviseFollowsTheWorkersLog(t *testing.T) {
	script := supervisorScript(t)
	program := `
import importlib.util, json, os, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("ts", sys.argv[1]); ts = importlib.util.module_from_spec(spec); spec.loader.exec_module(ts)
d = sys.argv[2]; T0 = 1793250000.0
def stamp(t): return __import__("datetime").datetime.fromtimestamp(t, __import__("datetime").timezone.utc).isoformat(timespec="milliseconds")
fail = lambda t: f'time={stamp(t)} level=WARN msg="Heartbeat send failed; will retry with backoff" worker-id=mch_x\n'
noise = lambda t: f'time={stamp(t)} level=WARN msg="Failed to check coordinator health" coordinator-id=coord-0 err="health check failed"\n'
out = {}

# 1. 600 s of uninterrupted failures, every 10 s, with about 300 KiB of other warnings between rounds.
p = os.path.join(d, "busy.log"); open(p, "w").close(); log = ts.WorkerLog(p, 45); seen = []
log.poll(T0 - 30)   # the supervisor's first round, before the outage: from here on every read is incremental
for i in range(61):
    t = T0 + 10 * i
    with open(p, "a") as f:
        f.write(fail(t))
        if i % 3 == 0:
            f.write(noise(t) * 2000)
    if i % 3 == 0:
        seen.append(log.poll(t + 1))
out["busy_start"] = seen[-1] - T0
out["busy_size"] = os.path.getsize(p)
v = ts.worker_unhealthy_since(p, T0 + 601, 45)   # a single tail read sees only the end, or no failure at all
out["one_shot_start"] = None if v is None else v - T0

# 2. The file is replaced (rotation by rename): the episode starts over in the new file.
p = os.path.join(d, "rot.log"); log = ts.WorkerLog(p, 45)
with open(p, "w") as f: f.write(fail(T0) + fail(T0 + 10))
out["rot_before"] = log.poll(T0 + 11) - T0
os.rename(p, p + ".1")
with open(p, "w") as f: f.write(fail(T0 + 30))
out["rot_after"] = log.poll(T0 + 31) - T0

# 3. The file is truncated in place: the same.
p = os.path.join(d, "trunc.log"); log = ts.WorkerLog(p, 45)
with open(p, "w") as f: f.write(fail(T0) + fail(T0 + 10) + fail(T0 + 20))
log.poll(T0 + 21)
with open(p, "w") as f: f.write(fail(T0 + 40))
out["trunc_after"] = log.poll(T0 + 41) - T0

# 4. A line cut across two reads is read once, whole.
p = os.path.join(d, "cut.log"); log = ts.WorkerLog(p, 45)
line = fail(T0)
with open(p, "w") as f: f.write(line[:30])
out["cut_first"] = log.poll(T0 + 1)
with open(p, "a") as f: f.write(line[30:])
out["cut_second"] = log.poll(T0 + 1) - T0

# 5. The log disappears: no evidence, and following starts again when it is back.
p = os.path.join(d, "gone.log"); log = ts.WorkerLog(p, 45)
with open(p, "w") as f: f.write(fail(T0))
log.poll(T0 + 1); os.unlink(p)
out["gone"] = log.poll(T0 + 2)
print(json.dumps(out))
`
	stdout, stderr, err := python(t, "-c", program, script, t.TempDir())
	require.NoError(t, err, stderr)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &got))
	assert.Greater(t, got["busy_size"], float64(4*256*1024), "the log grew well past one tail read")
	assert.Equal(t, 0.0, got["busy_start"], "the episode keeps its start across all of it")
	assert.NotEqual(t, 0.0, got["one_shot_start"], "a single tail read would have lost the start")
	assert.Equal(t, 0.0, got["rot_before"])
	assert.Equal(t, 30.0, got["rot_after"])
	assert.Equal(t, 40.0, got["trunc_after"])
	assert.Nil(t, got["cut_first"])
	assert.Equal(t, 0.0, got["cut_second"])
	assert.Nil(t, got["gone"])
}

// The supervisor reads three of the worker's own log messages. Each is pinned to the code that
// emits it, together with what the supervisor relies on: every heartbeat goes through attemptCall,
// which records each failure, and recordSuccess logs the recovery on the first success after a
// recorded failure. If any of this changes, this fails instead of the supervisor misreading.
func TestTunnelSuperviseMatchesTheWorkersMessages(t *testing.T) {
	read := func(parts ...string) string {
		b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
		require.NoError(t, err)
		return string(b)
	}
	worker := read("internal", "service", "worker", "worker.go")
	client := read("internal", "service", "coordinator", "client.go")
	assert.Contains(t, worker, `logger.Warn(ctx, "Heartbeat send failed; will retry with backoff",`)
	assert.Contains(t, worker, `logger.Info(ctx, "Starting worker",`)
	assert.Contains(t, client, `logger.Info(ctx, "CoordinatorCli connection recovered",`)
	assert.Contains(t, client, `if !cli.state.IsConnected && cli.state.ConsecutiveFails > 0 {`)
	hb := client[strings.Index(client, "func (cli *clientImpl) Heartbeat("):]
	hb = hb[:strings.Index(hb, "\nfunc ")]
	assert.Contains(t, hb, "cli.attemptCall(", "the heartbeat must go through attemptCall")
	attempt := client[strings.Index(client, "func (cli *clientImpl) attemptCall("):]
	attempt = attempt[:strings.Index(attempt, "\nfunc ")]
	assert.Equal(t, 3, strings.Count(attempt, "cli.recordFailure(err)"), "every failed attempt is recorded")
	assert.Contains(t, attempt, "cli.recordSuccess(ctx)")
	sup, err := os.ReadFile(supervisorScript(t))
	require.NoError(t, err)
	for _, want := range []string{`HEARTBEAT_MSG = "Heartbeat send failed; will retry with backoff"`,
		`RECOVERED_MSG = "CoordinatorCli connection recovered"`, `STARTED_MSG = "Starting worker"`} {
		assert.Contains(t, string(sup), want)
	}
}
