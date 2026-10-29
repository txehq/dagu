// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker_test

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The marker lines txe/worker/logpipe.py writes, in the worker's text format, and the three
// worker messages TXE-5398's supervisor matches exactly: a marker must never equal one.
var (
	logpipeMarker   = regexp.MustCompile(`^time=(\S+) level=INFO msg="txe-logpipe: ([^"]*)"`)
	workerTextLine  = regexp.MustCompile(`^time=(\S+) level=\S+ msg="((?:[^"\\]|\\.)*)"`)
	supervisorMsgs  = []string{"Heartbeat send failed; will retry with backoff", "CoordinatorCli connection recovered", "Starting worker"}
	rotatedFileName = regexp.MustCompile(`^worker\.log\.(\d{8}T\d{12}Z)(\.gz)?$`)
)

type logpipeRun struct {
	logs   string
	cmd    *exec.Cmd
	errOut bytes.Buffer
}

// childScript is the fake worker: it writes `lines` numbered lines of about 36 bytes, then
// `tail` without a newline, and exits with `code`. With wait=true it first waits for a
// signal and reports it; with stubborn=true it ignores SIGTERM.
func childScript(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "child.py")
	require.NoError(t, os.WriteFile(path, []byte(`import os, signal, sys, time
lines, tail, code, mode, big = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5])
out = sys.stdout.buffer
for i in range(lines):
    out.write(b"line %05d some worker output text\n" % i)
if big:
    out.write(b"B" * big + b"\n")
out.write(tail.encode())
out.flush()
if mode in ("wait", "stubborn"):
    got = []
    def on(sig, _f):
        got.append(sig)
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, on if mode == "wait" else (lambda sig, _f: None))
    sys.stderr.write("ready\n"); sys.stderr.flush()
    deadline = time.time() + 30
    while time.time() < deadline and not got:
        time.sleep(0.02)
    if got:
        out.write(("signal %d\n" % got[0]).encode()); out.flush()
        sys.exit(code)
    time.sleep(60)
sys.exit(code)
`), 0o600))
	return path
}

func startLogpipe(t *testing.T, logs string, maxBytes, backups, chunk int, extra []string, child ...string) *logpipeRun {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the worker scripts run on the macOS worker only")
	}
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	script, err := filepath.Abs("logpipe.py")
	require.NoError(t, err)
	args := []string{"-I", script, "--path", filepath.Join(logs, "worker.log"),
		"--max-bytes", strconv.Itoa(maxBytes), "--backups", strconv.Itoa(backups), "--chunk-bytes", strconv.Itoa(chunk)}
	args = append(args, extra...)
	args = append(args, "--")
	if len(child) > 0 && child[0] == "python3" {
		child = append([]string{py}, child[1:]...)
	}
	args = append(args, child...)
	r := &logpipeRun{logs: logs}
	r.cmd = exec.Command(py, args...)
	r.cmd.Env = []string{"PATH=/usr/bin:/bin"}
	r.cmd.Stderr = &r.errOut
	require.NoError(t, r.cmd.Start())
	return r
}

// exitCode waits for the wrapper and returns its exit code.
func (r *logpipeRun) exitCode(t *testing.T) int {
	t.Helper()
	err := r.cmd.Wait()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, r.errOut.String())
	return exitErr.ExitCode()
}

// logSet is what reassemble found: the worker's bytes with the marker lines removed, the
// markers, the uncompressed size of every managed file, and the rotated file names oldest first.
type logSet struct {
	worker  []byte
	markers []string
	sizes   map[string]int
	rotated []string
}

// reassemble joins every managed file oldest first (gunzipping the compressed ones).
func reassemble(t *testing.T, logs string) logSet {
	t.Helper()
	var rotated []string
	entries, err := os.ReadDir(logs)
	require.NoError(t, err)
	for _, e := range entries {
		if rotatedFileName.MatchString(e.Name()) {
			rotated = append(rotated, e.Name())
		}
	}
	sort.Slice(rotated, func(i, j int) bool {
		return rotatedFileName.FindStringSubmatch(rotated[i])[1] < rotatedFileName.FindStringSubmatch(rotated[j])[1]
	})
	sizes := map[string]int{}
	var all []byte
	for _, name := range append(append([]string{}, rotated...), "worker.log") {
		raw, err := os.ReadFile(filepath.Join(logs, name))
		require.NoError(t, err)
		if strings.HasSuffix(name, ".gz") {
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			require.NoError(t, err)
			raw, err = io.ReadAll(zr)
			require.NoError(t, err)
		}
		sizes[name] = len(raw)
		all = append(all, raw...)
	}
	var kept [][]byte
	var markers []string
	for _, line := range bytes.SplitAfter(all, []byte("\n")) {
		if logpipeMarker.Match(line) {
			markers = append(markers, strings.TrimRight(string(line), "\n"))
			continue
		}
		kept = append(kept, line)
	}
	return logSet{worker: bytes.Join(kept, nil), markers: markers, sizes: sizes, rotated: rotated}
}

func expectedOutput(lines int, big int, tail string) []byte {
	var b bytes.Buffer
	for i := range lines {
		fmt.Fprintf(&b, "line %05d some worker output text\n", i)
	}
	if big > 0 {
		b.Write(bytes.Repeat([]byte("B"), big))
		b.WriteString("\n")
	}
	b.WriteString(tail)
	return b.Bytes()
}

// Every byte the worker writes lands in the log, in order, including a final line without a
// newline; every file stays within the cap; rotated files are compressed; the child's exit
// code is the wrapper's. backups is large here so nothing is pruned and the reassembly is exact.
func TestLogpipeKeepsEveryByteWithinTheCap(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	r := startLogpipe(t, logs, 20000, 50, 4096, nil, "python3", childScript(t, dir), "5000", "partial-last", "7", "exit", "0")
	assert.Equal(t, 7, r.exitCode(t))
	set := reassemble(t, logs)
	worker, markers, sizes, rotated := set.worker, set.markers, set.sizes, set.rotated
	assert.Equal(t, expectedOutput(5000, 0, "partial-last"), worker, "worker bytes, in order, newline fidelity included")
	require.NotEmpty(t, rotated)
	for name, size := range sizes {
		assert.LessOrEqual(t, size, 20000, name)
	}
	for _, name := range rotated {
		assert.True(t, strings.HasSuffix(name, ".gz"), "rotated files are compressed: %s", name)
	}
	assert.Len(t, markers, len(rotated)+1, "one opening marker, one per rotation")
	assert.Contains(t, markers[0], `msg="txe-logpipe: opened worker.log"`)
	assert.Contains(t, markers[1], `msg="txe-logpipe: rotated worker.log"`)
	assert.Regexp(t, `took_ms=\d+`, markers[1])
	assert.Contains(t, r.errOut.String(), "compressed worker.log.", "compression is reported, rate-limited")
}

// Markers are in the worker's text format so TXE-5398's parser can place them, and their
// message never equals a worker message, so none can pass for a start or a recovery.
func TestLogpipeMarkersCannotMasqueradeAsWorkerLines(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	r := startLogpipe(t, logs, 20000, 50, 4096, nil, "python3", childScript(t, dir), "3000", "", "0", "exit", "0")
	require.Equal(t, 0, r.exitCode(t))
	markers := reassemble(t, logs).markers
	require.NotEmpty(t, markers)
	for _, m := range markers {
		sub := workerTextLine.FindStringSubmatch(m)
		require.NotNil(t, sub, m)
		_, err := time.Parse(time.RFC3339Nano, sub[1])
		assert.NoError(t, err, "the stamp is RFC 3339 with an offset: %s", sub[1])
		assert.True(t, strings.HasPrefix(sub[2], "txe-logpipe: "), m)
		for _, w := range supervisorMsgs {
			assert.NotEqual(t, w, sub[2])
		}
	}
	// Each file this process opens starts with a marker.
	first, err := os.ReadFile(filepath.Join(logs, "worker.log"))
	require.NoError(t, err)
	assert.True(t, logpipeMarker.Match(bytes.SplitN(first, []byte("\n"), 2)[0]))
}

// Only the newest `backups` rotated files are kept: the rest are deleted, and that is the
// only deletion the wrapper does.
func TestLogpipePrunesBeyondTheBackupCount(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	r := startLogpipe(t, logs, 20000, 3, 4096, nil, "python3", childScript(t, dir), "5000", "", "0", "exit", "0")
	require.Equal(t, 0, r.exitCode(t))
	rotated := reassemble(t, logs).rotated
	assert.Len(t, rotated, 3, rotated)
	for _, name := range rotated {
		assert.True(t, strings.HasSuffix(name, ".gz"), name)
	}
}

// A worker.log that exists at start and was not written by the wrapper (launchd's file from
// before activation) is moved aside untouched, to a name outside the pruned set, and a managed
// file is appended to on the next start without another archive.
func TestLogpipeArchivesThePreActivationLogOnce(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	require.NoError(t, os.MkdirAll(logs, 0o700))
	legacy := []byte("old launchd line 1\nold launchd line 2\n")
	require.NoError(t, os.WriteFile(filepath.Join(logs, "worker.log"), legacy, 0o644))

	r := startLogpipe(t, logs, 20000, 1, 4096, nil, "python3", childScript(t, dir), "10", "", "0", "exit", "0")
	require.Equal(t, 0, r.exitCode(t))
	archives, err := filepath.Glob(filepath.Join(logs, "worker.legacy-*.log"))
	require.NoError(t, err)
	require.Len(t, archives, 1)
	got, err := os.ReadFile(archives[0])
	require.NoError(t, err)
	assert.Equal(t, legacy, got, "archived verbatim")
	assert.False(t, rotatedFileName.MatchString(filepath.Base(archives[0])), "outside the pruned set")
	active, err := os.ReadFile(filepath.Join(logs, "worker.log"))
	require.NoError(t, err)
	assert.Contains(t, string(active), `msg="txe-logpipe: opened worker.log" archived=`+filepath.Base(archives[0]))

	// Enough rotations to prune with backups=1: the archive survives.
	r = startLogpipe(t, logs, 20000, 1, 4096, nil, "python3", childScript(t, dir), "3000", "", "0", "exit", "0")
	require.Equal(t, 0, r.exitCode(t))
	archives, err = filepath.Glob(filepath.Join(logs, "worker.legacy-*.log"))
	require.NoError(t, err)
	assert.Len(t, archives, 1, "no second archive, nothing pruned the first")
	markers := reassemble(t, logs).markers
	opened := 0
	for _, m := range markers {
		if strings.Contains(m, "txe-logpipe: opened") {
			opened++
		}
	}
	assert.Equal(t, 0, opened, "a managed file is appended to, not re-opened with a marker, after rotation; the first file's opening marker was rotated away")
}

// A line longer than --chunk-bytes is written in pieces to the current file and never split
// across files: every byte is kept, every file holds whole lines only (so no marker can sit
// inside a line and nothing can be joined across a boundary), and the only file over the cap
// is over it by at most that one line.
func TestLogpipeNeverSplitsALineAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	const big = 50000
	r := startLogpipe(t, logs, 20000, 50, 4096, nil, "python3", childScript(t, dir), "1000", "", "0", "exit", strconv.Itoa(big))
	require.Equal(t, 0, r.exitCode(t))
	set := reassemble(t, logs)
	worker, sizes, rotated := set.worker, set.sizes, set.rotated
	assert.Equal(t, expectedOutput(1000, big, ""), worker)
	over := 0
	for name, size := range sizes {
		assert.LessOrEqual(t, size, 20000+big+1, name)
		if size > 20000 {
			over++
		}
	}
	assert.LessOrEqual(t, over, 1, "only the file holding the oversized line may exceed the cap")
	for _, name := range append(rotated, "worker.log") {
		raw, err := os.ReadFile(filepath.Join(logs, name))
		require.NoError(t, err)
		if strings.HasSuffix(name, ".gz") {
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			require.NoError(t, err)
			raw, err = io.ReadAll(zr)
			require.NoError(t, err)
		}
		assert.True(t, logpipeMarker.Match(bytes.SplitN(raw, []byte("\n"), 2)[0]), "%s starts with a marker", name)
		if name != "worker.log" {
			assert.True(t, bytes.HasSuffix(raw, []byte("\n")), "%s ends at a line boundary", name)
		}
		for line := range bytes.SplitSeq(raw, []byte("\n")) {
			if bytes.Contains(line, []byte("txe-logpipe: ")) {
				assert.True(t, logpipeMarker.Match(line), "a marker is always a whole line of its own: %q", line)
			}
		}
	}
}

// If the log cannot be opened at start the worker is not started: it would be silent loss.
func TestLogpipeRefusesToStartWithoutALog(t *testing.T) {
	dir := t.TempDir()
	// --path dir/worker.log, where dir/worker.log is a directory, so it cannot be opened.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "worker.log"), 0o700))
	marker := filepath.Join(dir, "child-ran")
	r := startLogpipe(t, dir, 20000, 3, 4096, nil, "sh", "-c", "touch "+marker)
	assert.Equal(t, 1, r.exitCode(t))
	assert.Contains(t, r.errOut.String(), "not starting the worker")
	_, err := os.Stat(marker)
	assert.True(t, os.IsNotExist(err), "the child never ran")
}

// A rotation that fails (the directory became read-only) is reported on stderr and writes
// continue to the current file, but only up to twice the target: there the wrapper stops the
// worker and exits 74 rather than let the active log grow without bound. Every byte written
// before that is present, in order.
func TestLogpipeRotationFailureIsBoundedByTheDegradedLimit(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	require.NoError(t, os.MkdirAll(logs, 0o700))
	t.Cleanup(func() { _ = os.Chmod(logs, 0o700) })
	child := childScript(t, dir)
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	r := startLogpipe(t, logs, 20000, 3, 4096, []string{"--kill-timeout", "2"}, "sh", "-c",
		fmt.Sprintf("chmod 0500 %q; %q %q 5000 '' 5 wait 0", logs, py, child))
	assert.Equal(t, 74, r.exitCode(t), r.errOut.String())
	require.NoError(t, os.Chmod(logs, 0o700))
	assert.Contains(t, r.errOut.String(), "could not rotate worker.log")
	assert.Contains(t, r.errOut.String(), "the next write would pass 2x its target; rotation has been failing")
	assert.Contains(t, r.errOut.String(), "stopping the worker (its running tasks end) and exiting 74")
	set := reassemble(t, logs)
	worker, sizes, rotated := set.worker, set.sizes, set.rotated
	assert.Empty(t, rotated)
	assert.LessOrEqual(t, sizes["worker.log"], 2*20000, "never past the degraded limit (a line here is shorter than a chunk)")
	assert.Greater(t, sizes["worker.log"], 20000, "writes went on past the target while rotation failed")
	assert.True(t, bytes.HasPrefix(expectedOutput(5000, 0, ""), worker), "a prefix of the worker's output, in order, nothing reordered or duplicated")
}

// harness runs a Python script that imports logpipe.py and drives Log and drain in-process,
// with os.write scripted for the log's descriptor (ok, partial:N, fail) and a fake clock so
// the stall bound elapses without waiting. It returns the script's stdout, stderr and exit code.
func harness(t *testing.T, body string) (stdout, stderr string, code int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the worker scripts run on the macOS worker only")
	}
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	dir, err := filepath.Abs(".")
	require.NoError(t, err)
	script := `import errno, os, sys
sys.path.insert(0, sys.argv[1])
import logpipe

LOG_FDS = set()
real_open = logpipe.Log._open
def tracked_open(self):
    real_open(self)
    LOG_FDS.add(self.fd)
logpipe.Log._open = tracked_open

ACTIONS = []            # per call on a log descriptor: "ok", "partial:N", "fail"; then "ok" forever
real_write = os.write
def scripted_write(fd, data):
    if fd in LOG_FDS and ACTIONS:
        action = ACTIONS.pop(0)
        if action == "fail":
            raise OSError(errno.ENOSPC, "No space left on device")
        if action.startswith("partial:"):
            n = int(action.split(":")[1])
            return real_write(fd, bytes(data)[:n])
    return real_write(fd, data)
os.write = scripted_write

CLOCK = [0.0]
SLEPT = []
def fake_sleep(s):
    SLEPT.append(s); CLOCK[0] += s
logpipe.time.monotonic = lambda: CLOCK[0]

def run_drain(log, payload, chunk=4096):
    r, w = os.pipe()
    os.write(w, payload); os.close(w)
    try:
        logpipe.drain(r, log, chunk)
    finally:
        os.close(r)

def new_log(path, max_bytes=1 << 20, backups=3, stall=5.0):
    log = logpipe.Log(path, max_bytes, backups, stall, logpipe.Diag(), sleep=fake_sleep)
    log.open_at_start()
    return log

def worker_bytes(path):
    out = []
    for line in open(path, "rb").read().split(b"\n"):
        if line.startswith(b"time=") and b'msg="txe-logpipe: ' in line:
            continue
        out.append(line)
    return b"\n".join(out)
` + body
	path := filepath.Join(t.TempDir(), "harness.py")
	require.NoError(t, os.WriteFile(path, []byte(script), 0o600))
	cmd := exec.Command(py, "-I", path, dir)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	code = 0
	if err != nil {
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr, errOut.String())
		code = exitErr.ExitCode()
	}
	return out.String(), errOut.String(), code
}

// A write that fails is retried from the offset already written: a partial write is not
// repeated, a transient failure costs a retry and nothing else, and the bytes come out exact.
func TestLogpipeRetriesWritesFromTheOffsetWithoutDuplication(t *testing.T) {
	stdout, stderr, code := harness(t, `
import tempfile
d = tempfile.mkdtemp()
path = os.path.join(d, "worker.log")
log = new_log(path)
payload = b"".join(b"line %05d some worker output text\n" % i for i in range(300)) + b"tail"
ACTIONS[:] = ["partial:7", "fail", "fail", "partial:100", "fail", "ok"]
run_drain(log, payload)
log.finish()
got = worker_bytes(path)
print("exact", got == payload, len(got), len(payload))
print("retries", log.stats["write_retries"], "slept", SLEPT)
`)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "exact True")
	assert.Contains(t, stdout, "retries 3 slept [1.0, 1.0, 1.0]")
	assert.Contains(t, stderr, "could not write")
	assert.Contains(t, stderr, "works again after")
}

// Writes failing for longer than the stall bound end in FailStop: the bytes persisted before
// the failure are intact, the unwritten remainder is named, and nothing is written twice.
func TestLogpipeFailStopsAfterTheWriteStallBound(t *testing.T) {
	stdout, stderr, code := harness(t, `
import tempfile
d = tempfile.mkdtemp()
path = os.path.join(d, "worker.log")
log = new_log(path, stall=5.0)
before = b"".join(b"line %05d some worker output text\n" % i for i in range(100))
run_drain(log, before)
ACTIONS[:] = ["fail"] * 1000
try:
    run_drain(log, b"after the disk filled\n")
    print("no FailStop")
except logpipe.FailStop as e:
    print("FailStop:", e)
log.finish()
got = worker_bytes(path)
print("persisted intact", got == before)
print("slept", len(SLEPT), "x", SLEPT[0] if SLEPT else None, "clock", CLOCK[0])
`)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "FailStop: could not write to worker.log for 5s (OSError: [Errno 28] No space left on device); 22 bytes unwritten")
	assert.Contains(t, stdout, "persisted intact True")
	assert.Contains(t, stdout, "slept 5 x 1.0 clock 5.0", "retried once a second for the stall bound, then stopped")
	assert.NotContains(t, stdout, "no FailStop")
}

// End to end: with the log unwritable past the stall bound, main() stops the worker with
// SIGTERM, exits 74 and says so; the worker's lines written before the failure are kept.
func TestLogpipeMainFailStopsAndStopsTheWorker(t *testing.T) {
	stdout, stderr, code := harness(t, `
import subprocess, sys, tempfile
d = tempfile.mkdtemp()
path = os.path.join(d, "worker.log")
child = os.path.join(d, "child.py")
open(child, "w").write("import signal, sys, time\n"
    "signal.signal(signal.SIGTERM, lambda s, f: sys.exit(3))\n"
    "for i in range(50): print('line %05d some worker output text' % i)\n"
    "sys.stdout.flush(); time.sleep(0.5)\n"  # the lines reach the log before the trigger
    "print('ready', file=sys.stderr); sys.stderr.flush()\n"
    "time.sleep(60)\n")
# Fail every write once the child has written its lines: the 'ready' line is the trigger.
real_scripted = os.write
def write_until_ready(fd, data):
    if fd in LOG_FDS and b"ready" in bytes(data):
        ACTIONS[:] = ["fail"] * 100000
    return real_scripted(fd, data)
os.write = write_until_ready
logpipe.time.sleep = fake_sleep  # the retry sleeps; kill_after still polls in real time
code = logpipe.main(["--path", path, "--max-bytes", "1048576", "--backups", "2", "--chunk-bytes", "4096",
                     "--write-stall-seconds", "3", "--kill-timeout", "5", "--", sys.executable, child])
print("exit", code)
print("lines kept", worker_bytes(path).count(b"\n"))
`)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "exit 74")
	assert.Contains(t, stdout, "lines kept 50")
	assert.Contains(t, stderr, "could not write to worker.log for 3s")
	assert.Contains(t, stderr, "stopping the worker (its running tasks end) and exiting 74; bytes not yet written are lost")
}

// SIGTERM is forwarded; the wrapper keeps draining, then exits with the worker's code.
// A worker that ignores it is killed after --kill-timeout and the wrapper exits 137.
func TestLogpipeForwardsSignalsWithABoundedWait(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	r := startLogpipe(t, logs, 20000, 3, 4096, nil, "python3", childScript(t, dir), "5", "", "3", "wait", "0")
	waitForLog(t, logs, "ready")
	require.NoError(t, r.cmd.Process.Signal(syscall.SIGTERM))
	assert.Equal(t, 3, r.exitCode(t))
	worker := reassemble(t, logs).worker
	assert.True(t, bytes.HasSuffix(worker, []byte(fmt.Sprintf("signal %d\n", syscall.SIGTERM))), string(worker))
	assert.Contains(t, r.errOut.String(), "forwarding signal 15 to the worker")

	logs2 := filepath.Join(dir, "logs2") // a fresh log, so "ready" is this child's, after its handlers are installed
	r = startLogpipe(t, logs2, 20000, 3, 4096, []string{"--kill-timeout", "1"}, "python3", childScript(t, dir), "5", "", "3", "stubborn", "0")
	waitForLog(t, logs2, "ready")
	start := time.Now()
	require.NoError(t, r.cmd.Process.Signal(syscall.SIGTERM))
	assert.Equal(t, 137, r.exitCode(t), "128 + SIGKILL")
	assert.Less(t, time.Since(start), 10*time.Second, "bounded by --kill-timeout, not by the worker")
	assert.Contains(t, r.errOut.String(), "sending SIGKILL")
}

// waitForLog waits until the active log holds text (the child's stderr goes through the
// wrapper into the log, like the worker's).
func waitForLog(t *testing.T, logs, text string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join(logs, "worker.log")); err == nil && strings.Contains(string(b), text) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the log never showed %q", text)
}
