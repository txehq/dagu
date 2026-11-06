// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package worker_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lifecycleEnv enables TestSystemdLifecycle. The test installs and starts two units in this
// user's own systemd manager, so it runs only where that is asked for: a disposable machine.
const lifecycleEnv = "TXE_DAGU_SYSTEMD_LIFECYCLE"

// lifecycleActor stands in for the worker, a step it runs, and kubectl. Each records its start
// and every signal it receives in <role>.events beside this script.
//
//	worker  starts one step in its own process group, as the worker's command executor does;
//	        on a signal it sends that step SIGTERM once, waits for it, and exits 0
//	step    on a signal cleans up for half a second and exits; in the mode "stubborn-step" it
//	        ignores the signal, keeps the wrapper's pipe open and keeps writing
//	tunnel  has no handler, as kubectl port-forward has none for SIGTERM; with tunnel.flood
//	        present it first writes seven logs' worth of output
const lifecycleActor = `import os, signal, subprocess, sys, time
base = os.path.dirname(os.path.abspath(__file__))
role = sys.argv[1]
def note(text):
    with open(os.path.join(base, role + ".events"), "a") as f:
        f.write(text + "\n")
def mode():
    try:
        with open(os.path.join(base, "mode")) as f:
            return f.read().strip()
    except OSError:
        return ""
got = []
def on(sig, _frame):
    got.append(sig)
    note("signal " + signal.Signals(sig).name)
if role != "tunnel":
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, on)
note("start %d" % os.getpid())
if role == "tunnel":
    flood = os.path.join(base, "tunnel.flood")
    if os.path.exists(flood):
        os.rename(flood, flood + "ed")
        line = b'E1106 00:00:00.000000   12345 portforward.go:413] "Unhandled Error" err="an error occurred forwarding 18080 -> 8080: a stand-in"\n'
        block = line * 500
        for _ in range(60000000 // len(block)):
            os.write(1, block)
        os.write(1, b"the last line of the flood\n")
        note("flooded")
    print("Forwarding from 127.0.0.1:18080 -> 8080 (a stand-in: it listens on nothing)", flush=True)
    while True:
        time.sleep(3600)
if role == "worker":
    print('time=2026-11-06T00:00:00Z level=INFO msg="Starting worker"', flush=True)
    step = subprocess.Popen([sys.executable, __file__, "step"], preexec_fn=os.setpgrp)
    while not got:
        time.sleep(0.02)
    print("worker: stopping", flush=True)
    step.send_signal(signal.SIGTERM)
    if mode() != "stubborn-step":
        step.wait()
        print("worker: the step exited %d" % step.returncode, flush=True)
    print("worker: stopped", flush=True)
    sys.exit(0)
print("step: running", flush=True)
while not got:
    time.sleep(0.02)
if mode() == "stubborn-step":
    while True:
        print("step: still here", flush=True)
        time.sleep(0.2)
time.sleep(0.5)
print("step: cleaned up", flush=True)
note("cleaned up")
`

// The names a unit may leave in logs/, as internal/txe/continuity classifies a machine home's
// (machineHomeRules): the units must add no other, so a Linux home needs no rule of its own.
var lifecycleLogNames = []*regexp.Regexp{
	regexp.MustCompile(`^(tunnel|worker)\.log$`),
	regexp.MustCompile(`^(tunnel|worker)\.log\.[0-9]{8}T[0-9]{12}Z(-[0-9]+)?(\.gz|\.gz\.tmp)?$`),
	regexp.MustCompile(`^(tunnel|worker)\.legacy-[0-9]{8}T[0-9]{12}Z(-[0-9]+)?\.log$`),
	regexp.MustCompile(`^(tunnel|worker)\.logpipe\.log(\.1)?$`),
}

type lifecycle struct {
	t              *testing.T
	h              unitHome
	tunnel, worker string
}

func (l lifecycle) systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (l lifecycle) must(args ...string) string {
	l.t.Helper()
	out, err := l.systemctl(args...)
	require.NoError(l.t, err, "systemctl --user %s: %s", strings.Join(args, " "), out)
	return out
}

func (l lifecycle) show(unit, property string) string {
	l.t.Helper()
	return l.must("show", "-p", property, "--value", unit)
}

// state is systemctl's word for the unit; is-active exits non-zero for every state but active.
func (l lifecycle) state(unit string) string {
	out, _ := l.systemctl("is-active", unit)
	return out
}

func (l lifecycle) wait(limit time.Duration, what string, ok func() bool) {
	l.t.Helper()
	deadline := time.Now().Add(limit)
	for !ok() {
		require.True(l.t, time.Now().Before(deadline), "not within %s: %s", limit, what)
		time.Sleep(100 * time.Millisecond)
	}
}

// events returns a stand-in's recorded lines; none yet is an empty list.
func (l lifecycle) events(role string) []string {
	data, err := os.ReadFile(filepath.Join(l.h.base, role+".events"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// count is how many of a stand-in's events are exactly `event`.
func (l lifecycle) count(role, event string) int {
	n := 0
	for _, e := range l.events(role) {
		if e == event {
			n++
		}
	}
	return n
}

// pids are the process ids of every start a stand-in recorded, oldest first.
func (l lifecycle) pids(role string) []int {
	var pids []int
	for _, e := range l.events(role) {
		if rest, ok := strings.CutPrefix(e, "start "); ok {
			pid, err := strconv.Atoi(rest)
			require.NoError(l.t, err)
			pids = append(pids, pid)
		}
	}
	return pids
}

func gone(pid int) bool { return syscall.Kill(pid, 0) == syscall.ESRCH }

// cgroup returns the process ids in the unit's control group.
func (l lifecycle) cgroup(unit string) []int {
	l.t.Helper()
	data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", l.show(unit, "ControlGroup"), "cgroup.procs"))
	require.NoError(l.t, err)
	var pids []int
	for f := range strings.FieldsSeq(string(data)) {
		pid, err := strconv.Atoi(f)
		require.NoError(l.t, err)
		pids = append(pids, pid)
	}
	return pids
}

func (l lifecycle) log(name string) string {
	l.t.Helper()
	data, err := os.ReadFile(filepath.Join(l.h.home, "logs", name))
	require.NoError(l.t, err)
	return string(data)
}

// The units units.py writes, under a real systemd user manager, from a home whose path has a
// space, a % and a $, with stand-ins for the worker, a step and kubectl: what bounding the logs
// must not change about starting, stopping and restarting, and what it must bound.
//
// It installs and starts units, so it runs only with TXE_DAGU_SYSTEMD_LIFECYCLE=1, in a
// disposable machine whose user has a systemd manager (XDG_RUNTIME_DIR set). The units have
// names of their own and live in the manager's runtime directory; they are stopped and removed
// at the end. The stand-in tunnel listens on nothing.
func TestSystemdLifecycle(t *testing.T) {
	if os.Getenv(lifecycleEnv) != "1" {
		t.Skipf("installs and starts systemd user units: set %s=1 in a disposable machine to run it", lifecycleEnv)
	}
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	require.NotEmpty(t, runtime, "XDG_RUNTIME_DIR names the user's systemd manager")
	unitsDir := filepath.Join(runtime, "systemd", "user")
	require.NoError(t, os.MkdirAll(unitsDir, 0o700))
	l := lifecycle{t: t,
		tunnel: fmt.Sprintf("txe-dagu-lifecycle-%d-tunnel.service", os.Getpid()),
		worker: fmt.Sprintf("txe-dagu-lifecycle-%d-worker.service", os.Getpid())}
	out, err := l.systemctl("show-environment")
	require.NoError(t, err, "no systemd user manager answers: %s", out)
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	stand := func(role string) string {
		return fmt.Sprintf(`exec '%s' "$(dirname "$0")/../../actor.py" %s`+"\n", py, role)
	}
	l.h = newUnitHome(t, l.tunnel, l.worker, unitsDir, stand("tunnel"), stand("worker"))
	require.NoError(t, os.WriteFile(filepath.Join(l.h.base, "actor.py"), []byte(lifecycleActor), 0o600))
	t.Cleanup(func() {
		for _, unit := range []string{l.worker, l.tunnel} {
			_, _ = l.systemctl("stop", unit)
			_ = os.Remove(filepath.Join(unitsDir, unit))
			_, _ = l.systemctl("reset-failed", unit)
		}
		_, _ = l.systemctl("daemon-reload")
	})
	// What the units before TXE-5408 left: systemd appended each program's output here itself.
	earlier := map[string][]byte{
		"worker.log": []byte("worker line systemd appended 1\nworker line systemd appended 2\n"),
		"tunnel.log": bytes.Repeat([]byte("tunnel line systemd appended\n"), 1000),
	}
	for name, data := range earlier {
		require.NoError(t, os.WriteFile(filepath.Join(l.h.home, "logs", name), data, 0o600))
	}
	l.must("daemon-reload")

	// systemd reads the units as written.
	for _, unit := range []string{l.tunnel, l.worker} {
		assert.Equal(t, "mixed", l.show(unit, "KillMode"))
		assert.Equal(t, "1min 45s", l.show(unit, "TimeoutStopUSec"))
		assert.Equal(t, "journal", l.show(unit, "StandardOutput"))
		assert.Equal(t, "journal", l.show(unit, "StandardError"))
		assert.Equal(t, strings.TrimSuffix(unit, ".service"), l.show(unit, "SyslogIdentifier"))
	}

	t.Log("stage: the worker starts under the wrapper")
	{
		l.must("start", l.worker)
		l.wait(15*time.Second, "the worker and its step start", func() bool {
			return len(l.pids("worker")) == 1 && len(l.pids("step")) == 1
		})
		assert.Equal(t, "active", l.state(l.worker))
		assert.Equal(t, []string{"worker", "--worker.id", agentsMachine,
			"--worker.labels", "txe.machine=" + agentsMachine + ",txe.owner=" + agentsOwner,
			"--worker.coordinators", "127.0.0.1:50055"}, l.h.lines(t, "worker.args"), "systemd passed the arguments as written")
		assert.Equal(t, []string{l.h.home + "/worker-home"}, l.h.lines(t, "worker.home"))
		// The wrapper is the unit's main process; the worker and its step, in a process group
		// of its own, are in the unit's control group, which is what systemd cleans up.
		group := l.cgroup(l.worker)
		main, err := strconv.Atoi(l.show(l.worker, "MainPID"))
		require.NoError(t, err)
		assert.Contains(t, group, main)
		assert.Contains(t, group, l.pids("worker")[0])
		assert.Contains(t, group, l.pids("step")[0])
		assert.NotEqual(t, main, l.pids("worker")[0])

		archives := l.h.logNames(t, unitLegacy, "worker")
		require.Len(t, archives, 1)
		assert.Equal(t, string(earlier["worker.log"]), l.log(archives[0]), "the earlier unit's log, archived whole")
		l.wait(5*time.Second, "the step's first line reaches the log", func() bool {
			return strings.Contains(l.log("worker.log"), "step: running\n")
		})
		lines := strings.Split(l.log("worker.log"), "\n")
		assert.Contains(t, lines[0], `msg="txe-logpipe: opened worker.log" archived=`+archives[0])
		assert.Equal(t, `time=2026-11-06T00:00:00Z level=INFO msg="Starting worker"`, lines[1])
	}

	t.Log("stage: the tunnel log stays bounded while the unit runs")
	{
		const limit, backups = 8 << 20, 5
		require.NoError(t, os.WriteFile(filepath.Join(l.h.base, "tunnel.flood"), nil, 0o600))
		l.must("start", l.tunnel)
		l.wait(60*time.Second, "the flood is written", func() bool { return l.count("tunnel", "flooded") == 1 })
		l.wait(60*time.Second, "the newest five rotated files remain, compressed", func() bool {
			rotated := l.h.logNames(t, unitRotated, "tunnel")
			for _, name := range rotated {
				if !strings.HasSuffix(name, ".gz") {
					return false
				}
			}
			return len(rotated) == backups
		})
		st, err := os.Stat(filepath.Join(l.h.home, "logs", "tunnel.log"))
		require.NoError(t, err)
		assert.LessOrEqual(t, st.Size(), int64(limit+200), "the active log is within its limit, give or take one line")
		assert.Contains(t, l.log("tunnel.log"), "\nthe last line of the flood\n")
		archives := l.h.logNames(t, unitLegacy, "tunnel")
		require.Len(t, archives, 1)
		assert.Equal(t, string(earlier["tunnel.log"]), l.log(archives[0]), "the earlier log outlives every rotation")
		assert.Equal(t, "active", l.state(l.tunnel))
		assert.Equal(t, "0", l.show(l.tunnel, "NRestarts"))
	}

	t.Log("stage: a stop reaches the worker and its step once each")
	{
		worker, step := l.pids("worker")[0], l.pids("step")[0]
		l.must("stop", l.worker)
		assert.Equal(t, "inactive", l.state(l.worker))
		assert.Equal(t, "success", l.show(l.worker, "Result"))
		assert.Equal(t, 1, l.count("worker", "signal SIGTERM"), "the worker's events: %v", l.events("worker"))
		assert.Equal(t, 1, l.count("step", "signal SIGTERM"), "the step's events: %v", l.events("step"))
		assert.Equal(t, 1, l.count("step", "cleaned up"), "the step had the time to clean up")
		assert.True(t, gone(worker) && gone(step))
		// What the worker and its step wrote while stopping was drained into the log, in order.
		log := l.log("worker.log")
		at := -1
		for _, line := range []string{"worker: stopping\n", "step: cleaned up\n", "worker: the step exited 0\n", "worker: stopped\n"} {
			next := strings.Index(log, line)
			assert.Greater(t, next, at, "%q comes in order in the log", line)
			at = next
		}
	}

	t.Log("stage: a stopped tunnel is inactive, not failed")
	{
		tunnel := l.pids("tunnel")[0]
		l.must("stop", l.tunnel)
		// SIGTERM ends kubectl; the wrapper reports that as exit 143, which the unit counts as a stop.
		assert.Equal(t, "inactive", l.state(l.tunnel))
		assert.Equal(t, "success", l.show(l.tunnel, "Result"))
		assert.True(t, gone(tunnel))
		assert.Contains(t, l.log("tunnel.logpipe.log"), "forwarding signal 15 to the worker")
	}

	t.Log("stage: a worker that dies is restarted and its orphan is killed")
	{
		l.must("start", l.worker)
		l.wait(15*time.Second, "the second worker and step start", func() bool {
			return len(l.pids("worker")) == 2 && len(l.pids("step")) == 2
		})
		worker, step := l.pids("worker")[1], l.pids("step")[1]
		require.NoError(t, syscall.Kill(worker, syscall.SIGKILL))
		// The step still holds the wrapper's pipe: the wrapper drains for its 5 s grace, exits
		// with the worker's 137, systemd kills the step and starts the unit again 5 s later.
		l.wait(30*time.Second, "systemd restarts the unit", func() bool {
			return len(l.pids("worker")) == 3 && len(l.pids("step")) == 3
		})
		assert.Equal(t, "1", l.show(l.worker, "NRestarts"))
		assert.True(t, gone(step), "the orphaned step was killed with the control group")
		assert.Equal(t, 1, l.count("step", "signal SIGTERM"), "and was never signalled: only the first stop was")
		l.wait(5*time.Second, "the unit is active again", func() bool { return l.state(l.worker) == "active" })
		// The restarted unit appends to the wrapper's own log: one opening marker, one archive.
		assert.Equal(t, 1, strings.Count(l.log("worker.log"), "txe-logpipe: opened"))
		assert.Equal(t, 3, strings.Count(l.log("worker.log"), `msg="Starting worker"`))
		assert.Len(t, l.h.logNames(t, unitLegacy, "worker"), 1)
	}

	t.Log("stage: a wrapper that is killed takes its worker with it")
	{
		worker, step := l.pids("worker")[2], l.pids("step")[2]
		main, err := strconv.Atoi(l.show(l.worker, "MainPID"))
		require.NoError(t, err)
		require.NoError(t, syscall.Kill(main, syscall.SIGKILL))
		l.wait(5*time.Second, "systemd kills the worker and its step", func() bool { return gone(worker) && gone(step) })
		l.wait(30*time.Second, "systemd restarts the unit", func() bool {
			return len(l.pids("worker")) == 4 && len(l.pids("step")) == 4
		})
		assert.Equal(t, "2", l.show(l.worker, "NRestarts"))
		assert.Equal(t, 4, strings.Count(l.log("worker.log"), `msg="Starting worker"`), "the new worker's output is logged")
	}

	t.Log("stage: a step that ignores the stop does not hold the unit")
	{
		require.NoError(t, os.WriteFile(filepath.Join(l.h.base, "mode"), []byte("stubborn-step\n"), 0o600))
		worker, step := l.pids("worker")[3], l.pids("step")[3]
		before := l.count("step", "signal SIGTERM")
		started := time.Now()
		l.must("stop", l.worker)
		took := time.Since(started)
		// The worker exits at once; the step keeps the pipe and keeps writing; the wrapper
		// drains for its 5 s grace and exits, and systemd kills the step: far inside the
		// unit's 105 s.
		assert.Greater(t, took, 4*time.Second)
		assert.Less(t, took, 20*time.Second)
		assert.Equal(t, "inactive", l.state(l.worker))
		assert.Equal(t, "success", l.show(l.worker, "Result"))
		assert.True(t, gone(worker) && gone(step))
		assert.Equal(t, before+1, l.count("step", "signal SIGTERM"), "one stop signal, from the worker")
		assert.Contains(t, l.log("worker.log"), "step: still here\n", "what it wrote meanwhile was logged")
	}

	// Nothing the units wrote is outside what continuity already classifies in a machine home,
	// and the worker's own output is in its log, never in the journal.
	entries, err := os.ReadDir(filepath.Join(l.h.home, "logs"))
	require.NoError(t, err)
	for _, e := range entries {
		known := false
		for _, pattern := range lifecycleLogNames {
			known = known || pattern.MatchString(e.Name())
		}
		assert.True(t, known, "an unclassified name in logs/: %s", e.Name())
	}
	journal, err := exec.Command("journalctl", "--user", "-u", l.worker, "-o", "cat", "--no-pager").CombinedOutput()
	if err != nil {
		t.Logf("the user journal is not readable here (%v); its content is not checked", err)
		return
	}
	assert.NotContains(t, string(journal), `msg="Starting worker"`)
	assert.NotContains(t, string(journal), "step: running")
}
