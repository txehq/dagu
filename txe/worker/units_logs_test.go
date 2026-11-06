// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The names logpipe.py leaves beside a log: rotated files, and the one archive of the log an
// earlier unit appended to.
var (
	unitRotated = regexp.MustCompile(`^(tunnel|worker)\.log\.\d{8}T\d{12}Z(-\d+)?(\.gz)?$`)
	unitLegacy  = regexp.MustCompile(`^(tunnel|worker)\.legacy-\d{8}T\d{12}Z(-\d+)?\.log$`)
)

// unitHome is a TXE home as install-systemd.sh leaves it, in a path with a space, a % and a $,
// with stand-ins for the worker and kubectl, and the units units.py writes for it.
type unitHome struct {
	base, home     string
	tunnel, worker unitFile
}

// newUnitHome writes the stand-ins and the units. Each stand-in records its arguments, and the
// worker its DAGU_HOME, in a file under base, then runs `body` (shell).
func newUnitHome(t *testing.T, tunnelUnit, workerUnit, unitsDir, kubectlBody, workerBody string) unitHome {
	t.Helper()
	agentsScript(t)
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	base := t.TempDir()
	h := unitHome{base: base, home: filepath.Join(base, "txe 100% $HOME")}
	for _, d := range []string{"bin", "logs", "tunnel", "worker-home", "kube ctl"} {
		require.NoError(t, os.MkdirAll(filepath.Join(h.home, d), 0o700))
	}
	wrapper, err := os.ReadFile("logpipe.py")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(h.home, "bin", "logpipe.py"), wrapper, 0o600))
	record := `printf '%s\n' "$@" > "$(dirname "$0")/../../`
	require.NoError(t, os.WriteFile(filepath.Join(h.home, "bin", "dagu"),
		[]byte("#!/bin/sh\n"+record+`worker.args"`+"\n"+`printf '%s\n' "$DAGU_HOME" > "$(dirname "$0")/../../worker.home"`+"\n"+workerBody), 0o700))
	kubectl := filepath.Join(h.home, "kube ctl", "kubectl")
	require.NoError(t, os.WriteFile(kubectl, []byte("#!/bin/sh\n"+record+`tunnel.args"`+"\n"+kubectlBody), 0o700))

	script, err := filepath.Abs("units.py")
	require.NoError(t, err)
	_, stderr, err := python(t, script, "write", unitsDir, h.home, kubectl, agentsMachine, agentsOwner,
		"/usr/bin:/bin", tunnelUnit, workerUnit, "dagu", "svc/dagu", "18080", "50055", "", py)
	require.NoError(t, err, stderr)
	h.tunnel = readUnit(t, filepath.Join(unitsDir, tunnelUnit))
	h.worker = readUnit(t, filepath.Join(unitsDir, workerUnit))
	return h
}

// run executes a unit's ExecStart= with its Environment=, as systemd would, and returns the
// exit code and what the unit's own stream (the journal, under systemd) received.
func (h unitHome) run(t *testing.T, unit unitFile) (code int, own string) {
	t.Helper()
	cmd := exec.Command(unit.argv[0], unit.argv[1:]...)
	for k, v := range unit.environment {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return exit.ExitCode(), out.String()
	}
	require.NoError(t, err, out.String())
	return 0, out.String()
}

func (h unitHome) lines(t *testing.T, name string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.base, name))
	require.NoError(t, err)
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// logNames returns the names in the home's logs directory that match pattern.
func (h unitHome) logNames(t *testing.T, pattern *regexp.Regexp, stem string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(h.home, "logs"))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		if m := pattern.FindStringSubmatch(e.Name()); m != nil && m[1] == stem {
			names = append(names, e.Name())
		}
	}
	return names
}

// The worker unit's own command line, read and run as systemd runs it, from a home whose path
// has a space, a % and a $: the worker gets exactly its arguments and its DAGU_HOME, its output
// lands in logs/worker.log behind the wrapper's marker, the log an earlier unit appended to is
// archived whole under a name nothing prunes, and the worker's exit code is the unit's.
func TestUnitRunsTheWorkerUnderTheLogWrapper(t *testing.T) {
	h := newUnitHome(t, "txe-dagu-tunnel.service", "txe-dagu-worker.service", filepath.Join(t.TempDir(), "user"),
		"exit 0\n", `echo 'time=2026-11-06T00:00:00Z level=INFO msg="Starting worker"'`+"\n"+`echo 'to stderr' >&2`+"\nexit 7\n")
	// What the unit before TXE-5408 left: systemd appended the worker's output here itself.
	earlier := []byte("line systemd appended 1\nline systemd appended 2\n")
	log := filepath.Join(h.home, "logs", "worker.log")
	require.NoError(t, os.WriteFile(log, earlier, 0o600))

	code, own := h.run(t, h.worker)
	assert.Equal(t, 7, code, "the worker's exit code is the unit's, so Restart= sees it")
	assert.Empty(t, own, "the unit's own stream gets nothing on the normal path")
	assert.Equal(t, []string{"worker", "--worker.id", agentsMachine,
		"--worker.labels", "txe.machine=" + agentsMachine + ",txe.owner=" + agentsOwner,
		"--worker.coordinators", "127.0.0.1:50055"}, h.lines(t, "worker.args"))
	assert.Equal(t, []string{h.home + "/worker-home"}, h.lines(t, "worker.home"))

	archives := h.logNames(t, unitLegacy, "worker")
	require.Len(t, archives, 1)
	got, err := os.ReadFile(filepath.Join(h.home, "logs", archives[0]))
	require.NoError(t, err)
	assert.Equal(t, earlier, got, "archived whole")
	active, err := os.ReadFile(log)
	require.NoError(t, err)
	lines := strings.Split(string(active), "\n")
	assert.Contains(t, lines[0], `msg="txe-logpipe: opened worker.log" archived=`+archives[0])
	assert.Equal(t, []string{`time=2026-11-06T00:00:00Z level=INFO msg="Starting worker"`, "to stderr", ""}, lines[1:],
		"stdout and stderr, in order, and nothing of the earlier log")

	// A restart appends to the wrapper's own file: no second archive.
	code, _ = h.run(t, h.worker)
	assert.Equal(t, 7, code)
	assert.Len(t, h.logNames(t, unitLegacy, "worker"), 1)
	active, err = os.ReadFile(log)
	require.NoError(t, err)
	assert.Equal(t, 2, strings.Count(string(active), `msg="Starting worker"`))
	assert.Equal(t, 1, strings.Count(string(active), "txe-logpipe: opened"))
}

// The tunnel unit's own command line under seven logs' worth of kubectl output: logs/tunnel.log
// stays within its 8 MiB, the newest five rotated files are kept, compressed, and the older
// ones are deleted, while the archive of the earlier unit's log is still there, untouched.
func TestUnitBoundsTheTunnelLog(t *testing.T) {
	const limit, backups = 8 << 20, 5
	line := `E1106 00:00:00.000000   12345 portforward.go:413] "Unhandled Error" err="an error occurred forwarding 18080 -> 8080: a stand-in"`
	h := newUnitHome(t, "txe-dagu-tunnel.service", "txe-dagu-worker.service", filepath.Join(t.TempDir(), "user"),
		"yes '"+line+"' | head -c 60000000\necho\necho 'the last line'\n", "exit 0\n")
	earlier := bytes.Repeat([]byte("line systemd appended\n"), 1000)
	log := filepath.Join(h.home, "logs", "tunnel.log")
	require.NoError(t, os.WriteFile(log, earlier, 0o600))

	code, own := h.run(t, h.tunnel)
	require.Equal(t, 0, code, own)
	assert.Empty(t, own)
	assert.Equal(t, []string{"--kubeconfig", h.home + "/tunnel/kubeconfig", "-n", "dagu",
		"port-forward", "--address", "127.0.0.1", "svc/dagu", "18080:8080", "50055:50055"}, h.lines(t, "tunnel.args"))

	st, err := os.Stat(log)
	require.NoError(t, err)
	assert.LessOrEqual(t, st.Size(), int64(limit+len(line)+1), "the active log is within its limit, give or take one line")
	active, err := os.ReadFile(log)
	require.NoError(t, err)
	assert.True(t, bytes.HasSuffix(active, []byte("\nthe last line\n")), "the newest output is kept")
	rotated := h.logNames(t, unitRotated, "tunnel")
	assert.Len(t, rotated, backups, "60 MB is seven files; only the newest %d rotated ones remain: %v", backups, rotated)
	for _, name := range rotated {
		assert.True(t, strings.HasSuffix(name, ".gz"), "rotated files are compressed: %s", name)
	}
	archives := h.logNames(t, unitLegacy, "tunnel")
	require.Len(t, archives, 1)
	got, err := os.ReadFile(filepath.Join(h.home, "logs", archives[0]))
	require.NoError(t, err)
	assert.Equal(t, earlier, got, "the earlier log outlives every rotation")
}
