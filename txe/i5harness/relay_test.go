// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package i5harness_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// python is the interpreter the harness runs its tools with: Apple's
// /usr/bin/python3 (3.9) where it exists, so the tests hold for that version.
func python(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat("/usr/bin/python3"); err == nil {
		return "/usr/bin/python3"
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	return py
}

// tool runs one of the harness's Python tools and returns its combined output
// and exit code.
func tool(t *testing.T, name string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(python(t), append([]string{"-I", name}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exit *exec.ExitError
		require.ErrorAs(t, err, &exit, "%s: %s", name, out)
		return string(out), exit.ExitCode()
	}
	return string(out), 0
}

// echoServer answers every line it reads with the same line, on network/addr.
func echoServer(t *testing.T, network, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln
}

// shortDir is a fresh directory short enough for a Unix socket path (104 bytes
// on macOS); t.TempDir under $TMPDIR is not.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "i5h")
	require.NoError(t, err)
	t.Cleanup(func() {
		// rig.sh down makes evidence read-only; make it removable again.
		_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(p, 0o755)
			}
			return nil
		})
		_ = os.RemoveAll(dir)
	})
	return dir
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

type relay struct {
	ctl, log string
	cmd      *exec.Cmd
}

// startRelay runs relay.py with one listener on 127.0.0.1:<free port> in front of target.
func startRelay(t *testing.T, target string) (*relay, string) {
	t.Helper()
	dir := shortDir(t)
	r := &relay{ctl: filepath.Join(dir, "relay.sock"), log: filepath.Join(dir, "relay.jsonl")}
	listen := "127.0.0.1:" + strconv.Itoa(freePort(t))
	r.cmd = exec.Command(python(t), "-I", "relay.py", "serve", "--listen", listen+"="+target,
		"--control", r.ctl, "--log", r.log)
	r.cmd.Stderr = os.Stderr
	require.NoError(t, r.cmd.Start())
	t.Cleanup(func() {
		_ = r.cmd.Process.Signal(syscall.SIGTERM)
		_ = r.cmd.Wait()
	})
	require.Eventually(t, func() bool { _, err := os.Stat(r.ctl); return err == nil }, 10*time.Second, 50*time.Millisecond)
	return r, listen
}

func (r *relay) do(t *testing.T, word string) map[string]any {
	t.Helper()
	out, code := tool(t, "relay.py", "ctl", r.ctl, word)
	require.Equal(t, 0, code, out)
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &m), out)
	return m
}

// echo writes a line on c and reports whether the same line came back.
func echo(c net.Conn, line string) bool {
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(line + "\n")); err != nil {
		return false
	}
	got, err := bufio.NewReader(c).ReadString('\n')
	return err == nil && got == line+"\n"
}

// The cut must end connections that are already established (a gRPC worker keeps
// one long-lived connection open), refuse new ones, and restore cleanly. Without
// the first, the worker's heartbeats would keep its lease alive and the harness
// would observe nothing.
func TestRelayCutClosesEstablishedConnections(t *testing.T) {
	target := echoServer(t, "tcp", "127.0.0.1:0").Addr().String()
	r, listen := startRelay(t, target)

	established, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func() { _ = established.Close() }()
	require.True(t, echo(established, "before"), "the relay forwards before a cut")

	cut := r.do(t, "cut")
	assert.Equal(t, "cut", cut["mode"])
	assert.EqualValues(t, 2, cut["closed"], "both sides of the one splice are closed")

	_ = established.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = established.Read(make([]byte, 16))
	require.Error(t, err, "the established connection ends at the cut")
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the established connection was still open 3 s after the cut: %v", err)
	}

	fresh, err := net.Dial("tcp", listen)
	if err == nil {
		assert.False(t, echo(fresh, "during"), "a new connection during the cut is refused")
		_ = fresh.Close()
	}
	state := r.do(t, "state")
	assert.Equal(t, "cut", state["mode"])
	assert.EqualValues(t, 0, state["active"])

	r.do(t, "restore")
	again, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func() { _ = again.Close() }()
	assert.True(t, echo(again, "after"), "the relay forwards again after a restore")

	logged, err := os.ReadFile(r.log)
	require.NoError(t, err)
	for _, event := range []string{`"event": "listening"`, `"event": "cut"`, `"event": "restore"`} {
		assert.Contains(t, string(logged), event)
	}
}

// The harness's coordinator binds [::1] while the relay owns 127.0.0.1 on the
// same port, so the relay must reach an IPv6 loopback target.
func TestRelayReachesIPv6Loopback(t *testing.T) {
	target := echoServer(t, "tcp6", "[::1]:0").Addr().String()
	_, listen := startRelay(t, target)
	c, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	assert.True(t, echo(c, "v6"))
}

func TestRelayRefusesNonLoopbackAddresses(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:28255=127.0.0.1:1", "127.0.0.1:28255=10.0.0.1:1", "localhost:1=127.0.0.1:2"} {
		out, code := tool(t, "relay.py", "serve", "--listen", listen, "--control", filepath.Join(t.TempDir(), "s"), "--log", filepath.Join(t.TempDir(), "l"))
		assert.Equal(t, 2, code, listen)
		assert.Contains(t, out, "relay:", listen)
	}
}

// procs.py signals only the process it started: a pid file whose start time no
// longer matches (a reused pid) is refused, and the process is left running.
func TestProcsStopsOnlyItsOwnProcess(t *testing.T) {
	dir := t.TempDir()
	pidfile, log := filepath.Join(dir, "p.pid"), filepath.Join(dir, "p.log")
	out, code := tool(t, "procs.py", "start", "--pidfile", pidfile, "--log", log, "--", "/bin/sleep", "300")
	require.Equal(t, 0, code, out)
	var rec map[string]any
	raw, err := os.ReadFile(pidfile)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &rec))
	pid := int(rec["pid"].(float64))
	t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
	assert.EqualValues(t, pid, rec["pgid"], "the process leads its own group")
	assert.Len(t, rec["token"], 32)

	out, code = tool(t, "procs.py", "check", "--pidfile", pidfile)
	assert.Equal(t, 0, code, out)

	forged := map[string]any{}
	maps.Copy(forged, rec)
	forged["lstart"] = "Thu Jan  1 00:00:00 1970"
	forgedFile := filepath.Join(dir, "forged.pid")
	b, _ := json.Marshal(forged)
	require.NoError(t, os.WriteFile(forgedFile, b, 0o600))
	out, code = tool(t, "procs.py", "stop", "--pidfile", forgedFile)
	assert.Equal(t, 3, code, out)
	assert.Contains(t, out, "refusing to signal")
	assert.NoError(t, syscall.Kill(pid, 0), "the refused stop left the process running")

	out, code = tool(t, "procs.py", "stop", "--pidfile", pidfile, "--timeout", "5")
	require.Equal(t, 0, code, out)
	require.Eventually(t, func() bool { return syscall.Kill(pid, 0) != nil }, 5*time.Second, 50*time.Millisecond)
	_, err = os.Stat(pidfile + ".stopped")
	assert.NoError(t, err)

	out, code = tool(t, "procs.py", "stop", "--pidfile", pidfile)
	assert.Equal(t, 0, code, out)
	assert.True(t, strings.Contains(out, "nothing to stop"), out)
}
