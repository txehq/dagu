// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmd"
)

// runDaguEnv makes this test binary run dagu's own worker command instead of
// its tests, so a rendered worker can be started exactly as installed: the
// rendered argv from "<home>/bin/dagu" on, its environment and its working
// directory, with "<home>/bin/dagu" a link to this binary.
const runDaguEnv = "TXE_WORKER_TEST_RUN_DAGU"

func TestMain(m *testing.M) {
	if os.Getenv(runDaguEnv) == "1" {
		os.Exit(runDagu(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// runDagu is cmd/main.go's root with only the worker command on it.
func runDagu(args []string) int {
	root := &cobra.Command{Use: "dagu", SilenceUsage: true}
	root.PersistentFlags().String("context", "", "")
	root.AddCommand(cmd.CmdWorker())
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}

// listener is an inet socket a process can be reached on: a TCP socket in
// LISTEN, or any UDP socket.
type listener struct {
	proto string
	addr  string
	port  int
}

func (l listener) String() string { return fmt.Sprintf("%s %s:%d", l.proto, l.addr, l.port) }

// listeners returns the inet listeners of one process, read by its pid.
func listeners(t *testing.T, pid int) []listener {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		return procListeners(t, pid)
	case "darwin":
		return lsofListeners(t, pid)
	default:
		t.Skipf("no listener reader for %s", runtime.GOOS)
		return nil
	}
}

// procListeners matches the process's socket descriptors against its network
// namespace's socket tables.
func procListeners(t *testing.T, pid int) []listener {
	t.Helper()
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	require.NoError(t, err)
	inodes := map[string]bool{}
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue // closed since the directory was read
		}
		if inode, ok := strings.CutPrefix(target, "socket:["); ok {
			inodes[strings.TrimSuffix(inode, "]")] = true
		}
	}
	var out []listener
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, table))
		if errors.Is(err, os.ErrNotExist) {
			continue // no IPv6 in this kernel
		}
		require.NoError(t, err)
		for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			fields := strings.Fields(line)
			if i == 0 || len(fields) < 10 || !inodes[fields[9]] {
				continue
			}
			// TCP_LISTEN is 0A; a UDP socket of the process is reachable in any state.
			if strings.HasPrefix(table, "tcp") && fields[3] != "0A" {
				continue
			}
			hexAddr, hexPort, ok := strings.Cut(fields[1], ":")
			require.True(t, ok, line)
			port, err := strconv.ParseUint(hexPort, 16, 16)
			require.NoError(t, err, line)
			out = append(out, listener{proto: strings.TrimSuffix(table, "6"), addr: procAddr(t, hexAddr), port: int(port)})
		}
	}
	return out
}

// procAddr decodes /proc/net's address: 32-bit words in host (little-endian) order.
func procAddr(t *testing.T, s string) string {
	t.Helper()
	raw, err := hex.DecodeString(s)
	require.NoError(t, err, s)
	require.Contains(t, []int{4, 16}, len(raw), s)
	for i := 0; i < len(raw); i += 4 {
		slices.Reverse(raw[i : i+4])
	}
	return net.IP(raw).String()
}

// lsofListeners asks lsof for the process's listening TCP and its UDP sockets.
// lsof exits 1 when it finds none.
func lsofListeners(t *testing.T, pid int) []listener {
	t.Helper()
	var out []listener
	for _, q := range []struct{ proto, filter, state string }{{"tcp", "-iTCP", "-sTCP:LISTEN"}, {"udp", "-iUDP", ""}} {
		args := []string{"-nP", "-a", "-p", strconv.Itoa(pid), q.filter, "-Fn"}
		if q.state != "" {
			args = append(args, q.state)
		}
		var stdout, stderr bytes.Buffer
		c := exec.Command("/usr/sbin/lsof", args...)
		c.Stdout, c.Stderr = &stdout, &stderr
		err := c.Run()
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 && stdout.Len() == 0 {
			continue
		}
		require.NoError(t, err, stderr.String())
		for line := range strings.SplitSeq(stdout.String(), "\n") {
			name, ok := strings.CutPrefix(line, "n")
			if !ok {
				continue
			}
			host, portText, err := net.SplitHostPort(name)
			require.NoError(t, err, name)
			port, err := strconv.Atoi(portText)
			require.NoError(t, err, name)
			out = append(out, listener{proto: q.proto, addr: host, port: port})
		}
	}
	return out
}

// lockedBuffer collects a child's output while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// deadLoopbackPort returns a loopback port nothing listens on: the rendered
// worker's coordinator, so the worker runs, fails its heartbeats and reaches nothing.
func deadLoopbackPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return strconv.Itoa(port)
}

// installedWorker is a rendered worker: its program arguments from
// "<home>/bin/dagu" on, its environment and its working directory.
type installedWorker struct {
	home string
	argv []string
	env  map[string]string
	dir  string
}

// renderMacWorker writes the agents with agents.py into a fresh home and reads the worker's plist.
func renderMacWorker(t *testing.T, coordPort string) installedWorker {
	t.Helper()
	script := agentsScript(t)
	home := filepath.Join(t.TempDir(), "txe dagu")
	agents := filepath.Join(t.TempDir(), "agents")
	require.NoError(t, os.MkdirAll(agents, 0o700))
	_, stderr, err := python(t, script, "write", agents, home, "/usr/bin/kubectl", agentsMachine, agentsOwner,
		"/usr/bin:/bin", "com.txe.dagu.tunnel", "com.txe.dagu.worker", "dagu", "svc/dagu", "18080", coordPort, "",
		"/usr/bin/python3")
	require.NoError(t, err, stderr)
	dump, stderr, err := python(t, "-c", `import json, plistlib, sys
p = plistlib.load(open(sys.argv[1], "rb"))
print(json.dumps([p["ProgramArguments"], p["EnvironmentVariables"], p["WorkingDirectory"]]))`,
		filepath.Join(agents, "com.txe.dagu.worker.plist"))
	require.NoError(t, err, stderr)
	var parsed []any
	require.NoError(t, json.Unmarshal([]byte(dump), &parsed))
	w := installedWorker{home: home, env: map[string]string{}, dir: parsed[2].(string)}
	for _, a := range parsed[0].([]any) {
		w.argv = append(w.argv, a.(string))
	}
	for k, v := range parsed[1].(map[string]any) {
		w.env[k] = v.(string)
	}
	w.argv = fromDagu(t, home, w.argv)
	return w
}

// renderLinuxWorker writes the units with units.py into a fresh home and reads the worker's unit.
func renderLinuxWorker(t *testing.T, coordPort string) installedWorker {
	t.Helper()
	agentsScript(t)
	script, err := filepath.Abs("units.py")
	require.NoError(t, err)
	home := filepath.Join(t.TempDir(), "txe dagu")
	units := filepath.Join(t.TempDir(), "user")
	_, stderr, err := python(t, script, "write", units, home, "/usr/bin/kubectl", agentsMachine, agentsOwner,
		"/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service", "dagu", "svc/dagu", "18080", coordPort, "",
		"/usr/bin/python3")
	require.NoError(t, err, stderr)
	unit := readUnit(t, filepath.Join(units, "txe-dagu-worker.service"))
	_, set := unit.settings["WorkingDirectory"]
	require.False(t, set, "the test runs the unit in systemd's default for a user unit, the user's home")
	dir, err := os.UserHomeDir()
	require.NoError(t, err)
	return installedWorker{home: home, argv: fromDagu(t, home, unit.argv), env: unit.environment, dir: dir}
}

// fromDagu cuts the log wrapper off: the worker's own argv starts at "<home>/bin/dagu".
func fromDagu(t *testing.T, home string, argv []string) []string {
	t.Helper()
	i := slices.Index(argv, home+"/bin/dagu")
	require.GreaterOrEqual(t, i, 0, "the rendered worker runs <home>/bin/dagu: %q", argv)
	return argv[i:]
}

// start runs the rendered worker with this test binary as <home>/bin/dagu and
// waits until it has started its health server step and is heartbeating. HOME
// is passed through unchanged; DAGU_HOME and the rest come from the rendering.
func (w installedWorker) start(t *testing.T) (pid int, output *lockedBuffer) {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(w.home, "bin"), 0o700))
	require.NoError(t, os.Symlink(self, w.argv[0]))
	require.NotEmpty(t, w.env["DAGU_HOME"])
	require.NoError(t, os.MkdirAll(w.env["DAGU_HOME"], 0o700))
	if strings.HasPrefix(w.dir, w.home+"/") {
		require.NoError(t, os.MkdirAll(w.dir, 0o700))
	}

	c := exec.Command(w.argv[0], w.argv[1:]...)
	c.Dir = w.dir
	c.Env = []string{runDaguEnv + "=1", "HOME=" + os.Getenv("HOME")}
	for k, v := range w.env {
		c.Env = append(c.Env, k+"="+v)
	}
	output = &lockedBuffer{}
	c.Stdout, c.Stderr = output, output
	require.NoError(t, c.Start())
	exited := make(chan error, 1)
	go func() { exited <- c.Wait() }()
	t.Cleanup(func() {
		_ = c.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			_ = c.Process.Kill()
			<-exited
		}
	})

	// The worker starts its health server (or logs it disabled) before it
	// polls or heartbeats, so a heartbeat line means that step is behind it.
	deadline := time.After(90 * time.Second)
	for {
		text := strings.ToLower(output.String())
		if strings.Contains(text, "health check server") && strings.Contains(text, "heartbeat") {
			return c.Process.Pid, output
		}
		select {
		case err := <-exited:
			exited <- err
			t.Fatalf("the rendered worker exited (%v) before it ran:\n%s", err, output.String())
		case <-deadline:
			t.Fatalf("the rendered worker did not reach its heartbeat in 90 s:\n%s", output.String())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func healthPortArgs(argv []string) [][]string {
	var found [][]string
	for i, a := range argv {
		if a == "--worker.health-port" && i+1 < len(argv) {
			found = append(found, []string{a, argv[i+1]})
		} else if strings.HasPrefix(a, "--worker.health-port=") {
			found = append(found, []string{a})
		}
	}
	return found
}

// An installed worker, macOS agent or Linux unit, run exactly as rendered,
// opens no inet listener at all: dagu's default would be a no-auth health
// server on *:8092, every interface (TXE-7849, TXE-7850).
func TestInstalledWorkerOpensNoListener(t *testing.T) {
	for name, render := range map[string]func(*testing.T, string) installedWorker{
		"agents.py": renderMacWorker,
		"units.py":  renderLinuxWorker,
	} {
		t.Run(name, func(t *testing.T) {
			w := render(t, deadLoopbackPort(t))
			assert.Equal(t, [][]string{{"--worker.health-port", "0"}}, healthPortArgs(w.argv))
			pid, output := w.start(t)
			assert.Empty(t, listeners(t, pid), "the installed worker listens on nothing:\n%s", output.String())
			assert.Contains(t, output.String(), "Health check server disabled")
		})
	}
}

// The control for the test above: the same rendered worker with its health
// port set to a free port is seen listening on it, so an empty reading is a
// worker with no listener, not a reader that sees nothing.
func TestListenerReaderSeesAWorkerHealthServer(t *testing.T) {
	w := renderMacWorker(t, deadLoopbackPort(t))
	i := slices.Index(w.argv, "--worker.health-port")
	require.Positive(t, i)
	port, err := strconv.Atoi(deadLoopbackPort(t))
	require.NoError(t, err)
	w.argv = slices.Clone(w.argv)
	w.argv[i+1] = strconv.Itoa(port)
	pid, output := w.start(t)
	got := listeners(t, pid)
	assert.True(t, slices.ContainsFunc(got, func(l listener) bool { return l.proto == "tcp" && l.port == port }),
		"the reader sees the health server on %d; it read %v:\n%s", port, got, output.String())
}

// The channel (--hub-url) workers carry the same setting. They cannot be run
// here: the worker refuses the channel without an enrolled machine's credential.
func TestChannelWorkersDisableTheHealthServer(t *testing.T) {
	_, worker := hubAgents(t, "https://hub.example")
	var mac []string
	for _, a := range worker["ProgramArguments"].([]any) {
		mac = append(mac, a.(string))
	}
	assert.Equal(t, [][]string{{"--worker.health-port", "0"}}, healthPortArgs(mac))

	agentsScript(t)
	script, err := filepath.Abs("units.py")
	require.NoError(t, err)
	dir := filepath.Join(t.TempDir(), "user")
	_, stderr, err := python(t, script, "write", dir, "/home/dev/txe", "", agentsMachine, agentsOwner,
		"/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service", "dagu", "svc/dagu", "18080", "50055",
		"/home/dev/txe/worker-credential.json", unitsPython, "https://hub.example")
	require.NoError(t, err, stderr)
	unit := readUnit(t, filepath.Join(dir, "txe-dagu-worker.service"))
	assert.Equal(t, [][]string{{"--worker.health-port", "0"}}, healthPortArgs(unit.argv))
}
