// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unitsPython stands in for the interpreter the install resolves; its path has a space.
const unitsPython = "/opt/py thon/bin/python3"

// unitsOut writes the Linux units into a fresh directory whose every path has a space, a % and a
// $ (systemd specifiers and variables), and returns the two unit files' text.
func unitsOut(t *testing.T, credential string) (dir, tunnel, worker string) {
	t.Helper()
	agentsScript(t)
	script, err := filepath.Abs("units.py")
	require.NoError(t, err)
	base := filepath.Join(t.TempDir(), "conf dir")
	dir = filepath.Join(base, "systemd", "user")
	home := filepath.Join(base, "txe 100% $HOME")
	_, stderr, err := python(t, script, "write", dir, home, "/opt/kube ctl/kubectl", agentsMachine, agentsOwner,
		"/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service", "dagu", "svc/dagu", "18080", "50055", credential,
		unitsPython)
	if err != nil {
		return dir, "", stderr
	}
	tb, err := os.ReadFile(filepath.Join(dir, "txe-dagu-tunnel.service"))
	require.NoError(t, err)
	wb, err := os.ReadFile(filepath.Join(dir, "txe-dagu-worker.service"))
	require.NoError(t, err)
	return dir, string(tb), string(wb)
}

// unitFile is a unit as systemd reads it: ExecStart= split into its words, Environment= into
// its assignments, and the [Service] settings that take one plain value.
type unitFile struct {
	text        string
	argv        []string
	environment map[string]string
	settings    map[string]string
}

// unitWords splits a line of double-quoted words as systemd.syntax(7) does, then undoes what
// units.py doubles: % always (specifiers), $ only on ExecStart= (variables). A % or $ that is
// not doubled would be expanded by systemd, so it fails the test.
func unitWords(t *testing.T, line string, exec bool) []string {
	t.Helper()
	var words []string
	for rest := line; rest != ""; {
		require.Equal(t, byte('"'), rest[0], "every word is quoted: %q", line)
		var word strings.Builder
		i := 1
		for ; i < len(rest) && rest[i] != '"'; i++ {
			c := rest[i]
			switch {
			case c == '\\':
				i++
				require.Less(t, i, len(rest), line)
				require.Contains(t, `\"`, string(rest[i]), "units.py escapes only a backslash and a quote: %q", line)
				word.WriteByte(rest[i])
			case c == '%', c == '$' && exec:
				i++
				require.True(t, i < len(rest) && rest[i] == c, "a lone %c would be expanded by systemd: %q", c, line)
				word.WriteByte(c)
			default:
				word.WriteByte(c)
			}
		}
		require.Less(t, i, len(rest), "an unterminated word: %q", line)
		words = append(words, word.String())
		rest = strings.TrimPrefix(rest[i+1:], " ")
	}
	return words
}

func readUnit(t *testing.T, path string) unitFile {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	unit := unitFile{text: string(data), environment: map[string]string{}, settings: map[string]string{}}
	for line := range strings.SplitSeq(unit.text, "\n") {
		key, value, found := strings.Cut(line, "=")
		switch {
		case !found:
		case key == "ExecStart":
			require.Nil(t, unit.argv, "one ExecStart=")
			unit.argv = unitWords(t, value, true)
		case key == "Environment":
			words := unitWords(t, value, false)
			require.Len(t, words, 1)
			name, v, ok := strings.Cut(words[0], "=")
			require.True(t, ok, line)
			unit.environment[name] = v
		default:
			unit.settings[key] = value
		}
	}
	require.NotEmpty(t, unit.argv, "the unit has an ExecStart=")
	return unit
}

// agentArguments returns a macOS agent's ProgramArguments (plistlib reads the plist).
func agentArguments(t *testing.T, plist string) []string {
	t.Helper()
	dump, stderr, err := python(t, "-c",
		`import json, plistlib, sys; print(json.dumps(plistlib.load(open(sys.argv[1], "rb"))["ProgramArguments"]))`, plist)
	require.NoError(t, err, stderr)
	var arguments []string
	require.NoError(t, json.Unmarshal([]byte(dump), &arguments))
	return arguments
}

// Each unit runs its program under the log wrapper with the macOS agent's limits, and the
// program's own arguments are the agent's: the worker's exactly, the tunnel's without the macOS
// supervisor. The only addition is the wrapper's --kill-timeout, sized to the unit's stop.
func TestUnitsMatchTheMacAgents(t *testing.T) {
	script := agentsScript(t)
	units, err := filepath.Abs("units.py")
	require.NoError(t, err)
	dir := filepath.Join(t.TempDir(), "user")
	home := "/home/dev/.local/share/txe-dagu"
	args := []string{home, "/usr/bin/kubectl", agentsMachine, agentsOwner, "/usr/bin:/bin"}
	rest := []string{"dagu", "svc/dagu", "18080", "50055", "", unitsPython}
	_, stderr, err := python(t, append(append(append([]string{units, "write", dir}, args...),
		"txe-dagu-tunnel.service", "txe-dagu-worker.service"), rest...)...)
	require.NoError(t, err, stderr)
	agents := filepath.Join(t.TempDir(), "agents")
	require.NoError(t, os.MkdirAll(agents, 0o700))
	_, stderr, err = python(t, append(append(append([]string{script, "write", agents}, args...),
		"com.txe.dagu.tunnel", "com.txe.dagu.worker"), rest...)...)
	require.NoError(t, err, stderr)

	tunnel := readUnit(t, filepath.Join(dir, "txe-dagu-tunnel.service"))
	worker := readUnit(t, filepath.Join(dir, "txe-dagu-worker.service"))
	macWorker := agentArguments(t, filepath.Join(agents, "com.txe.dagu.worker.plist"))
	macTunnel := agentArguments(t, filepath.Join(agents, "com.txe.dagu.tunnel.plist"))

	// The macOS worker agent's arguments, with the wrapper's stop wait before its "--".
	cut := slices.Index(macWorker, "--")
	require.Positive(t, cut)
	assert.Equal(t, slices.Concat(macWorker[:cut], []string{"--kill-timeout", "90"}, macWorker[cut:]), worker.argv)
	assert.Equal(t, []string{unitsPython, "-I", home + "/bin/logpipe.py", "--path", home + "/logs/worker.log",
		"--max-bytes", "67108864", "--backups", "10", "--kill-timeout", "90", "--",
		home + "/bin/dagu", "worker", "--worker.id", agentsMachine,
		"--worker.labels", "txe.machine=" + agentsMachine + ",txe.owner=" + agentsOwner,
		"--worker.coordinators", "127.0.0.1:50055"}, worker.argv)
	// The macOS tunnel agent's, without the supervisor between the wrapper's "--" and kubectl's.
	cut = slices.Index(macTunnel, "--")
	require.Positive(t, cut)
	kubectl := slices.Index(macTunnel, "/usr/bin/kubectl")
	require.Greater(t, kubectl, cut)
	assert.Equal(t, slices.Concat(macTunnel[:cut], []string{"--kill-timeout", "90", "--"}, macTunnel[kubectl:]), tunnel.argv)
	assert.Equal(t, []string{unitsPython, "-I", home + "/bin/logpipe.py", "--path", home + "/logs/tunnel.log",
		"--max-bytes", "8388608", "--backups", "5", "--kill-timeout", "90", "--",
		"/usr/bin/kubectl", "--kubeconfig", home + "/tunnel/kubeconfig", "-n", "dagu",
		"port-forward", "--address", "127.0.0.1", "svc/dagu", "18080:8080", "50055:50055"}, tunnel.argv)

	assert.Equal(t, map[string]string{"DAGU_HOME": home + "/worker-home", "PATH": "/usr/bin:/bin"}, worker.environment)
	assert.Equal(t, map[string]string{"PATH": "/usr/bin:/bin"}, tunnel.environment)
	for _, unit := range []unitFile{tunnel, worker} {
		assert.Contains(t, unit.text, "Restart=always\nRestartSec=5\n")
		assert.Contains(t, unit.text, "WantedBy=default.target\n")
		// The stop: SIGTERM to the wrapper alone, the wrapper's wait inside the unit's.
		assert.Equal(t, "mixed", unit.settings["KillMode"])
		assert.Equal(t, "105", unit.settings["TimeoutStopSec"])
		assert.Equal(t, "143", unit.settings["SuccessExitStatus"])
		// systemd holds no descriptor on a log the wrapper owns: the unit's own stream is the journal.
		assert.Equal(t, "journal", unit.settings["StandardOutput"])
		assert.Equal(t, "journal", unit.settings["StandardError"])
		assert.NotContains(t, unit.text, "append:")
	}
	assert.NotContains(t, worker.text, "DAGU_WORKER_AUTH_CREDENTIAL_FILE", "an install without a credential passes none")
	out, stderr, err := python(t, units, "credential", filepath.Join(dir, "txe-dagu-worker.service"))
	require.NoError(t, err, stderr)
	assert.Empty(t, out)
}

func TestUnitsPassTheCredentialPathOnly(t *testing.T) {
	cred := filepath.Join(t.TempDir(), "cred dir 5% $X", "worker-credential.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(cred), 0o700))
	require.NoError(t, os.WriteFile(cred, []byte(`{"refresh_token":"`+agentsSecret+`"}`), 0o600))
	agentsScript(t)
	script, err := filepath.Abs("units.py")
	require.NoError(t, err)
	dir := filepath.Join(t.TempDir(), "user")
	_, stderr, err := python(t, script, "write", dir, "/home/dev/txe", "/opt/kube ctl/kube%ctl$1", agentsMachine, agentsOwner,
		"/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service", "dagu", "svc/dagu", "18080", "50055", cred,
		unitsPython)
	require.NoError(t, err, stderr)
	worker, err := os.ReadFile(filepath.Join(dir, "txe-dagu-worker.service"))
	require.NoError(t, err)
	// Environment= expands specifiers but not variables: % is doubled, $ is kept as it is.
	escaped := strings.ReplaceAll(cred, "%", "%%")
	assert.Contains(t, string(worker), `Environment="DAGU_WORKER_AUTH_CREDENTIAL_FILE=`+escaped+`"`+"\n")
	assert.NotContains(t, string(worker), agentsSecret, "the unit holds the path, never the token")
	out, stderr, err := python(t, script, "credential", filepath.Join(dir, "txe-dagu-worker.service"))
	require.NoError(t, err, stderr)
	assert.Equal(t, cred+"\n", out, "the path reads back exactly")
	tunnel, err := os.ReadFile(filepath.Join(dir, "txe-dagu-tunnel.service"))
	require.NoError(t, err)
	assert.NotContains(t, string(tunnel), "CREDENTIAL", "the tunnel gets no machine credential")
	assert.Contains(t, string(tunnel), ` "--" "/opt/kube ctl/kube%%ctl$$1" "--kubeconfig"`, "a space is quoted, % and $ are doubled")
}

// A home with a space, a % and a $ was refused while the logs went to StandardOutput=append:,
// which takes its path unquoted. The log paths are arguments of the wrapper now, quoted like
// every other, so such a home is written and reads back exactly.
func TestUnitsTakeAHomeWithSpecialCharacters(t *testing.T) {
	dir, tunnel, worker := unitsOut(t, "")
	require.NotEmpty(t, tunnel, worker)
	home := filepath.Join(filepath.Dir(filepath.Dir(dir)), "txe 100% $HOME")
	w := readUnit(t, filepath.Join(dir, "txe-dagu-worker.service"))
	assert.Equal(t, []string{unitsPython, "-I", home + "/bin/logpipe.py", "--path", home + "/logs/worker.log"}, w.argv[:5])
	assert.Equal(t, home+"/bin/dagu", w.argv[slices.Index(w.argv, "--")+1])
	assert.Equal(t, home+"/worker-home", w.environment["DAGU_HOME"])
	tn := readUnit(t, filepath.Join(dir, "txe-dagu-tunnel.service"))
	assert.Equal(t, home+"/logs/tunnel.log", tn.argv[4])
	assert.Equal(t, home+"/tunnel/kubeconfig", tn.argv[slices.Index(tn.argv, "--kubeconfig")+1])
}

func TestUnitsRefuseARelativeHome(t *testing.T) {
	agentsScript(t)
	script, err := filepath.Abs("units.py")
	require.NoError(t, err)
	_, stderr, err := python(t, script, "write", filepath.Join(t.TempDir(), "user"), "relative/txe", "/usr/bin/kubectl",
		agentsMachine, agentsOwner, "/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service",
		"dagu", "svc/dagu", "18080", "50055", "", unitsPython)
	require.Error(t, err)
	assert.Contains(t, stderr, "the TXE home must be an absolute path")
}

// ExecStart= takes an absolute path only: an interpreter given by name is refused, not written
// into a unit systemd would not start.
func TestUnitsRefuseARelativeInterpreter(t *testing.T) {
	agentsScript(t)
	script, err := filepath.Abs("units.py")
	require.NoError(t, err)
	dir := filepath.Join(t.TempDir(), "user")
	_, stderr, err := python(t, script, "write", dir, "/home/dev/txe", "/usr/bin/kubectl",
		agentsMachine, agentsOwner, "/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service",
		"dagu", "svc/dagu", "18080", "50055", "", "python3")
	require.Error(t, err)
	assert.Contains(t, stderr, "python3 must be an absolute path")
	_, statErr := os.Stat(dir)
	assert.True(t, os.IsNotExist(statErr), "nothing was written")
}

func TestUnitsRefuseALineBreak(t *testing.T) {
	agentsScript(t)
	script, err := filepath.Abs("units.py")
	require.NoError(t, err)
	_, stderr, err := python(t, script, "write", filepath.Join(t.TempDir(), "user"), "/home/dev/txe", "/usr/bin/kubectl",
		agentsMachine, "own_x\nExecStartPre=/bin/sh", "/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service",
		"dagu", "svc/dagu", "18080", "50055", "", unitsPython)
	require.Error(t, err)
	assert.Contains(t, stderr, "cannot hold a line break")
}

func TestInstallSystemdRefusesBothCredentialFlags(t *testing.T) {
	agentsScript(t)
	install, err := filepath.Abs("install-systemd.sh")
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	for _, args := range [][]string{
		{"--no-credential", "--credential-file", "/x/worker-credential.json"},
		{"--credential-file", "/x/worker-credential.json", "--no-credential"},
	} {
		home := t.TempDir()
		cmd := exec.Command(bash, append([]string{install}, args...)...)
		cmd.Env = []string{"HOME=" + home, "TXE_DAGU_HOME=" + filepath.Join(home, "txe"), "PATH=/usr/bin:/bin"}
		var errOut bytes.Buffer
		cmd.Stderr = &errOut
		require.Error(t, cmd.Run(), args)
		assert.Contains(t, errOut.String(), "--credential-file and --no-credential cannot both be given")
		_, statErr := os.Stat(filepath.Join(home, "txe"))
		assert.True(t, os.IsNotExist(statErr), "nothing was created")
	}
}

func TestUninstallSystemdPurgeRefusesAHomeWithoutMachineJSON(t *testing.T) {
	agentsScript(t)
	script, err := filepath.Abs("uninstall-systemd.sh")
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	bin := t.TempDir()
	// A stand-in systemctl, so the test needs no systemd.
	require.NoError(t, os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\ncase \"$*\" in *is-active*) echo inactive; exit 3;; esac\nexit 0\n"), 0o755))
	home := t.TempDir()
	txe := filepath.Join(home, "not-a-txe-home")
	require.NoError(t, os.MkdirAll(txe, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(txe, "keep"), []byte("x"), 0o600))
	cmd := exec.Command(bash, script, "--purge")
	cmd.Env = []string{"HOME=" + home, "TXE_DAGU_HOME=" + txe, "PATH=" + bin + ":/usr/bin:/bin"}
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	require.Error(t, cmd.Run())
	assert.Contains(t, errOut.String(), "it holds no machine.json")
	_, statErr := os.Stat(filepath.Join(txe, "keep"))
	assert.NoError(t, statErr, "nothing was deleted")
}

func TestUninstallSystemdStopsBeforeItRemovesOrPurges(t *testing.T) {
	agentsScript(t)
	script, err := filepath.Abs("uninstall-systemd.sh")
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	for _, c := range []struct{ name, systemctl, want string }{
		// disable --now fails: a worker that could not be stopped keeps its unit and its home.
		{"stop fails", "case \"$*\" in *disable*) exit 1;; *is-active*) echo active;; esac\nexit 0\n", "could not stop txe-dagu-worker.service"},
		// disable --now succeeds but the unit is still running.
		{"still active", "case \"$*\" in *is-active*) echo active;; esac\nexit 0\n", "txe-dagu-worker.service is still active"},
		// The state query itself fails: nothing confirms the worker stopped.
		{"no state", "case \"$*\" in *is-active*) exit 1;; esac\nexit 0\n", "could not confirm that txe-dagu-worker.service is stopped"},
	} {
		t.Run(c.name, func(t *testing.T) {
			bin := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\n"+c.systemctl), 0o755))
			home := t.TempDir()
			units := filepath.Join(home, "units")
			require.NoError(t, os.MkdirAll(units, 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(units, "txe-dagu-worker.service"), []byte("[Service]\n"), 0o644))
			txe := filepath.Join(home, "txe")
			require.NoError(t, os.MkdirAll(txe, 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(txe, "machine.json"), []byte("{}"), 0o600))
			cmd := exec.Command(bash, script, "--purge")
			cmd.Env = []string{"HOME=" + home, "TXE_DAGU_HOME=" + txe, "TXE_DAGU_UNITS_DIR=" + units, "PATH=" + bin + ":/usr/bin:/bin"}
			var errOut bytes.Buffer
			cmd.Stderr = &errOut
			require.Error(t, cmd.Run())
			assert.Contains(t, errOut.String(), c.want)
			_, statErr := os.Stat(filepath.Join(units, "txe-dagu-worker.service"))
			assert.NoError(t, statErr, "the unit was not removed")
			_, statErr = os.Stat(filepath.Join(txe, "machine.json"))
			assert.NoError(t, statErr, "the home was not purged")
		})
	}
}

func TestUninstallSystemdPurgeRefusesTheHomeHoweverSpelled(t *testing.T) {
	agentsScript(t)
	script, err := filepath.Abs("uninstall-systemd.sh")
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	bin := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "systemctl"),
		[]byte("#!/bin/sh\ncase \"$*\" in *is-active*) echo inactive; exit 3;; esac\nexit 0\n"), 0o755))
	base := t.TempDir()
	home := filepath.Join(base, "home", "dev")
	require.NoError(t, os.MkdirAll(home, 0o700))
	// machine.json in the home itself: an install that used the home as its TXE home.
	require.NoError(t, os.WriteFile(filepath.Join(home, "machine.json"), []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(home), "machine.json"), []byte("{}"), 0o600))
	link := filepath.Join(base, "link-to-home")
	require.NoError(t, os.Symlink(home, link))
	for _, txe := range []string{home + "/", home + "/.", link, filepath.Dir(home), "/"} {
		cmd := exec.Command(bash, script, "--purge")
		cmd.Env = []string{"HOME=" + home, "TXE_DAGU_HOME=" + txe, "TXE_DAGU_UNITS_DIR=" + filepath.Join(base, "units"),
			"PATH=" + bin + ":/usr/bin:/bin"}
		var errOut bytes.Buffer
		cmd.Stderr = &errOut
		require.Error(t, cmd.Run(), txe)
		assert.Regexp(t, `refusing to purge`, errOut.String(), txe)
		_, statErr := os.Stat(filepath.Join(home, "machine.json"))
		require.NoError(t, statErr, "the home survived %q", txe)
	}
}

func TestSystemdWaitActive(t *testing.T) {
	agentsScript(t)
	script, err := filepath.Abs("systemd-wait-active.sh")
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	// The stand-in systemctl answers is-active with STATE and NRestarts from a counter file that
	// CYCLE increments on every NRestarts read after the first, as a unit that keeps respawning.
	for _, c := range []struct {
		name, state, cycle, want string
		ok                       bool
	}{
		{"active", "active", "", "", true},
		{"cycling-while-settling", "active", "yes", "restarted while settling", false},
		{"activating", "activating", "", "is activating, not active", false},
		{"failed", "failed", "", "is failed, not active", false},
		{"no answer", "", "", "is unknown, not active", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			bin := t.TempDir()
			n := filepath.Join(bin, "n")
			require.NoError(t, os.WriteFile(n, []byte("0"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(bin, "systemctl"), []byte(`#!/bin/sh
case "$*" in
  *NRestarts*) v=$(cat "`+n+`"); [ "`+c.cycle+`" = yes ] && echo $((v + 1)) > "`+n+`"; echo "$v" ;;
  *is-active*) echo '`+c.state+`'; [ '`+c.state+`' = active ] ;;
esac
`), 0o755))
			cmd := exec.Command(bash, script, "txe-dagu-tunnel.service", "txe-dagu-worker.service")
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "TXE_DAGU_ACTIVE_WAIT=1", "TXE_DAGU_ACTIVE_SETTLE=0"}
			var errOut bytes.Buffer
			cmd.Stderr = &errOut
			err := cmd.Run()
			if c.ok {
				require.NoError(t, err, errOut.String())
				return
			}
			require.Error(t, err)
			assert.Contains(t, errOut.String(), c.want)
		})
	}
}

func TestUnitsOnTheChannelHaveNoTunnel(t *testing.T) {
	agentsScript(t)
	script, err := filepath.Abs("units.py")
	require.NoError(t, err)
	dir := filepath.Join(t.TempDir(), "user")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "txe-dagu-tunnel.service"), []byte("left behind"), 0o600))
	_, stderr, err := python(t, script, "write", dir, "/home/dev/txe", "", agentsMachine, agentsOwner,
		"/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service", "dagu", "svc/dagu", "18080", "50055",
		"/home/dev/txe/worker-credential.json", unitsPython, "https://hub.example")
	require.NoError(t, err, stderr)
	worker, err := os.ReadFile(filepath.Join(dir, "txe-dagu-worker.service"))
	require.NoError(t, err)
	assert.Contains(t, string(worker), `"--worker.hub-url" "https://hub.example"`)
	assert.NotContains(t, string(worker), "--worker.coordinators")
	_, err = os.Stat(filepath.Join(dir, "txe-dagu-tunnel.service"))
	assert.True(t, os.IsNotExist(err))
}

// units.py removes the tunnel's file, and systemd cannot disable a unit with no
// file, so the old tunnel must be stopped first, and seen to have stopped.
func TestInstallStopsTheOldTunnelBeforeRemovingItsUnit(t *testing.T) {
	data, err := os.ReadFile("install-systemd.sh")
	require.NoError(t, err)
	script := string(data)
	stop := strings.Index(script, `--user stop "$TXE_DAGU_TUNNEL_UNIT"`)
	check := strings.Index(script, `is-active --quiet "$TXE_DAGU_TUNNEL_UNIT"`)
	write := strings.Index(script, `"$here/units.py" write`)
	require.Positive(t, stop)
	assert.Less(t, stop, check)
	assert.Less(t, check, write)
}
