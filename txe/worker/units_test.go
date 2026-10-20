// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		"/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service", "dagu", "svc/dagu", "18080", "50055", credential)
	if err != nil {
		return dir, "", stderr
	}
	tb, err := os.ReadFile(filepath.Join(dir, "txe-dagu-tunnel.service"))
	require.NoError(t, err)
	wb, err := os.ReadFile(filepath.Join(dir, "txe-dagu-worker.service"))
	require.NoError(t, err)
	return dir, string(tb), string(wb)
}

func TestUnitsMatchTheMacAgents(t *testing.T) {
	// The log paths go into StandardOutput=append:, which takes no quoting, so this home has none
	// of the special characters; quoting of the arguments is tested below.
	agentsScript(t)
	script, err := filepath.Abs("units.py")
	require.NoError(t, err)
	dir := filepath.Join(t.TempDir(), "user")
	home := "/home/dev/.local/share/txe-dagu"
	_, stderr, err := python(t, script, "write", dir, home, "/usr/bin/kubectl", agentsMachine, agentsOwner,
		"/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service", "dagu", "svc/dagu", "18080", "50055", "")
	require.NoError(t, err, stderr)
	tunnel, err := os.ReadFile(filepath.Join(dir, "txe-dagu-tunnel.service"))
	require.NoError(t, err)
	worker, err := os.ReadFile(filepath.Join(dir, "txe-dagu-worker.service"))
	require.NoError(t, err)
	assert.Contains(t, string(tunnel), `ExecStart="/usr/bin/kubectl" "--kubeconfig" "/home/dev/.local/share/txe-dagu/tunnel/kubeconfig" "-n" "dagu" "port-forward" "--address" "127.0.0.1" "svc/dagu" "18080:8080" "50055:50055"`+"\n")
	assert.Contains(t, string(worker), `ExecStart="/home/dev/.local/share/txe-dagu/bin/dagu" "worker" "--worker.id" "`+agentsMachine+`" "--worker.labels" "txe.machine=`+agentsMachine+`,txe.owner=`+agentsOwner+`" "--worker.coordinators" "127.0.0.1:50055"`+"\n")
	assert.Contains(t, string(worker), `Environment="DAGU_HOME=/home/dev/.local/share/txe-dagu/worker-home"`+"\n")
	assert.Contains(t, string(worker), "StandardOutput=append:/home/dev/.local/share/txe-dagu/logs/worker.log\n")
	for _, unit := range []string{string(tunnel), string(worker)} {
		assert.Contains(t, unit, "Restart=always\nRestartSec=5\n")
		assert.Contains(t, unit, "WantedBy=default.target\n")
	}
	assert.NotContains(t, string(worker), "DAGU_WORKER_AUTH_CREDENTIAL_FILE", "an install without a credential passes none")
	out, stderr, err := python(t, script, "credential", filepath.Join(dir, "txe-dagu-worker.service"))
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
		"/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service", "dagu", "svc/dagu", "18080", "50055", cred)
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
	assert.Contains(t, string(tunnel), `ExecStart="/opt/kube ctl/kube%%ctl$$1" "--kubeconfig"`, "a space is quoted, % and $ are doubled")
}

func TestUnitsRefuseALogPathSystemdCannotTake(t *testing.T) {
	// StandardOutput=append: takes the path unquoted, so a home with a space, a % or a $ is
	// refused rather than written into a unit that logs somewhere else.
	_, _, stderr := unitsOut(t, "")
	assert.Contains(t, stderr, "units refused: the log path must have no space or special character")
}

func TestUnitsRefuseALineBreak(t *testing.T) {
	agentsScript(t)
	script, err := filepath.Abs("units.py")
	require.NoError(t, err)
	_, stderr, err := python(t, script, "write", filepath.Join(t.TempDir(), "user"), "/home/dev/txe", "/usr/bin/kubectl",
		agentsMachine, "own_x\nExecStartPre=/bin/sh", "/usr/bin:/bin", "txe-dagu-tunnel.service", "txe-dagu-worker.service",
		"dagu", "svc/dagu", "18080", "50055", "")
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
	for _, c := range []struct {
		name, state string
		ok          bool
	}{{"active", "active", true}, {"cycling", "activating", false}, {"failed", "failed", false}, {"no answer", "", false}} {
		t.Run(c.name, func(t *testing.T) {
			bin := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(bin, "systemctl"),
				[]byte("#!/bin/sh\necho '"+c.state+"'\n[ '"+c.state+"' = active ]\n"), 0o755))
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
			assert.Contains(t, errOut.String(), "txe-dagu-tunnel.service is ")
			assert.Contains(t, errOut.String(), "not active")
		})
	}
}
