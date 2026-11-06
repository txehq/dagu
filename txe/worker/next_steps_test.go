// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker_test

import (
	"bytes"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A stub that records its arguments beside itself, one bracketed line per
// call, and answers "version" the way the installer's check expects. The
// machine's binary and the developer wrapper standing in for ~/.local/bin/dagu
// are both this script, each recording into its own directory.
const recordingDagu = `#!/bin/sh
calls="$(dirname "$0")/calls"
{ for a in "$@"; do printf '[%s]' "$a"; done; echo; } >> "$calls"
[ "${1:-}" != version ] || echo 2.18.2-txe.19
`

// channelPrep runs an installer on the worker channel with no credential, on a
// machine whose dagu on PATH is a developer wrapper the installer did not
// create, and whose TXE home has a space in its path. Nothing is built, cloned
// or enrolled: go is a no-op, git fails, and the binary for the tag is already
// there (TXE-5806).
type channelPrep struct {
	home, txeHome, linkDir, path string
	out, errOut                  string
}

func prepareOnTheChannel(t *testing.T, script string, extraStubs map[string]string) channelPrep {
	t.Helper()
	agentsScript(t)
	install, err := filepath.Abs(script)
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)

	home := t.TempDir()
	p := channelPrep{home: home, txeHome: filepath.Join(home, "txe dagu"), linkDir: filepath.Join(home, "bin")}
	require.NoError(t, os.MkdirAll(filepath.Join(p.txeHome, "bin"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(p.txeHome, "bin", "dagu-2.18.2-txe.19"), []byte(recordingDagu), 0o700)) //nolint:gosec // a test's stub
	require.NoError(t, os.MkdirAll(p.linkDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(p.linkDir, "dagu"), []byte(recordingDagu), 0o700)) //nolint:gosec // a test's stub

	tools := t.TempDir()
	stubs := map[string]string{
		"go":  "#!/bin/sh\n",
		"git": "#!/bin/sh\necho 'git must not run: nothing is cloned' >&2\nexit 99\n",
	}
	maps.Copy(stubs, extraStubs)
	for name, body := range stubs {
		require.NoError(t, os.WriteFile(filepath.Join(tools, name), []byte(body), 0o700)) //nolint:gosec // a test's stub
	}
	p.path = p.linkDir + ":" + tools + ":/usr/bin:/bin"

	cmd := exec.Command(bash, install, "--tag", "txe-v2.18.2-19", "--owner-id", "own_01M4GBBMJ7A2VKXJGAADCKV7RR", "--hub-url", "https://hub.example")
	cmd.Env = []string{"HOME=" + home, "TXE_DAGU_HOME=" + p.txeHome, "TXE_DAGU_LINK_DIR=" + p.linkDir, "PATH=" + p.path}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	require.NoError(t, cmd.Run(), "%s\n%s", out.String(), errOut.String())
	p.out, p.errOut = out.String(), errOut.String()
	return p
}

// nextSteps returns the lines printed after "next:".
func (p channelPrep) nextSteps(t *testing.T) []string {
	t.Helper()
	_, after, found := strings.Cut(p.out, "next:\n")
	require.True(t, found, "no next steps in:\n%s", p.out)
	return strings.Split(strings.TrimRight(after, "\n"), "\n")
}

// sh runs one command line in a shell with the machine's PATH, the developer
// wrapper first.
func (p channelPrep) sh(t *testing.T, line string) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	cmd := exec.Command(bash, "-c", line)
	cmd.Env = []string{"HOME=" + p.home, "PATH=" + p.path}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s: %s", line, out)
	return string(out)
}

func (p channelPrep) calls(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "calls"))
	if os.IsNotExist(err) {
		return ""
	}
	require.NoError(t, err)
	return string(b)
}

// The printed sign-in names this machine's binary by its absolute path, as one
// shell word, and running it as printed reaches that binary and not the
// developer wrapper that `dagu` resolves to. The other steps are unchanged.
func TestChannelNextStepsNameTheMachinesBinary(t *testing.T) {
	for _, tc := range []struct {
		script, stopped string
		stubs           map[string]string
	}{
		{script: "install.sh", stopped: "no agent was started"},
		{script: "install-systemd.sh", stopped: "no unit was started", stubs: map[string]string{
			"uname":     "#!/bin/sh\necho Linux\n",
			"systemctl": "#!/bin/sh\n",
		}},
	} {
		t.Run(tc.script, func(t *testing.T) {
			p := prepareOnTheChannel(t, tc.script, tc.stubs)
			assert.Contains(t, p.out, tc.stopped)
			machineBin := filepath.Join(p.txeHome, "bin", "dagu")

			steps := p.nextSteps(t)
			require.Len(t, steps, 5, "next steps:\n%s", strings.Join(steps, "\n"))
			assert.Equal(t, "  '"+machineBin+"' txe login --hub https://hub.example", steps[0])
			assert.True(t, strings.HasPrefix(steps[1], "    (this machine's own binary, by path: a dagu on PATH may be the developer CLI"), steps[1])
			assert.Equal(t, "  dagu txe machine create", steps[2])
			assert.Equal(t, "  dagu txe enrol --client-id <this machine's worker client> --wait 15m", steps[3])
			assert.Equal(t, "  run this install again with --hub-url", steps[4])

			// The ambiguity is real on this machine: `dagu` is the wrapper, which
			// the installer left alone and named.
			assert.Equal(t, filepath.Join(p.linkDir, "dagu")+"\n", p.sh(t, "command -v dagu"))
			assert.Contains(t, p.errOut, "not linked: "+filepath.Join(p.linkDir, "dagu"))

			// Run the sign-in as printed: the machine's binary gets it, the wrapper
			// nothing. Before that, the binary had answered only the installer's
			// version check.
			assert.Equal(t, "[version]\n", p.calls(t, filepath.Join(p.txeHome, "bin")))
			p.sh(t, strings.TrimSpace(steps[0]))
			assert.Equal(t, "[version]\n[txe][login][--hub][https://hub.example]\n", p.calls(t, filepath.Join(p.txeHome, "bin")))
			assert.Empty(t, p.calls(t, p.linkDir), "the developer wrapper was never run")

			// Nothing was cloned, enrolled or started.
			assert.NotContains(t, p.out+p.errOut, "git must not run")
			assert.NoFileExists(t, filepath.Join(p.txeHome, "worker-credential.json"))
			assert.NoFileExists(t, filepath.Join(p.home, "Library", "LaunchAgents", "com.txe.dagu.worker.plist"))
			assert.NoFileExists(t, filepath.Join(p.home, ".config", "systemd", "user", "txe-dagu-worker.service"))
			assert.FileExists(t, filepath.Join(p.txeHome, "machine.json"))
		})
	}
}

// The binary's path is printed as it is when a shell takes it as one word, and
// single-quoted otherwise; a relative TXE home is made absolute from the
// installer's working directory. Whatever the spelling, the line runs as printed.
func TestChannelNextStepsQuoteThePathOnlyWhenNeeded(t *testing.T) {
	agentsScript(t)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	lib, err := filepath.Abs("lib.sh")
	require.NoError(t, err)
	// The shell's $PWD is the resolved directory (macOS's temp dir is a link).
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	for _, tc := range []struct {
		home, want, binary string
	}{
		{home: "/opt/txe-dagu", want: "/opt/txe-dagu/bin/dagu", binary: "/opt/txe-dagu/bin/dagu"},
		{home: "/opt/txe dagu", want: "'/opt/txe dagu/bin/dagu'", binary: "/opt/txe dagu/bin/dagu"},
		{home: "/opt/it's", want: `'/opt/it'\''s/bin/dagu'`, binary: "/opt/it's/bin/dagu"},
		{home: "txe", want: filepath.Join(cwd, "txe", "bin", "dagu"), binary: filepath.Join(cwd, "txe", "bin", "dagu")},
	} {
		t.Run(tc.home, func(t *testing.T) {
			cmd := exec.Command(bash, "-c", `set -euo pipefail; . "$1"; channel_next_steps https://hub.example`, "bash", lib)
			cmd.Dir = cwd
			cmd.Env = []string{"HOME=" + cwd, "TXE_DAGU_HOME=" + tc.home, "PATH=/usr/bin:/bin"}
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, string(out))
			lines := strings.Split(string(out), "\n")
			require.Greater(t, len(lines), 2)
			assert.Equal(t, "  "+tc.want+" txe login --hub https://hub.example", lines[1])

			// A shell reads the line back into exactly the binary and its arguments.
			words := exec.Command(bash, "-c", `printf '%s\n' `+strings.TrimSpace(lines[1]))
			words.Env = []string{"PATH=/usr/bin:/bin"}
			parsed, err := words.Output()
			require.NoError(t, err)
			assert.Equal(t, tc.binary+"\ntxe\nlogin\n--hub\nhttps://hub.example\n", string(parsed))
		})
	}
}
