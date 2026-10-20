// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package developer_test exercises txe/developer/install.sh against a stub
// dagu: the script's own decisions (where the binary, wrapper and links go,
// and what it leaves alone), not the skill or sign-in, which dagu owns.
package developer_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubDagu answers "version" and the two skill commands the way dagu does,
// for one skill revision: install unpacks it under the TXE home and points
// "current" at it; status fails unless every location resolves to it.
const stubDagu = `#!/bin/sh
rev=rev-%s
case "$1" in
version) echo %s; exit 0 ;;
txe) shift ;;
*) exit 2 ;;
esac
# The wrapper passes the developer store first; record what reached us.
mkdir -p "$TXE_DAGU_HOME" && echo "$*" >> "$TXE_DAGU_HOME/stub-args"
while [ $# -gt 0 ]; do case "$1" in --contexts-dir|--data-dir) shift 2 ;; *) break ;; esac; done
case "$1 $2" in
"skill install")
  mkdir -p "$TXE_DAGU_HOME/skill/$rev" && echo "$rev" > "$TXE_DAGU_HOME/skill/$rev/REVISION"
  ln -sfn "$rev" "$TXE_DAGU_HOME/skill/current" ;;
"skill status")
  shift 2; bad=0
  while [ $# -gt 0 ]; do
    [ "$1" = --link ] && { [ "$(cat "$2/txe-dagu-jobs/REVISION" 2>/dev/null)" = "$rev" ] && echo "ok    $2" || { echo "STALE $2"; bad=1; }; shift; }
    shift
  done
  exit $bad ;;
esac
`

type devEnv struct {
	t                                 *testing.T
	home, txeHome, cliRoot, linkDir   string
	canon                             string
}

func newDevEnv(t *testing.T) *devEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the developer install runs on macOS and Linux")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	e := &devEnv{t: t, home: home,
		txeHome: filepath.Join(home, ".local/share/txe-dagu"), cliRoot: filepath.Join(home, ".local/share/txe-dagu-cli"),
		linkDir: filepath.Join(home, ".local/bin"), canon: filepath.Join(home, ".coding_skills")}
	for _, d := range []string{".claude", ".claude2", ".codex", ".codex3", ".coding_skills"} {
		require.NoError(t, os.MkdirAll(filepath.Join(home, d), 0o755))
	}
	return e
}

// stub writes a stub dagu reporting version and skill revision.
func (e *devEnv) stub(name, version, rev string) string {
	e.t.Helper()
	p := filepath.Join(e.home, "builds", name)
	require.NoError(e.t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(e.t, os.WriteFile(p, []byte(strings.ReplaceAll(strings.Replace(stubDagu, "%s", rev, 1), "%s", version)), 0o755)) //nolint:gosec // test stub
	return p
}

func (e *devEnv) run(args ...string) (string, error) {
	e.t.Helper()
	bash, err := exec.LookPath("bash")
	require.NoError(e.t, err)
	script, err := filepath.Abs("install.sh")
	require.NoError(e.t, err)
	cmd := exec.Command(bash, append([]string{script}, args...)...) //nolint:gosec // the script under test
	cmd.Env = []string{"HOME=" + e.home, "PATH=" + e.linkDir + ":/usr/bin:/bin", "TXE_DAGU_HOME=" + e.txeHome}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	return out.String(), err
}

func (e *devEnv) resolves(entry string) string {
	e.t.Helper()
	p, err := filepath.EvalSymlinks(entry)
	require.NoError(e.t, err, entry)
	return p
}

func TestInstallLinksEveryProfileAndKeepsTheWorkers(t *testing.T) {
	e := newDevEnv(t)
	// The worker's own binary and PATH link, as txe/worker/install.sh leaves them.
	workerBin := filepath.Join(e.txeHome, "bin", "dagu")
	require.NoError(t, os.MkdirAll(filepath.Dir(workerBin), 0o700))
	require.NoError(t, os.WriteFile(workerBin, []byte("#!/bin/sh\necho 2.18.2-txe.10\n"), 0o755)) //nolint:gosec // test stub
	require.NoError(t, os.MkdirAll(e.linkDir, 0o755))
	require.NoError(t, os.Symlink(workerBin, filepath.Join(e.linkDir, "dagu")))
	// Someone's own copy of the skill in one profile.
	custom := filepath.Join(e.home, ".codex3", "skills", "txe-dagu-jobs")
	require.NoError(t, os.MkdirAll(custom, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(custom, "NOTES"), []byte("mine"), 0o644)) //nolint:gosec // test file

	out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
	// The custom copy is not this binary's revision, so the readback fails,
	// and it is kept as it was.
	require.Error(t, err, out)
	assert.Contains(t, out, custom+" is not a link to this skill; left as it is")
	assert.Contains(t, out, "STALE "+filepath.Join(e.home, ".codex3", "skills"))
	assert.FileExists(t, filepath.Join(custom, "NOTES"))

	// The binary, the wrapper and dagu on PATH; the worker's binary untouched.
	bin := filepath.Join(e.cliRoot, "bin", "dagu-2.18.2-txe.11")
	assert.FileExists(t, bin)
	link, err := os.Readlink(filepath.Join(e.linkDir, "dagu"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(e.cliRoot, "bin", "dagu"), link)
	worker, err := os.ReadFile(workerBin)
	require.NoError(t, err)
	assert.Contains(t, string(worker), "2.18.2-txe.10")

	// Every other profile reaches the unpacked skill: Claude and Codex homes
	// through ~/.coding_skills, and the directory Codex reads.
	current := e.resolves(filepath.Join(e.txeHome, "skill", "current"))
	for _, entry := range []string{
		".coding_skills/txe-dagu-jobs", ".claude/skills/txe-dagu-jobs", ".claude2/skills/txe-dagu-jobs",
		".codex/skills/txe-dagu-jobs", ".agents/skills/txe-dagu-jobs",
	} {
		assert.Equal(t, current, e.resolves(filepath.Join(e.home, entry)), entry)
	}
	target, err := os.Readlink(filepath.Join(e.home, ".codex", "skills", "txe-dagu-jobs"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(e.canon, "txe-dagu-jobs"), target)

	// The wrapper gives txe commands the developer's store and nothing else.
	args, err := os.ReadFile(filepath.Join(e.txeHome, "stub-args"))
	require.NoError(t, err)
	assert.Contains(t, string(args), "--contexts-dir "+filepath.Join(e.cliRoot, "client", "data", "contexts")+" --data-dir "+filepath.Join(e.cliRoot, "client", "data")+" skill install")

	// Once the custom copy is moved away, a second run completes, and
	// --check agrees without changing anything.
	require.NoError(t, os.RemoveAll(custom))
	out, err = e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
	require.NoError(t, err, out)
	assert.Contains(t, out, "dagu -> "+filepath.Join(e.cliRoot, "bin", "dagu")+", version 2.18.2-txe.11")
	out, err = e.run("--check")
	require.NoError(t, err, out)
	assert.Contains(t, out, "ok.")

	// An upgrade moves every profile with it.
	out, err = e.run("--tag", "txe-v2.18.2-12", "--binary", e.stub("dagu-12", "2.18.2-txe.12", "c"))
	require.NoError(t, err, out)
	assert.FileExists(t, bin, "earlier versions are kept")
	assert.Equal(t, e.resolves(filepath.Join(e.txeHome, "skill", "current")), e.resolves(filepath.Join(e.home, ".codex", "skills", "txe-dagu-jobs")))
}

func TestInstallRefusals(t *testing.T) {
	t.Run("ABinaryOfAnotherVersion", func(t *testing.T) {
		e := newDevEnv(t)
		out, err := e.run("--tag", "txe-v2.18.2-12", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.Error(t, err)
		assert.Contains(t, out, "says it is version '2.18.2-txe.11', not 2.18.2-txe.12")
		assert.NoDirExists(t, filepath.Join(e.cliRoot, "bin"))
	})

	t.Run("ADifferentFileUnderTheSameVersion", func(t *testing.T) {
		e := newDevEnv(t)
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.NoError(t, err, out)
		out, err = e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("other-11", "2.18.2-txe.11", "z"))
		require.Error(t, err)
		assert.Contains(t, out, "already exists and differs from this build")
	})

	// A dagu on PATH that is neither this install's link nor the worker's is
	// someone else's: it is named and kept, and the readback fails.
	t.Run("SomeoneElsesDaguOnPath", func(t *testing.T) {
		e := newDevEnv(t)
		require.NoError(t, os.MkdirAll(e.linkDir, 0o755))
		mine := filepath.Join(e.linkDir, "dagu")
		require.NoError(t, os.WriteFile(mine, []byte("#!/bin/sh\necho mine\n"), 0o755)) //nolint:gosec // test stub
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.Error(t, err)
		assert.Contains(t, out, "not linked: "+mine+" is not this install's link nor the worker's")
		data, err := os.ReadFile(mine)
		require.NoError(t, err)
		assert.Equal(t, "#!/bin/sh\necho mine\n", string(data))
	})

	t.Run("BadTag", func(t *testing.T) {
		e := newDevEnv(t)
		out, err := e.run("--tag", "v2.18.2", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.Error(t, err)
		assert.Contains(t, out, "--tag must be txe-v<major>.<minor>.<patch>-<n>")
	})
}
