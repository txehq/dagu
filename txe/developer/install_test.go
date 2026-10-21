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
rev=rev-@REV@
while [ $# -gt 0 ]; do case "$1" in --help|-h|--*=*) shift ;; --*|-?) shift 2 ;; *) break ;; esac; done
case "$1" in
version) echo @VERSION@; exit 0 ;;
txe) shift ;;
*) exit 2 ;;
esac
# The wrapper passes the developer store first; record what reached us.
mkdir -p "$TXE_DAGU_HOME" && { for a in "$@"; do printf '[%s]' "$a"; done; echo; } >> "$TXE_DAGU_HOME/stub-args"
# Like dagu, any txe command opens the context store it is given, creating it,
# and writes a base configuration into its Dagu home (the TXE home's client
# when none is given).
home="$TXE_DAGU_HOME/client"; prev=""
for a in "$@"; do
  [ "$prev" = --contexts-dir ] && mkdir -p "$a"
  [ "$prev" = --dagu-home ] && home=$a
  prev=$a
done
mkdir -p "$home" && touch "$home/base.yaml"
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
	t                               *testing.T
	home, txeHome, cliRoot, linkDir string
	canon                           string
	env                             []string
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
	require.NoError(e.t, os.WriteFile(p, []byte(strings.NewReplacer("@REV@", rev, "@VERSION@", version).Replace(stubDagu)), 0o755)) //nolint:gosec // test stub
	return p
}

func (e *devEnv) run(args ...string) (string, error) {
	e.t.Helper()
	bash, err := exec.LookPath("bash")
	require.NoError(e.t, err)
	script, err := filepath.Abs("install.sh")
	require.NoError(e.t, err)
	cmd := exec.Command(bash, append([]string{script}, args...)...) //nolint:gosec // the script under test
	cmd.Env = append([]string{"HOME=" + e.home, "PATH=" + e.linkDir + ":/usr/bin:/bin", "TXE_DAGU_HOME=" + e.txeHome}, e.env...)
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
	assert.Contains(t, out, custom+" is not a link to "+filepath.Join(e.canon, "txe-dagu-jobs")+"; left as it is")
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

	// The skill command was given a store of its own, never the developer's
	// or the machine's.
	args, err := os.ReadFile(filepath.Join(e.txeHome, "stub-args"))
	require.NoError(t, err)
	assert.Contains(t, string(args), "[skill][install][--dagu-home]")
	assert.NotContains(t, string(args), filepath.Join(e.cliRoot, "client"))
	assert.NotContains(t, string(args), filepath.Join(e.txeHome, "client"))
	assert.NoDirExists(t, filepath.Join(e.txeHome, "client"), "the skill commands wrote nothing into the machine's store home")

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
		assert.Contains(t, out, "already exists and is not this build")
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

// wrapperArgs runs the installed wrapper and returns the arguments the stub
// binary received.
func (e *devEnv) wrapperArgs(args ...string) string {
	e.t.Helper()
	argsFile := filepath.Join(e.txeHome, "stub-args")
	_ = os.Remove(argsFile)
	cmd := exec.Command(filepath.Join(e.cliRoot, "bin", "dagu"), args...) //nolint:gosec // the wrapper under test
	cmd.Env = []string{"HOME=" + e.home, "PATH=/usr/bin:/bin", "TXE_DAGU_HOME=" + e.txeHome}
	out, _ := cmd.CombinedOutput()
	data, err := os.ReadFile(argsFile)
	if err != nil {
		return "(no txe call) " + string(out)
	}
	return strings.TrimSpace(string(data))
}

// brackets renders arguments the way the stub records them.
func brackets(args ...string) string {
	var b strings.Builder
	for _, a := range args {
		b.WriteString("[" + a + "]")
	}
	return b.String()
}

// The wrapper gives a dagu txe command the developer's store, whatever flags
// come before it, and leaves every other command and every argument as it is.
func TestWrapperFindsTheTXECommand(t *testing.T) {
	e := newDevEnv(t)
	out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
	require.NoError(t, err, out)
	store := filepath.Join(e.cliRoot, "client", "data")
	flags := []string{"--contexts-dir", filepath.Join(store, "contexts"), "--data-dir", store}
	with := func(rest ...string) string { return brackets(append(append([]string{}, flags...), rest...)...) }
	assert.Equal(t, with("whoami", "--json"), e.wrapperArgs("txe", "whoami", "--json"))
	assert.Equal(t, with("whoami"), e.wrapperArgs("--context", "txe", "txe", "whoami"))
	assert.Equal(t, with("whoami"), e.wrapperArgs("--context=txe", "txe", "whoami"))
	// Any flag before the subcommand, as dagu's parser reads it.
	assert.Equal(t, with("whoami"), e.wrapperArgs("--config", "/tmp/empty.yaml", "txe", "whoami"))
	assert.Equal(t, with("whoami"), e.wrapperArgs("-c", "/tmp/empty.yaml", "txe", "whoami"))
	// Spaces and empty arguments arrive as they were given.
	assert.Equal(t, with("register", "-f", "my job.yaml", "", "x"), e.wrapperArgs("txe", "register", "-f", "my job.yaml", "", "x"))
	// "txe" as an argument of another command is not the txe command.
	assert.Contains(t, e.wrapperArgs("start", "txe"), "(no txe call)")
	// Enrolment is the machine's: it keeps the machine's own store, so the
	// hub it records is the one this machine's job steps reach (TXE-4734).
	assert.Equal(t, brackets("enrol", "--client-id", "w"), e.wrapperArgs("txe", "enrol", "--client-id", "w"))
	assert.Equal(t, brackets("enrol", "check"), e.wrapperArgs("--context", "txe", "txe", "enrol", "check"))
	assert.Equal(t, brackets("--session", "s1", "enrol"), e.wrapperArgs("txe", "--session", "s1", "enrol"))
	// A job key or argument named enrol is not the enrol command.
	assert.Equal(t, with("inspect", "enrol"), e.wrapperArgs("txe", "inspect", "enrol"))
	// txe's boolean flags take no value, either way round.
	assert.Equal(t, brackets("--quiet", "enrol", "--client-id", "w"), e.wrapperArgs("txe", "--quiet", "enrol", "--client-id", "w"))
	assert.Equal(t, with("-q", "inspect", "enrol"), e.wrapperArgs("txe", "-q", "inspect", "enrol"))
	assert.Equal(t, brackets("--cpu-profile", "enrol"), e.wrapperArgs("txe", "--cpu-profile", "enrol"))
}

// The review's cases: nothing at a temporary name is followed, the
// developer's root cannot be the worker's, --check writes nothing, a quote in
// the root is kept, a home that is a link is followed, the wrapper is checked
// and a link pinned to one revision is not the managed one.
func TestInstallSafety(t *testing.T) {
	t.Run("NoFixedTemporaryName", func(t *testing.T) {
		e := newDevEnv(t)
		victim := filepath.Join(e.home, "victim")
		require.NoError(t, os.WriteFile(victim, []byte("keep"), 0o600))
		require.NoError(t, os.MkdirAll(filepath.Join(e.cliRoot, "bin"), 0o755))
		require.NoError(t, os.MkdirAll(e.linkDir, 0o755))
		for _, p := range []string{filepath.Join(e.cliRoot, "bin", "dagu.tmp"), filepath.Join(e.cliRoot, "bin", "dagu-2.18.2-txe.11.tmp"), filepath.Join(e.linkDir, "dagu.tmp")} {
			require.NoError(t, os.Symlink(victim, p))
		}
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.NoError(t, err, out)
		data, err := os.ReadFile(victim)
		require.NoError(t, err)
		assert.Equal(t, "keep", string(data))
	})

	t.Run("RootInsideTheTXEHome", func(t *testing.T) {
		e := newDevEnv(t)
		e.env = []string{"TXE_DAGU_CLI_ROOT=" + e.txeHome}
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.Error(t, err)
		assert.Contains(t, out, "are the same place or inside each other")
		assert.NoFileExists(t, filepath.Join(e.txeHome, "bin", "dagu"))
	})

	t.Run("ClientLinkedIntoTheTXEHome", func(t *testing.T) {
		e := newDevEnv(t)
		require.NoError(t, os.MkdirAll(filepath.Join(e.txeHome, "client"), 0o700))
		require.NoError(t, os.MkdirAll(e.cliRoot, 0o755))
		require.NoError(t, os.Symlink(filepath.Join(e.txeHome, "client"), filepath.Join(e.cliRoot, "client")))
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.Error(t, err)
		assert.Contains(t, out, "the worker's binary and store must stay apart from the developer's")
	})

	t.Run("CheckWritesNothing", func(t *testing.T) {
		e := newDevEnv(t)
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.NoError(t, err, out)
		require.NoError(t, os.RemoveAll(filepath.Join(e.cliRoot, "client")))
		out, err = e.run("--check")
		require.NoError(t, err, out)
		assert.NoDirExists(t, filepath.Join(e.cliRoot, "client"))
		assert.NoDirExists(t, filepath.Join(e.txeHome, "client"))
	})

	t.Run("BinDirectoriesSharedElsewhere", func(t *testing.T) {
		e := newDevEnv(t)
		shared := filepath.Join(e.home, "mnt", "dagu-bin")
		require.NoError(t, os.MkdirAll(shared, 0o755))
		require.NoError(t, os.MkdirAll(e.txeHome, 0o700))
		require.NoError(t, os.MkdirAll(e.cliRoot, 0o755))
		require.NoError(t, os.Symlink(shared, filepath.Join(e.txeHome, "bin")))
		require.NoError(t, os.Symlink(shared, filepath.Join(e.cliRoot, "bin")))
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.Error(t, err)
		assert.Contains(t, out, "must stay apart from the developer's")
		entries, err := os.ReadDir(shared)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("AWrapperPathThatIsALinkToADirectory", func(t *testing.T) {
		e := newDevEnv(t)
		elsewhere := filepath.Join(e.home, "elsewhere")
		require.NoError(t, os.MkdirAll(elsewhere, 0o755))
		require.NoError(t, os.MkdirAll(filepath.Join(e.cliRoot, "bin"), 0o755))
		require.NoError(t, os.Symlink(elsewhere, filepath.Join(e.cliRoot, "bin", "dagu")))
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.NoError(t, err, out)
		entries, err := os.ReadDir(elsewhere)
		require.NoError(t, err)
		assert.Empty(t, entries, "nothing was written through the link")
		info, err := os.Lstat(filepath.Join(e.cliRoot, "bin", "dagu"))
		require.NoError(t, err)
		assert.True(t, info.Mode().IsRegular(), "the link itself was replaced by the wrapper")
	})

	t.Run("AWrapperWithAnotherBody", func(t *testing.T) {
		e := newDevEnv(t)
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.NoError(t, err, out)
		wrapper := filepath.Join(e.cliRoot, "bin", "dagu")
		data, err := os.ReadFile(wrapper)
		require.NoError(t, err)
		// Same marker, binary and store lines; the dispatch removed.
		body := strings.Replace(string(data), `--contexts-dir "$store/contexts" --data-dir "$store"`, "", 1)
		require.NotEqual(t, string(data), body)
		require.NoError(t, os.WriteFile(wrapper, []byte(body), 0o755)) //nolint:gosec // test stub
		out, err = e.run("--check")
		require.Error(t, err)
		assert.Contains(t, out, "missing or not this script's: "+wrapper)
	})

	t.Run("DataDirectoriesSharedElsewhere", func(t *testing.T) {
		e := newDevEnv(t)
		shared := filepath.Join(e.home, "mnt", "dagu-data")
		require.NoError(t, os.MkdirAll(shared, 0o700))
		require.NoError(t, os.MkdirAll(filepath.Join(e.txeHome, "client"), 0o700))
		require.NoError(t, os.MkdirAll(filepath.Join(e.cliRoot, "client"), 0o700))
		require.NoError(t, os.Symlink(shared, filepath.Join(e.txeHome, "client", "data")))
		require.NoError(t, os.Symlink(shared, filepath.Join(e.cliRoot, "client", "data")))
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.Error(t, err)
		assert.Contains(t, out, "must stay apart from the developer's")
	})

	// The wrapper's binary is the one installed for its tag, and says so: a
	// binary of another release swapped in under the same name fails.
	t.Run("ABinaryOfAnotherReleaseUnderTheTagsName", func(t *testing.T) {
		e := newDevEnv(t)
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.NoError(t, err, out)
		bin := filepath.Join(e.cliRoot, "bin", "dagu-2.18.2-txe.11")
		other, err := os.ReadFile(e.stub("dagu-12", "2.18.2-txe.12", "b"))
		require.NoError(t, err)
		require.NoError(t, os.Remove(bin))
		require.NoError(t, os.WriteFile(bin, other, 0o755)) //nolint:gosec // test stub
		out, err = e.run("--check")
		require.Error(t, err)
		assert.Contains(t, out, "missing or not this script's")
	})

	t.Run("PathThroughALinkedDirectory", func(t *testing.T) {
		e := newDevEnv(t)
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.NoError(t, err, out)
		alias := filepath.Join(e.home, "bin")
		require.NoError(t, os.Symlink(e.linkDir, alias))
		e.env = []string{"PATH=" + alias + ":/usr/bin:/bin"}
		out, err = e.run("--check")
		require.NoError(t, err, out)
	})

	t.Run("AQuoteInTheRoot", func(t *testing.T) {
		e := newDevEnv(t)
		e.cliRoot = filepath.Join(e.home, "Connor's Disk", "txe-dagu-cli")
		e.env = []string{"TXE_DAGU_CLI_ROOT=" + e.cliRoot}
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.NoError(t, err, out)
		store := filepath.Join(e.cliRoot, "client", "data")
		assert.Equal(t, brackets("--contexts-dir", filepath.Join(store, "contexts"), "--data-dir", store, "whoami"), e.wrapperArgs("txe", "whoami"))
	})

	t.Run("AHomeThatIsALink", func(t *testing.T) {
		e := newDevEnv(t)
		real := filepath.Join(e.home, "profiles", "claude-work")
		require.NoError(t, os.MkdirAll(real, 0o755))
		require.NoError(t, os.Symlink(real, filepath.Join(e.home, ".claude7")))
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.NoError(t, err, out)
		target, err := os.Readlink(filepath.Join(real, "skills", "txe-dagu-jobs"))
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(e.canon, "txe-dagu-jobs"), target)
	})

	t.Run("AWrapperThatIsNotTheScripts", func(t *testing.T) {
		e := newDevEnv(t)
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.NoError(t, err, out)
		wrapper := filepath.Join(e.cliRoot, "bin", "dagu")
		require.NoError(t, os.Remove(wrapper))
		data, err := os.ReadFile(filepath.Join(e.cliRoot, "bin", "dagu-2.18.2-txe.11"))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(wrapper, data, 0o755)) //nolint:gosec // test stub
		out, err = e.run("--check")
		require.Error(t, err)
		assert.Contains(t, out, "missing or not this script's: "+wrapper)
	})

	t.Run("ALinkPinnedToOneRevision", func(t *testing.T) {
		e := newDevEnv(t)
		out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.NoError(t, err, out)
		entry := filepath.Join(e.home, ".codex", "skills", "txe-dagu-jobs")
		require.NoError(t, os.Remove(entry))
		require.NoError(t, os.Symlink(filepath.Join(e.txeHome, "skill", "rev-b"), entry))
		out, err = e.run("--check")
		require.Error(t, err)
		assert.Contains(t, out, entry+" is not the link to "+filepath.Join(e.canon, "txe-dagu-jobs"))
		out, err = e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
		require.Error(t, err)
		assert.Contains(t, out, entry+" is not a link to")
	})
}

// A profile with a name that is not a number (.claude-review) is a profile,
// and links this script made follow ~/.coding_skills appearing and going away.
func TestInstallProfilesAndMigration(t *testing.T) {
	e := newDevEnv(t)
	require.NoError(t, os.MkdirAll(filepath.Join(e.home, ".claude-review"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(e.home, ".claude.json"), []byte("{}"), 0o600))
	require.NoError(t, os.RemoveAll(e.canon))
	bin := e.stub("dagu-11", "2.18.2-txe.11", "b")

	out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", bin)
	require.NoError(t, err, out)
	current := filepath.Join(e.txeHome, "skill", "current")
	review := filepath.Join(e.home, ".claude-review", "skills", "txe-dagu-jobs")
	target, err := os.Readlink(review)
	require.NoError(t, err)
	assert.Equal(t, current, target, "with no ~/.coding_skills, profiles link to the unpacked skill")
	assert.NoFileExists(t, filepath.Join(e.home, ".claude.json", "skills"))

	// ~/.coding_skills appears: the script's own links move to it.
	require.NoError(t, os.MkdirAll(e.canon, 0o755))
	out, err = e.run("--tag", "txe-v2.18.2-11", "--binary", bin)
	require.NoError(t, err, out)
	assert.Contains(t, out, "(was "+current+")")
	target, err = os.Readlink(review)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(e.canon, "txe-dagu-jobs"), target)

	// It goes away again: they move back.
	require.NoError(t, os.RemoveAll(e.canon))
	out, err = e.run("--tag", "txe-v2.18.2-11", "--binary", bin)
	require.NoError(t, err, out)
	target, err = os.Readlink(review)
	require.NoError(t, err)
	assert.Equal(t, current, target)
	out, err = e.run("--check")
	require.NoError(t, err, out)
}

// Codex reads ~/.agents/skills as well as its home's skills: a custom
// CODEX_HOME, with no ~/.codex, ~/.agents or codex on PATH, still gets both.
func TestInstallLinksAgentsForACustomCodexHome(t *testing.T) {
	e := newDevEnv(t)
	require.NoError(t, os.RemoveAll(filepath.Join(e.home, ".codex")))
	require.NoError(t, os.RemoveAll(filepath.Join(e.home, ".codex3")))
	custom := filepath.Join(e.home, "profiles", "codex-work")
	require.NoError(t, os.MkdirAll(custom, 0o755))
	e.env = []string{"CODEX_HOME=" + custom}
	out, err := e.run("--tag", "txe-v2.18.2-11", "--binary", e.stub("dagu-11", "2.18.2-txe.11", "b"))
	require.NoError(t, err, out)
	for _, dir := range []string{filepath.Join(custom, "skills"), filepath.Join(e.home, ".agents", "skills")} {
		target, err := os.Readlink(filepath.Join(dir, "txe-dagu-jobs"))
		require.NoError(t, err, dir)
		assert.Equal(t, filepath.Join(e.canon, "txe-dagu-jobs"), target, dir)
	}
}
