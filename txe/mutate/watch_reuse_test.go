//go:build !windows

// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package mutate_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reuseSimulator runs the runner's main() with one path disguised (TXE-8535). Every lstat of that
// path, and every scandir entry stat of it, reports the inode the path had the first time it was
// looked at: the stand-in for a filesystem that hands a freed inode straight back, as ext4 does
// (on remote-dev, rmtree then mkdir of a directory under ~ got its inode back on the first try).
// APFS never reuses an inode number and Linux tmpfs rarely does, so the reuse is simulated rather
// than forced. With "nobirth" the path also reports no birth time, through either the stat result
// or the runner's statx reader, as on a filesystem that records none. Every other path, and every
// other field, is what the OS reports.
const reuseSimulator = `
import importlib.util, os, sys
script, target, nobirth = sys.argv[1], sys.argv[2], sys.argv[3] == "nobirth"
spec = importlib.util.spec_from_file_location("ms", script)
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
real_lstat, real_scandir, first = os.lstat, os.scandir, {}
HIDDEN = ("st_atime", "st_mtime", "st_ctime", "st_atime_ns", "st_mtime_ns", "st_ctime_ns", "st_blksize",
          "st_blocks", "st_rdev", "st_flags", "st_gen", "st_birthtime", "st_birthtime_ns")
def disguise(path, st):
    if not isinstance(path, (str, os.PathLike)) or os.fspath(path) != target:
        return st
    first.setdefault("ino", st.st_ino)
    seq = list(st[:10]); seq[1] = first["ino"]
    hidden = {n: getattr(st, n) for n in HIDDEN if hasattr(st, n) and not (nobirth and n.startswith("st_birthtime"))}
    return os.stat_result(seq, hidden)
class Entry:
    def __init__(self, e): self._e, self.name, self.path = e, e.name, e.path
    def stat(self, *, follow_symlinks=True): return disguise(self.path, self._e.stat(follow_symlinks=follow_symlinks))
    def __getattr__(self, n): return getattr(self._e, n)
class Scan:
    def __init__(self, *a, **k): self._it = real_scandir(*a, **k)
    def __enter__(self): return self
    def __exit__(self, *x): self._it.close()
    def __iter__(self): return self
    def __next__(self): return Entry(next(self._it))
    def close(self): self._it.close()
os.lstat = lambda p, *a, **k: disguise(p, real_lstat(p, *a, **k))
os.scandir = Scan
statx = getattr(ms, "statx_birth", None)
if nobirth and statx is not None:
    ms.statx_birth = lambda p: None if os.fspath(p) == target else statx(p)
sys.exit(ms.main(sys.argv[4:]))
`

// reuseFixture is a fixture with its own HOME (root/fixture-home, holding the given entries) and
// GOPATH (the fake one above the fake module cache), and a fake docker that runs effect, with
// modcache, gocache and home bound, on every run.
func reuseFixture(t *testing.T, homeEntries []string, effect string) (fixture, string) {
	t.Helper()
	f := newFixture(t, passingCheck)
	require.NoError(t, os.MkdirAll(filepath.Join(f.modcache, "cache", "download", "example.com"), 0o755))
	home := filepath.Join(f.root, "fixture-home")
	require.NoError(t, os.Mkdir(home, 0o755))
	for _, e := range homeEntries {
		require.NoError(t, os.WriteFile(filepath.Join(home, e), []byte("x\n"), 0o644))
	}
	// The effect deletes only below this test's own t.TempDir(): it refuses any other home.
	bind := fmt.Sprintf("modcache, gocache, home = %q, %q, %q\nassert home.endswith('/fixture-home') and home.startswith(%q)\n",
		f.modcache, f.gocache, home, f.root)
	f.docker = fakeDocker(t, f.root, f.log, bind+effect)
	resolved, err := filepath.EvalSymlinks(home)
	require.NoError(t, err)
	return f, resolved
}

// simulate runs one mutant through reuseSimulator, disguising target, with HOME and GOPATH set to
// the fixture's own.
func (f fixture) simulate(t *testing.T, target string, nobirth bool) outcome {
	t.Helper()
	report := filepath.Join(f.root, "report.json")
	birth := "birth"
	if nobirth {
		birth = "nobirth"
	}
	args := []string{"-I", "-B", "-c", reuseSimulator, script(t, "mutate-sandboxed.py"), target, birth,
		"--mutants", f.mutants(t, []map[string]any{cleanupMutant}), "--tree", f.tree,
		"--shared-modcache", f.modcache, "--shared-gocache", f.gocache, "--workdir-root", f.workRoot,
		"--docker", f.docker, "--no-seed", "--report", report, "--timeout", "60", "--image", "fixture-image",
		"--", "sh", "check.sh"}
	cmd := exec.Command(python(t), args...)
	cmd.Env = append(os.Environ(), "HOME="+filepath.Join(f.root, "fixture-home"),
		"GOPATH="+filepath.Dir(filepath.Dir(f.modcache)))
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	o := outcome{stdout: out.String(), stderr: errb.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		o.code = ee.ExitCode()
	} else {
		require.NoError(t, err)
	}
	return o
}

const recreateHome = "import shutil\nshutil.rmtree(home)\nos.mkdir(home)\n"

// A watched directory deleted and recreated, with its inode handed back, is exit 3 (TXE-8535, the
// TXE-7547 class): through the top-level entries it held when no birth time is reported, through
// its birth time when it held none, and for an entry directly inside a shared cache through that
// entry's birth time.
func TestAlarmOnRecreateWithReusedInode(t *testing.T) {
	// Subtest names carry no comma: t.TempDir() embeds them, and the runner refuses a work
	// directory docker's --mount value cannot carry.
	t.Run("HOME with entries and no birth time", func(t *testing.T) {
		f, home := reuseFixture(t, []string{".profile", "notes"}, recreateHome)
		o := f.simulate(t, home, true)
		require.Equal(t, 3, o.code, o.stdout+o.stderr)
		assert.Contains(t, o.stderr, "SHARED STATE CHANGED")
		assert.Contains(t, o.stderr, "after baseline")
		assert.Contains(t, o.stderr, "top level of HOME")
		// The disguise held: HOME's own identity matched, so only the top-level check saw it.
		assert.NotContains(t, o.stderr, "  HOME: ")
	})
	t.Run("empty HOME with birth time", func(t *testing.T) {
		f, home := reuseFixture(t, nil, recreateHome)
		o := f.simulate(t, home, false)
		require.Equal(t, 3, o.code, o.stdout+o.stderr)
		assert.Contains(t, o.stderr, "SHARED STATE CHANGED")
		assert.Contains(t, o.stderr, "  HOME: ")
	})
	t.Run("shared cache entry with birth time", func(t *testing.T) {
		f, _ := reuseFixture(t, []string{".profile"},
			"import shutil\ne = os.path.join(modcache, 'cache', 'download', 'example.com')\nshutil.rmtree(e)\nos.mkdir(e)\n")
		entry, err := filepath.EvalSymlinks(filepath.Join(f.modcache, "cache", "download", "example.com"))
		require.NoError(t, err)
		o := f.simulate(t, entry, false)
		require.Equal(t, 3, o.code, o.stdout+o.stderr)
		assert.Contains(t, o.stderr, "entries of GOMODCACHE/cache/download")
	})
}

// The top-level check fires only when nothing the directory held survives: HOME gaining an entry
// and losing one of the others during a run, with no inode disguised, is not an alarm.
func TestOrdinaryHomeChangesAreFine(t *testing.T) {
	f, _ := reuseFixture(t, []string{".profile", "notes", "scratch"},
		"p = os.path.join(home, 'scratch')\nos.path.exists(p) and os.remove(p)\nopen(os.path.join(home, 'new-%d' % os.getpid()), 'w').write('x')\n")
	o := f.simulate(t, "/nonexistent-target", true)
	assert.Equal(t, 0, o.code, o.stdout+o.stderr)
}
