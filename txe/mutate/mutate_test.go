// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package mutate_test tests txe/mutate/mutate-sandboxed.py and its guard hook (TXE-7549).
//
// These tests start no container, download nothing and run no destructive mutant. A fake docker
// records the argv the runner builds and then plays the container on the host, with the run's own
// directory standing in for /work. Every cache a test touches is a sentinel-only fake under
// t.TempDir(), never the real one. The alarm tests change those fakes from the fake docker itself
// (a test double that stands for a broken boundary), at paths the test names, never from a mutant
// or from an environment variable.
package mutate_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sentinel = ".mutate-sandboxed-fixture-sentinel"

func python(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the runner targets macOS and Linux hosts")
	}
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	return py
}

func script(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(name)
	require.NoError(t, err)
	return p
}

// fakeDocker writes a docker stand-in that appends each argv to log as a JSON line and, for
// `run`, executes the command on the host with only the --env values, /work and /goproxy mapped
// to their mount sources. It keeps a registry of "containers" (log + ".containers", a JSON map of
// id to [name, owner label]): `run` writes the id to --cidfile and registers it until the command
// ends; `inspect` and `rm -f` answer from the registry. An image named "infra-125" exits 125 as
// the daemon would, an image containing "hang" registers and then sleeps, an image containing
// "noexec" exits 0 without running the command, and `image inspect missing` fails. sideEffect,
// when set, is Python run on every `run` before the command: the tests' stand-in for a boundary
// that leaked.
func fakeDocker(t *testing.T, dir, log string, sideEffect ...string) string {
	t.Helper()
	effect := "pass"
	if len(sideEffect) > 0 {
		effect = sideEffect[0]
	}
	src := `#!/usr/bin/env python3
import hashlib, json, os, subprocess, sys, time
LOG = ` + fmt.Sprintf("%q", log) + `
REG = LOG + ".containers"
SECRET_DIR = os.path.join(os.path.dirname(LOG), "host-private")
args = sys.argv[1:]
with open(LOG, "a") as f:
    f.write(json.dumps(args) + "\n")
def reg():
    try:
        return json.load(open(REG))
    except (OSError, ValueError):
        return {}
def save(r):
    json.dump(r, open(REG + ".tmp", "w"))
    os.replace(REG + ".tmp", REG)
if args[:2] == ["image", "inspect"] and args[-1] == "missing":
    sys.exit(1)
if args[:2] == ["image", "inspect"] and "slowinspect" in args[-1]:
    time.sleep(30)
if args[:2] == ["image", "inspect"]:
    print('{"/data":{}}' if "volimage" in args[-1] else "null")
    sys.exit(0)
if args[:1] == ["inspect"]:
    if os.path.exists(LOG + ".slowclean"):
        time.sleep(30)
    r = reg()
    if "{{.State.Running}}" in args and os.path.exists(LOG + ".slowstate"):
        time.sleep(30)
    if os.path.exists(LOG + ".daemondown"):
        print("Cannot connect to the Docker daemon", file=sys.stderr)
        sys.exit(1)
    if args[-1] not in r:
        print("Error: No such object: " + args[-1], file=sys.stderr)
        sys.exit(1)
    if "{{.State.Running}}" in args:
        print("true")  # a registered container is a running one
    else:
        print("/%s %s" % tuple(r[args[-1]]))
    sys.exit(0)
if args[:2] == ["rm", "-f"]:
    if os.path.exists(LOG + ".rmtamper"):  # the stand-in for a boundary failing during cleanup
        with open(open(LOG + ".rmtamper").read().strip(), "a") as fh:
            fh.write("tampered during rm\n")
    if os.path.exists(LOG + ".rmrace"):  # docker's own --rm finishing first: rm fails, the container goes
        r = reg()
        r.pop(args[2], None)
        save(r)
        print("Error response from daemon: removal of container is already in progress", file=sys.stderr)
        sys.exit(1)
    if os.path.exists(LOG + ".rmrace-stays"):  # "in progress", but the container is still there
        print("Error response from daemon: removal of container is already in progress", file=sys.stderr)
        sys.exit(1)
    if os.path.exists(LOG + ".rmfail"):
        print("Error response from daemon: removal failed", file=sys.stderr)
        sys.exit(1)
    r = reg()
    if args[2] not in r:
        sys.exit(1)
    del r[args[2]]
    save(r)
    sys.exit(0)
if not args or args[0] != "run":
    sys.exit(0)
VALUED = {"--log-driver", "--pull", "--memory", "--cpus", "--name", "--network", "--cap-drop", "--security-opt", "--pids-limit",
          "--tmpfs", "--user", "--workdir", "--entrypoint", "--mount", "--env", "--cidfile", "--label"}
i, mounts, env, workdir, name, cidfile, owner = 1, {}, {}, "/", "", "", ""
while i < len(args) and args[i].startswith("--"):
    flag = args[i]
    if flag in VALUED:
        val = args[i + 1]
        i += 2
        if flag == "--mount":
            kv = dict(p.split("=", 1) for p in val.split(",") if "=" in p)
            mounts[kv["target"]] = kv["source"]
        elif flag == "--env":
            k, v = val.split("=", 1)
            env[k] = v
        elif flag == "--workdir":
            workdir = val
        elif flag == "--name":
            name = val
        elif flag == "--cidfile":
            cidfile = val
        elif flag == "--label":
            owner = val.split("=", 1)[1]
    else:
        i += 1
image, cmd = args[i], args[i + 1:]
if image == "infra-125":
    sys.exit(125)
cid = hashlib.sha256(name.encode()).hexdigest()
r = reg()
r[cid] = [name, owner]
save(r)
if cidfile:
    open(cidfile, "w").write(cid)
` + effect + `
if "flood" in image:
    sys.stdout.buffer.write(b"x" * (3 << 20))
    sys.stdout.flush()
    time.sleep(60)
if "fill" in image:
    with open(os.path.join(mounts["/work"], "filler"), "wb") as fh:
        fh.write(os.urandom(3 << 20))
    time.sleep(60)
if "manyfiles" in image:
    for n in range(50):
        open(os.path.join(mounts["/work"], "f%d" % n), "w").close()
    time.sleep(60)
if "lockdir" in image:
    locked = os.path.join(mounts["/work"], "locked")
    os.makedirs(os.path.join(locked, "inner"))
    os.chmod(locked, 0)
    time.sleep(60)
if "truncatelog" in image:
    sys.stdout.buffer.write(b"y" * (3 << 20))
    sys.stdout.flush()
    for name in os.listdir(mounts["/work"]):
        if name.endswith(".log"):
            open(os.path.join(mounts["/work"], name), "w").close()
    time.sleep(60)
if "burst" in image:
    # Writes past both bounds and exits at once, before any polling interval.
    sys.stdout.buffer.write(b"z" * (3 << 20))
    with open(os.path.join(mounts["/work"], "burst"), "wb") as fh:
        fh.write(os.urandom(3 << 20))
    sys.exit(0)
if "swapcache" in image:
    # The baseline replaces its build cache with a link to a host directory outside its mount.
    import shutil as _sh
    gc = os.path.join(mounts["/work"], "sandbox", "gocache")
    _sh.rmtree(gc)
    os.symlink(SECRET_DIR, gc)
if "fifocache" in image:
    os.mkfifo(os.path.join(mounts["/work"], "sandbox", "gocache", "pipe"))
if "nestedlink" in image:
    nested = os.path.join(mounts["/work"], "sandbox", "gocache", "nested")
    if not os.path.lexists(nested):  # later runs inherit it, as a link, through the warm cache
        os.symlink(SECRET_DIR, nested)
if "staysup" in image:
    # Exits as a client but leaves its container registered (still running) after a pass.
    print("ok")
    sys.exit(0)
if "sparsecache" in image:
    sp = os.path.join(mounts["/work"], "sandbox", "gocache", "sparse")
    if not os.path.exists(sp):
        with open(sp, "wb") as fh:
            fh.truncate(64 << 20)  # 64 MiB apparent, nothing allocated
if "selfkill" in image:
    import signal
    os.kill(os.getpid(), signal.SIGKILL)  # the client dies; the "container" stays registered
if "hang" in image:
    time.sleep(120)  # a container whose client is killed stays registered, as a detached one would
if "noexec" in image:
    # Runs nothing: prints the lines the fixture test logs, chosen by whether the copied source
    # carries the cleanup mutant.
    src = os.path.join(mounts.get("/work", "/nonexistent"), "src", "cleanup.go")
    mutated = os.path.exists(src) and "clean" in open(src).read().split("func Cleanup")[-1]
    if mutated:
        print("    cleanup_test.go:13: cleanup returned: <nil>")
        print("    cleanup_test.go:16: GOMODCACHE /work/sandbox/gomodcache after cleanup: exists=false (stat: no such file)")
    else:
        print("    cleanup_test.go:13: cleanup returned: <nil>")
        print("    cleanup_test.go:16: GOMODCACHE /work/sandbox/gomodcache after cleanup: exists=true (<nil>)")
    code = 0
else:
    def host(p):
        for target, source in sorted(mounts.items(), key=lambda kv: -len(kv[0])):
            if p == target or p.startswith(target + "/"):
                return source + p[len(target):]
        return p
    env = {k: host(v.replace("file://", "", 1)) if v.startswith("file:///") else host(v) for k, v in env.items()}
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    code = subprocess.run(cmd, env=env, cwd=host(workdir)).returncode
r = reg()
r.pop(cid, None)
save(r)
sys.exit(code)
`
	p := filepath.Join(dir, "docker")
	require.NoError(t, os.WriteFile(p, []byte(src), 0o755))
	return p
}

// registry reads the fake docker's live containers: id to [name, owner].
func registry(t *testing.T, log string) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(log + ".containers")
	if os.IsNotExist(err) {
		return map[string][]string{}
	}
	require.NoError(t, err)
	var r map[string][]string
	require.NoError(t, json.Unmarshal(raw, &r))
	return r
}

type fixture struct {
	root, tree, modcache, gocache, workRoot, log, docker string
}

// newFixture is a tree whose test is check.sh, and two fake shared caches holding the sentinel.
func newFixture(t *testing.T, check string) fixture {
	t.Helper()
	root := t.TempDir()
	f := fixture{
		root:     root,
		tree:     filepath.Join(root, "tree"),
		modcache: filepath.Join(root, "fake-gopath", "pkg", "mod"),
		gocache:  filepath.Join(root, "fake-gocache"),
		workRoot: filepath.Join(root, "work"),
		log:      filepath.Join(root, "docker.log"),
	}
	for _, d := range []string{f.tree, filepath.Join(f.modcache, "cache", "download"), f.gocache, f.workRoot} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	for _, d := range []string{f.modcache, f.gocache} {
		require.NoError(t, os.WriteFile(filepath.Join(d, sentinel), []byte("fixture\n"), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(f.tree, "check.sh"), []byte(check), 0o755))
	f.docker = fakeDocker(t, root, f.log)
	return f
}

func (f fixture) mutants(t *testing.T, list []map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(list)
	require.NoError(t, err)
	p := filepath.Join(f.root, "mutants.json")
	require.NoError(t, os.WriteFile(p, raw, 0o644))
	return p
}

type outcome struct {
	code           int
	stdout, stderr string
	report         map[string]any
}

func (f fixture) run(t *testing.T, mutants string, extra ...string) outcome {
	t.Helper()
	return f.invoke(t, []string{"--mutants", mutants}, extra...)
}

// diag runs the fixture in --diagnostic mode: no mutant list.
func (f fixture) diag(t *testing.T, extra ...string) outcome {
	t.Helper()
	return f.invoke(t, []string{"--diagnostic"}, extra...)
}

func (f fixture) invoke(t *testing.T, mode []string, extra ...string) outcome {
	t.Helper()
	report := filepath.Join(f.root, "report.json")
	_ = os.Remove(report)
	args := append([]string{"-I", script(t, "mutate-sandboxed.py")}, mode...)
	args = append(append(args, "--tree", f.tree,
		"--shared-modcache", f.modcache, "--shared-gocache", f.gocache, "--workdir-root", f.workRoot,
		"--docker", f.docker, "--no-seed", "--report", report, "--timeout", "60", "--image", "fixture-image"), extra...)
	args = append(args, "--", "sh", "check.sh")
	cmd := exec.Command(python(t), args...)
	cmd.Env = append(os.Environ(), "MUTATE_TEST_CANARY=host-only-value")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	o := outcome{stdout: out.String(), stderr: errb.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		o.code = ee.ExitCode()
	} else {
		require.NoError(t, err)
	}
	if raw, err := os.ReadFile(report); err == nil {
		require.NoError(t, json.Unmarshal(raw, &o.report))
	}
	return o
}

func (o outcome) outcomes() map[string]string {
	m := map[string]string{}
	results, _ := o.report["results"].([]any)
	for _, r := range results {
		r := r.(map[string]any)
		m[r["name"].(string)] = r["outcome"].(string)
	}
	return m
}

func dockerRuns(t *testing.T, log string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(log)
	require.NoError(t, err)
	var runs [][]string
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		var argv []string
		require.NoError(t, json.Unmarshal([]byte(line), &argv))
		if len(argv) > 0 && argv[0] == "run" {
			runs = append(runs, argv)
		}
	}
	return runs
}

// The check passes. The env mutant writes a marker into whatever GOMODCACHE names, where the
// incident's mutant ran `go clean -modcache`; it deletes nothing, and the check still passes.
const passingCheck = "#!/bin/sh\n: CLEANUP\n: GUARD\nexit 0\n"

const marker = "mutant-was-here"

var cleanupMutant = map[string]any{"name": "cleanup reaches the env cache", "file": "check.sh",
	"old": ": CLEANUP", "new": `touch "$GOMODCACHE/` + marker + `"`}

// A mutant that writes to the cache its environment names reaches only the sandbox: the fake
// shared cache and its sentinel are untouched, the mutant survives, and the container got nothing
// from the caller's environment, no HOME, and no host path but its own directory.
func TestSandboxKeepsSharedCache(t *testing.T) {
	f := newFixture(t, passingCheck)
	before, err := os.ReadFile(filepath.Join(f.modcache, sentinel))
	require.NoError(t, err)

	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}))
	require.Equal(t, 0, o.code, o.stderr)
	assert.Equal(t, "SURVIVED", o.outcomes()["cleanup reaches the env cache"])
	assert.Equal(t, "PASSED", o.outcomes()["baseline"])
	assert.Equal(t, "PASSED", o.outcomes()["baseline (after)"])
	after, err := os.ReadFile(filepath.Join(f.modcache, sentinel))
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assert.NoFileExists(t, filepath.Join(f.modcache, marker))
	assert.Equal(t, o.report["identity_before"], o.report["identity_after"])

	live, err := os.ReadFile(filepath.Join(f.tree, "check.sh"))
	require.NoError(t, err)
	assert.Equal(t, passingCheck, string(live), "the live tree is never edited")

	entries, err := os.ReadDir(f.workRoot)
	require.NoError(t, err)
	assert.Empty(t, entries, "the owned work directory is removed after a clean run")

	runs := dockerRuns(t, f.log)
	require.Len(t, runs, 3) // baseline, mutant, baseline after
	workdir := o.report["workdir"].(string)
	for _, argv := range runs {
		joined := strings.Join(argv, " ")
		assert.Contains(t, joined, "--network none")
		assert.Contains(t, joined, "--pull never")
		assert.Contains(t, joined, "--log-driver none", "docker keeps no unbounded copy of the output")
		assert.Contains(t, joined, "--memory 8g")
		assert.Contains(t, joined, "--cpus 4")
		assert.NotContains(t, joined, "--env HOME=", "HOME is never set")
		assert.Contains(t, joined, "--env GOFLAGS=-modcacherw -count=1", "no cached test result is replayed")
		for _, k := range []string{"HTTP_PROXY", "https_proxy", "NO_PROXY", "all_proxy", "FTP_PROXY"} {
			assert.Contains(t, argv, k+"=", "docker's configured proxies are cleared: %s", k)
		}
		assert.Contains(t, joined, "--cap-drop ALL")
		assert.Contains(t, joined, "--read-only")
		assert.NotContains(t, joined, "docker.sock")
		assert.NotContains(t, joined, "host-only-value", "no caller variable reaches the container")
		for i, a := range argv {
			switch a {
			case "--mount":
				src := strings.SplitN(strings.Split(argv[i+1], ",")[1], "=", 2)[1]
				realRoot, err := filepath.EvalSymlinks(f.workRoot)
				require.NoError(t, err)
				realWork := filepath.Join(realRoot, filepath.Base(workdir))
				assert.True(t, strings.HasPrefix(src, realWork+string(os.PathSeparator)), "mount %s outside %s", src, realWork)
			case "--env":
				kv := strings.SplitN(argv[i+1], "=", 2)
				if strings.HasPrefix(kv[1], "/") {
					assert.True(t, strings.HasPrefix(kv[1], "/work/"), "%s points outside the sandbox", argv[i+1])
				}
			}
		}
		for _, name := range []string{"GOPATH", "GOMODCACHE", "GOCACHE", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"} {
			assert.Contains(t, joined, "--env "+name+"=/work/sandbox/")
		}
	}
}

// alarmFixture is a fixture whose fake docker runs sideEffect (Python, with modcache, gocache and
// sentinel bound) on every run: the stand-in for a boundary that leaked.
func alarmFixture(t *testing.T, sideEffect string) fixture {
	t.Helper()
	f := newFixture(t, passingCheck)
	require.NoError(t, os.MkdirAll(filepath.Join(f.modcache, "cache", "download", "example.com"), 0o755))
	bind := fmt.Sprintf("modcache, gocache, sentinel = %q, %q, %q\n", f.modcache, f.gocache, sentinel)
	f.docker = fakeDocker(t, f.root, f.log, bind+sideEffect)
	return f
}

// The alarm fires, with exit 3, a banner, the work directory kept and no verdict, when the fake
// shared cache's sentinel content changes, when an entry inside it is replaced, and when the
// cache directory itself is replaced. The changes come from the fake docker, never a mutant.
func TestAlarmOnSharedChange(t *testing.T) {
	cases := map[string]struct{ effect, want string }{
		"sentinel content": {`open(os.path.join(modcache, sentinel), "w").write("changed\n")`,
			"GOMODCACHE/" + sentinel},
		"entry replaced": {`os.rename(os.path.join(modcache, "cache", "download", "example.com"), os.path.join(modcache, "moved"))`,
			"entries of GOMODCACHE/cache/download"},
		"cache replaced": {`os.rename(gocache, gocache + ".old"); os.mkdir(gocache)`, "GOCACHE"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			// The side effect fires on the baseline's run, so the alarm names the baseline.
			f := alarmFixture(t, c.effect)
			o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}))
			require.Equal(t, 3, o.code, o.stdout+o.stderr)
			assert.Contains(t, o.stderr, "SHARED STATE CHANGED")
			assert.Contains(t, o.stderr, "after baseline")
			assert.Contains(t, o.stderr, c.want)
			assert.Empty(t, o.outcomes(), "a run that touched host state has no verdict")
			assert.DirExists(t, o.report["workdir"].(string))
		})
	}
}

// Entries added to a shared cache during a run (another session filling it) are not an alarm.
func TestNewSharedEntriesAreFine(t *testing.T) {
	f := alarmFixture(t, `open(os.path.join(modcache, "cache", "download", "new-%d" % os.getpid()), "w").write("x")`)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}))
	assert.Equal(t, 0, o.code, o.stdout+o.stderr)
}

// The runner never pulls: an image that is not present locally is refused before anything runs.
func TestMissingImageRefused(t *testing.T) {
	f := newFixture(t, passingCheck)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "missing")
	assert.Equal(t, 2, o.code)
	assert.Contains(t, o.stderr, "never pulls")
	assert.Empty(t, dockerRuns(t, f.log))
}

// A kill must repeat in a new sandbox; one that does not is a finding (exit 5), not a flake.
func TestUnrepeatedKillIsFinding(t *testing.T) {
	f := newFixture(t, passingCheck)
	flag := filepath.Join(f.root, "flaky-once")
	o := f.run(t, f.mutants(t, []map[string]any{
		{"name": "real kill", "file": "check.sh", "old": ": GUARD", "new": "exit 1"},
		{"name": "flaky kill", "file": "check.sh", "old": ": GUARD",
			"new": fmt.Sprintf("[ -e %q ] || { touch %q; exit 1; }", flag, flag)},
	}))
	require.Equal(t, 5, o.code, o.stdout+o.stderr)
	assert.Equal(t, "KILLED", o.outcomes()["real kill"])
	assert.Equal(t, "UNREPEATED-KILL", o.outcomes()["flaky kill"])
	assert.Contains(t, o.stderr, "FINDING: flaky kill: killed once, then SURVIVED alone in a new sandbox")
	assert.Contains(t, o.stdout, "mutants: 1/2 killed")
}

func TestBaselineMustPass(t *testing.T) {
	f := newFixture(t, "#!/bin/sh\n: GUARD\nexit 1\n")
	o := f.run(t, f.mutants(t, []map[string]any{{"name": "m", "file": "check.sh", "old": ": GUARD", "new": "exit 0"}}))
	assert.Equal(t, 4, o.code)
	assert.Equal(t, "FAILED", o.outcomes()["baseline"])
	assert.NotContains(t, o.outcomes(), "m")
}

// docker's own exit codes are a sandbox error, never a kill.
func TestDockerFailureIsNotKill(t *testing.T) {
	f := newFixture(t, passingCheck)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "infra-125")
	assert.Equal(t, 4, o.code, "the baseline cannot run, so no mutant is judged")
	assert.Equal(t, "ERROR", o.outcomes()["baseline"])
}

func TestMutantListRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"occurs twice":   {"name": "m", "file": "check.sh", "old": "exit", "new": "x", "count": 2},
		"missing":        {"name": "m", "file": "check.sh", "old": "nope", "new": "x"},
		"parent path":    {"name": "m", "file": "../check.sh", "old": "exit", "new": "x"},
		"absolute path":  {"name": "m", "file": "/etc/hosts", "old": "localhost", "new": "x"},
		"no change":      {"name": "m", "file": "check.sh", "old": "exit", "new": "exit"},
		"unknown option": {"name": "m", "file": "check.sh", "old": "exit", "new": "x", "env": "keep"},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, passingCheck)
			o := f.run(t, f.mutants(t, []map[string]any{m}))
			assert.Equal(t, 2, o.code, o.stderr)
			assert.Contains(t, o.stderr, "refused")
			raw, err := os.ReadFile(f.log)
			if err == nil {
				assert.NotContains(t, string(raw), `"run"`)
			}
		})
	}
}

// check_mounts and check_workdir refuse any source that is, contains or lies inside protected state.
func TestMountChecks(t *testing.T) {
	root := t.TempDir()
	prog := `
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
root = Path(sys.argv[2])
work = root / "work"; (work / "m1").mkdir(parents=True); (root / "home" / "go").mkdir(parents=True)
forbidden = {"HOME": root / "home", "shared GOMODCACHE": root / "home" / "go"}
def verdict(f):
    try:
        f(); return "ok"
    except ms.Refused as e:
        return "refused"
print(verdict(lambda: ms.check_mounts([(work / "m1", "/work", False)], work, forbidden)))
print(verdict(lambda: ms.check_mounts([(work, "/work", False)], work, forbidden)))
print(verdict(lambda: ms.check_mounts([(root / "home", "/work", False)], work, forbidden)))
print(verdict(lambda: ms.check_mounts([(root, "/work", False)], root, {"HOME": root / "home"})))
print(verdict(lambda: ms.check_workdir(root / "home" / "go" / "x", forbidden)))
print(verdict(lambda: ms.check_workdir(work, forbidden)))
`
	out, err := exec.Command(python(t), "-I", "-c", prog, script(t, "mutate-sandboxed.py"), root).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Equal(t, "ok\nrefused\nrefused\nrefused\nrefused\nok\n", string(out))
}

func hook(t *testing.T, input string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(python(t), "-I", script(t, "guard-hook.py"))
	cmd.Stdin = strings.NewReader(input)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out.String(), errb.String()
	}
	require.NoError(t, err)
	return 0, out.String(), errb.String()
}

func bashInput(t *testing.T, command string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
	require.NoError(t, err)
	return string(raw)
}

// guardRefused are commands that execute a mutant or mutation script or tool outside
// mutate-sandboxed. The first block is the v3 rollout's acceptance list (TXE-7549); the rest are
// the other ways a shell can run one.
var guardRefused = []string{
	// TXE-7549 v3 acceptance test, §4.
	"python3 evidence/txe-7523/mutants-7538.py",
	"bash scripts/run-mutations.sh",
	"mutmut run",
	"cd /x && timeout 900 python3 docs/specs/foo/mutants.py",
	"python3 -I <(git show origin/main:docs/x/mutants.py)",
	"python3 mutants.py",
	// Refused correctly on 2026-11-16 (the live fixture check's mutation-shaped command).
	"python3 /var/folders/nm/T/tmp.mygxOzsvhO/mutants.py",
	// Earlier unit cases.
	"cd /x && GOFLAGS=-count=1 timeout 900 python3 -u docs/specs/foo/mutants.py --only guard",
	"python3 -I <(git show origin/main:docs/specs/foo/mutants.py)",
	"echo start; ./mutants.py",
	"out=$(python3 mutants.py)",
	"uv run mutmut run",
	"python3 -m mutmut run",
	"go run ./tools/mutate.go",
	"go-mutesting ./...",
	"env FOO=1 nohup python3 'mut''ants.py'",
	// Shell code is read as shell code.
	"bash -c 'python3 mutants.py'",
	`sh -ec "timeout 60 python3 -u x/mutants.py"`,
	"bash -lc 'cd x && python3 -I mutants.py --only one'",
	"eval 'python3 mutants.py'",
	"env -S 'python3 mutants.py'",
	"bash <<'EOF'\ncd x\npython3 mutants.py\nEOF",
	"bash <<< 'python3 mutants.py'",
	"source ./run-mutations.sh",
	". tools/mutants.sh",
	// Substitutions, lists, subshells and compound commands run what they contain.
	`echo "$(python3 mutants.py)"`,
	"echo `python3 mutants.py`",
	"cat <<EOF\n$(python3 mutants.py)\nEOF",
	"(cd x && python3 mutants.py)",
	"if true; then python3 mutants.py; fi",
	"for f in a b; do python3 mutants.py \"$f\"; done",
	"cd x; python3 mutants.py 2>&1 | tee log",
	"python3 mutants.py>log",
	"2>/dev/null python3 mutants.py",
	"true && { python3 mutants.py; }",
	// The program read on stdin.
	"python3 - < mutants.py",
	"cat mutants.py | python3 -",
	"git show origin/main:x/mutants.py | python3 -I",
	// Wrappers and runners.
	"timeout -s KILL 900 python3 mutants.py",
	"nice -n 5 python3 mutants.py",
	"sudo -u nobody python3 mutants.py",
	"xargs -n1 python3 mutants.py < list.txt",
	"uvx mutmut run",
	"poetry run python mutants.py",
	"uv run --with pytest python mutants.py",
	"find . -name '*.go' -exec python3 mutants.py {} \\;",
	"PY=/usr/bin/python3; $PY -I mutants.py",
	`"$PYTHON" -I tools/mutants.py`,
	"python3 -W ignore mutants.py",
	"python3 -Im mutmut run",
	"/opt/py/bin/python3.12 -u mutants.py",
	// Other interpreters.
	"node tools/mutants.js",
	"deno run mutants.ts",
	"ruby mutants.rb",
	"go run ./tools/mutate",
	// Code for a non-shell interpreter that imports a mutant, or names one and runs it.
	`python3 -c "import runpy; runpy.run_path('tools/mutants.py')"`,
	`python3 -I -c 'import subprocess; subprocess.run(["python3", "mutants.py"])'`,
	"python3 -I -c \"import subprocess\nprint('bash run-mutations.sh')\"",
	`python3 -c 'import os; os.system("mutmut run")'`,
	"python3 -c 'import mutants'",
	"python3 -c 'from tools.mutants import main; main()'",
	"python3 - <<'EOF'\nimport runpy\nrunpy.run_path(\"mutants.py\")\nEOF",
	`python3 <<< 'exec(open("mutants.py").read())'`,
	`node -e 'require("./mutants.js")'`,
	`node -e 'require("child_process").execSync("python3 mutants.py")'`,
	`perl -e 'system("python3 mutants.py")'`,
	`deno eval 'await import("./mutants.ts")'`,
	// Review findings on PR 276 (connector and security review).
	"((python3 mutants.py) )",
	"echo $(( $(python3 mutants.py) + 1 ))",
	"python3 < <(cat mutants.py)",
	"bash < <(cat run-mutations.sh)",
	"python3 -m runpy tools/mutants.py",
	"python3 -m pdb mutants.py",
	"python3 -m cProfile -o prof.out mutants.py",
	"coverage run mutants.py",
	"function f { python3 mutants.py; }",
	"node -r ./mutants.js app.js",
	"node --require=./mutants.js app.js",
	"ruby -rmutants app.rb",
	`perl -e'system("python3 mutants.py")'`,
	`ruby -e'system("python3 mutants.py")'`,
	`perl -e 'print 1' -e 'system("python3 mutants.py")'`,
	`perl -lne'system("python3 mutants.py")' notes.md`,
	"perl -Mmutants -e 1",
	"ruby -r ./mutants.rb app.rb",
	`ruby -E UTF-8 -e 'system("python3 mutants.py")'`,
	`ruby -We 'system("python3 mutants.py /x")'`,
	`ruby -Kue 'system("python3 mutants.py")'`,
	"perl -d:mutants app.pl",
	"perl -dt:mutants app.pl",
	"ruby --encoding UTF-8 mutants.rb",
	"ruby --external-encoding=UTF-8 tools/mutants.rb",
	`node --eval='require("./mutants.js")'`,
	"env --split-string='python3 mutants.py'",
	"env '-Spython3 mutants.py'",
	"python3 < mutants.py 3< /dev/null",
	"bash -s -- foo < run-mutations.sh",
	"cat run-mutations.sh | bash -s x",
	"python3 3< mutants.py <&3",
	"python3 /dev/fd/3 3< mutants.py",
	"bash /dev/fd/3 3<<'EOF'\npython3 mutants.py\nEOF",
	"python3 00< mutants.py",
	"node -e 'console.log(1)' -r ./mutants.js",
	`ruby --some-new-option value -e 'system("python3 mutants.py")'`,
	"bash --rcfile /dev/null run-mutations.sh",
	"bash --init-file ~/.bashrc -- tools/mutants.sh",
	"bash --rcfile=tools/mutants.sh -i",
	// Descriptors are resolved when judged, after here-document bodies are read; a descriptor
	// path the command does not set fails closed.
	"python3 3<<'EOF' <&3\nimport runpy; runpy.run_path('mutants.py')\nEOF",
	"bash 3<<'EOF' <&3-\npython3 mutants.py\nEOF",
	"python3 //dev/fd/3 3< mutants.py",
	"python3 /proc/self/../self/fd/3 3< mutants.py",
	"python3 /proc/thread-self/fd/3 3< mutants.py",
	"python3 /dev/fd/3 3>>mutants.py",
	"exec 3< mutants.py; python3 /dev/fd/3",
	"python3 <&3",
	"python3 3< mutants.py <&3 3< app.py",
	"python3 /dev/fd/$N 3< app.py",
	"bash --rcfile <(cat mutants.sh) -i",
	// Code given on the command line that runs a mutant named in its arguments.
	`python3 -c 'exec(open(__import__("sys").argv[1]).read())' mutants.py`,
	`node -e 'require(process.argv[1])' ./mutants.js`,
	`ruby -e 'load ARGV[0]' mutants.rb`,
	`perl -e 'do $ARGV[0]' mutants.pl`,
	// The guard does not follow data flow: code that can run a process, given a mutant script as
	// an argument, is refused even when it would not run that argument.
	`python3 -c 'import subprocess; print(subprocess.run(["git", "status"]).returncode)' mutants.py`,
	// Preloads and value-taking options.
	`bun --preload=./mutants.js -e 'console.log(1)'`,
	"bun --preload ./mutants.js app.js",
	"node --title harmless mutants.js",
	// Paths under /proc cannot be judged.
	"python3 /proc/1/cwd/x.py",
	// Security review of 93ed54893.
	"cat mutants.py | python3 < /dev/stdin",
	"python3 < /dev/fd/3 3< mutants.py",
	`perl -e 'print 1' -- -e 'system($ARGV[0])' mutants.pl`,
	"node --unknown-flag harmless app.js mutants.js",
	`M=tools/mutants.py python3 -c 'import os, runpy; runpy.run_path(os.environ["M"])'`,
	`env M=tools/mutants.py python3 -c 'import os, runpy; runpy.run_path(os.environ["M"])'`,
	`python3 -c 'import subprocess, sys; subprocess.run(sys.argv[1:])' mutmut run`,
	`python3 -c 'import runpy, sys; runpy.run_path(sys.argv[1])' ./run-mutations`,
	"PY=/usr/bin/python3; env PY=harmless true; $PY ./run-mutations",
	"node inspect mutants.js",
	"tsx watch tools/mutants.ts",
	"deno test mutants.ts",
	"bun test ./mutants.ts",
	"python3 3< mutants.py < /dev/fd/3 3< /dev/null",
	"go run -exec ./mutants.py ./cmd/dagu",
	"go test -exec=./tools/mutants.sh ./...",
	"go test -exec 'python3 mutants.py' ./x",
	"go build -toolexec=./mutants.sh ./cmd/x",
	"go vet -vettool ./tools/mutants ./...",
	"GOFLAGS=-exec=./mutants.py go test ./...",
	"env GOFLAGS='-count=1 -toolexec=./mutants.sh' go build ./...",
	"go env -w GOFLAGS=-exec=./tools/mutants.py",
	"X=./mutants.py; go test -exec $X ./...",
	"go test -exec $UNSET ./...",
	"export GOFLAGS=-exec=./mutants.py; go test ./...",
	"GOENV=/tmp/x/go.env go test ./...",
	"(python3) < mutants.py",
	"{ python3; } < mutants.py",
	"cat mutants.py | (python3 -)",
	"(cd x && python3) < tools/mutants.py",
	`perl -I ./mutants.pl -e 'do "x"'`,
	"python3 /dev/fd/3 3< /dev/fd/4",
	"python3 /dev/fd/3 3> /dev/fd/4",
	// TXE-8183: each Python data read newly allowed in guardAllowed is paired here with code that
	// EXECUTES the same kind of input. An extension, a missing extension or a runner-like path does
	// not make an executed input data; only code proven not to execute does.
	// Data extensions, executed (allowed before TXE-8183: the code token needed a script extension).
	`python3 -c 'exec(open("mutants.json").read())'`,
	`python3 -c 'import pickle; pickle.load(open("mutants.json", "rb"))'`,
	"python3 - <<'EOF'\nimport json\nexec(json.load(open(\"mutants.json\"))[\"code\"])\nEOF",
	`python3 -c 'import sys; exec(open(sys.argv[1]).read())' mutants.json`,
	`python3 -c 'import runpy, sys; runpy.run_path(sys.argv[1])' mutants.txt`,
	`python3 -c 'import json, sys; exec(json.load(open(sys.argv[1]))["code"])' mutants.json`,
	// Extensionless files, executed.
	`python3 -c 'exec(open("mutants").read())'`,
	`python3 -c 'import runpy, sys; runpy.run_path(sys.argv[1])' mutants`,
	// Runner-like paths, executed (the work directory is a path component, not the base name).
	`python3 -I -c 'import sys; exec(open(sys.argv[1]).read())' /tmp/mutate-sandboxed-1_y5j3xh/report.json`,
	`python3 -c 'import subprocess, sys; subprocess.run([sys.executable, sys.argv[1]])' /tmp/mutate-sandboxed-1_y5j3xh/sandbox/tool.py`,
	`W=/tmp/mutate-sandboxed-1_y5j3xh; python3 -I -c 'import sys; exec(open(sys.argv[1]).read())' $W/report.json`,
	`python3 -c 'import runpy, sys; runpy.run_path(sys.argv[1])' /tmp/mutate-sandboxed-1_y5j3xh/.mutate-sandboxed-owned`,
	// Aliases and language-specific run calls next to an allowed data read.
	`python3 -c 'import builtins as b, sys; b.exec(open(sys.argv[1]).read())' mutants.json`,
	`python3 -c 'from runpy import run_path as go; import sys; go(sys.argv[1])' mutants.cfg`,
	`python3 -c 'from os import system as s; import json, sys; s("python3 " + sys.argv[1])' mutants.json`,
	`python3 -c 'import sys; getattr(__builtins__, "ex" + "ec")(open(sys.argv[1]).read())' mutants.json`,
	`python3 -c 'import json, sys; json.__dict__["__builtins__"]["ex" "ec"](open(sys.argv[1]).read())' mutants.json`,
	`python3 -c 'import sys; sys.modules["os"].system("python3 " + sys.argv[1])' mutants.json`,
	`python3 -c 'import pickle, sys; print(pickle.load(open(sys.argv[1], "rb")))' mutants.pkl`,
	`python3 -c 'import marshal, sys; exec(marshal.loads(open(sys.argv[1], "rb").read()))' mutants.bin`,
	`python3 -c 'import importlib.util as u, sys; s = u.spec_from_file_location("m", sys.argv[1])' mutants.dat`,
	// Counterparts of observed false positives 7 and 8: the same variables and arguments, executed.
	`K=$R/mutate-sandboxed-1_y5j3xh; python3 -I -c 'import json,sys; exec(json.load(open(sys.argv[1]))["code"])' $E/report.json`,
	`T=tests/scripts/test_mutant_consumers.py; python3 -I -c 'import ast,sys; exec(compile(ast.parse(open(sys.argv[1]).read()), "m", "exec"))' $T`,
	`python3 -I -c 'import ast, runpy, sys; ast.parse(open(sys.argv[1]).read()); runpy.run_path(sys.argv[1])' tests/scripts/test_mutant_consumers.py`,
	// Code outside the read-only grammar is not cleared, so its JSON read of a mutant-named input
	// is judged by the run-call rule (automated security review, TXE-8183): open() in a write mode hidden
	// by *args or passed to map, and a coding declaration that changes how Python decodes stdin.
	`python3 -c 'import json, sys; json.load(open(sys.argv[1])); open(*[sys.argv[1], "w"])' mutants.json`,
	`python3 -c 'import json, sys; json.load(open(sys.argv[1])); list(map(open, [sys.argv[1]], ["w"]))' mutants.json`,
	"python3 - <<'EOF'\n# -*- coding: utf-7 -*-\nimport json\nprint(json.load(open(\"mutants.json\")))\nEOF",
	// The declaration on what CPython counts as line 2, after a \f that str.splitlines() splits at.
	"python3 - <<'EOF'\nx = 1\f\n# coding: utf-7\nimport json\nprint(json.load(open(\"mutants.json\")))\nEOF",
	// ... and after a lone \r, which ends a line for CPython.
	"python3 - <<'EOF'\nx = 1\r# coding: utf-7\nimport json\nprint(json.load(open(\"mutants.json\")))\nEOF",
	`python3 -c 'import json, sys; json.load(open(sys.argv[1])); list(map((x for x in ()).gi_frame.f_globals["__builtins__"]["exec"], ["print(1)"]))' mutants.json`,
	// A data read whose imports a PYTHON* variable can redirect is judged by the language-neutral rule.
	`PYTHONPATH=/tmp/x python3 -c 'import json, sys; print(json.load(open(sys.argv[1])))' mutants.json`,
	// TXE-8183 independent review findings F1-F3. All inert: none is executed.
	// F1: interactive forms are never cleared, and -i's stdin continuation is judged as a program.
	`python3 -i -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json`,
	`python3 -Ii -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json`,
	`python3 -I -i -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json`,
	`python3 -I -i -c 'import json' < mutants.py`,
	`cat mutants.py | python3 -Ii -c 'print(1)'`,
	`PYTHONINSPECT=1 python3 -c 'print(1)' < mutants.py`,
	`python3 -i app.py < mutants.py`,
	`python3 -i -m json.tool data.json < mutants.py`,
	// F1: flags and options outside the supported isolated form are not cleared.
	`python3 -I -X dev -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json`,
	`python3 -I -W ignore -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json`,
	`python3 -I --check-hash-based-pycs never -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json`,
	`python3 -IS -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json`,
	// F2: the non-isolated forms of the synthetic reads (documented false positives: a json.load of a
	// mutant-named input without -I is refused, pending explicit review, as before TXE-8183).
	`python3 -c 'import json, sys; print(len(json.load(open(sys.argv[1]))))' mutants.json`,
	`M=mutants.json python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["name"])' "$M"`,
	`python3 -c 'import json, sys; json.load(open(sys.argv[1], "rb"))' mutants`,
	// F2: PYTHON* variables, unsupported wrappers and runners, and nested contexts are not cleared.
	`PYTHONPATH=/tmp/x python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])))' mutants.json`,
	`env PYTHONSAFEPATH= python3 -I -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json`,
	`sudo -u nobody python3 -I -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json`,
	`uv run python3 -I -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json`,
	`eval "python3 -I -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json"`,
	`bash -c "python3 -I -c 'import json, sys; json.load(open(sys.argv[1]))' mutants.json"`,
	`env -S 'python3 -I -c "import json, sys; json.load(open(sys.argv[1]))" mutants.json'`,
	// F2: env -S carries the enclosing assignments as values (allowed before: the nested judge
	// started empty, so W was unknown inside).
	`W=/tmp/mutate-sandboxed-1_y5j3xh; env -S 'python3 -c "import json, sys; exec(json.load(open(sys.argv[1]))[0])" $W/r.json'`,
	// F3: module attribute writes and deletes, rebinding a builtin, an alias that shadows one, a
	// module passed on, and callback keywords are outside the grammar.
	`python3 -I -c 'import json, sys; json.load = print; json.load(open(sys.argv[1]))' mutants.json`,
	`python3 -I -c 'import json, sys; del json.load; print(json.load(open(sys.argv[1])))' mutants.json`,
	`python3 -I -c 'import json, sys; open = json.load; print(open(sys.argv[1]))' mutants.json`,
	`python3 -I -c 'import json as print, sys; print.load(open(sys.argv[1]))' mutants.json`,
	`python3 -I -c 'import json, sys; j = json; print(j.load(open(sys.argv[1])))' mutants.json`,
	`python3 -I -c 'import json, sys; print(sorted(json.load(open(sys.argv[1])), key=len))' mutants.json`,
	`python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]), object_hook=print))' mutants.json`,
	`python3 -I -c 'import json, sys; f = lambda p: json.load(open(p)); print(f(sys.argv[1]))' mutants.json`,
	`python3 -I -c 'import json, sys; print([json.load(open(p)) for p in sys.argv[1:]])' mutants.json`,
	// The security-review shapes in the isolated form, so they exercise the grammar itself.
	`python3 -I -c 'import json, sys; json.load(open(sys.argv[1])); open(*[sys.argv[1], "w"])' mutants.json`,
	`python3 -I -c 'import json, sys; json.load(open(sys.argv[1])); list(map(open, [sys.argv[1]], ["w"]))' mutants.json`,
	`python3 -I -c 'import json, sys; json.load(open(sys.argv[1])); list(map((x for x in ()).gi_frame.f_globals["__builtins__"]["exec"], ["print(1)"]))' mutants.json`,
	`python3 -I -c 'import json, sys; json.load(open(sys.argv[1], "r", -1, None, None, None, True, print))' mutants.json`,
	// Encoding: an active line-2 declaration after a first-line comment holding a form feed, a
	// declaration led by a form feed (valid per PEP 263), and a BOM.
	"python3 -I - <<'EOF'\n# first line\f\n# -*- coding: utf-7 -*-\nimport json\nprint(json.load(open(\"mutants.json\")))\nEOF",
	"python3 -I - <<'EOF'\n\f# coding: utf-7\nimport json\nprint(json.load(open(\"mutants.json\")))\nEOF",
	"python3 -I - <<'EOF'\n\ufeffimport json\nprint(json.load(open(\"mutants.json\")))\nEOF",
	// Code the shell expands first is not the text the guard read, so it is never cleared
	// (automated security review, TXE-8183): a substitution or variable in double quotes, ANSI-C
	// quoting, an unquoted here-document and an expanded here-string.
	`python3 -I -c "import json, sys; print(json.load(open(sys.argv[1])))$(printf ';x=1')" mutants.json`,
	`python3 -I -c "import json, sys; print(json.load(open(sys.argv[1])))$TAIL" mutants.json`,
	`python3 -I -c $'import json, sys\x3b print(json.load(open(sys.argv[1])))' mutants.json`,
	"python3 -I - <<EOF\nimport json\nprint(json.load(open(\"mutants.json\")))\nEOF",
	`python3 -I <<< "import json; print(json.load(open('mutants.json')))$TAIL"`,
	// ... also when the variable sits inside a Python string literal, so the unexpanded text parses.
	`python3 -I -c "import json, sys; print(json.load(open(sys.argv[1])), '${X}')" mutants.json`,
	`python3 -I -c "import json, sys; print(json.load(open(sys.argv[1])), '$X')" mutants.json`,
	`python3 -I -c "import json, sys; print(json.load(open(sys.argv[1])), '$1')" mutants.json`,
	`python3 -I <<< "import json; print(json.load(open('mutants.json')), '$X')"`,
}

// guardAllowed are commands in which the words appear only as data. The first block is the v3
// acceptance list; then the false positives observed after the rollout (2026-11-16/17), kept in
// their shape with local paths and ids replaced; then the data shapes TXE-7641 names.
var guardAllowed = []string{
	// TXE-7549 v3 acceptance test, §4.
	"go test ./...",
	"git commit -m 'mutants: add one'",
	"cat mutants.py",
	"grep -n mutant notes.md",
	"mutate-sandboxed --mutants m.json -- go test ./...",
	"python3 -I txe/mutate/mutate-sandboxed.py --help",
	"ls",
	"make check",
	"gh pr view 266",
	// Observed false positive 1 (cc3, 16:06Z): a python3 -c string naming the guard's hook.
	`git -C ~/.coding_global log --oneline -2; git -C ~/.coding_global diff --stat -- AGENTS.md; python3 -c 'import json;d=json.load(open("/home/u/.claude4/settings.json"));print(sum("mutant-run-guard" in json.dumps(e) for e in d.get("hooks",{}).get("PreToolUse",[])))'; grep -n -iE 'class fix|stale' /home/u/evidence/APPLY-REPORT.md | head -8`,
	// Observed false positive 1b (cc3, 16:09Z): a multi-line python3 -c string, then awk and ls.
	"cd ~/evidence && S=/tmp/scratch && python3 -I -B -c '\nimport json,sys\nraw=open(sys.argv[1]).read(); d=json.loads(raw[raw.index(\"{\"):])\nwith open(sys.argv[2],\"a\") as f:\n    for m in d[\"result\"][\"messages\"]: f.write(\"\\n## \"+m[\"id\"]+\": \"+m[\"subject\"]+\"\\n\")\n' $S/inbox.txt records/SLOTS.md; awk '/^## Mutation tests/{f=1} f&&/^## /&&!/Mutation tests/{exit} f' ~/.coding_global/AGENTS.md | head -40; ls -l ~/.coding_global/bin/mutate-sandboxed 2>&1 | cut -c1-120",
	// Observed false positive 2 (cc1, 16:09Z): a batch of pre-create gates; a grep pattern says "mutate".
	`cd ~/evidence/packet-r1 && PY=/home/u/.pyenv/versions/vv/bin/python3; S=/tmp/scratch; shasum -a 256 -c MANIFEST.sha256 >| $S/manifest.txt 2>&1; echo "rehash rc=$? notOK=$(grep -vc ': OK$' $S/manifest.txt)"; $PY -I -B run.py selfcheck >| $S/selfcheck.txt 2>&1; $PY -I -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["violations"])' $S/selfcheck.txt; $PY -I -B run_tests.py >| $S/tests.txt 2>&1; grep -E '^(Ran|OK|FAILED)' $S/tests.txt; docker ps -a --format '{{.Names}}' | grep -ciE 'txe7522|rig|mutate|w10|cal'; docker network ls --format '{{.Name}}' | grep -c txe7522; launchctl list | grep -c txe7522r5; date -u +%FT%TZ`,
	// Observed false positive 2b (cc1, 16:10Z): reporting the refusal, a quoted heredoc to a file.
	"S=/tmp/scratch; cat > $S/ask-guard.txt <<'EOF'\nVerbatim refusal: \"Refused: this runs a mutation test outside the sandboxed runner. Run it through mutate-sandboxed.\"\n- a read-only sweep: docker ps -a --format '{{.Names}}' | grep -ciE 'txe7522|rig|mutate|w10|cal'\nMy guess: the word \"mutate\"; python3 mutants.py was never run.\nEOF\norca orchestration ask --from term_x --question \"$(cat $S/ask-guard.txt)\" 2>&1 | tail -2",
	// Observed false positive 3 (cc3, 16:11Z): a brief written with printf, naming the guard and runner.
	"D=/home/u/briefs; GUARD='The mutant-run guard (TXE-7549) is live. Any mutant check runs ONLY through ~/.coding_global/bin/mutate-sandboxed: never python3 mutants.py on the host.'\n{ printf '%s\\n' \"Your ticket: TXE-7641.\" \"Repo: txehq/dagu: txe/mutate/guard-hook.py and its tests. Run bash scripts/run-mutations.sh only through mutate-sandboxed.\" \"$GUARD\"; } >| $D/spec-TXE-7641.md\ncd $D; bash launch.sh 7641 guard-exec-only 14",
	// Observed false positive 4 (cc14, 2026-11-17): a python3 script on a quoted heredoc that edits the guard.
	"cd txe/mutate && python3 - <<'EOF'\np=\"guard-hook.py\"; s=open(p).read()\ns=s.replace(\"python3 mutants.py\", \"bash run-mutations.sh\")\nopen(p,\"w\").write(s)\nEOF",
	// Observed on 2026-11-16 (the fixture check): a prompt and a printf naming mutants.py are data.
	`D=$(mktemp -d); printf 'open(%r,"w").write("x")\n' "$D/MARKER" > $D/mutants.py; cat $D/mutants.py; cd $D && timeout 300 claude -p "Run exactly: 1) python3 $D/mutants.py 2) python3 $D/control.py" 2>&1 | tail -20`,
	// Earlier unit cases.
	"python3 -I txe/mutate/mutate-sandboxed.py --mutants m.json -- go test ./...",
	"mutate-sandboxed --mutants mutants.json --tree . -- python3 -m pytest tests/test_mutants.py",
	"python3 -I <(git show origin/main:txe/mutate/mutate-sandboxed.py) --mutants m.json -- go test ./x",
	"~/.coding_global/bin/mutate-sandboxed --mutants m.json --tree . -- python3 mutants.py",
	"cat docs/specs/foo/mutants.py",
	"git add mutants.py && git commit -m 'mutants: add guard mutant'",
	"go test ./txe/mutate/...",
	"python3 -I txe/mutate/guard-hook.py",
	"grep -n mutant evidence/notes.md",
	// Data: patterns, messages, here-documents, paths and code strings of non-shell interpreters.
	"grep -rn 'python3 mutants.py' docs/",
	"sed -n 1,5p tools/mutants.py",
	"shasum -a 256 tools/mutants.py run-mutations.sh",
	"ls txe/mutate tools/mutants.py",
	"echo python3 mutants.py",
	"printf '%s\\n' 'bash run-mutations.sh' > notes.txt",
	"cat > notes.md <<'EOF'\npython3 mutants.py\nbash run-mutations.sh\nEOF",
	"cat > notes.md <<EOF\npython3 mutants.py\nmutmut run\nEOF",
	"cat <<-EOF >> notes.md\n\tpython3 mutants.py\n\tEOF\necho done",
	`orca orchestration send --subject x --body "run python3 mutants.py via mutate-sandboxed"`,
	"gh pr comment 1 --body 'python3 -I <(git show x:mutants.py)'",
	"linear comment --text \"mutmut run; bash run-mutations.sh\"",
	`python3 -c 'import json; print("mutants.py")'`,
	`python3 -c 'print(open("tools/mutants.py").read().count("old"))'`,
	`node -e 'console.log("mutants.js")'`,
	"true # ; python3 mutants.py",
	`python3 -c 'print("example: import mutants")'`,
	"python3 - <<'EOF'\n# import mutants\nprint(1)\nEOF",
	"echo $((1 + 2)); ((i++))",
	"python3 -m cProfile -o prof.out tools/report.py mutants.json",
	"node -r ./setup.js app.js mutants.json",
	"perl -Iexe -ne 'print if /mutants.py/' notes.md",
	"perl -lne 'print if /run-mutations.sh/' notes.md",
	"ruby -E UTF-8 -e 'puts 1' mutants.json",
	"perl -d -e 1",
	"ruby --encoding UTF-8 app.rb mutants.json",
	`node --eval='console.log("mutants.js")'`,
	"python3 app.py 3< mutants.py",
	"bash -s < setup.sh -- mutants.py",
	"cat 3<<'EOF' notes\npython3 mutants.py\nEOF",
	`ruby -Kue 'puts File.read("mutants.rb")'`,
	"python3 /dev/fd/3 3< app.py 4< mutants.py",
	"python3 - 3< mutants.py",
	"python3 app.py <&3",
	"python3 /dev/fd/3 3< app.py",
	"bash /dev/stdin < setup.sh",
	"python3 3< app.py <&3 3< mutants.py",
	"python3 /home/u/fd/app.py",
	"cat mutants.py | python3 < /dev/null",
	"ruby -e 'puts ARGV[0]' 'import mutants'",
	"node app.js --title mutants.js",
	"node --title mutants app.js",
	"python3 /dev/fd/3 3>>app.py",
	"python3 3< /dev/null < /dev/fd/3 3< mutants.py",
	"go test -run TestMutants ./txe/mutate/ -exec /usr/bin/env",
	"GOFLAGS=-count=1 go test ./txe/mutate/...",
	"(python3 app.py) < mutants.py",
	"{ cat; } < mutants.py",
	"node --inspect ./app.js fixtures/mutants.js",
	// Observed false positive 5 (cc1, 17:36Z): a python3 heredoc editing a test file, whose
	// replacement text has a loop variable named mutate. It edits data and runs nothing.
	"cd ~/evidence/packet-r1 && ~/.pyenv/versions/vv/bin/python3 -I - <<'PYEOF'\nimport os\np=\"tests/test_r5.py\"; s=open(p).read()\nreps=[(\"old\", '''for mutate, why in ((lambda p: p[\"ports\"].pop(\"worker_health\"), \"missing\"),):\n    bad = dict(good)\n    mutate(bad)\n''')]\nfor a, b in reps:\n    s = s.replace(a, b)\nopen(p + \".tmp\", \"w\").write(s); os.replace(p + \".tmp\", p)\nPYEOF",
	"perl -ne 'print if /mutants.py/' notes.md",
	"git show origin/main:txe/mutate/guard-hook.py | head",
	"git log --grep=mutate --oneline",
	"bash ~/.coding_global/hooks/mutant-run-guard < input.json",
	`python3 -I -c 'import json,sys; print(json.dumps({"tool_input": {"command": sys.argv[1]}}))' "python3 mutants.py" | "$P/b/hooks/mutant-run-guard" >"$T/hook.out" 2>&1`,
	"command -v mutmut",
	"which mutmut && pip install mutmut",
	"vim tools/mutants.py",
	"python3 tools/report.py mutants.json",
	"go run ./cmd/report mutants.json",
	"echo ok # python3 mutants.py",
	"x=$((1 + 2)); echo $x mutants.py",
	"case $x in mutants) echo python3 mutants.py;; esac",
	"for f in mutants.py run-mutations.sh; do wc -l $f; done",
	"cat <<'A' <<'B'\npython3 mutants.py\nA\nbash run-mutations.sh\nB",
	// TXE-8183: Python code proven not to execute reads data, whatever it is given. Each shape is
	// paired with executing counterparts in guardRefused.
	// Observed false positive 6 (2026-11-22 15:20Z, recorded on TXE-7549), verbatim
	// with the worktree path replaced.
	`cd /home/u/work/txe-8047 && sed -n 54,66p conftest.py; python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); print(json.dumps(r["suites"]["pytest-mutants"],indent=1)); print(r["images"])' ops/ci/mutant-consumers.json`,
	// Observed false positive 7 (2026-11-22 16:03Z, recorded on TXE-7549), verbatim
	// from the session transcript, with a local scratch path replaced. K names the runner's
	// work directory.
	`SP=/tmp/scratch; E=$(cat $SP/first-run2-E.txt); R=$(cat $SP/first-run2-R.txt); K=$R/mutate-sandboxed-1_y5j3xh; O=$E/post-run.txt; { echo "== container custody"; python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); print("container_cleanup:", json.dumps(r.get("container_cleanup"))); print("workdir:", json.dumps(r.get("workdir"))); print("image:", json.dumps(r.get("image"))); print("tree:", json.dumps(r.get("tree"))); print("seeded:", r.get("seeded"))' $E/report.json; for c in "$K"/cids/*; do echo "cidfile $(basename $c): $(cat $c)"; cid=$(cat $c); echo "  docker inspect now: $(docker inspect --format '{{.Id}}' $cid 2>&1 | head -1)"; done; echo "owner token file present: $(test -f $K/.mutate-sandboxed-owned && echo yes)"; } >> $O 2>&1; command cp -p "$K/report.json" $E/logs/workdir-report.json; tail -12 $O; cd $E && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs shasum -a 256 >| SHA256SUMS && cat SHA256SUMS`,
	// Observed false positive 8 (2026-11-22 16:08Z, recorded on TXE-7549), verbatim: a sed edit
	// whose text says globals(), then an ast parse and a json parse. T names a test file with
	// mutant in its name.
	`T=tests/scripts/test_mutant_consumers.py; sed -i '' -e 's|    monkeypatch.setattr(sys.modules\[__name__\], "REGISTRY", tmp_path / "reg.json")|    monkeypatch.setitem(globals(), "REGISTRY", tmp_path / "reg.json")|' -e 's|    monkeypatch.setattr(sys.modules\[__name__\], "VALIDATION_IMAGE", tmp_path / "man.json")|    monkeypatch.setitem(globals(), "VALIDATION_IMAGE", tmp_path / "man.json")|' $T; grep -n 'monkeypatch.setitem(globals()' $T; python3 -I -c 'import ast,sys; ast.parse(open(sys.argv[1]).read()); print("ast ok (parser)")' $T; python3 -I -c 'import json,sys; json.load(open(sys.argv[1])); print("json ok (parser)")' ops/ci/validation-image/manifest.json`,
	// The same parse that passed earlier that day, with the file as its argument.
	`python3 -I -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' tests/scripts/test_mutant_consumers.py`,
	`python3 -c 'import ast, sys; print(ast.dump(ast.parse(open(sys.argv[1]).read())))' mutants.py`,
	// Review F2: clearance needs the isolated form, so these three synthetic reads carry
	// -I; their non-isolated forms moved to guardRefused as documented false positives.
	`python3 -I -c 'import json, sys; print(len(json.load(open(sys.argv[1]))))' mutants.json`,
	`M=mutants.json python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["name"])' "$M"`,
	`python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["container_cleanup"])' /tmp/mutate-sandboxed-1_y5j3xh/report.json`,
	`python3 -I -c 'import json, sys; json.load(open(sys.argv[1], "rb"))' mutants`,
	// The supported form's flag and wrapper variants.
	`python3 -IB -c 'import json, sys; print(json.dumps(json.load(open(sys.argv[1])), indent=2))' mutants.json`,
	`timeout 60 python3 -I -c 'import json, sys; print(len(json.load(open(sys.argv[1]))))' mutants.json`,
	// A here-string in single quotes is not expanded, so it can be cleared.
	`python3 -I <<< 'import json; print(json.load(open("mutants.json")))'`,
	"python3 -I - <<'EOF'\nimport json\nwith open(\"mutants.json\") as f:\n    r = json.load(f)\nprint(r[\"container_cleanup\"])\nEOF",
	`python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' /tmp/mutate-sandboxed-1_y5j3xh/.mutate-sandboxed-owned`,
}

// The guard hook refuses a mutation run started outside mutate-sandboxed and leaves everything else.
func TestGuardHook(t *testing.T) {
	for _, c := range guardRefused {
		code, stdout, stderr := hook(t, bashInput(t, c))
		assert.Equal(t, 2, code, "should refuse: %s", c)
		assert.Empty(t, stdout)
		assert.Contains(t, stderr, "mutate-sandboxed", c)
		// The advice is a command that would actually run, and never "rename it".
		assert.Contains(t, stderr, "--image sha256:<local image id> -- <test cmd>")
		assert.Contains(t, stderr, "pins by commit and sha256")
		assert.NotContains(t, stderr, "main's")
		assert.Contains(t, stderr, "do not rename anything")
	}
	for _, c := range guardAllowed {
		code, stdout, stderr := hook(t, bashInput(t, c))
		assert.Equal(t, 0, code, "should allow: %s (%s)", c, stderr)
		assert.Empty(t, stdout+stderr)
	}
	for _, junk := range []string{"", "not json", `{"tool_name":"Read","tool_input":{"file_path":"mutants.py"}}`, `[1]`} {
		code, _, _ := hook(t, junk)
		assert.Equal(t, 0, code, junk)
	}
}

// Without --no-seed or explicit caches, the runner takes the shared caches from `go env`, seeds an
// owned module cache on the host from a file proxy over the shared one (HOME unchanged), and
// offers only that seed to the container, read-only. A fake go stands in for the toolchain.
func TestSeedReadsSharedCacheAsFileProxy(t *testing.T) {
	f := newFixture(t, passingCheck)
	goLog := filepath.Join(f.root, "go.log")
	gopath := filepath.Join(f.root, "fake-gopath")
	fakeGo := `#!/usr/bin/env python3
import json, os, sys
LOG = ` + fmt.Sprintf("%q", goLog) + `
with open(LOG, "a") as f:
    f.write(json.dumps({"args": sys.argv[1:], "cwd": os.getcwd(), "env": {k: os.environ.get(k) for k in
        ("HOME", "GOPROXY", "GOMODCACHE", "GOPATH", "GOCACHE", "GOFLAGS", "GOWORK", "GOENV",
         "MUTATE_TEST_CANARY")}}) + "\n")
if sys.argv[1:3] == ["env", "-json"]:
    print(json.dumps({"GOMODCACHE": ` + fmt.Sprintf("%q", f.modcache) + `, "GOCACHE": ` + fmt.Sprintf("%q", f.gocache) + `,
                      "GOPATH": ` + fmt.Sprintf("%q", gopath) + `, "GOPROXY": "https://proxy.example,direct"}))
elif sys.argv[1:3] == ["mod", "download"]:
    os.makedirs(os.path.join(os.environ["GOMODCACHE"], "cache", "download"), exist_ok=True)
`
	bin := filepath.Join(f.root, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "go"), []byte(fakeGo), 0o755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOWORK", filepath.Join(f.root, "live", "go.work")) // a caller's workspace outside the copy
	t.Setenv("MUTATE_TEST_CANARY", "host-only-value")

	report := filepath.Join(f.root, "report.json")
	cmd := exec.Command(python(t), "-I", script(t, "mutate-sandboxed.py"), "--mutants",
		f.mutants(t, []map[string]any{cleanupMutant}), "--tree", f.tree, "--workdir-root", f.workRoot,
		"--docker", f.docker, "--report", report, "--image", "fixture-image", "--", "sh", "check.sh")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	raw, err := os.ReadFile(goLog)
	require.NoError(t, err)
	var download map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		if fmt.Sprint(rec["args"]) == "[mod download]" {
			download = rec["env"].(map[string]any)
		}
		if fmt.Sprint(rec["args"])[:9] == "[env -jso" {
			assert.Equal(t, "/", rec["cwd"], "go env runs outside any caller module")
			assert.Equal(t, "off", rec["env"].(map[string]any)["GOWORK"])
		}
	}
	require.NotNil(t, download, "the seed ran go mod download")
	realMod, err := filepath.EvalSymlinks(f.modcache)
	require.NoError(t, err)
	assert.Equal(t, "file://"+filepath.Join(realMod, "cache", "download")+",https://proxy.example,direct", download["GOPROXY"])
	assert.Equal(t, os.Getenv("HOME"), download["HOME"], "HOME is never overridden")
	assert.Equal(t, "off", download["GOWORK"], "a caller's GOWORK never points the seed at a live workspace")
	assert.Equal(t, "off", download["GOENV"])
	assert.Nil(t, download["MUTATE_TEST_CANARY"], "the seed's environment is built from nothing")
	assert.NotContains(t, download["GOMODCACHE"], realMod)
	assert.Contains(t, download["GOMODCACHE"], f.workRoot[len(filepath.Dir(f.workRoot)):])

	for _, argv := range dockerRuns(t, f.log) {
		joined := strings.Join(argv, " ")
		assert.Regexp(t, `--mount type=bind,source=\S+/seed/gomodcache/cache/download,target=/goproxy,readonly`, joined)
		assert.Contains(t, joined, "--env GOPROXY=file:///goproxy")
		assert.NotContains(t, joined, realMod)
	}
}

// A mutant whose path runs through a directory symlink back into the live tree is refused before
// anything is written: the copy keeps the link, and writing through it would edit the live file.
func TestSymlinkedTargetRefused(t *testing.T) {
	f := newFixture(t, passingCheck)
	real := filepath.Join(f.tree, "real")
	require.NoError(t, os.MkdirAll(real, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(real, "code.sh"), []byte(": GUARD\n"), 0o644))
	require.NoError(t, os.Symlink(real, filepath.Join(f.tree, "alias"))) // absolute, into the live tree
	o := f.run(t, f.mutants(t, []map[string]any{{"name": "via alias", "file": "alias/code.sh", "old": ": GUARD", "new": "exit 1"}}))
	assert.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "refused")
	live, err := os.ReadFile(filepath.Join(real, "code.sh"))
	require.NoError(t, err)
	assert.Equal(t, ": GUARD\n", string(live), "the live tree is never edited")
}

// Codex's exec_command carries the command as cmd (a string or an argv list).
func TestGuardHookCodexInput(t *testing.T) {
	for _, input := range []string{
		`{"tool_name":"exec_command","tool_input":{"cmd":"python3 mutants.py"}}`,
		`{"tool_name":"shell","tool_input":{"command":["bash","-lc","python3 mutants.py"]}}`,
		`{"tool_name":"local_shell","tool_input":{"cmd":["python3","mutants.py"]}}`,
	} {
		code, _, stderr := hook(t, input)
		assert.Equal(t, 2, code, input)
		assert.Contains(t, stderr, "mutate-sandboxed")
	}
	for _, input := range []string{
		`{"tool_name":"exec_command","tool_input":{"cmd":"go test ./..."}}`,
		`{"tool_name":"exec_command","tool_input":{"cmd":["python3","-c","print('mutants.py')"]}}`,
		`{"tool_name":"shell","tool_input":{"command":["bash","-lc","grep -rn 'mutate' docs | head"]}}`,
		`{"tool_name":"shell","tool_input":{"command":["gh","pr","comment","1","--body","python3 mutants.py; mutmut run"]}}`,
	} {
		code, _, stderr := hook(t, input)
		assert.Equal(t, 0, code, "%s (%s)", input, stderr)
	}
}

// The reader never fails and never hangs, whatever the command text: random shell-ish input
// (unbalanced quotes, substitutions and here-documents included) and deep nesting all return a
// verdict, and a verdict on a mutation run survives being wrapped in noise.
func TestGuardHookReaderIsTotal(t *testing.T) {
	prog := `
import importlib.util, random, sys, time
spec = importlib.util.spec_from_file_location("guard", sys.argv[1])
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
rng = random.Random(7641)
alphabet = ["'", '"', "\\", "$(", ")", "(", "` + "`" + `", "<<", "<<-", "<<<", "EOF", "\n", ";", "|", "&",
            "&&", "<(", ">", "<", " ", "#", "$((", "{", "}", "python3", "bash", "-c", "mutants.py", "mutmut",
            "x", "=", "$", "\t", "-", "2>", "&>", "eval", "env", "-S", "find", "-exec"]
start = time.monotonic()
for _ in range(4000):
    s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
    g.refuses(s)
g.refuses("bash -c " + "'bash -c " * 200 + "x")
# Nesting too deep to read fails closed, whatever it holds.
for deep in ["$(" * 3000 + "ls" + ")" * 3000, "(" * 3000 + "ls" + ")" * 3000, "uv run " * 3000 + "ls",
             "find . -exec " * 3000 + "ls", "echo " + "<(" * 3000 + "ls" + ")" * 3000]:
    assert g.refuses(deep) is True, deep[:20]
assert g.refuses("$(" * 5 + "ls" + ")" * 5) is False
for noise in ["echo '", 'echo "', "cat <<EOF", "x=$(", "# "]:
    assert g.refuses("python3 mutants.py; " + noise) is True, noise
print("ok", round(time.monotonic() - start, 1) < 60)
`
	out, err := exec.Command(python(t), "-I", "-c", prog, script(t, "guard-hook.py")).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Equal(t, "ok True\n", string(out))
}

// foreignContainer registers a container the run did not start: cleanup must never touch it.
func foreignContainer(t *testing.T, log string) {
	t.Helper()
	raw, err := json.Marshal(map[string][]string{strings.Repeat("f", 64): {"someone-elses", "other-owner"}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(log+".containers", raw, 0o644))
}

// removals are the container ids the runner force-removed.
func removals(t *testing.T, log string) []string {
	t.Helper()
	raw, err := os.ReadFile(log)
	require.NoError(t, err)
	var out []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		var argv []string
		require.NoError(t, json.Unmarshal([]byte(line), &argv))
		if len(argv) == 3 && argv[0] == "rm" && argv[1] == "-f" {
			out = append(out, argv[2])
		}
	}
	return out
}

// recordedCIDs are the ids docker wrote to the run's cidfiles.
func recordedCIDs(t *testing.T, workdir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(workdir, "cids", "*.cid"))
	require.NoError(t, err)
	var ids []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		ids = append(ids, string(raw))
	}
	return ids
}

// A run that outlives its per-run timeout is a TIMEOUT, never a kill, and the container its
// killed client left behind is removed by its recorded id. Nothing else is removed.
func TestTimeoutRemovesOnlyOwnedContainer(t *testing.T) {
	f := newFixture(t, passingCheck)
	foreignContainer(t, f.log)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "hang", "--timeout", "1")
	assert.Equal(t, 4, o.code, o.stdout+o.stderr)
	assert.Equal(t, "TIMEOUT", o.outcomes()["baseline"])
	ids := recordedCIDs(t, o.report["workdir"].(string))
	require.Len(t, ids, 1)
	assert.Equal(t, ids, removals(t, f.log))
	assert.Equal(t, map[string][]string{strings.Repeat("f", 64): {"someone-elses", "other-owner"}}, registry(t, f.log))
	assert.Contains(t, o.stderr, ids[0]+": removed")
}

// The whole-run deadline stops the run (exit 6) mid-container, removes the container it started,
// keeps the work directory as evidence, and does so well inside the per-run timeout.
func TestDeadlineStopsRun(t *testing.T) {
	f := newFixture(t, passingCheck)
	foreignContainer(t, f.log)
	start := time.Now()
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "hang", "--timeout", "60", "--deadline", "6")
	assert.Less(t, time.Since(start), 20*time.Second)
	assert.Equal(t, 6, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "whole-run deadline (6s) passed during baseline")
	workdir := o.report["workdir"].(string)
	assert.DirExists(t, workdir)
	ids := recordedCIDs(t, workdir)
	require.Len(t, ids, 1)
	assert.Equal(t, ids, removals(t, f.log))
	assert.Len(t, registry(t, f.log), 1, "only the foreign container is left")
}

// SIGTERM and SIGINT stop the run (exit 6) and remove the running container by its recorded id.
func TestSignalStopsRun(t *testing.T) {
	for _, sig := range []os.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			f := newFixture(t, passingCheck)
			foreignContainer(t, f.log)
			report := filepath.Join(f.root, "report.json")
			cmd := exec.Command(python(t), "-I", script(t, "mutate-sandboxed.py"), "--mutants",
				f.mutants(t, []map[string]any{cleanupMutant}), "--tree", f.tree, "--shared-modcache", f.modcache,
				"--shared-gocache", f.gocache, "--workdir-root", f.workRoot, "--docker", f.docker, "--no-seed",
				"--report", report, "--image", "hang", "--timeout", "60", "--", "sh", "check.sh")
			var errb bytes.Buffer
			cmd.Stderr = &errb
			require.NoError(t, cmd.Start())
			require.Eventually(t, func() bool { return len(registry(t, f.log)) == 2 }, 15*time.Second, 50*time.Millisecond)
			require.NoError(t, cmd.Process.Signal(sig))
			err := cmd.Wait()
			var ee *exec.ExitError
			require.ErrorAs(t, err, &ee, errb.String())
			assert.Equal(t, 6, ee.ExitCode(), errb.String())
			assert.Contains(t, errb.String(), "stopped: signal")
			raw, err := os.ReadFile(report)
			require.NoError(t, err)
			var rep map[string]any
			require.NoError(t, json.Unmarshal(raw, &rep))
			ids := recordedCIDs(t, rep["workdir"].(string))
			require.Len(t, ids, 1)
			assert.Equal(t, ids, removals(t, f.log))
			assert.Len(t, registry(t, f.log), 1, "only the foreign container is left")
		})
	}
}

// Cleanup removes a recorded id only when docker reports this run's name and owner label on it.
func TestCleanupLeavesMismatchedContainer(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, "docker.log")
	docker := fakeDocker(t, root, log)
	id := strings.Repeat("a", 64)
	raw, err := json.Marshal(map[string][]string{id: {"mutate-sandboxed-x-001", "another-token"}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(log+".containers", raw, 0o644))
	cidfile := filepath.Join(root, "001.cid")
	require.NoError(t, os.WriteFile(cidfile, []byte(id), 0o644))
	prog := `
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
print(ms.remove_owned_container(sys.argv[2], Path(sys.argv[3]), "mutate-sandboxed-x-001", "my-token", ms.docker_client_env()))
print(ms.remove_owned_container(sys.argv[2], Path(sys.argv[3]), "mutate-sandboxed-x-001", "another-token", ms.docker_client_env()))
print(ms.remove_owned_container(sys.argv[2], Path(sys.argv[3]), "mutate-sandboxed-x-001", "another-token", ms.docker_client_env()))
`
	out, err := exec.Command(python(t), "-I", "-c", prog, script(t, "mutate-sandboxed.py"), docker, cidfile).CombinedOutput()
	require.NoError(t, err, string(out))
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.Len(t, lines, 3)
	assert.Contains(t, lines[0], "not ours")
	assert.Equal(t, id+": removed", lines[1])
	assert.Equal(t, id+": absent", lines[2])
}

// demo runs fixture-demo.py with the fake docker; the image decides what the fake does, and
// "noexec" images run no command at all, so no fixture mutant executes on this host.
func demo(t *testing.T, docker string, args ...string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	cmd := exec.Command(python(t), append([]string{"-I", script(t, "fixture-demo.py"), "--docker", docker}, args...)...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	return cmd, &out
}

// demoRoot is the directory the demo said it created; the test removes it if the demo kept it.
func demoRoot(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, " root ")
	require.GreaterOrEqual(t, i, 0, out)
	root := strings.Fields(out[i+len(" root "):])[0]
	require.Contains(t, root, "mutate-sandboxed-")
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	require.ErrorAs(t, err, &ee)
	return ee.ExitCode()
}

// The demo's happy path: the runner reports the mutant SURVIVED with the fake caches unchanged,
// the demo exits 0 and removes the directory it created.
func TestDemoSandboxedRemovesItsRoot(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, "docker.log")
	docker := fakeDocker(t, root, log)
	evidence := filepath.Join(root, "evidence")
	cmd, out := demo(t, docker, "sandboxed", evidence, "sha256:noexec", "--deadline", "60")
	require.Equal(t, 0, exitCode(t, cmd.Run()), out.String())
	dir := demoRoot(t, out.String())
	assert.NoDirExists(t, dir)
	assert.Contains(t, out.String(), "result: EXPECTED")
	assert.FileExists(t, filepath.Join(evidence, "sandboxed.report.json"))
	assert.FileExists(t, filepath.Join(evidence, "sandboxed.log"))
}

// A hanging container meets the whole-demo deadline: the runner is stopped, the container it
// recorded is removed (and no other), the demo exits 1 inside its deadline and keeps its root.
func TestDemoDeadlineRemovesOnlyRecorded(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, "docker.log")
	docker := fakeDocker(t, root, log)
	foreignContainer(t, log)
	start := time.Now()
	cmd, out := demo(t, docker, "sandboxed", filepath.Join(root, "evidence"), "sha256:hang", "--deadline", "30")
	require.Equal(t, 1, exitCode(t, cmd.Run()), out.String())
	assert.Less(t, time.Since(start), 30*time.Second)
	dir := demoRoot(t, out.String())
	assert.DirExists(t, dir, "an unexpected result keeps its evidence")
	assert.Contains(t, out.String(), "result: NOT AS EXPECTED")
	assert.Len(t, removals(t, log), 1)
	assert.Equal(t, map[string][]string{strings.Repeat("f", 64): {"someone-elses", "other-owner"}}, registry(t, log))
}

// SIGTERM to the demo stops the runner, which removes its recorded container; nothing else goes.
func TestDemoSignalRemovesOnlyRecorded(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, "docker.log")
	docker := fakeDocker(t, root, log)
	foreignContainer(t, log)
	cmd, out := demo(t, docker, "sandboxed", filepath.Join(root, "evidence"), "sha256:hang", "--deadline", "120")
	require.NoError(t, cmd.Start())
	require.Eventually(t, func() bool { return len(registry(t, log)) == 2 }, 20*time.Second, 50*time.Millisecond)
	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	assert.Equal(t, 1, exitCode(t, cmd.Wait()), out.String())
	demoRoot(t, out.String())
	assert.Len(t, removals(t, log), 1)
	assert.Len(t, registry(t, log), 1, "only the foreign container is left")
}

// The demo refuses a tag (only an immutable id) and an image that is not present locally.
func TestDemoRefusals(t *testing.T) {
	root := t.TempDir()
	docker := fakeDocker(t, root, filepath.Join(root, "docker.log"))
	for _, image := range []string{"golang:1.27.3-bookworm", "missing"} {
		cmd, out := demo(t, docker, "sandboxed", filepath.Join(root, "evidence"), image)
		assert.Equal(t, 2, exitCode(t, cmd.Run()), out.String())
	}
}

// A work directory is removed only while it is the one created: not after its token changed,
// and not after it was replaced by another directory at the same path.
func TestWorkDirRemovedOnlyOnMatch(t *testing.T) {
	prog := `
import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
root = Path(sys.argv[2])
def verdict(w):
    try:
        w.remove(); return "removed"
    except ms.Refused:
        return "refused"
w = ms.WorkDir(root); (w.path / ms.OWNER_FILE).write_text("someone else"); print(verdict(w), w.path.exists())
w = ms.WorkDir(root); os.rename(w.path, str(w.path) + ".moved"); w.path.mkdir(); (w.path / ms.OWNER_FILE).write_text(w.token); print(verdict(w), w.path.exists())
w = ms.WorkDir(root); print(verdict(w), w.path.exists())
`
	out, err := exec.Command(python(t), "-I", "-c", prog, script(t, "mutate-sandboxed.py"), t.TempDir()).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Equal(t, "refused True\nrefused True\nremoved False\n", string(out))
}

// The deadline clock starts before preflight: a docker that hangs on the image check is stopped.
func TestDeadlineCoversImageCheck(t *testing.T) {
	f := newFixture(t, passingCheck)
	start := time.Now()
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "slowinspect", "--deadline", "2")
	assert.Less(t, time.Since(start), 15*time.Second)
	assert.Equal(t, 6, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "docker image inspect took longer than")
	assert.Empty(t, dockerRuns(t, f.log))
}

// The demo's clock also starts before its own image check: a hung check ends inside the deadline.
func TestDemoDeadlineCoversImageCheck(t *testing.T) {
	root := t.TempDir()
	docker := fakeDocker(t, root, filepath.Join(root, "docker.log"))
	start := time.Now()
	cmd, out := demo(t, docker, "sandboxed", filepath.Join(root, "evidence"), "sha256:slowinspect", "--deadline", "30")
	assert.Equal(t, 1, exitCode(t, cmd.Run()), out.String())
	assert.Less(t, time.Since(start), 20*time.Second)
	assert.Contains(t, out.String(), "did not answer inside the deadline")
}

// A live mutation target edited during the baseline (not only during its own mutant) stops the
// run: every target's content is read before the tree is copied and checked after every run.
func TestLiveTargetWatchedFromStart(t *testing.T) {
	f := newFixture(t, passingCheck)
	live := filepath.Join(f.tree, "check.sh")
	bind := fmt.Sprintf("live = %q\n", live)
	f.docker = fakeDocker(t, f.root, f.log, bind+`open(live, "a").write("# edited\n")`)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}))
	require.Equal(t, 3, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "after baseline: the live tree's check.sh changed")
}

// Cleanup is inside the deadline: a docker slow to answer cleanup cannot hold the run past it by
// more than the bounded floor.
func TestCleanupInsideDeadline(t *testing.T) {
	f := newFixture(t, passingCheck)
	require.NoError(t, os.WriteFile(f.log+".slowclean", nil, 0o644))
	start := time.Now()
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "hang", "--timeout", "60", "--deadline", "6")
	assert.Equal(t, 6, o.code, o.stdout+o.stderr)
	// 6 s deadline, 2 s cleanup reserve, inspect cut to the 2 s left (floor 1 s).
	assert.Less(t, time.Since(start), 12*time.Second)
	assert.Contains(t, o.stderr, "cleanup error")
}

// A symlink in the tree that leads outside it (here an absolute go.sum link back into the live
// tree) is refused before anything runs on the host or in a container; a link inside is fine.
func TestOutsideSymlinkRefused(t *testing.T) {
	f := newFixture(t, passingCheck)
	outside := filepath.Join(f.root, "elsewhere.sum")
	require.NoError(t, os.WriteFile(outside, []byte("live\n"), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(f.tree, "go.sum")))
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}))
	assert.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "go.sum is a symlink to")
	assert.Empty(t, dockerRuns(t, f.log))
	raw, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, "live\n", string(raw))

	g := newFixture(t, passingCheck)
	require.NoError(t, os.Symlink("check.sh", filepath.Join(g.tree, "inside.sh")))
	o = g.run(t, g.mutants(t, []map[string]any{cleanupMutant}))
	assert.Equal(t, 0, o.code, o.stdout+o.stderr)
}

// A docker client killed by a signal is a sandbox error, never a kill, and the container it left
// is removed by its recorded id.
func TestKilledClientIsErrorAndCleaned(t *testing.T) {
	f := newFixture(t, passingCheck)
	foreignContainer(t, f.log)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "selfkill")
	assert.Equal(t, 4, o.code, o.stdout+o.stderr)
	assert.Equal(t, "ERROR", o.outcomes()["baseline"])
	ids := recordedCIDs(t, o.report["workdir"].(string))
	require.Len(t, ids, 1)
	assert.Equal(t, ids, removals(t, f.log))
	assert.Len(t, registry(t, f.log), 1, "only the foreign container is left")
}

// The step-2 double cannot run here (it refuses outside a container, and no mutant runs on this
// host), so this checks its contract by reading: the outer script writes the fake host's Go
// settings to the file the leaky docker applies, with the paths the runner watches there.
func TestOuterNegativeHandsFakeHostEnv(t *testing.T) {
	outer, err := os.ReadFile("negative-in-outer.sh")
	require.NoError(t, err)
	leaky, err := os.ReadFile(filepath.Join("testdata", "leaky-docker.py"))
	require.NoError(t, err)
	assert.Contains(t, string(leaky), `CALLER_ENV = "/fakehost/caller-env.json"`)
	assert.Contains(t, string(leaky), "env.update(json.load(f))")
	// It answers the runner's stopped-state check (its runs finish synchronously), or step 2 would
	// be refused before the mutant runs.
	assert.Contains(t, string(leaky), `if "{{.State.Running}}" in args:`)
	assert.Contains(t, string(leaky), `print("false")`)
	// The outer container's launch clears docker's configured proxies too (it is not run here).
	demoSrc, err := os.ReadFile("fixture-demo.py")
	require.NoError(t, err)
	assert.Contains(t, string(demoSrc), `for k in sorted(ms.CLEARED_PROXY_ENV) for x in ("--env", f"{k}=")`)
	assert.Contains(t, string(demoSrc), `"--log-driver", "none"`)
	assert.Contains(t, string(outer), `>"$fake/caller-env.json"`)
	assert.Contains(t, string(outer), `fake=/fakehost`)
	for _, key := range []string{"GOPATH", "GOMODCACHE", "GOCACHE", "GOPROXY"} {
		assert.Contains(t, string(outer), `"`+key+`":`)
	}
}

// A run stopped by the deadline after the boundary leaked still ends in the shared-state alarm
// (exit 3), not exit 6: the host check runs on every exit path.
func TestStoppedRunStillChecksSharedState(t *testing.T) {
	f := alarmFixture(t, `open(os.path.join(modcache, sentinel), "w").write("changed\n")`)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "hang", "--timeout", "60", "--deadline", "6")
	require.Equal(t, 3, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "stopped:")
	assert.Contains(t, o.stderr, "SHARED STATE CHANGED")
	assert.Contains(t, o.stderr, "after the end of the run")
	assert.Len(t, removals(t, f.log), 1, "the container is still removed")
}

// A watched path that becomes unreadable is a change, not a skipped check: the run fails closed
// with the shared-state alarm.
func TestUnreadableWatchFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads through permissions")
	}
	f := alarmFixture(t, `os.chmod(os.path.join(modcache, sentinel), 0)`)
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(f.modcache, sentinel), 0o644) })
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}))
	require.Equal(t, 3, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "SHARED STATE CHANGED")
	assert.Contains(t, o.stderr, "unreadable")
}

// A run's host footprint is bounded: past its captured-output cap or its directory-size cap it
// is stopped as ERROR (never a kill) and its container is removed by the recorded id.
func TestWriteBoundsStopRun(t *testing.T) {
	cases := map[string]struct{ image, flag, want string }{
		"output": {"flood", "--max-output-mib", "output over 1 MiB"},
		"disk":   {"fill", "--max-disk-mib", "run directory over 1 MiB"},
		// The log is outside the run's mount and measured by the runner's own descriptor.
		"output despite tamper": {"truncatelog", "--max-output-mib", "output over 1 MiB"},
		"entries":               {"manyfiles", "--max-files", "run directory over 10 entries"},
		// A burst written just before a normal exit is caught by the check before the exit is accepted.
		"burst before exit": {"burst", "--max-output-mib", "output over 1 MiB"},
		// An unreadable entry fails the measurement closed rather than being skipped.
		"unreadable": {"lockdir", "--max-files", "unreadable entry in the run directory"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, passingCheck)
			foreignContainer(t, f.log)
			start := time.Now()
			val := "1"
			switch c.flag {
			case "--max-files":
				val = map[string]string{"manyfiles": "10", "lockdir": "100000"}[c.image]
			}
			t.Cleanup(func() {
				_ = filepath.Walk(f.root, func(p string, _ os.FileInfo, _ error) error { _ = os.Chmod(p, 0o755); return nil })
			})
			o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", c.image, c.flag, val)
			assert.Less(t, time.Since(start), 30*time.Second)
			assert.Equal(t, 4, o.code, o.stdout+o.stderr)
			assert.Equal(t, "ERROR", o.outcomes()["baseline"])
			assert.Contains(t, o.stderr, c.want)
			assert.Len(t, removals(t, f.log), 1)
			assert.Len(t, registry(t, f.log), 1, "only the foreign container is left")
		})
	}
}

// Source preparation is inside the whole-run deadline: the host-side copies check it per file,
// so a copy whose deadline passes stops promptly instead of running to the end, and a copy whose
// deadline has already passed copies nothing.
func TestTreeCopyInsideDeadline(t *testing.T) {
	root := t.TempDir()
	prog := `
import importlib.util, os, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
root = Path(sys.argv[2])
src = root / "src"; (src / "big").mkdir(parents=True)
for i in range(20000):
    open(src / "big" / ("f%05d" % i), "w").close()
def attempt(fn):
    start = time.monotonic()
    try:
        fn()
        return "completed", time.monotonic() - start
    except ms.Stopped:
        return "stopped", time.monotonic() - start
full, full_secs = attempt(lambda: ms.copy_tree(src, root / "full", ()))
cut, cut_secs = attempt(lambda: ms.copy_tree(src, root / "cut", (), time.monotonic() + 0.05))
copied = sum(1 for _ in (root / "cut" / "big").iterdir()) if (root / "cut" / "big").exists() else 0
gone, _ = attempt(lambda: ms.clone_dir(src, root / "late", time.monotonic() - 1))
print(full, cut, gone, copied < 20000, cut_secs < full_secs, (root / "late").exists())
`
	out, err := exec.Command(python(t), "-I", "-c", prog, script(t, "mutate-sandboxed.py"), root).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Equal(t, "completed stopped stopped True True False\n", string(out))
}

// Run directories do not accumulate: each is discarded once its result is recorded, and the
// whole work directory is checked against --max-work-mib before every copy into it.
func TestWorkDirectoryDoesNotAccumulate(t *testing.T) {
	f := newFixture(t, passingCheck)
	pad := make([]byte, 2<<20)
	require.NoError(t, os.WriteFile(filepath.Join(f.tree, "pad.bin"), pad, 0o644))
	var list []map[string]any
	for i := range 6 {
		list = append(list, map[string]any{"name": fmt.Sprintf("m%d", i), "file": "check.sh",
			"old": ": GUARD", "new": fmt.Sprintf(": GUARD %d", i)})
	}
	// pristine 2 MiB + one live run copy 2 MiB fits 6 MiB; six kept copies would not.
	o := f.run(t, f.mutants(t, list), "--max-work-mib", "6", "--no-warm-gocache")
	require.Equal(t, 0, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stdout, "mutants: 0/6 killed")

	g := newFixture(t, passingCheck)
	require.NoError(t, os.WriteFile(filepath.Join(g.tree, "pad.bin"), pad, 0o644))
	o = g.run(t, g.mutants(t, []map[string]any{cleanupMutant}), "--max-work-mib", "1", "--no-warm-gocache")
	assert.Equal(t, 6, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "the work directory would pass 1 MiB")
	assert.Empty(t, dockerRuns(t, g.log))
}

// A baseline that swaps its build cache for a link to a host directory cannot get that directory
// cloned into the warm cache: the clone is refused, and the host file never reaches a mount.
func TestWarmCacheRefusesSwappedLink(t *testing.T) {
	f := newFixture(t, passingCheck)
	secret := filepath.Join(f.root, "host-private")
	require.NoError(t, os.MkdirAll(secret, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(secret, "private.txt"), []byte("host secret\n"), 0o600))
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "swapcache")
	assert.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "runs through the symlink sandbox/gocache")
	var leaked []string
	_ = filepath.Walk(f.workRoot, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Name() == "private.txt" {
			leaked = append(leaked, p)
		}
		return nil
	})
	assert.Empty(t, leaked, "the host file was never copied into the work directory")
	assert.Len(t, dockerRuns(t, f.log), 1, "no mutant ran after the refusal")
}

// A FIFO left in the baseline's build cache is refused before the host copies it (a copy would
// block on it forever), and the run stops inside its deadline.
func TestWarmCacheRefusesSpecialFile(t *testing.T) {
	f := newFixture(t, passingCheck)
	start := time.Now()
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "fifocache", "--deadline", "30")
	assert.Less(t, time.Since(start), 20*time.Second)
	assert.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "is a special file")
}

// A link nested below the cache root is copied as a link, never followed: the host directory it
// names is not read into the warm cache or any mutant's directory.
func TestWarmCacheKeepsNestedLinkAsLink(t *testing.T) {
	f := newFixture(t, passingCheck)
	secret := filepath.Join(f.root, "host-private")
	require.NoError(t, os.MkdirAll(secret, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(secret, "private.txt"), []byte("host secret\n"), 0o600))
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "nestedlink", "--keep")
	require.Equal(t, 0, o.code, o.stdout+o.stderr)
	workdir := o.report["workdir"].(string)
	var leaked []string
	_ = filepath.Walk(workdir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Name() == "private.txt" {
			leaked = append(leaked, p)
		}
		return nil
	})
	assert.Empty(t, leaked, "the nested link was never followed")
	link := filepath.Join(workdir, "warm-gocache", "nested")
	fi, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink, "the nested entry stays a link")
}

// The host reads a run's directory only once its container is gone or stopped.
func TestBaselineMustBeStoppedBeforeCacheRead(t *testing.T) {
	f := newFixture(t, passingCheck)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "staysup")
	assert.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "is still running; the host will not read its files")
	assert.Len(t, dockerRuns(t, f.log), 1, "no mutant ran")
	rm := removals(t, f.log)
	require.Len(t, rm, 1, "the still-running container is removed")
	assert.Contains(t, o.stderr, rm[0]+": removed")
	assert.Empty(t, registry(t, f.log))
}

// A failed inspection establishes nothing: when docker cannot answer, the host refuses to read
// the baseline's files rather than assuming the container is gone.
func TestStoppedCheckFailsClosed(t *testing.T) {
	f := alarmFixture(t, `open(LOG + ".daemondown", "w").close()`)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}))
	assert.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "cannot establish that the container of baseline")
}

// A container whose removal fails stays pending: no further run starts, the finalizer retries,
// and the run says loudly which containers it could not confirm removed.
func TestFailedRemovalStaysPending(t *testing.T) {
	f := newFixture(t, passingCheck)
	require.NoError(t, os.WriteFile(f.log+".rmfail", nil, 0o644))
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "hang", "--timeout", "1")
	assert.Equal(t, 6, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "a container could not be confirmed removed")
	assert.Contains(t, o.stderr, "CONTAINERS NOT CONFIRMED REMOVED")
	assert.Len(t, dockerRuns(t, f.log), 1, "no further run started")
	raw, err := os.ReadFile(f.log)
	require.NoError(t, err)
	assert.Equal(t, 2, strings.Count(string(raw), `["rm", "-f"`), "the removal was tried, then retried by the finalizer")
}

// The size walk streams entries and checks its limits per entry: a directory far larger than the
// entry cap is cut off at the cap, not listed whole; links are never followed; depth is capped.
func TestDirUsageStreamsAndCaps(t *testing.T) {
	root := t.TempDir()
	prog := `
import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
root = Path(sys.argv[2])
wide = root / "wide"; wide.mkdir()
for i in range(5000):
    open(wide / ("f%d" % i), "w").close()
outside = root / "outside"; outside.mkdir(); (outside / "big").write_bytes(b"x" * (1 << 20))
linked = root / "linked"; linked.mkdir(); os.symlink(outside, linked / "to-outside")
deep = root / "deep"; p = deep
for i in range(10):
    p = p / "d"
p.mkdir(parents=True)
used, n, problem = ms.dir_usage(wide, 10, 60.0); print(n, problem)
used, n, problem = ms.dir_usage(linked, 100, 60.0); print(n, problem, used < (1 << 20))
used, n, problem = ms.dir_usage(deep, 100, 60.0, max_depth=5); print(problem)
used, n, problem = ms.dir_usage(root / "absent", 100, 60.0); print(n, problem)
`
	out, err := exec.Command(python(t), "-I", "-c", prog, script(t, "mutate-sandboxed.py"), root).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Equal(t, "11 run directory over 10 entries\n1 None True\nrun directory nested over 5 levels\n0 None\n", string(out))
}

// An image that declares a VOLUME is refused by the runner and the demo before any container
// runs: Docker would give each run an anonymous writable host volume outside its bounds.
func TestImageWithDeclaredVolumeRefused(t *testing.T) {
	f := newFixture(t, passingCheck)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "volimage")
	assert.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "declares VOLUME /data")
	assert.Empty(t, dockerRuns(t, f.log))

	cmd, out := demo(t, f.docker, "sandboxed", filepath.Join(f.root, "evidence"), "sha256:volimage")
	assert.Equal(t, 2, exitCode(t, cmd.Run()), out.String())
	assert.Contains(t, out.String(), "declares VOLUME /data")
}

// The stopped-state check is inside the deadline: a docker slow to answer it stops the run
// (exit 6) near the deadline, and the container goes through the ownership-checked removal.
func TestStoppedCheckInsideDeadline(t *testing.T) {
	f := alarmFixture(t, `open(LOG + ".slowstate", "w").close()`)
	start := time.Now()
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--deadline", "9")
	assert.Less(t, time.Since(start), 15*time.Second)
	assert.Equal(t, 6, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "whether baseline stopped")
}

// The step-2 leaky docker parses the exact argument list the runner emits (captured from a real
// runner invocation against the fake docker), so a new runner flag cannot silently break step 2:
// an option the stand-in does not know is an error, never skipped.
func TestLeakyDockerParsesRunnerArgv(t *testing.T) {
	f := newFixture(t, passingCheck)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}))
	require.Equal(t, 0, o.code, o.stdout+o.stderr)
	runs := dockerRuns(t, f.log)
	require.NotEmpty(t, runs)
	raw, err := json.Marshal(runs)
	require.NoError(t, err)
	prog := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("leaky", sys.argv[1])
leaky = importlib.util.module_from_spec(spec); spec.loader.exec_module(leaky)
for argv in json.loads(sys.argv[2]):
    work, cmd = leaky.parse_run(argv)
    print(work.endswith("-baseline") or "-" in work, cmd)
try:
    leaky.parse_run(["run", "--brand-new-flag", "x", "image", "sh"])
except ValueError as e:
    print("refused:", e)
`
	out, err := exec.Command(python(t), "-I", "-c", prog, script(t, filepath.Join("testdata", "leaky-docker.py")), string(raw)).CombinedOutput()
	require.NoError(t, err, string(out))
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.Len(t, lines, len(runs)+1)
	for _, l := range lines[:len(runs)] {
		assert.Equal(t, "True ['sh', 'check.sh']", l)
	}
	assert.Equal(t, "refused: unknown docker run option --brand-new-flag", lines[len(runs)])
}

// A sparse file is counted at the size a copy would take: a baseline that leaves a 64 MiB sparse
// file in its build cache is stopped before the warm-cache copy writes it out in full.
func TestSparseFileCountedAtCopySize(t *testing.T) {
	f := newFixture(t, passingCheck)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "sparsecache", "--max-work-mib", "32")
	assert.Equal(t, 6, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "before the warm build cache: the work directory would pass 32 MiB")
	assert.NoFileExists(t, filepath.Join(o.report["workdir"].(string), "warm-gocache", "sparse"))
}

// The first copy of the live tree is checked to fit before it starts: a tree larger than the
// work-directory cap stops the run with nothing copied, and what the copy excludes is not counted.
func TestTreeCheckedBeforeFirstCopy(t *testing.T) {
	f := newFixture(t, passingCheck)
	require.NoError(t, os.WriteFile(filepath.Join(f.tree, "pad.bin"), make([]byte, 2<<20), 0o644))
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--max-work-mib", "1")
	assert.Equal(t, 6, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "before copying the tree: the work directory would pass 1 MiB")
	assert.NoFileExists(t, filepath.Join(o.report["workdir"].(string), "pristine", "pad.bin"))

	g := newFixture(t, passingCheck)
	require.NoError(t, os.MkdirAll(filepath.Join(g.tree, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(g.tree, ".git", "pack"), make([]byte, 2<<20), 0o644))
	o = g.run(t, g.mutants(t, []map[string]any{cleanupMutant}), "--max-work-mib", "1", "--no-warm-gocache")
	assert.Equal(t, 0, o.code, "an excluded .git is not counted: %s", o.stdout+o.stderr)
}

// ---------------------------------------------------------------- TXE-8053: --diagnostic and --ro-mount

const viewOID = "0123456789abcdef0123456789abcdef01234567"

// gitView writes a directory in the TXE-8047 view shape (commit objects, shallow, a detached HEAD,
// an index, a core-only config, empty refs) under parent and returns its real path.
func gitView(t *testing.T, parent string) string {
	t.Helper()
	dir := filepath.Join(parent, "view")
	for _, d := range []string{"objects/pack", "objects/info", "objects/01", "refs/heads", "refs/tags"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, d), 0o755))
	}
	for rel, body := range map[string]string{
		"HEAD":                                   viewOID + "\n",
		"shallow":                                viewOID + "\n",
		"config":                                 "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n",
		"index":                                  "DIRC\x00\x00\x00\x02\x00\x00\x00\x00",
		"objects/pack/pack-" + viewOID + ".pack": "PACK\x00\x00\x00\x02",
		"objects/pack/pack-" + viewOID + ".idx":  "\xfftOc",
		"objects/01/" + viewOID[2:]:              "loose object",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644))
	}
	real, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	return real
}

// goManifest is the --ro-manifest rule written independently: "D <rel>" per directory and
// "F <size> <sha256> <rel>" per file, sorted by rel as bytes, hashed together.
func goManifest(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		require.NoError(t, err)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			lines = append(lines, "D "+rel+"\n")
			return nil
		}
		raw, err := os.ReadFile(p)
		require.NoError(t, err)
		lines = append(lines, fmt.Sprintf("F %d %x %s\n", len(raw), sha256.Sum256(raw), rel))
		return nil
	}))
	last := func(s string) string { f := strings.Fields(s); return f[len(f)-1] }
	sort.Slice(lines, func(i, j int) bool { return last(lines[i]) < last(lines[j]) })
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(lines, ""))))
}

func roManifest(t *testing.T, dir string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(python(t), "-I", script(t, "mutate-sandboxed.py"), "--ro-manifest", dir)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out.String(), errb.String()
	}
	require.NoError(t, err)
	return 0, strings.TrimSpace(out.String()), errb.String()
}

// The runner's manifest equals the rule computed independently, includes empty directories, and
// changes when one file's content, one name or one empty directory changes.
func TestRoManifest(t *testing.T) {
	view := gitView(t, t.TempDir())
	code, got, stderr := roManifest(t, view)
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, goManifest(t, view), got)
	seen := map[string]bool{got: true}
	for name, change := range map[string]func(){
		"content":   func() { require.NoError(t, os.WriteFile(filepath.Join(view, "index"), []byte("DIRC-other"), 0o644)) },
		"name":      func() { require.NoError(t, os.Rename(filepath.Join(view, "shallow"), filepath.Join(view, "shallow2"))) },
		"empty dir": func() { require.NoError(t, os.Mkdir(filepath.Join(view, "refs", "remotes"), 0o755)) },
	} {
		change()
		code, next, stderr := roManifest(t, view)
		require.Equal(t, 0, code, stderr)
		assert.False(t, seen[next], "%s: the manifest did not change", name)
		assert.Equal(t, goManifest(t, view), next, name)
		seen[next] = true
	}
}

// Every --ro-mount shape outside the contract is refused (exit 2) before any container runs:
// source shapes, protected-state overlap, destinations, the hash, a writable form, the git view's
// contents, and the bounds. Nothing here needs privileged host access.
func TestRoMountShapesRefused(t *testing.T) {
	home, err := filepath.EvalSymlinks(os.Getenv("HOME"))
	require.NoError(t, err)
	type setup func(t *testing.T, f fixture, view, sum string) []string
	spec := func(src, dst, sum string) []string { return []string{"--ro-mount", src + ":" + dst + ":" + sum} }
	git := "/work/src/.git"
	write := func(t *testing.T, p, body string) {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	}
	realDir := func(t *testing.T, p string) string {
		require.NoError(t, os.MkdirAll(p, 0o755))
		r, err := filepath.EvalSymlinks(p)
		require.NoError(t, err)
		return r
	}
	cases := map[string]struct {
		setup setup
		want  string
	}{
		"relative source": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec("view", git, sum)
		}, "absolute path equal to its own realpath"},
		"dot-dot source": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(view+"/../view", git, sum)
		}, "own realpath"},
		"trailing slash": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(view+"/", git, sum)
		}, "own realpath"},
		"symlinked parent": {func(t *testing.T, f fixture, view, sum string) []string {
			link := filepath.Join(filepath.Dir(filepath.Dir(view)), "linked-parent")
			require.NoError(t, os.Symlink(filepath.Dir(view), link))
			return spec(link+"/view", git, sum)
		}, "own realpath"},
		"source is a symlink": {func(t *testing.T, f fixture, view, sum string) []string {
			link := filepath.Join(filepath.Dir(view), "view-link")
			require.NoError(t, os.Symlink(view, link))
			return spec(link, git, sum)
		}, "own realpath"},
		"source is a file": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(filepath.Join(view, "HEAD"), git, sum)
		}, "not a plain directory"},
		"symlink inside": {func(t *testing.T, f fixture, view, sum string) []string {
			require.NoError(t, os.Symlink(f.modcache, filepath.Join(view, "refs", "heads", "main")))
			return spec(view, git, sum)
		}, "is a symlink"},
		"fifo inside": {func(t *testing.T, f fixture, view, sum string) []string {
			require.NoError(t, syscall.Mkfifo(filepath.Join(view, "objects", "info", "pipe"), 0o644))
			return spec(view, git, sum)
		}, "special file"},
		"name outside the portable set": {func(t *testing.T, f fixture, view, sum string) []string {
			require.NoError(t, os.Mkdir(filepath.Join(view, "refs", "heads", "café"), 0o755))
			return spec(view, git, sum)
		}, "names must use only"},
		"name with a trailing newline": {func(t *testing.T, f fixture, view, sum string) []string {
			require.NoError(t, os.Mkdir(filepath.Join(view, "refs", "heads", "x\n"), 0o755))
			return spec(view, git, sum)
		}, "names must use only"},
		"hash with a trailing newline": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(view, git, sum+"\n")
		}, "64 lowercase hex"},
		"name with a space": {func(t *testing.T, f fixture, view, sum string) []string {
			require.NoError(t, os.Mkdir(filepath.Join(view, "refs", "heads", "a b"), 0o755))
			return spec(view, git, sum)
		}, "names must use only"},
		"source is the live tree": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(realDir(t, f.tree), git, sum)
		}, "overlaps live tree"},
		"source inside the live tree": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(realDir(t, filepath.Join(f.tree, "sub")), git, sum)
		}, "overlaps live tree"},
		"source contains the shared module cache": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(realDir(t, filepath.Join(f.root, "fake-gopath")), git, sum)
		}, "overlaps shared GOMODCACHE"},
		"source inside the shared build cache": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(realDir(t, filepath.Join(f.gocache, "sub")), git, sum)
		}, "overlaps shared GOCACHE"},
		"source contains HOME": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(filepath.Dir(home), git, sum)
		}, "overlaps"}, // GOPATH (under HOME) may be named first: the order is the forbidden map's
		"destination /":           {func(t *testing.T, f fixture, view, sum string) []string { return spec(view, "/", sum) }, "is not one of"},
		"destination /etc":        {func(t *testing.T, f fixture, view, sum string) []string { return spec(view, "/etc", sum) }, "is not one of"},
		"destination /work":       {func(t *testing.T, f fixture, view, sum string) []string { return spec(view, "/work", sum) }, "is not one of"},
		"destination /work/src":   {func(t *testing.T, f fixture, view, sum string) []string { return spec(view, "/work/src", sum) }, "is not one of"},
		"destination in the tree": {func(t *testing.T, f fixture, view, sum string) []string { return spec(view, "/work/src/x", sum) }, "is not one of"},
		"destination in sandbox": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(view, "/work/sandbox/gocache", sum)
		}, "is not one of"},
		"destination /goproxy": {func(t *testing.T, f fixture, view, sum string) []string { return spec(view, "/goproxy", sum) }, "is not one of"},
		"destination /tmp":     {func(t *testing.T, f fixture, view, sum string) []string { return spec(view, "/tmp", sum) }, "is not one of"},
		"destination with dot-dot": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(view, "/work/src/../src/.git", sum)
		}, "is not one of"},
		"relative destination":       {func(t *testing.T, f fixture, view, sum string) []string { return spec(view, "work/src/.git", sum) }, "is not one of"},
		"destination trailing slash": {func(t *testing.T, f fixture, view, sum string) []string { return spec(view, git+"/", sum) }, "is not one of"},
		"destination twice": {func(t *testing.T, f fixture, view, sum string) []string {
			return append(spec(view, git, sum), spec(view, git, sum)...)
		}, "given twice"},
		"wrong hash": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(view, git, strings.Repeat("0", 64))
		}, "the copy's manifest is"},
		"uppercase hash": {func(t *testing.T, f fixture, view, sum string) []string {
			return spec(view, git, strings.ToUpper(sum))
		}, "64 lowercase hex"},
		"missing hash": {func(t *testing.T, f fixture, view, sum string) []string {
			return []string{"--ro-mount", view + ":" + git}
		}, "expected SRC:DST:SHA256"},
		"writable option": {func(t *testing.T, f fixture, view, sum string) []string {
			return []string{"--ro-mount", view + ":" + git + ":rw:" + sum}
		}, "is not one of"},
		"hooks": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "hooks", "post-checkout"), "#!/bin/sh\n")
			return spec(view, git, goManifest(t, view))
		}, "git view: hooks is not part of the view"},
		"alternates": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "objects", "info", "alternates"), "/elsewhere/objects\n")
			return spec(view, git, goManifest(t, view))
		}, "no alternates"},
		"a ref": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "refs", "heads", "main"), viewOID+"\n")
			return spec(view, git, goManifest(t, view))
		}, "holds no refs"},
		"packed refs": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "packed-refs"), viewOID+" refs/remotes/origin/main\n")
			return spec(view, git, goManifest(t, view))
		}, "packed-refs is not part of the view"},
		"reflog": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "logs", "HEAD"), "x\n")
			return spec(view, git, goManifest(t, view))
		}, "logs is not part of the view"},
		"remote in config": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "config"), "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.invalid/x\n")
			return spec(view, git, goManifest(t, view))
		}, "only [core] is allowed"},
		"credential helper in config": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "config"), "[credential]\n\thelper = store\n")
			return spec(view, git, goManifest(t, view))
		}, "only [core] is allowed"},
		"hooksPath in core": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "config"), "[core]\n\thooksPath = /elsewhere\n")
			return spec(view, git, goManifest(t, view))
		}, "only core."},
		"include in config": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "config"), "[include]\n\tpath = /elsewhere/config\n")
			return spec(view, git, goManifest(t, view))
		}, "only [core] is allowed"},
		"symbolic HEAD": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "HEAD"), "ref: refs/heads/main\n")
			return spec(view, git, goManifest(t, view))
		}, "HEAD must be a detached object id"},
		"no HEAD": {func(t *testing.T, f fixture, view, _ string) []string {
			require.NoError(t, os.Remove(filepath.Join(view, "HEAD")))
			return spec(view, git, goManifest(t, view))
		}, "HEAD is missing"},
		"worktree link": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "commondir"), "/elsewhere/.git\n")
			return spec(view, git, goManifest(t, view))
		}, "commondir is not part of the view"},
		"file count bound": {func(t *testing.T, f fixture, view, sum string) []string {
			return append(spec(view, git, sum), "--ro-max-files", "3")
		}, "holds over 3 entries"},
		"depth bound": {func(t *testing.T, f fixture, view, sum string) []string {
			return append(spec(view, git, sum), "--ro-max-depth", "1")
		}, "nested over 1 levels"},
		"file size bound": {func(t *testing.T, f fixture, view, _ string) []string {
			write(t, filepath.Join(view, "index"), strings.Repeat("x", 1<<20+1))
			return append(spec(view, git, goManifest(t, view)), "--ro-max-file-mib", "1")
		}, "over 1048576 bytes"},
		"total size bound": {func(t *testing.T, f fixture, view, sum string) []string {
			return append(spec(view, git, sum), "--ro-max-mib", "0")
		}, "pass 0 bytes"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, passingCheck)
			view := gitView(t, f.root)
			o := f.diag(t, c.setup(t, f, view, goManifest(t, view))...)
			assert.Equal(t, 2, o.code, o.stdout+o.stderr)
			assert.Contains(t, o.stderr, "refused")
			assert.Contains(t, o.stderr, c.want)
			if _, err := os.Stat(f.log); err == nil {
				assert.Empty(t, dockerRuns(t, f.log), "no container runs on a refused mount")
			}
		})
	}
	// Two names that differ only in case, where the file system keeps both.
	t.Run("names differing in case", func(t *testing.T) {
		f := newFixture(t, passingCheck)
		view := gitView(t, f.root)
		require.NoError(t, os.Mkdir(filepath.Join(view, "refs", "heads", "A"), 0o755))
		if err := os.Mkdir(filepath.Join(view, "refs", "heads", "a"), 0o755); err != nil {
			t.Skip("this file system folds case, so the two names cannot coexist")
		}
		o := f.diag(t, spec(view, git, goManifest(t, view))...)
		assert.Equal(t, 2, o.code, o.stdout+o.stderr)
		assert.Contains(t, o.stderr, "differs only in case")
	})
}

func mountArgs(argv []string) []string {
	var out []string
	for i, a := range argv {
		if a == "--mount" {
			out = append(out, argv[i+1])
		}
	}
	return out
}

// An accepted view is copied, never mounted itself: the one extra mount is a read-only bind of
// the runner's copy inside its work directory, outside the run's read-write directory, at
// /work/src/.git, with GIT_OPTIONAL_LOCKS=0. The copy has the manifest, and no file in it has a
// second link. Without --ro-mount the argv carries no extra mount and no git variable.
func TestRoMountArgv(t *testing.T) {
	f := newFixture(t, passingCheck)
	view := gitView(t, f.root)
	// The live tree's own .git is never copied (excluded at every depth), so the mount at
	// /work/src/.git shadows no source data.
	require.NoError(t, os.MkdirAll(filepath.Join(f.tree, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(f.tree, ".git", "config"), []byte("[remote \"live\"]\n"), 0o644))
	// Restrictive source modes and umask: the copy's modes are set by the runner, not inherited.
	require.NoError(t, filepath.WalkDir(view, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() {
			return os.Chmod(p, 0o700)
		}
		return os.Chmod(p, 0o600)
	}))
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	sum := goManifest(t, view)
	o := f.diag(t, "--ro-mount", view+":/work/src/.git:"+sum)
	require.Equal(t, 7, o.code, o.stdout+o.stderr)
	runs := dockerRuns(t, f.log)
	require.Len(t, runs, 1)
	mounts := mountArgs(runs[0])
	require.Len(t, mounts, 2, "the run's directory and the read-only copy (no seed)")
	work := o.report["workdir"].(string)
	realWork, err := filepath.EvalSymlinks(work)
	require.NoError(t, err)
	var rw, ro string
	for _, m := range mounts {
		if strings.HasSuffix(m, ",target=/work/src/.git,readonly") {
			ro = strings.TrimSuffix(strings.TrimPrefix(m, "type=bind,source="), ",target=/work/src/.git,readonly")
		} else {
			require.True(t, strings.HasSuffix(m, ",target=/work"), m)
			rw = strings.TrimSuffix(strings.TrimPrefix(m, "type=bind,source="), ",target=/work")
		}
	}
	require.NotEmpty(t, ro, "the read-only mount: %v", mounts)
	assert.Equal(t, filepath.Join(realWork, "ro", "00"), ro, "the runner's copy, never the caller's directory")
	assert.NotEqual(t, view, ro)
	assert.False(t, strings.HasPrefix(ro+"/", rw+"/") || strings.HasPrefix(rw+"/", ro+"/"), "no writable alias: %s vs %s", ro, rw)
	assert.Contains(t, strings.Join(runs[0], " "), "--env GIT_OPTIONAL_LOCKS=0")
	assert.Equal(t, sum, goManifest(t, ro))
	require.NoError(t, filepath.WalkDir(ro, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		fi, err := os.Lstat(p)
		require.NoError(t, err)
		st := fi.Sys().(*syscall.Stat_t)
		assert.EqualValues(t, os.Getuid(), st.Uid, "owned by the runner's uid, the container's --user: %s", p)
		if d.IsDir() {
			assert.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "directory modes are normalised: %s", p)
			return nil
		}
		assert.EqualValues(t, 1, st.Nlink, p)
		assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "file modes are normalised: %s", p)
		return nil
	}))
	assert.NoDirExists(t, filepath.Join(work, "pristine", ".git"), "the tree copy holds no .git to shadow")
	mountsReport := o.report["ro_mounts"].([]any)
	require.Len(t, mountsReport, 1)
	assert.Equal(t, filepath.Join(work, "ro", "00"), mountsReport[0].(map[string]any)["copy"])

	t.Run("without --ro-mount", func(t *testing.T) {
		g := newFixture(t, passingCheck)
		o := g.run(t, g.mutants(t, []map[string]any{cleanupMutant}))
		require.Equal(t, 0, o.code, o.stderr)
		for _, argv := range dockerRuns(t, g.log) {
			assert.Len(t, mountArgs(argv), 1)
			assert.NotContains(t, strings.Join(argv, " "), "GIT_")
		}
	})
}

// The read-only boundary failing (the fake docker writing into the mounted copy, or giving one of
// its files a second link from the writable run directory) is exit 3 with no verdict: never a
// refusal, never a recorded diagnostic.
func TestRoMountChangeAlarms(t *testing.T) {
	cases := map[string]struct{ effect, want string }{
		"content written": {`open(os.path.join(mounts["/work/src/.git"], "HEAD"), "w").write("tampered\n")`, "manifest is"},
		"file added":      {`open(os.path.join(mounts["/work/src/.git"], "objects", "info", "x"), "w").close()`, "manifest is"},
		"writable alias":  {`os.link(os.path.join(mounts["/work/src/.git"], "index"), os.path.join(mounts["/work"], "alias"))`, "links: a writable alias"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, passingCheck)
			f.docker = fakeDocker(t, f.root, f.log, c.effect)
			view := gitView(t, f.root)
			o := f.diag(t, "--ro-mount", view+":/work/src/.git:"+goManifest(t, view))
			require.Equal(t, 3, o.code, o.stdout+o.stderr)
			assert.Contains(t, o.stderr, "SHARED STATE CHANGED")
			assert.Contains(t, o.stderr, "the read-only mount /work/src/.git")
			assert.Contains(t, o.stderr, c.want)
			assert.Empty(t, o.outcomes(), "a run whose read-only mount changed has no verdict")
			assert.NotContains(t, o.report, "diagnostic")
			assert.DirExists(t, o.report["workdir"].(string))
		})
	}
}

// The copy is checked again immediately before every mount: a change made on the host between
// runs is the boundary failing (SharedStateChanged), and a mountpoint that is not an empty plain
// directory is refused. check_mounts refuses a read-only source that a read-write mount reaches,
// and two mounts on one target.
func TestRoCopyRevalidatedBeforeMount(t *testing.T) {
	root := t.TempDir()
	view := gitView(t, root)
	tree := filepath.Join(root, "tree")
	require.NoError(t, os.Mkdir(tree, 0o755))
	prog := `
import importlib.util, sys, os, time
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
root, view, digest, tree = Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
def verdict(f):
    try:
        f(); return "ok"
    except ms.Stopped:
        return "stopped"
    except ms.SharedStateChanged:
        return "alarm"
    except ms.Refused:
        return "refused"
args = ms.parse(["--diagnostic", "--image", "img", "--tree", tree, "--", "true"])
work = ms.WorkDir(root)
runner = ms.Runner(args, ms.Watch({}), {}, work, "docker", [])
m = ms.parse_ro_mounts([view + ":/work/src/.git:" + digest])[0]
ms.prepare_ro_mount(m, work.path, 0, {}, runner.ro_limits)
runner.ro_mounts = [m]
d = work.path / "001-x"
(d / "src" / ".git").mkdir(parents=True)
cid = work.path / "c.cid"
print(verdict(lambda: runner.docker_argv(d, "n", cid)))
(d / "src" / ".git" / "stray").write_text("x")
print(verdict(lambda: runner.docker_argv(d, "n", cid)))
os.remove(d / "src" / ".git" / "stray")
os.chmod(m.copy / "config", 0o600)
print(verdict(lambda: runner.docker_argv(d, "n", cid)))
os.chmod(m.copy / "config", 0o644)
print(verdict(lambda: runner.docker_argv(d, "n", cid)))
past = time.monotonic() - 1
print(verdict(lambda: ms.verify_ro_copy(m, runner.ro_limits, past)))
print(verdict(lambda: runner.verify_ro_mounts("late", past)))
shadow = work.path / "pristine-with-git"; (shadow / ".git").mkdir(parents=True); (shadow / ".git" / "x").write_text("x")
print(verdict(lambda: runner.prepare("shadow", shadow, None)))
(m.copy / "HEAD").write_text("tampered\n")
print(verdict(lambda: runner.docker_argv(d, "n", cid)))
w = work.path / "rw"; w.mkdir(); (w / "inner").mkdir()
print(verdict(lambda: ms.check_mounts([(w, "/work", False), (w / "inner", "/work/src/.git", True)], work.path, {})))
print(verdict(lambda: ms.check_mounts([(w / "inner", "/work", False), (w, "/work/src/.git", True)], work.path, {})))
print(verdict(lambda: ms.check_mounts([(w, "/work", False), (w / "inner", "/work", True)], work.path, {})))
s = work.path / "sib"; s.mkdir()
print(verdict(lambda: ms.check_mounts([(w, "/work", False), (s, "/work/src/.git", True)], work.path, {})))
`
	out, err := exec.Command(python(t), "-I", "-c", prog, script(t, "mutate-sandboxed.py"), root, view,
		goManifest(t, view), tree).CombinedOutput()
	require.NoError(t, err, string(out))
	// ok; non-empty mountpoint; a mode changed (alarm); restored (ok); a deadline already passed
	// stops the re-hash, directly and through the runner (stopped, never ok); a tree copy holding
	// .git (refused: source data would be shadowed); content changed (alarm); the check_mounts rules.
	assert.Equal(t, "ok\nrefused\nalarm\nok\nstopped\nstopped\nrefused\nalarm\nrefused\nrefused\nrefused\nok\n", string(out))
}

// A diagnostic whose command exits non-zero is recorded as evidence and is not a pass: the runner
// exits 7 (never 0), the report says mode diagnostic, gate never and outcome DIAGNOSTIC, the
// command's status is only in diagnostic.command_exit, and the two raw streams are kept apart in
// files outside every mount with their exact bytes, sizes and sha256.
func TestDiagnosticNonzeroNotPass(t *testing.T) {
	f := newFixture(t, "#!/bin/sh\nprintf 'out-line\\n'\nprintf 'err-line\\n' >&2\nexit 1\n")
	o := f.diag(t)
	require.Equal(t, 7, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stdout, "DIAGNOSTIC: command exit 1 (evidence only, never a pass; runner exit 7)")
	assert.Equal(t, "diagnostic", o.report["mode"])
	assert.Equal(t, "never", o.report["gate"])
	assert.EqualValues(t, 7, o.report["exit"])
	assert.Equal(t, map[string]string{"diagnostic": "DIAGNOSTIC"}, o.outcomes())
	diag := o.report["diagnostic"].(map[string]any)
	assert.Equal(t, "completed", diag["status"])
	assert.EqualValues(t, 1, diag["command_exit"])
	assert.Equal(t, "command", diag["command_exit_attribution"])
	assert.Equal(t, "confirmed", diag["settlement"])
	assert.Equal(t, "held", diag["integrity"])
	assert.Equal(t, "complete", diag["evidence"])
	work := o.report["workdir"].(string)
	for stream, want := range map[string]string{"stdout": "out-line\n", "stderr": "err-line\n"} {
		ev := diag[stream].(map[string]any)
		p := ev["path"].(string)
		assert.Equal(t, filepath.Join(work, "logs", "001."+stream), p, "outside every mount")
		raw, err := os.ReadFile(p)
		require.NoError(t, err)
		assert.Equal(t, want, string(raw), stream)
		assert.EqualValues(t, len(want), ev["bytes"])
		assert.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte(want))), ev["sha256"])
	}
	raw, err := os.ReadFile(filepath.Join(work, "report.json"))
	require.NoError(t, err)
	for _, verdict := range []string{"PASSED", "SURVIVED", "KILLED", "FAILED"} {
		assert.NotContains(t, string(raw), `"`+verdict+`"`, "a diagnostic carries no mutation verdict")
	}
	assert.Len(t, dockerRuns(t, f.log), 1, "one run: no baseline, no mutant")
}

// A command that exits 0 is still only a recorded diagnostic: exit 7, never 0.
func TestDiagnosticZeroNotPass(t *testing.T) {
	f := newFixture(t, passingCheck)
	o := f.diag(t)
	require.Equal(t, 7, o.code, o.stdout+o.stderr)
	assert.EqualValues(t, 0, o.report["diagnostic"].(map[string]any)["command_exit"])
	assert.Equal(t, "DIAGNOSTIC", o.outcomes()["diagnostic"])
}

// --diagnostic takes no mutant list (no dummy mutant, no empty list), and outside diagnostic mode
// a mutant list is still required.
func TestDiagnosticRefusesMutants(t *testing.T) {
	f := newFixture(t, passingCheck)
	o := f.invoke(t, []string{"--diagnostic", "--mutants", f.mutants(t, []map[string]any{cleanupMutant})})
	assert.Equal(t, 2, o.code)
	assert.Contains(t, o.stderr, "--mutants is refused with it")
	o = f.invoke(t, nil)
	assert.Equal(t, 2, o.code)
	assert.Contains(t, o.stderr, "--mutants (or --diagnostic)")
	if _, err := os.Stat(f.log); err == nil {
		assert.Empty(t, dockerRuns(t, f.log))
	}
}

// A diagnostic that did not complete (docker's own exit, a timeout, an output bound) is a finding,
// exit 5, evidence incomplete: never 7 and never 0. The raw docker client exit is kept as recorded,
// and a 125 is attributed to neither side: the API cannot tell docker's from the command's.
func TestDiagnosticNotCompleted(t *testing.T) {
	cases := map[string]struct {
		extra       []string
		outcome     string
		exit        any
		attribution string
	}{
		"docker 125": {[]string{"--image", "infra-125"}, "ERROR", float64(125), "ambiguous: docker-or-command"},
		"timeout":    {[]string{"--image", "hang", "--timeout", "1"}, "TIMEOUT", nil, "none: the docker client was stopped before it returned"},
		"output":     {[]string{"--image", "flood", "--max-output-mib", "1"}, "ERROR", nil, "none: the docker client was stopped before it returned"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, passingCheck)
			o := f.diag(t, c.extra...)
			require.Equal(t, 5, o.code, o.stdout+o.stderr)
			assert.Equal(t, c.outcome, o.outcomes()["diagnostic"])
			diag := o.report["diagnostic"].(map[string]any)
			assert.Equal(t, "not-completed: "+c.outcome, diag["status"])
			assert.Equal(t, c.exit, diag["command_exit"])
			assert.Equal(t, c.attribution, diag["command_exit_attribution"])
			assert.Equal(t, "incomplete", diag["evidence"])
			assert.Equal(t, "confirmed", diag["settlement"])
			assert.Contains(t, o.stderr, "FINDING: diagnostic did not complete")
			assert.NotContains(t, o.stdout, "DIAGNOSTIC: command exit")
		})
	}
}

// A diagnostic during which shared state changed is exit 3 with no recorded result: an integrity
// failure is never masked by 7.
func TestDiagnosticAlarm(t *testing.T) {
	f := alarmFixture(t, `open(os.path.join(modcache, sentinel), "w").write("changed\n")`)
	o := f.diag(t)
	require.Equal(t, 3, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "SHARED STATE CHANGED")
	assert.Empty(t, o.outcomes())
	assert.NotContains(t, o.report, "diagnostic")
	assert.NotContains(t, o.stdout, "DIAGNOSTIC: command exit")
}

// A completed diagnostic is evidence only once its container is confirmed gone. The fake
// "staysup" image exits as a client but leaves its container registered; with removal failing, or
// the daemon unreachable for the owner check, the diagnostic is not complete: exit 5, never 7,
// with the raw command_exit kept, settlement unconfirmed, evidence incomplete and the run directory
// kept. With removal working it is 7.
func TestDiagnosticUnconfirmedContainerIsFinding(t *testing.T) {
	cases := map[string]string{"removal fails": ".rmfail", "daemon unreachable": ".daemondown"}
	for name, flag := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, passingCheck)
			require.NoError(t, os.WriteFile(f.log+flag, nil, 0o644))
			o := f.diag(t, "--image", "staysup")
			require.Equal(t, 5, o.code, o.stdout+o.stderr)
			diag := o.report["diagnostic"].(map[string]any)
			assert.Equal(t, "not-completed: container not confirmed removed", diag["status"])
			assert.EqualValues(t, 0, diag["command_exit"], "the raw command result is kept as evidence")
			assert.Equal(t, "unconfirmed", diag["settlement"])
			assert.Equal(t, "incomplete", diag["evidence"])
			assert.Contains(t, o.stderr, "FINDING: diagnostic did not complete: container")
			assert.Contains(t, o.stderr, "CONTAINERS NOT CONFIRMED REMOVED")
			assert.NotContains(t, o.stdout, "DIAGNOSTIC: command exit")
			assert.NotEmpty(t, o.report["containers_left"])
			entries, err := filepath.Glob(filepath.Join(o.report["workdir"].(string), "001-*"))
			require.NoError(t, err)
			assert.Len(t, entries, 1, "the run directory a container may still mount is kept")
		})
	}
	t.Run("removal confirmed", func(t *testing.T) {
		f := newFixture(t, passingCheck)
		o := f.diag(t, "--image", "staysup")
		require.Equal(t, 7, o.code, o.stdout+o.stderr)
		assert.Len(t, removals(t, f.log), 1, "the lingering container was removed, owner-checked")
		assert.Empty(t, registry(t, f.log))
		assert.Contains(t, o.stdout, "DIAGNOSTIC: command exit 0")
	})
}

// An integrity failure found after the diagnostic was recorded (here the fake docker changes the
// fake shared cache's sentinel while removing the container, after the run's own checks) wins:
// exit 3, the diagnostic marked invalid with integrity failed, its raw command_exit kept, and no DIAGNOSTIC line.
func TestDiagnosticIntegrityOverridesSeven(t *testing.T) {
	f := newFixture(t, passingCheck)
	require.NoError(t, os.WriteFile(f.log+".rmtamper", []byte(filepath.Join(f.modcache, sentinel)), 0o644))
	o := f.diag(t, "--image", "staysup")
	require.Equal(t, 3, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "SHARED STATE CHANGED")
	assert.Contains(t, o.stderr, "after the end of the run")
	diag := o.report["diagnostic"].(map[string]any)
	assert.Equal(t, "invalid: shared state changed", diag["status"])
	assert.EqualValues(t, 0, diag["command_exit"], "the raw command result is kept as evidence")
	assert.Equal(t, "failed", diag["integrity"])
	assert.Equal(t, "incomplete", diag["evidence"])
	assert.Equal(t, "confirmed", diag["settlement"])
	assert.EqualValues(t, 3, o.report["exit"])
	assert.NotContains(t, o.stdout, "DIAGNOSTIC: command exit")
}

// An exception the runner does not expect is a finding, never a pass: the sandboxed command leaves
// a directory the host cannot empty (0500 with a file in it, readable, so the disk bound still
// measures it), and the runner's discard of the run directory raises. The run exits 5, the report
// says exit 5 and names the error, and a diagnostic is marked incomplete.
func TestUnexpectedErrorIsFinding(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root removes through permissions")
	}
	check := "#!/bin/sh\n: CLEANUP\nmkdir -p ../x && touch ../x/f && chmod 500 ../x\nexit 0\n"
	for name, diagnostic := range map[string]bool{"diagnostic": true, "mutation": false} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, check)
			t.Cleanup(func() {
				_ = filepath.Walk(f.root, func(p string, _ os.FileInfo, _ error) error { _ = os.Chmod(p, 0o755); return nil })
			})
			var o outcome
			if diagnostic {
				o = f.diag(t)
			} else {
				o = f.run(t, f.mutants(t, []map[string]any{cleanupMutant}))
			}
			require.Equal(t, 5, o.code, o.stdout+o.stderr)
			assert.EqualValues(t, 5, o.report["exit"], "the report's exit is the process's")
			assert.Contains(t, o.report["error"], "Error")
			assert.Contains(t, o.stderr, "mutate-sandboxed: error:")
			if diagnostic {
				d := o.report["diagnostic"].(map[string]any)
				assert.EqualValues(t, 0, d["command_exit"], "the raw command result is kept as evidence")
				assert.Equal(t, "incomplete", d["evidence"])
				assert.True(t, strings.HasPrefix(d["status"].(string), "not-completed"), d["status"])
				assert.NotContains(t, o.stdout, "DIAGNOSTIC: command exit")
			}
		})
	}
}

// A pass whose work directory cannot be removed (its ownership token changed under it, here by the
// fake docker) is a finding, and BOTH reports say so: the removal is attempted before either report
// is written, so <work>/report.json and --report carry the process's own exit, 5.
func TestCleanupFailureInBothReports(t *testing.T) {
	f := newFixture(t, passingCheck)
	f.docker = fakeDocker(t, f.root, f.log,
		`open(os.path.join(os.path.dirname(mounts["/work"]), ".mutate-sandboxed-owned"), "w").write("someone else")`)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}))
	require.Equal(t, 5, o.code, o.stdout+o.stderr)
	assert.EqualValues(t, 5, o.report["exit"])
	assert.Contains(t, o.report["cleanup_error"], "ownership token")
	raw, err := os.ReadFile(filepath.Join(o.report["workdir"].(string), "report.json"))
	require.NoError(t, err, "the kept work directory receives the report")
	var inner map[string]any
	require.NoError(t, json.Unmarshal(raw, &inner))
	assert.EqualValues(t, 5, inner["exit"], "<work>/report.json carries the final exit too")
}

// A closed stdout (`| head`) neither loses the reports nor changes the exit: both reports are written
// before the DIAGNOSTIC line, and a broken pipe on that line is absorbed.
func TestDiagnosticClosedStdout(t *testing.T) {
	f := newFixture(t, passingCheck)
	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, r.Close())
	report := filepath.Join(f.root, "report.json")
	cmd := exec.Command(python(t), "-I", script(t, "mutate-sandboxed.py"), "--diagnostic", "--tree", f.tree,
		"--shared-modcache", f.modcache, "--shared-gocache", f.gocache, "--workdir-root", f.workRoot,
		"--docker", f.docker, "--no-seed", "--report", report, "--timeout", "60", "--image", "fixture-image",
		"--", "sh", "check.sh")
	cmd.Stdout = w
	var errb bytes.Buffer
	cmd.Stderr = &errb
	err = cmd.Run()
	require.NoError(t, w.Close())
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else {
		require.NoError(t, err)
	}
	require.Equal(t, 7, code, errb.String())
	assert.NotContains(t, errb.String(), "Traceback")
	raw, err := os.ReadFile(report)
	require.NoError(t, err)
	var rep map[string]any
	require.NoError(t, json.Unmarshal(raw, &rep))
	assert.EqualValues(t, 7, rep["exit"])
	inner, err := os.ReadFile(filepath.Join(rep["workdir"].(string), "report.json"))
	require.NoError(t, err)
	assert.Equal(t, raw, inner)
}

// docker's own --rm can finish while the runner's rm -f is refused ("removal already in
// progress"); one more inspect that finds it gone counts as absent, so the diagnostic settles: 7.
func TestRemovalInProgressCountsAbsent(t *testing.T) {
	f := newFixture(t, passingCheck)
	require.NoError(t, os.WriteFile(f.log+".rmrace", nil, 0o644))
	o := f.diag(t, "--image", "staysup")
	require.Equal(t, 7, o.code, o.stdout+o.stderr)
	assert.Equal(t, "confirmed", o.report["diagnostic"].(map[string]any)["settlement"])
	assert.Contains(t, o.stderr, ": absent")
	assert.Empty(t, registry(t, f.log))
}

// "Removal already in progress" with the container still there is not absence: settlement is
// unconfirmed and the diagnostic is 5, with its raw command_exit kept.
func TestRemovalInProgressStillPresentIsFinding(t *testing.T) {
	f := newFixture(t, passingCheck)
	require.NoError(t, os.WriteFile(f.log+".rmrace-stays", nil, 0o644))
	o := f.diag(t, "--image", "staysup")
	require.Equal(t, 5, o.code, o.stdout+o.stderr)
	d := o.report["diagnostic"].(map[string]any)
	assert.Equal(t, "unconfirmed", d["settlement"])
	assert.Equal(t, "incomplete", d["evidence"])
	assert.EqualValues(t, 0, d["command_exit"])
	assert.NotContains(t, o.stdout, "DIAGNOSTIC: command exit")
}

// A --report that cannot be written (here a directory) is missing evidence: the diagnostic is 5,
// never 7, and the kept work directory's report says so, with no DIAGNOSTIC line.
func TestReportWriteFailureIsFinding(t *testing.T) {
	f := newFixture(t, passingCheck)
	dir := filepath.Join(f.root, "report-is-a-directory")
	require.NoError(t, os.Mkdir(dir, 0o755))
	o := f.diag(t, "--report", dir) // the later --report wins
	require.Equal(t, 5, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "cannot write the report")
	assert.NotContains(t, o.stdout, "DIAGNOSTIC: command exit")
	inner, err := filepath.Glob(filepath.Join(f.workRoot, "mutate-sandboxed-*", "report.json"))
	require.NoError(t, err)
	require.Len(t, inner, 1)
	raw, err := os.ReadFile(inner[0])
	require.NoError(t, err)
	var rep map[string]any
	require.NoError(t, json.Unmarshal(raw, &rep))
	assert.EqualValues(t, 5, rep["exit"])
	assert.Contains(t, rep["report_error"], "Error")
	d := rep["diagnostic"].(map[string]any)
	assert.Equal(t, "incomplete", d["evidence"])
	assert.Equal(t, "not-completed: report not written", d["status"])
	assert.EqualValues(t, 0, d["command_exit"], "the raw command result is kept as evidence")
}

// A diagnostic whose command uses up the whole budget is exit 6 (the deadline), never a
// manufactured 7: nothing is extended past --deadline.
func TestDiagnosticDeadlineExhaustedIsSix(t *testing.T) {
	f := newFixture(t, passingCheck)
	start := time.Now()
	o := f.diag(t, "--image", "hang", "--deadline", "6")
	assert.Less(t, time.Since(start), 30*time.Second)
	require.Equal(t, 6, o.code, o.stdout+o.stderr)
	assert.EqualValues(t, 6, o.report["exit"])
	assert.NotContains(t, o.stdout, "DIAGNOSTIC: command exit")
	assert.Contains(t, o.report["stopped"], "deadline")
}
