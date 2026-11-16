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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
if args[:3] == ["image", "inspect", "missing"]:
    sys.exit(1)
if args[:2] == ["image", "inspect"] and "slowinspect" in args[2]:
    time.sleep(30)
if args[:1] == ["inspect"]:
    r = reg()
    if args[-1] not in r:
        sys.exit(1)
    print("/%s %s" % tuple(r[args[-1]]))
    sys.exit(0)
if args[:2] == ["rm", "-f"]:
    r = reg()
    if args[2] not in r:
        sys.exit(1)
    del r[args[2]]
    save(r)
    sys.exit(0)
if not args or args[0] != "run":
    sys.exit(0)
VALUED = {"--pull", "--memory", "--cpus", "--name", "--network", "--cap-drop", "--security-opt", "--pids-limit",
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
if "hang" in image:
    time.sleep(120)  # a container whose client is killed stays registered, as a detached one would
if "noexec" in image:
    code = 0
else:
` + "    " + strings.ReplaceAll(effect, "\n", "\n    ") + `
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
	report := filepath.Join(f.root, "report.json")
	_ = os.Remove(report)
	args := append([]string{"-I", script(t, "mutate-sandboxed.py"), "--mutants", mutants, "--tree", f.tree,
		"--shared-modcache", f.modcache, "--shared-gocache", f.gocache, "--workdir-root", f.workRoot,
		"--docker", f.docker, "--no-seed", "--report", report, "--timeout", "60", "--image", "fixture-image"}, extra...)
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
		assert.Contains(t, joined, "--memory 8g")
		assert.Contains(t, joined, "--cpus 4")
		assert.NotContains(t, joined, "--env HOME=", "HOME is never set")
		assert.Contains(t, joined, "--env GOFLAGS=-modcacherw -count=1", "no cached test result is replayed")
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

// The guard hook refuses a mutation run started outside mutate-sandboxed and leaves everything else.
func TestGuardHook(t *testing.T) {
	refused := []string{
		"python3 evidence/txe-7523/mutants-7538.py",
		"cd /x && GOFLAGS=-count=1 timeout 900 python3 -u docs/specs/foo/mutants.py --only guard",
		"python3 -I <(git show origin/main:docs/specs/foo/mutants.py)",
		"echo start; ./mutants.py",
		"bash scripts/run-mutations.sh",
		"out=$(python3 mutants.py)",
		"mutmut run",
		"uv run mutmut run",
		"python3 -m mutmut run",
		"go run ./tools/mutate.go",
		"go-mutesting ./...",
		"env FOO=1 nohup python3 'mut''ants.py'",
	}
	for _, c := range refused {
		code, stdout, stderr := hook(t, bashInput(t, c))
		assert.Equal(t, 2, code, "should refuse: %s", c)
		assert.Empty(t, stdout)
		assert.Contains(t, stderr, "mutate-sandboxed", c)
	}
	allowed := []string{
		"python3 -I txe/mutate/mutate-sandboxed.py --mutants m.json -- go test ./...",
		"mutate-sandboxed --mutants mutants.json --tree . -- python3 -m pytest tests/test_mutants.py",
		"python3 -I <(git show origin/main:txe/mutate/mutate-sandboxed.py) --mutants m.json -- go test ./x",
		"cat docs/specs/foo/mutants.py",
		"git add mutants.py && git commit -m 'mutants: add guard mutant'",
		"go test ./txe/mutate/...",
		"python3 -I txe/mutate/guard-hook.py",
		"grep -n mutant evidence/notes.md",
	}
	for _, c := range allowed {
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
    f.write(json.dumps({"args": sys.argv[1:], "env": {k: os.environ.get(k) for k in
        ("HOME", "GOPROXY", "GOMODCACHE", "GOPATH", "GOCACHE", "GOFLAGS")}}) + "\n")
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
	}
	require.NotNil(t, download, "the seed ran go mod download")
	realMod, err := filepath.EvalSymlinks(f.modcache)
	require.NoError(t, err)
	assert.Equal(t, "file://"+filepath.Join(realMod, "cache", "download")+",https://proxy.example,direct", download["GOPROXY"])
	assert.Equal(t, os.Getenv("HOME"), download["HOME"], "HOME is never overridden")
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
	code, _, _ := hook(t, `{"tool_name":"exec_command","tool_input":{"cmd":"go test ./..."}}`)
	assert.Equal(t, 0, code)
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
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--image", "hang", "--timeout", "60", "--deadline", "2")
	assert.Less(t, time.Since(start), 20*time.Second)
	assert.Equal(t, 6, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "whole-run deadline (2s) passed during baseline")
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
