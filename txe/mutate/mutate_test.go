// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package mutate_test tests txe/mutate/mutate-sandboxed.py and its guard hook (TXE-7549).
//
// These tests start no container and download nothing. A fake docker records the argv the runner
// builds and then plays the container on the host, with the run's own directory standing in for
// /work. Every cache a test touches is a sentinel-only fake under t.TempDir(), never the real one.
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
	"testing"

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
// to their mount sources. An image named "infra-125" exits 125 as the daemon would.
func fakeDocker(t *testing.T, dir, log string) string {
	t.Helper()
	src := `#!/usr/bin/env python3
import json, os, subprocess, sys
LOG = ` + fmt.Sprintf("%q", log) + `
args = sys.argv[1:]
with open(LOG, "a") as f:
    f.write(json.dumps(args) + "\n")
if not args or args[0] != "run":
    sys.exit(0)
VALUED = {"--name", "--network", "--cap-drop", "--security-opt", "--pids-limit", "--tmpfs", "--user",
          "--workdir", "--entrypoint", "--mount", "--env"}
i, mounts, env, workdir = 1, {}, {}, "/"
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
    else:
        i += 1
image, cmd = args[i], args[i + 1:]
if image == "infra-125":
    sys.exit(125)
def host(p):
    for target, source in sorted(mounts.items(), key=lambda kv: -len(kv[0])):
        if p == target or p.startswith(target + "/"):
            return source + p[len(target):]
    return p
env = {k: host(v.replace("file://", "", 1)) if v.startswith("file:///") else host(v) for k, v in env.items()}
env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
sys.exit(subprocess.run(cmd, env=env, cwd=host(workdir)).returncode)
`
	p := filepath.Join(dir, "docker")
	require.NoError(t, os.WriteFile(p, []byte(src), 0o755))
	return p
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
		"--docker", f.docker, "--no-seed", "--report", report, "--timeout", "60"}, extra...)
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

// The check passes unless BREAK is in it; the cleanup mutant deletes whatever GOMODCACHE names,
// as `go clean -modcache` does, and the check still passes.
const passingCheck = "#!/bin/sh\n: CLEANUP\n: GUARD\nexit 0\n"

var cleanupMutant = map[string]any{"name": "cleanup reaches the env cache", "file": "check.sh",
	"old": ": CLEANUP", "new": `rm -rf "$GOMODCACHE"`}

// A mutant that deletes the cache its environment names reaches only the sandbox: the fake shared
// cache and its sentinel are untouched, the mutant survives (the deletion is not a kill), and the
// container got nothing from the caller's environment and no host path but its own directory.
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
		for _, name := range []string{"HOME", "GOPATH", "GOMODCACHE", "GOCACHE", "TMPDIR", "XDG_CACHE_HOME"} {
			assert.Contains(t, joined, "--env "+name+"=/work/sandbox/")
		}
	}
}

// With the sandbox turned off, the same mutant deletes the fake shared cache and the runner fails
// loudly on the identity check (exit 3), keeping its work directory as evidence.
func TestHostRunFailsIdentityCheck(t *testing.T) {
	f := newFixture(t, passingCheck)
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--unsafe-host-run-for-fixture")
	require.Equal(t, 3, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "SHARED STATE CHANGED")
	assert.Contains(t, o.stderr, "after cleanup reaches the env cache")
	assert.Contains(t, o.stderr, "GOMODCACHE")
	assert.NoFileExists(t, filepath.Join(f.modcache, sentinel), "the fake cache was the target")
	assert.NotContains(t, o.outcomes(), "cleanup reaches the env cache", "a run that touched host state has no verdict")
	assert.DirExists(t, o.report["workdir"].(string))
	runs, _ := os.ReadFile(f.log)
	assert.NotContains(t, string(runs), `"run"`, "the host run starts no container")
}

// The sandbox is only turned off for caches that carry the fixture sentinel.
func TestHostRunRefusedWithoutSentinel(t *testing.T) {
	f := newFixture(t, passingCheck)
	require.NoError(t, os.Remove(filepath.Join(f.gocache, sentinel)))
	o := f.run(t, f.mutants(t, []map[string]any{cleanupMutant}), "--unsafe-host-run-for-fixture")
	assert.Equal(t, 2, o.code)
	assert.Contains(t, o.stderr, "holds no "+sentinel)
	assert.FileExists(t, filepath.Join(f.modcache, sentinel))
	entries, err := os.ReadDir(f.workRoot)
	require.NoError(t, err)
	assert.Empty(t, entries, "nothing ran")
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
		"--docker", f.docker, "--report", report, "--", "sh", "check.sh")
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
