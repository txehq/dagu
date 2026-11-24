//go:build !windows

// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package mutate_test

// The node seed (TXE-8348): a pnpm workspace's Linux node_modules, installed once with network from
// the workspace's manifests alone, then copied into every run's tree; every run stays offline.
// The fake docker plays the containers on the host (mutate_test.go), and a fake pnpm stands in for
// the install: it records what it was given and what it could see, and writes a small pnpm-shaped
// node_modules. These tests check what the runner builds, refuses and records; pnpm's own
// behaviour is accepted by the worked example in the README, not here.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePnpm writes pnpm-shaped output into its working directory. Its mode file (when present)
// picks a failure: "fail" exits 1, "abslink" adds a link out of the tree, "touchlock" edits the
// lockfile, "fifo" replaces a manifest with a FIFO, "outsidestore" puts the packages in a virtual
// store outside node_modules, "hoisted" lays them out as node-linker=hoisted does, and "injected"
// adds an injected copy of a workspace project. Each call is appended to log as JSON: args, the files it could see before it wrote
// anything, and a few environment values.
const fakePnpm = `#!/usr/bin/env python3
import json, os, sys
LOG, MODE = sys.argv[0] + ".log", sys.argv[0] + ".mode"
args = sys.argv[1:]
mode = open(MODE).read() if os.path.exists(MODE) else ""
files = sorted(os.path.relpath(os.path.join(d, n), ".") for d, _, ns in os.walk(".") for n in ns)
with open(LOG, "a") as f:
    f.write(json.dumps({"args": args, "files": files, "env": {k: os.environ.get(k) for k in
        ("HOME", "MUTATE_NODE_STORE", "XDG_DATA_HOME", "MUTATE_TEST_CANARY")}}) + "\n")
def write(p, text):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(text)
def pkg(path, data):
    write(path + "/package.json", json.dumps(data))
if args == ["--version"]:
    print("10.33.0")
elif args[0] == "install":
    if "fail" in mode:
        print("ERR_PNPM_FETCH_404")
        sys.exit(1)
    if "--ignore-scripts" not in args:
        write("tree-script-ran", "the workspace's postinstall would have run\n")
    if "hoisted" in mode:  # node-linker=hoisted: packages are plain directories under node_modules
        pkg("node_modules/leftpad", {"name": "leftpad", "version": "1.0.0"})
        write("node_modules/leftpad/index.js", "module.exports = 1\n")
        pkg("node_modules/esbuild", {"name": "esbuild", "version": "0.25.0", "scripts": {"postinstall": "node install.js"}})
        # a nested copy of the same name@version whose script differs: it must not hide behind the first
        pkg("node_modules/leftpad/node_modules/esbuild",
            {"name": "esbuild", "version": "0.25.0", "scripts": {"postinstall": "node other.js"}})
        os.makedirs("apps/web/node_modules", exist_ok=True)
        os.symlink("../../../node_modules/leftpad", "apps/web/node_modules/leftpad")
        sys.exit(0)
    # virtual-store-dir outside node_modules: the packages' contents are where the seed copies nothing
    store = ".pnpm-store-outside" if "outsidestore" in mode else "node_modules/.pnpm"
    if "outsidestore" in mode:
        os.makedirs("node_modules", exist_ok=True)
    pkg(store + "/leftpad@1.0.0/node_modules/leftpad", {"name": "leftpad", "version": "1.0.0"})
    write(store + "/leftpad@1.0.0/node_modules/leftpad/index.js", "module.exports = 1\n")
    pkg(store + "/esbuild@0.25.0/node_modules/esbuild",
        {"name": "esbuild", "version": "0.25.0", "scripts": {"postinstall": "node install.js"}})
    pkg(store + "/@scope+native@2.0.0/node_modules/@scope/native", {"name": "@scope/native", "version": "2.0.0"})
    write(store + "/@scope+native@2.0.0/node_modules/@scope/native/binding.gyp", "{}\n")
    os.symlink("../../esbuild@0.25.0/node_modules/esbuild", store + "/leftpad@1.0.0/node_modules/esbuild")
    write(store + "/leftpad@1.0.0/node_modules/leftpad/bin.js", "#!/usr/bin/env node\n")
    os.chmod(store + "/leftpad@1.0.0/node_modules/leftpad/bin.js", 0o755)
    leftpad = store + "/leftpad@1.0.0/node_modules/leftpad"
    os.symlink(os.path.relpath(leftpad, "node_modules"), "node_modules/leftpad")
    os.makedirs("apps/web/node_modules", exist_ok=True)
    os.symlink(os.path.relpath(leftpad, "apps/web/node_modules"), "apps/web/node_modules/leftpad")
    if "abslink" in mode:
        os.symlink("/etc", "node_modules/escape")
    if "touchlock" in mode:
        open("pnpm-lock.yaml", "a").write("# rewritten\n")
    if "setuid" in mode:  # an allowlisted script planting a setuid binary in the seed
        write("node_modules/.bin/shell", "#!/bin/sh\n")
        os.chmod("node_modules/.bin/shell", 0o4755)
    if "injected" in mode:  # injectWorkspacePackages: a copy of workspace project "web", manifest only
        pkg(store + "/web@file+apps+web/node_modules/web", {"name": "web"})
    if "published" in mode:  # a registry release named like workspace project "web": its own manifest
        pkg(store + "/web@1.0.0/node_modules/web", {"name": "web", "version": "1.0.0"})
        write(store + "/web@1.0.0/node_modules/web/index.js", "module.exports = 1\n")
    if "fifo" in mode:  # a manifest swapped for a FIFO: a blocking host read would wait forever
        os.remove("apps/web/package.json")
        os.mkfifo("apps/web/package.json")
elif args[0] == "rebuild":
    for name in [a for a in args[1:] if not a.startswith("-")]:
        write("node_modules/.rebuilt-" + name.replace("/", "+"), "rebuilt\n")
`

const nodeCheck = "#!/bin/sh\n" +
	"test -f node_modules/leftpad/index.js || { echo no node_modules; exit 3; }\n" +
	"test -L apps/web/node_modules/leftpad || exit 3\n" +
	": GUARD\n# NOOP\nexit 0\n"

type nodeFixture struct {
	fixture
	pnpmLog, pnpmMode string
}

// newNodeFixture is a pnpm workspace (root and apps/web) whose test is check.sh, with source and a
// pnpmfile the seed's install must never see, and the fake pnpm first on PATH.
func newNodeFixture(t *testing.T) nodeFixture {
	t.Helper()
	f := newFixture(t, nodeCheck)
	files := map[string]string{
		"package.json":          `{"name": "ws", "private": true, "scripts": {"postinstall": "touch /tmp/never"}}`,
		"pnpm-lock.yaml":        "lockfileVersion: '9.0'\n",
		"pnpm-workspace.yaml":   "packages:\n  - apps/*\n",
		"apps/web/package.json": `{"name": "web"}`,
		"apps/web/src/index.ts": "export const x = 1;\n",
		".pnpmfile.cjs":         "module.exports = { hooks: {} };\n",
	}
	for rel, text := range files {
		p := filepath.Join(f.tree, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(text), 0o644))
	}
	bin := filepath.Join(f.root, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	pnpm := filepath.Join(bin, "pnpm")
	require.NoError(t, os.WriteFile(pnpm, []byte(fakePnpm), 0o755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return nodeFixture{fixture: f, pnpmLog: pnpm + ".log", pnpmMode: pnpm + ".mode"}
}

// raw runs the runner with exactly these arguments, plus the fixture's fake caches and docker.
func (f nodeFixture) raw(t *testing.T, args ...string) outcome {
	t.Helper()
	return f.launch(t, []string{"-I", "-B", script(t, "mutate-sandboxed.py")}, args...)
}

// launch is raw with the interpreter's arguments given: the runner's script, or a harness program
// that loads it, patches it and calls its main with the remaining arguments.
func (f nodeFixture) launch(t *testing.T, interp []string, args ...string) outcome {
	t.Helper()
	report := filepath.Join(f.root, "report.json")
	_ = os.Remove(report)
	all := append(append(interp, "--tree", f.tree,
		"--shared-modcache", f.modcache, "--shared-gocache", f.gocache, "--workdir-root", f.workRoot,
		"--docker", f.docker, "--report", report, "--timeout", "60"), args...)
	cmd := exec.Command(python(t), all...)
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

func (f nodeFixture) build(t *testing.T, seed string, extra ...string) outcome {
	t.Helper()
	return f.raw(t, append([]string{"--node-seed-build", seed, "--image", "node-image"}, extra...)...)
}

// pnpmCalls reads the fake pnpm's log.
func (f nodeFixture) pnpmCalls(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(f.pnpmLog)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	var calls []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		var c map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &c))
		calls = append(calls, c)
	}
	return calls
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func sha256File(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(p)
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func readSeed(t *testing.T, dir string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "seed.json"))
	require.NoError(t, err)
	var seed map[string]any
	require.NoError(t, json.Unmarshal(raw, &seed))
	return seed
}

var nodeMutants = []map[string]any{
	{"name": "guard removed", "file": "check.sh", "old": ": GUARD", "new": "exit 1"},
	{"name": "comment only", "file": "check.sh", "old": "# NOOP", "new": "# NOOP, reworded"},
}

// A tree with a package.json or pnpm-lock.yaml at its root and no seed is refused before any
// docker call, in mutation and diagnostic mode, with a message that names the fix. --no-node-seed
// runs it as it is, and then the unmutated tree fails: the failure the refusal exists to prevent.
func TestNodeTreeWithoutSeedRefused(t *testing.T) {
	for name, mode := range map[string][]string{"mutants": nil, "diagnostic": {"--diagnostic"}} {
		t.Run(name, func(t *testing.T) {
			f := newNodeFixture(t)
			var o outcome
			if mode == nil {
				o = f.run(t, f.mutants(t, nodeMutants))
			} else {
				o = f.diag(t)
			}
			require.Equal(t, 2, o.code, o.stdout+o.stderr)
			assert.Contains(t, o.stderr, "is a JavaScript workspace (package.json at its root) and no --node-seed was given")
			assert.Contains(t, o.stderr, "--node-seed-build DIR")
			_, err := os.Stat(f.log)
			assert.True(t, os.IsNotExist(err), "no docker call at all, not even the image check")
		})
	}
	t.Run("a lockfile alone marks the tree", func(t *testing.T) {
		f := newNodeFixture(t)
		require.NoError(t, os.Remove(filepath.Join(f.tree, "package.json")))
		o := f.run(t, f.mutants(t, nodeMutants))
		require.Equal(t, 2, o.code, o.stdout+o.stderr)
		assert.Contains(t, o.stderr, "(pnpm-lock.yaml at its root)")
	})
	t.Run("--no-node-seed runs it unseeded", func(t *testing.T) {
		f := newNodeFixture(t)
		o := f.run(t, f.mutants(t, nodeMutants), "--no-node-seed")
		require.Equal(t, 4, o.code, o.stdout+o.stderr)
		assert.Equal(t, "FAILED", o.outcomes()["baseline"])
		assert.Nil(t, f.pnpmCalls(t), "nothing installs without a seed build")
	})
}

// The seed is built in one container with network from the manifests alone, every lifecycle
// script disabled and recorded; the runs that use it are offline, get node_modules in their own
// copy, and kill and keep mutants as any run does.
func TestNodeSeedBuildAndOfflineRuns(t *testing.T) {
	f := newNodeFixture(t)
	seedDir := filepath.Join(f.root, "seed")
	o := f.build(t, seedDir)
	require.Equal(t, 0, o.code, o.stdout+o.stderr)

	runs := dockerRuns(t, f.log)
	require.Len(t, runs, 1, "one container installs the seed")
	seedRun := strings.Join(runs[0], " ")
	assert.Contains(t, seedRun, "--network bridge", "the seed's install, and only it, has network")
	assert.Contains(t, seedRun, "--env MUTATE_NODE_STORE=/work/sandbox/pnpm-store")
	assert.Contains(t, seedRun, "--env XDG_DATA_HOME=/work/sandbox/xdg-data")
	assert.NotContains(t, seedRun, "--env HOME=", "HOME is never set")
	assert.NotContains(t, seedRun, "host-only-value")
	assert.Equal(t, []string{"/work"}, mountTargets(runs[0]))
	n := len(runs[0])
	assert.Equal(t, []string{"sha256:" + hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("node-image")); return s[:] }()),
		"sh", "-c"}, runs[0][n-5:n-2], "the runner's own command, launched by the image's id")
	assert.Equal(t, "sh", runs[0][n-1], "no allowlisted name follows")
	assert.Contains(t, runs[0][n-2], "pnpm install --frozen-lockfile --ignore-scripts --ignore-pnpmfile")

	calls := f.pnpmCalls(t)
	require.Len(t, calls, 2, "pnpm --version, then pnpm install; no rebuild without an allowlist")
	install := calls[1]
	args := strs(install["args"])
	assert.Equal(t, "install", args[0])
	for _, flag := range []string{"--frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile", "--package-import-method=copy"} {
		assert.Contains(t, args, flag)
	}
	assert.Equal(t, []string{"apps/web/package.json", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"},
		strs(install["files"]), "the install sees the manifests and nothing else: no source, no pnpmfile")
	assert.Nil(t, install["env"].(map[string]any)["HOME"])
	assert.Nil(t, install["env"].(map[string]any)["MUTATE_TEST_CANARY"])

	seed := readSeed(t, seedDir)
	assert.Equal(t, sha256File(t, filepath.Join(f.tree, "pnpm-lock.yaml")), seed["lockfile_sha256"])
	assert.Equal(t, "sha256:"+hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("node-image")); return s[:] }()),
		seed["image_id"])
	assert.ElementsMatch(t, []string{"node_modules", "apps/web/node_modules"}, keys(seed["node_modules"]))
	assert.Empty(t, seed["allow_build"])
	scripts := seed["lifecycle_scripts"].(map[string]any)
	deps := scripts["dependencies"].(map[string]any)
	assert.Equal(t, "skipped", deps["esbuild@0.25.0"].(map[string]any)["ran"])
	assert.Equal(t, map[string]any{"node_modules/.pnpm/esbuild@0.25.0/node_modules/esbuild": map[string]any{
		"postinstall": "node install.js"}}, deps["esbuild@0.25.0"].(map[string]any)["paths"], "scripts are recorded per path")
	assert.Equal(t, "skipped", deps["@scope/native@2.0.0"].(map[string]any)["ran"], "a binding.gyp implies an install script")
	assert.NotContains(t, deps, "leftpad@1.0.0", "a package without install scripts is not listed")
	assert.Contains(t, scripts["workspace_skipped"], "package.json", "the workspace's own postinstall is recorded, not run")
	log, err := os.ReadFile(filepath.Join(seedDir, "install.log"))
	require.NoError(t, err)
	assert.Contains(t, string(log), "+ pnpm install --frozen-lockfile --ignore-scripts")
	assert.Contains(t, o.stdout, "lifecycle scripts skipped: @scope/native@2.0.0, esbuild@0.25.0; allowlisted: none")
	assert.NoFileExists(t, filepath.Join(seedDir, "tree", "tree-script-ran"))
	entries, err := os.ReadDir(f.workRoot)
	require.NoError(t, err)
	assert.Empty(t, entries, "the build's work directory is removed")

	o = f.run(t, f.mutants(t, nodeMutants), "--node-seed", seedDir, "--image", "node-image")
	require.Equal(t, 0, o.code, o.stdout+o.stderr)
	assert.Equal(t, "PASSED", o.outcomes()["baseline"])
	assert.Equal(t, "KILLED", o.outcomes()["guard removed"])
	assert.Equal(t, "SURVIVED", o.outcomes()["comment only"])
	assert.Equal(t, "PASSED", o.outcomes()["baseline (after)"])
	all := dockerRuns(t, f.log)
	require.Len(t, all, 1+5, "seed, baseline, kill, kill again, survivor, baseline after")
	for _, argv := range all[1:] {
		joined := strings.Join(argv, " ")
		assert.Contains(t, joined, "--network none", "every run is offline")
		assert.NotContains(t, joined, "MUTATE_NODE_STORE")
		assert.NotContains(t, joined, seedDir, "the seed is copied, never mounted")
		assert.Equal(t, []string{"/work"}, mountTargets(argv))
		assert.Equal(t, []string{"sh", "check.sh"}, argv[len(argv)-2:])
	}
	assert.Len(t, f.pnpmCalls(t), 2, "no run installs anything")
	assert.NoDirExists(t, filepath.Join(f.tree, "node_modules"), "the live tree is never given a node_modules")
	assert.Equal(t, seed, readSeed(t, seedDir))
}

func keys(v any) []string {
	var out []string
	for k := range v.(map[string]any) {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mountTargets(argv []string) []string {
	var out []string
	for i, a := range argv {
		if a == "--mount" {
			for field := range strings.SplitSeq(argv[i+1], ",") {
				if v, ok := strings.CutPrefix(field, "target="); ok {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

// Node runs launch by the immutable id resolved once at the start, never by the caller's tag (root's
// review of 984f6e0f): a tag retargeted while a run is in progress cannot swap the image a seed was
// built with or a mutant runs in. The fake docker's tag moves on the first container (its
// side effect), so a later launch by tag would get the other image; every launch must name the id.
// A tag that has moved before a run starts resolves to another id, and the seed is refused.
func TestNodeRunsLaunchByImageID(t *testing.T) {
	f := newNodeFixture(t)
	retag := f.log + ".retag"
	f.docker = fakeDocker(t, f.root, f.log, fmt.Sprintf("open(%q, 'w').close()", retag))
	imageA := "sha256:" + hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("node-image")); return s[:] }())
	seedDir := filepath.Join(f.root, "seed")
	o := f.build(t, seedDir)
	require.Equal(t, 0, o.code, o.stdout+o.stderr)
	assert.Equal(t, imageA, readSeed(t, seedDir)["image_id"], "the id the tag named when the build started")
	require.FileExists(t, retag, "the tag moved once the seed's container started")

	require.NoError(t, os.Remove(retag)) // the tag names image A again when the run starts
	o = f.run(t, f.mutants(t, nodeMutants), "--node-seed", seedDir, "--image", "node-image")
	require.Equal(t, 0, o.code, o.stdout+o.stderr)
	runs := dockerRuns(t, f.log)
	require.Len(t, runs, 1+5)
	for _, argv := range runs {
		assert.Contains(t, argv, imageA, "launched by the immutable id")
		assert.NotContains(t, argv, "node-image", "never by the tag, which moved during each invocation")
	}

	require.FileExists(t, retag) // the tag moved again, and now names another image
	o = f.run(t, f.mutants(t, nodeMutants), "--node-seed", seedDir, "--image", "node-image")
	require.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "was built with image "+imageA)
	assert.Len(t, dockerRuns(t, f.log), 1+5, "no container ran on the retargeted tag")
}

func imageIDOf(name string) string {
	s := sha256.Sum256([]byte(name))
	return "sha256:" + hex.EncodeToString(s[:])
}

// dockerInspects lists the fake docker's `image inspect` argvs, in order.
func dockerInspects(t *testing.T, log string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(log)
	require.NoError(t, err)
	var out [][]string
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		var argv []string
		require.NoError(t, json.Unmarshal([]byte(line), &argv))
		if len(argv) > 1 && argv[0] == "image" && argv[1] == "inspect" {
			out = append(out, argv)
		}
	}
	return out
}

// The volume check reads the image the run launches (root's review of b51ba7c9). The fake tag
// names image A until its first inspection and image B, which declares a volume, from then on.
// The runner resolves the tag's id first and checks that id's volumes, so A is checked and A is
// launched; checking the tag first would have read A's volumes and then launched B. Once the tag
// names B, B's volume is refused.
func TestNodeVolumeCheckReadsTheResolvedImage(t *testing.T) {
	f := newNodeFixture(t)
	require.NoError(t, os.WriteFile(f.log+".voltag", []byte("node-image"), 0o644))
	imageA, imageB := imageIDOf("node-image"), imageIDOf("node-image@retargeted")
	o := f.build(t, filepath.Join(f.root, "seed"))
	require.Equal(t, 0, o.code, o.stdout+o.stderr)
	inspects := dockerInspects(t, f.log)
	require.Len(t, inspects, 2)
	assert.Equal(t, []string{"image", "inspect", "--format", "{{.Id}}", "node-image"}, inspects[0], "the id first")
	assert.Equal(t, []string{"image", "inspect", "--format", "{{json .Config.Volumes}}", imageA}, inspects[1],
		"then the volumes of that id, not of the tag, which has moved")
	for _, argv := range dockerRuns(t, f.log) {
		assert.Contains(t, argv, imageA)
		assert.NotContains(t, argv, imageB)
	}
	assert.Equal(t, imageA, readSeed(t, filepath.Join(f.root, "seed"))["image_id"])

	o = f.build(t, filepath.Join(f.root, "seed-b")) // the tag now names B
	require.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "image "+imageB+" declares VOLUME /data")
	assert.Len(t, dockerRuns(t, f.log), 1, "no container ran on B")
}

// The seed is written by pathname into the directory the build creates, so its parent must be
// one nobody else can rename entries in (security review of a63cbc52): the invoker's own and not
// group- or other-writable, or sticky. The build never runs as root. check_seed_parent takes the
// euid as an argument, so another uid and uid 0 are faked here, not obtained.
func TestNodeSeedParentDirectory(t *testing.T) {
	root := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(root, name)
		require.NoError(t, os.Mkdir(p, 0o700))
		require.NoError(t, os.Chmod(p, mode)) // after Mkdir: the umask never narrows it
		return p
	}
	dirs := map[string]string{
		"other-writable": mk("other-writable", 0o777), "group-writable": mk("group-writable", 0o775),
		"sticky-shared": mk("sticky-shared", 0o777|os.ModeSticky), "own-0700": mk("own-0700", 0o700),
		"own-0755": mk("own-0755", 0o755),
	}
	prog := `
import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
parent, euid = Path(sys.argv[2]), int(sys.argv[3])
try:
    ms.check_seed_parent(parent, os.getuid() if euid < 0 else euid)
    print("ok")
except ms.Refused as e:
    print(e)
`
	verdict := func(dir string, euid int) string {
		out, err := exec.Command(python(t), "-I", "-B", "-c", prog, script(t, "mutate-sandboxed.py"), dir, fmt.Sprint(euid)).CombinedOutput()
		require.NoError(t, err, string(out))
		return strings.TrimSpace(string(out))
	}
	const self = -1 // the test's own uid
	other := os.Getuid() + 1
	assert.Contains(t, verdict(dirs["other-writable"], self), "its parent directory "+dirs["other-writable"]+
		" is writable by its group or other users and not sticky")
	assert.Contains(t, verdict(dirs["group-writable"], self), "is writable by its group or other users and not sticky")
	assert.Contains(t, verdict(dirs["own-0755"], other), fmt.Sprintf("is owned by uid %d:", os.Getuid()),
		"a parent owned by another uid than the invoker's")
	assert.Equal(t, "ok", verdict(dirs["sticky-shared"], self), "a sticky shared directory the invoker owns")
	// The owner of a sticky directory can still rename its entries: one owned by another uid is refused.
	assert.Contains(t, verdict(dirs["sticky-shared"], other), fmt.Sprintf("its parent directory %s is owned by uid %d:",
		dirs["sticky-shared"], os.Getuid()))
	assert.Equal(t, "ok", verdict(dirs["own-0700"], self))
	assert.Equal(t, "ok", verdict(dirs["own-0755"], self))
	assert.Contains(t, verdict(dirs["own-0700"], 0), "refuses to run as root")

	// Every ancestor, not only the parent: a private parent under a writable, non-sticky directory is
	// refused, naming that ancestor.
	ancestor := mk("writable-ancestor", 0o777)
	child := filepath.Join(ancestor, "private")
	require.NoError(t, os.Mkdir(child, 0o700))
	assert.Contains(t, verdict(child, self), "an ancestor of its parent directory "+ancestor+
		" is writable by its group or other users and not sticky")
	// A root-owned sticky ancestor (the real /tmp) passes, with the invoker's private directory below it.
	tmp, err := filepath.EvalSymlinks("/tmp")
	require.NoError(t, err)
	under, err := os.MkdirTemp(tmp, "txe-8348-seed-parent-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(under) })
	require.NoError(t, os.Chmod(under, 0o700))
	assert.Equal(t, "ok", verdict(under, self), "a private directory under the root-owned sticky /tmp")

	// Through the runner: the build is refused before any docker call.
	f := newNodeFixture(t)
	o := f.build(t, filepath.Join(dirs["other-writable"], "seed"))
	require.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "put the seed in a directory only you (or root) can write, all the way up")
	_, err = os.Stat(f.log)
	assert.True(t, os.IsNotExist(err), "refused before any docker call")
}

// The seed directory is private from the moment it exists (root's review of 1ad1243e): it is made
// with mode 0700 at creation, so a permissive umask (0002, 0000) cannot leave it writable by a
// group peer before the first export write. Checked twice, in owned temporary fixtures:
//   - open_seed_dir (make_seed_dir, then the verified descriptor) alone, under each umask, before
//     anything is written into it;
//   - a whole build under each umask: the published seed directory is still 0700.
//
// No test in this package runs in parallel, so the process umask set around a build is this test's.
func TestNodeSeedDirectoryIsPrivateAtCreation(t *testing.T) {
	for _, mask := range []int{0o002, 0o000} {
		t.Run(fmt.Sprintf("umask %04o", mask), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "seed")
			prog := `
import importlib.util, os, stat, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
os.umask(int(sys.argv[3], 8))
d = Path(sys.argv[2])
parent = os.open(d.parent, os.O_RDONLY | os.O_DIRECTORY)
fd = ms.open_seed_dir(parent, d.name)
print(oct(stat.S_IMODE(os.fstat(fd).st_mode)), len(os.listdir(fd)))
`
			out, err := exec.Command(python(t), "-I", "-B", "-c", prog, script(t, "mutate-sandboxed.py"), dir,
				fmt.Sprintf("%o", mask)).CombinedOutput()
			require.NoError(t, err, string(out))
			assert.Equal(t, "0o700 0", strings.TrimSpace(string(out)), "private, and empty: before any export write")

			f := newNodeFixture(t)
			old := syscall.Umask(mask)
			defer syscall.Umask(old)
			seed := filepath.Join(f.root, "seed")
			o := f.build(t, seed)
			syscall.Umask(old)
			require.Equal(t, 0, o.code, o.stdout+o.stderr)
			st, err := os.Lstat(seed)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o700), st.Mode().Perm(), "the published seed directory is never widened")
		})
	}
}

// seedHarness loads the runner, patches one step of the build to play an attacker, and runs main
// with the rest of its arguments. argv: attack, target, moved, decoy, then the runner's arguments.
//   - rename: once the seed directory is open, target (the seed directory or an ancestor) is renamed
//     to moved, and a link to decoy takes its place: a pathname write would land in decoy.
//   - after-screen: as soon as check_seed_parent has screened the parent, before anything else
//     reads it, target (the parent) is renamed to moved and an empty directory takes its place.
//   - before-open: after check_node_mode screens the parent, target (the parent) is renamed to
//     moved and an empty directory takes its place, before the build opens it.
//   - plant:NAME: once the seed directory is open, a link NAME -> decoy/NAME is planted in it.
const seedHarness = `
import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
attack, target, moved, decoy = sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5])
if attack == "after-screen":
    screen = ms.check_seed_parent
    def hooked_screen(parent, euid):
        st = screen(parent, euid)
        os.rename(target, moved)
        os.mkdir(target, 0o700)
        return st
    ms.check_seed_parent = hooked_screen
elif attack == "before-open":
    check = ms.check_node_mode
    def hooked_check(args, forbidden):
        check(args, forbidden)
        os.rename(target, moved)
        os.mkdir(target, 0o700)
    ms.check_node_mode = hooked_check
else:
    opened = ms.open_seed_dir
    def hooked_open(parent_fd, name):
        fd = opened(parent_fd, name)
        if attack == "rename":
            os.rename(target, moved)
            os.symlink(decoy, target)
        else:
            planted = attack.removeprefix("plant:")
            os.symlink(decoy / planted, target / planted)
        return fd
    ms.open_seed_dir = hooked_open
sys.exit(ms.main(sys.argv[6:]))
`

func (f nodeFixture) attackedBuild(t *testing.T, attack, target, moved, decoy, seed string) outcome {
	t.Helper()
	return f.launch(t, []string{"-I", "-B", "-c", seedHarness, script(t, "mutate-sandboxed.py"), attack, target, moved, decoy},
		"--node-seed-build", seed, "--image", "node-image")
}

// filesUnder lists every entry below dir, relative, with a trailing / for a directory.
func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			rel += "/"
		}
		out = append(out, rel)
		return nil
	}))
	return out
}

// The seed is written relative to the descriptor of the directory the build created, never by
// pathname (TXE-8385): a rename of the seed directory, of its parent or of a further ancestor while
// the build writes moves every write with the directory, and none lands where the old pathname
// now leads (a link to a decoy). The seed is whole where it moved: install.log, seed.json last,
// and each node_modules checked against its digest through the same descriptor.
func TestNodeSeedWritesFollowTheDescriptor(t *testing.T) {
	for _, which := range []string{"seed", "parent", "ancestor"} {
		t.Run(which, func(t *testing.T) {
			f := newNodeFixture(t)
			anc := filepath.Join(f.root, "a")
			parent := filepath.Join(anc, "p")
			require.NoError(t, os.MkdirAll(parent, 0o755))
			seed := filepath.Join(parent, "seed")
			decoy := filepath.Join(f.root, "decoy")
			require.NoError(t, os.Mkdir(decoy, 0o700))
			c := map[string]struct {
				target, renameTo string // what is renamed, and to where
				moved            string // where the seed directory is then
				leads            string // where the seed's old pathname then leads, through the decoy link
			}{
				"seed":     {seed, filepath.Join(parent, "seed-moved"), filepath.Join(parent, "seed-moved"), decoy},
				"parent":   {parent, filepath.Join(anc, "p-moved"), filepath.Join(anc, "p-moved", "seed"), filepath.Join(decoy, "seed")},
				"ancestor": {anc, filepath.Join(f.root, "a-moved"), filepath.Join(f.root, "a-moved", "p", "seed"), filepath.Join(decoy, "p", "seed")},
			}[which]
			moved := c.moved
			// The decoy holds the directories a pathname write would need, empty: a write there would show.
			require.NoError(t, os.MkdirAll(c.leads, 0o700))
			before := filesUnder(t, decoy)

			o := f.attackedBuild(t, "rename", c.target, c.renameTo, decoy, seed)
			require.Equal(t, 0, o.code, o.stdout+o.stderr)
			assert.Equal(t, before, filesUnder(t, decoy), "no write followed the old pathname")
			got := readSeed(t, moved)
			assert.ElementsMatch(t, []string{"node_modules", "apps/web/node_modules"}, keys(got["node_modules"]))
			assert.Equal(t, sha256File(t, filepath.Join(moved, "install.log")), got["install_log_sha256"])
			assert.FileExists(t, filepath.Join(moved, "tree", "node_modules", ".pnpm", "leftpad@1.0.0", "node_modules",
				"leftpad", "index.js"))
			link, err := os.Readlink(filepath.Join(moved, "tree", "apps", "web", "node_modules", "leftpad"))
			require.NoError(t, err)
			assert.Equal(t, "../../../node_modules/.pnpm/leftpad@1.0.0/node_modules/leftpad", link)
			st, err := os.Lstat(moved)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o700), st.Mode().Perm())
		})
	}

	// Replaced between the screening and the open: the build refuses, and writes nothing anywhere.
	// after-screen swaps it the moment the screen returns, before any later read of the parent
	// could take the replacement as the identity to require (root's review of 2837c048).
	for _, attack := range []string{"after-screen", "before-open"} {
		t.Run("parent replaced "+attack, func(t *testing.T) {
			f := newNodeFixture(t)
			parent := filepath.Join(f.root, "p")
			require.NoError(t, os.Mkdir(parent, 0o755))
			moved := filepath.Join(f.root, "p-moved")
			o := f.attackedBuild(t, attack, parent, moved, filepath.Join(f.root, "unused"), filepath.Join(parent, "seed"))
			require.Equal(t, 2, o.code, o.stdout+o.stderr)
			assert.Contains(t, o.stderr, "is no longer the directory screened at the start (it or an ancestor was renamed)")
			assert.Empty(t, filesUnder(t, parent))
			assert.Empty(t, filesUnder(t, moved))
		})
	}
}

// Every descriptor the seed writer opens is closed when a write is refused (root's review of
// 2837c048): the source file when copy_dir_at's exclusive create of its destination is refused
// before a byte is read, the install log and the seed directory when write_seed's install.log is
// refused, and the parent when open_seed_parent refuses it. Each case compares this process's
// open descriptors (/dev/fd) before and after the refusal.
func TestNodeSeedWriterClosesDescriptorsOnRefusal(t *testing.T) {
	prog := `
import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
root = Path(sys.argv[2])
def fds():
    return sorted(int(n) for n in os.listdir("/dev/fd") if os.path.exists(f"/dev/fd/{n}"))
def case(name, fn):
    before = fds()
    try:
        fn()
        print(name, "NOT REFUSED")
        return
    except ms.Refused:
        pass
    after = fds()
    print(name, "ok" if after == before else f"leaked {sorted(set(after) - set(before))}")

# copy_dir_at: the destination already holds the file, so its exclusive create is refused.
(root / "src").mkdir(); (root / "src" / "a").write_text("x")
(root / "dst").mkdir(); (root / "dst" / "a").write_text("planted")
s, d = os.open(root / "src", ms.DIR_FLAGS), os.open(root / "dst", ms.DIR_FLAGS)
case("copy_dir_at", lambda: ms.copy_dir_at(s, d, [100], None, "copy"))

# write_seed: a link planted at install.log once the seed directory is open.
nm = root / "install" / "node_modules"; nm.mkdir(parents=True); (nm / "x").write_text("x")
log = root / "install.log"; log.write_text("log\n")
parent = root / "parent"; parent.mkdir()
st = os.lstat(parent)
digests = {"node_modules": ms.tree_digest(nm, 100, 1 << 20)[0]}
opened = ms.open_seed_dir
def planted(parent_fd, name):
    fd = opened(parent_fd, name)
    os.symlink(root / "decoy", parent / name / "install.log")
    return fd
ms.open_seed_dir = planted
case("write_seed", lambda: ms.write_seed(parent / "seed", (st.st_dev, st.st_ino), root / "install",
                                         ["node_modules"], digests, log, (100, 1 << 20), None))

# open_seed_parent: the identity does not match.
case("open_seed_parent", lambda: ms.open_seed_parent(parent, (st.st_dev, st.st_ino + 1)))
`
	out, err := exec.Command(python(t), "-I", "-B", "-c", prog, script(t, "mutate-sandboxed.py"), t.TempDir()).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Equal(t, "copy_dir_at ok\nwrite_seed ok\nopen_seed_parent ok", strings.TrimSpace(string(out)))
}

// A link planted in the seed directory where the build will create seed.json, install.log or tree
// (a peer that could write there, say) is never followed: the build refuses and the link's target
// is never created.
func TestNodeSeedPlantedLinkNotFollowed(t *testing.T) {
	for name, want := range map[string]string{
		"seed.json":   "writing the seed: cannot create seed.json: [Errno 17] File exists",
		"install.log": "writing the seed: cannot create install.log: [Errno 17] File exists",
		"tree":        "writing the seed: cannot open tree as a plain directory",
	} {
		t.Run(name, func(t *testing.T) {
			f := newNodeFixture(t)
			seed := filepath.Join(f.root, "seed")
			decoy := filepath.Join(f.root, "decoy")
			require.NoError(t, os.Mkdir(decoy, 0o700))
			o := f.attackedBuild(t, "plant:"+name, seed, filepath.Join(f.root, "unused"), decoy, seed)
			require.Equal(t, 2, o.code, o.stdout+o.stderr)
			assert.Contains(t, o.stderr, want)
			assert.Empty(t, filesUnder(t, decoy), "the planted link's target was never created")
			if name != "seed.json" {
				assert.NoFileExists(t, filepath.Join(seed, "seed.json"), "no seed is written")
			}
		})
	}
}

// copyCompare copies src twice, with the old export (shutil.copytree, symlinks kept, copy2) and with
// the descriptor copy (copy_dir_at, then the top directory's mode and times, as write_seed does), and
// prints each copy's tree_digest, then every entry whose type, permission bits, modification time
// or link target differ between the two. A link's own permission bits and times are not compared:
// they grant nothing, the digest does not cover them, and the descriptor copy does not keep them
// (copytree set them with lchmod where the platform has it).
const copyCompare = `
import importlib.util, os, shutil, stat, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
src, out = Path(sys.argv[2]), Path(sys.argv[3])
old, new = out / "old", out / "new"
shutil.copytree(src, old, symlinks=True, copy_function=shutil.copy2)
os.mkdir(new, 0o700)
s = os.open(src, ms.DIR_FLAGS)
d = os.open(new, ms.DIR_FLAGS)
ms.copy_dir_at(s, d, [10**7], None, "copy")
ms.keep_mode_and_times(d, os.fstat(s))
limits = (10**7, 1 << 40)
print(ms.tree_digest(old, *limits)[0])
print(ms.tree_digest(new, *limits)[0])
def facts(root):
    got = {}
    for dirpath, dirs, files in os.walk(root):
        for n in [".", *dirs, *files] if dirpath == str(root) else [*dirs, *files]:
            p = os.path.join(dirpath, n)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):  # a link's own mode and times mean nothing, and are not kept
                fact = (stat.S_IFMT(st.st_mode), None, None, os.readlink(p))
            else:
                fact = (stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_mtime_ns, None)
            got[os.path.normpath(os.path.relpath(p, root))] = fact
    return got
a, b = facts(old), facts(new)
for k in sorted(set(a) | set(b)):
    if a.get(k) != b.get(k):
        print("DIFF", k, a.get(k), b.get(k))
`

// The descriptor copy exports what the old shutil.copytree export did: the same tree_digest, and
// every entry's type, permission bits, modification time and link target alike, over directories,
// files and links of several modes (one directory read-only, one file executable, a link dangling
// and one absolute, which a seed refuses elsewhere but the copy keeps as it is).
func TestNodeSeedCopyMatchesCopytree(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	write := func(rel, text string, mode os.FileMode) {
		p := filepath.Join(src, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(text), 0o600))
		require.NoError(t, os.Chmod(p, mode))
	}
	write(".pnpm/a@1.0.0/node_modules/a/index.js", "module.exports = 1\n", 0o644)
	write(".pnpm/a@1.0.0/node_modules/a/bin.js", "#!/usr/bin/env node\n", 0o755)
	write(".pnpm/a@1.0.0/node_modules/a/private", "x", 0o600)
	write(".bin/a", "#!/bin/sh\n", 0o750)
	write("empty-dir/.keep", "", 0o644)
	require.NoError(t, os.Remove(filepath.Join(src, "empty-dir/.keep")))
	require.NoError(t, os.Symlink(".pnpm/a@1.0.0/node_modules/a", filepath.Join(src, "a")))
	require.NoError(t, os.Symlink("nowhere", filepath.Join(src, "dangling")))
	require.NoError(t, os.Symlink("/etc", filepath.Join(src, ".pnpm/abs")))
	require.NoError(t, os.Chmod(filepath.Join(src, ".pnpm/a@1.0.0"), 0o555))
	t.Cleanup(func() {
		for _, top := range []string{src, filepath.Join(root, "out")} {
			_ = filepath.WalkDir(top, func(p string, d os.DirEntry, _ error) error {
				if d != nil && d.IsDir() {
					_ = os.Chmod(p, 0o755)
				}
				return nil
			})
		}
	})
	outDir := filepath.Join(root, "out")
	require.NoError(t, os.Mkdir(outDir, 0o700))
	out, err := exec.Command(python(t), "-I", "-B", "-c", copyCompare, script(t, "mutate-sandboxed.py"), src, outDir).CombinedOutput()
	require.NoError(t, err, string(out))
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.Len(t, lines, 2, "two digests and no DIFF line: %s", out)
	assert.Equal(t, lines[0], lines[1], "the same tree_digest")
}

// okr/web's real seed, exported by TXE-8348's build: each of its node_modules is exported again by
// the old shutil.copytree export and by the descriptor copy (copyCompare), and the two hash alike
// and agree entry by entry. Set NODE_SEED_EXPORT_DIR to that seed's directory; skipped when it is
// unset, as in CI, which has no such seed. Nothing is installed or run: host-side copies into a
// temporary directory, hashed. The digests in that seed's seed.json are not compared: it was built
// before the digest covered execute bits (TXE-8348 ccca0513), so they are in an older format.
func TestNodeSeedRealExportHashesAlike(t *testing.T) {
	seedDir := os.Getenv("NODE_SEED_EXPORT_DIR")
	if seedDir == "" {
		t.Skip("NODE_SEED_EXPORT_DIR is unset")
	}
	modules := readSeed(t, seedDir)["node_modules"].(map[string]any)
	require.NotEmpty(t, modules)
	for nm := range modules {
		t.Run(nm, func(t *testing.T) {
			outDir := t.TempDir()
			out, err := exec.Command(python(t), "-I", "-B", "-c", copyCompare, script(t, "mutate-sandboxed.py"),
				filepath.Join(seedDir, "tree", nm), outDir).CombinedOutput()
			require.NoError(t, err, string(out))
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			require.Len(t, lines, 2, "two digests and no DIFF line: %s", out)
			assert.Equal(t, lines[0], lines[1], "the old export and the descriptor copy hash alike")
			t.Logf("%s %s", nm, lines[1])
		})
	}
}

// A seed whose lockfile, manifests, image or content no longer match is refused before any run.
func TestNodeSeedMismatchRefused(t *testing.T) {
	cases := map[string]struct {
		change func(t *testing.T, f nodeFixture, seed string)
		image  string
		want   string
	}{
		"lockfile hash differs": {func(t *testing.T, f nodeFixture, _ string) {
			appendFile(t, filepath.Join(f.tree, "pnpm-lock.yaml"), "# a dependency changed\n")
		}, "node-image", "was built for pnpm-lock.yaml sha256 "},
		"a manifest differs": {func(t *testing.T, f nodeFixture, _ string) {
			appendFile(t, filepath.Join(f.tree, "apps", "web", "package.json"), "\n")
		}, "node-image", "was built from other manifests (apps/web/package.json differ)"},
		"a new manifest": {func(t *testing.T, f nodeFixture, _ string) {
			require.NoError(t, os.MkdirAll(filepath.Join(f.tree, "apps", "docs"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(f.tree, "apps", "docs", "package.json"), []byte("{}"), 0o644))
		}, "node-image", "(apps/docs/package.json differ)"},
		"another image": {func(*testing.T, nodeFixture, string) {}, "other-image", "was built with image sha256:"},
		"seed content changed": {func(t *testing.T, _ nodeFixture, seed string) {
			appendFile(t, filepath.Join(seed, "tree", "node_modules", ".pnpm", "leftpad@1.0.0", "node_modules", "leftpad", "index.js"), "evil()\n")
		}, "node-image", "node_modules changed since the seed was built"},
		"seed executable lost its execute bit": {func(t *testing.T, _ nodeFixture, seed string) {
			require.NoError(t, os.Chmod(filepath.Join(seed, "tree", "node_modules", ".pnpm", "leftpad@1.0.0", "node_modules", "leftpad", "bin.js"), 0o644))
		}, "node-image", "node_modules changed since the seed was built"},
		"seed link changed": {func(t *testing.T, _ nodeFixture, seed string) {
			link := filepath.Join(seed, "tree", "apps", "web", "node_modules", "leftpad")
			require.NoError(t, os.Remove(link))
			require.NoError(t, os.Symlink("../../../node_modules/.pnpm/esbuild@0.25.0/node_modules/esbuild", link))
		}, "node-image", "apps/web/node_modules changed since the seed was built"},
		"not a seed": {func(t *testing.T, _ nodeFixture, seed string) {
			require.NoError(t, os.Remove(filepath.Join(seed, "seed.json")))
		}, "node-image", "is not a seed"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newNodeFixture(t)
			seed := filepath.Join(f.root, "seed")
			require.Equal(t, 0, f.build(t, seed).code)
			c.change(t, f, seed)
			o := f.run(t, f.mutants(t, nodeMutants), "--node-seed", seed, "--image", c.image)
			require.Equal(t, 2, o.code, o.stdout+o.stderr)
			assert.Contains(t, o.stderr, c.want)
			assert.Len(t, dockerRuns(t, f.log), 1, "only the seed's own install ever ran")
		})
	}
}

func appendFile(t *testing.T, p, text string) {
	t.Helper()
	fh, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = fh.WriteString(text)
	require.NoError(t, err)
	require.NoError(t, fh.Close())
}

// Lifecycle scripts stay disabled unless a package is allowlisted by name; an allowlisted package
// is rebuilt by its own step after the --ignore-scripts install, and the record says which ran.
func TestNodeSeedLifecycleAllowlist(t *testing.T) {
	f := newNodeFixture(t)
	seedDir := filepath.Join(f.root, "seed")
	o := f.build(t, seedDir, "--node-seed-allow-build", "esbuild")
	require.Equal(t, 0, o.code, o.stdout+o.stderr)
	calls := f.pnpmCalls(t)
	require.Len(t, calls, 3)
	assert.Contains(t, strs(calls[1]["args"]), "--ignore-scripts", "the install itself still runs no script")
	rebuild := strs(calls[2]["args"])
	assert.Equal(t, "rebuild", rebuild[0])
	assert.Equal(t, "-r", rebuild[1], "recursive: a package only a workspace project depends on is reached")
	assert.Equal(t, "esbuild", rebuild[len(rebuild)-1], "only the allowlisted name is rebuilt")
	runs := dockerRuns(t, f.log)
	assert.Equal(t, []string{"sh", "esbuild"}, runs[0][len(runs[0])-2:], "names are arguments, never script text")
	seed := readSeed(t, seedDir)
	assert.Equal(t, []any{"esbuild"}, seed["allow_build"])
	deps := seed["lifecycle_scripts"].(map[string]any)["dependencies"].(map[string]any)
	assert.Equal(t, "allowlisted", deps["esbuild@0.25.0"].(map[string]any)["ran"])
	assert.Equal(t, "skipped", deps["@scope/native@2.0.0"].(map[string]any)["ran"])
	log, err := os.ReadFile(filepath.Join(seedDir, "install.log"))
	require.NoError(t, err)
	// The fake docker maps /work to the run's host directory, so the store path is a host path here.
	// The install's pnpmfile and package-manager settings carry over (root's review of 984f6e0f).
	assert.Regexp(t, `\n\+ pnpm rebuild -r --config.dangerously-allow-all-builds=true --config.ignore-pnpmfile=true `+
		`--config.manage-package-manager-versions=false --store-dir=\S+/sandbox/pnpm-store --reporter=append-only esbuild\n`, string(log))

	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"shell text":            {[]string{"--node-seed-build", filepath.Join(f.root, "s2"), "--image", "node-image", "--node-seed-allow-build", "esbuild;id"}, "is not an npm package name"},
		"upper case":            {[]string{"--node-seed-build", filepath.Join(f.root, "s3"), "--image", "node-image", "--node-seed-allow-build", "Esbuild"}, "is not an npm package name"},
		"allowlist on a run":    {[]string{"--node-seed", seedDir, "--image", "node-image", "--mutants", f.mutants(t, nodeMutants), "--node-seed-allow-build", "esbuild", "--", "sh", "check.sh"}, "used only with --node-seed-build"},
		"seed and no seed":      {[]string{"--node-seed", seedDir, "--no-node-seed", "--image", "node-image", "--mutants", f.mutants(t, nodeMutants), "--", "sh", "check.sh"}, "exclude each other"},
		"build with a command":  {[]string{"--node-seed-build", filepath.Join(f.root, "s4"), "--image", "node-image", "--", "sh", "check.sh"}, "takes no command"},
		"build with mutants":    {[]string{"--node-seed-build", filepath.Join(f.root, "s5"), "--image", "node-image", "--mutants", f.mutants(t, nodeMutants)}, "takes no command"},
		"build with diagnostic": {[]string{"--node-seed-build", filepath.Join(f.root, "s6"), "--image", "node-image", "--diagnostic"}, "takes no command"},
		// pnpm rebuild -r selects by name: a workspace project's own scripts must never be reachable.
		"a workspace project's name": {[]string{"--node-seed-build", filepath.Join(f.root, "s7"), "--image", "node-image", "--node-seed-allow-build", "web"}, "names a workspace project (apps/web/package.json)"},
	} {
		t.Run(name, func(t *testing.T) {
			o := f.raw(t, c.args...)
			assert.Equal(t, 2, o.code, o.stdout+o.stderr)
			assert.Contains(t, o.stderr, c.want)
		})
	}
	assert.Len(t, dockerRuns(t, f.log), 1, "no refused call reached docker run")
}

// The tree's .npmrc can set node-linker=hoisted: packages are plain directories under node_modules,
// and the record and the allowlist check still find them, by path.
func TestNodeSeedHoistedLayout(t *testing.T) {
	f := newNodeFixture(t)
	require.NoError(t, os.WriteFile(f.pnpmMode, []byte("hoisted"), 0o644))
	seedDir := filepath.Join(f.root, "seed")
	o := f.build(t, seedDir, "--node-seed-allow-build", "esbuild")
	require.Equal(t, 0, o.code, o.stdout+o.stderr)
	deps := readSeed(t, seedDir)["lifecycle_scripts"].(map[string]any)["dependencies"].(map[string]any)
	esbuild := deps["esbuild@0.25.0"].(map[string]any)
	assert.Equal(t, "allowlisted", esbuild["ran"])
	assert.Equal(t, map[string]any{"node_modules/esbuild": map[string]any{"postinstall": "node install.js"},
		"node_modules/leftpad/node_modules/esbuild": map[string]any{"postinstall": "node other.js"}}, esbuild["paths"],
		"two copies of one name@version keep their own scripts")
	o = f.run(t, f.mutants(t, nodeMutants), "--node-seed", seedDir, "--image", "node-image")
	require.Equal(t, 0, o.code, o.stdout+o.stderr)
	assert.Equal(t, "KILLED", o.outcomes()["guard removed"])
}

// A published release that shares a workspace project's name (a project depending on its previous
// release) is a dependency with its own manifest, not an injected copy: the seed is built.
func TestNodeSeedPublishedNamesakeIsNotInjected(t *testing.T) {
	f := newNodeFixture(t)
	require.NoError(t, os.WriteFile(f.pnpmMode, []byte("published"), 0o644))
	o := f.build(t, filepath.Join(f.root, "seed"))
	require.Equal(t, 0, o.code, o.stdout+o.stderr)
	assert.FileExists(t, filepath.Join(f.root, "seed", "tree", "node_modules", ".pnpm", "web@1.0.0", "node_modules", "web", "index.js"))
}

// A workspace package's bin points at source the manifest-only install lacks, so pnpm would link no
// shim for the project that depends on it: refused after the image check, before any container.
// A bin that no other project depends on links nothing and is fine.
func TestNodeSeedWorkspaceBinRefused(t *testing.T) {
	f := newNodeFixture(t)
	require.NoError(t, os.WriteFile(filepath.Join(f.tree, "apps", "web", "package.json"),
		[]byte(`{"name": "web", "bin": {"web-cli": "src/cli.js"}}`), 0o644))
	o := f.build(t, filepath.Join(f.root, "seed-unused"))
	require.Equal(t, 0, o.code, "a bin no project depends on: "+o.stdout+o.stderr)
	require.NoError(t, os.WriteFile(filepath.Join(f.tree, "package.json"),
		[]byte(`{"name": "ws", "private": true, "devDependencies": {"web": "workspace:*"}}`), 0o644))
	before := len(dockerRuns(t, f.log))
	o = f.build(t, filepath.Join(f.root, "seed"))
	require.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, "package.json uses web (apps/web/package.json)")
	assert.NoFileExists(t, filepath.Join(f.root, "seed", "seed.json"))
	assert.Len(t, dockerRuns(t, f.log), before, "no container ran")
}

// okrWebConfig is okr/web's pnpm configuration surface on txehq/txe main b002c1d0 (2026-11-24):
// pnpm-workspace.yaml and the lockfile's header verbatim, and every manifest field and dependency
// specifier shape its six projects use. The lockfile body and the dependency list are not copied:
// this repository is public, and they would list a private application's dependencies.
var okrWebConfig = map[string]string{
	"pnpm-workspace.yaml": "packages:\n  - packages/*\n  - apps/*\n\n" +
		"# @axe-core/playwright accepts any playwright-core; pin it to the one\n" +
		"# @playwright/test uses so there is a single Playwright in the workspace.\n" +
		"overrides:\n  playwright-core: 1.62.1\n\n" +
		"# @sentry/cli ships its binary as a per-platform optional dependency; its\n" +
		"# install script only downloads the same binary when that is missing, and\n" +
		"# needs the network. The build uses the packaged one (TXE-3424).\n" +
		"ignoredBuiltDependencies:\n  - '@sentry/cli'\n",
	// The lockfile's header verbatim, then one entry of each nested shape okr/web's lockfile has
	// (measured over its 6 importers, 547 packages and 547 snapshots): every resolution an
	// integrity, `link:` only as a workspace:* importer version, an npm: alias, peer suffixes.
	"pnpm-lock.yaml": `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

overrides:
  playwright-core: 1.62.1

importers:

  .:
    devDependencies:
      typescript:
        specifier: 5.9.3
        version: 5.9.3

  apps/web:
    dependencies:
      '@okr/ui':
        specifier: workspace:*
        version: link:../../packages/ui
      webreplay-css-tokenizer:
        specifier: npm:@csstools/css-tokenizer@3.0.4
        version: '@csstools/css-tokenizer@3.0.4'
    devDependencies:
      vitest:
        specifier: 4.1.8
        version: 4.1.8(@types/node@22.20.4)

  packages/calc: {}

  packages/ui:
    dependencies:
      '@okr/calc':
        specifier: workspace:*
        version: link:../calc

packages:

  '@csstools/css-tokenizer@3.0.4':
    resolution: {integrity: sha512-AAAA}
    engines: {node: '>=18'}

  typescript@5.9.3:
    resolution: {integrity: sha512-BBBB}
    engines: {node: '>=14.17'}
    hasBin: true

  vitest@4.1.8:
    resolution: {integrity: sha512-CCCC==}
    engines: {node: ^20.0.0 || ^22.0.0 || >=24.0.0}
    hasBin: true
    peerDependencies:
      '@types/node': ^20.0.0 || ^22.0.0 || >=24.0.0
      jsdom: '*'
    peerDependenciesMeta:
      jsdom:
        optional: true

  '@rolldown/binding-linux-arm64-gnu@1.0.3':
    resolution: {integrity: sha512-DDDD}
    cpu: [arm64]
    os: [linux]
    libc: [glibc]

snapshots:

  '@csstools/css-tokenizer@3.0.4': {}

  typescript@5.9.3: {}

  vitest@4.1.8(@types/node@22.20.4):
    dependencies:
      '@types/node': 22.20.4
    optionalDependencies:
      '@rolldown/binding-linux-arm64-gnu': 1.0.3
    transitivePeerDependencies:
      - jsdom

  '@rolldown/binding-linux-arm64-gnu@1.0.3':
    optional: true
`,
	"packages/calc/package.json": `{"name": "@okr/calc", "private": true, "version": "0.0.0", "type": "module",
		"exports": {".": "./src/index.ts"}, "sideEffects": false}`,
	"package.json": `{"name": "okr-web", "private": true, "version": "0.0.0", "type": "module", "packageManager": "pnpm@10.33.0",
		"engines": {"node": "^22.18.0 || >=23.6.0"}, "scripts": {"test": "pnpm -r run test"},
		"devDependencies": {"typescript": "5.9.3", "globals": "^16.0.0"}}`,
	"apps/web/package.json": `{"name": "@okr/web", "private": true, "version": "0.0.0", "type": "module", "scripts": {"test": "vitest run"},
		"dependencies": {"@okr/ui": "workspace:*", "rrweb": "2.0.0-alpha.20", "webreplay-css-tokenizer": "npm:@csstools/css-tokenizer@3.0.4"},
		"devDependencies": {"vitest": "4.1.8"}}`,
	"packages/ui/package.json": `{"name": "@okr/ui", "private": true, "version": "0.0.0", "type": "module", "scripts": {},
		"exports": {".": "./src/index.ts"}, "sideEffects": false, "dependencies": {"@okr/calc": "workspace:*"},
		"peerDependencies": {"react": "^19.0.0"}, "devDependencies": {"@types/react": "^19.0.0"}}`,
}

// nodeConfigVerdict writes files over okrWebConfig into a new tree and runs the runner's own
// check_node_config on it: "ok" or the refusal's text.
func nodeConfigVerdict(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	merged := map[string]string{}
	maps.Copy(merged, okrWebConfig)
	maps.Copy(merged, files)
	for rel, text := range merged {
		p := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(text), 0o644))
	}
	prog := `
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
root = Path(sys.argv[2])
try:
    ms.check_node_config(root, ms.node_inputs(root))
    print("ok")
except ms.Refused as e:
    print(e)
`
	out, err := exec.Command(python(t), "-I", "-B", "-c", prog, script(t, "mutate-sandboxed.py"), root).CombinedOutput()
	require.NoError(t, err, string(out))
	return strings.TrimSpace(string(out))
}

// The closed set: okr/web's configuration passes, and each setting or layout feature outside it
// is refused by name, never built into a different seed.
func TestNodeConfigClosedSet(t *testing.T) {
	assert.Equal(t, "ok", nodeConfigVerdict(t, nil), "okr/web's configuration is the supported one")
	// Positive controls for the glob rule: a relative exclusion and a nested relative glob pass.
	assert.Equal(t, "ok", nodeConfigVerdict(t, map[string]string{"pnpm-workspace.yaml": strings.Replace(
		okrWebConfig["pnpm-workspace.yaml"], "  - apps/*", "  - apps/*\n  - '!apps/old'\n  - tools/web/*", 1)}),
		"relative globs, `!` exclusions included, stay inside the tree")
	const tail = "is outside the pnpm configuration the node seed supports"
	lock, ws := okrWebConfig["pnpm-lock.yaml"], okrWebConfig["pnpm-workspace.yaml"]
	cases := map[string]struct {
		files map[string]string
		want  string
	}{
		"an .npmrc setting": {map[string]string{".npmrc": "# layout\nnode-linker=hoisted\n"},
			".npmrc:2: the setting 'node-linker=hoisted' (no .npmrc setting is supported) " + tail},
		"a workspace setting": {map[string]string{"pnpm-workspace.yaml": okrWebConfig["pnpm-workspace.yaml"] + "injectWorkspacePackages: true\n"},
			"pnpm-workspace.yaml: the setting 'injectWorkspacePackages' " + tail},
		"workspace flow style": {map[string]string{"pnpm-workspace.yaml": "{packages: [apps/*]}\n"},
			"is outside the YAML the seed reads"},
		"a workspace anchor": {map[string]string{"pnpm-workspace.yaml": "packages: &p\n  - apps/*\n"},
			"is outside the YAML the seed reads"},
		"a lockfile setting": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "  excludeLinksFromLockfile: false\n",
			"  excludeLinksFromLockfile: false\n  injectWorkspacePackages: true\n", 1)},
			"pnpm-lock.yaml settings: 'injectWorkspacePackages: true' " + tail},
		"a lockfile setting's value": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "autoInstallPeers: true", "autoInstallPeers: false", 1)},
			"'autoInstallPeers: false' " + tail},
		"a lockfile section": {map[string]string{"pnpm-lock.yaml": lock + "\npatchedDependencies:\n  x: patches/x.patch\n"},
			"pnpm-lock.yaml: the section 'patchedDependencies' " + tail},
		"another lockfile version": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "'9.0'", "'6.0'", 1)},
			"lockfileVersion '6.0' " + tail},
		// Nested routes (root's review of 984f6e0f): each way a nested entry could name a file:,
		// link:, URL or git source, or repeat a key, is refused.
		"workspace override to link:": {map[string]string{"pnpm-workspace.yaml": strings.Replace(ws, "playwright-core: 1.62.1", "playwright-core: link:../pw", 1)},
			"pnpm-workspace.yaml overrides: the override playwright-core: 'link:../pw' " + tail},
		"workspace override to file:": {map[string]string{"pnpm-workspace.yaml": strings.Replace(ws, "playwright-core: 1.62.1", "playwright-core: file:../pw.tgz", 1)},
			"the override playwright-core: 'file:../pw.tgz'"},
		"workspace override to a URL": {map[string]string{"pnpm-workspace.yaml": strings.Replace(ws, "playwright-core: 1.62.1", "playwright-core: https://example.com/pw.tgz", 1)},
			"the override playwright-core: 'https://example.com/pw.tgz'"},
		"workspace override to git": {map[string]string{"pnpm-workspace.yaml": strings.Replace(ws, "playwright-core: 1.62.1", "playwright-core: github:user/pw", 1)},
			"the override playwright-core: 'github:user/pw'"},
		"workspace override to workspace:": {map[string]string{"pnpm-workspace.yaml": strings.Replace(ws, "playwright-core: 1.62.1", "playwright-core: workspace:*", 1)},
			"the override playwright-core: 'workspace:*'"},
		"workspace override selector": {map[string]string{"pnpm-workspace.yaml": strings.Replace(ws, "playwright-core: 1.62.1", "'a>playwright-core': 1.62.1", 1)},
			"the override selector 'a>playwright-core'"},
		"workspace duplicate override": {map[string]string{"pnpm-workspace.yaml": strings.Replace(ws, "playwright-core: 1.62.1", "playwright-core: 1.62.1\n  playwright-core: 1.0.0", 1)},
			"the key 'playwright-core' is given twice"},
		"workspace package glob outside": {map[string]string{"pnpm-workspace.yaml": strings.Replace(ws, "  - apps/*", "  - ../outside/*", 1)},
			"pnpm-workspace.yaml packages: the entry '../outside/*'"},
		// Absolute globs (root's review of b51ba7c9), with and without pnpm's `!` exclusion.
		"workspace package glob absolute": {map[string]string{"pnpm-workspace.yaml": strings.Replace(ws, "  - apps/*", "  - /srv/apps/*", 1)},
			"pnpm-workspace.yaml packages: the entry '/srv/apps/*'"},
		"workspace exclusion glob absolute": {map[string]string{"pnpm-workspace.yaml": strings.Replace(ws, "  - apps/*", "  - apps/*\n  - '!/srv/apps/old'", 1)},
			"pnpm-workspace.yaml packages: the entry '!/srv/apps/old'"},
		"workspace exclusion glob outside": {map[string]string{"pnpm-workspace.yaml": strings.Replace(ws, "  - apps/*", "  - apps/*\n  - '!../old'", 1)},
			"pnpm-workspace.yaml packages: the entry '!../old'"},
		"lockfile override to link:": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "overrides:\n  playwright-core: 1.62.1", "overrides:\n  playwright-core: link:../pw", 1)},
			"pnpm-lock.yaml overrides: the override playwright-core: 'link:../pw'"},
		"lockfile tarball resolution": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "{integrity: sha512-BBBB}", "{tarball: https://example.com/ts.tgz}", 1)},
			"the resolution '{tarball: https://example.com/ts.tgz}' (a registry integrity only)"},
		"lockfile directory resolution": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "{integrity: sha512-BBBB}", "{directory: ../ts, type: directory}", 1)},
			"the resolution '{directory: ../ts, type: directory}'"},
		"lockfile git resolution": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "{integrity: sha512-BBBB}", "{commit: abc, repo: https://example.com/ts.git, type: git}", 1)},
			"the resolution '{commit: abc, repo: https://example.com/ts.git, type: git}'"},
		// Quoted, as pnpm writes such keys; unquoted, the ':' already fails the grammar.
		"lockfile file: package": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "  typescript@5.9.3:\n    resolution", "  'typescript@file:../ts':\n    resolution", 1)},
			"the package 'typescript@file:../ts' (registry packages only)"},
		"lockfile package field": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "    hasBin: true\n\n  vitest", "    hasBin: true\n    bundledDependencies: [x]\n\n  vitest", 1)},
			"pnpm-lock.yaml packages typescript@5.9.3: the field 'bundledDependencies'"},
		"lockfile duplicate package": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "  typescript@5.9.3:\n    resolution: {integrity: sha512-BBBB}", "  typescript@5.9.3:\n    resolution: {integrity: sha512-BBBB}\n\n  typescript@5.9.3:\n    resolution: {integrity: sha512-BBBB}", 1)},
			"the key 'typescript@5.9.3' is given twice"},
		"lockfile snapshot link:": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "      '@types/node': 22.20.4", "      '@types/node': link:../node", 1)},
			"pnpm-lock.yaml snapshots vitest@4.1.8(@types/node@22.20.4): the dependencies value"},
		"lockfile file: snapshot": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "  typescript@5.9.3: {}", "  'typescript@file:../ts': {}", 1)},
			"the snapshot 'typescript@file:../ts' (registry packages only)"},
		"lockfile importer specifier file:": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "        specifier: 4.1.8\n", "        specifier: file:../vitest\n", 1)},
			"pnpm-lock.yaml importers apps/web devDependencies: the entry vitest"},
		"lockfile importer version link:": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "        version: 4.1.8(@types/node@22.20.4)", "        version: link:../vitest", 1)},
			"the version vitest: 'link:../vitest'"},
		"lockfile workspace link outside": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "version: link:../../packages/ui", "version: link:../../../elsewhere", 1)},
			"the workspace version @okr/ui: 'link:../../../elsewhere'"},
		"lockfile unknown importer": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "  packages/calc: {}", "  packages/calc: {}\n\n  ../other: {}", 1)},
			"pnpm-lock.yaml importers ../other: an importer that is not a workspace project"},
		"unquoted key with a colon": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "  typescript@5.9.3: {}", "  typescript@file:../ts: {}", 1)},
			"is outside the YAML the seed reads"},
		"lockfile importer not a project": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "  packages/calc: {}", "  packages/calc: {}\n\n  packages/gone: {}", 1)},
			"pnpm-lock.yaml importers packages/gone: an importer that is not a workspace project"},
		"lockfile double-quoted value": {map[string]string{"pnpm-lock.yaml": strings.Replace(lock, "playwright-core: 1.62.1", `playwright-core: "1.62.1"`, 1)},
			"is outside the YAML the seed reads"},
		"a pnpm field": {map[string]string{"package.json": `{"name": "okr-web", "pnpm": {"overrides": {}}}`},
			"package.json: the field 'pnpm' " + tail},
		"dependenciesMeta": {map[string]string{"apps/web/package.json": `{"name": "@okr/web", "dependenciesMeta": {"@okr/ui": {"injected": true}}}`},
			"apps/web/package.json: the field 'dependenciesMeta' " + tail},
		"optionalDependencies": {map[string]string{"apps/web/package.json": `{"name": "@okr/web", "optionalDependencies": {"x": "1.0.0"}}`},
			"the field 'optionalDependencies'"},
		"publishConfig": {map[string]string{"packages/ui/package.json": `{"name": "@okr/ui", "publishConfig": {"directory": "dist"}}`},
			"the field 'publishConfig'"},
		"a file: dependency": {map[string]string{"apps/web/package.json": `{"name": "@okr/web", "dependencies": {"x": "file:../vendor/x"}}`},
			"the dependencies specifier x: 'file:../vendor/x' " + tail},
		"a link: dependency": {map[string]string{"apps/web/package.json": `{"name": "@okr/web", "devDependencies": {"x": "link:../x"}}`},
			"the devDependencies specifier x: 'link:../x'"},
		"a GitHub dependency": {map[string]string{"apps/web/package.json": `{"name": "@okr/web", "dependencies": {"x": "user/repo"}}`},
			"the dependencies specifier x: 'user/repo'"},
		"another workspace range": {map[string]string{"apps/web/package.json": `{"name": "@okr/web", "dependencies": {"@okr/ui": "workspace:^"}}`},
			"the dependencies specifier @okr/ui: 'workspace:^'"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Contains(t, nodeConfigVerdict(t, c.files), c.want)
		})
	}
}

// A real workspace's configuration against the closed set, read only (nothing is installed or
// run): set NODE_SEED_CONFIG_TREE to a pnpm workspace's root. Skipped when it is unset, as in CI,
// which has no such tree (TXE-8348 ran it on an export of okr/web).
func TestNodeConfigRealTree(t *testing.T) {
	root := os.Getenv("NODE_SEED_CONFIG_TREE")
	if root == "" {
		t.Skip("NODE_SEED_CONFIG_TREE is unset")
	}
	prog := `
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("ms", sys.argv[1])
ms = importlib.util.module_from_spec(spec); sys.modules["ms"] = ms; spec.loader.exec_module(ms)
root = Path(sys.argv[2])
inputs = ms.node_inputs(root)
ms.check_node_config(root, inputs)
print("ok:", len(inputs), "inputs")
`
	out, err := exec.Command(python(t), "-I", "-B", "-c", prog, script(t, "mutate-sandboxed.py"), root).CombinedOutput()
	require.NoError(t, err, string(out))
	t.Log(strings.TrimSpace(string(out)))
}

// The closed set stops the build before its container: an unlisted setting writes no seed.
func TestNodeSeedBuildRefusesUnlistedConfig(t *testing.T) {
	f := newNodeFixture(t)
	require.NoError(t, os.WriteFile(filepath.Join(f.tree, ".npmrc"), []byte("virtual-store-dir=.pnpm\n"), 0o644))
	o := f.build(t, filepath.Join(f.root, "seed"))
	require.Equal(t, 2, o.code, o.stdout+o.stderr)
	assert.Contains(t, o.stderr, ".npmrc:1: the setting 'virtual-store-dir=.pnpm'")
	assert.NoFileExists(t, filepath.Join(f.root, "seed", "seed.json"))
	assert.Empty(t, dockerRuns(t, f.log), "no container ran")
	assert.Nil(t, f.pnpmCalls(t))
}

// A seed build that cannot produce a sound seed writes none.
func TestNodeSeedBuildRefusals(t *testing.T) {
	cases := map[string]struct {
		setup func(t *testing.T, f nodeFixture, seed string)
		want  string
		ran   bool
	}{
		"seed directory exists": {func(t *testing.T, _ nodeFixture, seed string) {
			require.NoError(t, os.MkdirAll(seed, 0o755))
		}, "already exists", false},
		"no lockfile": {func(t *testing.T, f nodeFixture, _ string) {
			require.NoError(t, os.Remove(filepath.Join(f.tree, "pnpm-lock.yaml")))
		}, "has no regular pnpm-lock.yaml", false},
		"inside the live tree": {nil, "overlaps live tree", false},
		"install fails": {func(t *testing.T, f nodeFixture, _ string) {
			require.NoError(t, os.WriteFile(f.pnpmMode, []byte("fail"), 0o644))
		}, "the seed's install did not pass (FAILED, exit 1)", true},
		"link out of the tree": {func(t *testing.T, f nodeFixture, _ string) {
			require.NoError(t, os.WriteFile(f.pnpmMode, []byte("abslink"), 0o644))
		}, "outside the tree", true},
		"lockfile rewritten": {func(t *testing.T, f nodeFixture, _ string) {
			require.NoError(t, os.WriteFile(f.pnpmMode, []byte("touchlock"), 0o644))
		}, "the seed's install changed pnpm-lock.yaml", true},
		"manifest swapped for a FIFO": {func(t *testing.T, f nodeFixture, _ string) {
			require.NoError(t, os.WriteFile(f.pnpmMode, []byte("fifo"), 0o644))
		}, "apps/web/package.json is not a regular file", true},
		// The tree's .npmrc can set virtual-store-dir: copying only node_modules would leave dangling links.
		"virtual store outside node_modules": {func(t *testing.T, f nodeFixture, _ string) {
			require.NoError(t, os.WriteFile(f.pnpmMode, []byte("outsidestore"), 0o644))
		}, "outside every node_modules", true},
		// A setuid file would keep its mode when exported, owned by the runner's uid.
		"setuid file in the seed": {func(t *testing.T, f nodeFixture, _ string) {
			require.NoError(t, os.WriteFile(f.pnpmMode, []byte("setuid"), 0o644))
		}, "node_modules: .bin/shell is setuid or setgid (mode 0o4755); a seed never holds one", true},
		// An injected workspace package is a copy of its source, which a manifest-only install lacks.
		"injected workspace package": {func(t *testing.T, f nodeFixture, _ string) {
			require.NoError(t, os.WriteFile(f.pnpmMode, []byte("injected"), 0o644))
		}, "injected workspace project copies (web at node_modules/.pnpm/web@file+apps+web/node_modules/web:", true},
		// A rebuild of a name nothing installed runs nothing, silently; it is never recorded as allowlisted.
		"allowlisted name not installed": {func(t *testing.T, f nodeFixture, _ string) {
			require.NoError(t, os.WriteFile(f.pnpmMode, []byte("allow:nosuchpkg"), 0o644))
		}, "--node-seed-allow-build nosuchpkg: no installed dependency has that name", true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newNodeFixture(t)
			seed := filepath.Join(f.root, "seed")
			if c.setup == nil {
				seed = filepath.Join(f.tree, "seed")
			} else {
				c.setup(t, f, seed)
			}
			var extra []string
			if mode, err := os.ReadFile(f.pnpmMode); err == nil {
				if name, ok := strings.CutPrefix(string(mode), "allow:"); ok {
					extra = []string{"--node-seed-allow-build", name}
				}
			}
			o := f.build(t, seed, extra...)
			require.Equal(t, 2, o.code, o.stdout+o.stderr)
			assert.Contains(t, o.stderr, c.want)
			assert.NoFileExists(t, filepath.Join(seed, "seed.json"), "no seed is written")
			_, err := os.Stat(f.log)
			if c.ran {
				assert.Len(t, dockerRuns(t, f.log), 1)
			} else {
				assert.True(t, os.IsNotExist(err), "refused before any docker call")
			}
		})
	}
}
