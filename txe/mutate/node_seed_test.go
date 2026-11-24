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
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
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
	report := filepath.Join(f.root, "report.json")
	_ = os.Remove(report)
	all := append([]string{"-I", "-B", script(t, "mutate-sandboxed.py"), "--tree", f.tree,
		"--shared-modcache", f.modcache, "--shared-gocache", f.gocache, "--workdir-root", f.workRoot,
		"--docker", f.docker, "--report", report, "--timeout", "60"}, args...)
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
	assert.Equal(t, []string{"node-image", "sh", "-c"}, runs[0][n-5:n-2], "the runner's own command")
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
	assert.Regexp(t, `\n\+ pnpm rebuild -r --config.dangerously-allow-all-builds=true --store-dir=\S+/sandbox/pnpm-store `+
		`--reporter=append-only esbuild\n`, string(log))

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
