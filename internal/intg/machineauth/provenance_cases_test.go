// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package machineauth_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ociFixture builds an OCI image layout on disk, link by link, so each test
// can break exactly one link of the chain.
type ociFixture struct {
	t      *testing.T
	layout string
	// pad, when set, pads each uncompressed tar with zeros to a multiple of
	// pad bytes after its end-of-archive blocks, as some tar writers do.
	pad int
}

type tarEntry struct {
	name     string
	body     string
	typeflag byte
}

func newOCIFixture(t *testing.T) *ociFixture {
	t.Helper()
	layout := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(layout, "blobs", "sha256"), 0o700))
	return &ociFixture{t: t, layout: layout}
}

// put stores a blob and returns its descriptor digest.
func (f *ociFixture) put(raw []byte) string {
	f.t.Helper()
	d := "sha256:" + sha256Hex(raw)
	require.NoError(f.t, os.WriteFile(filepath.Join(f.layout, "blobs", "sha256", sha256Hex(raw)), raw, 0o600))
	return d
}

// layer makes a gzip tar layer and returns its blob digest and diff id.
func (f *ociFixture) layer(entries ...tarEntry) (digest, diffID string, size int64) {
	f.t.Helper()
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0o755, Typeflag: tf, Size: int64(len(e.body))}
		if tf == tar.TypeDir {
			h.Mode, h.Size = 0o755, 0
		}
		if tf == tar.TypeSymlink {
			h.Linkname, h.Size = "elsewhere", 0
		}
		require.NoError(f.t, tw.WriteHeader(h))
		if h.Size > 0 {
			_, err := tw.Write([]byte(e.body))
			require.NoError(f.t, err)
		}
	}
	require.NoError(f.t, tw.Close())
	if f.pad > 0 {
		if rem := plain.Len() % f.pad; rem != 0 {
			plain.Write(make([]byte, f.pad-rem))
		}
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err := zw.Write(plain.Bytes())
	require.NoError(f.t, err)
	require.NoError(f.t, zw.Close())
	return f.put(gz.Bytes()), "sha256:" + sha256Hex(plain.Bytes()), int64(gz.Len())
}

type fixtureImage struct {
	index, manifest string
	layers          []string
}

// image assembles config, manifest and an index naming it for linux/amd64
// beside an attestation and an arm64 manifest. edit may change any JSON
// before it is stored.
func (f *ociFixture) image(layers [][]tarEntry, edit func(kind string, doc map[string]any)) fixtureImage {
	f.t.Helper()
	if edit == nil {
		edit = func(string, map[string]any) {}
	}
	var descs []any
	var diffIDs []any
	var digests []string
	for _, l := range layers {
		d, diff, size := f.layer(l...)
		descs = append(descs, map[string]any{"mediaType": mtOCILayerGzip, "digest": d, "size": size})
		diffIDs = append(diffIDs, diff)
		digests = append(digests, d)
	}
	store := func(kind string, doc map[string]any) (string, int) {
		edit(kind, doc)
		raw, err := json.Marshal(doc)
		require.NoError(f.t, err)
		return f.put(raw), len(raw)
	}
	cfg, cfgSize := store("config", map[string]any{"os": "linux", "architecture": "amd64", "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}})
	man, manSize := store("manifest", map[string]any{"schemaVersion": 2, "mediaType": mtOCIManifest,
		"config": map[string]any{"mediaType": mtOCIConfig, "digest": cfg, "size": cfgSize}, "layers": descs})
	other, otherSize := store("other", map[string]any{"schemaVersion": 2, "mediaType": mtOCIManifest, "config": map[string]any{}, "layers": []any{}})
	idx, _ := store("index", map[string]any{"schemaVersion": 2, "mediaType": mtOCIIndex, "manifests": []any{
		map[string]any{"mediaType": mtOCIManifest, "digest": man, "size": manSize, "platform": map[string]any{"os": "linux", "architecture": "amd64"}},
		map[string]any{"mediaType": mtOCIManifest, "digest": other, "size": otherSize, "platform": map[string]any{"os": "linux", "architecture": "arm64"}},
		map[string]any{"mediaType": mtOCIManifest, "digest": other, "size": otherSize, "platform": map[string]any{"os": "unknown", "architecture": "unknown"}},
	}})
	return fixtureImage{index: idx, manifest: man, layers: digests}
}

func (f *ociFixture) spec(img fixtureImage) extractSpec {
	return extractSpec{Name: "c", Layout: f.layout, Index: img.index, Platform: "linux/amd64", Manifest: img.manifest,
		Path: "/usr/local/bin/dagu", OutDir: filepath.Join(f.t.TempDir(), "out")}
}

func TestExtractFollowsTheChainToTheBinary(t *testing.T) {
	t.Parallel()
	f := newOCIFixture(t)
	img := f.image([][]tarEntry{
		{{name: "usr/local/bin/dagu", body: "first build"}, {name: "etc/passwd", body: "root"}},
		{{name: "./usr/local/bin/dagu", body: "the final build"}},
		{{name: "usr/share/doc", body: "unrelated"}},
	}, nil)
	spec := f.spec(img)
	rec, err := extractImageBinary(spec)
	require.NoError(t, err)
	raw, err := os.ReadFile(filepath.Join(spec.OutDir, "dagu"))
	require.NoError(t, err)
	assert.Equal(t, "the final build", string(raw), "the last layer that sets the file wins")
	assert.Equal(t, sha256Hex(raw), rec.BinarySHA256)
	assert.Equal(t, img.layers[1], rec.Image.Layer)
	assert.Equal(t, img.manifest, rec.Image.Manifest)
	assert.Len(t, rec.Image.Layers, 3)
	// The record on disk is the one returned, and binds as a provenance ref.
	recRaw, err := os.ReadFile(filepath.Join(spec.OutDir, "provenance.json"))
	require.NoError(t, err)
	got, err := readProvenance(&provenanceRef{Record: filepath.Join(spec.OutDir, "provenance.json"), SHA256: sha256Hex(recRaw)}, rec.BinarySHA256)
	require.NoError(t, err)
	assert.Equal(t, "image", got.Kind)
	// A second extraction into the same directory is refused.
	_, err = extractImageBinary(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "never overwrites")
}

// A tar padded past its end-of-archive blocks is read whole: both digests
// cover every byte (the padding is part of the layer's diff id).
func TestExtractReadsAPaddedLayer(t *testing.T) {
	t.Parallel()
	f := newOCIFixture(t)
	f.pad = 10240
	img := f.image([][]tarEntry{{{name: "usr/local/bin/dagu", body: "padded build"}}}, nil)
	spec := f.spec(img)
	rec, err := extractImageBinary(spec)
	require.NoError(t, err)
	assert.Equal(t, sha256Hex([]byte("padded build")), rec.BinarySHA256)
}

// A layer's whiteouts apply to the layers below it: a file the same layer
// sets survives them, whatever the order of the tar's entries.
func TestExtractKeepsAFileSetInTheWhiteoutsLayer(t *testing.T) {
	t.Parallel()
	f := newOCIFixture(t)
	img := f.image([][]tarEntry{
		{{name: "usr/local/bin/dagu", body: "old build"}},
		{{name: "usr/local/bin/dagu", body: "new build"}, {name: "usr/local/.wh..wh..opq"}, {name: "usr/local/.wh.bin"}},
	}, nil)
	rec, err := extractImageBinary(f.spec(img))
	require.NoError(t, err)
	assert.Equal(t, sha256Hex([]byte("new build")), rec.BinarySHA256)
	assert.Equal(t, img.layers[1], rec.Image.Layer)
}

// Each broken link stops the extraction, and nothing is left as a build.
func TestExtractStopsOnAnyMismatch(t *testing.T) {
	t.Parallel()
	binary := []tarEntry{{name: "usr/local/bin/dagu", body: "build"}}
	cases := map[string]struct {
		layers [][]tarEntry
		edit   func(kind string, doc map[string]any)
		spec   func(f *ociFixture, img fixtureImage, s *extractSpec)
		want   string
	}{
		"the index is not the expected one": {spec: func(_ *ociFixture, _ fixtureImage, s *extractSpec) {
			s.Index = "sha256:" + strings.Repeat("0", 64)
		}, want: "index: blob sha256:0000"},
		"the platform manifest is not the published one": {spec: func(_ *ociFixture, _ fixtureImage, s *extractSpec) {
			s.Manifest = "sha256:" + strings.Repeat("1", 64)
		}, want: "the spec expects sha256:1111"},
		"a tampered manifest blob": {spec: func(f *ociFixture, img fixtureImage, _ *extractSpec) {
			require.NoError(t, os.WriteFile(filepath.Join(f.layout, "blobs", "sha256", strings.TrimPrefix(img.manifest, "sha256:")), []byte(`{"tampered":true}`), 0o600))
		}, want: "manifest: blob"},
		"a tampered layer blob": {spec: func(f *ociFixture, img fixtureImage, _ *extractSpec) {
			p := filepath.Join(f.layout, "blobs", "sha256", strings.TrimPrefix(img.layers[0], "sha256:"))
			raw, err := os.ReadFile(p)
			require.NoError(t, err)
			var gz bytes.Buffer
			zw := gzip.NewWriter(&gz)
			_, _ = zw.Write([]byte("not the layer"))
			_ = zw.Close()
			require.NotEqual(t, raw, gz.Bytes())
			require.NoError(t, os.WriteFile(p, gz.Bytes(), 0o600))
		}, want: "layer 0"},
		"a diff id the layer does not hash to": {edit: func(kind string, doc map[string]any) {
			if kind == "config" {
				doc["rootfs"].(map[string]any)["diff_ids"] = []any{"sha256:" + strings.Repeat("2", 64)}
			}
		}, want: "the config's diff id is sha256:2222"},
		"a config for another platform": {edit: func(kind string, doc map[string]any) {
			if kind == "config" {
				doc["architecture"] = "arm64"
			}
		}, want: "is for linux/arm64, not linux/amd64"},
		"two manifests for the platform": {edit: func(kind string, doc map[string]any) {
			if kind == "index" {
				m := doc["manifests"].([]any)
				doc["manifests"] = append(m, m[0])
			}
		}, want: "names linux/amd64 twice"},
		"no manifest for the platform": {spec: func(_ *ociFixture, _ fixtureImage, s *extractSpec) {
			s.Platform, s.Manifest = "linux/riscv64", ""
		}, want: "names no linux/riscv64 manifest"},
		"a layer media type this extraction does not read": {edit: func(kind string, doc map[string]any) {
			if kind == "manifest" {
				doc["layers"].([]any)[0].(map[string]any)["mediaType"] = "application/vnd.oci.image.layer.v1.tar+zstd"
			}
		}, want: "is not a layer this extraction reads"},
		"the binary removed by a whiteout": {layers: [][]tarEntry{binary, {{name: "usr/local/bin/.wh.dagu"}}},
			want: "no regular file at /usr/local/bin/dagu"},
		"the binary's directory made opaque": {layers: [][]tarEntry{binary, {{name: "usr/local/.wh..wh..opq"}}},
			want: "no regular file at /usr/local/bin/dagu"},
		"the binary's directory removed by a whiteout": {layers: [][]tarEntry{binary, {{name: "usr/local/.wh.bin"}}},
			want: "no regular file at /usr/local/bin/dagu"},
		"a directory further up removed by a whiteout": {layers: [][]tarEntry{binary, {{name: ".wh.usr"}}},
			want: "no regular file at /usr/local/bin/dagu"},
		"a directory above the binary that is a link": {layers: [][]tarEntry{binary, {{name: "usr/local/bin", typeflag: tar.TypeSymlink}}},
			want: "/usr/local/bin, above /usr/local/bin/dagu, is not a directory"},
		"a whiteout of a sibling leaves the binary": {layers: [][]tarEntry{binary, {{name: "usr/local/bin/.wh.dagu-old"}, {name: "usr/local/.wh.binaries"}}},
			want: ""},
		"the binary is a link": {layers: [][]tarEntry{{{name: "usr/local/bin/dagu", typeflag: tar.TypeSymlink}}},
			want: "is not a regular file"},
		"no binary at all": {layers: [][]tarEntry{{{name: "usr/bin/other", body: "x"}}},
			want: "no regular file at /usr/local/bin/dagu"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newOCIFixture(t)
			layers := tc.layers
			if layers == nil {
				layers = [][]tarEntry{binary}
			}
			img := f.image(layers, tc.edit)
			spec := f.spec(img)
			if tc.spec != nil {
				tc.spec(f, img, &spec)
			}
			_, err := extractImageBinary(spec)
			if tc.want == "" {
				require.NoError(t, err, "a whiteout of another path must not remove the binary")
				return
			}
			require.Error(t, err, "the extraction went through")
			assert.Contains(t, err.Error(), tc.want)
			_, statErr := os.Stat(filepath.Join(spec.OutDir, "dagu"))
			assert.True(t, errors.Is(statErr, os.ErrNotExist), "a stopped extraction leaves no binary")
			_, statErr = os.Stat(filepath.Join(spec.OutDir, "provenance.json"))
			assert.True(t, errors.Is(statErr, os.ErrNotExist), "a stopped extraction leaves no record")
		})
	}
}

// fixtureRepo makes a git repository shaped like dagu's for the controlled
// build: module "fixture" with its main package in cmd/, a tag, and an
// ignored .local/ directory. In .local/evil it puts a module of its own,
// named like the main module, that is not part of any commit: the shape
// the borrowed-stamp attack takes. It returns the repository and the tag's
// commit.
func fixtureRepo(t *testing.T) (string, string) {
	t.Helper()
	for _, tool := range []string{"git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s on PATH to make the fixture", tool)
		}
	}
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	git := func(args ...string) string {
		out, err := runIn(dir, gitEnv(), time.Minute, "git", append([]string{"-c", "user.name=fixture", "-c", "user.email=fixture@rig.test", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		require.NoError(t, err)
		return out
	}
	write("go.mod", "module fixture\n\ngo 1.22\n")
	write("cmd/main.go", "package main\n\nvar version = \"dev\"\n\nfunc main() { println(version) }\n")
	write(".gitignore", ".local/\n")
	git("init", "-q")
	git("add", "-A")
	git("commit", "-q", "-m", "fixture")
	git("tag", "txe-v2.18.2-18")
	// Not committed, ignored: a module named like the main one.
	write(".local/evil/go.mod", "module fixture\n\ngo 1.22\n")
	write(".local/evil/cmd/main.go", "package main\n\nvar version = \"dev\"\n\nfunc main() { println(\"not the tag's code\", version) }\n")
	return dir, git("rev-parse", "HEAD")
}

func fixtureSpec(t *testing.T, repo, commit string) sourceSpec {
	return sourceSpec{Name: "w18", Repo: repo, Tag: "txe-v2.18.2-18", Commit: commit, Module: "fixture", Package: "./cmd",
		Version: "2.18.2-txe.18", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Parallel: 2, OutDir: filepath.Join(t.TempDir(), "w18")}
}

func TestSourceBuildFromAVerifiedClone(t *testing.T) {
	t.Parallel()
	repo, commit := fixtureRepo(t)
	spec := fixtureSpec(t, repo, commit)
	spec.Installed = &installedRecord{Tag: "txe-v2.18.2-18", Commit: commit, Version: "2.18.2-txe.18", ReadFrom: "the Mac worker kit's dagu-2.18.2-txe.18.json"}
	rec, err := buildFromSource(spec)
	require.NoError(t, err)
	src := rec.Source
	assert.Equal(t, controlledBuilder, src.Builder)
	assert.Equal(t, commit, src.Commit)
	assert.Equal(t, commit, src.Revision)
	assert.Equal(t, "false", src.Modified)
	assert.Equal(t, "fixture", src.Module)
	assert.Equal(t, "fixture/cmd", src.Package)
	assert.Equal(t, "0", src.CGO)
	assert.Contains(t, src.Env, "GOENV=off", "the caller's go env file does not reach the build")
	assert.Contains(t, src.Env, "GOFLAGS=", "the caller's GOFLAGS do not reach the build")
	assert.Equal(t, []string{"go", "build", "-p", "2", "-mod=readonly", "-buildvcs=true", "-ldflags", "-X 'main.version=2.18.2-txe.18'", "-o"}, src.Command[:9])
	assert.Contains(t, src.Env, "GOMAXPROCS=2", "the go command and its compilers are bounded")
	assert.NotEmpty(t, src.Tree)
	assert.Contains(t, rec.Scope, "NOT the installed binary of any machine")
	assert.Contains(t, rec.Scope, "corroborates the tag, commit and version only, not the bytes")
	bin, err := os.ReadFile(filepath.Join(spec.OutDir, "dagu"))
	require.NoError(t, err)
	assert.Equal(t, sha256Hex(bin), rec.BinarySHA256)
	raw, err := os.ReadFile(filepath.Join(spec.OutDir, "provenance.json"))
	require.NoError(t, err)
	_, err = readProvenance(&provenanceRef{Record: filepath.Join(spec.OutDir, "provenance.json"), SHA256: sha256Hex(raw)}, rec.BinarySHA256)
	require.NoError(t, err)
	// Never overwritten.
	_, err = buildFromSource(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "never overwrites")
}

// The attack the record must not accept: a module built in an ignored
// directory of the tag's checkout carries the checkout's revision and
// vcs.modified=false. Its stamp is the tag's, so a check of the stamp alone
// would take it; the controlled build never sees it (the clone has no
// ignored files), and a binary cannot be handed to the command.
func TestSourceBuildRefusesABorrowedStamp(t *testing.T) {
	t.Parallel()
	repo, commit := fixtureRepo(t)
	// The threat is real: built in place, the ignored module wears the stamp.
	borrowed := filepath.Join(t.TempDir(), "borrowed")
	_, err := runIn(filepath.Join(repo, ".local", "evil"), append(callerEnv(), "GOFLAGS=", "GOWORK=off", "GOENV=off", "CGO_ENABLED=0", "HOME="+t.TempDir()),
		5*time.Minute, "go", "build", "-buildvcs=true", "-o", borrowed, "./cmd")
	require.NoError(t, err)
	info, err := buildinfo.ReadFile(borrowed)
	require.NoError(t, err)
	stamp := map[string]string{}
	for _, st := range info.Settings {
		stamp[st.Key] = st.Value
	}
	require.Equal(t, commit, stamp["vcs.revision"], "the ignored module borrows the tag's revision")
	require.Equal(t, "false", stamp["vcs.modified"], "and reads as unmodified")
	require.Equal(t, "fixture", info.Main.Path, "under the main module's own name")

	// Asked to build it, the command finds no such package in its clone.
	spec := fixtureSpec(t, repo, commit)
	spec.Package = "./.local/evil/cmd"
	_, err = buildFromSource(spec)
	require.Error(t, err, "the controlled build built the ignored module")
	assert.Contains(t, err.Error(), "source record: build")
	_, statErr := os.Stat(filepath.Join(spec.OutDir, "provenance.json"))
	assert.True(t, errors.Is(statErr, os.ErrNotExist), "no record")

	// And it cannot be handed the borrowed binary: the spec has no such field.
	var s sourceSpec
	err = strictUnmarshal([]byte(`{"name":"w18","repo":"`+filepath.ToSlash(repo)+`","binary":"`+filepath.ToSlash(borrowed)+`"}`), &s)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown field "binary"`)
}

func TestSourceBuildRefusesWhatItCannotVerify(t *testing.T) {
	t.Parallel()
	repo, commit := fixtureRepo(t)
	for name, tc := range map[string]struct {
		mutate func(s *sourceSpec)
		want   string
	}{
		"a tag that names another commit": {func(s *sourceSpec) { s.Commit = strings.Repeat("f", 40) }, "tag txe-v2.18.2-18 is commit " + commit},
		"an unknown tag":                  {func(s *sourceSpec) { s.Tag = "txe-v9" }, "source record: clone"},
		"another main module":             {func(s *sourceSpec) { s.Module = "github.com/dagucloud/dagu/v2" }, "the binary is package fixture/cmd of module fixture"},
		"a package outside the clone":     {func(s *sourceSpec) { s.Package = "../elsewhere" }, "must be a path inside the clone"},
		"an installed record of another commit": {func(s *sourceSpec) {
			s.Installed = &installedRecord{Tag: "txe-v2.18.2-18", Commit: strings.Repeat("e", 40), Version: "2.18.2-txe.18"}
		}, "the installed record names"},
		"a short commit":       {func(s *sourceSpec) { s.Commit = commit[:8] }, "is not a full commit id"},
		"a relative directory": {func(s *sourceSpec) { s.OutDir = "w18" }, "out_dir must be absolute"},
		"an unbounded build":   {func(s *sourceSpec) { s.Parallel = 0 }, "parallel 0 must be between 1 and 64"},
	} {
		spec := fixtureSpec(t, repo, commit)
		tc.mutate(&spec)
		_, err := buildFromSource(spec)
		if assert.Error(t, err, name) {
			assert.Contains(t, err.Error(), tc.want, name)
		}
		if filepath.IsAbs(spec.OutDir) {
			_, statErr := os.Stat(filepath.Join(spec.OutDir, "provenance.json"))
			assert.True(t, errors.Is(statErr, os.ErrNotExist), "%s: a refused build writes no record", name)
		}
	}
}

// The clone check sees untracked and ignored files, not only modified ones.
func TestCleanTreeSeesIgnoredFiles(t *testing.T) {
	t.Parallel()
	repo, _ := fixtureRepo(t)
	err := cleanTree(repo) // the source repository holds the ignored .local/evil
	require.Error(t, err)
	assert.Contains(t, err.Error(), "!! .local/")
	clone := filepath.Join(t.TempDir(), "c")
	_, err = runIn(t.TempDir(), gitEnv(), time.Minute, "git", "clone", "--quiet", "--", repo, clone)
	require.NoError(t, err)
	require.NoError(t, cleanTree(clone), "a fresh clone is its commit alone")
	require.NoError(t, os.WriteFile(filepath.Join(clone, "untracked.go"), []byte("package main\n"), 0o600))
	require.Error(t, cleanTree(clone))
}

// checkBuildInfo on binaries built in place: the checks it makes hold, and a
// borrowed stamp passes them all, which is why only the controlled build
// writes records.
func TestCheckBuildInfo(t *testing.T) {
	t.Parallel()
	repo, commit := fixtureRepo(t)
	build := func(dir string, args ...string) *debug.BuildInfo {
		t.Helper()
		out := filepath.Join(t.TempDir(), "bin")
		_, err := runIn(dir, append(callerEnv(), "GOFLAGS=", "GOWORK=off", "GOENV=off", "CGO_ENABLED=0", "HOME="+t.TempDir()), 5*time.Minute,
			"go", append(append([]string{"build"}, args...), "-ldflags", "-X 'main.version=2.18.2-txe.18'", "-o", out, "./cmd")...)
		require.NoError(t, err)
		info, err := buildinfo.ReadFile(out)
		require.NoError(t, err)
		return info
	}
	spec := fixtureSpec(t, repo, commit)
	clean := build(repo, "-buildvcs=true")
	borrowed := build(filepath.Join(repo, ".local", "evil"), "-buildvcs=true")
	unstamped := build(repo, "-buildvcs=false")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "cmd", "main.go"), []byte("package main\n\nvar version = \"dev\"\n\nfunc main() { println(version, 2) }\n"), 0o600))
	modified := build(repo, "-buildvcs=true")

	_, err := checkBuildInfo(clean, spec, "cmd")
	require.NoError(t, err)
	_, err = checkBuildInfo(borrowed, spec, "cmd")
	require.NoError(t, err, "the borrowed binary passes every check of the binary alone; the controlled build is what refuses it")

	other := func(f func(s *sourceSpec)) sourceSpec {
		s := spec
		f(&s)
		return s
	}
	for name, tc := range map[string]struct {
		info *debug.BuildInfo
		spec sourceSpec
		want string
	}{
		"no stamp":         {unstamped, spec, `own stamp (vcs="" revision="" modified="")`},
		"a modified tree":  {modified, spec, `modified="true"`},
		"another commit":   {clean, other(func(s *sourceSpec) { s.Commit = strings.Repeat("f", 40) }), "does not name the clean clone of ffff"},
		"another platform": {clean, other(func(s *sourceSpec) { s.GOOS = "plan9" }), "the binary was built for"},
		"another version":  {clean, other(func(s *sourceSpec) { s.Version = "2.18.2-txe.19" }), "do not set main.version=2.18.2-txe.19"},
		"another package":  {clean, spec, "the spec names fixture/other of fixture"},
	} {
		pkg := "cmd"
		if name == "another package" {
			pkg = "other"
		}
		_, err := checkBuildInfo(tc.info, tc.spec, pkg)
		if assert.Error(t, err, name) {
			assert.Contains(t, err.Error(), tc.want, name)
		}
	}
}

// h1 is the go.sum hash of a set of files (dirhash.Hash1): the sha256 of the
// sorted "sha256  name" lines, base64.
func h1(files map[string]string) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	var summary strings.Builder
	for _, n := range names {
		sum := sha256.Sum256([]byte(files[n]))
		fmt.Fprintf(&summary, "%x  %s\n", sum, n)
	}
	sum := sha256.Sum256([]byte(summary.String()))
	return "h1:" + base64.StdEncoding.EncodeToString(sum[:])
}

// depFixture makes a module proxy on disk serving example.com/dep v1.0.0, a
// tagged repository whose main package imports it (go.sum included), and the
// environment that points a build at that proxy and at a module cache of the
// test's own.
type depRig struct {
	repo, commit, cache string
	env                 []string
}

func depFixture(t *testing.T) depRig {
	t.Helper()
	repo, _ := fixtureRepo(t)
	proxy, cache := t.TempDir(), t.TempDir()
	const mod, ver = "example.com/dep", "v1.0.0"
	depMod := "module " + mod + "\n\ngo 1.22\n"
	depSrc := "package dep\n\nfunc Name() string { return \"dep\" }\n"
	dir := filepath.Join(proxy, "example.com", "dep", "@v")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for name, body := range map[string]string{"go.mod": depMod, "dep.go": depSrc} {
		w, err := zw.Create(mod + "@" + ver + "/" + name)
		require.NoError(t, err)
		_, err = w.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	for name, body := range map[string][]byte{
		"list":        []byte(ver + "\n"),
		ver + ".info": []byte(`{"Version":"` + ver + `","Time":"2026-01-01T00:00:00Z"}`),
		ver + ".mod":  []byte(depMod),
		ver + ".zip":  zbuf.Bytes(),
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), body, 0o600))
	}
	zipSum := h1(map[string]string{mod + "@" + ver + "/go.mod": depMod, mod + "@" + ver + "/dep.go": depSrc})
	modSum := h1(map[string]string{"go.mod": depMod})
	write := func(rel, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(repo, filepath.FromSlash(rel)), []byte(body), 0o600))
	}
	write("go.mod", "module fixture\n\ngo 1.22\n\nrequire "+mod+" "+ver+"\n")
	write("go.sum", mod+" "+ver+" "+zipSum+"\n"+mod+" "+ver+"/go.mod "+modSum+"\n")
	write("cmd/main.go", "package main\n\nimport \""+mod+"\"\n\nvar version = \"dev\"\n\nfunc main() { println(dep.Name(), version) }\n")
	git := func(args ...string) string {
		out, err := runIn(repo, gitEnv(), time.Minute, "git", append([]string{"-c", "user.name=fixture", "-c", "user.email=fixture@rig.test", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		require.NoError(t, err)
		return out
	}
	git("add", "-A")
	git("commit", "-q", "-m", "depend on example.com/dep")
	git("tag", "-f", "txe-v2.18.2-18")
	commit := git("rev-parse", "HEAD")
	proxyURL := "file://" + filepath.ToSlash(proxy)
	if !strings.HasPrefix(filepath.ToSlash(proxy), "/") {
		proxyURL = "file:///" + filepath.ToSlash(proxy)
	}
	var env []string
	for _, kv := range callerEnv() {
		switch strings.SplitN(kv, "=", 2)[0] {
		case "GOMODCACHE", "GOPROXY", "GOSUMDB", "GONOSUMDB", "GONOSUMCHECK", "GOPRIVATE":
		default:
			env = append(env, kv)
		}
	}
	env = append(env, "GOPROXY="+proxyURL, "GOSUMDB=off", "GOMODCACHE="+cache)
	// The module cache's files are read-only; clear it before TempDir removes it.
	t.Cleanup(func() {
		_, _ = runIn(repo, append(slices.Clone(env), "GOENV=off", "GOFLAGS="), time.Minute, "go", "clean", "-modcache")
	})
	return depRig{repo: repo, commit: commit, cache: cache, env: env}
}

// A dependency changed in the shared module cache after it was downloaded is
// refused: -mod=readonly would build it, go mod verify does not pass it.
func TestSourceBuildRefusesATamperedModuleCache(t *testing.T) {
	t.Parallel()
	d := depFixture(t)
	spec := fixtureSpec(t, d.repo, d.commit)
	rec, err := buildFromSourceIn(spec, d.env)
	require.NoError(t, err)
	assert.Equal(t, modulesVerified+" (before and after the build)", rec.Source.ModVerify)
	assert.Contains(t, rec.Source.Env, "GOCACHE=<a fresh private cache of this build>")
	assert.NotContains(t, rec.Source.PassThrough, "GOCACHE", "the build cache is never shared")

	src := filepath.Join(d.cache, "example.com", "dep@v1.0.0", "dep.go")
	require.NoError(t, os.Chmod(src, 0o600))
	require.NoError(t, os.WriteFile(src, []byte("package dep\n\nfunc Name() string { return \"tampered\" }\n"), 0o600))
	spec2 := fixtureSpec(t, d.repo, d.commit)
	_, err = buildFromSourceIn(spec2, d.env)
	require.Error(t, err, "a tampered cached module was built and recorded")
	assert.Contains(t, err.Error(), "before the build: go mod verify")
	_, statErr := os.Stat(filepath.Join(spec2.OutDir, "provenance.json"))
	assert.True(t, errors.Is(statErr, os.ErrNotExist), "no record")
}
