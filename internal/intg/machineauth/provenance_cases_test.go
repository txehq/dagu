// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package machineauth_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ociFixture builds an OCI image layout on disk, link by link, so each test
// can break exactly one link of the chain.
type ociFixture struct {
	t      *testing.T
	layout string
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
			require.Error(t, err, "the extraction went through")
			assert.Contains(t, err.Error(), tc.want)
			_, statErr := os.Stat(filepath.Join(spec.OutDir, "dagu"))
			assert.True(t, errors.Is(statErr, os.ErrNotExist), "a stopped extraction leaves no binary")
			_, statErr = os.Stat(filepath.Join(spec.OutDir, "provenance.json"))
			assert.True(t, errors.Is(statErr, os.ErrNotExist), "a stopped extraction leaves no record")
		})
	}
}

// buildVersioned builds a tiny program with -X main.version, as the worker
// kit builds dagu, for the source record's tests.
func buildVersioned(t *testing.T, version string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH to build the fixture binary")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixture\n\ngo 1.22\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nvar version = \"dev\"\n\nfunc main() { println(version) }\n"), 0o600))
	out := filepath.Join(dir, "fixture")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command(goBin, "build", "-buildvcs=false", "-ldflags", "-X main.version="+version, "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-mod=mod", "GOWORK=off")
	raw, err := cmd.CombinedOutput()
	require.NoError(t, err, "build the fixture: %s", raw)
	return out
}

func TestSourceRecordHoldsTheBuildToItsTag(t *testing.T) {
	t.Parallel()
	bin := buildVersioned(t, "2.18.2-txe.18")
	commit := narrowedScopes[0].Commit
	tags := func(_, tag string) (string, error) {
		if tag == "txe-v2.18.2-18" {
			return commit, nil
		}
		return "", errors.New("no such tag")
	}
	spec := func() sourceSpec {
		return sourceSpec{Name: "w18", Repo: "/repo", Tag: "txe-v2.18.2-18", Commit: commit, Binary: bin, Version: "2.18.2-txe.18",
			GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Out: filepath.Join(t.TempDir(), "provenance.json")}
	}
	s := spec()
	s.Installed = &installedRecord{Tag: "txe-v2.18.2-18", Commit: commit, Version: "2.18.2-txe.18", ReadFrom: "the Mac worker kit's dagu-2.18.2-txe.18.json"}
	rec, err := recordSourceBuild(s, tags)
	require.NoError(t, err)
	assert.Equal(t, "source", rec.Kind)
	assert.Contains(t, rec.Scope, "NOT the installed binary of any machine")
	assert.Contains(t, rec.Scope, "corroborates the tag, commit and version only, not the bytes")
	raw, err := os.ReadFile(s.Out)
	require.NoError(t, err)
	_, err = readProvenance(&provenanceRef{Record: s.Out, SHA256: sha256Hex(raw)}, rec.BinarySHA256)
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		mutate func(s *sourceSpec)
		want   string
	}{
		"a tag that names another commit": {func(s *sourceSpec) { s.Commit = strings.Repeat("f", 40) }, "tag txe-v2.18.2-18 is commit 5b011eba"},
		"an unknown tag":                  {func(s *sourceSpec) { s.Tag = "txe-v9" }, "no such tag"},
		"another platform":                {func(s *sourceSpec) { s.GOOS = "plan9" }, "the spec names plan9/"},
		"another version":                 {func(s *sourceSpec) { s.Version = "2.18.2-txe.19" }, "do not set main.version=2.18.2-txe.19"},
		"an installed record of another commit": {func(s *sourceSpec) {
			s.Installed = &installedRecord{Tag: "txe-v2.18.2-18", Commit: strings.Repeat("e", 40), Version: "2.18.2-txe.18"}
		}, "the installed record names"},
		"a short commit": {func(s *sourceSpec) { s.Commit = "5b011eba" }, "is not a full commit id"},
	} {
		s := spec()
		tc.mutate(&s)
		_, err := recordSourceBuild(s, tags)
		if assert.Error(t, err, name) {
			assert.Contains(t, err.Error(), tc.want, name)
		}
		_, statErr := os.Stat(s.Out)
		assert.True(t, errors.Is(statErr, os.ErrNotExist), "%s: a refused record is not written", name)
	}
}
