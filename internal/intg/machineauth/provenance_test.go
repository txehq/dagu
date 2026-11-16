// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package machineauth_test

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A build's provenance record says where its binary came from, and the
// manifest binds the record by digest. Two kinds:
//
//   - image: the binary was read out of a published image, through a chain the
//     extraction checked link by link (index → the platform's manifest → config
//     and layers → the file), from an OCI layout on disk. Any link that does not
//     hash to the digest that names it stops the extraction.
//   - source: the binary was built from a tag's commit. The record holds what
//     the binary's own build information says and what git says the tag is; it
//     is a build of that commit, never the installed binary of another machine.
//
// Both are written by opt-in commands of this package (README.md), never by hand.

const provenanceSchema = 1

type provenanceRecord struct {
	Schema       int               `json:"schema"`
	Kind         string            `json:"kind"` // image or source
	Name         string            `json:"name"`
	BinarySHA256 string            `json:"binary_sha256"`
	BinarySize   int64             `json:"binary_size"`
	Image        *imageProvenance  `json:"image,omitempty"`
	Source       *sourceProvenance `json:"source,omitempty"`
	// Scope says what the record does and does not stand for.
	Scope string `json:"scope"`
}

type imageProvenance struct {
	Ref      string        `json:"ref,omitempty"` // the reference it was pulled by, for the reader
	Index    string        `json:"index"`
	Platform string        `json:"platform"`
	Manifest string        `json:"manifest"`
	Config   string        `json:"config"`
	Layers   []layerRecord `json:"layers"`
	Path     string        `json:"path"`
	// Layer is the digest of the layer the binary's final content came from.
	Layer string `json:"layer"`
}

type layerRecord struct {
	Digest    string `json:"digest"`
	MediaType string `json:"media_type"`
	DiffID    string `json:"diff_id"`
}

type sourceProvenance struct {
	Tag       string `json:"tag"`
	Commit    string `json:"commit"`
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	CGO       string `json:"cgo_enabled"`
	LDFlags   string `json:"ldflags"`
	// Installed is another machine's own record of the binary it runs (the
	// worker kit's dagu-<version>.json), when one was read: it corroborates the
	// tag, commit and version only, never the bytes.
	Installed *installedRecord `json:"installed,omitempty"`
}

type installedRecord struct {
	Tag      string `json:"tag"`
	Commit   string `json:"commit"`
	Version  string `json:"version"`
	ReadFrom string `json:"read_from"`
}

// provenanceRef is how a manifest binds a record: its path and digest.
type provenanceRef struct {
	Record string `json:"record"`
	SHA256 string `json:"sha256"`
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// readProvenance reads a bound record and holds it to its digest and to the
// build: the record's binary is the build's binary.
func readProvenance(ref *provenanceRef, buildSHA string) (*provenanceRecord, error) {
	raw, err := os.ReadFile(ref.Record)
	if err != nil {
		return nil, fmt.Errorf("provenance record: %w", err)
	}
	if got := sha256Hex(raw); got != ref.SHA256 {
		return nil, fmt.Errorf("provenance record %s is sha256 %s, the manifest binds %s", ref.Record, got, ref.SHA256)
	}
	var rec provenanceRecord
	if err := strictUnmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("provenance record %s: %w", ref.Record, err)
	}
	switch {
	case rec.Schema != provenanceSchema:
		return nil, fmt.Errorf("provenance record %s: schema %d, this harness reads %d", ref.Record, rec.Schema, provenanceSchema)
	case rec.BinarySHA256 != buildSHA:
		return nil, fmt.Errorf("provenance record %s is for binary sha256 %s, the build is %s", ref.Record, rec.BinarySHA256, buildSHA)
	case rec.Kind == "image" && (rec.Image == nil || rec.Source != nil):
		return nil, fmt.Errorf("provenance record %s: an image record needs its image chain and nothing else", ref.Record)
	case rec.Kind == "source" && (rec.Source == nil || rec.Image != nil):
		return nil, fmt.Errorf("provenance record %s: a source record needs its source and nothing else", ref.Record)
	case rec.Kind != "image" && rec.Kind != "source":
		return nil, fmt.Errorf("provenance record %s: kind %q, not image or source", ref.Record, rec.Kind)
	}
	return &rec, nil
}

// ── image extraction ─────────────────────────────────────────────────────────

// extractSpec is DAGU_MACHINEAUTH_EXTRACT's file.
type extractSpec struct {
	Name string `json:"name"`
	// Layout is an OCI image layout directory (crane pull --format=oci of the
	// index by digest); only its content-addressed blobs are read.
	Layout   string `json:"layout"`
	Ref      string `json:"ref,omitempty"`
	Index    string `json:"index"`
	Platform string `json:"platform"` // os/arch
	// Manifest is the platform manifest's digest the index must name, when it
	// is known in advance (from the image's publication record).
	Manifest string `json:"manifest,omitempty"`
	Path     string `json:"path"`    // the binary's path in the image
	OutDir   string `json:"out_dir"` // gets dagu and provenance.json; must not hold them yet
}

const (
	mtOCIIndex      = "application/vnd.oci.image.index.v1+json"
	mtDockerList    = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtOCIManifest   = "application/vnd.oci.image.manifest.v1+json"
	mtDockerV2      = "application/vnd.docker.distribution.manifest.v2+json"
	mtOCIConfig     = "application/vnd.oci.image.config.v1+json"
	mtDockerConfig  = "application/vnd.docker.container.image.v1+json"
	mtOCILayerGzip  = "application/vnd.oci.image.layer.v1.tar+gzip"
	mtOCILayerTar   = "application/vnd.oci.image.layer.v1.tar"
	mtDockerLayerGz = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant,omitempty"`
	} `json:"platform,omitempty"`
}

type ociIndex struct {
	MediaType string          `json:"mediaType"`
	Manifests []ociDescriptor `json:"manifests"`
}

type ociManifest struct {
	MediaType string          `json:"mediaType"`
	Config    ociDescriptor   `json:"config"`
	Layers    []ociDescriptor `json:"layers"`
}

type ociConfig struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	RootFS       struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// blob opens a content-addressed blob of the layout after checking its name.
func blobPath(layout, digest string) (string, error) {
	if !digestRE.MatchString(digest) {
		return "", fmt.Errorf("digest %q is not sha256:<64 hex>", digest)
	}
	return filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")), nil
}

// readBlob reads a small blob (an index, a manifest, a config) and holds it to
// its digest and, when given, its size.
func readBlob(layout string, d ociDescriptor) ([]byte, error) {
	p, err := blobPath(layout, d.Digest)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", d.Digest, err)
	}
	if got := "sha256:" + sha256Hex(raw); got != d.Digest {
		return nil, fmt.Errorf("blob %s hashes to %s", d.Digest, got)
	}
	if d.Size != 0 && int64(len(raw)) != d.Size {
		return nil, fmt.Errorf("blob %s is %d bytes, its descriptor says %d", d.Digest, len(raw), d.Size)
	}
	return raw, nil
}

// extractImageBinary follows the chain from the index to the binary and stops
// at the first link that does not hold. It writes the binary and its record
// into the spec's directory and returns the record.
func extractImageBinary(spec extractSpec) (*provenanceRecord, error) {
	switch {
	case spec.Name == "" || spec.Layout == "" || spec.Index == "" || spec.Platform == "" || spec.Path == "" || spec.OutDir == "":
		return nil, errors.New("extract: name, layout, index, platform, path and out_dir are all required")
	case !filepath.IsAbs(spec.Layout) || !filepath.IsAbs(spec.OutDir):
		return nil, errors.New("extract: layout and out_dir must be absolute")
	case spec.Manifest != "" && !digestRE.MatchString(spec.Manifest):
		return nil, fmt.Errorf("extract: manifest %q is not sha256:<64 hex>", spec.Manifest)
	}
	osArch := strings.Split(spec.Platform, "/")
	if len(osArch) != 2 {
		return nil, fmt.Errorf("extract: platform %q is not os/arch", spec.Platform)
	}
	outBin, outRec := filepath.Join(spec.OutDir, "dagu"), filepath.Join(spec.OutDir, "provenance.json")
	for _, p := range []string{outBin, outRec} {
		if _, err := os.Lstat(p); err == nil {
			return nil, fmt.Errorf("extract: %s exists; an extraction never overwrites", p)
		}
	}
	// The index.
	rawIndex, err := readBlob(spec.Layout, ociDescriptor{Digest: spec.Index})
	if err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	var index ociIndex
	if err := json.Unmarshal(rawIndex, &index); err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	if index.MediaType != mtOCIIndex && index.MediaType != mtDockerList {
		return nil, fmt.Errorf("index %s has media type %q, not an image index", spec.Index, index.MediaType)
	}
	var child *ociDescriptor
	for i := range index.Manifests {
		d := &index.Manifests[i]
		if d.Platform == nil || d.Platform.OS != osArch[0] || d.Platform.Architecture != osArch[1] {
			continue
		}
		if child != nil {
			return nil, fmt.Errorf("index %s names %s twice (%s and %s)", spec.Index, spec.Platform, child.Digest, d.Digest)
		}
		child = d
	}
	if child == nil {
		return nil, fmt.Errorf("index %s names no %s manifest", spec.Index, spec.Platform)
	}
	if spec.Manifest != "" && child.Digest != spec.Manifest {
		return nil, fmt.Errorf("index %s names %s manifest %s, the spec expects %s", spec.Index, spec.Platform, child.Digest, spec.Manifest)
	}
	// The platform's manifest.
	rawManifest, err := readBlob(spec.Layout, *child)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	var man ociManifest
	if err := json.Unmarshal(rawManifest, &man); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if man.MediaType != mtOCIManifest && man.MediaType != mtDockerV2 {
		return nil, fmt.Errorf("manifest %s has media type %q, not an image manifest", child.Digest, man.MediaType)
	}
	// Its config: the platform again, and the uncompressed digest of every layer.
	if man.Config.MediaType != mtOCIConfig && man.Config.MediaType != mtDockerConfig {
		return nil, fmt.Errorf("config %s has media type %q", man.Config.Digest, man.Config.MediaType)
	}
	rawConfig, err := readBlob(spec.Layout, man.Config)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var cfg ociConfig
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if cfg.OS != osArch[0] || cfg.Architecture != osArch[1] {
		return nil, fmt.Errorf("config %s is for %s/%s, not %s", man.Config.Digest, cfg.OS, cfg.Architecture, spec.Platform)
	}
	if len(cfg.RootFS.DiffIDs) != len(man.Layers) || len(man.Layers) == 0 {
		return nil, fmt.Errorf("config %s lists %d layer diff ids for %d layers", man.Config.Digest, len(cfg.RootFS.DiffIDs), len(man.Layers))
	}
	// The layers, in order: each compressed blob hashes to its digest, each
	// uncompressed stream to its diff id; the file's last state wins.
	target := strings.TrimPrefix(path.Clean("/"+spec.Path), "/")
	if err := os.MkdirAll(spec.OutDir, 0o700); err != nil {
		return nil, err
	}
	tmp := filepath.Join(spec.OutDir, ".dagu.extracting")
	_ = os.Remove(tmp)
	defer func() { _ = os.Remove(tmp) }()
	found, fromLayer := false, ""
	var layers []layerRecord
	for i, l := range man.Layers {
		present, deleted, err := scanLayer(spec.Layout, l, cfg.RootFS.DiffIDs[i], target, tmp)
		if err != nil {
			return nil, fmt.Errorf("layer %d (%s): %w", i, l.Digest, err)
		}
		layers = append(layers, layerRecord{Digest: l.Digest, MediaType: l.MediaType, DiffID: cfg.RootFS.DiffIDs[i]})
		switch {
		case present:
			found, fromLayer = true, l.Digest
		case deleted:
			found, fromLayer = false, ""
		}
	}
	if !found {
		return nil, fmt.Errorf("the image has no regular file at %s", spec.Path)
	}
	raw, err := os.ReadFile(tmp)
	if err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, outBin); err != nil {
		return nil, err
	}
	if err := os.Chmod(outBin, 0o755); err != nil { //nolint:gosec // the extracted binary is executed by the matrix
		return nil, err
	}
	rec := &provenanceRecord{Schema: provenanceSchema, Kind: "image", Name: spec.Name, BinarySHA256: sha256Hex(raw), BinarySize: int64(len(raw)),
		Image: &imageProvenance{Ref: spec.Ref, Index: spec.Index, Platform: spec.Platform, Manifest: child.Digest, Config: man.Config.Digest,
			Layers: layers, Path: "/" + target, Layer: fromLayer},
		Scope: fmt.Sprintf("the %s binary %s of image index %s, read through its manifest %s, config and layers, every link checked by digest", spec.Platform, "/"+target, spec.Index, child.Digest)}
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(outRec, append(out, '\n'), 0o600); err != nil {
		return nil, err
	}
	return rec, nil
}

// scanLayer reads one layer: it checks the blob against its digest and the
// uncompressed stream against its diff id, and reports whether the layer sets
// the target (a regular file, copied to tmp) or deletes it (a whiteout of the
// file or an opaque whiteout of a directory above it). A link at the target
// stops the extraction: the binary must be the file itself.
func scanLayer(layout string, l ociDescriptor, diffID, target, tmp string) (present, deleted bool, err error) {
	p, err := blobPath(layout, l.Digest)
	if err != nil {
		return false, false, err
	}
	f, err := os.Open(p)
	if err != nil {
		return false, false, err
	}
	defer func() { _ = f.Close() }()
	compressed := sha256.New()
	stream := io.TeeReader(f, compressed)
	switch l.MediaType {
	case mtOCILayerGzip, mtDockerLayerGz:
		gz, err := gzip.NewReader(stream)
		if err != nil {
			return false, false, err
		}
		defer func() { _ = gz.Close() }()
		stream = gz
	case mtOCILayerTar:
	default:
		return false, false, fmt.Errorf("media type %q is not a layer this extraction reads", l.MediaType)
	}
	uncompressed := sha256.New()
	tr := tar.NewReader(io.TeeReader(stream, uncompressed))
	dir, base := path.Split(target)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return false, false, err
		}
		name := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		entryDir, entryBase := path.Split(name)
		switch {
		case entryBase == ".wh..wh..opq" && strings.HasPrefix(dir, entryDir):
			deleted, present = true, false
		case entryBase == ".wh."+base && entryDir == dir:
			deleted, present = true, false
		case name == target:
			if h.Typeflag != tar.TypeReg {
				return false, false, fmt.Errorf("%s is not a regular file in this layer (type %q)", "/"+target, h.Typeflag)
			}
			out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return false, false, err
			}
			_, cerr := io.Copy(out, tr) //nolint:gosec // the size is the image's, and the blob is digest-checked
			if err := errors.Join(cerr, out.Close()); err != nil {
				return false, false, err
			}
			present, deleted = true, false
		}
	}
	// Drain what follows the tar's end, so both digests cover the whole blob.
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return false, false, err
	}
	if _, err := io.Copy(io.Discard, f); err != nil {
		return false, false, err
	}
	if got := "sha256:" + hex.EncodeToString(compressed.Sum(nil)); got != l.Digest {
		return false, false, fmt.Errorf("the blob hashes to %s", got)
	}
	if got := "sha256:" + hex.EncodeToString(uncompressed.Sum(nil)); got != diffID {
		return false, false, fmt.Errorf("the uncompressed layer hashes to %s, the config's diff id is %s", got, diffID)
	}
	return present, deleted, nil
}

// ── source record ────────────────────────────────────────────────────────────

// sourceSpec is DAGU_MACHINEAUTH_SOURCE_RECORD's file.
type sourceSpec struct {
	Name    string `json:"name"`
	Repo    string `json:"repo"` // a git checkout holding the tag
	Tag     string `json:"tag"`
	Commit  string `json:"commit"`
	Binary  string `json:"binary"`
	Version string `json:"version"`
	GOOS    string `json:"goos"`
	GOARCH  string `json:"goarch"`
	// Installed is another machine's own record of what it runs, when read.
	Installed *installedRecord `json:"installed,omitempty"`
	Out       string           `json:"out"` // the record's path; must not exist yet
}

// tagCommit asks git which commit a tag names.
func tagCommit(repo, tag string) (string, error) {
	out, err := exec.Command("git", "-C", repo, "rev-parse", "--verify", "--quiet", "refs/tags/"+tag+"^{commit}").Output()
	if err != nil {
		return "", fmt.Errorf("git: tag %s not found in %s: %w", tag, repo, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// recordSourceBuild holds a source build to its tag, its own build
// information and, when given, the installed record, and writes its record.
func recordSourceBuild(spec sourceSpec, commitOf func(repo, tag string) (string, error)) (*provenanceRecord, error) {
	switch {
	case spec.Name == "" || spec.Repo == "" || spec.Tag == "" || spec.Binary == "" || spec.Version == "" || spec.GOOS == "" || spec.GOARCH == "" || spec.Out == "":
		return nil, errors.New("source record: name, repo, tag, commit, binary, version, goos, goarch and out are all required")
	case len(spec.Commit) != 40:
		return nil, fmt.Errorf("source record: commit %q is not a full commit id", spec.Commit)
	}
	if _, err := os.Lstat(spec.Out); err == nil {
		return nil, fmt.Errorf("source record: %s exists; a record is never overwritten", spec.Out)
	}
	commit, err := commitOf(spec.Repo, spec.Tag)
	if err != nil {
		return nil, err
	}
	if commit != spec.Commit {
		return nil, fmt.Errorf("source record: tag %s is commit %s, the spec names %s", spec.Tag, commit, spec.Commit)
	}
	info, err := buildinfo.ReadFile(spec.Binary)
	if err != nil {
		return nil, fmt.Errorf("source record: the binary's build information: %w", err)
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	switch {
	case settings["GOOS"] != spec.GOOS || settings["GOARCH"] != spec.GOARCH:
		return nil, fmt.Errorf("source record: the binary was built for %s/%s, the spec names %s/%s", settings["GOOS"], settings["GOARCH"], spec.GOOS, spec.GOARCH)
	case !strings.Contains(settings["-ldflags"], "main.version="+spec.Version):
		return nil, fmt.Errorf("source record: the binary's -ldflags %q do not set main.version=%s", settings["-ldflags"], spec.Version)
	case settings["vcs.revision"] != "" && settings["vcs.revision"] != spec.Commit:
		return nil, fmt.Errorf("source record: the binary says it was built from %s, not %s", settings["vcs.revision"], spec.Commit)
	}
	if in := spec.Installed; in != nil {
		if in.Commit != spec.Commit || in.Tag != spec.Tag || in.Version != spec.Version {
			return nil, fmt.Errorf("source record: the installed record names tag %s commit %s version %s, not %s %s %s",
				in.Tag, in.Commit, in.Version, spec.Tag, spec.Commit, spec.Version)
		}
	}
	raw, err := os.ReadFile(spec.Binary)
	if err != nil {
		return nil, err
	}
	scope := fmt.Sprintf("a %s/%s build of tag %s at commit %s; it is NOT the installed binary of any machine (the live worker runs its own build on its own platform)",
		spec.GOOS, spec.GOARCH, spec.Tag, spec.Commit)
	if spec.Installed != nil {
		scope += "; the installed record read from " + spec.Installed.ReadFrom + " corroborates the tag, commit and version only, not the bytes"
	}
	rec := &provenanceRecord{Schema: provenanceSchema, Kind: "source", Name: spec.Name, BinarySHA256: sha256Hex(raw), BinarySize: int64(len(raw)),
		Source: &sourceProvenance{Tag: spec.Tag, Commit: commit, GoVersion: info.GoVersion, GOOS: settings["GOOS"], GOARCH: settings["GOARCH"],
			CGO: settings["CGO_ENABLED"], LDFlags: settings["-ldflags"], Installed: spec.Installed},
		Scope: scope}
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(spec.Out, append(out, '\n'), 0o600); err != nil {
		return nil, err
	}
	return rec, nil
}

// ── the opt-in commands ──────────────────────────────────────────────────────

func loadSpec(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, strictUnmarshal(raw, into), "spec %s", path)
}

// DAGU_MACHINEAUTH_EXTRACT=<spec.json> reads a build's binary out of an image
// layout and writes its provenance record (README.md).
func TestMachineAuthExtract(t *testing.T) {
	specPath := os.Getenv("DAGU_MACHINEAUTH_EXTRACT")
	if specPath == "" {
		t.Skip("set DAGU_MACHINEAUTH_EXTRACT=<spec.json> to extract a build's binary from an OCI image layout")
	}
	var spec extractSpec
	loadSpec(t, specPath, &spec)
	rec, err := extractImageBinary(spec)
	require.NoError(t, err, "the extraction stopped; nothing it wrote is a build")
	raw, err := os.ReadFile(filepath.Join(spec.OutDir, "provenance.json"))
	require.NoError(t, err)
	t.Logf("%s: binary sha256 %s (%d bytes) from layer %s of manifest %s; record sha256 %s",
		rec.Name, rec.BinarySHA256, rec.BinarySize, rec.Image.Layer, rec.Image.Manifest, sha256Hex(raw))
}

// DAGU_MACHINEAUTH_SOURCE_RECORD=<spec.json> records a source build (README.md).
func TestMachineAuthSourceRecord(t *testing.T) {
	specPath := os.Getenv("DAGU_MACHINEAUTH_SOURCE_RECORD")
	if specPath == "" {
		t.Skip("set DAGU_MACHINEAUTH_SOURCE_RECORD=<spec.json> to record a build from source")
	}
	var spec sourceSpec
	loadSpec(t, specPath, &spec)
	rec, err := recordSourceBuild(spec, tagCommit)
	require.NoError(t, err)
	raw, err := os.ReadFile(spec.Out)
	require.NoError(t, err)
	t.Logf("%s: binary sha256 %s, tag %s commit %s; record sha256 %s; %s", rec.Name, rec.BinarySHA256, rec.Source.Tag, rec.Source.Commit, sha256Hex(raw), rec.Scope)
}
