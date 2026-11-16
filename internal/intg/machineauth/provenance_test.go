// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package machineauth_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A build's provenance record says where its binary came from, and the
// manifest binds the record by digest. Two kinds:
//
//   - image: the binary was read out of a published image, through a chain the
//     extraction checked link by link (index → the platform's manifest → config
//     and layers → the file), from an OCI layout on disk. Any link that does not
//     hash to the digest that names it stops the extraction.
//   - source: the binary was built by this package's own command from a fresh
//     clone of a tag, which it verified (the tag's commit, a clean tree with no
//     ignored or untracked file) before and after the build. The record names
//     the inputs the command controlled and what the binary's build information
//     says. A binary handed to the command is never recorded: a VCS stamp can
//     be borrowed (a module built in an ignored directory of a checkout carries
//     the checkout's revision and vcs.modified=false). It is a build of that
//     commit, never the installed binary of another machine.
//
// Both are written by opt-in commands of this package (README.md), never by hand.

// provenanceSchema 2: source records come only from the controlled build
// (TXE-7531); a schema-1 source record trusted a binary it was handed.
const provenanceSchema = 2

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
	// Builder names the command that built the binary; only the controlled
	// build writes source records.
	Builder string `json:"builder"`
	Tag     string `json:"tag"`
	Commit  string `json:"commit"`
	Tree    string `json:"tree"`
	// Module and Package are the main module and the package that was built,
	// from the binary's own build information.
	Module  string `json:"module"`
	Package string `json:"package"`
	// Command and Env are the build the command ran: the go arguments, the
	// variables it set, and the names of the variables it passed through.
	Command     []string `json:"command"`
	Env         []string `json:"env"`
	PassThrough []string `json:"pass_through"`
	// ModVerify is what go mod verify said of the module cache.
	ModVerify string `json:"mod_verify"`
	// Revision and Modified are the binary's own VCS stamp, which must agree.
	Revision  string `json:"vcs_revision"`
	Modified  string `json:"vcs_modified"`
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
// uncompressed stream against its diff id, every byte of each, the tar's
// trailing padding included. It reports whether the layer sets the target (a
// regular file, copied to tmp) or deletes what lower layers had there: a
// whiteout of the target or of any directory above it, or an opaque whiteout
// of a directory above it. A file the layer sets survives the layer's own
// whiteouts, which apply to the layers below. A link at the target, or an
// ancestor that is not a directory, stops the extraction: the binary must be
// the file itself, at its own path.
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
	raw := io.TeeReader(f, compressed)
	stream := raw
	switch l.MediaType {
	case mtOCILayerGzip, mtDockerLayerGz:
		gz, err := gzip.NewReader(raw)
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
	plain := io.TeeReader(stream, uncompressed)
	tr := tar.NewReader(plain)
	targetDir := path.Dir(target) + "/"
	// whitedOut says whether a whiteout of name deletes the target: name is the
	// target or one of its ancestor directories.
	whitedOut := func(name string) bool {
		return name == target || strings.HasPrefix(target, name+"/")
	}
	set, white := false, false
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
		case entryBase == ".wh..wh..opq":
			if strings.HasPrefix(targetDir, entryDir) {
				white = true
			}
		case strings.HasPrefix(entryBase, ".wh."):
			if whitedOut(entryDir + strings.TrimPrefix(entryBase, ".wh.")) {
				white = true
			}
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
			set = true
		case strings.HasPrefix(target, name+"/") && h.Typeflag != tar.TypeDir:
			return false, false, fmt.Errorf("/%s, above %s, is not a directory in this layer (type %q)", name, "/"+target, h.Typeflag)
		}
	}
	// Drain what follows the tar's end through both hashing readers, so each
	// digest covers its whole stream: the tar's padding, then the blob's rest.
	if _, err := io.Copy(io.Discard, plain); err != nil {
		return false, false, err
	}
	if _, err := io.Copy(io.Discard, raw); err != nil {
		return false, false, err
	}
	if got := "sha256:" + hex.EncodeToString(compressed.Sum(nil)); got != l.Digest {
		return false, false, fmt.Errorf("the blob hashes to %s", got)
	}
	if got := "sha256:" + hex.EncodeToString(uncompressed.Sum(nil)); got != diffID {
		return false, false, fmt.Errorf("the uncompressed layer hashes to %s, the config's diff id is %s", got, diffID)
	}
	return set, white && !set, nil
}

// ── source record: the controlled build ──────────────────────────────────────

// controlledBuilder names the build below in every record it writes.
const controlledBuilder = "machineauth-controlled-clone-v1"

// sourceSpec is DAGU_MACHINEAUTH_SOURCE_RECORD's file. There is no field for
// a binary: the command builds it.
type sourceSpec struct {
	Name    string `json:"name"`
	Repo    string `json:"repo"` // a git repository holding the tag; cloned, never built in place
	Tag     string `json:"tag"`
	Commit  string `json:"commit"`
	Module  string `json:"module"`  // the main module the binary must be built from
	Package string `json:"package"` // the package to build, relative to the clone ("./cmd" for dagu)
	Version string `json:"version"`
	GOOS    string `json:"goos"`
	GOARCH  string `json:"goarch"`
	// Parallel bounds the build's CPU use: go build -p and GOMAXPROCS for the
	// go command and the compilers it starts. Required, so a build on a shared
	// host is always bounded.
	Parallel int `json:"parallel"`
	// Installed is another machine's own record of what it runs, when read.
	Installed *installedRecord `json:"installed,omitempty"`
	// OutDir gets dagu and provenance.json; it must not hold them yet.
	OutDir string `json:"out_dir"`
}

// passThrough are the only variables of the caller's environment the build
// sees, besides what it sets: where tools, temporary files, the module cache
// and the module proxy are, and what Windows needs to start a process. Their
// values are not recorded (a proxy URL may carry a credential). Neither cache
// is shared with the build. A writer of a shared GOCACHE could plant compiled
// packages under the keys a build looks up, and a writer of a shared
// GOMODCACHE could change an extracted file during the build and restore it
// after (a check before and after sees nothing). Each build gets a fresh
// private build cache and a fresh private module cache, filled through go's
// own download path (moduleProxyChain), which checks every zip against go.sum;
// go mod verify runs before and after as well.
var passThrough = []string{"PATH", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "PATHEXT", "COMSPEC",
	"GOPATH", "GOMODCACHE", "GOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOPRIVATE", "GOSUMDB"}

// resolvedGoEnv is what the caller's go command resolves for the variables a
// build with GOENV=off would otherwise lose (the caller's go env file may set
// the proxy; the module cache would move under the build's own HOME).
var resolvedGoEnv = sync.OnceValue(func() map[string]string {
	out, err := exec.Command("go", "env", "-json", "GOMODCACHE", "GOPROXY", "GOSUMDB").Output()
	vals := map[string]string{}
	if err == nil {
		_ = json.Unmarshal(out, &vals)
	}
	return vals
})

// gitEnv runs git with no user or system configuration: no filters, hooks,
// templates or rewrites can change what a clone checks out.
func gitEnv() []string {
	return append(callerEnv(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
}

func callerEnv() []string {
	var env []string
	for _, k := range passThrough {
		v, ok := os.LookupEnv(k)
		if !ok {
			v, ok = resolvedGoEnv()[k]
			ok = ok && v != ""
		}
		if ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func runIn(dir string, env []string, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env = dir, env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, truncateText(stderr.String(), 400))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// cleanTree fails unless git sees nothing in the clone beyond its commit:
// no modified, untracked or ignored file.
func cleanTree(dir string) error {
	out, err := runIn(dir, gitEnv(), time.Minute, "git", "status", "--porcelain", "--ignored", "--untracked-files=all")
	if err != nil {
		return err
	}
	if out != "" {
		return fmt.Errorf("the clone is not its commit alone:\n%s", truncateText(out, 400))
	}
	return nil
}

// checkBuildInfo holds a binary's own build information to the spec: the main
// module and package, the platform with cgo off, the version flag, and a git
// stamp of the commit on an unmodified tree. On its own it cannot tell a
// borrowed stamp (TestSourceBuildRefusesABorrowedStamp): it is a check of the
// controlled build's result, never a reason to record a binary it was handed.
func checkBuildInfo(info *debug.BuildInfo, spec sourceSpec, pkg string) (map[string]string, error) {
	settings := map[string]string{}
	for _, st := range info.Settings {
		settings[st.Key] = st.Value
	}
	wantPath := spec.Module
	if pkg != "." {
		wantPath += "/" + pkg
	}
	switch {
	case info.Main.Path != spec.Module || info.Path != wantPath:
		return nil, fmt.Errorf("source record: the binary is package %s of module %s, the spec names %s of %s", info.Path, info.Main.Path, wantPath, spec.Module)
	case settings["GOOS"] != spec.GOOS || settings["GOARCH"] != spec.GOARCH || settings["CGO_ENABLED"] != "0":
		return nil, fmt.Errorf("source record: the binary was built for %s/%s cgo=%s", settings["GOOS"], settings["GOARCH"], settings["CGO_ENABLED"])
	case !strings.Contains(settings["-ldflags"], "main.version="+spec.Version):
		return nil, fmt.Errorf("source record: the binary's -ldflags %q do not set main.version=%s", settings["-ldflags"], spec.Version)
	case settings["vcs"] != "git" || settings["vcs.revision"] != spec.Commit || settings["vcs.modified"] != "false":
		return nil, fmt.Errorf("source record: the binary's own stamp (vcs=%q revision=%q modified=%q) does not name the clean clone of %s",
			settings["vcs"], settings["vcs.revision"], settings["vcs.modified"], spec.Commit)
	}
	return settings, nil
}

// buildFromSource clones the tag into a directory of its own, verifies the
// clone, builds the package as the worker kit builds dagu (go build with
// -X main.version) for the spec's platform with cgo off, verifies the clone
// again and the binary's build information against the inputs, and writes
// the binary and its record into the spec's directory. It never builds in
// the caller's checkout and never records a binary it did not build.
func buildFromSource(spec sourceSpec) (*provenanceRecord, error) {
	return buildFromSourceIn(spec, callerEnv())
}

// ownedDir is a directory this package created exclusively (MkdirTemp or
// Mkdir, which fail on an existing name), bound by the identity it had at
// creation: its own file and its parent's (device and inode on Unix, volume
// and index on Windows, compared by os.SameFile), and its path. Removal acts
// on that record alone: no environment variable or go env output can name
// what is removed. It refuses a record it does not hold, a target replaced
// or turned into a link, and a parent that is no longer the one it was
// created under (TXE-7538: a cleanup that resolved the module cache from the
// environment deleted the host's shared cache when a mutant dropped the
// private one).
type ownedDir struct {
	path       string
	info       os.FileInfo
	parent     string
	parentInfo os.FileInfo
}

// createOwnedDir makes a new directory under parent, an existing real
// directory given by absolute path.
func createOwnedDir(parent, pattern string) (*ownedDir, error) {
	if !filepath.IsAbs(parent) {
		return nil, fmt.Errorf("owned dir: parent %q is not absolute", parent)
	}
	pinfo, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("owned dir: parent: %w", err)
	}
	if pinfo.Mode()&os.ModeSymlink != 0 || !pinfo.IsDir() {
		return nil, fmt.Errorf("owned dir: parent %s is not a real directory", parent)
	}
	path, err := os.MkdirTemp(parent, pattern)
	if err != nil {
		return nil, fmt.Errorf("owned dir: %w", err)
	}
	return bindOwned(path, parent, pinfo)
}

// sub makes the directory name inside d. os.Mkdir refuses a name that exists,
// so a pre-existing target is never adopted.
func (d *ownedDir) sub(name string) (*ownedDir, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	if name == "" || name != filepath.Base(name) || !filepath.IsLocal(name) {
		return nil, fmt.Errorf("owned dir: %q is not one plain name", name)
	}
	path := filepath.Join(d.path, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, fmt.Errorf("owned dir: %w", err)
	}
	return bindOwned(path, d.path, d.info)
}

func bindOwned(path, parent string, pinfo os.FileInfo) (*ownedDir, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("owned dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("owned dir: %s is not a real directory", path)
	}
	return &ownedDir{path: path, info: info, parent: parent, parentInfo: pinfo}, nil
}

// check holds the directory on disk now to its record.
func (d *ownedDir) check() error {
	if d == nil || d.path == "" || d.info == nil || d.parentInfo == nil || d.parent == "" {
		return errors.New("owned dir: no record of a directory this package created; refusing")
	}
	if filepath.Dir(d.path) != d.parent {
		return fmt.Errorf("owned dir: %s is not in its recorded parent %s; refusing", d.path, d.parent)
	}
	for _, c := range []struct {
		path string
		was  os.FileInfo
		what string
	}{{d.parent, d.parentInfo, "its parent"}, {d.path, d.info, "the directory"}} {
		now, err := os.Lstat(c.path)
		if err != nil {
			return fmt.Errorf("owned dir: %s (%s): %w; refusing", c.path, c.what, err)
		}
		switch {
		case now.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("owned dir: %s (%s) is now a link; refusing", c.path, c.what)
		case !now.IsDir():
			return fmt.Errorf("owned dir: %s (%s) is no longer a directory; refusing", c.path, c.what)
		case !os.SameFile(c.was, now):
			return fmt.Errorf("owned dir: %s (%s) is not the directory that was created; refusing", c.path, c.what)
		}
	}
	return nil
}

// remove removes the directory and what it holds, the read-only files of a
// private module cache included, after check. WalkDir does not follow links,
// so only the tree itself is made writable.
func (d *ownedDir) remove() error {
	if err := d.check(); err != nil {
		return err
	}
	_ = filepath.WalkDir(d.path, func(p string, e os.DirEntry, err error) error {
		if err == nil && e.IsDir() {
			_ = os.Chmod(p, 0o700) //nolint:gosec // a directory this package created, made removable
		}
		return nil
	})
	return os.RemoveAll(d.path)
}

// privateGoDirs are the go command's directories a build owns. Every go
// invocation of the build must name each of them as its own (checkPrivateEnv):
// a value missing or pointing elsewhere refuses the command instead of
// letting go fall back to the caller's.
var privateGoDirs = []string{"GOPATH", "GOMODCACHE", "GOCACHE"}

// envValue is the value go sees for key: the last one in env.
func envValue(env []string, key string) (string, bool) {
	v, found := "", false
	for _, kv := range env {
		if k, rest, ok := strings.Cut(kv, "="); ok && k == key {
			v, found = rest, true
		}
	}
	return v, found
}

// checkPrivateEnv refuses an environment in which any of the build's go
// directories is not the owned directory recorded for it.
func checkPrivateEnv(env []string, owned map[string]*ownedDir) error {
	for _, key := range privateGoDirs {
		d := owned[key]
		if err := d.check(); err != nil {
			return fmt.Errorf("source record: %s: %w", key, err)
		}
		v, ok := envValue(env, key)
		if !ok || v != d.path {
			return fmt.Errorf("source record: the build's %s is %q, not its own %s; refusing to run go", key, v, d.path)
		}
	}
	return nil
}

// moduleProxyChain is where the build's private module cache is filled from:
// the caller's module cache downloads (zips and go.mod files, served as a
// file proxy, so nothing need be fetched again), then the caller's proxy. Go
// checks every zip against go.sum as it lands in the private cache; the
// shared cache's extracted files are never read, so a change made to them,
// at any moment, cannot reach the build.
func moduleProxyChain(base []string) string {
	value := func(key string) string {
		v := ""
		for _, kv := range base {
			if k, rest, ok := strings.Cut(kv, "="); ok && k == key {
				v = rest
			}
		}
		return v
	}
	callerProxy := value("GOPROXY")
	if callerProxy == "" {
		callerProxy = "https://proxy.golang.org,direct"
	}
	if shared := value("GOMODCACHE"); shared != "" {
		return fileURL(filepath.Join(shared, "cache", "download")) + "," + callerProxy
	}
	return callerProxy
}

// fileURL is a file:// URL of an absolute path, on Unix and Windows, with
// every URL-significant character of the path escaped, and the go proxy
// list's separators (comma, pipe) too, so a path such as "cache#one,two"
// stays one path of one proxy.
func fileURL(p string) string {
	slashed := filepath.ToSlash(p)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed // a Windows drive path: file:///C:/...
	}
	u := (&url.URL{Scheme: "file", Path: slashed}).String()
	return strings.NewReplacer(",", "%2C", "|", "%7C").Replace(u)
}

// buildSet is what the build sets over the caller's variables: the platform,
// cgo off, no go env file or GOFLAGS, the parallelism bound, the owned go
// directories, and the module proxy chain. HOME is never set: the go
// directories are named explicitly instead.
func buildSet(spec sourceSpec, base []string, owned map[string]*ownedDir) []string {
	return []string{"GOOS=" + spec.GOOS, "GOARCH=" + spec.GOARCH, "CGO_ENABLED=0", "GOTOOLCHAIN=auto", "GOFLAGS=", "GOWORK=off", "GOENV=off",
		"GOMAXPROCS=" + strconv.Itoa(spec.Parallel), "GOPATH=" + owned["GOPATH"].path, "GOCACHE=" + owned["GOCACHE"].path,
		"GOMODCACHE=" + owned["GOMODCACHE"].path, "GOPROXY=" + moduleProxyChain(base)}
}

// modulesVerified is what go mod verify prints when every cached module of
// the build matches go.sum.
const modulesVerified = "all modules verified"

// buildFromSourceIn is buildFromSource with the caller's environment given
// (its tests point the module proxy and cache at fixtures of their own).
func buildFromSourceIn(spec sourceSpec, base []string) (*provenanceRecord, error) {
	pkg := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(spec.Package)), "./")
	switch {
	case spec.Name == "" || spec.Repo == "" || spec.Tag == "" || spec.Module == "" || spec.Package == "" || spec.Version == "" ||
		spec.GOOS == "" || spec.GOARCH == "" || spec.OutDir == "":
		return nil, errors.New("source record: name, repo, tag, commit, module, package, version, goos, goarch and out_dir are all required")
	case !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(spec.Commit):
		return nil, fmt.Errorf("source record: commit %q is not a full commit id", spec.Commit)
	case !filepath.IsAbs(spec.OutDir):
		return nil, errors.New("source record: out_dir must be absolute")
	case spec.Parallel < 1 || spec.Parallel > 64:
		return nil, fmt.Errorf("source record: parallel %d must be between 1 and 64: the build is always bounded", spec.Parallel)
	case !filepath.IsLocal(filepath.FromSlash(pkg)) && pkg != ".":
		return nil, fmt.Errorf("source record: package %q must be a path inside the clone", spec.Package)
	}
	if in := spec.Installed; in != nil && (in.Commit != spec.Commit || in.Tag != spec.Tag || in.Version != spec.Version) {
		return nil, fmt.Errorf("source record: the installed record names tag %s commit %s version %s, not %s %s %s",
			in.Tag, in.Commit, in.Version, spec.Tag, spec.Commit, spec.Version)
	}
	outBin, outRec := filepath.Join(spec.OutDir, "dagu"), filepath.Join(spec.OutDir, "provenance.json")
	for _, p := range []string{outBin, outRec} {
		if _, err := os.Lstat(p); err == nil {
			return nil, fmt.Errorf("source record: %s exists; a build never overwrites", p)
		}
	}
	tmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return nil, err
	}
	workDir, err := createOwnedDir(tmp, "machineauth-source-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = workDir.remove() }()
	owned := map[string]*ownedDir{}
	for key, name := range map[string]string{"GOPATH": "gopath", "GOMODCACHE": "gomodcache", "GOCACHE": "gocache"} {
		if owned[key], err = workDir.sub(name); err != nil {
			return nil, err
		}
	}
	work := workDir.path
	clone := filepath.Join(work, "src")
	if _, err := runIn(work, gitEnv(), 10*time.Minute, "git", "-c", "advice.detachedHead=false", "clone", "--quiet", "--no-hardlinks",
		"--branch", spec.Tag, "--", spec.Repo, clone); err != nil {
		return nil, fmt.Errorf("source record: clone: %w", err)
	}
	head, err := runIn(clone, gitEnv(), time.Minute, "git", "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	tagged, err := runIn(clone, gitEnv(), time.Minute, "git", "rev-parse", "--verify", "refs/tags/"+spec.Tag+"^{commit}")
	if err != nil {
		return nil, fmt.Errorf("source record: %s is not a tag of %s: %w", spec.Tag, spec.Repo, err)
	}
	if head != spec.Commit || tagged != spec.Commit {
		return nil, fmt.Errorf("source record: tag %s is commit %s (checked out %s), the spec names %s", spec.Tag, tagged, head, spec.Commit)
	}
	tree, err := runIn(clone, gitEnv(), time.Minute, "git", "rev-parse", "HEAD^{tree}")
	if err != nil {
		return nil, err
	}
	if err := cleanTree(clone); err != nil {
		return nil, fmt.Errorf("source record: before the build: %w", err)
	}
	built := filepath.Join(work, "dagu")
	set := buildSet(spec, base, owned)
	env := append(slices.Clone(base), set...)
	goCmd := func(timeout time.Duration, args ...string) (string, error) {
		if err := checkPrivateEnv(env, owned); err != nil {
			return "", err
		}
		return runIn(clone, env, timeout, "go", args...)
	}
	// Every module the build needs is in the cache and matches go.sum: a
	// download is checked as it lands, and verify rehashes what was there.
	verify := func(when string) error {
		if _, err := goCmd(20*time.Minute, "mod", "download"); err != nil {
			return fmt.Errorf("source record: %s the build: module download: %w", when, err)
		}
		out, err := goCmd(20*time.Minute, "mod", "verify")
		if err != nil {
			return fmt.Errorf("source record: %s the build: go mod verify: %w", when, err)
		}
		if out != modulesVerified {
			return fmt.Errorf("source record: %s the build: go mod verify says %q", when, truncateText(out, 300))
		}
		return nil
	}
	if err := verify("before"); err != nil {
		return nil, err
	}
	command := []string{"build", "-p", strconv.Itoa(spec.Parallel), "-mod=readonly", "-buildvcs=true", "-ldflags", "-X 'main.version=" + spec.Version + "'", "-o", built, "./" + pkg}
	if pkg == "." {
		command[len(command)-1] = "."
	}
	if _, err := goCmd(30*time.Minute, command...); err != nil {
		return nil, fmt.Errorf("source record: build: %w", err)
	}
	if err := verify("after"); err != nil {
		return nil, err
	}
	if err := cleanTree(clone); err != nil {
		return nil, fmt.Errorf("source record: after the build: %w", err)
	}
	info, err := buildinfo.ReadFile(built)
	if err != nil {
		return nil, fmt.Errorf("source record: the binary's build information: %w", err)
	}
	settings, err := checkBuildInfo(info, spec, pkg)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(built)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(spec.OutDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(outBin, raw, 0o755); err != nil { //nolint:gosec // the built binary is executed by the matrix
		return nil, err
	}
	var names []string
	for _, kv := range base {
		names = append(names, strings.SplitN(kv, "=", 2)[0])
	}
	recorded := slices.Clone(set)
	for i, kv := range recorded {
		switch strings.SplitN(kv, "=", 2)[0] {
		case "GOCACHE":
			recorded[i] = "GOCACHE=<a fresh private build cache of this build>"
		case "GOMODCACHE":
			recorded[i] = "GOMODCACHE=<a fresh private module cache of this build>"
		case "GOPATH":
			recorded[i] = "GOPATH=<a fresh private GOPATH of this build>"
		case "GOPROXY":
			recorded[i] = "GOPROXY=<the caller's module cache downloads as a file proxy, then the caller's proxy>"
		}
	}
	scope := fmt.Sprintf("built by %s from a verified clean clone of tag %s at commit %s (tree %s) for %s/%s; it is NOT the installed binary of any machine (the live worker runs its own build on its own platform)",
		controlledBuilder, spec.Tag, spec.Commit, tree, spec.GOOS, spec.GOARCH)
	if spec.Installed != nil {
		scope += "; the installed record read from " + spec.Installed.ReadFrom + " corroborates the tag, commit and version only, not the bytes"
	}
	rec := &provenanceRecord{Schema: provenanceSchema, Kind: "source", Name: spec.Name, BinarySHA256: sha256Hex(raw), BinarySize: int64(len(raw)),
		Source: &sourceProvenance{Builder: controlledBuilder, Tag: spec.Tag, Commit: spec.Commit, Tree: tree, Module: info.Main.Path, Package: info.Path,
			Command: append([]string{"go"}, command...), Env: recorded, PassThrough: names, ModVerify: modulesVerified + " (before and after the build)",
			Revision: settings["vcs.revision"], Modified: settings["vcs.modified"], GoVersion: info.GoVersion,
			GOOS: settings["GOOS"], GOARCH: settings["GOARCH"], CGO: settings["CGO_ENABLED"], LDFlags: settings["-ldflags"], Installed: spec.Installed},
		Scope: scope}
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(outRec, append(out, '\n'), 0o600); err != nil {
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

// DAGU_MACHINEAUTH_SOURCE_RECORD=<spec.json> builds a binary from a tag in a
// verified clean clone and records it (README.md).
func TestMachineAuthSourceRecord(t *testing.T) {
	specPath := os.Getenv("DAGU_MACHINEAUTH_SOURCE_RECORD")
	if specPath == "" {
		t.Skip("set DAGU_MACHINEAUTH_SOURCE_RECORD=<spec.json> to build and record a binary from a tag")
	}
	var spec sourceSpec
	loadSpec(t, specPath, &spec)
	rec, err := buildFromSource(spec)
	require.NoError(t, err, "the build stopped; nothing it wrote is a build")
	raw, err := os.ReadFile(filepath.Join(spec.OutDir, "provenance.json"))
	require.NoError(t, err)
	t.Logf("%s: binary sha256 %s (%d bytes), tag %s commit %s tree %s; record sha256 %s; %s",
		rec.Name, rec.BinarySHA256, rec.BinarySize, rec.Source.Tag, rec.Source.Commit, rec.Source.Tree, sha256Hex(raw), rec.Scope)
}
