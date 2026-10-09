// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
)

const (
	stagingDir = ".staging"

	defaultMaxFiles = 4096
	defaultMaxBytes = 64 << 20

	// sniffBytes is how much of each file is inspected for credential content.
	sniffBytes = 4096
)

// ErrPackageCorrupt reports a stored package that no longer matches its digest.
var ErrPackageCorrupt = errors.New("package does not match its digest")

// ErrStagingExists reports a build left by an earlier attempt with the same
// request ID. Load it with LoadStaged instead of building again, so a resumed
// registration keeps the digest it already sent.
var ErrStagingExists = errors.New("a staged package already exists for this request")

// Store keeps packages under Root as <job id>/<digest directory>.
type Store struct {
	Root     string
	Policy   PathPolicy
	MaxFiles int
	MaxBytes int64
}

// NewStore returns the package store of a TXE home with the default policy.
func NewStore(home Home) *Store {
	return &Store{Root: home.PackagesDir(), Policy: DefaultPathPolicy()}
}

// BuildOptions describes the files and command of a new package.
type BuildOptions struct {
	// SourceRoot is the directory Include paths are relative to. The
	// payload keeps their layout beneath it.
	SourceRoot string
	// Include lists files and directories to package. Uncommitted and
	// untracked files are packaged like any other: the working copy is the
	// source, not a commit.
	Include        []string
	Entrypoint     []string
	Runtimes       []string
	CredentialRefs []CredentialRef
	Provenance     Provenance
}

// Staged is a complete package that has not yet been given to a job.
type Staged struct {
	Dir      string
	Digest   string
	Manifest Manifest
}

// Package is an immutable package assigned to a job.
type Package struct {
	JobID    string
	Digest   string
	Dir      string
	Manifest Manifest
}

// WorkDir is the read-only payload directory the job's steps run in.
func (p *Package) WorkDir() string { return filepath.Join(p.Dir, FilesDir) }

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// hasModeBits is false where the file system has no Unix permission bits to
// check. Job packages run on Unix workers.
const hasModeBits = runtime.GOOS != "windows"

// Stage builds a package in the staging area under requestID and returns its
// digest. Nothing outside the staging area changes.
func (s *Store) Stage(requestID string, opts BuildOptions) (*Staged, error) {
	if !hasModeBits {
		return nil, errors.New("job packages are built on the Unix machine that runs them; this is a Windows build")
	}
	if !namePattern.MatchString(requestID) {
		return nil, fmt.Errorf("invalid request id %q", requestID)
	}
	if err := s.Policy.CheckDurable(s.Root); err != nil {
		return nil, fmt.Errorf("package store: %w", err)
	}
	for _, ref := range opts.CredentialRefs {
		if err := ref.Validate(s.Policy); err != nil {
			return nil, err
		}
	}
	root, err := filepath.Abs(opts.SourceRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve source root: %w", err)
	}
	root = resolveExisting(root)
	if len(opts.Include) == 0 {
		return nil, errors.New("no files to package: name at least one file or directory")
	}

	dir := filepath.Join(s.Root, stagingDir, requestID)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, fmt.Errorf("create staging area: %w", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("%w: %s", ErrStagingExists, dir)
		}
		return nil, fmt.Errorf("create staging directory: %w", err)
	}

	staged, err := s.build(dir, root, opts)
	if err != nil {
		// A failed build was never referenced by anything.
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return staged, nil
}

func (s *Store) build(dir, root string, opts BuildOptions) (*Staged, error) {
	files, err := s.copySources(root, filepath.Join(dir, FilesDir), opts)
	if err != nil {
		return nil, err
	}

	entrypoint, runtimes, err := checkEntrypoint(opts.Entrypoint, opts.Runtimes, files, s.Policy)
	if err != nil {
		return nil, err
	}

	provenance := opts.Provenance
	provenance.SourceRoot = root
	manifest := Manifest{
		Schema:         ManifestSchema,
		Entrypoint:     entrypoint,
		Files:          files,
		ContentSHA256:  contentDigest(files),
		Runtimes:       runtimes,
		CredentialRefs: opts.CredentialRefs,
		Provenance:     provenance,
	}
	data, err := manifest.encode()
	if err != nil {
		return nil, err
	}
	if err := fileutil.WriteFileAtomic(filepath.Join(dir, ManifestName), data, 0o600); err != nil {
		return nil, fmt.Errorf("write manifest: %w", err)
	}
	if err := syncTree(dir); err != nil {
		return nil, err
	}
	return &Staged{Dir: dir, Digest: Digest(data), Manifest: manifest}, nil
}

// LoadStaged returns the package an earlier Stage built for requestID, after
// checking it is intact.
func (s *Store) LoadStaged(requestID string) (*Staged, error) {
	if !namePattern.MatchString(requestID) {
		return nil, fmt.Errorf("invalid request id %q", requestID)
	}
	dir := filepath.Join(s.Root, stagingDir, requestID)
	manifest, digest, err := verifyDir(dir, false)
	if err != nil {
		return nil, err
	}
	return &Staged{Dir: dir, Digest: digest, Manifest: *manifest}, nil
}

// Commit moves a staged package to its final, read-only location for jobID.
// Committing a package that is already in place returns it unchanged, so a
// resumed registration can repeat the call.
func (s *Store) Commit(staged *Staged, jobID string) (*Package, error) {
	final, err := s.packageDir(jobID, staged.Digest)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(final); err == nil {
		return s.Adopt(jobID, staged.Digest)
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return nil, fmt.Errorf("create package directory: %w", err)
	}
	if err := os.Rename(staged.Dir, final); err != nil {
		return nil, fmt.Errorf("move package into place: %w", err)
	}
	return s.Adopt(jobID, staged.Digest)
}

// Adopt finishes placing a package that is already in its final location: it
// seals it, in case an earlier attempt stopped between moving and sealing,
// and then verifies it. A package is never vouched for unsealed.
func (s *Store) Adopt(jobID, digest string) (*Package, error) {
	final, err := s.packageDir(jobID, digest)
	if err != nil {
		return nil, err
	}
	if _, _, err := verifyDir(final, false); err != nil {
		return nil, err
	}
	if err := sealTree(final); err != nil {
		return nil, err
	}
	if err := fileutil.SyncDir(filepath.Dir(final)); err != nil {
		return nil, fmt.Errorf("sync package directory: %w", err)
	}
	return s.Verify(jobID, digest)
}

// Verify re-reads a stored package and checks the manifest against its digest,
// every payload file against the manifest, each file's executable bit, and
// that nothing in the package is writable.
func (s *Store) Verify(jobID, digest string) (*Package, error) {
	dir, err := s.packageDir(jobID, digest)
	if err != nil {
		return nil, err
	}
	manifest, found, err := verifyDir(dir, true)
	if err != nil {
		return nil, err
	}
	if found != digest {
		return nil, fmt.Errorf("%w: %s holds a manifest with digest %s", ErrPackageCorrupt, dir, found)
	}
	if err := s.Policy.CheckDurable(dir); err != nil {
		return nil, err
	}
	return &Package{JobID: jobID, Digest: digest, Dir: dir, Manifest: *manifest}, nil
}

// PackageDir returns where the package for jobID and digest is, or would be.
func (s *Store) PackageDir(jobID, digest string) (string, error) {
	return s.packageDir(jobID, digest)
}

func (s *Store) packageDir(jobID, digest string) (string, error) {
	if !namePattern.MatchString(jobID) {
		return "", fmt.Errorf("invalid job id %q", jobID)
	}
	name, err := DigestDirName(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.Root, jobID, name), nil
}

// copySources copies the included files from the source root into dst and
// returns them sorted by path.
//
// Each file is opened once, through a handle on the source root, and what is
// checked is what is copied: the handle cannot be led outside the root by a
// link that appears after the walk has seen the path, and the checks for a
// regular file, for credentials and for size apply to the opened file itself.
func (s *Store) copySources(root, dst string, opts BuildOptions) ([]File, error) {
	maxFiles, remaining := s.MaxFiles, s.MaxBytes
	if maxFiles == 0 {
		maxFiles = defaultMaxFiles
	}
	if remaining == 0 {
		remaining = defaultMaxBytes
	}
	limit := remaining

	source, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("open source root: %w", err)
	}
	defer func() { _ = source.Close() }()

	// A credential the job refers to by file must not also travel in the
	// package, under any name.
	var credentials []fs.FileInfo
	for _, ref := range opts.CredentialRefs {
		if ref.Kind != CredentialFile {
			continue
		}
		if info, err := os.Stat(ref.Locator); err == nil {
			credentials = append(credentials, info)
		}
	}

	seen := map[string]bool{}
	var files []File
	for _, item := range opts.Include {
		if filepath.IsAbs(item) {
			return nil, fmt.Errorf("include path %q must be relative to the source root", item)
		}
		start := filepath.ToSlash(filepath.Clean(item))
		if start == ".." || strings.HasPrefix(start, "../") {
			return nil, fmt.Errorf("include path %q leaves the source root", item)
		}
		err := fs.WalkDir(source.FS(), start, func(rel string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Name() == ".git" {
				return fmt.Errorf("include path %q contains %s; name the files the job needs, not a repository", item, rel)
			}
			if d.IsDir() || seen[rel] {
				return nil
			}
			seen[rel] = true
			if len(seen) > maxFiles {
				return fmt.Errorf("package has more than %d files; name the needed files instead of a whole tree", maxFiles)
			}
			f, err := s.copyOne(source, rel, filepath.Join(dst, filepath.FromSlash(rel)), credentials, remaining)
			if err != nil {
				if errors.Is(err, errTooLarge) {
					return fmt.Errorf("package is larger than %d bytes", limit)
				}
				return err
			}
			remaining -= f.Size
			f.Path = rel
			files = append(files, f)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(files, func(a, b int) bool { return files[a].Path < files[b].Path })
	return files, nil
}

var errTooLarge = errors.New("package size limit exceeded")

// copyOne opens rel beneath the source root, checks the opened file, and
// copies at most budget bytes of it to dst.
func (s *Store) copyOne(source *os.Root, rel string, dst string, credentials []fs.FileInfo, budget int64) (File, error) {
	// A link is packaged as the file it points to, so every name on the way
	// to that file is judged, not only the one the spec used.
	names, err := linkNames(source, rel)
	if err != nil {
		return File{}, err
	}
	if slices.ContainsFunc(names, looksLikeCredentialName) {
		return File{}, fmt.Errorf("%w: %s; reference it with a credential reference instead of packaging it", ErrCredentialFile, rel)
	}

	// The root handle follows a link only while it stays inside the root.
	in, err := source.Open(filepath.FromSlash(rel))
	if err != nil {
		return File{}, fmt.Errorf("open %s: %w (a link is packaged only when it is relative and stays inside the source root)", rel, err)
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return File{}, err
	}
	if !info.Mode().IsRegular() {
		return File{}, fmt.Errorf("%s is not a regular file", rel)
	}
	for _, credential := range credentials {
		if os.SameFile(info, credential) {
			return File{}, fmt.Errorf("%w: %s is the file a credential reference points to; a job refers to its credential, it does not carry it", ErrCredentialFile, rel)
		}
	}

	head := make([]byte, sniffBytes)
	n, err := io.ReadFull(in, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return File{}, fmt.Errorf("read %s: %w", rel, err)
	}
	head = head[:n]
	if looksLikeCredentialContent(head) {
		return File{}, fmt.Errorf("%w: %s holds a private key or a kubeconfig", ErrCredentialFile, rel)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return File{}, err
	}
	executable := info.Mode()&0o111 != 0
	perm := os.FileMode(0o600)
	if executable {
		perm = 0o700
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:gosec // dst is inside the staging directory
	if err != nil {
		return File{}, fmt.Errorf("create %s: %w", dst, err)
	}
	hash := sha256.New()
	// One byte past the budget tells a file that fits from one that does not.
	size, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(io.MultiReader(bytes.NewReader(head), in), budget+1))
	if err == nil && size > budget {
		err = errTooLarge
	}
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		if errors.Is(err, errTooLarge) {
			return File{}, err
		}
		return File{}, fmt.Errorf("copy %s: %w", rel, err)
	}
	return File{Size: size, SHA256: hex.EncodeToString(hash.Sum(nil)), Executable: executable}, nil
}

// maxLinkHops bounds a chain of links, as the operating system does.
const maxLinkHops = 40

// linkNames returns the names a packaged path goes by: its own base name, the
// base name of every link that stands for it, and the name of the file it
// finally is. It resolves the path the way the operating system does, one
// component at a time, asking the root about each. A directory walk reports
// its starting path by what it points to, so the walk's own entry cannot be
// trusted to say whether the path is a link.
func linkNames(source *os.Root, rel string) ([]string, error) {
	pending := strings.Split(path.Clean(filepath.ToSlash(rel)), "/")
	names := []string{pending[len(pending)-1]}
	var resolved []string
	hops := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(resolved) == 0 {
				return nil, fmt.Errorf("%s is a link that leaves the source root", rel)
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}
		candidate := filepath.Join(filepath.Join(resolved...), part)
		info, err := source.Lstat(candidate)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", rel, err)
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			resolved = append(resolved, part)
			continue
		}
		if hops++; hops > maxLinkHops {
			return nil, fmt.Errorf("%s is a chain of more than %d links", rel, maxLinkHops)
		}
		target, err := source.Readlink(candidate)
		if err != nil {
			return nil, fmt.Errorf("read link %s: %w", rel, err)
		}
		target = filepath.ToSlash(target)
		if path.IsAbs(target) {
			return nil, fmt.Errorf("%s is a link to an absolute path; a link is packaged only when it is relative and stays inside the source root", rel)
		}
		if len(pending) == 0 {
			// This link stands for the file itself, not a directory on the way.
			names = append(names, path.Base(target))
		}
		pending = append(strings.Split(target, "/"), pending...)
	}
	if len(resolved) > 0 {
		names = append(names, resolved[len(resolved)-1])
	}
	return names, nil
}

// checkEntrypoint validates the command. A first element naming a packaged
// file must be executable; a bare name is a runtime found on the worker's PATH
// and is recorded as such; an absolute path must be durable.
func checkEntrypoint(argv, runtimes []string, files []File, policy PathPolicy) ([]string, []string, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, nil, errors.New("entrypoint is required")
	}
	runtimes = slices.Clone(runtimes)
	command := argv[0]
	switch {
	case filepath.IsAbs(command):
		if err := policy.CheckDurable(command); err != nil {
			return nil, nil, fmt.Errorf("entrypoint: %w", err)
		}
	case strings.Contains(command, "/"):
		rel := path.Clean(filepath.ToSlash(command))
		i := slices.IndexFunc(files, func(f File) bool { return f.Path == rel })
		if i < 0 {
			return nil, nil, fmt.Errorf("entrypoint %s is not one of the packaged files", command)
		}
		if !files[i].Executable {
			return nil, nil, fmt.Errorf("entrypoint %s is not executable", command)
		}
	default:
		if !slices.Contains(runtimes, command) {
			runtimes = append(runtimes, command)
		}
	}
	sort.Strings(runtimes)
	return slices.Clone(argv), runtimes, nil
}

// verifyDir checks a package directory against its own manifest and returns
// the manifest with the digest of its bytes. With sealed set it also requires
// what a package in its final place must have: each file's executable bit as
// the manifest records it, and no write permission anywhere.
func verifyDir(dir string, sealed bool) (*Manifest, string, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManifestName)) //nolint:gosec // dir is built from validated names
	if err != nil {
		return nil, "", fmt.Errorf("read package manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, "", fmt.Errorf("%w: unreadable manifest in %s: %v", ErrPackageCorrupt, dir, err)
	}
	if manifest.Schema != ManifestSchema {
		return nil, "", fmt.Errorf("package manifest schema %d is not supported by this build (wants %d)", manifest.Schema, ManifestSchema)
	}
	if sealed && hasModeBits {
		for _, p := range []string{dir, filepath.Join(dir, ManifestName)} {
			info, err := os.Stat(p)
			if err != nil {
				return nil, "", err
			}
			if info.Mode().Perm()&0o222 != 0 {
				return nil, "", fmt.Errorf("%w: %s is writable; the package was not sealed", ErrPackageCorrupt, p)
			}
		}
	}

	listed := make(map[string]File, len(manifest.Files))
	for _, f := range manifest.Files {
		listed[f.Path] = f
	}
	payload := filepath.Join(dir, FilesDir)
	err = filepath.WalkDir(payload, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if sealed && hasModeBits && info.Mode().Perm()&0o222 != 0 {
			return fmt.Errorf("%w: %s is writable; the package was not sealed", ErrPackageCorrupt, p)
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(payload, p)
		rel = filepath.ToSlash(rel)
		want, ok := listed[rel]
		if !ok {
			return fmt.Errorf("%w: %s is not in the manifest", ErrPackageCorrupt, p)
		}
		delete(listed, rel)
		if !d.Type().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file", ErrPackageCorrupt, p)
		}
		sum, size, err := hashFile(p)
		if err != nil {
			return err
		}
		if size != want.Size || sum != want.SHA256 {
			return fmt.Errorf("%w: %s changed after packaging", ErrPackageCorrupt, p)
		}
		if sealed && hasModeBits && (info.Mode().Perm()&0o111 != 0) != want.Executable {
			return fmt.Errorf("%w: the executable bit of %s is not as packaged", ErrPackageCorrupt, p)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if len(listed) > 0 {
		missing := slices.Sorted(maps.Keys(listed))
		return nil, "", fmt.Errorf("%w: %s is missing from %s", ErrPackageCorrupt, strings.Join(missing, ", "), dir)
	}
	return &manifest, Digest(data), nil
}

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p) //nolint:gosec // p is inside a package directory
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// sealTree removes write permission from a package so neither a job nor a
// later session edits it in place. Directories lose it last. The changes go
// through a root handle on the package, so nothing outside it can be reached
// by way of a link.
func sealTree(dir string) error {
	type entry struct {
		rel  string
		perm os.FileMode
	}
	var files, dirs []entry
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, entry{rel, 0o555})
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		perm := os.FileMode(0o444)
		if info.Mode()&0o100 != 0 {
			perm = 0o555
		}
		files = append(files, entry{rel, perm})
		return nil
	})
	if err != nil {
		return fmt.Errorf("seal package: %w", err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("seal package: %w", err)
	}
	defer func() { _ = root.Close() }()
	// Deepest directories first, and every directory after the files in it.
	slices.Reverse(dirs)
	for _, e := range slices.Concat(files, dirs) {
		if err := root.Chmod(e.rel, e.perm); err != nil {
			return fmt.Errorf("seal package: %w", err)
		}
	}
	return nil
}

// syncTree flushes every directory under dir so the staged package survives a
// crash. Files were synced as they were written.
func syncTree(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if err := fileutil.SyncDir(p); err != nil {
				return fmt.Errorf("sync %s: %w", p, err)
			}
		}
		return nil
	})
}
