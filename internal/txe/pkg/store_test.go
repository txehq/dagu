// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testJob = "job_01K7A5ZQ8M3N4P5R6S7T8V9W0X"

// newStore returns a store in a test directory. The path policy is empty
// because test directories are themselves temporary.
func newStore(t *testing.T) *Store {
	t.Helper()
	root := filepath.Join(t.TempDir(), "packages")
	t.Cleanup(func() { unseal(root) })
	return &Store{Root: root}
}

// unseal restores write permission so the test directory can be removed.
func unseal(root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700) //nolint:gosec // test cleanup
		}
		return nil
	})
}

// writeSource creates files under a new source root; a "+x" suffix on the
// name marks the file executable.
func writeSource(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		perm := os.FileMode(0o644)
		if trimmed, ok := strings.CutSuffix(name, "+x"); ok {
			name, perm = trimmed, 0o755
		}
		p := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), perm))
	}
	return root
}

func collectorSource(t *testing.T) (string, BuildOptions) {
	t.Helper()
	root := writeSource(t, map[string]string{
		"collect.py+x":    "#!/usr/bin/env python3\nfrom lib.snapshot import summarise\n",
		"lib/snapshot.py": "def summarise(root):\n    return {}\n",
		"notes.txt":       "not part of the job\n",
	})
	return root, BuildOptions{
		SourceRoot: root,
		Include:    []string{"collect.py", "lib"},
		Entrypoint: []string{"./collect.py"},
	}
}

func TestStageAndCommit(t *testing.T) {
	store := newStore(t)
	_, opts := collectorSource(t)

	staged, err := store.Stage("req-1", opts)
	require.NoError(t, err)
	pkg, err := store.Commit(staged, testJob)
	require.NoError(t, err)

	// The digest is the hash of the manifest file as stored.
	manifest, err := os.ReadFile(filepath.Join(pkg.Dir, ManifestName))
	require.NoError(t, err)
	sum := sha256.Sum256(manifest)
	assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), pkg.Digest)
	assert.Equal(t, filepath.Join(store.Root, testJob, "sha256-"+hex.EncodeToString(sum[:])), pkg.Dir)

	// Only the named files are packaged, with their layout kept.
	paths := make([]string, 0, len(pkg.Manifest.Files))
	for _, f := range pkg.Manifest.Files {
		paths = append(paths, f.Path)
	}
	assert.Equal(t, []string{"collect.py", "lib/snapshot.py"}, paths)
	assert.FileExists(t, filepath.Join(pkg.WorkDir(), "lib", "snapshot.py"))
	assert.NoFileExists(t, filepath.Join(pkg.WorkDir(), "notes.txt"))

	// The package is read-only, and the staging entry is gone.
	info, err := os.Stat(pkg.WorkDir())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o555), info.Mode().Perm())
	info, err = os.Stat(filepath.Join(pkg.WorkDir(), "collect.py"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o555), info.Mode().Perm())
	assert.Error(t, os.WriteFile(filepath.Join(pkg.WorkDir(), "new"), nil, 0o600))
	assert.NoDirExists(t, staged.Dir)

	_, err = store.Verify(testJob, pkg.Digest)
	require.NoError(t, err)
}

// The same files and command give the same digest whichever request built them.
func TestDigestIsStable(t *testing.T) {
	store := newStore(t)
	_, opts := collectorSource(t)

	first, err := store.Stage("req-1", opts)
	require.NoError(t, err)
	second, err := store.Stage("req-2", opts)
	require.NoError(t, err)
	assert.Equal(t, first.Digest, second.Digest)

	require.NoError(t, os.WriteFile(filepath.Join(opts.SourceRoot, "lib", "snapshot.py"), []byte("changed\n"), 0o644))
	third, err := store.Stage("req-3", opts)
	require.NoError(t, err)
	assert.NotEqual(t, first.Digest, third.Digest)
	assert.NotEqual(t, first.Manifest.ContentSHA256, third.Manifest.ContentSHA256)
}

// A committed package does not depend on the directory it was built from.
func TestPackageSurvivesSourceRemoval(t *testing.T) {
	store := newStore(t)
	root, opts := collectorSource(t)

	staged, err := store.Stage("req-1", opts)
	require.NoError(t, err)
	pkg, err := store.Commit(staged, testJob)
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(root))

	again, err := store.Verify(testJob, pkg.Digest)
	require.NoError(t, err)
	body, err := os.ReadFile(filepath.Join(again.WorkDir(), "lib", "snapshot.py"))
	require.NoError(t, err)
	assert.Contains(t, string(body), "summarise")
}

func TestStageRefusals(t *testing.T) {
	outside := writeSource(t, map[string]string{"secret.txt": "x"})
	tests := []struct {
		name    string
		files   map[string]string
		link    [2]string // name -> target, created under the source root
		include []string
		entry   []string
		wantIs  error
		wantMsg string
	}{
		{
			name:    "DotEnv",
			files:   map[string]string{"run.sh+x": "#!/bin/sh\n", ".env": "TOKEN=abc\n"},
			include: []string{"."}, entry: []string{"./run.sh"},
			wantIs: ErrCredentialFile,
		},
		{
			name:    "PrivateKeyContent",
			files:   map[string]string{"run.sh+x": "#!/bin/sh\n", "data.txt": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"},
			include: []string{"."}, entry: []string{"./run.sh"},
			wantIs: ErrCredentialFile,
		},
		{
			name:    "Kubeconfig",
			files:   map[string]string{"run.sh+x": "#!/bin/sh\n", "cluster.yaml": "apiVersion: v1\nkind: Config\nclusters: []\nusers: []\n"},
			include: []string{"."}, entry: []string{"./run.sh"},
			wantIs: ErrCredentialFile,
		},
		{
			name:    "SymlinkOutsideRoot",
			files:   map[string]string{"run.sh+x": "#!/bin/sh\n"},
			link:    [2]string{"leak", filepath.Join(outside, "secret.txt")},
			include: []string{"."}, entry: []string{"./run.sh"},
			wantMsg: "stays inside the source root",
		},
		{
			name:    "Repository",
			files:   map[string]string{"run.sh+x": "#!/bin/sh\n", ".git/HEAD": "ref: refs/heads/main\n"},
			include: []string{"."}, entry: []string{"./run.sh"},
			wantMsg: "not a repository",
		},
		{
			name:    "IncludeLeavesRoot",
			files:   map[string]string{"run.sh+x": "#!/bin/sh\n"},
			include: []string{"../elsewhere"}, entry: []string{"./run.sh"},
			wantMsg: "leaves the source root",
		},
		{
			name:    "AbsoluteInclude",
			files:   map[string]string{"run.sh+x": "#!/bin/sh\n"},
			include: []string{filepath.Join(outside, "secret.txt")}, entry: []string{"./run.sh"},
			wantMsg: "must be relative",
		},
		{
			name:    "MissingInclude",
			files:   map[string]string{"run.sh+x": "#!/bin/sh\n"},
			include: []string{"run.sh", "lib"}, entry: []string{"./run.sh"},
			wantIs: fs.ErrNotExist,
		},
		{
			name:    "EntrypointNotPackaged",
			files:   map[string]string{"run.sh+x": "#!/bin/sh\n", "other.sh+x": "#!/bin/sh\n"},
			include: []string{"run.sh"}, entry: []string{"./other.sh"},
			wantMsg: "not one of the packaged files",
		},
		{
			name:    "EntrypointNotExecutable",
			files:   map[string]string{"run.sh": "#!/bin/sh\n"},
			include: []string{"run.sh"}, entry: []string{"./run.sh"},
			wantMsg: "not executable",
		},
		{
			name:    "NoEntrypoint",
			files:   map[string]string{"run.sh+x": "#!/bin/sh\n"},
			include: []string{"run.sh"},
			wantMsg: "entrypoint is required",
		},
		{
			name:  "NothingIncluded",
			files: map[string]string{"run.sh+x": "#!/bin/sh\n"},
			entry: []string{"./run.sh"}, wantMsg: "no files to package",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newStore(t)
			root := writeSource(t, tt.files)
			if tt.link[0] != "" {
				require.NoError(t, os.Symlink(tt.link[1], filepath.Join(root, tt.link[0])))
			}
			_, err := store.Stage("req-1", BuildOptions{SourceRoot: root, Include: tt.include, Entrypoint: tt.entry})
			require.Error(t, err)
			if tt.wantIs != nil {
				require.ErrorIs(t, err, tt.wantIs)
			}
			if tt.wantMsg != "" {
				require.ErrorContains(t, err, tt.wantMsg)
			}
			// A refused build leaves nothing behind.
			assert.NoDirExists(t, filepath.Join(store.Root, stagingDir, "req-1"))
		})
	}
}

// A symlink to a file inside the source root is packaged as that file.
func TestStageFollowsInternalSymlink(t *testing.T) {
	store := newStore(t)
	root := writeSource(t, map[string]string{"run.sh+x": "#!/bin/sh\n", "real/data.txt": "payload\n"})
	require.NoError(t, os.Symlink(filepath.Join("real", "data.txt"), filepath.Join(root, "data.txt")))

	staged, err := store.Stage("req-1", BuildOptions{SourceRoot: root, Include: []string{"run.sh", "data.txt"}, Entrypoint: []string{"./run.sh"}})
	require.NoError(t, err)

	info, err := os.Lstat(filepath.Join(staged.Dir, FilesDir, "data.txt"))
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular())
}

// A link is followed only while it stays inside the source root, whichever
// component of the path it is. This is what holds when a file or a directory
// is swapped for a link after it was listed: the copy opens it through the
// root and is refused.
func TestStageRefusesEscapingLinks(t *testing.T) {
	outside := writeSource(t, map[string]string{"token": "plain-text-token-value\n", "dir/data.txt": "x"})
	tests := []struct {
		name    string
		link    [2]string // name under the source root -> target
		include []string
	}{
		{"FileLinkRelative", [2]string{"data.txt", "../" + filepath.Base(outside) + "/token"}, []string{"run.sh", "data.txt"}},
		{"FileLinkAbsolute", [2]string{"data.txt", filepath.Join(outside, "token")}, []string{"run.sh", "data.txt"}},
		{"DirectoryLink", [2]string{"lib", filepath.Join(outside, "dir")}, []string{"run.sh", "lib"}},
		{"DirectoryLinkInTree", [2]string{"lib", filepath.Join(outside, "dir")}, []string{"."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newStore(t)
			// The source root sits beside the outside directory, so a
			// relative link can reach it.
			root := filepath.Join(filepath.Dir(outside), "src-"+tt.name)
			require.NoError(t, os.MkdirAll(root, 0o755))
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			require.NoError(t, os.WriteFile(filepath.Join(root, "run.sh"), []byte("#!/bin/sh\n"), 0o755)) //nolint:gosec // test script
			require.NoError(t, os.Symlink(tt.link[1], filepath.Join(root, tt.link[0])))

			_, err := store.Stage("req-1", BuildOptions{SourceRoot: root, Include: tt.include, Entrypoint: []string{"./run.sh"}})
			require.Error(t, err)
			assert.NoDirExists(t, filepath.Join(store.Root, stagingDir, "req-1"))
		})
	}
}

// The file a credential reference points to cannot also be packaged, whatever
// it is called and however it is reached.
func TestStageRefusesReferencedCredential(t *testing.T) {
	root := writeSource(t, map[string]string{"run.sh+x": "#!/bin/sh\n", "linear-token": "lin_api_0123456789\n"})
	token := filepath.Join(root, "linear-token")
	refs := []CredentialRef{{Name: "LINEAR_API_KEY", Kind: CredentialFile, Locator: token}}

	t.Run("ByName", func(t *testing.T) {
		store := newStore(t)
		_, err := store.Stage("req-1", BuildOptions{SourceRoot: root, Include: []string{"run.sh", "linear-token"}, Entrypoint: []string{"./run.sh"}, CredentialRefs: refs})
		require.ErrorIs(t, err, ErrCredentialFile)
		require.ErrorContains(t, err, "credential reference points to")
	})
	t.Run("ByHardLink", func(t *testing.T) {
		store := newStore(t)
		require.NoError(t, os.Link(token, filepath.Join(root, "settings.dat")))
		_, err := store.Stage("req-1", BuildOptions{SourceRoot: root, Include: []string{"run.sh", "settings.dat"}, Entrypoint: []string{"./run.sh"}, CredentialRefs: refs})
		require.ErrorIs(t, err, ErrCredentialFile)
	})
	t.Run("ByLink", func(t *testing.T) {
		store := newStore(t)
		require.NoError(t, os.Symlink("linear-token", filepath.Join(root, "alias.txt")))
		_, err := store.Stage("req-1", BuildOptions{SourceRoot: root, Include: []string{"run.sh", "alias.txt"}, Entrypoint: []string{"./run.sh"}, CredentialRefs: refs})
		require.ErrorIs(t, err, ErrCredentialFile)
	})
	t.Run("NotIncluded", func(t *testing.T) {
		store := newStore(t)
		_, err := store.Stage("req-1", BuildOptions{SourceRoot: root, Include: []string{"run.sh"}, Entrypoint: []string{"./run.sh"}, CredentialRefs: refs})
		require.NoError(t, err)
	})
}

// The size limit counts the bytes copied, not what a file looked like earlier.
func TestStageSizeLimit(t *testing.T) {
	store := newStore(t)
	store.MaxBytes = 64
	root := writeSource(t, map[string]string{"run.sh+x": "#!/bin/sh\n", "data.bin": strings.Repeat("x", 60)})

	_, err := store.Stage("req-1", BuildOptions{SourceRoot: root, Include: []string{"run.sh", "data.bin"}, Entrypoint: []string{"./run.sh"}})
	require.ErrorContains(t, err, "larger than 64 bytes")

	store.MaxBytes = 80
	_, err = store.Stage("req-2", BuildOptions{SourceRoot: root, Include: []string{"run.sh", "data.bin"}, Entrypoint: []string{"./run.sh"}})
	require.NoError(t, err)
}

// A package found in its final place but never sealed, as after a crash
// between the move and the seal, is sealed before it is accepted; until then
// it does not verify.
func TestAdoptSealsAnUnsealedPackage(t *testing.T) {
	store := newStore(t)
	_, opts := collectorSource(t)
	staged, err := store.Stage("req-1", opts)
	require.NoError(t, err)

	// Move it into place by hand, without sealing.
	final, err := store.PackageDir(testJob, staged.Digest)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(final), 0o700))
	require.NoError(t, os.Rename(staged.Dir, final))

	_, err = store.Verify(testJob, staged.Digest)
	require.ErrorIs(t, err, ErrPackageCorrupt)
	require.ErrorContains(t, err, "not sealed")

	pkg, err := store.Adopt(testJob, staged.Digest)
	require.NoError(t, err)
	assert.Error(t, os.WriteFile(filepath.Join(pkg.WorkDir(), "new"), nil, 0o600))
	_, err = store.Verify(testJob, staged.Digest)
	require.NoError(t, err)
}

// An entrypoint that lost its executable bit has the same bytes and would
// fail at its scheduled time; verification reports it.
func TestVerifyChecksExecutableBit(t *testing.T) {
	store := newStore(t)
	_, opts := collectorSource(t)
	staged, err := store.Stage("req-1", opts)
	require.NoError(t, err)
	pkg, err := store.Commit(staged, testJob)
	require.NoError(t, err)

	require.NoError(t, os.Chmod(filepath.Join(pkg.WorkDir(), "collect.py"), 0o444))
	_, err = store.Verify(testJob, pkg.Digest)
	require.ErrorIs(t, err, ErrPackageCorrupt)
	require.ErrorContains(t, err, "executable bit")
}

// A bare command is a runtime the worker must provide, and is recorded.
func TestRuntimeEntrypoint(t *testing.T) {
	store := newStore(t)
	root := writeSource(t, map[string]string{"collect.py": "print('ok')\n"})

	staged, err := store.Stage("req-1", BuildOptions{SourceRoot: root, Include: []string{"collect.py"}, Entrypoint: []string{"python3", "collect.py"}, Runtimes: []string{"kubectl"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"kubectl", "python3"}, staged.Manifest.Runtimes)
}

func TestVerifyDetectsChanges(t *testing.T) {
	commit := func(t *testing.T) (*Store, *Package) {
		t.Helper()
		store := newStore(t)
		_, opts := collectorSource(t)
		staged, err := store.Stage("req-1", opts)
		require.NoError(t, err)
		pkg, err := store.Commit(staged, testJob)
		require.NoError(t, err)
		return store, pkg
	}

	t.Run("EditedFile", func(t *testing.T) {
		store, pkg := commit(t)
		p := filepath.Join(pkg.WorkDir(), "collect.py")
		require.NoError(t, os.Chmod(p, 0o700))
		require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\nrm -rf /\n"), 0o700))
		_, err := store.Verify(testJob, pkg.Digest)
		require.ErrorIs(t, err, ErrPackageCorrupt)
	})
	t.Run("AddedFile", func(t *testing.T) {
		store, pkg := commit(t)
		require.NoError(t, os.Chmod(pkg.WorkDir(), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(pkg.WorkDir(), "extra.sh"), []byte("x"), 0o600))
		_, err := store.Verify(testJob, pkg.Digest)
		require.ErrorIs(t, err, ErrPackageCorrupt)
	})
	t.Run("RemovedFile", func(t *testing.T) {
		store, pkg := commit(t)
		require.NoError(t, os.Chmod(filepath.Join(pkg.WorkDir(), "lib"), 0o700))
		require.NoError(t, os.Remove(filepath.Join(pkg.WorkDir(), "lib", "snapshot.py")))
		_, err := store.Verify(testJob, pkg.Digest)
		require.ErrorIs(t, err, ErrPackageCorrupt)
	})
	t.Run("EditedManifest", func(t *testing.T) {
		store, pkg := commit(t)
		p := filepath.Join(pkg.Dir, ManifestName)
		data, err := os.ReadFile(p)
		require.NoError(t, err)
		require.NoError(t, os.Chmod(pkg.Dir, 0o700))
		require.NoError(t, os.Chmod(p, 0o600))
		require.NoError(t, os.WriteFile(p, append(data, ' '), 0o600))
		_, err = store.Verify(testJob, pkg.Digest)
		require.ErrorIs(t, err, ErrPackageCorrupt)
	})
}

// A resumed registration reuses the staged package and may repeat the commit.
func TestResume(t *testing.T) {
	store := newStore(t)
	_, opts := collectorSource(t)

	staged, err := store.Stage("req-1", opts)
	require.NoError(t, err)

	_, err = store.Stage("req-1", opts)
	require.ErrorIs(t, err, ErrStagingExists)
	// The refused second build did not remove the first.
	loaded, err := store.LoadStaged("req-1")
	require.NoError(t, err)
	assert.Equal(t, staged.Digest, loaded.Digest)

	first, err := store.Commit(loaded, testJob)
	require.NoError(t, err)
	second, err := store.Commit(loaded, testJob)
	require.NoError(t, err)
	assert.Equal(t, first.Dir, second.Dir)
}

func TestInvalidNames(t *testing.T) {
	store := newStore(t)
	_, opts := collectorSource(t)

	_, err := store.Stage("../escape", opts)
	require.ErrorContains(t, err, "invalid request id")

	staged, err := store.Stage("req-1", opts)
	require.NoError(t, err)
	_, err = store.Commit(staged, "../escape")
	require.ErrorContains(t, err, "invalid job id")
	_, err = store.PackageDir(testJob, "sha256:short")
	require.ErrorContains(t, err, "invalid package digest")
}
