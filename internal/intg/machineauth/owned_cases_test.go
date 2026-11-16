// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package machineauth_test

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests prove the cleanup guard of the controlled build (TXE-7538) on
// disposable fixtures only: a stand-in "shared cache" holding a sentinel
// file, under the test's own temporary directory. None runs go, downloads a
// module, or touches the host's real caches or HOME.

// homeVar is named, not written as a literal assignment, so the source scan
// below can forbid the latter.
const homeVar = "HOME"

// sentinelDir is a stand-in for a cache a cleanup must never touch: a
// directory holding one sentinel file. intact reports whether both are as
// they were (same directory, same file, same content).
type sentinelDir struct {
	path, file string
	info       os.FileInfo
}

func newSentinel(t *testing.T, name string) sentinelDir {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	dir := filepath.Join(parent, name)
	require.NoError(t, os.Mkdir(dir, 0o700))
	file := filepath.Join(dir, "SENTINEL")
	require.NoError(t, os.WriteFile(file, []byte("must survive"), 0o600))
	info, err := os.Lstat(dir)
	require.NoError(t, err)
	return sentinelDir{path: dir, file: file, info: info}
}

func (s sentinelDir) intact(t *testing.T) bool {
	t.Helper()
	now, err := os.Lstat(s.path)
	if err != nil || !os.SameFile(s.info, now) {
		return false
	}
	raw, err := os.ReadFile(s.file)
	return err == nil && string(raw) == "must survive"
}

func TestOwnedDirRemovesItselfOnly(t *testing.T) {
	t.Parallel()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	neighbour := filepath.Join(parent, "NEIGHBOUR")
	require.NoError(t, os.WriteFile(neighbour, []byte("x"), 0o600))
	d, err := createOwnedDir(parent, "work-")
	require.NoError(t, err)
	// A read-only tree, as a module cache leaves.
	cache, err := d.sub("gomodcache")
	require.NoError(t, err)
	deep := filepath.Join(cache.path, "example.com", "dep@v1.0.0")
	require.NoError(t, os.MkdirAll(deep, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(deep, "dep.go"), []byte("package dep\n"), 0o400))
	require.NoError(t, os.Chmod(deep, 0o500))
	require.NoError(t, os.Chmod(filepath.Dir(deep), 0o500))
	require.NoError(t, d.remove())
	_, err = os.Lstat(d.path)
	assert.True(t, os.IsNotExist(err), "the owned tree is gone")
	_, err = os.Stat(neighbour)
	assert.NoError(t, err, "its parent's other entries stay")
	assert.Error(t, d.remove(), "a removed directory is no longer the recorded one")
}

// A record cleanup does not hold, or one the disk no longer matches, is
// refused, and nothing is removed.
func TestOwnedDirRefusesWhatItDidNotCreate(t *testing.T) {
	t.Parallel()
	var none *ownedDir
	assert.ErrorContains(t, none.remove(), "no record")
	assert.ErrorContains(t, (&ownedDir{}).remove(), "no record")

	t.Run("a path named without a record", func(t *testing.T) {
		t.Parallel()
		shared := newSentinel(t, "shared-cache")
		fake := &ownedDir{path: shared.path, parent: filepath.Dir(shared.path)}
		assert.ErrorContains(t, fake.remove(), "no record")
		assert.True(t, shared.intact(t))
	})
	t.Run("a record pointed at another directory", func(t *testing.T) {
		t.Parallel()
		shared := newSentinel(t, "shared-cache")
		parent, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		d, err := createOwnedDir(parent, "work-")
		require.NoError(t, err)
		d.path, d.parent = shared.path, filepath.Dir(shared.path) // the record's identity is still the owned dir's
		assert.ErrorContains(t, d.remove(), "not the directory that was created")
		assert.True(t, shared.intact(t))
	})
	t.Run("the directory replaced under the same name", func(t *testing.T) {
		t.Parallel()
		parent, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		d, err := createOwnedDir(parent, "work-")
		require.NoError(t, err)
		moved := filepath.Join(parent, "moved")
		require.NoError(t, os.Rename(d.path, moved))
		require.NoError(t, os.Mkdir(d.path, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(d.path, "SENTINEL"), []byte("other"), 0o600))
		assert.ErrorContains(t, d.remove(), "not the directory that was created")
		_, err = os.Stat(filepath.Join(d.path, "SENTINEL"))
		assert.NoError(t, err, "the replacement stays")
	})
	t.Run("the directory turned into a link", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "windows" {
			t.Skip("creating a symbolic link needs a privilege on Windows")
		}
		shared := newSentinel(t, "shared-cache")
		parent, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		d, err := createOwnedDir(parent, "work-")
		require.NoError(t, err)
		require.NoError(t, os.Rename(d.path, filepath.Join(parent, "moved")))
		require.NoError(t, os.Symlink(shared.path, d.path))
		assert.ErrorContains(t, d.remove(), "is now a link")
		assert.True(t, shared.intact(t), "the link's target is untouched")
	})
	t.Run("the parent changed custody", func(t *testing.T) {
		t.Parallel()
		root, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		parent := filepath.Join(root, "p")
		require.NoError(t, os.Mkdir(parent, 0o700))
		d, err := createOwnedDir(parent, "work-")
		require.NoError(t, err)
		// The same directory, now under a new directory of the same name.
		require.NoError(t, os.Rename(parent, filepath.Join(root, "p-old")))
		require.NoError(t, os.Mkdir(parent, 0o700))
		require.NoError(t, os.Rename(filepath.Join(root, "p-old", filepath.Base(d.path)), d.path))
		assert.ErrorContains(t, d.remove(), "its parent")
		_, err = os.Stat(d.path)
		assert.NoError(t, err, "nothing removed")
	})
	t.Run("a pre-existing name is never adopted", func(t *testing.T) {
		t.Parallel()
		parent, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		d, err := createOwnedDir(parent, "work-")
		require.NoError(t, err)
		require.NoError(t, os.Mkdir(filepath.Join(d.path, "gomodcache"), 0o700))
		_, err = d.sub("gomodcache")
		assert.Error(t, err, "an existing directory is not created, so not owned")
		_, err = d.sub("../escape")
		assert.ErrorContains(t, err, "not one plain name")
	})
	t.Run("a parent that is relative or a link", func(t *testing.T) {
		t.Parallel()
		_, err := createOwnedDir("relative", "work-")
		assert.ErrorContains(t, err, "not absolute")
		if runtime.GOOS == "windows" {
			return
		}
		root, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(root, "link")))
		_, err = createOwnedDir(filepath.Join(root, "link"), "work-")
		assert.ErrorContains(t, err, "not a real directory")
	})
}

// The build's go directories are its own on every go command, and an
// environment in which one is missing or names another directory is refused
// before go runs. This is what a mutant dropping the private GOMODCACHE meets
// now: the caller's value is not used, and nothing derives a path from it.
func TestCheckPrivateEnvRefusesAnyOtherCache(t *testing.T) {
	t.Parallel()
	shared := newSentinel(t, "shared-gomodcache")
	parent, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	work, err := createOwnedDir(parent, "machineauth-source-")
	require.NoError(t, err)
	owned := map[string]*ownedDir{}
	for key, name := range map[string]string{"GOPATH": "gopath", "GOMODCACHE": "gomodcache", "GOCACHE": "gocache"} {
		owned[key], err = work.sub(name)
		require.NoError(t, err)
	}
	spec := sourceSpec{GOOS: "linux", GOARCH: "amd64", Parallel: 2}
	base := []string{"PATH=/usr/bin", "GOMODCACHE=" + shared.path, "GOPATH=" + filepath.Dir(shared.path), "GOPROXY=off"}
	set := buildSet(spec, base, owned)
	env := append(slices.Clone(base), set...)
	require.NoError(t, checkPrivateEnv(env, owned))
	for _, kv := range set {
		assert.False(t, strings.HasPrefix(kv, homeVar+"="), "the build never sets HOME")
	}
	assert.Contains(t, set, "GOPROXY="+fileURL(filepath.Join(shared.path, "cache", "download"))+",off",
		"the caller's cache is read only as a file proxy")

	drop := func(key string) []string {
		var out []string
		for _, kv := range set {
			if !strings.HasPrefix(kv, key+"=") {
				out = append(out, kv)
			}
		}
		return out
	}
	for _, key := range privateGoDirs {
		// Dropped with the caller's value present: refused, not inherited.
		e := append(slices.Clone(base), drop(key)...)
		assert.ErrorContains(t, checkPrivateEnv(e, owned), "not its own", "%s dropped, caller's present", key)
		// Dropped with no caller value: refused, not defaulted.
		var bare []string
		for _, kv := range e {
			if !strings.HasPrefix(kv, key+"=") {
				bare = append(bare, kv)
			}
		}
		assert.ErrorContains(t, checkPrivateEnv(bare, owned), "not its own", "%s missing", key)
		// Pointed at the shared cache: refused.
		assert.ErrorContains(t, checkPrivateEnv(append(slices.Clone(env), key+"="+shared.path), owned), "not its own", "%s shared", key)
	}
	// A record of the go dirs that no longer matches the disk: refused.
	require.NoError(t, os.Rename(owned["GOCACHE"].path, owned["GOCACHE"].path+"-moved"))
	require.NoError(t, os.Mkdir(owned["GOCACHE"].path, 0o700))
	assert.ErrorContains(t, checkPrivateEnv(env, owned), "not the directory that was created")

	// The cleanup the build defers acts on its own record only.
	require.NoError(t, work.remove())
	assert.True(t, shared.intact(t), "the stand-in shared cache and its sentinel survive")
}

// No code in this package cleans a module cache through go, and none sets
// HOME for a go or git command: a cache named by the environment can be the
// caller's own (TXE-7538). The release matrix's dagu processes (rig_test.go,
// release_test.go) set HOME inside their own isolated rig and are not go
// tooling; they are the only files allowed to.
func TestNoModuleCacheCleanOrHomeOverride(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	clean := `"-` + `modcache"`
	home := `"HOME` + `="`
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		raw, err := os.ReadFile(e.Name())
		require.NoError(t, err)
		assert.NotContains(t, string(raw), clean, "%s cleans a module cache through go; remove an owned directory by its record instead", e.Name())
		if e.Name() != "rig_test.go" && e.Name() != "release_test.go" {
			assert.NotContains(t, string(raw), home, "%s sets HOME; name owned GOPATH, GOMODCACHE and GOCACHE instead", e.Name())
		}
	}
}
