// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package devtoolsgate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Real access control list fixtures. They run only with
// DAGU_TEST_REAL_ACL=1, and then a missing capability fails the test, never
// skips it. Each sets lists only on directories and files it made in its
// own directory, with unix.Setxattr (no tool, no process), and reads them
// back through the gate's own reader.
//
// DAGU_TEST_REAL_ACL_DIR, when set, is the directory the fixtures are made
// in (one this user owns, on a trusted path), so they can run on a chosen
// filesystem; DAGU_TEST_REAL_ACL_FS, when set, is the statfs magic that
// filesystem must have (for example 794c7630 for overlayfs), checked first.

// realACLDir returns a fresh directory, 0700, for one fixture.
func realACLDir(t *testing.T) string {
	t.Helper()
	if os.Getenv("DAGU_TEST_REAL_ACL") != "1" {
		t.Skip("real access control list fixtures run only with DAGU_TEST_REAL_ACL=1")
	}
	parent := os.Getenv("DAGU_TEST_REAL_ACL_DIR")
	if parent == "" {
		parent = privateTempDir(t)
	}
	dir, err := os.MkdirTemp(parent, "acl-")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove the fixture %s: %v", dir, err)
		}
	})
	require.NoError(t, os.Chmod(dir, 0o700))
	if want := os.Getenv("DAGU_TEST_REAL_ACL_FS"); want != "" {
		var fs unix.Statfs_t
		require.NoError(t, unix.Statfs(dir, &fs))
		assert.Equal(t, want, formatMagic(uint32(fs.Type)), "the fixtures run on the filesystem asked for") //nolint:gosec // a statfs magic
		require.False(t, t.Failed())
	}
	return dir
}

func formatMagic(m uint32) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 8)
	for shift := 28; shift >= 0; shift -= 4 {
		out = append(out, hex[(m>>uint(shift))&0xF])
	}
	return string(out)
}

// setACL sets the list name on path, failing the fixture (not skipping
// it) when the filesystem refuses.
func setACL(t *testing.T, path, name string, entries ...posixEntry) {
	t.Helper()
	require.NoError(t, unix.Setxattr(path, name, posixACL(entries...), 0), "set %s on %s", name, path)
}

// Read from the kernel through the gate's own reader:
//   - a list that only repeats the mode bits is not kept (the kernel
//     folds it into the mode), so the profile reads as having none, and
//     passes;
//   - a list the kernel keeps, with a named entry for this user under a
//     mask that grants nothing, passes: an extended list that lets no
//     one else in;
//   - a named entry for another account, even one the mask hides, is
//     refused on the profile directory and on an entry;
//   - an inheritable write in a directory's default list is refused.
func TestRealACLReaderOnThisFilesystem(t *testing.T) {
	t.Parallel()
	const nobody = 65534
	euid := uint32(os.Geteuid()) //nolint:gosec // a uid
	require.NotZero(t, euid, "the fixtures run as an ordinary user")
	none := func(tag uint16) posixEntry { return posixEntry{tag, 0, posixUndefinedID} }

	folded := filepath.Join(realACLDir(t), "profile")
	require.NoError(t, os.Mkdir(folded, 0o700))
	setACL(t, folded, "system.posix_acl_access", posixEntry{posixUserObj, 7, posixUndefinedID}, none(posixGroupObj), none(posixOther))
	f, err := openTrusted(folded)
	require.NoError(t, err, "a list that only repeats the mode")
	_, present, err := getXattr(int(f.Fd()), "system.posix_acl_access") //nolint:gosec // a descriptor
	require.NoError(t, err)
	assert.False(t, present, "the kernel folded the list into the mode")
	require.NoError(t, f.Close())

	kept := filepath.Join(realACLDir(t), "profile")
	require.NoError(t, os.Mkdir(kept, 0o700))
	setACL(t, kept, "system.posix_acl_access",
		posixEntry{posixUserObj, 7, posixUndefinedID}, namedUser(euid, 7), none(posixGroupObj), mask(0), none(posixOther))
	f, err = openTrusted(kept)
	require.NoError(t, err, "an extended list that lets no one else in")
	raw, present, err := getXattr(int(f.Fd()), "system.posix_acl_access") //nolint:gosec // a descriptor
	require.NoError(t, err)
	require.True(t, present, "the kernel kept the extended list")
	entries, err := parsePOSIXACL(raw)
	require.NoError(t, err)
	assert.Contains(t, entries, namedUser(euid, 7), "the reader read the list the kernel kept")
	require.NoError(t, f.Close())

	opened := filepath.Join(realACLDir(t), "profile")
	require.NoError(t, os.Mkdir(opened, 0o700))
	setACL(t, opened, "system.posix_acl_access",
		posixEntry{posixUserObj, 7, posixUndefinedID}, namedUser(nobody, 4), none(posixGroupObj), mask(0), none(posixOther))
	_, err = openTrusted(opened)
	assert.ErrorContains(t, err, "opens the profile directory", "a named read on the profile directory, masked off")

	dir := testProfileDirIn(t, realACLDir(t))
	root, err := OpenProfileRoot(dir)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	file := filepath.Join(dir, "Preferences")
	require.NoError(t, os.WriteFile(file, []byte("{}"), 0o600))
	setACL(t, file, "system.posix_acl_access",
		posixEntry{posixUserObj, 6, posixUndefinedID}, namedUser(nobody, 6), none(posixGroupObj), mask(0), none(posixOther))
	info, err := os.Stat(file)
	require.NoError(t, err)
	require.Zero(t, info.Mode().Perm()&0o077, "the mask hides the named write from the mode bits")
	_, err = OpenProfileEntry(root, "Preferences", false)
	assert.ErrorContains(t, err, "lets another account change", "the reader, not the mode, refuses it")

	inherit := filepath.Join(dir, "Default")
	require.NoError(t, os.Mkdir(inherit, 0o700))
	setACL(t, inherit, "system.posix_acl_default",
		posixEntry{posixUserObj, 7, posixUndefinedID}, namedUser(nobody, 6), none(posixGroupObj), mask(6), none(posixOther))
	_, err = OpenProfileEntry(root, "Default", true)
	assert.ErrorContains(t, err, "what is created in")

	plain := filepath.Join(dir, "Plain")
	require.NoError(t, os.Mkdir(plain, 0o700))
	setACL(t, plain, "system.posix_acl_default",
		posixEntry{posixUserObj, 7, posixUndefinedID}, none(posixGroupObj), none(posixOther))
	f, err = OpenProfileEntry(root, "Plain", true)
	require.NoError(t, err, "a default list that lets only the owner write")
	require.NoError(t, f.Close())
}

// testProfileDirIn is testProfileDir in parent.
func testProfileDirIn(t *testing.T, parent string) string {
	t.Helper()
	dir := filepath.Join(parent, "profile")
	require.NoError(t, os.Mkdir(dir, 0o700))
	return dir
}

// On an overlay, a directory from a lower layer is copied up when it is
// first written, and may come back as a different object. The gate checks
// each start afresh, so the profile is opened, written and opened again,
// and each opening must find the directory it walked to be the one its
// Root holds (OpenProfileRoot refuses a mismatch). The lower directory is
// DAGU_TEST_REAL_ACL_LOWER, a directory this user owns, 0700, that the
// overlay has not copied up yet.
func TestRealOverlayCopyUpKeepsTheProfileChecked(t *testing.T) {
	if os.Getenv("DAGU_TEST_REAL_ACL") != "1" {
		t.Skip("real access control list fixtures run only with DAGU_TEST_REAL_ACL=1")
	}
	lower := os.Getenv("DAGU_TEST_REAL_ACL_LOWER")
	require.NotEmpty(t, lower, "DAGU_TEST_REAL_ACL_LOWER names a lower-layer directory")
	var fs unix.Statfs_t
	require.NoError(t, unix.Statfs(lower, &fs))
	require.Equal(t, "794c7630", formatMagic(uint32(fs.Type)), "the lower directory is seen through an overlay") //nolint:gosec // a statfs magic

	before, err := os.Stat(lower)
	require.NoError(t, err)
	root, err := OpenProfileRoot(lower)
	require.NoError(t, err, "before the copy-up")
	require.NoError(t, root.Close())
	// A walk done before the copy-up, bridged after it: the bridge must
	// refuse it if the copy-up changed what the path names.
	stale, err := openTrusted(lower)
	require.NoError(t, err)
	defer func() { _ = stale.Close() }()

	marker := filepath.Join(lower, "copy-up")
	t.Cleanup(func() {
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove %s: %v", marker, err)
		}
	})
	require.NoError(t, os.WriteFile(marker, []byte("x"), 0o600))
	after, err := os.Stat(lower)
	require.NoError(t, err)
	kept := os.SameFile(before, after)
	t.Logf("copy-up kept the directory's identity: %v", kept)
	bridged, err := bridgeRoot(stale, lower)
	if kept {
		require.NoError(t, err)
		require.NoError(t, bridged.Close())
	} else {
		assert.ErrorContains(t, err, "changed while it was opened", "a stale walk is refused, not trusted")
	}

	root, err = OpenProfileRoot(lower)
	require.NoError(t, err, "after the copy-up, opened afresh")
	defer func() { _ = root.Close() }()
	f, err := OpenProfileEntry(root, "copy-up", false)
	require.NoError(t, err)
	require.NotNil(t, f)
	require.NoError(t, f.Close())
}
