// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || darwin

package devtoolsgate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The path to a profile is opened one directory at a time from "/", with
// no symbolic link followed, and a directory another account could change
// refuses it, wherever on the path it is. These run on the host's own
// filesystem, in a directory of the test's: they read real descriptors and
// real access control lists (none), without changing any list.
func TestOpenTrustedRefusesAPathAnotherAccountCouldChange(t *testing.T) {
	t.Parallel()
	base := privateTempDir(t)
	mkdir := func(path string, mode os.FileMode) string {
		t.Helper()
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.Mkdir(path, 0o700))
		require.NoError(t, os.Chmod(path, mode))
		return path
	}

	good := mkdir(filepath.Join(base, "good"), 0o700)
	opened, err := openTrusted(good)
	require.NoError(t, err)
	info, err := opened.Stat()
	require.NoError(t, err)
	want, err := os.Stat(good)
	require.NoError(t, err)
	assert.True(t, os.SameFile(info, want), "the profile directory is what the walk returns")
	require.NoError(t, opened.Close())

	shared := mkdir(filepath.Join(base, "shared"), 0o770)
	_, err = openTrusted(mkdir(filepath.Join(shared, "p"), 0o700))
	assert.ErrorContains(t, err, "others may write a directory on the profile's path")

	sticky := mkdir(filepath.Join(base, "sticky"), 0o777|os.ModeSticky)
	require.NoError(t, os.Chmod(sticky, 0o777|os.ModeSticky))
	_, err = openTrusted(mkdir(filepath.Join(sticky, "p"), 0o700))
	assert.ErrorContains(t, err, "others may write", "a sticky directory passes only when root owns it")

	target := mkdir(filepath.Join(base, "real"), 0o700)
	mkdir(filepath.Join(target, "p"), 0o700)
	require.NoError(t, os.Symlink(target, filepath.Join(base, "link")))
	_, err = openTrusted(filepath.Join(base, "link", "p"))
	assert.ErrorContains(t, err, "passes through a symbolic link")
	require.NoError(t, os.Symlink(filepath.Join(target, "p"), filepath.Join(base, "linked-profile")))
	_, err = openTrusted(filepath.Join(base, "linked-profile"))
	assert.ErrorContains(t, err, "passes through a symbolic link", "the profile directory itself")

	_, err = openTrusted(base + "/./good")
	assert.ErrorContains(t, err, "not canonical")
	_, err = openTrusted(base + "/good/")
	assert.ErrorContains(t, err, "not canonical")
	_, err = openTrusted("relative/p")
	assert.ErrorIs(t, err, ErrProfileRequired)

	for mode, want := range map[os.FileMode]string{0o750: "it must be 0700", 0o701: "it must be 0700", 0o720: "others may write"} {
		p := mkdir(filepath.Join(base, "mode-"+mode.String()[1:]), mode)
		_, err = openTrusted(p)
		assert.ErrorContains(t, err, want, mode.String())
	}

	file := filepath.Join(base, "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	_, err = openTrusted(file)
	assert.ErrorContains(t, err, "not a directory")
}

// An entry is opened without following a link and checked from the open
// file: a directory where a file is wanted, and the reverse, are refused.
func TestOpenEntryChecksWhatItOpened(t *testing.T) {
	t.Parallel()
	dir := testProfileDir(t)
	root, err := OpenProfileRoot(dir)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "d"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600))

	f, err := OpenProfileEntry(root, "f", false)
	require.NoError(t, err)
	require.NotNil(t, f)
	require.NoError(t, f.Close())
	f, err = OpenProfileEntry(root, "missing", false)
	assert.NoError(t, err)
	assert.Nil(t, f)
	_, err = OpenProfileEntry(root, "d", false)
	assert.ErrorContains(t, err, "not a regular file")
	_, err = OpenProfileEntry(root, "f", true)
	assert.ErrorContains(t, err, "not a directory")
	require.NoError(t, os.Symlink("f", filepath.Join(dir, "lf")))
	_, err = OpenProfileEntry(root, "lf", false)
	assert.ErrorContains(t, err, "a symbolic link is not followed")
}

// A FIFO where the gate wants a regular file is refused without waiting
// for a writer: as the marker, as the preferences and as any entry. Each
// call runs against a deadline, so a hang fails instead of stalling.
func TestEntriesThatAreFIFOsAreRefusedWithoutWaiting(t *testing.T) {
	t.Parallel()
	within := func(name string, call func() error) error {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: still waiting after 10s", name)
			return nil
		}
	}

	marked := testProfileDir(t)
	require.NoError(t, unix.Mkfifo(filepath.Join(marked, profileMarker), 0o600))
	assert.False(t, ProfileClaimed(marked), "a FIFO marks nothing")
	err := within("claim", func() error { return claimProfile(marked) })
	assert.ErrorContains(t, err, "not a regular file")
	err = within("start", func() error { return disableOffTheRecord([]string{"--user-data-dir=" + marked}) })
	assert.ErrorIs(t, err, ErrProfileNotOwned)

	prefs := ownedProfile(t)
	require.NoError(t, os.Mkdir(filepath.Join(prefs, "Default"), 0o700))
	require.NoError(t, unix.Mkfifo(filepath.Join(prefs, "Default", "Preferences"), 0o600))
	err = within("preferences", func() error { return disableOffTheRecord([]string{"--user-data-dir=" + prefs}) })
	assert.ErrorContains(t, err, "not a regular file")

	root, err := OpenProfileRoot(prefs)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	err = within("entry", func() error {
		f, err := OpenProfileEntry(root, "Default/Preferences", false)
		if f != nil {
			_ = f.Close()
		}
		return err
	})
	assert.ErrorContains(t, err, "not a regular file")
}
