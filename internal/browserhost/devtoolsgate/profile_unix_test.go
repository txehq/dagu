// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package devtoolsgate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A symbolic link is never followed: not for the profile directory, the
// profile within it, its Preferences or the marker; what a link points to
// is left as it was.
func TestDisableOffTheRecordRefusesSymbolicLinks(t *testing.T) {
	t.Parallel()
	target := ownedProfile(t)
	link := filepath.Join(t.TempDir(), "profile")
	require.NoError(t, os.Symlink(target, link))
	assert.ErrorContains(t, ClaimProfile(link), "symbolic link")
	assert.ErrorContains(t, disableOffTheRecord([]string{"--user-data-dir=" + link}), "symbolic link")

	elsewhere := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(elsewhere, "Preferences"), []byte(`{"kept":true}`), 0o600))
	dir := ownedProfile(t)
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(dir, "Default")))
	assert.ErrorContains(t, disableOffTheRecord([]string{"--user-data-dir=" + dir}), "not a directory")

	dir = ownedProfile(t)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "Default"), 0o700))
	require.NoError(t, os.Symlink(filepath.Join(elsewhere, "Preferences"), filepath.Join(dir, "Default", "Preferences")))
	assert.ErrorContains(t, disableOffTheRecord([]string{"--user-data-dir=" + dir}), "not a regular file")
	raw, err := os.ReadFile(filepath.Join(elsewhere, "Preferences"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"kept":true}`, string(raw), "the link's target is left as it was")

	unmarked := t.TempDir()
	require.NoError(t, os.Symlink(filepath.Join(target, profileMarker), filepath.Join(unmarked, profileMarker)))
	assert.ErrorIs(t, disableOffTheRecord([]string{"--user-data-dir=" + unmarked}), ErrProfileNotOwned)
}

// A profile another user may write, or one a running browser holds, is
// refused; a lock a browser left when it ended is not.
func TestDisableOffTheRecordRefusesASharedOrRunningProfile(t *testing.T) {
	t.Parallel()
	shared := ownedProfile(t)
	require.NoError(t, os.Chmod(shared, 0o777))
	assert.ErrorContains(t, disableOffTheRecord([]string{"--user-data-dir=" + shared}), "others may write")
	assert.ErrorContains(t, ClaimProfile(shared), "others may write")

	host, err := os.Hostname()
	require.NoError(t, err)
	running := ownedProfile(t)
	require.NoError(t, os.Symlink(fmt.Sprintf("%s-%d", host, os.Getpid()), filepath.Join(running, "SingletonLock")))
	assert.ErrorIs(t, disableOffTheRecord([]string{"--user-data-dir=" + running}), ErrProfileInUse)
	_, err = os.Lstat(filepath.Join(running, "Default", "Preferences"))
	assert.ErrorIs(t, err, os.ErrNotExist, "nothing is written under a running browser")

	elsewhere := ownedProfile(t)
	require.NoError(t, os.Symlink("another-host-1", filepath.Join(elsewhere, "SingletonLock")))
	assert.ErrorIs(t, disableOffTheRecord([]string{"--user-data-dir=" + elsewhere}), ErrProfileInUse)

	ended := ownedProfile(t)
	// No process has id 0x7ffffffe.
	require.NoError(t, os.Symlink(fmt.Sprintf("%s-%d", host, 0x7ffffffe), filepath.Join(ended, "SingletonLock")))
	require.NoError(t, disableOffTheRecord([]string{"--user-data-dir=" + ended}))
}

// A browser still ending when the gate starts another on its profile, as
// the browser step does after it learns its user agent, is waited for.
func TestDisableOffTheRecordWaitsForAnEndingBrowser(t *testing.T) {
	t.Parallel()
	host, err := os.Hostname()
	require.NoError(t, err)
	ending := exec.Command("sleep", "1")
	require.NoError(t, ending.Start())
	go func() { _ = ending.Wait() }()
	dir := ownedProfile(t)
	require.NoError(t, os.Symlink(fmt.Sprintf("%s-%d", host, ending.Process.Pid), filepath.Join(dir, "SingletonLock")))
	started := time.Now()
	require.NoError(t, disableOffTheRecord([]string{"--user-data-dir=" + dir}))
	assert.Less(t, time.Since(started), profileReleaseWait, "the gate went on once the browser let go")
}
