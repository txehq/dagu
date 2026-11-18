// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package browser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/browserhost/devtoolsgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snapshotDir returns every file under dir with a hash of its bytes, and
// every directory, so a test can tell the tree was left as it was.
func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	require.NoError(t, filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		if entry.IsDir() {
			snapshot[rel] = "dir"
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		snapshot[rel] = hex.EncodeToString(sum[:])
		return nil
	}))
	return snapshot
}

// oldProfile makes a named profile as one made before Dagu marked its
// profiles, with preferences and a cookie jar, and returns its directory.
func oldProfile(t *testing.T, browserDir, name, prefs string) string {
	t.Helper()
	dir := filepath.Join(browserDir, profilesDirName, name)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "Default"), 0o700))
	if prefs != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "Default", "Preferences"), []byte(prefs), 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Default", "Cookies"), []byte("a person's logins"), 0o600))
	return dir
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var value map[string]any
	require.NoError(t, json.Unmarshal(raw, &value))
	return value
}

// A named profile that does not exist yet is created by the lease that
// first takes it, and is the gate's own.
func TestAcquireProfileCreatesAnOwnedProfile(t *testing.T) {
	t.Parallel()
	browserDir := t.TempDir()
	lease, err := acquireProfile(context.Background(), browserDir, "fresh", "rec", false)
	require.NoError(t, err)
	defer lease.release()
	assert.True(t, devtoolsgate.ProfileClaimed(lease.dir))
}

// A named profile made before Dagu marked its profiles is refused, with
// the way to claim it, and left exactly as it was: no mark, no file
// written, its logins kept.
func TestAcquireProfileRefusesAnUnclaimedProfileAndLeavesItAsItWas(t *testing.T) {
	t.Parallel()
	browserDir := t.TempDir()
	dir := oldProfile(t, browserDir, "old", `{"profile":{"name":"old"}}`)
	before := snapshotDir(t, dir)
	_, err := acquireProfile(context.Background(), browserDir, "old", "rec", false)
	var unclaimed *profileUnclaimedError
	require.True(t, errors.As(err, &unclaimed), "%v", err)
	assert.ErrorContains(t, err, `dagu browser profile claim old`)
	assert.ErrorContains(t, err, "logins and cookies")
	assert.Equal(t, before, snapshotDir(t, dir), "the profile is left as it was")
	assert.False(t, devtoolsgate.ProfileClaimed(dir))
}

// A claim keeps a copy of the profile's preferences and the value Dagu's
// browsers change, and marks the profile; a step may then use it. Its undo
// puts the value back and keeps what the browser wrote since; a step
// refuses the profile again.
func TestClaimProfileAndItsUndo(t *testing.T) {
	t.Parallel()
	browserDir := t.TempDir()
	original := `{"incognito":{"mode_availability":0,"other":"kept"},"profile":{"name":"old"}}`
	dir := oldProfile(t, browserDir, "old", original)
	prefs := filepath.Join(dir, "Default", "Preferences")

	report, err := ClaimProfile(browserDir, "old")
	require.NoError(t, err)
	assert.True(t, report.Claimed)
	assert.True(t, report.Changed)
	assert.JSONEq(t, "0", string(report.PreviousValue))
	assert.Equal(t, prefs+claimBackupSuffix, report.Backup)
	backup, err := os.ReadFile(report.Backup)
	require.NoError(t, err)
	assert.Equal(t, original, string(backup), "the copy is the preferences as they were")
	assert.Equal(t, "dagu browser profile unclaim old", report.Undo)
	assert.Contains(t, report.Change, "incognito.mode_availability = 1")
	assert.True(t, devtoolsgate.ProfileClaimed(dir))

	again, err := ClaimProfile(browserDir, "old")
	require.NoError(t, err)
	assert.False(t, again.Changed, "a second claim changes nothing")

	lease, err := acquireProfile(context.Background(), browserDir, "old", "rec", false)
	require.NoError(t, err)
	lease.release()

	// What a browser started on the claimed profile leaves: the gate's
	// value, and a preference of its own.
	require.NoError(t, os.WriteFile(prefs, []byte(`{"incognito":{"mode_availability":1,"other":"kept"},"profile":{"name":"old"},"later":true}`), 0o600))
	undone, err := UnclaimProfile(browserDir, "old")
	require.NoError(t, err)
	assert.True(t, undone.Changed)
	assert.Equal(t, prefs+claimBackupSuffix, undone.Backup, "the copy stays")
	restored := readJSON(t, prefs)
	assert.Equal(t, map[string]any{"mode_availability": float64(0), "other": "kept"}, restored["incognito"])
	assert.Equal(t, true, restored["later"], "what the browser wrote since is kept")
	assert.False(t, devtoolsgate.ProfileClaimed(dir))
	_, err = os.Lstat(filepath.Join(dir, claimRecordName))
	assert.ErrorIs(t, err, os.ErrNotExist)

	_, err = acquireProfile(context.Background(), browserDir, "old", "rec", false)
	var unclaimed *profileUnclaimedError
	assert.True(t, errors.As(err, &unclaimed), "%v", err)
}

// A profile without preferences yet is claimed with nothing to copy; its
// undo removes the value the gate set.
func TestClaimProfileWithoutPreferences(t *testing.T) {
	t.Parallel()
	browserDir := t.TempDir()
	dir := oldProfile(t, browserDir, "bare", "")
	report, err := ClaimProfile(browserDir, "bare")
	require.NoError(t, err)
	assert.JSONEq(t, "null", string(report.PreviousValue))
	assert.Empty(t, report.Backup)
	prefs := filepath.Join(dir, "Default", "Preferences")
	require.NoError(t, os.WriteFile(prefs, []byte(`{"incognito":{"mode_availability":1},"kept":1}`), 0o600))
	_, err = UnclaimProfile(browserDir, "bare")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"kept": float64(1)}, readJSON(t, prefs))
}

// A claim is refused, and leaves the profile as it was, for a name that is
// not a profile's, one that does not exist, one in use, and one that is
// not exactly where its name says.
func TestClaimProfileRefusals(t *testing.T) {
	t.Parallel()
	browserDir := t.TempDir()
	_, err := ClaimProfile(browserDir, "../elsewhere")
	assert.ErrorContains(t, err, "not a profile name")
	_, err = ClaimProfile(browserDir, "missing")
	assert.ErrorContains(t, err, "no browser profile")

	dir := oldProfile(t, browserDir, "busy", `{"a":1}`)
	before := snapshotDir(t, dir)
	lease, err := acquireProfileLockOnly(t, browserDir, "busy")
	require.NoError(t, err)
	_, err = ClaimProfile(browserDir, "busy")
	var held *profileHeldError
	assert.True(t, errors.As(err, &held), "%v", err)
	assert.Equal(t, before, snapshotDir(t, dir))
	lease()

	if runtime.GOOS != "windows" {
		elsewhere := t.TempDir()
		require.NoError(t, os.Symlink(elsewhere, filepath.Join(browserDir, profilesDirName, "linked")))
		_, err = ClaimProfile(browserDir, "linked")
		assert.ErrorContains(t, err, "not a directory of its own")
		assert.False(t, devtoolsgate.ProfileClaimed(elsewhere))

		shared := oldProfile(t, browserDir, "shared", `{"a":1}`)
		require.NoError(t, os.Chmod(shared, 0o777))
		before := snapshotDir(t, shared)
		_, err = ClaimProfile(browserDir, "shared")
		assert.ErrorContains(t, err, "others may write")
		assert.Equal(t, before, snapshotDir(t, shared), "a refused claim leaves no copy and no record")
	}
}

// acquireProfileLockOnly holds the named profile's lease as a running step
// would, without creating or checking the profile, and returns its release.
func acquireProfileLockOnly(t *testing.T, browserDir, name string) (func(), error) {
	t.Helper()
	dir, unlock, err := holdExistingProfile(browserDir, name)
	if err != nil {
		return nil, err
	}
	_ = dir
	return unlock, nil
}
