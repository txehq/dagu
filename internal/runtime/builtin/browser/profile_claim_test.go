// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package browser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/browserhost/devtoolsgate"
	"github.com/dagucloud/dagu/v2/internal/cmn/dirlock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snapshotDir returns every entry under dir with its mode, modification
// time and, for a file, a hash of its bytes. A directory's modification
// time changes when an entry is made in it or removed from it, so a file
// written and removed again shows too: an unchanged snapshot means nothing
// was written.
func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	require.NoError(t, filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		state := fmt.Sprintf("%v %d", info.Mode(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(raw)
			state += " " + hex.EncodeToString(sum[:])
		}
		snapshot[rel] = state
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
	// Modification times a later write would move.
	past := time.Now().Add(-time.Hour)
	require.NoError(t, filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, past, past)
	}))
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
// the way to claim it, and nothing is written in it.
func TestAcquireProfileRefusesAnUnclaimedProfileAndWritesNothing(t *testing.T) {
	t.Parallel()
	browserDir := t.TempDir()
	dir := oldProfile(t, browserDir, "old", `{"profile":{"name":"old"}}`)
	before := snapshotDir(t, dir)
	_, err := acquireProfile(context.Background(), browserDir, "old", "rec", false)
	var unclaimed *profileUnclaimedError
	require.True(t, errors.As(err, &unclaimed), "%v", err)
	assert.ErrorContains(t, err, `dagu browser profile claim old`)
	assert.ErrorContains(t, err, "logins and cookies")
	assert.Equal(t, before, snapshotDir(t, dir), "nothing is written in the profile")
}

// A claim keeps a copy of the profile's preferences and the value Dagu's
// browsers change, changes no preference, and marks the profile; a step
// may then use it. Its undo puts the value back, keeps what the browser
// wrote since and the copy, and removes the mark and the record.
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
	require.True(t, strings.HasPrefix(report.Backup, filepath.Join(dir, "Default", claimBackupPrefix)), report.Backup)
	backup, err := os.ReadFile(report.Backup)
	require.NoError(t, err)
	assert.Equal(t, original, string(backup), "the copy is the preferences as they were")
	current, err := os.ReadFile(prefs)
	require.NoError(t, err)
	assert.Equal(t, original, string(current), "the claim changes no preference")
	for _, written := range []string{report.Backup, filepath.Join(dir, claimRecordName)} {
		info, err := os.Lstat(written)
		require.NoError(t, err)
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), written)
		}
	}
	assert.Equal(t, "dagu browser profile unclaim old", report.Undo)
	assert.Contains(t, report.Change, "incognito.mode_availability = 1")
	assert.True(t, devtoolsgate.ProfileClaimed(dir))

	again, err := ClaimProfile(browserDir, "old")
	require.NoError(t, err)
	assert.False(t, again.Changed, "a second claim changes nothing")
	assert.Equal(t, report.Backup, again.Backup)

	lease, err := acquireProfile(context.Background(), browserDir, "old", "rec", false)
	require.NoError(t, err)
	lease.release()

	// What a browser started on the claimed profile leaves: the gate's
	// value, and a preference of its own.
	require.NoError(t, os.WriteFile(prefs, []byte(`{"incognito":{"mode_availability":1,"other":"kept"},"profile":{"name":"old"},"later":true}`), 0o600))
	undone, err := UnclaimProfile(browserDir, "old")
	require.NoError(t, err)
	assert.True(t, undone.Changed)
	assert.Equal(t, report.Backup, undone.Backup, "the copy stays")
	_, err = os.Lstat(report.Backup)
	assert.NoError(t, err)
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

// Every refused claim writes nothing in the profile: the checks all come
// before the first write.
func TestClaimProfileRefusalsWriteNothing(t *testing.T) {
	t.Parallel()
	browserDir := t.TempDir()
	_, err := ClaimProfile(browserDir, "../elsewhere")
	assert.ErrorContains(t, err, "not a profile name")
	_, err = ClaimProfile(browserDir, "missing")
	assert.ErrorContains(t, err, "no browser profile")

	refuse := func(t *testing.T, name, want string, setup func(dir string)) {
		t.Helper()
		dir := oldProfile(t, browserDir, name, `{"a":1}`)
		setup(dir)
		before := snapshotDir(t, dir)
		_, err := ClaimProfile(browserDir, name)
		assert.ErrorContains(t, err, want)
		assert.Equal(t, before, snapshotDir(t, dir), "%s: nothing is written", name)
		assert.False(t, devtoolsgate.ProfileClaimed(dir))
	}
	refuse(t, "busy", "in use by a running browser step", func(dir string) {
		held, err := holdExistingProfile(browserDir, "busy")
		require.NoError(t, err)
		t.Cleanup(held.release)
	})
	refuse(t, "stale-record", "a claim record is already there", func(dir string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, claimRecordName), []byte(`{}`), 0o600))
	})
	refuse(t, "odd-mark", "not a regular file", func(dir string) {
		require.NoError(t, os.Mkdir(filepath.Join(dir, ".dagu-devtools-gate-profile"), 0o700))
	})
	if runtime.GOOS == "windows" {
		return
	}
	refuse(t, "shared", "others may write", func(dir string) {
		require.NoError(t, os.Chmod(dir, 0o777))
	})
	// Not only the profile directory: each entry the claim reads or writes.
	refuse(t, "shared-default", "others may write", func(dir string) {
		require.NoError(t, os.Chmod(filepath.Join(dir, "Default"), 0o777))
	})
	refuse(t, "shared-prefs", "others may write", func(dir string) {
		require.NoError(t, os.Chmod(filepath.Join(dir, "Default", "Preferences"), 0o666))
	})
	// A marker that is a link to a file made for something else claims
	// nothing, and is not taken for an earlier claim.
	refuse(t, "linked-mark", "has another link", func(dir string) {
		other := filepath.Join(t.TempDir(), "other")
		require.NoError(t, os.WriteFile(other, nil, 0o600))
		require.NoError(t, os.Link(other, filepath.Join(dir, ".dagu-devtools-gate-profile")))
	})
	elsewhere := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(elsewhere, "Preferences"), []byte(`{"theirs":1}`), 0o600))
	refuse(t, "linked-prefs", "not a regular file", func(dir string) {
		require.NoError(t, os.Remove(filepath.Join(dir, "Default", "Preferences")))
		require.NoError(t, os.Symlink(filepath.Join(elsewhere, "Preferences"), filepath.Join(dir, "Default", "Preferences")))
	})
	refuse(t, "linked-default", "not a directory", func(dir string) {
		require.NoError(t, os.RemoveAll(filepath.Join(dir, "Default")))
		require.NoError(t, os.Symlink(elsewhere, filepath.Join(dir, "Default")))
	})
	host, err := os.Hostname()
	require.NoError(t, err)
	refuse(t, "running", "open in a running browser", func(dir string) {
		require.NoError(t, os.Symlink(fmt.Sprintf("%s-%d", host, os.Getpid()), filepath.Join(dir, "SingletonLock")))
	})
	assert.Equal(t, map[string]any{"theirs": float64(1)}, readJSON(t, filepath.Join(elsewhere, "Preferences")), "a link's target is never written")

	linkedTarget := t.TempDir()
	require.NoError(t, os.Symlink(linkedTarget, filepath.Join(browserDir, profilesDirName, "linked")))
	before := snapshotDir(t, linkedTarget)
	_, err = ClaimProfile(browserDir, "linked")
	assert.ErrorContains(t, err, "not a directory of its own")
	assert.Equal(t, before, snapshotDir(t, linkedTarget))
}

// A claim whose mark fails removes what it wrote, having changed no
// preference; what it cannot remove it keeps, and names.
func TestClaimProfileThatFailsLeavesItsEvidence(t *testing.T) {
	t.Parallel()
	failMark := defaultClaimOps
	failMark.mark = func(*os.Root) error { return errors.New("the mark failed") }

	browserDir := t.TempDir()
	original := `{"incognito":{"mode_availability":0}}`
	dir := oldProfile(t, browserDir, "undone", original)
	before := snapshotDir(t, dir)
	_, err := claimProfileWith(browserDir, "undone", failMark)
	assert.ErrorContains(t, err, "the mark failed")
	// The snapshot sees writes that were undone: the refusals above write
	// nothing, where this claim wrote and removed.
	assert.NotEqual(t, before, snapshotDir(t, dir), "a write removed again still shows")
	entries, err := os.ReadDir(filepath.Join(dir, "Default"))
	require.NoError(t, err)
	assert.Len(t, entries, 2, "only Preferences and Cookies are left")
	_, err = os.Lstat(filepath.Join(dir, claimRecordName))
	assert.ErrorIs(t, err, os.ErrNotExist)
	raw, err := os.ReadFile(filepath.Join(dir, "Default", "Preferences"))
	require.NoError(t, err)
	assert.Equal(t, original, string(raw), "no preference changed")

	failBoth := failMark
	failBoth.remove = func(*os.Root, string) error { return errors.New("the removal failed") }
	dir = oldProfile(t, browserDir, "kept", original)
	_, err = claimProfileWith(browserDir, "kept", failBoth)
	assert.ErrorContains(t, err, "the mark failed")
	assert.ErrorContains(t, err, "could not be removed and are kept")
	assert.ErrorContains(t, err, claimRecordName)
	_, err = os.Lstat(filepath.Join(dir, claimRecordName))
	assert.NoError(t, err, "the record it could not remove is kept")
	raw, err = os.ReadFile(filepath.Join(dir, "Default", "Preferences"))
	require.NoError(t, err)
	assert.Equal(t, original, string(raw))
	assert.False(t, devtoolsgate.ProfileClaimed(dir))
}

// An undo that put the preference back but could not remove the mark keeps
// the record and the copy, and says so.
func TestUnclaimProfileThatFailsKeepsTheRecord(t *testing.T) {
	t.Parallel()
	browserDir := t.TempDir()
	dir := oldProfile(t, browserDir, "half", `{"incognito":{"mode_availability":0}}`)
	report, err := ClaimProfile(browserDir, "half")
	require.NoError(t, err)
	prefs := filepath.Join(dir, "Default", "Preferences")
	require.NoError(t, os.WriteFile(prefs, []byte(`{"incognito":{"mode_availability":1}}`), 0o600))

	failRelease := defaultClaimOps
	failRelease.release = func(*os.Root) error { return errors.New("the release failed") }
	_, err = unclaimProfileWith(browserDir, "half", failRelease)
	assert.ErrorContains(t, err, "the claim record and the copy of its preferences are kept")
	assert.Equal(t, map[string]any{"mode_availability": float64(0)}, readJSON(t, prefs)["incognito"])
	assert.True(t, devtoolsgate.ProfileClaimed(dir))
	_, err = os.Lstat(filepath.Join(dir, claimRecordName))
	assert.NoError(t, err)
	_, err = os.Lstat(report.Backup)
	assert.NoError(t, err)

	// The undo can be run again, and completes.
	_, err = UnclaimProfile(browserDir, "half")
	require.NoError(t, err)
	assert.False(t, devtoolsgate.ProfileClaimed(dir))
}

// A mark that was made but whose claim then failed (its file could not be
// closed, say) leaves a profile a browser may change. The claim then keeps
// the record and the copy of the preferences, so the undo still restores
// what the profile had.
func TestClaimProfileWhoseMarkMayBeMadeKeepsItsEvidence(t *testing.T) {
	t.Parallel()
	markThenFail := defaultClaimOps
	markThenFail.mark = func(root *os.Root) error {
		if err := devtoolsgate.ClaimExistingProfileRoot(root); err != nil {
			return err
		}
		return errors.New("the mark's file could not be closed")
	}
	browserDir := t.TempDir()
	original := `{"incognito":{"mode_availability":0}}`
	dir := oldProfile(t, browserDir, "marked", original)
	_, err := claimProfileWith(browserDir, "marked", markThenFail)
	assert.ErrorContains(t, err, "the mark's file could not be closed")
	assert.ErrorContains(t, err, "may be marked as claimed")
	assert.ErrorContains(t, err, "which are kept as they are")
	assert.True(t, devtoolsgate.ProfileClaimed(dir))
	_, err = os.Lstat(filepath.Join(dir, claimRecordName))
	require.NoError(t, err, "the record stays with the mark")

	// A browser changes the profile, and the undo puts back what it had.
	prefs := filepath.Join(dir, "Default", "Preferences")
	require.NoError(t, os.WriteFile(prefs, []byte(`{"incognito":{"mode_availability":1}}`), 0o600))
	_, err = UnclaimProfile(browserDir, "marked")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"mode_availability": float64(0)}, readJSON(t, prefs)["incognito"])
	assert.False(t, devtoolsgate.ProfileClaimed(dir))
}

// A claim keeps its lease while it works, and writes nothing once another
// holder took the lease from it: its checks run first, and every write
// follows a renewal that fails when the lease is no longer its own.
func TestClaimProfileThatLostItsLeaseWritesNothing(t *testing.T) {
	t.Parallel()
	browserDir := t.TempDir()
	dir := oldProfile(t, browserDir, "taken", `{"incognito":{"mode_availability":0}}`)
	lockDir := dir + profileLockSuffix
	var other dirlock.DirLock
	takeLease := defaultClaimOps
	takeLease.now = func() time.Time {
		// Another holder takes the lease while the claim is checking, as
		// one may once a lease that was not renewed went stale.
		require.NoError(t, os.RemoveAll(filepath.Join(lockDir, dirlock.LockDirectoryName)))
		other = dirlock.New(lockDir, nil)
		require.NoError(t, other.TryLock())
		return time.Now()
	}
	before := snapshotDir(t, dir)
	_, err := claimProfileWith(browserDir, "taken", takeLease)
	assert.ErrorContains(t, err, "its lease was lost before the next write")
	assert.Equal(t, before, snapshotDir(t, dir), "nothing in the profile was written")
	assert.False(t, devtoolsgate.ProfileClaimed(dir))
	require.NotNil(t, other)
	assert.True(t, other.IsHeldByMe(), "the other holder keeps the lease")
	require.NoError(t, other.Unlock())
}
