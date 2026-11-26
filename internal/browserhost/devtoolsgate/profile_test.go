// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readPrefs(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var prefs map[string]any
	require.NoError(t, json.Unmarshal(raw, &prefs))
	return prefs
}

// testProfileDir is a new, empty profile directory only this user may
// write, as the gate's own profiles are made (0700), whatever the umask:
// t.TempDir's own directory takes its mode from the umask.
func testProfileDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profile")
	require.NoError(t, os.Mkdir(dir, 0o700))
	return dir
}

// ownedProfile is a profile directory created for the gate and claimed.
func ownedProfile(t *testing.T) string {
	t.Helper()
	dir := testProfileDir(t)
	require.NoError(t, claimProfile(dir))
	return dir
}

// The gate turns windows off the record off in its own profile before the
// browser starts: in a new profile, and in one the browser already wrote,
// whose other preferences, numbers included, stay as they were.
func TestDisableOffTheRecordSetsTheProfilePreference(t *testing.T) {
	t.Parallel()
	fresh := ownedProfile(t)
	require.NoError(t, disableOffTheRecord([]string{"--headless", "--user-data-dir=" + fresh}))
	prefs := readPrefs(t, filepath.Join(fresh, "Default", "Preferences"))
	assert.Equal(t, map[string]any{"mode_availability": float64(offTheRecordDisabled)}, prefs["incognito"])

	used := ownedProfile(t)
	require.NoError(t, os.MkdirAll(filepath.Join(used, "Work"), 0o700))
	written := `{"browser":{"window":{"x":12345678901234567}},"incognito":{"mode_availability":0,"other":"kept"},"profile":{"name":"p"}}`
	require.NoError(t, os.WriteFile(filepath.Join(used, "Work", "Preferences"), []byte(written), 0o600))
	// The browser reads the last of a repeated switch.
	require.NoError(t, disableOffTheRecord([]string{"--user-data-dir=" + fresh, "--user-data-dir=" + used, "--profile-directory=Work"}))
	raw, err := os.ReadFile(filepath.Join(used, "Work", "Preferences"))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"x":12345678901234567`, "numbers stay as the browser wrote them")
	prefs = readPrefs(t, filepath.Join(used, "Work", "Preferences"))
	assert.Equal(t, map[string]any{"mode_availability": float64(offTheRecordDisabled), "other": "kept"}, prefs["incognito"])
	assert.Equal(t, map[string]any{"name": "p"}, prefs["profile"])
	info, err := os.Stat(filepath.Join(used, "Work", "Preferences"))
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Join(used, "Work"))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary file is left behind")

	// Claiming again changes nothing.
	require.NoError(t, claimProfile(used))
}

// A browser on a profile the gate was not given as its own is not started,
// and the profile is left as it was: a person's or a shared profile, one
// named by a relative path or none, or preferences the gate cannot read.
func TestDisableOffTheRecordRefusesAProfileThatIsNotTheGates(t *testing.T) {
	t.Parallel()
	assert.ErrorIs(t, disableOffTheRecord([]string{"--headless"}), ErrProfileRequired)
	assert.ErrorIs(t, disableOffTheRecord([]string{"--user-data-dir="}), ErrProfileRequired)
	assert.ErrorIs(t, disableOffTheRecord([]string{"--user-data-dir=relative/profile"}), ErrProfileRequired)
	assert.ErrorIs(t, claimProfile("relative/profile"), ErrProfileRequired)

	persons := testProfileDir(t)
	require.NoError(t, os.MkdirAll(filepath.Join(persons, "Default"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(persons, "Default", "Preferences"), []byte(`{"a":1}`), 0o600))
	assert.ErrorIs(t, disableOffTheRecord([]string{"--user-data-dir=" + persons}), ErrProfileNotOwned)
	raw, err := os.ReadFile(filepath.Join(persons, "Default", "Preferences"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":1}`, string(raw), "a profile that is not the gate's is left as it was")

	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	assert.Error(t, claimProfile(file))

	dir := ownedProfile(t)
	for _, profile := range []string{"", ".", "..", "../x", "a/b", `a\b`} {
		assert.Error(t, disableOffTheRecord([]string{"--user-data-dir=" + dir, "--profile-directory=" + profile}), profile)
	}
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "Default"), 0o700))
	for _, broken := range []string{"not json", "[]", "null"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "Default", "Preferences"), []byte(broken), 0o600))
		assert.ErrorContains(t, disableOffTheRecord([]string{"--user-data-dir=" + dir}), "not a JSON object", broken)
		raw, err := os.ReadFile(filepath.Join(dir, "Default", "Preferences"))
		require.NoError(t, err)
		assert.Equal(t, broken, string(raw))
	}
}

// Config refuses a browser whose arguments name no profile, or one by a
// relative path, before anything starts.
func TestConfigRefusesABrowserWithoutAnAbsoluteProfile(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--headless"}, {"--user-data-dir="}, {"--user-data-dir=profile"}} {
		assert.ErrorIs(t, Config{Token: NewToken(), Executable: "/usr/bin/chrome", Args: args}.validate(), ErrProfileRequired, "%v", args)
	}
}
