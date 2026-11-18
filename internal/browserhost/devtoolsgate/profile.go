// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The browser the gate starts runs every target in its own context
// (mux.go). The gate closes a target it is told of in any other, but Chrome
// sends the first request of a window opened already navigating before the
// gate can hold it, so the gate also has the browser refuse windows off the
// record: before the browser starts, the profile's preferences turn them
// off, and before the gate serves anyone it checks that the browser does
// refuse one (preflight.go), since a platform policy outranks a profile.
//
// The gate changes the preferences of a profile only when the profile is
// its own, never a person's or a shared one:
//
//   - The profile is the --user-data-dir the browser's arguments name, the
//     last one as the browser reads it, which must be an absolute path; the
//     profile within it is --profile-directory, or "Default". There is no
//     default directory: arguments that name none are refused.
//   - It is the gate's when it holds the marker that NewProfile and
//     NewTempProfile leave in the same call that creates the directory: a
//     directory that already existed is never marked on the way. A
//     directory without the marker is refused and left as it is. The one
//     way to mark a directory that existed before is ClaimExistingProfile,
//     for an explicit claim a person asks for (dagu browser profile claim),
//     after its own checks.
//   - The directory, the profile within it and its Preferences are refused
//     when any is a symbolic link; on Unix the directory must belong to this
//     user and be writable by nobody else.
//   - A profile a running browser holds is refused: the gate does not
//     change preferences under a browser that would write its own back. A
//     browser still ending, as when a browser is started again on the
//     profile it just used, is given profileReleaseWait to let go.
//   - Preferences are merged: every other preference stays as it was,
//     numbers included, and the file is replaced in one rename.
//   - The previous value is not put back. The profile is the gate's, and the
//     preference is its policy for every browser it starts there.
//
// On Windows the directory's owner and access are not checked
// (profile_windows.go): the gate's isolation of its own profiles there is
// unproven.

// ErrProfileRequired is returned for a browser whose arguments name no
// profile directory of its own.
var ErrProfileRequired = errors.New("devtools gate: the browser needs a profile directory of its own (--user-data-dir, an absolute path)")

// ErrProfileNotOwned is returned for a profile directory the gate was not
// given as its own (NewProfile, NewTempProfile or ClaimExistingProfile).
var ErrProfileNotOwned = errors.New("devtools gate: the profile directory is not one created for the browsers the gate starts")

// ErrProfileInUse is returned for a profile a running browser holds.
var ErrProfileInUse = errors.New("devtools gate: a running browser holds the profile directory")

// profileMarker is the file that marks a profile directory as the gate's.
const profileMarker = ".dagu-devtools-gate-profile"

// profileReleaseWait is how long a profile a browser still holds is given
// to be let go of, and profileReleasePoll how often it is looked at.
const (
	profileReleaseWait = browserExitGrace
	profileReleasePoll = 100 * time.Millisecond
)

// profileReleased reports whether no running browser holds the profile, or
// none does within profileReleaseWait.
func profileReleased(userDataDir string) bool {
	deadline := time.Now().Add(profileReleaseWait)
	for profileInUse(userDataDir) {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(profileReleasePoll)
	}
	return true
}

// offTheRecordDisabled is the value of the profile preference
// incognito.mode_availability that turns off-the-record windows off.
const offTheRecordDisabled = 1

// NewProfile creates dir, which must not exist yet, as a profile directory
// of the gate's own for the browsers it starts. A directory that exists is
// refused (fs.ErrExist) and left as it is.
func NewProfile(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return ErrProfileRequired
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if err := claimProfile(dir); err != nil {
		_ = os.Remove(dir)
		return err
	}
	return nil
}

// NewTempProfile creates a new temporary profile directory of the gate's
// own, as os.MkdirTemp does with parent and pattern, and returns it.
func NewTempProfile(parent, pattern string) (string, error) {
	dir, err := os.MkdirTemp(parent, pattern)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(dir) {
		_ = os.Remove(dir)
		return "", ErrProfileRequired
	}
	if err := claimProfile(dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// ProfileClaimed reports whether dir holds the gate's marker.
func ProfileClaimed(dir string) bool {
	info, err := os.Lstat(filepath.Join(dir, profileMarker))
	return err == nil && info.Mode().IsRegular()
}

// ClaimExistingProfile marks dir, a profile directory that existed before,
// as the gate's own. It is for an explicit claim a person asks for, never a
// step's launch: the caller has checked the directory is the one meant and
// that no browser holds it. It refuses a directory the gate would refuse to
// start a browser on, and a running browser's.
func ClaimExistingProfile(dir string) error {
	if ProfileInUse(dir) {
		return fmt.Errorf("%w: %s", ErrProfileInUse, dir)
	}
	return claimProfile(dir)
}

// ReleaseProfileClaim removes the gate's marker from dir, undoing a claim.
// What the gate wrote in the profile's preferences stays.
func ReleaseProfileClaim(dir string) error {
	if err := checkProfileDir(dir); err != nil {
		return err
	}
	marker := filepath.Join(dir, profileMarker)
	info, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("devtools gate: the profile marker is not a regular file: %s", marker)
	}
	return os.Remove(marker)
}

// ProfileInUse reports whether a running browser holds the profile dir.
func ProfileInUse(dir string) bool {
	return profileInUse(dir)
}

// claimProfile leaves the gate's marker in dir, after the checks the gate
// makes before it starts a browser there.
func claimProfile(dir string) error {
	if err := checkProfileDir(dir); err != nil {
		return err
	}
	marker := filepath.Join(dir, profileMarker)
	if info, err := os.Lstat(marker); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("devtools gate: the profile marker is not a regular file: %s", marker)
		}
		return nil
	}
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a new file in the directory checked above
	if err != nil {
		return fmt.Errorf("devtools gate: claim the profile directory: %w", err)
	}
	return file.Close()
}

// profileDirs returns the profile directory args name, the last
// --user-data-dir= and --profile-directory= as the browser reads them, and
// the profile within it ("Default" unless named).
func profileDirs(args []string) (userDataDir, profile string) {
	profile = "Default"
	for _, arg := range args {
		if value, ok := strings.CutPrefix(arg, "--user-data-dir="); ok {
			userDataDir = value
		}
		if value, ok := strings.CutPrefix(arg, "--profile-directory="); ok {
			profile = value
		}
	}
	return userDataDir, profile
}

// checkProfileDir refuses a profile directory that is not an absolute path
// to a real directory this user alone may write.
func checkProfileDir(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return ErrProfileRequired
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("devtools gate: the profile directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("devtools gate: the profile directory is a symbolic link: %s", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("devtools gate: the profile directory is not a directory: %s", dir)
	}
	return checkProfileOwner(dir, info)
}

// disableOffTheRecord sets incognito.mode_availability in the preferences
// of the profile args name, keeping every other preference as it is, once
// the profile is found to be the gate's own and not in use.
func disableOffTheRecord(args []string) error {
	userDataDir, profile := profileDirs(args)
	if err := checkProfileDir(userDataDir); err != nil {
		return err
	}
	if marker, err := os.Lstat(filepath.Join(userDataDir, profileMarker)); err != nil || !marker.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrProfileNotOwned, userDataDir)
	}
	if !profileReleased(userDataDir) {
		return fmt.Errorf("%w: %s", ErrProfileInUse, userDataDir)
	}
	if profile == "" || profile == "." || profile == ".." || filepath.Base(profile) != profile || strings.ContainsAny(profile, `/\`) {
		return fmt.Errorf("devtools gate: the profile %q is not a single directory name", profile)
	}
	dir := filepath.Join(userDataDir, profile)
	switch info, err := os.Lstat(dir); {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(dir, 0o700); err != nil {
			return fmt.Errorf("devtools gate: create the profile: %w", err)
		}
	case err != nil:
		return fmt.Errorf("devtools gate: the profile: %w", err)
	case !info.IsDir() || info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("devtools gate: the profile is not a directory: %s", dir)
	}
	path := filepath.Join(dir, "Preferences")
	prefs := map[string]any{}
	switch info, err := os.Lstat(path); {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("devtools gate: the profile's preferences: %w", err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("devtools gate: the profile's preferences are not a regular file: %s", path)
	default:
		raw, err := os.ReadFile(path) //nolint:gosec // the gate's own profile's preferences, checked above
		if err != nil {
			return fmt.Errorf("devtools gate: read the profile's preferences: %w", err)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		// Numbers stay as the browser wrote them.
		decoder.UseNumber()
		if err := decoder.Decode(&prefs); err != nil || prefs == nil {
			return fmt.Errorf("devtools gate: the profile's preferences are not a JSON object: %s", path)
		}
	}
	incognito, _ := prefs["incognito"].(map[string]any)
	if incognito == nil {
		incognito = map[string]any{}
	}
	incognito["mode_availability"] = offTheRecordDisabled
	prefs["incognito"] = incognito
	encoded, err := json.Marshal(prefs)
	if err != nil {
		return fmt.Errorf("devtools gate: encode the profile's preferences: %w", err)
	}
	temp, err := os.CreateTemp(dir, "Preferences.gate-*")
	if err != nil {
		return fmt.Errorf("devtools gate: write the profile's preferences: %w", err)
	}
	_, writeErr := temp.Write(encoded)
	closeErr := temp.Close()
	if err := errors.Join(writeErr, closeErr, os.Chmod(temp.Name(), 0o600)); err != nil {
		_ = os.Remove(temp.Name())
		return fmt.Errorf("devtools gate: write the profile's preferences: %w", err)
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		_ = os.Remove(temp.Name())
		return fmt.Errorf("devtools gate: write the profile's preferences: %w", err)
	}
	return nil
}
