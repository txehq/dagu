// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
//     way to mark a directory that existed before is ClaimExistingProfileRoot,
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
// given as its own (NewProfile, NewTempProfile or ClaimExistingProfileRoot).
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

// profileReleasedRoot reports whether no running browser holds the profile
// directory open as root, or none does within profileReleaseWait.
func profileReleasedRoot(root *os.Root) bool {
	deadline := time.Now().Add(profileReleaseWait)
	for profileInUseRoot(root) {
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

// ProfileClaimed reports whether dir holds the gate's marker, one that
// passes checkMarker. A marker that fails it does not count.
func ProfileClaimed(dir string) bool {
	path := filepath.Join(dir, profileMarker)
	info, err := os.Lstat(path)
	return err == nil && checkMarker(path, info) == nil
}

// checkMarker refuses a marker that is not a regular file of this user's
// alone with a single link: one another account made, or a link to a file
// made for something else, does not mark a profile as the gate's.
func checkMarker(path string, info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("devtools gate: the profile marker is not a regular file: %s", path)
	}
	return checkEntryOwner(path, info)
}

// The explicit claim of a profile that existed before works on the
// directory as it was opened and checked (an *os.Root): what it reads and
// writes there cannot be redirected by a directory swapped in afterwards,
// and none of it follows a symbolic link.

// CheckProfileRoot refuses the profile directory open as root when the
// gate would refuse to start a browser on it: on Unix, one another user
// owns or may write.
func CheckProfileRoot(root *os.Root) error {
	info, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("devtools gate: the profile directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("devtools gate: the profile directory is not a directory: %s", root.Name())
	}
	return checkProfileOwner(root.Name(), info)
}

// ProfileClaimedRoot reports whether the profile directory open as root
// holds the gate's marker, and refuses a marker that is not a regular file.
func ProfileClaimedRoot(root *os.Root) (bool, error) {
	info, err := root.Lstat(profileMarker)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := checkMarker(filepath.Join(root.Name(), profileMarker), info); err != nil {
		return false, err
	}
	return true, nil
}

// ClaimExistingProfileRoot marks the profile directory open as root, one
// that existed before, as the gate's own. It is for an explicit claim a
// person asks for, never a step's launch, after the caller's own checks; it
// checks the directory again and refuses one a running browser holds.
func ClaimExistingProfileRoot(root *os.Root) error {
	if err := CheckProfileRoot(root); err != nil {
		return err
	}
	if ProfileInUseRoot(root) {
		return fmt.Errorf("%w: %s", ErrProfileInUse, root.Name())
	}
	claimed, err := ProfileClaimedRoot(root)
	if err != nil || claimed {
		return err
	}
	file, err := root.OpenFile(profileMarker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollow, 0o600)
	if err != nil {
		return fmt.Errorf("devtools gate: claim the profile directory: %w", err)
	}
	if err := file.Close(); err != nil {
		// A marker the claim failed to finish does not stay as a claim.
		return errors.Join(fmt.Errorf("devtools gate: claim the profile directory: %w", err), root.Remove(profileMarker))
	}
	return nil
}

// ReleaseProfileClaimRoot removes the gate's marker from the profile
// directory open as root, undoing a claim. What the gate wrote in the
// profile's preferences stays.
func ReleaseProfileClaimRoot(root *os.Root) error {
	claimed, err := ProfileClaimedRoot(root)
	if err != nil || !claimed {
		return err
	}
	return root.Remove(profileMarker)
}

// ProfileInUse reports whether a running browser holds the profile dir.
func ProfileInUse(dir string) bool {
	return profileInUse(dir)
}

// ProfileInUseRoot reports whether a running browser holds the profile
// directory open as root.
func ProfileInUseRoot(root *os.Root) bool {
	return profileInUseRoot(root)
}

// claimProfile leaves the gate's marker in dir, after the checks the gate
// makes before it starts a browser there.
func claimProfile(dir string) error {
	if err := checkProfileDir(dir); err != nil {
		return err
	}
	marker := filepath.Join(dir, profileMarker)
	if info, err := os.Lstat(marker); err == nil {
		return checkMarker(marker, info)
	}
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollow, 0o600) //nolint:gosec // a new file in the directory checked above
	if err != nil {
		return fmt.Errorf("devtools gate: claim the profile directory: %w", err)
	}
	if err := file.Close(); err != nil {
		// A marker the claim failed to finish does not stay as a claim.
		return errors.Join(fmt.Errorf("devtools gate: claim the profile directory: %w", err), os.Remove(marker))
	}
	return nil
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
	_, err := checkedProfileDir(dir)
	return err
}

// checkedProfileDir is checkProfileDir that also returns what it checked.
func checkedProfileDir(dir string) (os.FileInfo, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, ErrProfileRequired
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("devtools gate: the profile directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("devtools gate: the profile directory is a symbolic link: %s", dir)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("devtools gate: the profile directory is not a directory: %s", dir)
	}
	return info, checkProfileOwner(dir, info)
}

// CheckProfileEntry refuses an entry of a profile, a directory or a file
// within it the gate reads or writes, on the same terms as the profile
// directory: on Unix, one another user owns or may write.
func CheckProfileEntry(path string, info os.FileInfo) error {
	return checkEntryOwner(path, info)
}

// disableOffTheRecord sets incognito.mode_availability in the preferences
// of the profile args name, keeping every other preference as it is, once
// the profile is found to be the gate's own and not in use. Everything it
// reads and writes is reached through the profile directory it checked,
// held open (an *os.Root), so a directory swapped in on the way is not
// written; and every entry it uses is checked as the directory is.
func disableOffTheRecord(args []string) error {
	userDataDir, profile := profileDirs(args)
	checked, err := checkedProfileDir(userDataDir)
	if err != nil {
		return err
	}
	if profile == "" || profile == "." || profile == ".." || filepath.Base(profile) != profile || strings.ContainsAny(profile, `/\`) {
		return fmt.Errorf("devtools gate: the profile %q is not a single directory name", profile)
	}
	root, err := os.OpenRoot(userDataDir)
	if err != nil {
		return fmt.Errorf("devtools gate: the profile directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	if opened, err := root.Stat("."); err != nil || !os.SameFile(opened, checked) {
		return fmt.Errorf("devtools gate: the profile directory changed while it was opened: %s", userDataDir)
	}
	if marker, err := root.Lstat(profileMarker); err != nil || checkMarker(filepath.Join(userDataDir, profileMarker), marker) != nil {
		return fmt.Errorf("%w: %s", ErrProfileNotOwned, userDataDir)
	}
	if !profileReleasedRoot(root) {
		return fmt.Errorf("%w: %s", ErrProfileInUse, userDataDir)
	}
	dir := filepath.Join(userDataDir, profile)
	info, err := root.Lstat(profile)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := root.Mkdir(profile, 0o700); err != nil {
			return fmt.Errorf("devtools gate: create the profile: %w", err)
		}
		if info, err = root.Lstat(profile); err != nil {
			return fmt.Errorf("devtools gate: the profile: %w", err)
		}
	case err != nil:
		return fmt.Errorf("devtools gate: the profile: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("devtools gate: the profile is not a directory: %s", dir)
	}
	if err := CheckProfileEntry(dir, info); err != nil {
		return err
	}
	profileRoot, err := root.OpenRoot(profile)
	if err != nil {
		return fmt.Errorf("devtools gate: the profile: %w", err)
	}
	defer func() { _ = profileRoot.Close() }()
	if opened, err := profileRoot.Stat("."); err != nil || !os.SameFile(opened, info) {
		return fmt.Errorf("devtools gate: the profile changed while it was opened: %s", dir)
	}
	path := filepath.Join(dir, "Preferences")
	prefs := map[string]any{}
	switch info, err := profileRoot.Lstat("Preferences"); {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("devtools gate: the profile's preferences: %w", err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("devtools gate: the profile's preferences are not a regular file: %s", path)
	default:
		if err := CheckProfileEntry(path, info); err != nil {
			return err
		}
		raw, err := readRegularNoFollow(profileRoot, "Preferences")
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
	temp := "Preferences.gate-" + rand.Text()
	file, err := profileRoot.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollow, 0o600)
	if err != nil {
		return fmt.Errorf("devtools gate: write the profile's preferences: %w", err)
	}
	_, writeErr := file.Write(encoded)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = profileRoot.Remove(temp)
		return fmt.Errorf("devtools gate: write the profile's preferences: %w", err)
	}
	if err := profileRoot.Rename(temp, "Preferences"); err != nil {
		_ = profileRoot.Remove(temp)
		return fmt.Errorf("devtools gate: write the profile's preferences: %w", err)
	}
	return nil
}

// readRegularNoFollow reads the regular file name in root without following
// a link.
func readRegularNoFollow(root *os.Root, name string) ([]byte, error) {
	file, err := root.OpenFile(name, os.O_RDONLY|openNoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	return io.ReadAll(file)
}
