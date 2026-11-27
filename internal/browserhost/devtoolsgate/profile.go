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
//   - On Unix the profile is private to this user (privacy_unix.go): the
//     path to it passes through no symbolic link and through no directory
//     another account could change; the profile directory is this user's
//     and 0700, with no access control entry for another account; the
//     entries the gate and a claim use in it (the profile within it, its
//     Preferences, the marker, a claim's record and copy) are this user's,
//     writable by no one else, files with a single link. Each is read from
//     the open object, and only on a filesystem whose permissions the gate
//     reads (supportedLinuxFS, supportedDarwinFS); anything it cannot read
//     is refused. Root and this user's own processes are outside what it
//     guards. On overlayfs it relies on the overlay's storage being as
//     trusted as the rest: backing directories no other account can reach,
//     and no untrusted layer metadata.
//   - A profile a running browser holds is refused: the gate does not
//     change preferences under a browser that would write its own back. A
//     browser still ending, as when a browser is started again on the
//     profile it just used, is given profileReleaseWait to let go.
//   - Preferences are merged: every other preference stays as it was,
//     numbers included, and the file is replaced in one rename.
//   - The previous value is not put back. The profile is the gate's, and the
//     preference is its policy for every browser it starts there.
//
// On Windows the owner and access of the profile and its path are not
// checked (privacy_windows.go): the gate's isolation of its own profiles
// there is unproven.

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
// own, as os.MkdirTemp does with parent and pattern, and returns it. The
// directory is made in parent with its symbolic links resolved, so the path
// the browser is started on passes through none (openTrusted).
func NewTempProfile(parent, pattern string) (string, error) {
	if parent == "" {
		parent = os.TempDir()
	}
	parent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
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

// OpenProfileRoot opens the profile directory dir for the gate's checks
// and writes: along a path no other account can change, the directory
// itself this user's alone (openTrusted, on Unix), and as an *os.Root that
// is that same directory. What is read and written through the Root then
// cannot be redirected to another directory.
func OpenProfileRoot(dir string) (*os.Root, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, ErrProfileRequired
	}
	walked, err := openTrusted(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = walked.Close() }()
	return bridgeRoot(walked, dir)
}

// bridgeRoot opens dir as an *os.Root and refuses it unless it is the
// directory walked, the one the checks read: the os.Root holds no
// descriptor of its own to check, so the two are proven the same object.
func bridgeRoot(walked *os.File, dir string) (*os.Root, error) {
	checked, err := walked.Stat()
	if err != nil {
		return nil, fmt.Errorf("devtools gate: the profile directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("devtools gate: the profile directory: %w", err)
	}
	if opened, err := root.Stat("."); err != nil || !os.SameFile(opened, checked) {
		_ = root.Close()
		return nil, fmt.Errorf("devtools gate: the profile directory changed while it was opened: %s", dir)
	}
	return root, nil
}

// OpenProfileEntry opens name in root, a profile directory or a directory
// in it, as an entry the gate or a claim uses: not through a symbolic link,
// a directory when dir is set and a regular file otherwise, and on Unix
// this user's, writable by no one else, a file with a single link, read
// from the open file itself. It returns nil and no error when nothing is
// there.
func OpenProfileEntry(root *os.Root, name string, dir bool) (*os.File, error) {
	return openEntry(root, name, dir)
}

// ProfileClaimed reports whether dir is a profile directory the gate may
// use (OpenProfileRoot) that holds the gate's marker (ProfileClaimedRoot).
// A directory or marker that fails a check does not count.
func ProfileClaimed(dir string) bool {
	root, err := OpenProfileRoot(dir)
	if err != nil {
		return false
	}
	defer func() { _ = root.Close() }()
	claimed, err := ProfileClaimedRoot(root)
	return err == nil && claimed
}

// The explicit claim of a profile that existed before works on the
// directory as it was opened and checked (an *os.Root): what it reads and
// writes there cannot be redirected by a directory swapped in afterwards,
// and none of it follows a symbolic link.

// CheckProfileRoot refuses the profile directory open as root when the
// gate would refuse to start a browser on it, read from the directory the
// Root holds: on Unix, one that is not this user's alone.
func CheckProfileRoot(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("devtools gate: the profile directory: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("devtools gate: the profile directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("devtools gate: the profile directory is not a directory: %s", root.Name())
	}
	return checkOpened(f, roleProfile, root.Name())
}

// ProfileClaimedRoot reports whether the profile directory open as root
// holds the gate's marker. A marker must be an entry the gate may use
// (OpenProfileEntry): one another account made, a link to a file made for
// something else, or anything but a regular file is refused.
func ProfileClaimedRoot(root *os.Root) (bool, error) {
	marker, err := openEntry(root, profileMarker, false)
	if err != nil || marker == nil {
		return false, err
	}
	return true, marker.Close()
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
	return createMarker(root)
}

// createMarker leaves the gate's marker in root, a new file that is then
// checked as an entry, from the file itself. A marker that fails, or that
// could not be finished, does not stay as a claim.
func createMarker(root *os.Root) error {
	file, err := root.OpenFile(profileMarker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollow, 0o600)
	if err != nil {
		return fmt.Errorf("devtools gate: claim the profile directory: %w", err)
	}
	checkErr := checkOpened(file, roleEntry, filepath.Join(root.Name(), profileMarker))
	if err := errors.Join(checkErr, file.Close()); err != nil {
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
	root, err := OpenProfileRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	claimed, err := ProfileClaimedRoot(root)
	if err != nil || claimed {
		return err
	}
	return createMarker(root)
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

// disableOffTheRecord sets incognito.mode_availability in the preferences
// of the profile args name, keeping every other preference as it is, once
// the profile is found to be the gate's own and not in use. The profile
// directory is opened along a path no other account can change, and the
// browser is started on that same path after this returns; everything read
// and written is reached through the directory checked, held open, and
// every entry used is checked from the open entry itself.
func disableOffTheRecord(args []string) error {
	userDataDir, profile := profileDirs(args)
	if userDataDir == "" || !filepath.IsAbs(userDataDir) {
		return ErrProfileRequired
	}
	if profile == "" || profile == "." || profile == ".." || filepath.Base(profile) != profile || strings.ContainsAny(profile, `/\`) {
		return fmt.Errorf("devtools gate: the profile %q is not a single directory name", profile)
	}
	root, err := OpenProfileRoot(userDataDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if claimed, err := ProfileClaimedRoot(root); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrProfileNotOwned, userDataDir, err)
	} else if !claimed {
		return fmt.Errorf("%w: %s", ErrProfileNotOwned, userDataDir)
	}
	if !profileReleasedRoot(root) {
		return fmt.Errorf("%w: %s", ErrProfileInUse, userDataDir)
	}
	dir := filepath.Join(userDataDir, profile)
	opened, err := openEntry(root, profile, true)
	if err != nil {
		return err
	}
	if opened == nil {
		if err := root.Mkdir(profile, 0o700); err != nil {
			return fmt.Errorf("devtools gate: create the profile: %w", err)
		}
		if opened, err = openEntry(root, profile, true); err != nil {
			return err
		}
		if opened == nil {
			return fmt.Errorf("devtools gate: the profile went away as it was made: %s", dir)
		}
	}
	defer func() { _ = opened.Close() }()
	checked, err := opened.Stat()
	if err != nil {
		return fmt.Errorf("devtools gate: the profile: %w", err)
	}
	profileRoot, err := root.OpenRoot(profile)
	if err != nil {
		return fmt.Errorf("devtools gate: the profile: %w", err)
	}
	defer func() { _ = profileRoot.Close() }()
	if same, err := profileRoot.Stat("."); err != nil || !os.SameFile(same, checked) {
		return fmt.Errorf("devtools gate: the profile changed while it was opened: %s", dir)
	}
	path := filepath.Join(dir, "Preferences")
	prefs := map[string]any{}
	current, err := openEntry(profileRoot, "Preferences", false)
	if err != nil {
		return err
	}
	if current != nil {
		raw, err := io.ReadAll(current)
		_ = current.Close()
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
	// The new preferences are checked as an entry before they replace the
	// old: an inherited access control list would show here.
	checkErr := checkOpened(file, roleEntry, filepath.Join(dir, temp))
	closeErr := file.Close()
	if err := errors.Join(writeErr, checkErr, closeErr); err != nil {
		_ = profileRoot.Remove(temp)
		return fmt.Errorf("devtools gate: write the profile's preferences: %w", err)
	}
	if err := profileRoot.Rename(temp, "Preferences"); err != nil {
		_ = profileRoot.Remove(temp)
		return fmt.Errorf("devtools gate: write the profile's preferences: %w", err)
	}
	return nil
}
