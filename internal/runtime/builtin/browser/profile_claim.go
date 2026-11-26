// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/browserhost/devtoolsgate"
	"github.com/dagucloud/dagu/v2/internal/cmn/dirlock"
	"github.com/dagucloud/dagu/v2/internal/runtime/builtin/internal/agentstep"
)

// A named profile made before Dagu marked the profiles its browsers may
// change is refused by a step (profileUnclaimedError) and left as it is. A
// person who wants Dagu's browsers to use it claims it explicitly, and can
// undo that.
//
//   - Everything is checked before anything is written: the name, that the
//     profile is <browserDir>/profiles/<name> itself and no link, that it is
//     this user's alone, that no step, session or browser holds it (under
//     its lease), and that each file the claim reads or writes is a regular
//     file or absent, and, like each directory it uses, this user's alone.
//     A refused claim writes nothing in the profile.
//   - The lease is kept alive while the claim works, and every write comes
//     after a renewal that fails once another holder took it: a claim that
//     lost the profile writes nothing more.
//   - A mark that may have been made is never undone by removing what it
//     would be undone with: the record and the copy stay unless the mark is
//     known to be absent.
//   - The profile is opened once (an *os.Root) and every later step works on
//     that open directory: a directory swapped in after the checks cannot
//     receive the writes, and no step follows a symbolic link.
//   - A claim writes only new files, created exclusively with mode 0600: a
//     copy of the preferences, a record of the one value Dagu's browsers
//     change, and the gate's mark. It changes no preference itself.
//   - Its undo puts that value back, keeping every preference the browser
//     wrote since, then removes the mark and the record. The copy stays.
//   - Evidence is never lost: a claim that fails after writing removes what
//     it wrote only while no preference has changed, and keeps whatever it
//     cannot remove, naming it. An undo that changed the preferences but
//     could not remove the mark keeps the record and the copy.

const (
	// claimRecordName holds, inside a claimed profile, what the claim
	// found: whether the profile had preferences, the value of the one
	// preference Dagu's browsers change, and the copy it kept.
	claimRecordName = ".dagu-profile-claim.json"
	// claimBackupPrefix names the copies of the profile's preferences a
	// claim keeps, beside them, with the claim's time after it.
	claimBackupPrefix = "Preferences.dagu-before-claim-"
	// claimedProfile is the profile within the directory Dagu's browsers
	// use, and so the one whose preferences they change.
	claimedProfile = "Default"
	// claimPreferences is the preferences file within the directory.
	claimPreferences = claimedProfile + "/Preferences"
)

// ProfileClaimReport says what a claim, or its undoing, did.
type ProfileClaimReport struct {
	Name string `json:"name"`
	Dir  string `json:"dir"`
	// Claimed says whether Dagu's browsers may use the profile now.
	Claimed bool `json:"claimed"`
	// Changed is false when the profile already was as asked.
	Changed bool `json:"changed"`
	// Change describes what Dagu's browsers change in a claimed profile.
	Change string `json:"change"`
	// PreviousValue is the value of the preference before the claim, or
	// null when the profile did not set it.
	PreviousValue json.RawMessage `json:"previousIncognitoModeAvailability"`
	// Backup is the copy of the profile's preferences kept by the claim.
	Backup string `json:"backup,omitempty"`
	Undo   string `json:"undo,omitempty"`
}

// claimRecord is what a claim keeps in the profile for its undoing.
type claimRecord struct {
	HadPreferences bool            `json:"hadPreferences"`
	PreviousValue  json.RawMessage `json:"previousIncognitoModeAvailability"`
	Backup         string          `json:"backup,omitempty"`
}

const claimChange = `Dagu's browsers set incognito.mode_availability = 1 in Default/Preferences each time they start, so the browser opens no window off the record; nothing else in the profile is changed`

// claimOps are the steps a claim takes that a test makes fail.
type claimOps struct {
	mark    func(root *os.Root) error
	release func(root *os.Root) error
	remove  func(root *os.Root, name string) error
	now     func() time.Time
}

var defaultClaimOps = claimOps{
	mark:    devtoolsgate.ClaimExistingProfileRoot,
	release: devtoolsgate.ReleaseProfileClaimRoot,
	remove:  func(root *os.Root, name string) error { return root.Remove(name) },
	now:     time.Now,
}

// ClaimProfile claims the named profile under browserDir for Dagu's
// browsers.
func ClaimProfile(browserDir, name string) (ProfileClaimReport, error) {
	return claimProfileWith(browserDir, name, defaultClaimOps)
}

// UnclaimProfile undoes ClaimProfile.
func UnclaimProfile(browserDir, name string) (ProfileClaimReport, error) {
	return unclaimProfileWith(browserDir, name, defaultClaimOps)
}

func claimProfileWith(browserDir, name string, ops claimOps) (ProfileClaimReport, error) {
	report := ProfileClaimReport{Name: name, Change: claimChange, Undo: "dagu browser profile unclaim " + name, PreviousValue: json.RawMessage("null")}
	held, err := holdExistingProfile(browserDir, name)
	if err != nil {
		return report, err
	}
	defer held.release()
	root := held.root
	report.Dir = held.dir
	claimed, err := devtoolsgate.ProfileClaimedRoot(root)
	if err != nil {
		return report, fmt.Errorf("browser profile %q: %w", name, err)
	}
	if claimed {
		report.Claimed = true
		if record, err := readClaimRecord(root); err == nil {
			report.PreviousValue = record.PreviousValue
			report.Backup = backupPath(held.dir, record.Backup)
		}
		return report, nil
	}

	// Every check before the first write.
	if _, err := regularOrAbsent(root, claimRecordName); err != nil {
		return report, fmt.Errorf("browser profile %q: %w", name, err)
	} else if err := absent(root, claimRecordName); err != nil {
		return report, fmt.Errorf("browser profile %q: a claim record is already there (%w); it is evidence of an earlier claim, so look at it before claiming again", name, err)
	}
	if err := dirOrAbsent(root, claimedProfile); err != nil {
		return report, fmt.Errorf("browser profile %q: %w", name, err)
	}
	present, err := regularOrAbsent(root, claimPreferences)
	if err != nil {
		return report, fmt.Errorf("browser profile %q: %w", name, err)
	}
	record := claimRecord{PreviousValue: json.RawMessage("null")}
	var prefs []byte
	if present {
		if prefs, err = readNoFollow(root, claimPreferences); err != nil {
			return report, fmt.Errorf("browser profile %q: read its preferences: %w", name, err)
		}
		if record.PreviousValue, err = incognitoValue(prefs); err != nil {
			return report, fmt.Errorf("browser profile %q: its preferences: %w", name, err)
		}
		record.HadPreferences = true
		record.Backup = path.Join(claimedProfile, claimBackupPrefix+ops.now().UTC().Format("20060102T150405.000000000Z"))
		if err := absent(root, record.Backup); err != nil {
			return report, fmt.Errorf("browser profile %q: %w", name, err)
		}
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return report, err
	}

	// The writes: new files only, then the mark. No preference changes,
	// so what was written may go again if the mark fails.
	var written []string
	undo := func(cause error) error {
		var kept []string
		for _, file := range written {
			if err := ops.remove(root, file); err != nil {
				kept = append(kept, filepath.Join(held.dir, filepath.FromSlash(file)))
			}
		}
		if len(kept) > 0 {
			return fmt.Errorf("%w; the claim also left %s, which could not be removed and are kept as they are", cause, strings.Join(kept, ", "))
		}
		return cause
	}
	if err := held.lease(); err != nil {
		return report, err
	}
	if present {
		if err := writeNewFile(root, record.Backup, prefs); err != nil {
			return report, fmt.Errorf("browser profile %q: keep a copy of its preferences: %w", name, err)
		}
		written = append(written, record.Backup)
		if err := held.lease(); err != nil {
			return report, keptAfter(err, held.dir, written)
		}
	}
	if err := writeNewFile(root, claimRecordName, encoded); err != nil {
		return report, undo(fmt.Errorf("browser profile %q: record the claim: %w", name, err))
	}
	written = append(written, claimRecordName)
	if err := held.lease(); err != nil {
		return report, keptAfter(err, held.dir, written)
	}
	if err := ops.mark(root); err != nil {
		cause := fmt.Errorf("browser profile %q: %w", name, err)
		// The mark is what lets a browser change the profile. Unless it is
		// known to be absent, the record and the copy of the preferences it
		// would be undone with stay.
		if marked, readErr := devtoolsgate.ProfileClaimedRoot(root); readErr != nil || marked {
			return report, keptAfter(fmt.Errorf("%w; the profile may be marked as claimed", cause), held.dir, written)
		}
		return report, undo(cause)
	}
	report.Claimed, report.Changed, report.PreviousValue = true, true, record.PreviousValue
	report.Backup = backupPath(held.dir, record.Backup)
	return report, nil
}

func unclaimProfileWith(browserDir, name string, ops claimOps) (ProfileClaimReport, error) {
	report := ProfileClaimReport{Name: name, Change: claimChange, PreviousValue: json.RawMessage("null")}
	held, err := holdExistingProfile(browserDir, name)
	if err != nil {
		return report, err
	}
	defer held.release()
	root := held.root
	report.Dir = held.dir
	claimed, err := devtoolsgate.ProfileClaimedRoot(root)
	if err != nil {
		return report, fmt.Errorf("browser profile %q: %w", name, err)
	}
	if !claimed {
		return report, nil
	}

	// Every check before the first write.
	recordPresent, err := regularOrAbsent(root, claimRecordName)
	if err != nil {
		return report, fmt.Errorf("browser profile %q: %w", name, err)
	}
	record := claimRecord{PreviousValue: json.RawMessage("null")}
	if recordPresent {
		if record, err = readClaimRecord(root); err != nil {
			return report, fmt.Errorf("browser profile %q: read its claim: %w", name, err)
		}
	}
	report.PreviousValue, report.Backup = record.PreviousValue, backupPath(held.dir, record.Backup)
	if err := dirOrAbsent(root, claimedProfile); err != nil {
		return report, fmt.Errorf("browser profile %q: %w", name, err)
	}
	present, err := regularOrAbsent(root, claimPreferences)
	if err != nil {
		return report, fmt.Errorf("browser profile %q: %w", name, err)
	}
	var restored []byte
	if present {
		prefs, err := readNoFollow(root, claimPreferences)
		if err != nil {
			return report, fmt.Errorf("browser profile %q: read its preferences: %w", name, err)
		}
		if restored, err = withIncognitoValue(prefs, record.PreviousValue); err != nil {
			return report, fmt.Errorf("browser profile %q: its preferences: %w", name, err)
		}
	}

	// The writes: the preference first, then the mark, then the record.
	if err := held.lease(); err != nil {
		return report, err
	}
	if present {
		if err := replaceFile(root, claimPreferences, restored); err != nil {
			return report, fmt.Errorf("browser profile %q: put its preference back: %w", name, err)
		}
	}
	if err := held.lease(); err != nil {
		return report, fmt.Errorf("%w; its preference was already put back, and the mark, the claim record and the copy of its preferences are kept", err)
	}
	if err := ops.release(root); err != nil {
		// The preference is back but the mark stays, so the next browser
		// sets it again; the record and the copy stay with it.
		return report, fmt.Errorf("browser profile %q: its preference was put back, but its mark could not be removed (%w); the claim record and the copy of its preferences are kept", name, err)
	}
	if recordPresent {
		if err := held.lease(); err != nil {
			return report, fmt.Errorf("%w; it is unclaimed, and its claim record %s is kept", err, filepath.Join(held.dir, claimRecordName))
		}
		if err := ops.remove(root, claimRecordName); err != nil {
			return report, fmt.Errorf("browser profile %q: unclaimed, but its claim record %s could not be removed: %w", name, filepath.Join(held.dir, claimRecordName), err)
		}
	}
	report.Changed = true
	return report, nil
}

// heldProfile is a named profile open for a claim, with its lease.
type heldProfile struct {
	dir     string
	root    *os.Root
	release func()
	// lease renews the lease and fails once another holder took it: every
	// write of a claim or an unclaim comes after it, so none is made by an
	// operation that lost the profile.
	lease func() error
}

// holdExistingProfile checks the named profile exists exactly where it is
// named and is this user's alone, opens it, takes its lease so no step or
// session starts on it meanwhile, and refuses it when a step, a session or
// a browser holds it. Nothing is written in the profile.
func holdExistingProfile(browserDir, name string) (*heldProfile, error) {
	if !agentstep.FileNamePattern.MatchString(name) {
		return nil, fmt.Errorf("browser profile %q: not a profile name", name)
	}
	profilesDir := filepath.Join(browserDir, profilesDirName)
	dir := filepath.Join(profilesDir, name)
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no browser profile %q in %s", name, profilesDir)
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("browser profile %q is not a directory of its own: %s", name, dir)
	}
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	canonicalProfiles, err := filepath.EvalSymlinks(profilesDir)
	if err != nil {
		return nil, err
	}
	if canonicalDir != filepath.Join(canonicalProfiles, name) {
		return nil, fmt.Errorf("browser profile %q resolves to %s, outside %s", name, canonicalDir, canonicalProfiles)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	// The directory opened is the one checked: the same file, still no link.
	if opened, err := root.Stat("."); err != nil || !os.SameFile(opened, info) {
		_ = root.Close()
		return nil, fmt.Errorf("browser profile %q changed while it was opened", name)
	}
	if err := devtoolsgate.CheckProfileRoot(root); err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("browser profile %q: %w", name, err)
	}
	lockDir := dir + profileLockSuffix
	if err := os.MkdirAll(lockDir, profileDirMode); err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("lock browser profile %q: %w", name, err)
	}
	lock := dirlock.New(lockDir, nil)
	if err := lock.TryLock(); err != nil {
		_ = root.Close()
		if errors.Is(err, dirlock.ErrLockConflict) {
			return nil, &profileHeldError{message: fmt.Sprintf("browser profile %q is in use by a running browser step", name)}
		}
		return nil, fmt.Errorf("lock browser profile %q: %w", name, err)
	}
	stop := agentstep.KeepLockAlive(context.Background(), lock)
	release := func() {
		stop()
		_ = lock.Unlock()
		_ = root.Close()
	}
	if heldErr := profileHolder(browserDir, name, ""); heldErr != nil {
		release()
		return nil, heldErr
	}
	if devtoolsgate.ProfileInUseRoot(root) {
		release()
		return nil, &profileHeldError{message: fmt.Sprintf("browser profile %q is open in a running browser", name)}
	}
	lease := func() error {
		if err := lock.Heartbeat(context.Background()); err != nil {
			return fmt.Errorf("browser profile %q: its lease was lost before the next write (%w); nothing more was written", name, err)
		}
		return nil
	}
	return &heldProfile{dir: dir, root: root, release: release, lease: lease}, nil
}

// keptAfter reports a claim that stopped after writing the files written,
// which are kept as they are: evidence of what it did.
func keptAfter(cause error, dir string, written []string) error {
	kept := make([]string, 0, len(written))
	for _, file := range written {
		kept = append(kept, filepath.Join(dir, filepath.FromSlash(file)))
	}
	return fmt.Errorf("%w; the claim left %s, which are kept as they are", cause, strings.Join(kept, ", "))
}

func backupPath(dir, backup string) string {
	if backup == "" {
		return ""
	}
	return filepath.Join(dir, filepath.FromSlash(backup))
}

// regularOrAbsent reports whether name is a regular file in root, and
// refuses anything else that is there: a link, a directory, a device.
func regularOrAbsent(root *os.Root, name string) (bool, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", name)
	}
	// What the claim reads or replaces is this user's alone, as the
	// profile directory is.
	if err := devtoolsgate.CheckProfileEntry(filepath.Join(root.Name(), filepath.FromSlash(name)), info); err != nil {
		return false, err
	}
	return true, nil
}

// dirOrAbsent refuses name in root unless it is a directory or absent.
func dirOrAbsent(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a directory", name)
	}
	return devtoolsgate.CheckProfileEntry(filepath.Join(root.Name(), filepath.FromSlash(name)), info)
}

// absent refuses name in root when anything is there.
func absent(root *os.Root, name string) error {
	if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("%s is already there", name)
		}
		return err
	}
	return nil
}

// readNoFollow reads the regular file name in root without following a
// link.
func readNoFollow(root *os.Root, name string) ([]byte, error) {
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

// writeNewFile writes data to a new file name in root, mode 0600, refusing
// anything already there, a link included.
func writeNewFile(root *os.Root, name string, data []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollow, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		_ = root.Remove(name)
		return err
	}
	return nil
}

// replaceFile replaces the regular file name in root with data in one
// rename, mode 0600.
func replaceFile(root *os.Root, name string, data []byte) error {
	temp := name + ".dagu-unclaim"
	if err := writeNewFile(root, temp, data); err != nil {
		return err
	}
	if err := root.Rename(temp, name); err != nil {
		_ = root.Remove(temp)
		return err
	}
	return nil
}

// incognitoValue returns incognito.mode_availability in the preferences
// raw, or null when they do not set it.
func incognitoValue(raw []byte) (json.RawMessage, error) {
	var prefs map[string]json.RawMessage
	if err := json.Unmarshal(raw, &prefs); err != nil || prefs == nil {
		return nil, errors.New("not a JSON object")
	}
	var incognito map[string]json.RawMessage
	if section, ok := prefs["incognito"]; ok {
		if err := json.Unmarshal(section, &incognito); err != nil {
			return nil, errors.New("incognito is not a JSON object")
		}
	}
	if value, ok := incognito["mode_availability"]; ok {
		return value, nil
	}
	return json.RawMessage("null"), nil
}

// withIncognitoValue returns the preferences raw with
// incognito.mode_availability set to previous, or removed when previous is
// null, every other preference kept as it is.
func withIncognitoValue(raw []byte, previous json.RawMessage) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var prefs map[string]any
	if err := decoder.Decode(&prefs); err != nil || prefs == nil {
		return nil, errors.New("not a JSON object")
	}
	incognito, _ := prefs["incognito"].(map[string]any)
	if string(previous) == "null" || len(previous) == 0 {
		delete(incognito, "mode_availability")
		if incognito != nil && len(incognito) == 0 {
			delete(prefs, "incognito")
		}
	} else {
		if incognito == nil {
			incognito = map[string]any{}
			prefs["incognito"] = incognito
		}
		incognito["mode_availability"] = previous
	}
	return json.Marshal(prefs)
}

// readClaimRecord reads what a claim recorded in root.
func readClaimRecord(root *os.Root) (claimRecord, error) {
	var record claimRecord
	raw, err := readNoFollow(root, claimRecordName)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return record, err
	}
	if len(record.PreviousValue) == 0 {
		record.PreviousValue = json.RawMessage("null")
	}
	return record, nil
}
