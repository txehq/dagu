// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package browser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dagucloud/dagu/v2/internal/browserhost/devtoolsgate"
	"github.com/dagucloud/dagu/v2/internal/cmn/dirlock"
	"github.com/dagucloud/dagu/v2/internal/runtime/builtin/internal/agentstep"
)

// A named profile made before Dagu marked the profiles its browsers may
// change is refused by a step (profileUnclaimedError) and left as it is. A
// person who wants Dagu's browsers to use it claims it explicitly:
// ClaimProfile checks the profile is the one meant and that nothing holds
// it, keeps a copy of its preferences and the one value Dagu's browsers
// change there, and marks it. UnclaimProfile undoes that: it removes the
// mark and puts the value back as it was, keeping every preference the
// browser wrote since.

const (
	// claimRecordName holds, inside a claimed profile, what the claim
	// found: whether the profile had preferences and the value of the one
	// preference Dagu's browsers change.
	claimRecordName = ".dagu-profile-claim.json"
	// claimBackupSuffix names the copy of the profile's preferences a claim
	// keeps, beside them.
	claimBackupSuffix = ".dagu-before-claim"
	// claimedProfile is the profile within the directory Dagu's browsers
	// use, and so the one whose preferences they change.
	claimedProfile = "Default"
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
}

const claimChange = `Dagu's browsers set incognito.mode_availability = 1 in Default/Preferences each time they start, so the browser opens no window off the record; nothing else in the profile is changed`

// ClaimProfile claims the named profile under browserDir for Dagu's
// browsers. It refuses a profile that does not exist, is not exactly
// <browserDir>/profiles/<name> on disk, is not this user's alone, or that a
// step, a session or a browser holds.
func ClaimProfile(browserDir, name string) (ProfileClaimReport, error) {
	report := ProfileClaimReport{Name: name, Change: claimChange, Undo: "dagu browser profile unclaim " + name}
	dir, unlock, err := holdExistingProfile(browserDir, name)
	if err != nil {
		return report, err
	}
	defer unlock()
	report.Dir = dir
	prefs := filepath.Join(dir, claimedProfile, "Preferences")
	if devtoolsgate.ProfileClaimed(dir) {
		report.Claimed = true
		if record, err := readClaimRecord(dir); err == nil {
			report.PreviousValue = record.PreviousValue
		}
		if _, err := os.Lstat(prefs + claimBackupSuffix); err == nil {
			report.Backup = prefs + claimBackupSuffix
		}
		return report, nil
	}

	record := claimRecord{PreviousValue: json.RawMessage("null")}
	created := []string{}
	rollback := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	switch info, err := os.Lstat(prefs); {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return report, fmt.Errorf("browser profile %q: %w", name, err)
	case !info.Mode().IsRegular():
		return report, fmt.Errorf("browser profile %q: its preferences are not a regular file", name)
	default:
		raw, err := os.ReadFile(prefs) //nolint:gosec // the named profile's own preferences, checked above
		if err != nil {
			return report, fmt.Errorf("browser profile %q: %w", name, err)
		}
		value, err := incognitoValue(raw)
		if err != nil {
			return report, fmt.Errorf("browser profile %q: its preferences: %w", name, err)
		}
		record.HadPreferences, record.PreviousValue = true, value
		backup := prefs + claimBackupSuffix
		if err := writeNew(backup, raw); err != nil {
			return report, fmt.Errorf("browser profile %q: keep a copy of its preferences: %w", name, err)
		}
		created = append(created, backup)
		report.Backup = backup
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		rollback()
		return report, err
	}
	recordPath := filepath.Join(dir, claimRecordName)
	if err := writeNew(recordPath, encoded); err != nil {
		rollback()
		return report, fmt.Errorf("browser profile %q: record the claim: %w", name, err)
	}
	created = append(created, recordPath)
	if err := devtoolsgate.ClaimExistingProfile(dir); err != nil {
		rollback()
		return report, fmt.Errorf("browser profile %q: %w", name, err)
	}
	report.Claimed, report.Changed, report.PreviousValue = true, true, record.PreviousValue
	return report, nil
}

// UnclaimProfile undoes ClaimProfile: Dagu's browsers no longer use the
// named profile, and the preference they change is put back as it was
// before the claim, every other preference staying as the browser left it.
// The copy the claim kept stays, and the report names it.
func UnclaimProfile(browserDir, name string) (ProfileClaimReport, error) {
	report := ProfileClaimReport{Name: name, Change: claimChange}
	dir, unlock, err := holdExistingProfile(browserDir, name)
	if err != nil {
		return report, err
	}
	defer unlock()
	report.Dir = dir
	if !devtoolsgate.ProfileClaimed(dir) {
		return report, nil
	}
	prefs := filepath.Join(dir, claimedProfile, "Preferences")
	if _, err := os.Lstat(prefs + claimBackupSuffix); err == nil {
		report.Backup = prefs + claimBackupSuffix
	}
	record, err := readClaimRecord(dir)
	if errors.Is(err, os.ErrNotExist) {
		// A profile Dagu created claimed: it had nothing to put back.
		record = claimRecord{PreviousValue: json.RawMessage("null")}
	} else if err != nil {
		return report, fmt.Errorf("browser profile %q: read its claim: %w", name, err)
	}
	if err := restoreIncognitoValue(prefs, record.PreviousValue); err != nil {
		return report, fmt.Errorf("browser profile %q: put its preference back: %w", name, err)
	}
	if err := devtoolsgate.ReleaseProfileClaim(dir); err != nil {
		return report, fmt.Errorf("browser profile %q: %w", name, err)
	}
	_ = os.Remove(filepath.Join(dir, claimRecordName))
	report.Changed, report.PreviousValue = true, record.PreviousValue
	return report, nil
}

// holdExistingProfile checks the named profile exists exactly where it is
// named, takes its lease so no step or session starts on it meanwhile, and
// refuses it when a step, a session or a browser holds it.
func holdExistingProfile(browserDir, name string) (string, func(), error) {
	if !agentstep.FileNamePattern.MatchString(name) {
		return "", nil, fmt.Errorf("browser profile %q: not a profile name", name)
	}
	profilesDir := filepath.Join(browserDir, profilesDirName)
	dir := filepath.Join(profilesDir, name)
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil, fmt.Errorf("no browser profile %q in %s", name, profilesDir)
	}
	if err != nil {
		return "", nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf("browser profile %q is not a directory of its own: %s", name, dir)
	}
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", nil, err
	}
	canonicalProfiles, err := filepath.EvalSymlinks(profilesDir)
	if err != nil {
		return "", nil, err
	}
	if canonicalDir != filepath.Join(canonicalProfiles, name) {
		return "", nil, fmt.Errorf("browser profile %q resolves to %s, outside %s", name, canonicalDir, canonicalProfiles)
	}
	lockDir := dir + profileLockSuffix
	if err := os.MkdirAll(lockDir, profileDirMode); err != nil {
		return "", nil, fmt.Errorf("lock browser profile %q: %w", name, err)
	}
	lock := dirlock.New(lockDir, nil)
	if err := lock.TryLock(); err != nil {
		if errors.Is(err, dirlock.ErrLockConflict) {
			return "", nil, &profileHeldError{message: fmt.Sprintf("browser profile %q is in use by a running browser step", name)}
		}
		return "", nil, fmt.Errorf("lock browser profile %q: %w", name, err)
	}
	unlock := func() { _ = lock.Unlock() }
	if heldErr := profileHolder(browserDir, name, ""); heldErr != nil {
		unlock()
		return "", nil, heldErr
	}
	if devtoolsgate.ProfileInUse(dir) {
		unlock()
		return "", nil, &profileHeldError{message: fmt.Sprintf("browser profile %q is open in a running browser", name)}
	}
	return dir, unlock, nil
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

// restoreIncognitoValue puts incognito.mode_availability in the
// preferences at path back to previous, removing it when previous is null,
// and keeps every other preference as it is.
func restoreIncognitoValue(path string, previous json.RawMessage) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("the preferences are not a regular file")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the named profile's own preferences, checked above
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var prefs map[string]any
	if err := decoder.Decode(&prefs); err != nil || prefs == nil {
		return errors.New("the preferences are not a JSON object")
	}
	incognito, _ := prefs["incognito"].(map[string]any)
	if string(previous) == "null" || len(previous) == 0 {
		delete(incognito, "mode_availability")
		if len(incognito) == 0 {
			delete(prefs, "incognito")
		}
	} else {
		if incognito == nil {
			incognito = map[string]any{}
			prefs["incognito"] = incognito
		}
		incognito["mode_availability"] = previous
	}
	encoded, err := json.Marshal(prefs)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "Preferences.unclaim-*")
	if err != nil {
		return err
	}
	_, writeErr := temp.Write(encoded)
	closeErr := temp.Close()
	if err := errors.Join(writeErr, closeErr, os.Chmod(temp.Name(), 0o600)); err != nil {
		_ = os.Remove(temp.Name())
		return err
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		_ = os.Remove(temp.Name())
		return err
	}
	return nil
}

// readClaimRecord reads what a claim recorded in dir.
func readClaimRecord(dir string) (claimRecord, error) {
	var record claimRecord
	raw, err := os.ReadFile(filepath.Join(dir, claimRecordName)) //nolint:gosec // the claimed profile's own record
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return record, err
	}
	return record, nil
}

// writeNew writes data to a new file at path, refusing one that exists.
func writeNew(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a new file in the checked profile
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
