// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// StepAuthFile names, in the machine's own context store (the TXE home's
// client directory, which its steps read), how those steps reach the hub, by
// credential class. Continuity does not read that directory.
const StepAuthFile = "step-auth.json"

// StepAuthSchema is the version of StepAuth this build reads and writes.
const StepAuthSchema = 1

// StepModeCredential is a class whose steps present the machine's own
// enrolled credential and nothing else.
const StepModeCredential = "credential"

// StepAuth says, for each credential class ("worker", "reviewer"), how the
// steps of that class reach the hub. A class it does not name has no
// enrolled credential: its steps use the context's API key, as every step did
// before machines were enrolled.
//
// It is written by "dagu txe enrol" once the hub reports the machine enrolled
// for the class, and is never turned back by any command that runs on its
// own. A missing or unreadable credential file is therefore an error for a
// class named here, never a reason to fall back to the API key.
type StepAuth struct {
	Schema  int                      `json:"schema"`
	Classes map[string]StepAuthClass `json:"classes"`
}

// StepAuthClass is one class's mode, its credential file and the hub the
// machine is enrolled with for it.
type StepAuthClass struct {
	Mode string `json:"mode"`
	// CredentialFile is the absolute path of the class's credential file.
	CredentialFile string `json:"credential_file"`
	// Hub is the hub's API root the enrolment was made with. The credential
	// is presented there and nowhere else.
	Hub string `json:"hub"`
}

// stepAuthClasses are the credential classes a step can need.
var stepAuthClasses = map[string]bool{"worker": true, "reviewer": true}

// StepAuth reads the step-auth file. A home without one has no enrolled
// class. The file must be a regular file only its owner can read or write.
func (h Home) StepAuth() (StepAuth, error) {
	path := filepath.Join(h.ClientDir(), StepAuthFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return StepAuth{Schema: StepAuthSchema}, nil
	}
	if err != nil {
		return StepAuth{}, fmt.Errorf("read %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return StepAuth{}, fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return StepAuth{}, fmt.Errorf("%s has mode %#o; it must be readable by its owner only (0600)", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path) //nolint:gosec // fixed file name under the TXE home
	if err != nil {
		return StepAuth{}, fmt.Errorf("read %s: %w", path, err)
	}
	var auth StepAuth
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&auth); err != nil || decoder.More() {
		return StepAuth{}, fmt.Errorf("%s is not valid JSON of the expected shape", path)
	}
	if auth.Schema != StepAuthSchema {
		return StepAuth{}, fmt.Errorf("%s has schema %d, not %d", path, auth.Schema, StepAuthSchema)
	}
	// The file exists only once a class was enrolled, so one that names no
	// class, or a class no step needs, was not written by this program.
	if len(auth.Classes) == 0 {
		return StepAuth{}, fmt.Errorf("%s names no enrolled class", path)
	}
	for class, c := range auth.Classes {
		if !stepAuthClasses[class] {
			return StepAuth{}, fmt.Errorf("%s: %q is not a credential class", path, class)
		}
		if c.Mode != StepModeCredential || !filepath.IsAbs(c.CredentialFile) || c.Hub == "" {
			return StepAuth{}, fmt.Errorf("%s: class %q must have mode %q, an absolute credential_file and a hub", path, class, StepModeCredential)
		}
	}
	return auth, nil
}

// Enrolled returns the class's entry and whether it has one.
func (a StepAuth) Enrolled(class string) (StepAuthClass, bool) {
	c, ok := a.Classes[class]
	return c, ok
}

// SetStepCredential records that the class's steps present the credential
// at path to hub, replacing the file atomically, readable by its owner only.
func (h Home) SetStepCredential(class, path, hub string) error {
	if !stepAuthClasses[class] {
		return fmt.Errorf("%q is not a credential class", class)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("the %s credential file %q must be an absolute path", class, path)
	}
	if hub == "" {
		return fmt.Errorf("the %s enrolment names no hub", class)
	}
	auth, err := h.StepAuth()
	if err != nil {
		return err
	}
	if auth.Classes == nil {
		auth.Classes = map[string]StepAuthClass{}
	}
	auth.Classes[class] = StepAuthClass{Mode: StepModeCredential, CredentialFile: path, Hub: hub}
	data, err := json.MarshalIndent(auth, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h.ClientDir(), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(h.ClientDir(), "."+StepAuthFile+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(h.ClientDir(), StepAuthFile))
}
