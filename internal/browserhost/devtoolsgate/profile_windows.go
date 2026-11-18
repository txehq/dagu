// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package devtoolsgate

import (
	"errors"
	"os"
	"path/filepath"
)

// checkProfileOwner accepts the directory. On Windows its access is the
// access control list it inherited where it was created; the gate reads
// neither its owner nor that list, so it does not claim that another
// account cannot write the profile there (unproven, TXE-7856).
func checkProfileOwner(string, os.FileInfo) error {
	return nil
}

// profileInUse reports whether a running browser holds the profile: Chrome
// keeps its lockfile open, shared with nobody, while it runs.
func profileInUse(userDataDir string) bool {
	path := filepath.Join(userDataDir, "lockfile")
	file, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // the profile's own lock file, opened only to see whether it is held
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	_ = file.Close()
	return false
}
