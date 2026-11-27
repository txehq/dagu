// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package devtoolsgate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// On Windows the gate reads neither the owner nor the access control list
// of a profile or of the directories on its path, so it does not claim
// that a profile there is private (unproven, TXE-7856). It still refuses a
// symbolic link and an object of the wrong type.

// openTrusted opens the profile directory path, which must be absolute and
// neither a symbolic link nor anything but a directory.
func openTrusted(path string) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, ErrProfileRequired
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("devtools gate: the profile directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("devtools gate: the profile path passes through a symbolic link: %s", path)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("devtools gate: the profile path is not a directory: %s", path)
	}
	f, err := os.Open(path) //nolint:gosec // the profile directory checked above
	if err != nil {
		return nil, fmt.Errorf("devtools gate: the profile directory: %w", err)
	}
	if opened, err := f.Stat(); err != nil || !os.SameFile(opened, info) {
		_ = f.Close()
		return nil, fmt.Errorf("devtools gate: the profile directory changed while it was opened: %s", path)
	}
	return f, nil
}

// openEntry opens name in root, refusing a symbolic link and an object of
// the wrong type: a directory when dir is set, a regular file otherwise. It
// returns nil and no error when nothing is there.
func openEntry(root *os.Root, name string, dir bool) (*os.File, error) {
	path := filepath.Join(root.Name(), name)
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("devtools gate: %s: %w", roleEntry, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || dir != info.IsDir() || (!dir && !info.Mode().IsRegular()) {
		if dir {
			return nil, fmt.Errorf("devtools gate: %s is not a directory (a symbolic link is not followed): %s", roleEntry, path)
		}
		return nil, fmt.Errorf("devtools gate: %s is not a regular file (a symbolic link is not followed): %s", roleEntry, path)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("devtools gate: %s: %w", roleEntry, err)
	}
	if opened, err := f.Stat(); err != nil || !os.SameFile(opened, info) {
		_ = f.Close()
		return nil, fmt.Errorf("devtools gate: %s changed while it was opened: %s", roleEntry, path)
	}
	return f, nil
}

// checkOpened checks nothing more on Windows, where the owner and access
// of a file are not read.
func checkOpened(*os.File, role, string) error {
	return nil
}
