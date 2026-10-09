// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package probe

import (
	"fmt"
	"io/fs"
	"os"
)

// openNoFollow refuses a symbolic link, then opens the file. Windows has no
// O_NOFOLLOW; the opened file is checked again by the caller.
func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link", path)
	}
	return os.Open(path) //nolint:gosec // path checked absolute and clean by the caller
}

// checkOwner is not enforced on Windows, where file permissions are ACLs;
// the path and type checks still apply.
func checkOwner(string, fs.FileInfo) error { return nil }
