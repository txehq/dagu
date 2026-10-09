// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package probe

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// openNoFollow opens path for reading and refuses a symbolic link.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// checkOwnership requires the file to be this user's and not writable by
// group or others.
func checkOwnership(path string, info fs.FileInfo) error {
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be written by others (mode %v)", path, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s", path)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, not by this user", path, st.Uid)
	}
	return nil
}
