// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package cliauth

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkPrivate requires path to be a directory (dir) or regular file owned
// by this user that no other user can read or write. A directory of the
// user's own that is more open than that is closed to storeDirPerm; a file
// is refused, since something other than this package wrote it so.
func checkPrivate(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("sign-in store: %s is a symbolic link", path)
	case dir && !fi.IsDir():
		return fmt.Errorf("sign-in store: %s is not a directory", path)
	case !dir && !fi.Mode().IsRegular():
		return fmt.Errorf("sign-in store: %s is not a regular file", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("sign-in store: %s belongs to another user", path)
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if dir {
		if err := os.Chmod(path, storeDirPerm); err != nil {
			return fmt.Errorf("sign-in store: close %s to other users: %w", path, err)
		}
		return nil
	}
	return fmt.Errorf("sign-in store: %s can be read or written by other users (mode %04o); run \"dagu txe login\" to replace it", path, fi.Mode().Perm())
}
