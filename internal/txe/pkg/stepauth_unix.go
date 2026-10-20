// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package txepkg

import (
	"fmt"
	"os"
	"syscall"
)

// openStepAuth opens the step-auth file without following a link, and
// checks the open file itself: a regular file, owned by this user, that only
// its owner can read or write. Checking the path and then reading it would
// leave a moment for it to be replaced.
func openStepAuth(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // fixed file name under the TXE home
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	problem := ""
	switch st, ok := info.Sys().(*syscall.Stat_t); {
	case !info.Mode().IsRegular():
		problem = "is not a regular file"
	case info.Mode().Perm()&0o077 != 0:
		problem = fmt.Sprintf("has mode %#o; it must be readable by its owner only (0600)", info.Mode().Perm())
	case ok && int(st.Uid) != os.Getuid():
		problem = fmt.Sprintf("is owned by uid %d, not this user (%d)", st.Uid, os.Getuid())
	}
	if problem != "" {
		_ = f.Close()
		return nil, fmt.Errorf("%s %s", path, problem)
	}
	return f, nil
}
