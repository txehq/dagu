// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package cliauth

import (
	"fmt"
	"io/fs"
	"os"
)

// checkPrivate checks the kind of path on Windows, where access is governed
// by the profile directory's ACL rather than mode bits. A symbolic link,
// junction or other reparse point is refused, as on other systems, so that
// the store cannot be redirected elsewhere.
func checkPrivate(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0:
		return fmt.Errorf("sign-in store: %s is a link or reparse point", path)
	case dir && !fi.IsDir():
		return fmt.Errorf("sign-in store: %s is not a directory", path)
	case !dir && !fi.Mode().IsRegular():
		return fmt.Errorf("sign-in store: %s is not a regular file", path)
	}
	return nil
}
