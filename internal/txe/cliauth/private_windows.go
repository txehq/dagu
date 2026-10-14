// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package cliauth

import (
	"fmt"
	"os"
)

// checkPrivate only checks the kind of path on Windows, where access is
// governed by the profile directory's ACL rather than mode bits.
func checkPrivate(path string, dir bool) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if dir != fi.IsDir() {
		return fmt.Errorf("sign-in store: %s is not the kind of path expected", path)
	}
	return nil
}
