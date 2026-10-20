// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package txepkg

import (
	"fmt"
	"os"
)

// openStepAuth opens the step-auth file. Windows has no owner-only file
// mode to check, and no machine credential is kept there, so a link or
// another kind of file is all that is refused.
func openStepAuth(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return os.Open(path) //nolint:gosec // fixed file name under the TXE home
}
