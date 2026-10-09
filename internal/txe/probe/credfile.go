// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// checkCredentialFile refuses a credential file locator the probe should
// not read: it must be an absolute, clean path to a regular file that this
// user owns and nobody else can write. Locators come from the registry, so
// this keeps a hub record from steering the probe at another file.
func checkCredentialFile(locator string) error {
	if locator == "" || !filepath.IsAbs(locator) || filepath.Clean(locator) != locator || strings.Contains(locator, "..") {
		return fmt.Errorf("locator %q is not an absolute, clean path", locator)
	}
	info, err := os.Stat(locator)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("file %s does not exist on this machine", locator)
	}
	if err != nil {
		return fmt.Errorf("file %s: %w", locator, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", locator)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be written by others (mode %v)", locator, info.Mode().Perm())
	}
	return checkOwner(locator, info)
}
