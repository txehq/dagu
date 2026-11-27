// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows && !linux && !darwin

package devtoolsgate

import (
	"fmt"
	"os"
)

// checkFilesystemAndACL refuses every object on a Unix other than Linux
// and macOS: the gate does not read access control lists there, so it
// cannot tell that a profile is private.
func checkFilesystemAndACL(_ *os.File, _ bool, r role, path string) error {
	return fmt.Errorf("devtools gate: access control lists cannot be read on this system, so %s cannot be checked: %s", r, path)
}
