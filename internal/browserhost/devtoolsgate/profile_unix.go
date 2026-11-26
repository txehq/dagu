// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package devtoolsgate

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/dagucloud/dagu/v2/internal/cmn/procutil"
)

// openNoFollow makes an open refuse a symbolic link.
const openNoFollow = syscall.O_NOFOLLOW

// profileInUse reports whether a running browser holds the profile: Chrome
// keeps a SingletonLock link in it naming its host and process.
func profileInUse(userDataDir string) bool {
	target, err := os.Readlink(filepath.Join(userDataDir, "SingletonLock"))
	if err != nil {
		return false
	}
	return lockHeld(target)
}

// profileInUseRoot is profileInUse for the profile directory open as root.
func profileInUseRoot(root *os.Root) bool {
	target, err := root.Readlink("SingletonLock")
	if err != nil {
		return false
	}
	return lockHeld(target)
}

// lockHeld reports whether the SingletonLock target names a live browser.
func lockHeld(target string) bool {
	// "<host>-<pid>": a host name may hold a dash; the process id is last.
	cut := strings.LastIndex(target, "-")
	if cut <= 0 {
		// A lock the gate cannot read is taken to be held.
		return true
	}
	host := target[:cut]
	pid, err := strconv.Atoi(target[cut+1:])
	if err != nil {
		return true
	}
	if self, err := os.Hostname(); err == nil && self != host {
		// Held from another host, as over a shared directory.
		return true
	}
	return procutil.IsAlive(pid)
}
