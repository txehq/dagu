// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package devtoolsgate

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/dagucloud/dagu/v2/internal/cmn/procutil"
)

// checkProfileOwner refuses a profile directory another user owns, or one
// another user may write.
func checkProfileOwner(dir string, info os.FileInfo) error {
	return checkOwner("the profile directory", dir, info)
}

// checkEntryOwner refuses an entry of a profile on the same terms.
func checkEntryOwner(path string, info os.FileInfo) error {
	return checkOwner("the profile's entry", path, info)
}

func checkOwner(what, path string, info os.FileInfo) error {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("devtools gate: %s belongs to another user: %s", what, path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("devtools gate: others may write %s: %s", what, path)
	}
	return nil
}

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
