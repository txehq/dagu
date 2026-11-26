// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"fmt"
	"os"
)

// role is what an object is to a profile the gate writes, and so the rules
// it is checked by (checkMetadata, and the access control list rules).
type role int

const (
	// roleAncestor is a directory on the path to the profile: this user's
	// or root's, writable by no one else unless it is sticky and root's.
	roleAncestor role = iota
	// roleProfile is the profile directory: this user's, and open to no
	// one else at all (0700, and no access control entry for another).
	roleProfile
	// roleEntry is a directory or file in the profile the gate or a claim
	// uses: this user's, writable by no one else, a file with one link.
	roleEntry
)

func (r role) String() string {
	switch r {
	case roleAncestor:
		return "a directory on the profile's path"
	case roleProfile:
		return "the profile directory"
	case roleEntry:
		return "the profile's entry"
	}
	return "an object of the profile"
}

// checkMetadata refuses an object of role r at path whose owner uid, mode
// or link count break that role's rules, for a process whose effective uid
// is euid. A sticky directory root owns may be writable by others: nobody
// but its owner and root can remove or rename what this user or root owns
// in it, which is the next component of the path, so additions there leave
// the path alone.
func checkMetadata(r role, path string, mode os.FileMode, uid uint32, nlink uint64, euid uint32) error {
	perm := mode.Perm()
	switch r {
	case roleAncestor:
		if uid != euid && uid != 0 {
			return fmt.Errorf("devtools gate: %s belongs to another user: %s", r, path)
		}
		if perm&0o022 != 0 && (mode&os.ModeSticky == 0 || uid != 0) {
			return fmt.Errorf("devtools gate: others may write %s: %s", r, path)
		}
	case roleProfile:
		if uid != euid {
			return fmt.Errorf("devtools gate: %s belongs to another user: %s", r, path)
		}
		if perm&0o022 != 0 {
			return fmt.Errorf("devtools gate: others may write %s: %s", r, path)
		}
		if perm&0o077 != 0 {
			return fmt.Errorf("devtools gate: others may read or enter %s (it must be 0700): %s", r, path)
		}
	case roleEntry:
		if uid != euid {
			return fmt.Errorf("devtools gate: %s belongs to another user: %s", r, path)
		}
		if perm&0o022 != 0 {
			return fmt.Errorf("devtools gate: others may write %s: %s", r, path)
		}
		// A file with another link is also reached by a name outside what
		// was checked.
		if mode.IsRegular() && nlink != 1 {
			return fmt.Errorf("devtools gate: %s has another link: %s", r, path)
		}
	default:
		return fmt.Errorf("devtools gate: no rules for %s: %s", r, path)
	}
	return nil
}

// Linux filesystems whose permission model the gate reads: mode bits and
// POSIX access control lists, nothing else (statfs f_type).
const (
	fsExt4  = 0xEF53 // ext2, ext3 and ext4
	fsXFS   = 0x58465342
	fsBtrfs = 0x9123683E
	fsTmpfs = 0x01021994
	// fsOverlay is overlayfs, where Dagu's container image keeps "/" and
	// /tmp. It carries POSIX access control lists (since Linux 4.8): an
	// object reports the list of the layer that backs it, and one copied up
	// on its first write carries its list along. The gate reads the list of
	// the object it opened, so it reads what governs that object.
	fsOverlay = 0x794C7630
)

// supportedLinuxFS reports whether the filesystem with statfs type magic
// is one whose permissions the gate can check.
func supportedLinuxFS(magic uint32) bool {
	switch magic {
	case fsExt4, fsXFS, fsBtrfs, fsTmpfs:
		return true
	case fsOverlay:
		return overlayFSSupported
	}
	return false
}

// overlayFSSupported admits overlayfs (fsOverlay). It is one constant so
// that the choice stays visible and can be undone in one place.
const overlayFSSupported = true

// darwinMountLocal is MNT_LOCAL in statfs f_flags.
const darwinMountLocal = 0x1000

// supportedDarwinFS reports whether the macOS filesystem named fstype,
// mounted with flags, is one whose permissions the gate can check: a local
// APFS or HFS+ volume, where access control lists are always supported.
func supportedDarwinFS(fstype string, flags uint32) bool {
	return (fstype == "apfs" || fstype == "hfs") && flags&darwinMountLocal != 0
}
