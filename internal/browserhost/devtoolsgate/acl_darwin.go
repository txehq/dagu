// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build darwin

package devtoolsgate

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// checkFilesystemAndACL refuses the open object f, at path, when it is not
// on a local APFS or HFS+ volume (supportedDarwinFS), or when its access
// control list, read from f itself with fgetattrlist, lets another account
// in (parseAttrList, checkKauthACL). A list that cannot be read is refused.
func checkFilesystemAndACL(f *os.File, _ bool, r role, path string) error {
	fd := int(f.Fd()) //nolint:gosec // a descriptor number
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return fmt.Errorf("devtools gate: %s: read its filesystem: %w", r, err)
	}
	if name := unix.ByteSliceToString(fs.Fstypename[:]); !supportedDarwinFS(name, fs.Flags) {
		return fmt.Errorf("devtools gate: %s is on a filesystem whose permissions the gate cannot check (%s): %s", r, name, path)
	}
	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: attrRequested}
	// Room for the fixed part and the largest list the kernel keeps.
	buf := make([]byte, attrFixedSize+kauthFilesecSize0+kauthACLMaxEntries*kauthACESize)
	// x/sys has no libSystem wrapper for fgetattrlist, and Dagu is built
	// without cgo, so it goes through the syscall entry x/sys keeps. Should
	// macOS ever drop that, the call fails and every profile is refused.
	_, _, errno := unix.Syscall6(unix.SYS_FGETATTRLIST, uintptr(fd), //nolint:staticcheck // see above
		uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), //nolint:gosec // fgetattrlist's arguments
		uintptr(unix.FSOPT_PACK_INVAL_ATTRS), 0)
	runtime.KeepAlive(f)
	if errno != 0 {
		return fmt.Errorf("devtools gate: the access control list of %s cannot be read: %w: %s", r, errno, path)
	}
	acl, err := parseAttrList(buf)
	if err != nil {
		return fmt.Errorf("devtools gate: %s: %w: %s", r, err, path)
	}
	return checkKauthACL(acl, r, path)
}
