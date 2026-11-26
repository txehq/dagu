// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package devtoolsgate

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// checkFilesystemAndACL refuses the open object f, at path, when its
// filesystem is not one whose permissions the gate reads
// (supportedLinuxFS), or when its POSIX access control lists, read from f
// itself, let another account in (checkPOSIXAccessACL,
// checkPOSIXDefaultACL for a directory).
//
// A POSIX list the filesystem cannot hold (EOPNOTSUPP: lists are off on
// the mount) is refused, never taken for an empty one. A list of another
// model (NFSv4 or rich lists) is refused when present; on these
// filesystems their names have no handler, which answers EOPNOTSUPP, and
// that alone does not refuse.
func checkFilesystemAndACL(f *os.File, dir bool, r role, path string) error {
	fd := int(f.Fd()) //nolint:gosec // a descriptor number
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return fmt.Errorf("devtools gate: %s: read its filesystem: %w", r, err)
	}
	if !supportedLinuxFS(uint32(fs.Type)) { //nolint:gosec // statfs magics are 32-bit
		return fmt.Errorf("devtools gate: %s is on a filesystem whose permissions the gate cannot check (type %#x): %s", r, uint32(fs.Type), path) //nolint:gosec // as above
	}
	euid := uint32(os.Geteuid()) //nolint:gosec // a uid
	lists := []struct {
		name  string
		check func([]posixEntry, role, uint32, string) error
	}{{"system.posix_acl_access", checkPOSIXAccessACL}}
	if dir {
		lists = append(lists, struct {
			name  string
			check func([]posixEntry, role, uint32, string) error
		}{"system.posix_acl_default", checkPOSIXDefaultACL})
	}
	for _, list := range lists {
		raw, present, err := getXattr(fd, list.name)
		switch {
		case errors.Is(err, unix.EOPNOTSUPP):
			return fmt.Errorf("devtools gate: access control lists are off on the filesystem of %s, so they cannot be checked (mount it with acl): %s", r, path)
		case err != nil:
			return fmt.Errorf("devtools gate: the access control list of %s cannot be read: %w: %s", r, err, path)
		case !present:
			continue
		}
		entries, err := parsePOSIXACL(raw)
		if err != nil {
			return fmt.Errorf("devtools gate: %s: %w: %s", r, err, path)
		}
		if err := list.check(entries, r, euid, path); err != nil {
			return err
		}
	}
	for _, name := range []string{"system.nfs4_acl", "system.richacl"} {
		_, present, err := getXattr(fd, name)
		switch {
		case errors.Is(err, unix.EOPNOTSUPP):
		case err != nil:
			return fmt.Errorf("devtools gate: the access control list of %s cannot be read: %w: %s", r, err, path)
		case present:
			return fmt.Errorf("devtools gate: %s carries an access control list of a kind the gate does not read (%s): %s", r, name, path)
		}
	}
	return nil
}

// getXattr reads the extended attribute name of the open object fd. It
// reports present false, with no error, for ENODATA: the object has no
// such attribute.
func getXattr(fd int, name string) ([]byte, bool, error) {
	for range 3 {
		size, err := unix.Fgetxattr(fd, name, nil)
		if errors.Is(err, unix.ENODATA) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		buf := make([]byte, size)
		n, err := unix.Fgetxattr(fd, name, buf)
		if errors.Is(err, unix.ERANGE) {
			continue // it grew between the two reads
		}
		if errors.Is(err, unix.ENODATA) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		return buf[:n], true, nil
	}
	return nil, false, fmt.Errorf("extended attribute %s kept changing size", name)
}
