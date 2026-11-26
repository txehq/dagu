// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package devtoolsgate

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// On Unix a profile the gate writes is private to this user: no other
// account can change the profile directory, the entries the gate and a
// claim use in it, or any directory on the path to it, from the check until
// the browser has opened the profile. Every check reads one open object, a
// file descriptor: its owner, mode, link count, filesystem and access
// control list come from that descriptor and never from a path name beside
// it (checkOpened). The path is opened one component at a time from "/"
// (openTrusted), each directory checked before the next is opened, so the
// path the browser is later started on cannot be redirected by anyone but
// this user or root.

// checkOpened refuses the open object f, at path, when it breaks the rules
// of its role (checkMetadata), sits on a filesystem whose permissions the
// gate cannot check, or carries an access control list that lets another
// account in (checkFilesystemAndACL, per platform).
func checkOpened(f *os.File, r role, path string) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("devtools gate: %s: %w", r, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("devtools gate: %s cannot be read: %s", r, path)
	}
	if err := checkMetadata(r, path, info.Mode(), uint32(stat.Uid), uint64(stat.Nlink), uint32(os.Geteuid())); err != nil { //nolint:gosec // uid and link count are small
		return err
	}
	return checkFilesystemAndACL(f, info.IsDir(), r, path)
}

// openTrusted opens the profile directory path one component at a time
// from "/", without following a symbolic link anywhere, and checks each
// directory before it opens the next: every directory on the way under the
// rules of roleAncestor, the last one under roleProfile. It returns the
// profile directory open. path must be absolute and canonical: no ".",
// ".." or empty component, and no symbolic link, since a link is a name
// another account may be able to point elsewhere.
func openTrusted(path string) (*os.File, error) {
	if path == "" || path[0] != '/' {
		return nil, ErrProfileRequired
	}
	names := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, name := range names {
		if name == "" || name == "." || name == ".." {
			return nil, fmt.Errorf("devtools gate: the profile path is not canonical: %s", path)
		}
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("devtools gate: open /: %w", err)
	}
	current := os.NewFile(uintptr(fd), "/")
	if err := checkOpened(current, roleAncestor, "/"); err != nil {
		_ = current.Close()
		return nil, err
	}
	for i, name := range names {
		walked := "/" + strings.Join(names[:i+1], "/")
		parent := int(current.Fd()) //nolint:gosec // a descriptor number
		next, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			// Which of the two a link gives depends on the system: look.
			var st unix.Stat_t
			if unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
				_ = current.Close()
				return nil, fmt.Errorf("devtools gate: the profile path passes through a symbolic link: %s", walked)
			}
		}
		_ = current.Close()
		switch {
		case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
			return nil, fmt.Errorf("devtools gate: the profile path is not a directory: %s", walked)
		case err != nil:
			return nil, fmt.Errorf("devtools gate: the profile directory: %s: %w", walked, err)
		}
		current = os.NewFile(uintptr(next), walked)
		r := roleAncestor
		if i == len(names)-1 {
			r = roleProfile
		}
		if err := checkOpened(current, r, walked); err != nil {
			_ = current.Close()
			return nil, err
		}
	}
	return current, nil
}

// openEntry opens name in root, the profile directory or a directory in
// it, without following a symbolic link, and checks it under roleEntry: a
// directory when dir is set, a regular file otherwise. It returns nil and
// no error when nothing is there.
func openEntry(root *os.Root, name string, dir bool) (*os.File, error) {
	flags := os.O_RDONLY | unix.O_NOFOLLOW
	if dir {
		flags |= unix.O_DIRECTORY
	}
	path := root.Name() + "/" + name
	// A symbolic link is refused by name first: os.Root answers one that
	// points out of the directory with an error of its own. The open below
	// refuses one that appears after this look all the same (O_NOFOLLOW).
	if info, err := root.Lstat(name); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if dir {
			return nil, fmt.Errorf("devtools gate: %s is not a directory (a symbolic link is not followed): %s", roleEntry, path)
		}
		return nil, fmt.Errorf("devtools gate: %s is not a regular file (a symbolic link is not followed): %s", roleEntry, path)
	}
	f, err := root.OpenFile(name, flags, 0)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case dir && (errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR)):
		return nil, fmt.Errorf("devtools gate: %s is not a directory (a symbolic link is not followed): %s", roleEntry, path)
	case errors.Is(err, unix.ELOOP):
		return nil, fmt.Errorf("devtools gate: %s is not a regular file (a symbolic link is not followed): %s", roleEntry, path)
	case err != nil:
		return nil, fmt.Errorf("devtools gate: %s: %w", roleEntry, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("devtools gate: %s: %w", roleEntry, err)
	}
	if dir != info.IsDir() || (!dir && !info.Mode().IsRegular()) {
		_ = f.Close()
		if dir {
			return nil, fmt.Errorf("devtools gate: %s is not a directory: %s", roleEntry, path)
		}
		return nil, fmt.Errorf("devtools gate: %s is not a regular file: %s", roleEntry, path)
	}
	if err := checkOpened(f, roleEntry, path); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
