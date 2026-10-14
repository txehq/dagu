// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package cliauth

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// checkPrivate requires path to be a directory (dir) or regular file, not a
// link or other reparse point, owned by this user and closed to every other
// user by its DACL. SYSTEM and Administrators are trusted as on any Windows
// profile; they also own what an elevated shell creates. A directory of the
// user's own that is more open than that is closed to those three; a file is
// refused, since something other than this package made it so.
func checkPrivate(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0:
		return fmt.Errorf("sign-in store: %s is a link or reparse point", path)
	case dir && !fi.IsDir():
		return fmt.Errorf("sign-in store: %s is not a directory", path)
	case !dir && !fi.Mode().IsRegular():
		return fmt.Errorf("sign-in store: %s is not a regular file", path)
	}
	trusted, err := trustedSIDs()
	if err != nil {
		return fmt.Errorf("sign-in store: %w", err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("sign-in store: read the access control of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("sign-in store: read the owner of %s: %w", path, err)
	}
	if !trusted.has(owner) {
		return fmt.Errorf("sign-in store: %s belongs to another user", path)
	}
	open, err := openToOthers(sd, trusted)
	if err != nil {
		return fmt.Errorf("sign-in store: read the access control of %s: %w", path, err)
	}
	if !open {
		return nil
	}
	if dir {
		if err := closeToOthers(path, trusted); err != nil {
			return fmt.Errorf("sign-in store: close %s to other users: %w", path, err)
		}
		return nil
	}
	return fmt.Errorf("sign-in store: %s can be read or written by other users; run \"dagu txe login\" to replace it", path)
}

// sids is this user, SYSTEM and Administrators.
type sids []*windows.SID

func (s sids) has(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	for _, t := range s {
		if t.Equals(sid) {
			return true
		}
	}
	return false
}

func trustedSIDs() (sids, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read this user's identity: %w", err)
	}
	self, err := user.User.Sid.Copy()
	if err != nil {
		return nil, fmt.Errorf("read this user's identity: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	return sids{self, system, admins}, nil
}

// openToOthers reports whether the DACL lets anyone outside trusted in. No
// DACL, or a null one, lets everyone in. An allow entry of a kind not read
// here counts as open.
func openToOthers(sd *windows.SECURITY_DESCRIPTOR, trusted sids) (bool, error) {
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if dacl == nil {
		return true, nil
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // the SID starts at SidStart inside the ACE
			if !trusted.has(sid) {
				return true, nil
			}
		default:
			return true, nil
		}
	}
	return false, nil
}

// closeToOthers gives path a protected DACL that only trusted may use,
// inherited by everything created in it.
func closeToOthers(path string, trusted sids) error {
	// A TrusteeValue is an address the collector does not see, so each SID
	// is pinned until the ACL is built from it.
	var pins runtime.Pinner
	defer pins.Unpin()
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(trusted))
	for _, sid := range trusted {
		pins.Pin(sid)
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
