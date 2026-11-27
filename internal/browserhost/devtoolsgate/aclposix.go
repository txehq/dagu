// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// A POSIX access control list as Linux stores it in the extended
// attributes system.posix_acl_access and system.posix_acl_default
// (linux/posix_acl_xattr.h): a little-endian u32 version, then 8-byte
// entries {u16 tag, u16 perm, u32 id}.
const (
	posixACLVersion  = 2
	posixUserObj     = 0x01
	posixUser        = 0x02
	posixGroupObj    = 0x04
	posixGroup       = 0x08
	posixMask        = 0x10
	posixOther       = 0x20
	posixWrite       = 0x02
	posixPermBits    = 0x07
	posixUndefinedID = 0xFFFFFFFF
)

type posixEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

// errUnreadableACL is wrapped by every refusal of a list the gate cannot
// read as a valid one.
var errUnreadableACL = errors.New("an access control list the gate cannot read")

// parsePOSIXACL parses and validates a list as acl(5) defines a valid one,
// in the form the kernel keeps it (posix_acl_valid): exactly one owner,
// owning group and other entry; named user and group entries, each with a
// defined qualifier, in ascending order of it, so none twice; a mask entry,
// at most one, which must be there when a named entry is and may be there
// without one; permissions within read, write and execute; and the entries
// in canonical order (owner, named users, owning group, named groups, mask,
// other). Anything else is refused.
func parsePOSIXACL(b []byte) ([]posixEntry, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 {
		return nil, fmt.Errorf("%w: %d bytes", errUnreadableACL, len(b))
	}
	if v := binary.LittleEndian.Uint32(b); v != posixACLVersion {
		return nil, fmt.Errorf("%w: version %d", errUnreadableACL, v)
	}
	entries := make([]posixEntry, 0, (len(b)-4)/8)
	counts := map[uint16]int{}
	users, groups := map[uint32]bool{}, map[uint32]bool{}
	var prev *posixEntry
	for off := 4; off < len(b); off += 8 {
		e := posixEntry{
			tag:  binary.LittleEndian.Uint16(b[off:]),
			perm: binary.LittleEndian.Uint16(b[off+2:]),
			id:   binary.LittleEndian.Uint32(b[off+4:]),
		}
		if e.perm&^posixPermBits != 0 {
			return nil, fmt.Errorf("%w: permissions %#x", errUnreadableACL, e.perm)
		}
		switch e.tag {
		case posixUserObj, posixGroupObj, posixMask, posixOther:
			if e.id != posixUndefinedID {
				return nil, fmt.Errorf("%w: a qualifier on tag %#x", errUnreadableACL, e.tag)
			}
		case posixUser, posixGroup:
			if e.id == posixUndefinedID {
				return nil, fmt.Errorf("%w: a named entry without a qualifier", errUnreadableACL)
			}
			if e.tag == posixUser {
				users[e.id] = true
			} else {
				groups[e.id] = true
			}
		default:
			return nil, fmt.Errorf("%w: tag %#x", errUnreadableACL, e.tag)
		}
		// The tag values ascend in canonical order; named entries of one
		// tag ascend by qualifier, which also refuses one twice.
		if prev != nil && (e.tag < prev.tag || (e.tag == prev.tag && (e.tag&(posixUser|posixGroup) == 0 || e.id <= prev.id))) {
			return nil, fmt.Errorf("%w: entries out of order", errUnreadableACL)
		}
		counts[e.tag]++
		entries = append(entries, e)
		prev = &entries[len(entries)-1]
	}
	for _, tag := range []uint16{posixUserObj, posixGroupObj, posixOther} {
		if counts[tag] != 1 {
			return nil, fmt.Errorf("%w: %d entries of tag %#x", errUnreadableACL, counts[tag], tag)
		}
	}
	if counts[posixMask] > 1 || (len(users)+len(groups) > 0 && counts[posixMask] == 0) {
		return nil, fmt.Errorf("%w: mask entries do not match its named entries", errUnreadableACL)
	}
	return entries, nil
}

// checkPOSIXAccessACL refuses an access list (system.posix_acl_access) of
// an object of role r that lets an account other than this user (euid) or
// root change it, or, for the profile directory, have any access at all.
//
// Only named user and group entries are read here. The owning group's,
// the mask's and other's permissions are the object's mode bits (with a
// list, the group bits are the mask), which checkMetadata already holds to
// the role's rules; the mask bounds every named entry, so a named write
// the mask allows shows as group write and is refused there too. A named
// write the mask hides grants nothing, and is refused anyway: the gate does
// not rely on the mask staying as it is.
func checkPOSIXAccessACL(entries []posixEntry, r role, euid uint32, path string) error {
	for _, e := range entries {
		named := e.tag == posixGroup || (e.tag == posixUser && e.id != euid && e.id != 0)
		if !named {
			continue
		}
		if r == roleProfile && e.perm != 0 {
			return fmt.Errorf("devtools gate: an access control list opens %s to another account: %s", r, path)
		}
		if e.perm&posixWrite != 0 {
			return fmt.Errorf("devtools gate: an access control list lets another account change %s: %s", r, path)
		}
	}
	return nil
}

// checkPOSIXDefaultACL refuses a default list (system.posix_acl_default)
// of a directory of role r in which an entry other than the owner's (and
// the mask, a ceiling that grants nothing itself) grants write: the list is
// inherited by what is created in the directory later, whatever mode that
// is created with. For the profile directory, any access is refused.
func checkPOSIXDefaultACL(entries []posixEntry, r role, euid uint32, path string) error {
	for _, e := range entries {
		switch {
		case e.tag == posixUserObj, e.tag == posixMask:
			continue
		case e.tag == posixUser && (e.id == euid || e.id == 0):
			continue
		}
		if r == roleProfile && e.perm != 0 {
			return fmt.Errorf("devtools gate: an inherited access control list opens what is created in %s to another account: %s", r, path)
		}
		if e.perm&posixWrite != 0 {
			return fmt.Errorf("devtools gate: an inherited access control list lets another account change what is created in %s: %s", r, path)
		}
	}
	return nil
}
