// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// macOS: an object's access control list as fgetattrlist returns it, asked
// for ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID
// with FSOPT_PACK_INVAL_ATTRS (sys/attr.h, sys/kauth.h). The buffer holds,
// each field 4-byte aligned:
//
//	u32             length of what was returned
//	attribute_set_t returned: commonattr, volattr, dirattr, fileattr, forkattr
//	attrreference_t extended security: {i32 offset from this field, u32 length}
//	guid_t          the owner's UUID
//
// and, at the attrreference's offset, a kauth_filesec: u32 magic, two
// 16-byte GUIDs (left empty by the kernel), u32 entry count, u32 flags,
// then 24-byte entries {guid_t, u32 flags, u32 rights}.
const (
	attrCmnReturnedAttrs    = 0x80000000
	attrCmnExtendedSecurity = 0x00400000
	attrCmnUUID             = 0x00800000
	attrRequested           = attrCmnReturnedAttrs | attrCmnExtendedSecurity | attrCmnUUID

	attrFixedSize = 4 + 20 + 8 + 16 // what precedes the variable data
	attrRefOffset = 24              // where the extended security reference is
	attrUUIDAt    = 32              // where the owner's UUID is

	kauthFilesecMagic  = 0x012cc16d
	kauthFilesecNoACL  = 0xFFFFFFFF
	kauthFilesecSize0  = 44 // KAUTH_FILESEC_SIZE(0): magic, two GUIDs, count, flags
	kauthACESize       = 24
	kauthACLMaxEntries = 128

	kauthACEKindMask = 0xf
	kauthACEPermit   = 1
	kauthACEDeny     = 2
	// The flag bits an entry may carry besides its kind: inherited, file
	// and directory inherit, limit inherit, inherit only.
	kauthACEKnownFlags = kauthACEKindMask | 1<<4 | 1<<5 | 1<<6 | 1<<7 | 1<<8

	// The rights an entry may carry: KAUTH_VNODE_READ_DATA (1<<1) to
	// TAKE_OWNERSHIP (1<<13), SYNCHRONIZE (1<<20) and the generic rights
	// (1<<21 to 1<<24).
	kauthKnownRights = 0x3FFE | 1<<20 | 1<<21 | 1<<22 | 1<<23 | 1<<24
	// The rights that let a principal change an object or what it holds:
	// write data or add a file, delete, append data or add a directory,
	// delete a child, write attributes, write extended attributes, write
	// security (the list itself), take ownership, generic all and write.
	kauthChangeRights = 1<<2 | 1<<4 | 1<<5 | 1<<6 | 1<<8 | 1<<10 | 1<<12 | 1<<13 | 1<<21 | 1<<23
)

type kauthACE struct {
	guid   [16]byte
	flags  uint32
	rights uint32
}

// kauthACL is what parseAttrList read: the owner's UUID, when it was
// returned and is not empty, and the list's entries (none when the object
// has no list).
type kauthACL struct {
	owner      [16]byte
	ownerKnown bool
	entries    []kauthACE
}

// parseAttrList reads an fgetattrlist buffer laid out as above. A buffer
// that does not hold exactly what was asked for is refused: a length out
// of bounds, a returned attribute not asked for, a reference outside the
// returned data or into the fixed part, misaligned, or of a size that is
// not a whole kauth_filesec, a wrong magic, an entry count that does not
// match the size or is over KAUTH_ACL_MAX_ENTRIES, or list flags set.
func parseAttrList(b []byte) (kauthACL, error) {
	var acl kauthACL
	if len(b) < attrFixedSize {
		return acl, fmt.Errorf("%w: %d bytes", errUnreadableACL, len(b))
	}
	le := binary.LittleEndian
	length := le.Uint32(b)
	if length < attrFixedSize || uint64(length) > uint64(len(b)) {
		return acl, fmt.Errorf("%w: length %d", errUnreadableACL, length)
	}
	common := le.Uint32(b[4:])
	if common&^attrRequested != 0 || le.Uint32(b[8:])|le.Uint32(b[12:])|le.Uint32(b[16:])|le.Uint32(b[20:]) != 0 {
		return acl, fmt.Errorf("%w: attributes not asked for", errUnreadableACL)
	}
	copy(acl.owner[:], b[attrUUIDAt:attrUUIDAt+16])
	acl.ownerKnown = common&attrCmnUUID != 0 && acl.owner != [16]byte{}
	offset := int64(int32(le.Uint32(b[attrRefOffset:]))) //nolint:gosec // a signed field as the kernel writes it
	size := int64(le.Uint32(b[attrRefOffset+4:]))
	if common&attrCmnExtendedSecurity == 0 {
		// No list: the kernel packs an empty reference, whose offset it
		// may still set, so only the length is read.
		if size != 0 {
			return acl, fmt.Errorf("%w: a list that was not returned has a length", errUnreadableACL)
		}
		return acl, nil
	}
	start := attrRefOffset + offset
	if start < attrFixedSize || start%4 != 0 || size > int64(length)-start {
		return acl, fmt.Errorf("%w: the list's reference is out of bounds", errUnreadableACL)
	}
	if size < kauthFilesecSize0 || (size-kauthFilesecSize0)%kauthACESize != 0 {
		return acl, fmt.Errorf("%w: a list of %d bytes", errUnreadableACL, size)
	}
	sec := b[start : start+size]
	if le.Uint32(sec) != kauthFilesecMagic {
		return acl, fmt.Errorf("%w: magic %#x", errUnreadableACL, le.Uint32(sec))
	}
	count, flags := le.Uint32(sec[36:]), le.Uint32(sec[40:])
	if flags != 0 {
		return acl, fmt.Errorf("%w: list flags %#x", errUnreadableACL, flags)
	}
	if count == kauthFilesecNoACL {
		if size != kauthFilesecSize0 {
			return acl, fmt.Errorf("%w: an empty list of %d bytes", errUnreadableACL, size)
		}
		return acl, nil
	}
	if count > kauthACLMaxEntries || size != kauthFilesecSize0+int64(count)*kauthACESize {
		return acl, fmt.Errorf("%w: %d entries in %d bytes", errUnreadableACL, count, size)
	}
	for i := range int64(count) {
		at := kauthFilesecSize0 + i*kauthACESize
		var e kauthACE
		copy(e.guid[:], sec[at:at+16])
		e.flags, e.rights = le.Uint32(sec[at+16:]), le.Uint32(sec[at+20:])
		acl.entries = append(acl.entries, e)
	}
	return acl, nil
}

// checkKauthACL refuses a list that lets a principal other than the
// object's owner change the object of role r, or, for the profile
// directory, have any access to it. Deny entries are passed over: an
// allowing entry the gate refuses is refused even where a deny before it
// would take effect first. An allowing entry for a group is refused
// whatever the group, since membership is not read. Entries that only
// govern what is created in a directory later count as well. An entry of a
// kind, with a flag or with a right the gate does not know is refused. The
// owner is recognised only by the UUID the kernel returned for it.
func checkKauthACL(acl kauthACL, r role, path string) error {
	for _, e := range acl.entries {
		if e.flags&^kauthACEKnownFlags != 0 {
			return fmt.Errorf("devtools gate: %w on %s, with flags %#x: %s", errUnreadableACL, r, e.flags, path)
		}
		switch e.flags & kauthACEKindMask {
		case kauthACEDeny:
			continue
		case kauthACEPermit:
		default:
			return fmt.Errorf("devtools gate: %w on %s, of kind %d: %s", errUnreadableACL, r, e.flags&kauthACEKindMask, path)
		}
		if e.rights&^kauthKnownRights != 0 {
			return fmt.Errorf("devtools gate: %w on %s, with rights %#x: %s", errUnreadableACL, r, e.rights, path)
		}
		if acl.ownerKnown && bytes.Equal(e.guid[:], acl.owner[:]) {
			continue
		}
		if r == roleProfile && e.rights != 0 {
			return fmt.Errorf("devtools gate: an access control list opens %s to another account: %s", r, path)
		}
		if e.rights&kauthChangeRights != 0 {
			return fmt.Errorf("devtools gate: an access control list lets another account change %s: %s", r, path)
		}
	}
	return nil
}
