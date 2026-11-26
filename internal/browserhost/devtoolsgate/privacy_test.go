// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests read synthetic bytes and stat values only: they check the
// parsers and rules, not that a kernel returns these bytes (that is the
// real access control list fixtures' work).

const testEUID = 1000

func TestCheckMetadataRules(t *testing.T) {
	t.Parallel()
	dir, sticky := os.ModeDir, os.ModeDir|os.ModeSticky
	for name, c := range map[string]struct {
		r     role
		mode  os.FileMode
		uid   uint32
		nlink uint64
		want  string
	}{
		"ancestor of this user":              {roleAncestor, dir | 0o755, testEUID, 2, ""},
		"ancestor of root":                   {roleAncestor, dir | 0o755, 0, 2, ""},
		"ancestor of another user":           {roleAncestor, dir | 0o755, 2000, 2, "belongs to another user"},
		"group-writable ancestor":            {roleAncestor, dir | 0o775, testEUID, 2, "others may write"},
		"sticky ancestor of root":            {roleAncestor, sticky | 0o777, 0, 2, ""},
		"sticky ancestor of this user":       {roleAncestor, sticky | 0o777, testEUID, 2, "others may write"},
		"profile 0700":                       {roleProfile, dir | 0o700, testEUID, 2, ""},
		"profile others may enter":           {roleProfile, dir | 0o711, testEUID, 2, "it must be 0700"},
		"profile others may read":            {roleProfile, dir | 0o750, testEUID, 2, "it must be 0700"},
		"profile others may write":           {roleProfile, dir | 0o770, testEUID, 2, "others may write"},
		"profile of root":                    {roleProfile, dir | 0o700, 0, 2, "belongs to another user"},
		"entry file":                         {roleEntry, 0o644, testEUID, 1, ""},
		"entry file with another link":       {roleEntry, 0o600, testEUID, 2, "has another link"},
		"entry directory with links":         {roleEntry, dir | 0o755, testEUID, 3, ""},
		"entry others may write":             {roleEntry, 0o664, testEUID, 1, "others may write"},
		"entry of another user":              {roleEntry, 0o600, 2000, 1, "belongs to another user"},
		"entry of root is not this user's":   {roleEntry, 0o600, 0, 1, "belongs to another user"},
		"sticky entry gets no ancestor pass": {roleEntry, sticky | 0o777, 0, 2, "belongs to another user"},
	} {
		err := checkMetadata(c.r, "/p", c.mode, c.uid, c.nlink, testEUID)
		if c.want == "" {
			assert.NoError(t, err, name)
		} else {
			assert.ErrorContains(t, err, c.want, name)
		}
	}
}

func TestSupportedFilesystems(t *testing.T) {
	t.Parallel()
	for _, magic := range []uint32{0xEF53, 0x58465342, 0x9123683E, 0x01021994} {
		assert.True(t, supportedLinuxFS(magic), "%#x", magic)
	}
	assert.Equal(t, overlayFSSupported, supportedLinuxFS(0x794C7630), "overlayfs follows its one constant")
	// NFS, SMB2, FUSE, ZFS, 9p and an unknown type are refused.
	for _, magic := range []uint32{0x6969, 0xFE534D42, 0x65735546, 0x2FC12FC1, 0x01021997, 0x12345678} {
		assert.False(t, supportedLinuxFS(magic), "%#x", magic)
	}
	assert.True(t, supportedDarwinFS("apfs", darwinMountLocal))
	assert.True(t, supportedDarwinFS("hfs", darwinMountLocal|0x1))
	assert.False(t, supportedDarwinFS("apfs", 0), "a volume not mounted local")
	for _, fs := range []string{"smbfs", "nfs", "afpfs", "exfat", "msdos", "macfuse", ""} {
		assert.False(t, supportedDarwinFS(fs, darwinMountLocal), fs)
	}
}

// posixACL builds a system.posix_acl_* value from entries.
func posixACL(entries ...posixEntry) []byte {
	b := binary.LittleEndian.AppendUint32(nil, posixACLVersion)
	for _, e := range entries {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	return b
}

var (
	userObj  = posixEntry{posixUserObj, 7, posixUndefinedID}
	groupObj = posixEntry{posixGroupObj, 5, posixUndefinedID}
	other    = posixEntry{posixOther, 5, posixUndefinedID}
)

func mask(perm uint16) posixEntry                  { return posixEntry{posixMask, perm, posixUndefinedID} }
func namedUser(id uint32, perm uint16) posixEntry  { return posixEntry{posixUser, perm, id} }
func namedGroup(id uint32, perm uint16) posixEntry { return posixEntry{posixGroup, perm, id} }

func TestParsePOSIXACLValidity(t *testing.T) {
	t.Parallel()
	valid := map[string][]byte{
		"minimal":                       posixACL(userObj, groupObj, other),
		"mask without a named entry":    posixACL(userObj, groupObj, mask(5), other),
		"named entries with their mask": posixACL(userObj, namedUser(2000, 4), groupObj, namedGroup(3000, 4), mask(5), other),
	}
	for name, b := range valid {
		_, err := parsePOSIXACL(b)
		assert.NoError(t, err, name)
	}
	short := posixACL(userObj, groupObj, other)
	invalid := map[string][]byte{
		"empty":                      nil,
		"header only":                binary.LittleEndian.AppendUint32(nil, posixACLVersion),
		"a partial entry":            short[:len(short)-3],
		"version 1":                  append(binary.LittleEndian.AppendUint32(nil, 1), short[4:]...),
		"no owner entry":             posixACL(groupObj, other, mask(0)),
		"two owner entries":          posixACL(userObj, userObj, groupObj, other),
		"no other entry":             posixACL(userObj, groupObj, mask(0)),
		"a named entry and no mask":  posixACL(userObj, namedUser(2000, 4), groupObj, other),
		"two masks":                  posixACL(userObj, groupObj, mask(5), mask(5), other),
		"a user twice":               posixACL(userObj, namedUser(2000, 4), namedUser(2000, 5), groupObj, mask(5), other),
		"a group twice":              posixACL(userObj, groupObj, namedGroup(3000, 4), namedGroup(3000, 4), mask(5), other),
		"a qualifier on the owner":   posixACL(posixEntry{posixUserObj, 7, 0}, groupObj, other),
		"a permission bit not known": posixACL(posixEntry{posixUserObj, 0o17, posixUndefinedID}, groupObj, other),
		"an unknown tag":             posixACL(userObj, groupObj, other, posixEntry{0x40, 0, posixUndefinedID}),
	}
	for name, b := range invalid {
		_, err := parsePOSIXACL(b)
		assert.ErrorIs(t, err, errUnreadableACL, name)
	}
}

func TestPOSIXAccessACLRules(t *testing.T) {
	t.Parallel()
	check := func(r role, entries ...posixEntry) error {
		parsed, err := parsePOSIXACL(posixACL(entries...))
		require.NoError(t, err)
		return checkPOSIXAccessACL(parsed, r, testEUID, "/p")
	}
	assert.NoError(t, check(roleEntry, userObj, groupObj, other))
	assert.NoError(t, check(roleEntry, userObj, namedUser(2000, 5), groupObj, mask(5), other), "a named read")
	assert.ErrorContains(t, check(roleEntry, userObj, namedUser(2000, 7), groupObj, mask(5), other),
		"lets another account change", "a named write the mask hides is refused all the same")
	assert.ErrorContains(t, check(roleAncestor, userObj, namedGroup(3000, 2), groupObj, mask(7), other), "lets another account change")
	assert.NoError(t, check(roleEntry, userObj, namedUser(testEUID, 7), groupObj, mask(7), other), "this user's own named entry")
	assert.NoError(t, check(roleAncestor, userObj, namedUser(0, 7), groupObj, mask(7), other), "root's named entry")
	assert.NoError(t, check(roleEntry, userObj, groupObj, mask(7), other),
		"a mask alone grants nothing; a writable mask shows as group write, which checkMetadata refuses")
	assert.ErrorContains(t, check(roleProfile, userObj, namedUser(2000, 4), groupObj, mask(0), other),
		"opens the profile directory", "the profile directory admits no other account at all")
}

func TestPOSIXDefaultACLRules(t *testing.T) {
	t.Parallel()
	check := func(r role, entries ...posixEntry) error {
		parsed, err := parsePOSIXACL(posixACL(entries...))
		require.NoError(t, err)
		return checkPOSIXDefaultACL(parsed, r, testEUID, "/p")
	}
	noWrite := func(e posixEntry) posixEntry { e.perm &^= posixWrite; return e }
	assert.NoError(t, check(roleEntry, userObj, noWrite(groupObj), noWrite(other)), "only the owner may write")
	assert.ErrorContains(t, check(roleEntry, userObj, posixEntry{posixGroupObj, 7, posixUndefinedID}, noWrite(other)), "what is created in")
	assert.ErrorContains(t, check(roleEntry, userObj, noWrite(groupObj), posixEntry{posixOther, 6, posixUndefinedID}), "what is created in")
	assert.ErrorContains(t, check(roleEntry, userObj, namedUser(2000, 6), noWrite(groupObj), mask(4), noWrite(other)),
		"what is created in", "a named write in a default list is refused whatever the mask")
	assert.NoError(t, check(roleEntry, userObj, noWrite(groupObj), mask(7), noWrite(other)), "a mask is a ceiling")
	assert.NoError(t, check(roleEntry, userObj, namedUser(testEUID, 7), noWrite(groupObj), mask(7), noWrite(other)))
	assert.ErrorContains(t, check(roleProfile, userObj, posixEntry{posixGroupObj, 0, posixUndefinedID}, posixEntry{posixOther, 4, posixUndefinedID}),
		"opens what is created in", "the profile directory: no inherited access at all")
	assert.NoError(t, check(roleProfile, userObj, posixEntry{posixGroupObj, 0, posixUndefinedID}, posixEntry{posixOther, 0, posixUndefinedID}))
}

// attrList builds an fgetattrlist buffer: returned is the common attribute
// group returned; filesec, when not nil, is placed after the fixed part
// and referenced; owner is the owner's UUID.
func attrList(returned uint32, owner [16]byte, filesec []byte) []byte {
	le := binary.LittleEndian
	b := make([]byte, attrFixedSize)
	le.PutUint32(b[4:], returned)
	copy(b[attrUUIDAt:], owner[:])
	if filesec != nil {
		le.PutUint32(b[attrRefOffset:], uint32(attrFixedSize-attrRefOffset))
		le.PutUint32(b[attrRefOffset+4:], uint32(len(filesec))) //nolint:gosec // test sizes
		b = append(b, filesec...)
	}
	le.PutUint32(b, uint32(len(b))) //nolint:gosec // test sizes
	return b
}

// filesec builds a kauth_filesec holding aces, or the empty list when aces
// is nil.
func filesec(aces []kauthACE) []byte {
	le := binary.LittleEndian
	b := le.AppendUint32(nil, kauthFilesecMagic)
	b = append(b, make([]byte, 32)...)
	if aces == nil {
		b = le.AppendUint32(b, kauthFilesecNoACL)
		return le.AppendUint32(b, 0)
	}
	b = le.AppendUint32(b, uint32(len(aces))) //nolint:gosec // test sizes
	b = le.AppendUint32(b, 0)
	for _, e := range aces {
		b = append(b, e.guid[:]...)
		b = le.AppendUint32(b, e.flags)
		b = le.AppendUint32(b, e.rights)
	}
	return b
}

var (
	ownerUUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	otherUUID = [16]byte{0xAB, 0xCD}
)

const (
	rightRead        = 1 << 1
	rightAddFile     = 1 << 2
	rightSearch      = 1 << 3
	rightDelete      = 1 << 4
	rightDeleteChild = 1 << 6
	rightWriteSec    = 1 << 12
	rightTakeOwner   = 1 << 13
	rightGenericAll  = 1 << 21
	flagOnlyInherit  = 1 << 8
	flagFileInherit  = 1 << 5
	allCommon        = attrCmnReturnedAttrs | attrCmnExtendedSecurity | attrCmnUUID
)

func TestParseAttrListLayout(t *testing.T) {
	t.Parallel()
	le := binary.LittleEndian

	// No list: the attribute is not returned, and its reference is empty
	// though the kernel may leave an offset in it.
	b := attrList(attrCmnReturnedAttrs|attrCmnUUID, ownerUUID, nil)
	le.PutUint32(b[attrRefOffset:], 24)
	acl, err := parseAttrList(b)
	require.NoError(t, err)
	assert.Empty(t, acl.entries)
	assert.True(t, acl.ownerKnown)

	acl, err = parseAttrList(attrList(allCommon, ownerUUID, filesec(nil)))
	require.NoError(t, err, "an empty list (KAUTH_FILESEC_NOACL) is 44 bytes")
	assert.Empty(t, acl.entries)

	acl, err = parseAttrList(attrList(allCommon, ownerUUID, filesec([]kauthACE{{otherUUID, kauthACEDeny, rightDelete}})))
	require.NoError(t, err)
	assert.Len(t, acl.entries, 1)

	acl, err = parseAttrList(attrList(attrCmnReturnedAttrs|attrCmnExtendedSecurity, ownerUUID, filesec(nil)))
	require.NoError(t, err)
	assert.False(t, acl.ownerKnown, "a UUID that was not returned is not the owner's")
	acl, err = parseAttrList(attrList(allCommon, [16]byte{}, filesec(nil)))
	require.NoError(t, err)
	assert.False(t, acl.ownerKnown, "an empty UUID is not the owner's")

	one := filesec([]kauthACE{{otherUUID, kauthACEDeny, rightDelete}})
	bad := map[string][]byte{
		"shorter than the fixed part": make([]byte, attrFixedSize-1),
		"an attribute not asked for":  attrList(allCommon|1, ownerUUID, filesec(nil)),
		"another group returned":      func() []byte { b := attrList(allCommon, ownerUUID, filesec(nil)); le.PutUint32(b[8:], 1); return b }(),
		"a length past the buffer": func() []byte {
			b := attrList(allCommon, ownerUUID, filesec(nil))
			le.PutUint32(b, uint32(len(b)+4))
			return b
		}(),
		"an absent list with a length": func() []byte {
			b := attrList(attrCmnReturnedAttrs, ownerUUID, nil)
			le.PutUint32(b[attrRefOffset+4:], 4)
			return b
		}(),
		"a reference into the fixed part": func() []byte {
			b := attrList(allCommon, ownerUUID, filesec(nil))
			le.PutUint32(b[attrRefOffset:], 4)
			return b
		}(),
		"a negative reference": func() []byte {
			b := attrList(allCommon, ownerUUID, filesec(nil))
			le.PutUint32(b[attrRefOffset:], uint32(0xFFFFFFF0))
			return b
		}(),
		"a misaligned reference": func() []byte {
			b := attrList(allCommon, ownerUUID, append([]byte{0, 0}, filesec(nil)...))
			le.PutUint32(b[attrRefOffset:], uint32(attrFixedSize-attrRefOffset+2))
			le.PutUint32(b[attrRefOffset+4:], 44)
			return b
		}(),
		"a reference past the data": func() []byte {
			b := attrList(allCommon, ownerUUID, filesec(nil))
			le.PutUint32(b[attrRefOffset+4:], 44+24)
			return b
		}(),
		"a list that is not a whole filesec": attrList(allCommon, ownerUUID, append(filesec(nil), 0, 0, 0, 0)),
		"a wrong magic": func() []byte {
			s := filesec(nil)
			le.PutUint32(s, 0x0BADF00D)
			return attrList(allCommon, ownerUUID, s)
		}(),
		"an empty list of the wrong size": func() []byte {
			s := filesec(nil)
			return attrList(allCommon, ownerUUID, append(s, make([]byte, 24)...))
		}(),
		"a count that does not match": func() []byte {
			s := append([]byte(nil), one...)
			le.PutUint32(s[36:], 2)
			return attrList(allCommon, ownerUUID, s)
		}(),
		"a count over the maximum": func() []byte {
			s := append([]byte(nil), one...)
			le.PutUint32(s[36:], kauthACLMaxEntries+1)
			return attrList(allCommon, ownerUUID, s)
		}(),
		"list flags": func() []byte {
			s := append([]byte(nil), one...)
			le.PutUint32(s[40:], 1)
			return attrList(allCommon, ownerUUID, s)
		}(),
	}
	for name, b := range bad {
		_, err := parseAttrList(b)
		assert.ErrorIs(t, err, errUnreadableACL, name)
	}
}

func TestKauthACLRules(t *testing.T) {
	t.Parallel()
	check := func(r role, owner [16]byte, returned uint32, aces ...kauthACE) error {
		acl, err := parseAttrList(attrList(returned, owner, filesec(aces)))
		require.NoError(t, err)
		return checkKauthACL(acl, r, "/p")
	}
	permit := func(guid [16]byte, rights uint32) kauthACE { return kauthACE{guid, kauthACEPermit, rights} }
	assert.NoError(t, check(roleAncestor, ownerUUID, allCommon, kauthACE{otherUUID, kauthACEDeny, rightDelete}),
		"everyone deny delete, as macOS puts on a home folder")
	assert.NoError(t, check(roleAncestor, ownerUUID, allCommon, permit(otherUUID, rightRead|rightSearch)), "read and search")
	for name, rights := range map[string]uint32{
		"add a file":      rightAddFile,
		"delete a child":  rightDeleteChild,
		"write security":  rightWriteSec,
		"take ownership":  rightTakeOwner,
		"generic all":     rightGenericAll,
		"add and delete":  rightAddFile | rightDeleteChild,
		"delete the item": rightDelete,
	} {
		assert.ErrorContains(t, check(roleEntry, ownerUUID, allCommon, permit(otherUUID, rights)), "lets another account change", name)
	}
	assert.ErrorContains(t, check(roleAncestor, ownerUUID, allCommon,
		kauthACE{otherUUID, kauthACEPermit | flagFileInherit | flagOnlyInherit, rightAddFile}),
		"lets another account change", "an inherit-only grant governs what is created later")
	assert.ErrorContains(t, check(roleAncestor, ownerUUID, allCommon,
		kauthACE{otherUUID, kauthACEDeny, rightAddFile}, permit(otherUUID, rightAddFile)),
		"lets another account change", "a grant is refused even after a deny")
	assert.NoError(t, check(roleEntry, ownerUUID, allCommon, permit(ownerUUID, rightAddFile|rightDelete)), "the owner's own entry")
	assert.ErrorContains(t, check(roleEntry, ownerUUID, attrCmnReturnedAttrs|attrCmnExtendedSecurity, permit(ownerUUID, rightAddFile)),
		"lets another account change", "without a returned owner UUID there is no owner exemption")
	assert.ErrorContains(t, check(roleProfile, ownerUUID, allCommon, permit(otherUUID, rightRead)),
		"opens the profile directory", "the profile directory admits no other account at all")
	assert.ErrorIs(t, check(roleEntry, ownerUUID, allCommon, kauthACE{otherUUID, 3, rightRead}), errUnreadableACL, "an audit entry")
	assert.ErrorIs(t, check(roleEntry, ownerUUID, allCommon, kauthACE{otherUUID, kauthACEDeny | 1<<9, rightRead}), errUnreadableACL, "an unknown flag")
	assert.ErrorIs(t, check(roleEntry, ownerUUID, allCommon, permit(otherUUID, 1<<27)), errUnreadableACL, "an unknown right")
}
