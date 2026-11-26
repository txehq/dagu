// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build darwin

package devtoolsgate

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real access control list fixtures on macOS, which also check the
// fgetattrlist call and the layout parseAttrList reads on this machine.
// They run only with DAGU_TEST_REAL_ACL=1; then a missing capability fails,
// never skips. Each grant is made with /bin/chmod +a, bounded, on a
// directory or file the fixture made in its own directory, and the removal
// of every list (chmod -N) is registered before the grant.

func realACLDir(t *testing.T) string {
	t.Helper()
	if os.Getenv("DAGU_TEST_REAL_ACL") != "1" {
		t.Skip("real access control list fixtures run only with DAGU_TEST_REAL_ACL=1")
	}
	return privateTempDir(t)
}

// chmodACL runs /bin/chmod with args on path, bounded to 10 seconds. A
// grant registers the list's removal first.
func chmodACL(t *testing.T, path string, args ...string) {
	t.Helper()
	run := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/bin/chmod", append(args, path)...).CombinedOutput() //nolint:gosec // fixed tool, the fixture's own path
		if err != nil {
			t.Logf("chmod %v: %s", args, out)
		}
		return err
	}
	t.Cleanup(func() {
		if err := run("-N"); err != nil {
			t.Errorf("remove the list on %s: %v", path, err)
		}
	})
	require.NoError(t, run(args...))
}

func TestRealACLReaderOnThisMac(t *testing.T) {
	base := realACLDir(t)
	me, err := user.Current()
	require.NoError(t, err)

	// No list at all: the call and the buffer read as no list.
	clean := filepath.Join(base, "clean")
	require.NoError(t, os.Mkdir(clean, 0o700))
	f, err := openTrusted(clean)
	require.NoError(t, err, "fgetattrlist on a directory with no list")
	require.NoError(t, f.Close())

	cases := []struct {
		name, ace string
		file      bool
		want      string // "" when allowed
	}{
		{"everyone deny delete", "group:everyone deny delete", false, ""},
		{"everyone allow read", "group:everyone allow list,search", false, "opens the profile directory"},
		{"the owner's own grant", "user:" + me.Username + " allow add_file,delete_child", false, ""},
		// On the profile directory any grant to another account is refused
		// as opening it, whatever the right.
		{"everyone allow add and delete", "group:everyone allow add_file,delete_child", false, "opens the profile directory"},
		{"an inheritable add", "group:everyone allow add_file,file_inherit,directory_inherit", false, "opens the profile directory"},
	}
	for _, c := range cases {
		dir := filepath.Join(base, "p-"+filepath.Base(c.name))
		require.NoError(t, os.Mkdir(dir, 0o700))
		chmodACL(t, dir, "+a", c.ace)
		f, err := openTrusted(dir)
		if c.want == "" {
			assert.NoError(t, err, c.name)
		} else {
			assert.ErrorContains(t, err, c.want, c.name)
		}
		if f != nil {
			_ = f.Close()
		}
	}

	// An entry: a grant to change it is refused as such. Write security
	// on the marker lets another account change the list itself; add and
	// delete on the profile's Default directory let it replace what is in
	// it; read alone is allowed on an entry.
	profile := testProfileDirIn(t, base)
	root, err := OpenProfileRoot(profile)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	marker := filepath.Join(profile, profileMarker)
	require.NoError(t, os.WriteFile(marker, nil, 0o600))
	chmodACL(t, marker, "+a", "group:everyone allow writesecurity")
	_, err = OpenProfileEntry(root, profileMarker, false)
	assert.ErrorContains(t, err, "lets another account change")

	inside := filepath.Join(profile, "Default")
	require.NoError(t, os.Mkdir(inside, 0o700))
	chmodACL(t, inside, "+a", "group:everyone allow add_file,delete_child")
	_, err = OpenProfileEntry(root, "Default", true)
	assert.ErrorContains(t, err, "lets another account change")

	readable := filepath.Join(profile, "Readable")
	require.NoError(t, os.Mkdir(readable, 0o700))
	chmodACL(t, readable, "+a", "group:everyone allow list,search")
	f, err = OpenProfileEntry(root, "Readable", true)
	require.NoError(t, err, "read and search on an entry")
	require.NoError(t, f.Close())
}

// testProfileDirIn is testProfileDir in parent.
func testProfileDirIn(t *testing.T, parent string) string {
	t.Helper()
	dir := filepath.Join(parent, "profile")
	require.NoError(t, os.Mkdir(dir, 0o700))
	return dir
}

// A diagnostic, not a check of the gate's rules: for a directory with no
// list, one with an entry for this user and one with an entry for
// everyone, it logs what fgetattrlist returned on this Mac (the returned
// attributes, the owner-UUID slot, and each entry's GUID, kind, flags and
// rights), so that the owner exemption's failure can be placed: the UUID
// not returned (H1), or returned but not the GUID chmod wrote for this
// user (H2). It asserts only that each read and parse succeeds, and it runs
// only with DAGU_TEST_REAL_ACL=1 and DAGU_TEST_REAL_ACL_DIAG=1.
func TestRealACLOwnerUUIDDiagnosticOnThisMac(t *testing.T) {
	if os.Getenv("DAGU_TEST_REAL_ACL_DIAG") != "1" {
		t.Skip("the owner-UUID diagnostic runs only with DAGU_TEST_REAL_ACL_DIAG=1")
	}
	base := realACLDir(t)
	me, err := user.Current()
	require.NoError(t, err)
	t.Logf("user=%s uid=%s", me.Username, me.Uid)

	for _, c := range []struct{ name, ace string }{
		{"no-list", ""},
		{"owner-entry", "user:" + me.Username + " allow add_file,delete_child"},
		{"everyone-entry", "group:everyone allow list"},
	} {
		dir := filepath.Join(base, c.name)
		require.NoError(t, os.Mkdir(dir, 0o700))
		if c.ace != "" {
			chmodACL(t, dir, "+a", c.ace)
		}
		f, err := os.Open(dir) //nolint:gosec // the fixture's own directory
		require.NoError(t, err)
		buf, err := readAttrList(f)
		require.NoError(t, f.Close())
		require.NoError(t, err, "%s: fgetattrlist", c.name)
		le := binary.LittleEndian
		common := le.Uint32(buf[4:])
		t.Logf("%s: length=%d returned common=%#08x (returned_attrs=%t extended_security=%t uuid=%t) other groups=%#x/%#x/%#x/%#x",
			c.name, le.Uint32(buf), common,
			common&attrCmnReturnedAttrs != 0, common&attrCmnExtendedSecurity != 0, common&attrCmnUUID != 0,
			le.Uint32(buf[8:]), le.Uint32(buf[12:]), le.Uint32(buf[16:]), le.Uint32(buf[20:]))
		t.Logf("%s: extended security reference offset=%d length=%d; owner-UUID slot=%x",
			c.name, int32(le.Uint32(buf[attrRefOffset:])), le.Uint32(buf[attrRefOffset+4:]), buf[attrUUIDAt:attrUUIDAt+16]) //nolint:gosec // a signed field as the kernel writes it
		acl, err := parseAttrList(buf)
		require.NoError(t, err, "%s: parse", c.name)
		t.Logf("%s: ownerKnown=%t owner=%x entries=%d", c.name, acl.ownerKnown, acl.owner, len(acl.entries))
		for i, e := range acl.entries {
			verdict := "the owner-UUID slot was not returned (H1)"
			switch {
			case acl.ownerKnown && e.guid == acl.owner:
				verdict = "equals the returned owner UUID"
			case acl.ownerKnown:
				verdict = "differs from the returned owner UUID (H2, for an entry naming this user)"
			}
			t.Logf("%s: entry %d guid=%x kind=%d flags=%#x rights=%#x: %s",
				c.name, i, e.guid, e.flags&kauthACEKindMask, e.flags, e.rights, verdict)
		}
	}
}
