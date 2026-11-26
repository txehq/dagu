// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build darwin

package devtoolsgate

import (
	"context"
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
		{"everyone allow add and delete", "group:everyone allow add_file,delete_child", false, "lets another account change"},
		{"an inheritable add", "group:everyone allow add_file,file_inherit,directory_inherit", false, "lets another account change"},
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

	// An entry: write security on the marker lets another account change
	// the list itself.
	profile := testProfileDirIn(t, base)
	root, err := OpenProfileRoot(profile)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	marker := filepath.Join(profile, profileMarker)
	require.NoError(t, os.WriteFile(marker, nil, 0o600))
	chmodACL(t, marker, "+a", "group:everyone allow writesecurity")
	_, err = OpenProfileEntry(root, profileMarker, false)
	assert.ErrorContains(t, err, "lets another account change")
}

// testProfileDirIn is testProfileDir in parent.
func testProfileDirIn(t *testing.T, parent string) string {
	t.Helper()
	dir := filepath.Join(parent, "profile")
	require.NoError(t, os.Mkdir(dir, 0o700))
	return dir
}
