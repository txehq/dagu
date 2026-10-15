// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
)

// signinEntry is a sign-in entry's name for a hub: the first 16 bytes of the
// SHA-256 of its normalized URL, in hex (internal/txe/cliauth entryPaths).
const signinEntry = "0123456789abcdef0123456789abcdef"

// writeSecret writes a placeholder credential that cannot be read, so a scan
// that opened it would fail.
func writeSecret(t *testing.T, p string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
	require.NoError(t, os.WriteFile(p, []byte("fixture-credential-placeholder"), 0o600))
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(p, 0o000))
		t.Cleanup(func() { _ = os.Chmod(p, 0o600) }) //nolint:gosec // restore for cleanup
	}
}

// signedInAndEnrolled writes what a sign-in, an enrolment and a hub with
// transport authentication leave, including a save in progress of each.
func signedInAndEnrolled(t *testing.T, l *fixture.Layout) {
	t.Helper()
	for _, rel := range []string{
		"signin/" + signinEntry + ".json", "signin/" + signinEntry + ".lock", "signin/" + signinEntry + ".json.tmp.1234567",
		"worker-credential.json", "worker-credential.json.lock", ".worker-credential.json.2345678",
	} {
		writeSecret(t, homePath(l, rel))
	}
	for _, rel := range []string{"coordinator/hub.key", "coordinator/.hub.key.3456789"} {
		writeSecret(t, filepath.Join(l.DataDir, filepath.FromSlash(rel)))
	}
}

// A machine that signed in and enrolled, and a hub with transport
// authentication, validate: every credential is excluded by its exact name
// and none is opened.
func TestCredentialsAreExcludedExactly(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	signedInAndEnrolled(t, l)
	inv := scan(t, l)
	assert.Empty(t, continuity.Blocking(continuity.Validate(inv, continuity.Policy{})))
	excluded := map[string]bool{}
	for _, e := range inv.Excluded {
		excluded[e.Root+"/"+e.Path] = true
	}
	for _, p := range []string{
		"laptop-home/signin/" + signinEntry + ".json", "laptop-home/signin/" + signinEntry + ".lock",
		"laptop-home/signin/" + signinEntry + ".json.tmp.1234567", "laptop-home/worker-credential.json",
		"laptop-home/worker-credential.json.lock", "laptop-home/.worker-credential.json.2345678",
		"hub-data/coordinator/hub.key", "hub-data/coordinator/.hub.key.3456789",
	} {
		assert.True(t, excluded[p], p)
	}
	for _, f := range inv.Files {
		assert.False(t, strings.HasPrefix(f.Path, "signin/") || strings.Contains(f.Path, "credential") || strings.HasPrefix(f.Path, "coordinator/"), f.Path)
	}
}

// Only the exact names are excluded: anything else beside them blocks
// without being read, and a link is never followed.
func TestCredentialAreasStayExact(t *testing.T) {
	file := func(rel string) func(*testing.T, *fixture.Layout) {
		return func(t *testing.T, l *fixture.Layout) { writeSecret(t, homePath(l, rel)) }
	}
	dir := func(rel string) func(*testing.T, *fixture.Layout) {
		return func(t *testing.T, l *fixture.Layout) { require.NoError(t, os.MkdirAll(homePath(l, rel), 0o700)) }
	}
	cases := []struct {
		name   string
		links  bool
		break_ func(*testing.T, *fixture.Layout)
		want   string
	}{
		{name: "another file in the sign-in store", break_: file("signin/notes.txt"), want: "unclassified_area"},
		{name: "a sign-in entry not named by a hub digest", break_: file("signin/0123.json"), want: "unclassified_area"},
		{name: "a sign-in entry that is a directory", break_: dir("signin/" + signinEntry + ".json"), want: "unsupported_file"},
		{name: "the sign-in store as a file", break_: file("signin"), want: "unsupported_file"},
		{name: "the machine credential as a directory", break_: dir("worker-credential.json"), want: "unsupported_file"},
		{name: "a credential save not named by its writer", break_: file(".worker-credential.json.tmp"), want: "unclassified_area"},
		{name: "another credential file beside it", break_: file("worker-credential.json.bak"), want: "unclassified_area"},
		{name: "the machine credential as a link", links: true, break_: func(t *testing.T, l *fixture.Layout) {
			writeSecret(t, filepath.Join(l.Root, "elsewhere.json"))
			require.NoError(t, os.Symlink(filepath.Join(l.Root, "elsewhere.json"), homePath(l, "worker-credential.json")))
		}, want: "unsupported_file"},
		{name: "another file beside the hub key", break_: func(t *testing.T, l *fixture.Layout) {
			writeSecret(t, filepath.Join(l.DataDir, "coordinator", "hub.key.old"))
		}, want: "unclassified_area"},
		{name: "the hub key as a directory", break_: func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.MkdirAll(filepath.Join(l.DataDir, "coordinator", "hub.key"), 0o700))
		}, want: "unsupported_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.links {
				skipWithoutSymlinks(t)
			}
			l, _ := build(t)
			tc.break_(t, l)
			got := blocking(t, l)
			assert.Positive(t, got[tc.want], "want %s, got %v", tc.want, got)
		})
	}
}

// A credential at a path no rule names (a worker credential given to
// dagu txe enrol inside the TXE home) is kept by an explicit manifest
// entry: never opened, pinned by its type and permission bits, so a
// rotation in place is not a change but a loss or a looser mode is.
func TestKeepCredentialIsNeverRead(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	p := homePath(l, "my-worker.json")
	writeSecret(t, p)
	m := &continuity.KeepManifest{Format: continuity.KeepFormatV1, Entries: []continuity.KeepEntry{
		{Root: "laptop-home", Path: "my-worker.json", Credential: true, Provenance: "dagu txe enrol --credential-file (fixture)"},
	}}
	got := codes(continuity.Validate(scanKeep(t, l, m), continuity.Policy{}), continuity.SeverityBlock)
	assert.Equal(t, map[string]int{"kept_unpinned": 1}, got)
	pin(t, m, scanKeep(t, l, m))
	before := scanKeep(t, l, m)
	assert.Empty(t, continuity.Blocking(continuity.Validate(before, continuity.Policy{})))
	for _, f := range before.Files {
		assert.NotEqual(t, "my-worker.json", f.Path)
	}
	excluded := map[string]bool{}
	for _, e := range before.Excluded {
		excluded[e.Root+"/"+e.Path] = true
	}
	assert.True(t, excluded["laptop-home/my-worker.json"])

	if runtime.GOOS == "windows" {
		return
	}
	// A rotation rewrites it with the same mode.
	require.NoError(t, os.Chmod(p, 0o600))
	require.NoError(t, os.WriteFile(p, []byte("rotated-placeholder"), 0o600))
	require.NoError(t, os.Chmod(p, 0o000))
	assert.Empty(t, compareCodes(continuity.Compare(before, scanKeep(t, l, m), continuity.CompareOptions{})))
	require.NoError(t, os.Chmod(p, 0o444))
	assert.Equal(t, map[string]int{"kept_changed": 1}, compareCodes(continuity.Compare(before, scanKeep(t, l, m), continuity.CompareOptions{})))
	require.NoError(t, os.Remove(p))
	got = codes(continuity.Validate(scanKeep(t, l, m), continuity.Policy{}), continuity.SeverityBlock)
	assert.Equal(t, map[string]int{"kept_missing": 1}, got)

	_, err := continuity.DecodeKeep([]byte(`{"format":"txe.continuity.keep/v1","entries":[{"root":"r","path":"p","provenance":"x","credential":true,"exclude":["a"]}]}`))
	assert.Error(t, err, "a credential has nothing to exclude")
}
