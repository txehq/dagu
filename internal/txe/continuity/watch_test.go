// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
)

// watchFiles are the files the credential watch (TXE-7233) adds to a machine
// home under either installer: the installer's copy of the script, its
// record of delivered alerts with a save in progress, and its log as
// logpipe.py keeps it (rotated, compressed, being compressed, archived from
// before logpipe took it, and logpipe's diagnostics).
var watchFiles = []string{
	"bin/credential-watch.py",
	"credential-watch/state.json",
	"credential-watch/.state-k2x_9q7a",
	"logs/credential-watch.log",
	"logs/credential-watch.log.20261113T080000123456Z",
	"logs/credential-watch.log.20261113T070000123456Z.gz",
	"logs/credential-watch.log.20261113T090000123456Z-1.gz.tmp",
	"logs/credential-watch.legacy-20261113T060000123456Z.log",
	"logs/credential-watch.logpipe.log",
	"logs/credential-watch.logpipe.log.1",
}

// watchLaunchdFiles are what only install.sh adds: launchd's own file for the
// watch agent. The systemd installer's units write to the journal instead.
var watchLaunchdFiles = []string{"logs/credential-watch.launchd.log"}

// installWatch lays the watch out as an installer does, with the webhook
// file at its default path, unreadable so that opening it fails the scan.
func installWatch(t *testing.T, l *fixture.Layout, launchd bool) []string {
	t.Helper()
	files := append([]string{}, watchFiles...)
	if launchd {
		files = append(files, watchLaunchdFiles...)
	}
	for _, rel := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(homePath(l, rel)), 0o750))
		require.NoError(t, os.WriteFile(homePath(l, rel), []byte("fixture "+rel+"\n"), 0o600))
	}
	writeSecret(t, homePath(l, "alert-webhook.url"))
	return files
}

// A machine home as install.sh (launchd) and install-systemd.sh (systemd)
// lay it out with the credential watch validates: every watch file is an
// operational file with its digest recorded, and the webhook file is
// excluded by name and type without being opened or hashed.
func TestMachineHomeWithCredentialWatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		launchd bool
	}{{"install.sh", true}, {"install-systemd.sh", false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, _ := build(t)
			linkCurrentBinary(t, l)
			signedInAndEnrolled(t, l)
			writeLogpipeFiles(t, l)
			files := installWatch(t, l, tc.launchd)
			inv := scan(t, l)
			assert.Empty(t, continuity.Blocking(continuity.Validate(inv, continuity.Policy{})))

			got := map[string]continuity.File{}
			for _, f := range inv.Files {
				if f.Root == "laptop-home" {
					got[f.Path] = f
				}
			}
			for _, rel := range files {
				f, ok := got[rel]
				if assert.True(t, ok, rel) {
					assert.Equal(t, continuity.PolicyOperational, f.Policy, rel)
					assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, f.SHA256, rel)
				}
			}
			_, inventoried := got["alert-webhook.url"]
			assert.False(t, inventoried, "the webhook file is never inventoried")
			excluded := false
			for _, e := range inv.Excluded {
				if e.Root == "laptop-home" && e.Path == "alert-webhook.url" {
					excluded = true
				}
			}
			assert.True(t, excluded, "the webhook file is excluded")
		})
	}
}

// Only the watch's exact names are classified: a name near one of them, or
// one of them of the wrong type, blocks.
func TestMachineHomeCredentialWatchNamesStayExact(t *testing.T) {
	file := func(rel string) func(*testing.T, *fixture.Layout) {
		return func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.MkdirAll(filepath.Dir(homePath(l, rel)), 0o750))
			require.NoError(t, os.WriteFile(homePath(l, rel), []byte("x\n"), 0o600))
		}
	}
	dir := func(rel string) func(*testing.T, *fixture.Layout) {
		return func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.RemoveAll(homePath(l, rel)))
			require.NoError(t, os.MkdirAll(homePath(l, rel), 0o750))
		}
	}
	cases := []struct {
		name   string
		links  bool
		break_ func(*testing.T, *fixture.Layout)
		want   string
	}{
		{name: "another file in the watch's state directory", break_: file("credential-watch/state.json.bak"), want: "unclassified_area"},
		{name: "a save in progress under another prefix", break_: file("credential-watch/.tmp-k2x_9q7a"), want: "unclassified_area"},
		{name: "the state outside its directory", break_: file("state.json"), want: "unclassified_area"},
		{name: "another webhook file", break_: file("alert-webhook.url.bak"), want: "unclassified_area"},
		{name: "a compiled watch", break_: file("bin/credential-watch.pyc"), want: "unclassified_area"},
		{name: "a rotated watch log numbered, not stamped", break_: file("logs/credential-watch.log.1"), want: "unclassified_area"},
		{name: "another script's next copy", break_: file("bin/agents.py.next"), want: "unclassified_area"},
		{name: "the webhook file as a directory", break_: dir("alert-webhook.url"), want: "unsupported_file"},
		{name: "the state directory as a file", break_: func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.RemoveAll(homePath(l, "credential-watch")))
			require.NoError(t, os.WriteFile(homePath(l, "credential-watch"), []byte("x\n"), 0o600))
		}, want: "unsupported_file"},
		{name: "the state as a directory", break_: dir("credential-watch/state.json"), want: "unsupported_file"},
		{name: "the watch as a directory", break_: dir("bin/credential-watch.py"), want: "unsupported_file"},
		{name: "the next binary link as a file", break_: file("bin/dagu.next"), want: "unsupported_file"},
		{name: "the next binary link pointing elsewhere", links: true, break_: func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.Symlink("/usr/local/bin/dagu", homePath(l, "bin/dagu.next")))
		}, want: "unsupported_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.links && runtime.GOOS == "windows" {
				t.Skip("symlinks need privileges on Windows")
			}
			t.Parallel()
			l, _ := build(t)
			installWatch(t, l, true)
			require.Empty(t, blocking(t, l), "the fixture starts clean")
			tc.break_(t, l)
			got := blocking(t, l)
			assert.Positive(t, got[tc.want], "want %s, got %v", tc.want, got)
		})
	}
}

// An interrupted install leaves the next copy of a script or the next link
// to the current binary; the next install replaces them, and they validate.
func TestMachineHomeInterruptedInstallValidates(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	for _, rel := range []string{"bin/logpipe.py.next", "bin/credential-watch.py.next"} {
		require.NoError(t, os.WriteFile(homePath(l, rel), []byte("next\n"), 0o600))
	}
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Symlink("dagu-2.18.2-txe.6", homePath(l, "bin/dagu.next")))
	}
	assert.Empty(t, blocking(t, l))
}
