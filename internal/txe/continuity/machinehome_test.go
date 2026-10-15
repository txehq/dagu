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

func homePath(l *fixture.Layout, rel string) string {
	return filepath.Join(l.MachineHome, filepath.FromSlash(rel))
}

// linkCurrentBinary adds the installer's link to the current binary, which
// the fixture leaves out.
func linkCurrentBinary(t *testing.T, l *fixture.Layout) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	require.NoError(t, os.Symlink("dagu-2.18.2-txe.6", homePath(l, "bin/dagu")))
}

// A machine home as the worker installer and the CLI write it validates:
// machine.json with its created_at, the binaries and the link to the
// current one, the agents' logs, the worker's Dagu home and the CLI's
// local state. Each part has the class its writer gives it.
func TestMachineHomeAsInstalled(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	linkCurrentBinary(t, l)
	inv := scan(t, l)
	assert.Empty(t, continuity.Blocking(continuity.Validate(inv, continuity.Policy{})))
	assert.Equal(t, f.Machine, inv.Machines["laptop-home"])

	policies := map[string]string{}
	links := map[string]string{}
	for _, file := range inv.Files {
		if file.Root == "laptop-home" {
			policies[file.Path] = file.Policy
			links[file.Path] = file.Link
		}
	}
	for path, want := range map[string]string{
		"bin/dagu-2.18.2-txe.6":                           continuity.PolicyOperational,
		"bin/dagu-2.18.2-txe.6.json":                      continuity.PolicyOperational,
		"logs/tunnel.log":                                 continuity.PolicyOperational,
		"logs/worker.log":                                 continuity.PolicyOperational,
		"state/hub-install-" + f.Machine + ".lock":        continuity.PolicyOperational,
		"state/probe/journal-" + f.Machine + ".json":      continuity.PolicyMutable,
		"state/probe/journal-" + f.Machine + ".json.lock": continuity.PolicyOperational,
		"state/review/reviews/run-1/prepared.json":        continuity.PolicyMutable,
		"receipts/journal.jsonl":                          continuity.PolicyMutable,
	} {
		assert.Equal(t, want, policies[path], path)
	}
	if runtime.GOOS != "windows" {
		assert.Equal(t, "dagu-2.18.2-txe.6", links["bin/dagu"], "the link is recorded, not followed")
	}
	excluded := map[string]bool{}
	for _, e := range inv.Excluded {
		excluded[e.Root+"/"+e.Path] = true
	}
	for _, p := range []string{"laptop-home/tunnel", "laptop-home/worker-home/data/auth", "laptop-home/worker-home/data/contexts"} {
		assert.True(t, excluded[p], p)
	}
}

// The tunnel credential and the worker's encryption key are never opened:
// their directories are unreadable and the scan still succeeds, and no
// placeholder reaches the inventory.
func TestMachineHomeCredentialsAreNotRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits do not stop reads on Windows")
	}
	t.Parallel()
	l, _ := build(t)
	for _, dir := range []string{"tunnel", "worker-home/data/auth"} {
		p := homePath(l, dir)
		require.NoError(t, os.Chmod(p, 0o000))
		t.Cleanup(func() { _ = os.Chmod(p, 0o750) }) //nolint:gosec // restore for cleanup
	}
	inv := scan(t, l)
	for _, file := range inv.Files {
		assert.False(t, strings.HasPrefix(file.Path, "tunnel/") || strings.HasPrefix(file.Path, "worker-home/"), file.Path)
	}
	assert.Empty(t, continuity.Blocking(continuity.Validate(inv, continuity.Policy{})))
}

// Anything in a machine home that is not in its writers' exact format
// blocks, as do the parts of the home that no TXE writer owns.
func TestMachineHomeBreaksAreBlocking(t *testing.T) {
	editMachine := func(change func(m map[string]any)) func(*testing.T, *fixture.Layout) {
		return func(t *testing.T, l *fixture.Layout) {
			edit(t, homePath(l, "machine.json"), change)
		}
	}
	write := func(rel, data string) func(*testing.T, *fixture.Layout) {
		return func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.MkdirAll(filepath.Dir(homePath(l, rel)), 0o750))
			require.NoError(t, os.WriteFile(homePath(l, rel), []byte(data), 0o600))
		}
	}
	cases := []struct {
		name   string
		links  bool
		break_ func(*testing.T, *fixture.Layout)
		want   string
		count  int
	}{
		{name: "machine.json with a field the installer does not write",
			break_: editMachine(func(m map[string]any) { m["installed_by"] = "someone" }), want: "undecodable"},
		{name: "machine.json whose created_at is not a timestamp",
			break_: editMachine(func(m map[string]any) { m["created_at"] = "yesterday" }), want: "undecodable"},
		{name: "machine.json of a later schema",
			break_: editMachine(func(m map[string]any) { m["schema"] = 2 }), want: "unsupported_schema"},
		{name: "a file in bin that is not an installed build", break_: write("bin/notes.txt", "x"), want: "unclassified_area"},
		{name: "a build that is a directory", break_: func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.MkdirAll(homePath(l, "bin/dagu-2.18.3-txe.1"), 0o750))
		}, want: "unsupported_file"},
		{name: "the current binary links out of bin", links: true, break_: func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.Symlink("../client/contexts/hub.yaml", homePath(l, "bin/dagu")))
		}, want: "unsupported_file"},
		{name: "the current binary is a regular file", break_: write("bin/dagu", "x"), want: "unsupported_file"},
		{name: "a log the agents do not write", break_: write("logs/other.log", "x"), want: "unclassified_area"},
		{name: "a new area of the worker's Dagu home", break_: write("worker-home/data/dag-runs/run.jsonl", "{}"), want: "unclassified_area"},
		{name: "a file beside the worker's data directory", break_: write("worker-home/base.yaml", "x"), want: "unclassified_area"},
		{name: "another file in a review hand-off", break_: write("state/review/reviews/run-1/notes.txt", "x"), want: "unclassified_area"},
		{name: "a probe journal not named by a machine", break_: write("state/probe/journal-laptop.json", "{}"), want: "unclassified_area"},
		{name: "an unknown directory of the CLI's state", break_: write("state/cache/x", "x"), want: "unclassified_area"},
		{name: "the review state is a link", links: true, break_: func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.Rename(homePath(l, "state/review"), filepath.Join(l.Root, "review")))
			require.NoError(t, os.Symlink(filepath.Join(l.Root, "review"), homePath(l, "state/review")))
		}, want: "unsupported_file"},
		{name: "the tunnel directory is a link", links: true, break_: func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.Rename(homePath(l, "tunnel"), filepath.Join(l.Root, "tunnel")))
			require.NoError(t, os.Symlink(filepath.Join(l.Root, "tunnel"), homePath(l, "tunnel")))
		}, want: "unsupported_file"},
		// A Dagu run whose DAGU_HOME is the TXE home writes Dagu's
		// first-run defaults there. No TXE writer does that, so each part
		// blocks until someone decides what to do with it.
		{name: "Dagu's first-run defaults in the home", break_: func(t *testing.T, l *fixture.Layout) {
			write("base.yaml", "# Base DAG Configuration\n")(t, l)
			write(".base-config-created", "# Marker\n")(t, l)
			write("dags/example-01-basic-sequential.yaml", "steps: []\n")(t, l)
			require.NoError(t, os.MkdirAll(homePath(l, "data/contexts"), 0o750))
			require.NoError(t, os.MkdirAll(homePath(l, "logs/admin/events/inbox"), 0o750))
		}, want: "unclassified_area", count: 5},
		{name: "a package directory not named by a job", break_: write("packages/txe-smoke/v1/files/smoke.sh", "#!/bin/sh\n"), want: "unsupported_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.links {
				skipWithoutSymlinks(t)
			}
			l, _ := build(t)
			require.Empty(t, blocking(t, l), "the fixture starts clean")
			tc.break_(t, l)
			got := blocking(t, l)
			if tc.count > 0 {
				assert.Equal(t, tc.count, got[tc.want], "got %v", got)
				return
			}
			assert.Positive(t, got[tc.want], "want %s, got %v", tc.want, got)
		})
	}
}

// The freeze comparison holds the retained state of a machine home: a lost
// probe journal or a changed review hand-off blocks. The agents' logs and
// an upgrade's binaries are counted, not compared.
func TestMachineHomeCompare(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	linkCurrentBinary(t, l)
	before := scan(t, l)

	logf, err := os.OpenFile(homePath(l, "logs/worker.log"), os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = logf.WriteString("another line\n")
	require.NoError(t, err)
	require.NoError(t, logf.Close())
	require.NoError(t, os.WriteFile(homePath(l, "bin/dagu-2.18.3-txe.1"), []byte("next\n"), 0o700))
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Remove(homePath(l, "bin/dagu")))
		require.NoError(t, os.Symlink("dagu-2.18.3-txe.1", homePath(l, "bin/dagu")))
	}
	rep := continuity.Compare(before, scan(t, l), continuity.CompareOptions{})
	assert.Empty(t, compareCodes(rep), "logs and binaries are operational")

	require.NoError(t, os.Remove(homePath(l, "state/probe/journal-"+f.Machine+".json")))
	require.NoError(t, os.WriteFile(homePath(l, "state/review/reviews/run-1/prepared.json"), []byte(`{"job_id":"other"}`), 0o600))
	got := compareCodes(continuity.Compare(before, scan(t, l), continuity.CompareOptions{}))
	assert.Equal(t, 1, got["file_missing"], "got %v", got)
	assert.Equal(t, 1, got["file_changed"], "got %v", got)
	for k := range got {
		assert.True(t, strings.HasPrefix(k, "file_"), "only the two files: %v", got)
	}
}
