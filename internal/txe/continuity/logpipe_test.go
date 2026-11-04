// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
)

// logpipeFiles are the names an install since TXE-4724 and TXE-5398 adds to
// a machine home: the installer's copy of logpipe.py, the logs launchd wrote
// before logpipe took them over (archived, here once with logpipe's "-N"),
// launchd's own file for each agent, rotated logs compressed, not yet
// compressed and being compressed, and logpipe's diagnostics.
var logpipeFiles = []string{
	"bin/logpipe.py",
	"logs/tunnel.legacy-20261104T074507171634Z.log",
	"logs/worker.legacy-20261104T074512581619Z.log",
	"logs/worker.legacy-20261104T074512581619Z-1.log",
	"logs/tunnel.launchd.log",
	"logs/worker.launchd.log",
	"logs/worker.log.20261104T080000123456Z.gz",
	"logs/worker.log.20261104T090000123456Z",
	"logs/worker.log.20261104T090000123456Z.gz.tmp",
	"logs/tunnel.log.20261104T100000123456Z-2.gz",
	"logs/worker.logpipe.log",
	"logs/worker.logpipe.log.1",
	"logs/tunnel.logpipe.log",
}

func writeLogpipeFiles(t *testing.T, l *fixture.Layout) {
	t.Helper()
	for _, rel := range logpipeFiles {
		require.NoError(t, os.WriteFile(homePath(l, rel), []byte("fixture "+rel+"\n"), 0o600))
	}
	// The supervisor and its state sit in the tunnel directory, which is
	// excluded as a whole for the credential beside them.
	for _, rel := range []string{"tunnel/tunnel-supervise.py", "tunnel/supervise-state.json"} {
		require.NoError(t, os.WriteFile(homePath(l, rel), []byte("fixture\n"), 0o600))
	}
}

// A machine home installed with logpipe and the tunnel supervisor, signed in
// and enrolled as a worker and a reviewer, validates. Each new file is an
// operational file with its digest recorded, and every credential is
// excluded by name and type without being opened (each is unreadable here).
func TestMachineHomeWithLogpipe(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	linkCurrentBinary(t, l)
	signedInAndEnrolled(t, l)
	writeLogpipeFiles(t, l)
	inv := scan(t, l)
	assert.Empty(t, continuity.Blocking(continuity.Validate(inv, continuity.Policy{})))

	files := map[string]continuity.File{}
	for _, f := range inv.Files {
		if f.Root == "laptop-home" {
			files[f.Path] = f
		}
	}
	for _, rel := range logpipeFiles {
		f, ok := files[rel]
		if assert.True(t, ok, rel) {
			assert.Equal(t, continuity.PolicyOperational, f.Policy, rel)
			assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, f.SHA256, rel)
		}
	}
	excluded := map[string]bool{}
	for _, e := range inv.Excluded {
		excluded[e.Root+"/"+e.Path] = true
	}
	for _, p := range []string{"tunnel", "worker-credential.json", "reviewer-credential.json", "reviewer-credential.json.lock"} {
		assert.True(t, excluded["laptop-home/"+p], p)
	}
	for path := range files {
		assert.False(t, strings.HasPrefix(path, "tunnel/") || strings.Contains(path, "credential"), path)
	}
}

// Only logpipe's exact names are classified: a name near one of them, or one
// of them of the wrong type, blocks.
func TestMachineHomeLogpipeNamesStayExact(t *testing.T) {
	file := func(rel string) func(*testing.T, *fixture.Layout) {
		return func(t *testing.T, l *fixture.Layout) {
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
		break_ func(*testing.T, *fixture.Layout)
		want   string
	}{
		{name: "a legacy archive without a stamp", break_: file("logs/worker.legacy.log"), want: "unclassified_area"},
		{name: "a legacy archive with a short stamp", break_: file("logs/worker.legacy-20261104T074512Z.log"), want: "unclassified_area"},
		{name: "a legacy archive of another log", break_: file("logs/hub.legacy-20261104T074512581619Z.log"), want: "unclassified_area"},
		{name: "a rotated log numbered, not stamped", break_: file("logs/worker.log.1"), want: "unclassified_area"},
		{name: "a rotated log compressed another way", break_: file("logs/worker.log.20261104T080000123456Z.bz2"), want: "unclassified_area"},
		{name: "launchd's file for another agent", break_: file("logs/reviewer.launchd.log"), want: "unclassified_area"},
		{name: "a diagnostics copy logpipe does not keep", break_: file("logs/worker.logpipe.log.2"), want: "unclassified_area"},
		{name: "a compiled logpipe", break_: file("bin/logpipe.pyc"), want: "unclassified_area"},
		{name: "the supervisor outside the tunnel directory", break_: file("bin/tunnel-supervise.py"), want: "unclassified_area"},
		{name: "logpipe.py as a directory", break_: dir("bin/logpipe.py"), want: "unsupported_file"},
		{name: "a legacy archive as a directory", break_: dir("logs/worker.legacy-20261104T074512581619Z.log"), want: "unsupported_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, _ := build(t)
			writeLogpipeFiles(t, l)
			require.Empty(t, blocking(t, l), "the fixture starts clean")
			tc.break_(t, l)
			got := blocking(t, l)
			assert.Positive(t, got[tc.want], "want %s, got %v", tc.want, got)
		})
	}
}

// logpipe rotates, compresses and prunes its files while the agents run, and
// an install replaces logpipe.py: the freeze comparison counts them and
// raises nothing, as for the agents' logs.
func TestMachineHomeLogpipeCompare(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	writeLogpipeFiles(t, l)
	before := scan(t, l)

	require.NoError(t, os.Remove(homePath(l, "logs/worker.log.20261104T080000123456Z.gz")))
	require.NoError(t, os.Rename(homePath(l, "logs/worker.log.20261104T090000123456Z"), homePath(l, "logs/worker.log.20261104T090000123456Z.gz")))
	require.NoError(t, os.Remove(homePath(l, "logs/worker.log.20261104T090000123456Z.gz.tmp")))
	require.NoError(t, os.WriteFile(homePath(l, "logs/worker.log.20261104T110000123456Z"), []byte("rotated\n"), 0o600))
	require.NoError(t, os.WriteFile(homePath(l, "bin/logpipe.py"), []byte("next install\n"), 0o600))
	require.NoError(t, os.WriteFile(homePath(l, "logs/worker.launchd.log"), []byte("a traceback\n"), 0o600))
	assert.Empty(t, compareCodes(continuity.Compare(before, scan(t, l), continuity.CompareOptions{})))
}
