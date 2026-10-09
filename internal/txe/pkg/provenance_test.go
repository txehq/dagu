// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeRepository(t *testing.T) {
	for remote, want := range map[string]string{
		"https://github.com/txehq/txe.git":             "github.com/txehq/txe",
		"https://github.com/TxeHQ/TXE":                 "github.com/txehq/txe",
		"git@github.com:txehq/txe.git":                 "github.com/txehq/txe",
		"ssh://git@github.com/txehq/txe.git":           "github.com/txehq/txe",
		"ssh://git@github.com:22/txehq/txe":            "github.com/txehq/txe",
		"https://user:secret@github.com/txehq/txe.git": "github.com/txehq/txe",
		"https://github.com/txehq/txe/":                "github.com/txehq/txe",
	} {
		assert.Equal(t, want, NormalizeRepository(remote), remote)
	}
}

// The provenance of a package names the files that a commit alone would not
// reproduce: the modified one and the untracked one.
func TestDetectProvenance(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := resolveExisting(t.TempDir())
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	}

	git("init", "-q")
	git("remote", "add", "origin", "git@github.com:txehq/txe.git")
	write("jobs/collect.py", "v1\n")
	write("jobs/lib/snapshot.py", "v1\n")
	write("unrelated.txt", "v1\n")
	git("add", ".")
	git("commit", "-q", "-m", "init")

	write("jobs/collect.py", "v2\n")     // modified
	write("jobs/lib/helper.py", "new\n") // untracked
	write("unrelated.txt", "v2\n")       // modified, but not packaged

	source := filepath.Join(root, "jobs")
	p := DetectProvenance(context.Background(), source, []string{"collect.py", "lib"})

	assert.Equal(t, "github.com/txehq/txe", p.Repository)
	assert.Len(t, p.Commit, 40)
	assert.Equal(t, source, p.SourceRoot)
	assert.Equal(t, []string{"collect.py", "lib/helper.py"}, p.Uncommitted)
}

func TestDetectProvenanceOutsideGit(t *testing.T) {
	dir := t.TempDir()
	p := DetectProvenance(context.Background(), dir, []string{"run.sh"})
	assert.Equal(t, Provenance{SourceRoot: dir}, p)
}
