// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeskill

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevision(t *testing.T) {
	assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{12}$`), Revision())
	assert.Equal(t, Revision(), Revision())
}

// Every profile links to one unpacked copy, so they cannot hold different
// revisions, and an unpack keeps scripts executable.
func TestUnpackAndLink(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "txe-dagu", "skill")

	unpacked, err := Unpack(dir)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "current"), unpacked)
	assert.True(t, Inspect(unpacked).Current)

	skill, err := os.ReadFile(filepath.Join(unpacked, "SKILL.md"))
	require.NoError(t, err)
	assert.Contains(t, string(skill), "name: "+Name)
	info, err := os.Stat(filepath.Join(unpacked, "examples", "healthcheck", "check.sh"))
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&0o111, "an example script lost its executable bit")
	info, err = os.Stat(filepath.Join(unpacked, "examples", "healthcheck", "job.yaml"))
	require.NoError(t, err)
	assert.Zero(t, info.Mode()&0o111)

	// A second unpack changes nothing.
	again, err := Unpack(dir)
	require.NoError(t, err)
	assert.Equal(t, unpacked, again)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "one revision and the current link")

	// Three profiles link to the same copy.
	for _, profile := range []string{".claude1", ".claude2", ".claude3"} {
		link, err := Link(unpacked, filepath.Join(base, profile, "skills"))
		require.NoError(t, err)
		state := Inspect(link)
		assert.True(t, state.Current, state.Problem)
		assert.Equal(t, Revision(), state.Revision)
	}
}

func TestLinkLeavesRealDirectoryAlone(t *testing.T) {
	base := t.TempDir()
	unpacked, err := Unpack(filepath.Join(base, "skill"))
	require.NoError(t, err)
	skills := filepath.Join(base, "skills")
	require.NoError(t, os.MkdirAll(filepath.Join(skills, Name), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(skills, Name, "SKILL.md"), []byte("someone's own copy"), 0o644))

	_, err = Link(unpacked, skills)
	require.ErrorContains(t, err, "is not a link")
	data, err := os.ReadFile(filepath.Join(skills, Name, "SKILL.md"))
	require.NoError(t, err)
	assert.Equal(t, "someone's own copy", string(data))
}

func TestInspectReportsDifferences(t *testing.T) {
	base := t.TempDir()
	assert.Equal(t, "not installed", Inspect(filepath.Join(base, "absent")).Problem)

	unpacked, err := Unpack(filepath.Join(base, "skill"))
	require.NoError(t, err)
	resolved, err := filepath.EvalSymlinks(unpacked)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(resolved, "SKILL.md"), []byte("edited by hand"), 0o644))

	state := Inspect(unpacked)
	assert.False(t, state.Current)
	assert.Contains(t, state.Problem, "different revision")
}

// The embedded files are the ones in this directory: nothing generated or
// hidden is carried along.
func TestEmbeddedFiles(t *testing.T) {
	var names []string
	require.NoError(t, fs.WalkDir(Files(), ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			names = append(names, path)
		}
		return err
	}))
	assert.ElementsMatch(t, []string{
		"SKILL.md",
		"examples/collector/collect.py", "examples/collector/job.yaml", "examples/collector/lib/snapshot.py",
		"examples/healthcheck/check.sh", "examples/healthcheck/job.yaml",
		"examples/validation/job.yaml", "examples/validation/validate.sh",
	}, names)
}
