// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package worker_test exercises the shell helpers in txe/worker/lib.sh.
package worker_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type linkEnv struct {
	home, txeHome, linkDir, link, target string
}

func newLinkEnv(t *testing.T) linkEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the worker scripts run on the macOS worker only")
	}
	home := t.TempDir()
	e := linkEnv{home: home, txeHome: filepath.Join(home, "txe"), linkDir: filepath.Join(home, "bin")}
	e.link = filepath.Join(e.linkDir, "dagu")
	e.target = filepath.Join(e.txeHome, "bin", "dagu")
	return e
}

// run sources lib.sh and calls link_dagu_on_path with path as the shell's PATH.
func (e linkEnv) run(t *testing.T, path string) (stdout, stderr string) {
	t.Helper()
	return e.runIn(t, "", e.txeHome, path)
}

// runIn is run from working directory dir, with txeHome as TXE_DAGU_HOME.
func (e linkEnv) runIn(t *testing.T, dir, txeHome, path string) (stdout, stderr string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	lib, err := filepath.Abs("lib.sh")
	require.NoError(t, err)
	cmd := exec.Command(bash, "-c", `set -euo pipefail; . "$1"; link_dagu_on_path`, "bash", lib)
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + e.home, "TXE_DAGU_HOME=" + txeHome, "TXE_DAGU_LINK_DIR=" + e.linkDir, "PATH=" + path}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	require.NoError(t, cmd.Run(), "link_dagu_on_path must not fail the install: %s", errOut.String())
	return out.String(), errOut.String()
}

func sysPath(extra ...string) string {
	p := "/usr/bin:/bin"
	for _, d := range extra {
		p = d + ":" + p
	}
	return p
}

// A missing dagu is linked to this install, and a second run keeps the link.
func TestLinkDaguOnPathCreatesTheLinkOnce(t *testing.T) {
	e := newLinkEnv(t)
	out, errOut := e.run(t, sysPath(e.linkDir))
	got, err := os.Readlink(e.link)
	require.NoError(t, err)
	assert.Equal(t, e.target, got)
	assert.Contains(t, out, e.link+" -> "+e.target)
	assert.Empty(t, errOut)

	_, errOut = e.run(t, sysPath(e.linkDir))
	got, err = os.Readlink(e.link)
	require.NoError(t, err)
	assert.Equal(t, e.target, got)
	assert.Empty(t, errOut)
}

// A dagu the installer did not put there is never replaced, and the install
// still succeeds.
func TestLinkDaguOnPathLeavesAForeignDaguAlone(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		e := newLinkEnv(t)
		require.NoError(t, os.MkdirAll(e.linkDir, 0o755))
		require.NoError(t, os.WriteFile(e.link, []byte("#!/bin/sh\necho other\n"), 0o755))
		_, errOut := e.run(t, sysPath(e.linkDir))
		data, err := os.ReadFile(e.link)
		require.NoError(t, err)
		assert.Equal(t, "#!/bin/sh\necho other\n", string(data))
		assert.Contains(t, errOut, "not linked: "+e.link)
	})
	t.Run("directory", func(t *testing.T) {
		e := newLinkEnv(t)
		require.NoError(t, os.MkdirAll(e.link, 0o755))
		_, errOut := e.run(t, sysPath(e.linkDir))
		entries, err := os.ReadDir(e.link)
		require.NoError(t, err)
		assert.Empty(t, entries, "nothing is written inside a directory named dagu")
		assert.Contains(t, errOut, "not linked: "+e.link)
	})
	t.Run("symlink elsewhere", func(t *testing.T) {
		e := newLinkEnv(t)
		require.NoError(t, os.MkdirAll(e.linkDir, 0o755))
		require.NoError(t, os.Symlink("/opt/other/dagu", e.link))
		_, errOut := e.run(t, sysPath(e.linkDir))
		got, err := os.Readlink(e.link)
		require.NoError(t, err)
		assert.Equal(t, "/opt/other/dagu", got)
		assert.Contains(t, errOut, "not linked: "+e.link)
	})
}

// A relative TXE_DAGU_HOME still gives a link that resolves to the binary: the
// stored target is absolute, not relative to the link's directory.
func TestLinkDaguOnPathMakesARelativeHomeAbsolute(t *testing.T) {
	e := newLinkEnv(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(e.target), 0o755))
	require.NoError(t, os.WriteFile(e.target, []byte("#!/bin/sh\n"), 0o755))
	_, errOut := e.runIn(t, e.home, "txe", sysPath(e.linkDir))
	assert.Empty(t, errOut)
	got, err := os.Readlink(e.link)
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(got), "stored target %q", got)
	resolved, err := filepath.EvalSymlinks(e.link)
	require.NoError(t, err)
	want, err := filepath.EvalSymlinks(e.target)
	require.NoError(t, err)
	assert.Equal(t, want, resolved)
}

// A foreign dagu in a directory missing from PATH gets both messages.
func TestLinkDaguOnPathNamesAMissingPathEvenWhenNotLinked(t *testing.T) {
	e := newLinkEnv(t)
	require.NoError(t, os.MkdirAll(e.linkDir, 0o755))
	require.NoError(t, os.WriteFile(e.link, []byte("other"), 0o755))
	_, errOut := e.run(t, sysPath())
	assert.Contains(t, errOut, "not linked: "+e.link)
	assert.Contains(t, errOut, e.linkDir+" is not on this shell's PATH")
}

// The link is still made when its directory is not on PATH, and the operator is
// told to add it.
func TestLinkDaguOnPathNamesALinkDirMissingFromPath(t *testing.T) {
	e := newLinkEnv(t)
	_, errOut := e.run(t, sysPath())
	got, err := os.Readlink(e.link)
	require.NoError(t, err)
	assert.Equal(t, e.target, got)
	assert.Contains(t, errOut, e.linkDir+" is not on this shell's PATH")
}
