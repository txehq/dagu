// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindBrowser(t *testing.T) {
	t.Parallel()
	existing := map[string]bool{
		"/opt/chrome": true,
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome":                        true,
		filepath.Join("C:", "Program Files", "Google", "Chrome", "Application", "chrome.exe"): true,
		"/usr/bin/chromium": true,
	}
	exists := func(path string) bool { return existing[path] }
	noEnv := func(string) string { return "" }
	noLook := func(string) (string, error) { return "", errors.New("not found") }

	path, err := findBrowser("/opt/chrome", "linux", noEnv, noLook, exists)
	require.NoError(t, err)
	assert.Equal(t, "/opt/chrome", path)
	_, err = findBrowser("/opt/missing", "linux", noEnv, noLook, exists)
	assert.ErrorContains(t, err, "does not exist")

	env := func(key string) string {
		if key == "CHROME_PATH" {
			return "/opt/chrome"
		}
		return ""
	}
	path, err = findBrowser("", "linux", env, noLook, exists)
	require.NoError(t, err)
	assert.Equal(t, "/opt/chrome", path, "CHROME_PATH wins over the candidates")

	path, err = findBrowser("", "darwin", noEnv, noLook, exists)
	require.NoError(t, err)
	assert.Equal(t, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", path)

	winEnv := func(key string) string {
		if key == "PROGRAMFILES" {
			return filepath.Join("C:", "Program Files")
		}
		return ""
	}
	path, err = findBrowser("", "windows", winEnv, noLook, exists)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("C:", "Program Files", "Google", "Chrome", "Application", "chrome.exe"), path)

	look := func(name string) (string, error) {
		if name == "chromium" {
			return "/usr/bin/chromium", nil
		}
		return "", errors.New("not found")
	}
	path, err = findBrowser("", "linux", noEnv, look, exists)
	require.NoError(t, err)
	assert.Equal(t, "/usr/bin/chromium", path)

	_, err = findBrowser("", "linux", noEnv, noLook, exists)
	assert.ErrorIs(t, err, ErrBrowserNotFound)
	_, err = findBrowser("", "plan9", noEnv, noLook, exists)
	assert.ErrorContains(t, err, "not supported")
}

// The helper runs in the dagu executable's directory, so a relative browser
// path from the configuration or CHROME_PATH is made absolute first.
func TestFindBrowserReturnsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	chrome := filepath.Join(dir, "chrome")
	require.NoError(t, os.WriteFile(chrome, []byte("#!/bin/sh\n"), 0o700))
	t.Chdir(dir)

	path, err := FindBrowser("chrome")
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(path), path)
	assert.Equal(t, chrome, path)

	t.Setenv("CHROME_PATH", "./chrome")
	path, err = FindBrowser("")
	require.NoError(t, err)
	assert.Equal(t, chrome, path)
}
