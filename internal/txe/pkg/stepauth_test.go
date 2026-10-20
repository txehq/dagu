// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A home with no step-auth file has no enrolled class; recording a class
// keeps the others, and the file is the owner's alone.
func TestStepAuth(t *testing.T) {
	home := Home{Root: t.TempDir()}
	auth, err := home.StepAuth()
	require.NoError(t, err)
	_, ok := auth.Enrolled("worker")
	assert.False(t, ok)

	require.NoError(t, home.SetStepCredential("worker", "/abs/worker-credential.json", "http://127.0.0.1:18080/api/v1"))
	require.NoError(t, home.SetStepCredential("reviewer", "/abs/reviewer-credential.json", "http://127.0.0.1:18080/api/v1"))
	auth, err = home.StepAuth()
	require.NoError(t, err)
	worker, ok := auth.Enrolled("worker")
	require.True(t, ok)
	assert.Equal(t, StepAuthClass{Mode: StepModeCredential, CredentialFile: "/abs/worker-credential.json", Hub: "http://127.0.0.1:18080/api/v1"}, worker)
	_, ok = auth.Enrolled("reviewer")
	assert.True(t, ok)
	path := filepath.Join(home.ClientDir(), StepAuthFile)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	require.ErrorContains(t, home.SetStepCredential("worker", "relative.json", "http://h/api/v1"), "must be an absolute path")

	// The directory is synced after the rename, and a failed sync is an
	// error, not a silent success.
	synced := ""
	before := syncStepAuthDir
	t.Cleanup(func() { syncStepAuthDir = before })
	syncStepAuthDir = func(dir string) error { synced = dir; return nil }
	require.NoError(t, home.SetStepCredential("worker", "/abs/w.json", "http://h/api/v1"))
	assert.Equal(t, home.ClientDir(), synced)
	syncStepAuthDir = func(string) error { return os.ErrPermission }
	require.ErrorContains(t, home.SetStepCredential("worker", "/abs/w.json", "http://h/api/v1"), "could not be synced")
	require.ErrorContains(t, home.SetStepCredential("Worker", "/abs", "http://h/api/v1"), "not a credential class")
	require.ErrorContains(t, home.SetStepCredential("worker", "/abs", ""), "names no hub")
}

// A file this build did not write is refused rather than read loosely: an
// unknown field, another mode, a relative path or another schema.
func TestStepAuthRefusesWhatItDidNotWrite(t *testing.T) {
	for name, body := range map[string]string{
		"UnknownField": `{"schema":1,"classes":{"worker":{"mode":"credential","credential_file":"/abs","hub":"http://h/api/v1"}},"extra":true}`,
		"AnotherMode":  `{"schema":1,"classes":{"worker":{"mode":"api_key","credential_file":"/abs","hub":"http://h/api/v1"}}}`,
		"RelativePath": `{"schema":1,"classes":{"worker":{"mode":"credential","credential_file":"rel","hub":"http://h/api/v1"}}}`,
		"NoHub":        `{"schema":1,"classes":{"worker":{"mode":"credential","credential_file":"/abs"}}}`,
		"Schema":       `{"schema":2,"classes":{"worker":{"mode":"credential","credential_file":"/abs","hub":"http://h/api/v1"}}}`,
		"Trailing":     `{"schema":1,"classes":{"worker":{"mode":"credential","credential_file":"/abs","hub":"http://h/api/v1"}}} {}`,
		// Shapes that would otherwise read as "not enrolled" and fall back to
		// the API key.
		"NoClasses":    `{"schema":1}`,
		"NullClasses":  `{"schema":1,"classes":null}`,
		"EmptyClasses": `{"schema":1,"classes":{}}`,
		"UnknownClass": `{"schema":1,"classes":{"Worker":{"mode":"credential","credential_file":"/abs","hub":"http://h/api/v1"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			home := Home{Root: t.TempDir()}
			require.NoError(t, os.MkdirAll(home.ClientDir(), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(home.ClientDir(), StepAuthFile), []byte(body), 0o600))
			_, err := home.StepAuth()
			require.Error(t, err)
		})
	}
}

// A step-auth file that is a link is refused, even to a valid file.
func TestStepAuthRefusesALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links are refused there by Lstat, tested by the reader itself")
	}
	home := Home{Root: t.TempDir()}
	require.NoError(t, home.SetStepCredential("worker", "/abs/w.json", "http://h/api/v1"))
	real := filepath.Join(home.ClientDir(), StepAuthFile)
	moved := real + ".real"
	require.NoError(t, os.Rename(real, moved))
	require.NoError(t, os.Symlink(moved, real))
	_, err := home.StepAuth()
	require.Error(t, err)
}
