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

	require.NoError(t, home.SetStepCredential("worker", "/abs/worker-credential.json"))
	require.NoError(t, home.SetStepCredential("reviewer", "/abs/reviewer-credential.json"))
	auth, err = home.StepAuth()
	require.NoError(t, err)
	worker, ok := auth.Enrolled("worker")
	require.True(t, ok)
	assert.Equal(t, StepAuthClass{Mode: StepModeCredential, CredentialFile: "/abs/worker-credential.json"}, worker)
	_, ok = auth.Enrolled("reviewer")
	assert.True(t, ok)
	path := filepath.Join(home.ClientDir(), StepAuthFile)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	require.ErrorContains(t, home.SetStepCredential("worker", "relative.json"), "must be an absolute path")
}

// A file this build did not write is refused rather than read loosely: an
// unknown field, another mode, a relative path or another schema.
func TestStepAuthRefusesWhatItDidNotWrite(t *testing.T) {
	for name, body := range map[string]string{
		"UnknownField": `{"schema":1,"classes":{},"extra":true}`,
		"AnotherMode":  `{"schema":1,"classes":{"worker":{"mode":"api_key","credential_file":"/abs"}}}`,
		"RelativePath": `{"schema":1,"classes":{"worker":{"mode":"credential","credential_file":"rel"}}}`,
		"Schema":       `{"schema":2,"classes":{}}`,
		"Trailing":     `{"schema":1,"classes":{}} {}`,
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
