// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth_test

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the hub key is refused on Windows")
	}
}

func TestHubKeyIsCreatedOnceOwnerOnlyAndReadAfter(t *testing.T) {
	skipOnWindows(t)
	path := filepath.Join(t.TempDir(), "coordinator", "hub.key")

	first, err := transportauth.LoadOrCreateHubKey(path)
	require.NoError(t, err)
	assert.Len(t, first, 64)
	assert.GreaterOrEqual(t, len(first), transportauth.MinHubKeyBytes)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	again, err := transportauth.LoadOrCreateHubKey(path)
	require.NoError(t, err)
	assert.Equal(t, first, again)

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary file is left behind")
}

func TestProcessesStartingTogetherShareOneHubKey(t *testing.T) {
	skipOnWindows(t)
	path := filepath.Join(t.TempDir(), "hub.key")
	const n = 16
	keys := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { keys[i], errs[i] = transportauth.LoadOrCreateHubKey(path) })
	}
	wg.Wait()
	for i := range n {
		require.NoError(t, errs[i])
		assert.Equal(t, keys[0], keys[i])
	}
}

func TestHubKeyFileIsNeverRepairedOrReplaced(t *testing.T) {
	skipOnWindows(t)
	cases := map[string]func(t *testing.T, path string){
		"readable by others": func(t *testing.T, path string) {
			_, err := transportauth.LoadOrCreateHubKey(path)
			require.NoError(t, err)
			require.NoError(t, os.Chmod(path, 0o644))
		},
		"short": func(t *testing.T, path string) {
			require.NoError(t, os.WriteFile(path, []byte("abc\n"), 0o600))
		},
		"not hex": func(t *testing.T, path string) {
			require.NoError(t, os.WriteFile(path, []byte(string(make([]byte, 64))+"\n"), 0o600))
		},
		"upper case": func(t *testing.T, path string) {
			require.NoError(t, os.WriteFile(path, []byte("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789\n"), 0o600))
		},
		"empty": func(t *testing.T, path string) {
			require.NoError(t, os.WriteFile(path, nil, 0o600))
		},
		"a directory": func(t *testing.T, path string) {
			require.NoError(t, os.Mkdir(path, 0o700))
		},
		"a symlink": func(t *testing.T, path string) {
			target := path + ".target"
			_, err := transportauth.LoadOrCreateHubKey(target)
			require.NoError(t, err)
			require.NoError(t, os.Symlink(target, path))
		},
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hub.key")
			prepare(t, path)
			before, _ := os.Lstat(path)
			_, err := transportauth.LoadOrCreateHubKey(path)
			require.Error(t, err)
			after, statErr := os.Lstat(path)
			require.NoError(t, statErr)
			assert.Equal(t, before.ModTime(), after.ModTime(), "left as it was")
			assert.Equal(t, before.Mode(), after.Mode(), "left as it was")
		})
	}

	t.Run("relative path", func(t *testing.T) {
		_, err := transportauth.LoadOrCreateHubKey("hub.key")
		require.Error(t, err)
	})
}

func TestHubKeyFromTheFileIsAcceptedByTheServer(t *testing.T) {
	skipOnWindows(t)
	key, err := transportauth.LoadOrCreateHubKey(filepath.Join(t.TempDir(), "hub.key"))
	require.NoError(t, err)
	f := newFixture(t, fixtureOptions{hubKey: key})
	_, err = f.hub(key).Dispatch(t.Context(), dispatchRequest())
	require.NoError(t, err)
}
