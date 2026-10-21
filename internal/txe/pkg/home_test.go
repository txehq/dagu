// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PublishMachine writes an identity Machine reads back, owner-only, and never
// replaces one: of several writers at once, exactly one wins.
func TestPublishMachineNeverReplacesAnIdentity(t *testing.T) {
	home := Home{Root: filepath.Join(t.TempDir(), "txe-home")}
	_, err := home.Machine()
	require.ErrorIs(t, err, ErrNoMachine)

	var wg sync.WaitGroup
	results := make([]error, 8)
	for i := range results {
		wg.Go(func() {
			results[i] = home.PublishMachine(Machine{MachineID: "mch_" + string(rune('A'+i)), OwnerID: "own_a", DisplayName: "laptop"}, time.Now())
		})
	}
	wg.Wait()
	won := 0
	for _, err := range results {
		if err == nil {
			won++
		} else {
			assert.ErrorIs(t, err, os.ErrExist)
		}
	}
	assert.Equal(t, 1, won)

	m, err := home.Machine()
	require.NoError(t, err)
	assert.Equal(t, "own_a", m.OwnerID)
	assert.Equal(t, 1, m.Schema)
	assert.Equal(t, "laptop", m.DisplayName)
	entries, err := os.ReadDir(home.Root)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary file is left behind")
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(home.Root, "machine.json"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		dir, err := os.Stat(home.Root)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), dir.Mode().Perm())
	}

	require.Error(t, home.PublishMachine(Machine{MachineID: "mch_a"}, time.Now()), "an owner is required")
}
