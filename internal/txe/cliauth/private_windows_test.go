// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package cliauth

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
)

func TestCheckPrivateUsesTheDACL(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, checkPrivate(s.dir, true))
	file := filepath.Join(s.dir, "entry.json")
	require.NoError(t, fileutil.WriteFileAtomic(file, []byte("{}"), storeFilePerm))
	require.NoError(t, checkPrivate(file, false), "a file made in the store inherits its DACL")

	trusted, err := trustedSIDs()
	require.NoError(t, err)
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	require.NoError(t, err)
	everyone := append(append(sids{}, trusted...), world)

	// A file anyone may use is refused.
	require.NoError(t, closeToOthers(file, everyone))
	assert.ErrorContains(t, checkPrivate(file, false), "other users")

	// A directory anyone may use is closed again.
	require.NoError(t, closeToOthers(s.dir, everyone))
	require.NoError(t, checkPrivate(s.dir, true))
	sd, err := windows.GetNamedSecurityInfo(s.dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	open, err := openToOthers(sd, trusted)
	require.NoError(t, err)
	assert.False(t, open)
}
