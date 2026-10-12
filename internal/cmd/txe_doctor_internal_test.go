// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

// A staged package is accounted for by the unfinished request it is named
// after, not by there being as many requests as staged packages.
func TestTXEUnreferencedStaging(t *testing.T) {
	staging := t.TempDir()
	for _, name := range []string{"req_kept", "req_orphan"} {
		require.NoError(t, os.Mkdir(filepath.Join(staging, name), 0o700))
	}
	entries := []txepkg.Entry{{RequestID: "req_kept"}, {RequestID: "req_already_moved"}}

	assert.Equal(t, []string{"req_orphan"}, txeUnreferencedStaging(staging, entries))
	assert.Equal(t, []string{"req_kept", "req_orphan"}, txeUnreferencedStaging(staging, nil))
	assert.Empty(t, txeUnreferencedStaging(filepath.Join(staging, "absent"), nil), "no staging area yet")
}
