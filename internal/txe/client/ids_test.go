// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewID(t *testing.T) {
	shape := regexp.MustCompile(`^job_[0-9A-HJKMNP-TV-Z]{26}$`)
	seen := map[string]bool{}
	var previous string
	for range 200 {
		id, err := NewID("job")
		require.NoError(t, err)
		assert.Regexp(t, shape, id)
		assert.False(t, seen[id], "minted %s twice", id)
		seen[id] = true
		// The time comes first, so later IDs do not sort before earlier ones
		// by more than their random part.
		assert.GreaterOrEqual(t, id[:14], previous)
		previous = id[:14]
	}
	// The first character carries only the top three bits of the time.
	id, err := NewID("job")
	require.NoError(t, err)
	assert.Contains(t, "01234567", string(id[4]))
}
