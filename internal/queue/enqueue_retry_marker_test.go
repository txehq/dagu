// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package queue

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The queued-retry marker must be strictly later than the previous marker,
// whatever the clock reads, so (AttemptID, QueuedAt) identifies each queued
// execution of an attempt.
func TestNextRetryQueuedAt(t *testing.T) {
	base := time.Date(2026, 10, 10, 1, 2, 3, 400_000_000, time.UTC)
	perth := time.FixedZone("AWST", 8*60*60)

	tests := []struct {
		name     string
		previous string
		now      time.Time
		want     string
	}{
		{"clock ahead", base.Format(time.RFC3339Nano), base.Add(time.Second), "2026-10-10T01:02:04.4Z"},
		{"clock equal", base.Format(time.RFC3339Nano), base, "2026-10-10T01:02:03.400000001Z"},
		{"clock behind", base.Format(time.RFC3339Nano), base.Add(-time.Hour), "2026-10-10T01:02:03.400000001Z"},
		{"first enqueue in seconds with offset", "2026-10-10T09:02:03+08:00", base.In(perth).Add(-time.Minute), "2026-10-10T01:02:03.000000001Z"},
		{"legacy local format", base.In(time.Local).Format("2006-01-02 15:04:05"), base.Add(-time.Minute), base.Truncate(time.Second).Add(time.Nanosecond).Format(time.RFC3339Nano)},
		{"empty previous", "", base, "2026-10-10T01:02:03.4Z"},
		{"unparseable previous", "new-admission", base, "2026-10-10T01:02:03.4Z"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, nextRetryQueuedAt(tc.previous, tc.now))
		})
	}
}

// Repeated retries at one frozen or regressing clock still produce strictly
// increasing, distinct markers.
func TestNextRetryQueuedAtIsStrictlyIncreasing(t *testing.T) {
	base := time.Date(2026, 10, 10, 1, 2, 3, 0, time.UTC)
	marker := base.Format(time.RFC3339Nano)
	seen := map[string]bool{marker: true}
	prev := base
	for i := range 100 {
		now := base.Add(-time.Duration(i%3) * time.Second)
		marker = nextRetryQueuedAt(marker, now)
		got, err := time.Parse(time.RFC3339Nano, marker)
		require.NoError(t, err)
		require.True(t, got.After(prev), "retry %d: %s is not after %s", i, got, prev)
		require.False(t, seen[marker], "retry %d repeated %s", i, marker)
		seen[marker] = true
		prev = got
	}
}
