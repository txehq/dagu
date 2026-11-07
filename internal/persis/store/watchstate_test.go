// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	"github.com/dagucloud/dagu/v2/internal/schedulerstate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatchStateStoreRoundTrip(t *testing.T) {
	t.Parallel()

	col := testutil.NewMemoryBackend().Collection("watch")
	s := store.NewWatchStateStore(col)
	ctx := context.Background()

	ledgers, err := s.LoadWatch(ctx)
	require.NoError(t, err)
	assert.Empty(t, ledgers)

	at := time.Date(2026, 10, 26, 9, 0, 0, 0, time.FixedZone("JST", 9*3600))
	ledger := schedulerstate.WatchLedger{Path: "/srv/inbox", Pattern: "*.pdf", Files: map[string]schedulerstate.WatchedFile{
		"old.pdf": {FileMark: schedulerstate.FileMark{Size: 3, ModTime: at}},
	}}
	ledger.Arrive("a.pdf", schedulerstate.FileMark{Size: 5, ModTime: at})
	require.NoError(t, s.SaveWatch(ctx, map[string]schedulerstate.WatchLedger{"inbox": ledger}))

	ledgers, err = store.NewWatchStateStore(col).LoadWatch(ctx)
	require.NoError(t, err)
	require.Contains(t, ledgers, "inbox")
	got := ledgers["inbox"]
	assert.Equal(t, "/srv/inbox", got.Path)
	assert.Equal(t, "*.pdf", got.Pattern)
	assert.Equal(t, ledger.Epoch, got.Epoch)
	assert.Equal(t, uint64(1), got.Arrivals)
	assert.True(t, got.Files["a.pdf"].Same(schedulerstate.FileMark{Size: 5, ModTime: at}))
	assert.Equal(t, uint64(1), got.Files["a.pdf"].Arrival)
	assert.True(t, got.Files["a.pdf"].Unqueued, "an arrival is saved before its run is queued")
	assert.Equal(t, uint64(0), got.Files["old.pdf"].Arrival)
	assert.False(t, got.Files["old.pdf"].Unqueued)
}

// A record of version 1, written before arrivals were numbered, is read
// with its files as files with no arrival whose runs are queued, which is
// what version 1 recorded: none of them is queued again.
func TestWatchStateStoreReadsVersion1(t *testing.T) {
	t.Parallel()

	col := testutil.NewMemoryBackend().Collection("watch")
	ctx := context.Background()
	v1 := `{"version":1,"dags":{"inbox":{"path":"/srv/inbox","pattern":"*.pdf","files":{"a.pdf":{"size":5,"modTime":"2026-10-26T09:00:00+09:00"}}}}}`
	require.NoError(t, col.Put(ctx, &persis.Record{ID: "watch", Data: []byte(v1), CreatedAt: time.Now(), UpdatedAt: time.Now()}))

	ledgers, err := store.NewWatchStateStore(col).LoadWatch(ctx)
	require.NoError(t, err)
	require.Contains(t, ledgers, "inbox")
	got := ledgers["inbox"]
	assert.Equal(t, "/srv/inbox", got.Path)
	assert.Empty(t, got.Epoch)
	at := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, schedulerstate.WatchedFile{FileMark: schedulerstate.FileMark{Size: 5, ModTime: got.Files["a.pdf"].ModTime}}, got.Files["a.pdf"])
	assert.True(t, got.Files["a.pdf"].ModTime.Equal(at))
}

func TestWatchStateStoreStartsFreshFromAnUnknownVersion(t *testing.T) {
	t.Parallel()

	col := testutil.NewMemoryBackend().Collection("watch")
	ctx := context.Background()
	future := `{"version":3,"dags":{"inbox":{"path":"/srv/inbox"}}}`
	require.NoError(t, col.Put(ctx, &persis.Record{ID: "watch", Data: []byte(future), CreatedAt: time.Now(), UpdatedAt: time.Now()}))

	ledgers, err := store.NewWatchStateStore(col).LoadWatch(ctx)
	require.NoError(t, err)
	assert.Empty(t, ledgers)
}

func TestWatchStateStoreStartsFreshFromACorruptRecord(t *testing.T) {
	t.Parallel()

	col := testutil.NewMemoryBackend().Collection("watch")
	ctx := context.Background()
	require.NoError(t, col.Put(ctx, &persis.Record{ID: "watch", Data: []byte("{not json"), CreatedAt: time.Now(), UpdatedAt: time.Now()}))

	ledgers, err := store.NewWatchStateStore(col).LoadWatch(ctx)
	require.NoError(t, err)
	assert.Empty(t, ledgers)
}
