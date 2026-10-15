// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/dirlock"
	"github.com/dagucloud/dagu/v2/internal/persis"
	persisfile "github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// Locks the backend really writes are excluded: a held scheduler lock and a
// collection's record lock buckets.
func TestBackendLocksAreExcluded(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	backend := persisfile.NewBackend(backendPaths(l.DataDir))
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, name := range []string{persis.CollectionSchedulerState, persis.CollectionDAGSettings} {
		require.NoError(t, backend.Collection(name).Put(context.Background(), &persis.Record{ID: "r1", Data: []byte(`{}`), CreatedAt: at, UpdatedAt: at}))
	}
	lock := dirlock.New(filepath.Join(persisfile.SchedulerStateDir(backendPaths(l.DataDir)), "locks"), nil)
	require.NoError(t, lock.TryLock())
	t.Cleanup(func() { _ = lock.Unlock() })
	inv := scan(t, l)
	assert.Empty(t, continuity.Blocking(continuity.Validate(inv, continuity.Policy{})))
	excluded := map[string]bool{}
	for _, e := range inv.Excluded {
		excluded[e.Root+"/"+e.Path] = true
	}
	assert.True(t, excluded["hub-data/scheduler/locks/"+dirlock.LockDirectoryName], "%v", inv.Excluded)
	assert.True(t, excluded["hub-data/dag-settings/.dagu_record_locks"], "%v", inv.Excluded)
}

// A reserved lock name hides nothing: a directory with that name but
// another shape blocks unread, and a directory or file whose name merely
// looks like a lock is retained data.
func TestLockNamesHideNothing(t *testing.T) {
	area := func(l *fixture.Layout, rel string) string {
		return filepath.Join(l.DataDir, "dag-runs", filepath.FromSlash(rel))
	}
	write := func(rel string) func(*testing.T, *fixture.Layout) {
		return func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.MkdirAll(filepath.Dir(area(l, rel)), 0o750))
			require.NoError(t, os.WriteFile(area(l, rel), []byte(`{"retained":true}`), 0o600))
		}
	}
	blocks := []struct {
		name   string
		break_ func(*testing.T, *fixture.Layout)
	}{
		{"a directory lock that holds more than its owner", func(t *testing.T, l *fixture.Layout) {
			write("job/.dagu_lock/owner")(t, l)
			write("job/.dagu_lock/data.json")(t, l)
		}},
		{"a directory lock whose owner is a directory", func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.MkdirAll(area(l, "job/.dagu_lock/owner"), 0o750))
		}},
		{"a releasing lock that holds data", write("job/.dagu_lock.releasing.1/data.json")},
		{"record locks with a bucket not named by two hex digits", func(t *testing.T, l *fixture.Layout) {
			require.NoError(t, os.MkdirAll(area(l, "job/.dagu_record_locks/zz"), 0o750))
		}},
		{"record locks that hold a file", write("job/.dagu_record_locks/ab/data.json")},
		{"record locks that hold a file at their top", write("job/.dagu_record_locks/data.json")},
		{"a registry lock directory that holds data", func(t *testing.T, l *fixture.Layout) {
			p := filepath.Join(registry.Dir(l.DataDir), ".dagu_record_locks", "ab", "data.json")
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
			require.NoError(t, os.WriteFile(p, []byte(`{}`), 0o600))
		}},
	}
	for _, tc := range blocks {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, _ := build(t)
			tc.break_(t, l)
			inv := scan(t, l)
			got := codes(continuity.Validate(inv, continuity.Policy{}), continuity.SeverityBlock)
			assert.Positive(t, got["unsupported_file"], "%v", got)
			for _, f := range inv.Files {
				assert.False(t, strings.HasSuffix(f.Path, "data.json") && strings.Contains(f.Path, "lock"), "nothing under it is read: %s", f.Path)
			}
		})
	}
	retained := []string{"job/lock/data.json", "job/locks/data.json", "job/.lock/data.json", "job/dagu_lock/data.json", "job/.dagu_lockx/data.json", "job/.dagu_lock"}
	t.Run("names that only look like locks", func(t *testing.T) {
		t.Parallel()
		l, _ := build(t)
		for _, rel := range retained {
			write(rel)(t, l)
		}
		inv := scan(t, l)
		assert.Empty(t, continuity.Blocking(continuity.Validate(inv, continuity.Policy{})))
		files := map[string]string{}
		for _, f := range inv.Files {
			files[f.Root+"/"+f.Path] = f.Policy
		}
		for _, rel := range retained {
			assert.Equal(t, continuity.PolicyMutable, files["hub-data/dag-runs/"+rel], rel)
		}
	})
}
