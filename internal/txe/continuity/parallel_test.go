// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
)

// The inventory a scan reads on its pool is byte for byte the one it reads
// one file at a time (TXE-7023): the same files, records, digests, issues
// and seal.
func TestParallelScanEqualsSerialScan(t *testing.T) {
	l, _ := build(t)

	restore := continuity.SetScanWorkers(1)
	serial := scan(t, l)
	restore()

	restore = continuity.SetScanWorkers(16)
	parallel := scan(t, l)
	restore()

	require.NotEmpty(t, serial.Files)
	require.NotEmpty(t, serial.Records)
	a, err := json.Marshal(serial)
	require.NoError(t, err)
	b, err := json.Marshal(parallel)
	require.NoError(t, err)
	assert.JSONEq(t, string(a), string(b))
	assert.Equal(t, string(a), string(b))
}

// The pool really reads more than one file at a time, and never more than
// its bound: a pool that ran one call at a time would leave the scan of a
// Ceph-backed store at 7.7 to 8.9 ms per file.
func TestPoolRunsCallsConcurrentlyWithinItsBound(t *testing.T) {
	restore := continuity.SetScanWorkers(4)
	defer restore()

	var running, peak atomic.Int32
	release := make(chan struct{})
	reached := make(chan struct{})
	var once sync.Once
	done := make(chan error, 1)
	go func() {
		done <- continuity.ForEach(context.Background(), 40, func(int) error {
			n := running.Add(1)
			defer running.Add(-1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			if n == 4 {
				once.Do(func() { close(reached) })
			}
			<-release
			return nil
		})
	}()
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatalf("the pool never ran 4 calls at once (peak %d)", peak.Load())
	}
	close(release)
	require.NoError(t, <-done)
	assert.Equal(t, int32(4), peak.Load())
}

// The pool reports the failure of the lowest index, as a scan in walk order
// would, whichever finishes first, and every call has returned by then.
func TestPoolReportsTheLowestFailingIndex(t *testing.T) {
	restore := continuity.SetScanWorkers(8)
	defer restore()

	var calls atomic.Int32
	err := continuity.ForEach(context.Background(), 50, func(i int) error {
		calls.Add(1)
		switch i {
		case 7:
			time.Sleep(20 * time.Millisecond)
			return fmt.Errorf("file %d", i)
		case 31:
			return fmt.Errorf("file %d", i)
		}
		return nil
	})
	require.EqualError(t, err, "file 7")
	assert.Equal(t, int32(50), calls.Load())
}

// A cancelled scan fails rather than returning a partial inventory.
func TestPoolFailsOnACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := continuity.ForEach(ctx, 5, func(int) error { return nil })
	assert.True(t, errors.Is(err, context.Canceled), "%v", err)
}

// A file the pool cannot read fails the scan, with any worker count.
func TestAnUnreadableFileFailsTheScan(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permissions and a non-root user")
	}
	for _, workers := range []int{1, 16} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			restore := continuity.SetScanWorkers(workers)
			defer restore()
			l, _ := build(t)
			p := filepath.Join(l.LogsDir, "unreadable.log")
			require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
			require.NoError(t, os.Chmod(p, 0))
			t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
			_, err := continuity.Scan(context.Background(), continuity.Options{Roots: roots(l), ExpectedOwner: "own_x",
				Label: "test", Now: func() time.Time { return scanTime }})
			require.Error(t, err)
			assert.True(t, errors.Is(err, os.ErrPermission), "%v", err)
		})
	}
}
