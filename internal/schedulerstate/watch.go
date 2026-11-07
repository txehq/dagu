// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package schedulerstate

import (
	"context"
	"crypto/rand"
	"time"
)

// WatchLedger is what the scheduler remembers of one DAG's watched folder:
// the folder and pattern it was read with, the files it has seen there, and
// the arrivals it has numbered.
type WatchLedger struct {
	Path    string `json:"path"`
	Pattern string `json:"pattern,omitempty"`
	// Epoch names this ledger's life. A ledger made again, because the
	// folder or the pattern changed or the record was lost, gets another,
	// so the arrival numbers it hands out again never name an earlier run.
	Epoch string `json:"epoch,omitempty"`
	// Arrivals is the number of the last arrival this ledger recorded.
	Arrivals uint64                 `json:"arrivals,omitempty"`
	Files    map[string]WatchedFile `json:"files,omitempty"`
}

// WatchedFile is a file the ledger holds: the version it was last seen at
// and the arrival that version came with.
type WatchedFile struct {
	FileMark
	// Arrival is the number of the arrival, starting at 1. It is 0 for a
	// file that has none: one the folder held when the ledger was made, or
	// one a record of version 1 holds, whose run was queued under the old
	// naming.
	Arrival uint64 `json:"arrival,omitempty"`
	// Unqueued says the arrival's run may not be queued yet. An arrival is
	// saved before its run is queued, so one whose run was being queued when
	// the scheduler stopped is queued again, under the same run ID.
	Unqueued bool `json:"unqueued,omitempty"`
}

// FileMark tells one version of a file apart from another.
type FileMark struct {
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
}

// Same reports whether two marks are of the same version of a file. Times
// are compared as instants, since a mark read back from the store carries
// another location.
func (m FileMark) Same(o FileMark) bool {
	return m.Size == o.Size && m.ModTime.Equal(o.ModTime)
}

// Arrive records that the file name arrived at version mark: it is given
// the next arrival number and waits for its run to be queued. Arrive is the
// only way an arrival is made, so two arrivals of the same version are
// always two arrivals.
func (l *WatchLedger) Arrive(name string, mark FileMark) {
	if l.Epoch == "" {
		l.Epoch = rand.Text()
	}
	if l.Files == nil {
		l.Files = map[string]WatchedFile{}
	}
	l.Arrivals++
	l.Files[name] = WatchedFile{FileMark: mark, Arrival: l.Arrivals, Unqueued: true}
}

// WatchStore keeps the ledgers of watched folders, by DAG name.
type WatchStore interface {
	LoadWatch(ctx context.Context) (map[string]WatchLedger, error)
	SaveWatch(ctx context.Context, ledgers map[string]WatchLedger) error
}
