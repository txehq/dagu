// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"hash/fnv"
	"sync"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

// attemptWriteLocks serializes, per root DAG run, three things: a worker write's
// validation, the write itself, and the claim that records a new execution's
// lease. A queued retry reuses the attempt's output files. Without this lock,
// a write validated just before the next execution's claim could land after
// it, inside the new execution's output.
//
// The locks are local to this process, so they make validate-and-write atomic
// against claims handled by the same coordinator. A deployment with several
// coordinators sharing one lease store keeps per-chunk validation, which
// limits a stale write to the chunk already in flight.
type attemptWriteLocks struct {
	stripes [64]sync.Mutex
}

// lock acquires the lock for a root DAG run and returns its release function.
// Keying by the root covers every lease of the run, including a sub-DAG's
// and an inline descendant's, and is known to every caller before
// validation.
func (l *attemptWriteLocks) lock(root ir.DAGRunRef) func() {
	h := fnv.New32a()
	_, _ = h.Write([]byte(root.Name + "\x00" + root.ID))
	m := &l.stripes[h.Sum32()%uint32(len(l.stripes))]
	m.Lock()
	return m.Unlock
}
