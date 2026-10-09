// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// coverage is the checkpoint's run cursor over the service's run history:
// which results of a job's runs reviews have already been shown.
//
// A result is one execution of one run: an attempt, as queued at one time.
// A native retry keeps the run id and either starts a new attempt or queues
// the latest one again, so a run id alone does not name a result, and the
// service lists runs by when they were created, not by when a result
// arrived. Coverage is therefore kept as three bounded things:
//
//   - at: every result that ended before it is covered, except those of
//     pending runs;
//   - frontier: the results that ended exactly at it and are covered, each
//     by run and execution. Two results with one timestamp are told apart
//     by name, never by order, so one that turns up later at that same
//     timestamp is not taken for covered wherever it sorts;
//   - pending: every run that was unfinished, queued or executing, when at
//     last moved, and every run known to be owed a review. Their result
//     may be reported with an end time before at, so they stay owed,
//     whatever their time, until a review is shown them.
//
// It relies on one thing the service does not guarantee by itself: a run
// created after a checkpoint ends after that checkpoint's at, or exactly at
// it. A job's runs are on one machine and their times come from its clock,
// so this holds unless that clock is set back between two runs.
//
// Both sets are bounded and nothing is ever dropped from them to fit. The
// supported bound is exact: at most maxCoverageSet covered results sharing
// one end timestamp, and at most maxCoverageSet runs unfinished or owed at
// once. A job beyond either is refused with ErrRunsUntrackable. Its
// coverage is left as it was, so no result is passed over; the refusal is
// raised as an exception and the review deferred until the job is within
// the bound again.
type coverage struct {
	at       time.Time
	frontier map[string]bool
	pending  map[string]bool
	// legacy is a run id, from a cursor written before coverage carried
	// executions: everything up to that run's place is covered.
	legacy string
}

const (
	coverageVersion = "v2"
	// maxCoverageSet bounds the frontier and the pending set.
	maxCoverageSet = 512
)

// runPoint is one result: the latest execution of a run and when it ended.
type runPoint struct {
	runID string
	// execution is the reference of the run's latest execution; empty when
	// the service does not identify it.
	execution string
	at        time.Time
}

func (p runPoint) key() string {
	return p.runID + "@" + p.execution
}

// before orders results by end time and then by key.
func (p runPoint) before(q runPoint) bool {
	if !p.at.Equal(q.at) {
		return p.at.Before(q.at)
	}
	return p.key() < q.key()
}

func newCoverage() coverage {
	return coverage{frontier: map[string]bool{}, pending: map[string]bool{}}
}

func parseCoverage(cursor string) (coverage, error) {
	c := newCoverage()
	if cursor == "" {
		return c, nil
	}
	parts := strings.Split(cursor, "|")
	if parts[0] != coverageVersion {
		if len(parts) != 1 {
			return c, fmt.Errorf("run cursor %q is not understood", cursor)
		}
		c.legacy = cursor
		return c, nil
	}
	if len(parts) != 4 {
		return c, fmt.Errorf("run cursor %q is not understood", cursor)
	}
	if parts[1] != "" {
		at, err := time.Parse(time.RFC3339Nano, parts[1])
		if err != nil {
			return c, fmt.Errorf("run cursor time: %w", err)
		}
		c.at = at
	}
	for key := range strings.SplitSeq(parts[2], ",") {
		if key != "" {
			c.frontier[key] = true
		}
	}
	for id := range strings.SplitSeq(parts[3], ",") {
		if id != "" {
			c.pending[id] = true
		}
	}
	return c, nil
}

func (c coverage) String() string {
	at := ""
	if !c.at.IsZero() {
		at = c.at.UTC().Format(time.RFC3339Nano)
	}
	return strings.Join([]string{coverageVersion, at, sortedKeys(c.frontier), sortedKeys(c.pending)}, "|")
}

func sortedKeys(set map[string]bool) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// covered reports whether a review has already been shown this result.
func (c coverage) covered(p runPoint) bool {
	return c.frontier[p.key()] || (!c.pending[p.runID] && p.at.Before(c.at))
}

// after is the coverage once the given results, a prefix of the uncovered
// ones in order, have been shown as well. unfinished are all the runs the
// service lists as not finished now, queued or executing. owed are runs
// whose result is known to be uncovered whatever its time: pending runs
// that have finished, and runs found changed while they were being listed
// or read. An owed run that was not shown stays pending.
//
// It fails with ErrRunsUntrackable, changing nothing, when the result would
// not fit the bound.
func (c coverage) after(shown []runPoint, unfinished, owed []string) (coverage, error) {
	next := newCoverage()
	next.at = c.at
	seen := map[string]bool{}
	for _, p := range shown {
		seen[p.runID] = true
		if p.at.After(next.at) {
			next.at = p.at
		}
	}
	if next.at.Equal(c.at) {
		for key := range c.frontier {
			next.frontier[key] = true
		}
	}
	for _, p := range shown {
		if p.at.Equal(next.at) {
			next.frontier[p.key()] = true
		}
	}
	if len(next.frontier) > maxCoverageSet {
		return coverage{}, fmt.Errorf("%w: more than %d of its results share the end time %s; a review can cover at most that many at one timestamp",
			ErrRunsUntrackable, maxCoverageSet, next.at.UTC().Format(time.RFC3339))
	}
	for _, id := range unfinished {
		next.pending[id] = true
	}
	for _, id := range owed {
		if !seen[id] {
			next.pending[id] = true
		}
	}
	if len(next.pending) > maxCoverageSet {
		return coverage{}, fmt.Errorf("%w: %d of its runs are queued, executing or owed a review at once; a review can keep track of at most %d",
			ErrRunsUntrackable, len(next.pending), maxCoverageSet)
	}
	return next, nil
}

// uncovered collects the results still to be shown, oldest first, keeping
// at most limit of them in memory however many the service lists.
type uncovered struct {
	limit  int
	points []runPoint
}

func (u *uncovered) add(p runPoint) {
	u.points = append(u.points, p)
	if len(u.points) > 4*u.limit {
		u.settle()
	}
}

func (u *uncovered) settle() []runPoint {
	sort.Slice(u.points, func(i, j int) bool { return u.points[i].before(u.points[j]) })
	if len(u.points) > u.limit {
		u.points = u.points[:u.limit]
	}
	return u.points
}
