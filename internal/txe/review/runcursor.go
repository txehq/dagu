// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"fmt"
	"slices"
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
// arrived. Coverage is therefore kept as a few bounded things:
//
//   - at: every result that ended before it is covered, except those of
//     pending runs;
//   - frontier: the results that ended exactly at it and are covered, by
//     run and execution, so two results with one timestamp are told apart;
//   - floor: only when more results share that one instant than the
//     frontier may hold. Every result at it whose key is not after floor is
//     covered. Results are shown in key order, so this is exact for
//     everything that had ended when it was set;
//   - pending: runs that were unfinished when at last moved. Their result
//     may be reported late with an end time before at, so they stay owed,
//     whatever their time, until a review is shown them.
//
// It relies on one thing the service does not guarantee by itself: a run
// that starts after a checkpoint ends after that checkpoint's at. A job's
// runs are on one machine and their times come from its clock, so this
// holds unless that clock is set back between two runs.
//
// Nothing a job's history contains makes it unreviewable for good. Too many
// results in one instant fold into floor. Too many queued runs are tracked
// oldest first, which are the next to start, and the rest fall under the
// assumption above. Only more runs actually executing at once than can be
// tracked stops reviews, visibly and for as long as that lasts.
type coverage struct {
	at       time.Time
	floor    string
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

// before orders results by end time and then by key. The key order is the
// one floor is compared in.
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
	if len(parts) != 5 {
		return c, fmt.Errorf("run cursor %q is not understood", cursor)
	}
	if parts[1] != "" {
		at, err := time.Parse(time.RFC3339Nano, parts[1])
		if err != nil {
			return c, fmt.Errorf("run cursor time: %w", err)
		}
		c.at = at
	}
	c.floor = parts[2]
	for key := range strings.SplitSeq(parts[3], ",") {
		if key != "" {
			c.frontier[key] = true
		}
	}
	for id := range strings.SplitSeq(parts[4], ",") {
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
	return strings.Join([]string{coverageVersion, at, c.floor, sortedKeys(c.frontier), sortedKeys(c.pending)}, "|")
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
	switch {
	case c.frontier[p.key()]:
		return true
	case c.pending[p.runID]:
		return false
	case p.at.Before(c.at):
		return true
	}
	return p.at.Equal(c.at) && c.floor != "" && p.key() <= c.floor
}

// inFlight is what the service lists as unfinished when a cursor is made.
type inFlight struct {
	// executing are the runs that have an execution under way.
	executing []string
	// queued are the runs waiting to start, oldest created last.
	queued []string
	// owed are runs whose result is known to be uncovered whatever its
	// time: pending runs that have finished, and runs found changed while
	// they were being listed or read.
	owed []string
}

// after is the coverage once the given results, a prefix of the uncovered
// ones in order, have been shown as well. An owed run that was not shown
// stays pending.
func (c coverage) after(shown []runPoint, now inFlight) (coverage, error) {
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
		next.floor = c.floor
		for key := range c.frontier {
			next.frontier[key] = true
		}
	}
	last := ""
	for _, p := range shown {
		if p.at.Equal(next.at) {
			next.frontier[p.key()] = true
			last = max(last, p.key())
		}
	}
	if len(next.frontier) > maxCoverageSet && last != "" {
		// More results share this instant than are kept one by one. They
		// were shown in key order, so everything at it up to the last one
		// shown is covered, and only what lies beyond stays by name.
		next.floor = max(next.floor, last)
		for key := range next.frontier {
			if key <= next.floor {
				delete(next.frontier, key)
			}
		}
	}
	if len(next.frontier) > maxCoverageSet {
		return coverage{}, fmt.Errorf("%w: more than %d results at one instant were covered out of order", ErrRunsUntrackable, maxCoverageSet)
	}
	for _, id := range now.owed {
		if !seen[id] {
			next.pending[id] = true
		}
	}
	for _, id := range now.executing {
		next.pending[id] = true
	}
	if len(next.pending) > maxCoverageSet {
		return coverage{}, fmt.Errorf("%w: more than %d of its runs are executing or owed a review at once", ErrRunsUntrackable, maxCoverageSet)
	}
	// Queued runs fill what room is left, oldest created first: those are
	// the next to start. One left out is still queued, so it starts, and
	// ends, after this cursor's time.
	for _, id := range slices.Backward(now.queued) {
		if len(next.pending) >= maxCoverageSet {
			break
		}
		next.pending[id] = true
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
