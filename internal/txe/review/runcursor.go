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
// A result is one attempt of one run. A native retry keeps the run id and
// starts a new attempt, so a run id alone does not name a result, and the
// service lists runs by when they were created, not by when a result
// arrived. Coverage is therefore kept as three bounded things:
//
//   - at: every result that ended before it is covered, except those of
//     pending runs;
//   - frontier: the results that ended exactly at it and are covered, by
//     run and attempt, so two results with one timestamp are told apart;
//   - pending: the runs that were unfinished when at last moved. Their
//     result may be reported late with an end time before at, so they stay
//     owed, whatever their time, until a review is shown them.
//
// It relies on one thing the service does not guarantee by itself: a run
// that starts after a checkpoint ends after that checkpoint's at. A job's
// runs are on one machine and their times come from its clock, so this
// holds unless that clock is set back between two runs.
type coverage struct {
	at       time.Time
	frontier map[string]bool
	pending  map[string]bool
	// legacy is a run id, from a cursor written before coverage carried
	// attempts: everything up to that run's place is covered.
	legacy string
}

const (
	coverageVersion = "v2"
	// maxCoverageSet bounds the frontier and the pending set. A job with
	// more results in one instant, or more unfinished runs, than this is
	// not reviewed until that is no longer so; nothing is dropped to fit.
	maxCoverageSet = 512
)

// runPoint is one result: the latest attempt of a run and when it ended.
type runPoint struct {
	runID     string
	attemptID string
	at        time.Time
}

func (p runPoint) key() string {
	return p.runID + "@" + p.attemptID
}

// before orders results by end time, then run, then attempt.
func (p runPoint) before(q runPoint) bool {
	if !p.at.Equal(q.at) {
		return p.at.Before(q.at)
	}
	if p.runID != q.runID {
		return p.runID < q.runID
	}
	return p.attemptID < q.attemptID
}

func parseCoverage(cursor string) (coverage, error) {
	c := coverage{frontier: map[string]bool{}, pending: map[string]bool{}}
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

// after is the coverage once the given results have been shown as well.
// unfinished are the runs the service lists as not finished now, and owed
// the pending runs that have finished: an owed run that was not shown
// stays pending.
func (c coverage) after(shown []runPoint, unfinished, owed []string) (coverage, error) {
	next := coverage{at: c.at, frontier: map[string]bool{}, pending: map[string]bool{}}
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
	for _, id := range unfinished {
		next.pending[id] = true
	}
	for _, id := range owed {
		if !seen[id] {
			next.pending[id] = true
		}
	}
	if len(next.frontier) > maxCoverageSet || len(next.pending) > maxCoverageSet {
		return coverage{}, fmt.Errorf("the job has more than %d results in one instant or unfinished runs; its runs cannot be tracked for review", maxCoverageSet)
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
