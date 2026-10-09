// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"sort"
	"time"
)

// runPoint is one result of a job: the latest execution of a run. A result
// is identified by its key. The time only gives the order results are shown
// in; it plays no part in deciding whether one has been covered.
type runPoint struct {
	runID string
	// execution is the reference of the run's latest execution.
	execution string
	// at is when the execution ended, or the latest time the service has
	// for it; zero when it has none.
	at time.Time
}

// key names the result as a review records it: "run@execution".
func (p runPoint) key() string {
	return coveredKey(p.runID, p.execution)
}

// coveredKey is the name under which a review records a result it covered.
func coveredKey(runID, executionRef string) string {
	return runID + "@" + executionRef
}

// before orders results by end time and then by key.
func (p runPoint) before(q runPoint) bool {
	if !p.at.Equal(q.at) {
		return p.at.Before(q.at)
	}
	return p.key() < q.key()
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
