// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"sync"
	"time"
)

const (
	// healthSummaryInterval is the least time between two warnings about one
	// coordinator's failing health checks after the first (TXE-5406).
	healthSummaryInterval = time.Minute
	// healthEpisodeExpiry forgets an episode whose coordinator has not been
	// checked for this long, such as one that left the membership. Its next
	// failure, if any, is logged as the first of a new episode.
	healthEpisodeExpiry = 10 * time.Minute
	// healthEpisodesMax bounds the episodes kept at once; the least recently
	// failing one is forgotten to make room.
	healthEpisodesMax = 64
)

// healthLogAction is what a failed health check is to log.
type healthLogAction int

const (
	healthLogNothing healthLogAction = iota
	// healthLogFirst is the first failure of an episode: the warning it has
	// always been, at once.
	healthLogFirst
	// healthLogSummary is the periodic summary of the failures since.
	healthLogSummary
)

// healthEpisode is one run of failed health checks of one coordinator.
type healthEpisode struct {
	since    time.Time // the first failure
	last     time.Time // the latest failure
	lastLine time.Time // the last line logged about it
	attempts int       // failures in the episode, the first included
	unlogged int       // failures since the last line
}

// healthFailureLog bounds the "Failed to check coordinator health" warnings
// (TXE-5406). The health check runs before every coordinator call, and a
// worker's pollers make many, so while a coordinator is unreachable the same
// warning used to be written several times a second. Now the first failure of
// an episode is logged as before, then at most one summary per interval while
// failures continue, and one line when a check passes again. It changes what
// is logged only: the checks, their timing and the client's connection state
// are as before.
//
// Every client New builds has one. A nil log is a fallback for a client
// assembled without New, in tests: it logs every failure, exactly as before
// TXE-5406, and keeps no state.
type healthFailureLog struct {
	mu        sync.Mutex
	now       func() time.Time
	interval  time.Duration
	expiry    time.Duration
	max       int
	lastSweep time.Time
	episodes  map[string]*healthEpisode
}

func newHealthFailureLog(now func() time.Time) *healthFailureLog {
	return &healthFailureLog{
		now: now, interval: healthSummaryInterval, expiry: healthEpisodeExpiry, max: healthEpisodesMax,
		episodes: make(map[string]*healthEpisode),
	}
}

// failed records a failed check of the coordinator key and says what to log,
// with the episode as it stands after this failure.
func (l *healthFailureLog) failed(key string) (healthLogAction, healthEpisode) {
	if l == nil {
		return healthLogFirst, healthEpisode{attempts: 1}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)
	ep, ok := l.episodes[key]
	if !ok {
		l.makeRoom()
		ep = &healthEpisode{since: now, last: now, lastLine: now, attempts: 1}
		l.episodes[key] = ep
		return healthLogFirst, *ep
	}
	ep.last = now
	ep.attempts++
	ep.unlogged++
	if now.Sub(ep.lastLine) < l.interval {
		return healthLogNothing, *ep
	}
	out := *ep
	ep.lastLine, ep.unlogged = now, 0
	return healthLogSummary, out
}

// passed records a passing check of the coordinator key. It returns the
// episode it ended, if one was open.
func (l *healthFailureLog) passed(key string) (healthEpisode, bool) {
	if l == nil {
		return healthEpisode{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ep, ok := l.episodes[key]
	if !ok {
		return healthEpisode{}, false
	}
	delete(l.episodes, key)
	return *ep, true
}

// sweep forgets the episodes not failed for longer than the expiry, at most
// once an interval, so a coordinator gone from the membership is not kept
// forever.
func (l *healthFailureLog) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < l.interval {
		return
	}
	l.lastSweep = now
	for key, ep := range l.episodes {
		if now.Sub(ep.last) > l.expiry {
			delete(l.episodes, key)
		}
	}
}

// makeRoom forgets the least recently failing episode when the log is full.
func (l *healthFailureLog) makeRoom() {
	if len(l.episodes) < l.max {
		return
	}
	var (
		oldest string
		at     time.Time
		found  bool
	)
	for key, ep := range l.episodes {
		if !found || ep.last.Before(at) {
			oldest, at, found = key, ep.last, true
		}
	}
	delete(l.episodes, oldest)
}

// size reports how many episodes are kept.
func (l *healthFailureLog) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.episodes)
}
