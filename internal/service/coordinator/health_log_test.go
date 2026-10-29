// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stepClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TXE-5406: the first failure of an episode is logged at once, then at most
// one summary per interval with what it counted, and a passing check ends the
// episode with its counts. Each coordinator has its own episode.
func TestHealthFailureLogSummarisesAnEpisode(t *testing.T) {
	t0 := time.Date(2026, 10, 30, 2, 0, 0, 0, time.UTC)
	clock := &stepClock{now: t0}
	l := newHealthFailureLog(clock.Now)

	action, ep := l.failed("a")
	require.Equal(t, healthLogFirst, action)
	assert.Equal(t, healthEpisode{since: t0, last: t0, lastLine: t0, attempts: 1}, ep)

	for range 9 {
		clock.Advance(6 * time.Second) // up to 54 s: inside the interval
		action, _ = l.failed("a")
		require.Equal(t, healthLogNothing, action)
	}
	clock.Advance(5999 * time.Millisecond) // 59.999 s
	action, _ = l.failed("a")
	require.Equal(t, healthLogNothing, action, "a summary before a full interval")
	clock.Advance(time.Millisecond) // 60 s
	action, ep = l.failed("a")
	require.Equal(t, healthLogSummary, action)
	assert.Equal(t, 12, ep.attempts)
	assert.Equal(t, 11, ep.unlogged, "the failures since the first line, this one included")
	assert.Equal(t, t0, ep.since)

	// Another coordinator's failures are an episode of their own.
	action, _ = l.failed("b")
	assert.Equal(t, healthLogFirst, action)

	clock.Advance(time.Second)
	action, _ = l.failed("a")
	require.Equal(t, healthLogNothing, action, "the interval runs from the last summary")
	clock.Advance(59 * time.Second)
	action, ep = l.failed("a")
	require.Equal(t, healthLogSummary, action)
	assert.Equal(t, 14, ep.attempts)
	assert.Equal(t, 2, ep.unlogged)

	clock.Advance(time.Second)
	action, _ = l.failed("a")
	require.Equal(t, healthLogNothing, action)
	ended, ok := l.passed("a")
	require.True(t, ok)
	assert.Equal(t, 15, ended.attempts)
	assert.Equal(t, 1, ended.unlogged, "the failure no line reported")
	assert.Equal(t, t0, ended.since)

	_, ok = l.passed("a")
	assert.False(t, ok, "a passing check with no episode open ends nothing")
	action, ep = l.failed("a")
	assert.Equal(t, healthLogFirst, action, "a failure after a pass starts a new episode")
	assert.Equal(t, 1, ep.attempts)

	_, ok = l.passed("b")
	assert.True(t, ok, "b's episode was still open")
}

// A nil log logs every failure, as the client did before.
func TestHealthFailureLogNilLogsEveryFailure(t *testing.T) {
	var l *healthFailureLog
	for range 3 {
		action, _ := l.failed("a")
		assert.Equal(t, healthLogFirst, action)
	}
	_, ok := l.passed("a")
	assert.False(t, ok)
}

// The worker's pollers check health concurrently: an episode gets exactly one
// first line and every failure is counted.
func TestHealthFailureLogIsSafeUnderConcurrentFailures(t *testing.T) {
	clock := &stepClock{now: time.Date(2026, 10, 30, 2, 0, 0, 0, time.UTC)}
	l := newHealthFailureLog(clock.Now)
	const goroutines, each = 64, 50
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		counts = map[healthLogAction]int{}
	)
	for range goroutines {
		wg.Go(func() {
			for range each {
				action, _ := l.failed("a")
				mu.Lock()
				counts[action]++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	assert.Equal(t, 1, counts[healthLogFirst])
	assert.Equal(t, 0, counts[healthLogSummary], "no time passed")
	assert.Equal(t, goroutines*each-1, counts[healthLogNothing])

	clock.Advance(time.Minute)
	action, ep := l.failed("a")
	require.Equal(t, healthLogSummary, action)
	assert.Equal(t, goroutines*each+1, ep.attempts)
	assert.Equal(t, goroutines*each, ep.unlogged)
}

// Episodes are not kept forever: a coordinator not checked for longer than the
// expiry, as one gone from the membership, is forgotten, and the number kept
// is capped, forgetting the least recently failing one first.
func TestHealthFailureLogForgetsStaleEpisodes(t *testing.T) {
	clock := &stepClock{now: time.Date(2026, 10, 30, 2, 0, 0, 0, time.UTC)}
	l := newHealthFailureLog(clock.Now)

	l.failed("gone")
	l.failed("live")
	require.Equal(t, 2, l.size())
	for range 11 { // "live" keeps failing for 11 minutes; "gone" is never checked again
		clock.Advance(time.Minute)
		l.failed("live")
	}
	assert.Equal(t, 1, l.size(), "the departed coordinator's episode is forgotten")
	_, kept := l.passed("gone")
	assert.False(t, kept)
	action, _ := l.failed("live")
	assert.Equal(t, healthLogNothing, action, "a coordinator still failing keeps its episode")

	capped := newHealthFailureLog(clock.Now)
	for i := range healthEpisodesMax + 10 {
		clock.Advance(time.Millisecond)
		capped.failed(fmt.Sprintf("coord-%d", i))
	}
	assert.Equal(t, healthEpisodesMax, capped.size())
	_, kept = capped.passed("coord-0")
	assert.False(t, kept, "the least recently failing episode went first")
	_, kept = capped.passed(fmt.Sprintf("coord-%d", healthEpisodesMax+9))
	assert.True(t, kept)
}

// Every client New builds bounds its warnings; nil is only a fallback.
func TestNewClientHasAHealthFailureLog(t *testing.T) {
	cli := New(stubServiceRegistry{}, DefaultConfig()).(*clientImpl)
	require.NotNil(t, cli.healthLog)
	assert.Equal(t, healthSummaryInterval, cli.healthLog.interval)
}
