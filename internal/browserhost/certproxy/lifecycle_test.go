// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package certproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/browserhost"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPollInterval = 20 * time.Millisecond

// scriptedBrowser answers the watch's probes from what a test set, so the
// watch is tested on its own terms: no socket and no clock but the poll
// interval. The probes over a real address are browserhost.BrowserID's, and
// what it makes of a fake browser's answers is checked once each below.
type scriptedBrowser struct {
	mu     sync.Mutex
	id     string
	err    error
	probes int
}

func (b *scriptedBrowser) probe(context.Context, string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probes++
	return b.id, b.err
}

// answer sets what the next probes get.
func (b *scriptedBrowser) answer(id string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.id, b.err = id, err
}

func (b *scriptedBrowser) probed() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.probes
}

// errGone is what a probe returns when no browser answers at the address:
// a refused connection, or a server that is not a browser.
var errGone = errors.New("browser DevTools endpoint returned 404 Not Found")

// errBusy is what a probe returns when the browser did not answer in time.
var errBusy = context.DeadlineExceeded

// watch runs watchBrowser on the scripted browser and returns a channel
// closed when it returns.
func watch(t *testing.T, browser *scriptedBrowser, grace time.Duration) <-chan struct{} {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchBrowser(ctx, "http://127.0.0.1:1/TESTGATETOKEN000000000000A", grace, testPollInterval, browser.probe)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return done
}

// assertRunning checks that the watch goes on probing for a while without
// ending.
func assertRunning(t *testing.T, browser *scriptedBrowser, done <-chan struct{}) {
	t.Helper()
	before := browser.probed()
	select {
	case <-done:
		t.Fatal("the watch ended while the browser was running")
	case <-time.After(10 * testPollInterval):
	}
	assert.Greater(t, browser.probed(), before, "the watch keeps probing")
}

func assertEnds(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not end")
	}
}

func TestWatchBrowser(t *testing.T) {
	t.Parallel()

	t.Run("EndsWhenBrowserStops", func(t *testing.T) {
		t.Parallel()
		browser := &scriptedBrowser{id: "first"}
		done := watch(t, browser, time.Minute)
		assertRunning(t, browser, done)
		browser.answer("", browserhost.ErrUnreachable)
		assertEnds(t, done)
	})

	t.Run("EndsWhenAnotherBrowserAnswers", func(t *testing.T) {
		t.Parallel()
		browser := &scriptedBrowser{id: "first"}
		done := watch(t, browser, time.Minute)
		assertRunning(t, browser, done)
		browser.answer("second", nil)
		assertEnds(t, done)
	})

	// Another server can take the port of a browser that closed.
	t.Run("EndsWhenSomethingElseAnswers", func(t *testing.T) {
		t.Parallel()
		browser := &scriptedBrowser{id: "first"}
		done := watch(t, browser, time.Minute)
		assertRunning(t, browser, done)
		browser.answer("", errGone)
		assertEnds(t, done)
	})

	// A browser slow to answer is running; the watch waits for it, however
	// many probes run out of time, and ends when an answer says it is gone.
	t.Run("WaitsForABusyBrowser", func(t *testing.T) {
		t.Parallel()
		browser := &scriptedBrowser{id: "first"}
		done := watch(t, browser, time.Minute)
		assertRunning(t, browser, done)
		browser.answer("", errBusy)
		assertRunning(t, browser, done)
		browser.answer("", &net.OpError{Op: "dial", Err: timeoutError{}})
		assertRunning(t, browser, done)
		browser.answer("", errGone)
		assertEnds(t, done)
	})

	t.Run("EndsWhenNoBrowserAnswersInTime", func(t *testing.T) {
		t.Parallel()
		const grace = 300 * time.Millisecond
		browser := &scriptedBrowser{err: browserhost.ErrUnreachable}
		began := time.Now()
		done := watch(t, browser, grace)
		assertEnds(t, done)
		assert.GreaterOrEqual(t, time.Since(began), grace, "a browser not yet started has the grace period to answer")
	})

	// A browser that answers within grace is pinned, however late.
	t.Run("PinsABrowserThatAnswersWithinGrace", func(t *testing.T) {
		t.Parallel()
		browser := &scriptedBrowser{err: browserhost.ErrUnreachable}
		done := watch(t, browser, time.Minute)
		assertRunning(t, browser, done)
		browser.answer("first", nil)
		assertRunning(t, browser, done)
		browser.answer("second", nil)
		assertEnds(t, done)
	})

	t.Run("EndsWithContext", func(t *testing.T) {
		t.Parallel()
		browser := &scriptedBrowser{id: "first"}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			watchBrowser(ctx, "http://127.0.0.1:1/TESTGATETOKEN000000000000A", time.Minute, testPollInterval, browser.probe)
		}()
		assertRunning(t, browser, done)
		cancel()
		assertEnds(t, done)
	})
}

// The probe the proxy watches with, over a browser's real address, tells
// the watch what it needs: the browser's identity while it answers, an
// error that is no timeout once something else answers there or nothing
// does. One probe each; a probe that ran out of time says so.
func TestBrowserIDTellsTheWatchWhatItNeeds(t *testing.T) {
	t.Parallel()
	browser := newFakeBrowser(t)
	ctx := context.Background()

	began := time.Now()
	id, err := browserhost.BrowserID(ctx, browser.url())
	require.NoError(t, err, "a running browser answers (after %s)", time.Since(began))
	assert.Contains(t, id, browser.id.Load().(string), "the identity is the browser's own")

	browser.replaced.Store(true)
	began = time.Now()
	_, err = browserhost.BrowserID(ctx, browser.url())
	require.Error(t, err, "something else answering is an error")
	assert.False(t, timedOut(err), "something else answering is no timeout (after %s): %v", time.Since(began), err)

	browser.server.Close()
	began = time.Now()
	_, err = browserhost.BrowserID(ctx, browser.url())
	require.Error(t, err, "nothing answering is an error")
	assert.ErrorIs(t, err, browserhost.ErrUnreachable)
	assert.False(t, timedOut(err), "nothing answering is no timeout (after %s): %v", time.Since(began), err)
}

// A check that runs out of time is a busy browser, not a gone one.
func TestTimedOut(t *testing.T) {
	t.Parallel()

	assert.True(t, timedOut(context.DeadlineExceeded))
	assert.True(t, timedOut(&net.OpError{Op: "dial", Err: timeoutError{}}))
	assert.False(t, timedOut(errors.New("browser DevTools endpoint returned 404 Not Found")))
	assert.False(t, timedOut(browserhost.ErrUnreachable))
}

// timeoutError is a network error that ran out of time.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
