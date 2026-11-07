// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is a clock a test moves by hand. Advancing it fires every
// ticker it made once, so a tick observes the new time.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	tickers []*fakeTicker
}

type fakeTicker struct {
	c chan time.Time
}

func (t *fakeTicker) C() <-chan time.Time { return t.c }
func (t *fakeTicker) Stop()               {}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) NewTicker(time.Duration) ticker {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTicker{c: make(chan time.Time, 1)}
	f.tickers = append(f.tickers, t)
	return t
}

// Advance moves the clock and ticks every ticker once.
func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	now := f.now
	tickers := append([]*fakeTicker(nil), f.tickers...)
	f.mu.Unlock()
	for _, t := range tickers {
		select {
		case t.c <- now:
		default:
		}
	}
}

// The policy on a fake clock: a browser with an admitted client is never
// ended by time, however long; the unattended cap runs from the last
// client's leaving; an explicit hard cap ends an attended browser too.
func TestKeeperDecidesByAttendanceAndCaps(t *testing.T) {
	t.Parallel()
	ends := func(k *keeper) string {
		reason, end := k.verdict()
		if !end {
			return ""
		}
		return reason
	}

	t.Run("a connected client for a week, then the unattended cap from its leaving", func(t *testing.T) {
		t.Parallel()
		clk := newFakeClock()
		k := newKeeper(clk.Now, Config{}.lifetime())
		clk.Advance(DefaultMaxUnattended - time.Second)
		assert.Empty(t, ends(k), "just under the cap, unattended")
		k.joined()
		clk.Advance(7 * 24 * time.Hour)
		assert.Empty(t, ends(k), "a week with a client connected")
		k.left()
		clk.Advance(DefaultMaxUnattended - time.Second)
		assert.Empty(t, ends(k), "the clock restarted when the client left")
		clk.Advance(time.Second)
		assert.Equal(t, endedUnattended, ends(k))
	})

	t.Run("never admitted a client", func(t *testing.T) {
		t.Parallel()
		clk := newFakeClock()
		k := newKeeper(clk.Now, Config{MaxUnattended: 10 * time.Minute}.lifetime())
		clk.Advance(10*time.Minute - time.Millisecond)
		assert.Empty(t, ends(k))
		clk.Advance(time.Millisecond)
		assert.Equal(t, endedUnattended, ends(k))
	})

	t.Run("zero and one, several times", func(t *testing.T) {
		t.Parallel()
		clk := newFakeClock()
		k := newKeeper(clk.Now, Config{MaxUnattended: time.Hour}.lifetime())
		for range 3 {
			clk.Advance(50 * time.Minute)
			k.joined()
			clk.Advance(2 * time.Hour)
			assert.Empty(t, ends(k), "attended")
			k.left()
			assert.Empty(t, ends(k), "the cap runs from now")
		}
		clk.Advance(time.Hour)
		assert.Equal(t, endedUnattended, ends(k))
	})

	t.Run("several clients: attended until the last leaves", func(t *testing.T) {
		t.Parallel()
		clk := newFakeClock()
		k := newKeeper(clk.Now, Config{MaxUnattended: time.Hour}.lifetime())
		k.joined()
		k.joined()
		k.joined()
		clk.Advance(3 * time.Hour)
		k.left()
		clk.Advance(3 * time.Hour)
		k.left()
		assert.Equal(t, 1, k.admitted())
		clk.Advance(3 * time.Hour)
		assert.Empty(t, ends(k), "one client still connected")
		k.left()
		clk.Advance(time.Hour - time.Second)
		assert.Empty(t, ends(k))
		clk.Advance(time.Second)
		assert.Equal(t, endedUnattended, ends(k))
	})

	t.Run("an explicit hard cap ends an attended browser", func(t *testing.T) {
		t.Parallel()
		clk := newFakeClock()
		k := newKeeper(clk.Now, Config{MaxLifetime: time.Hour, MaxUnattended: 10 * time.Hour}.lifetime())
		k.joined()
		clk.Advance(time.Hour - time.Second)
		assert.Empty(t, ends(k))
		clk.Advance(time.Second)
		assert.Equal(t, endedHardCap, ends(k))
	})

	t.Run("the hard cap wins over a shorter unattended wait", func(t *testing.T) {
		t.Parallel()
		clk := newFakeClock()
		k := newKeeper(clk.Now, Config{MaxLifetime: time.Minute, MaxUnattended: time.Hour}.lifetime())
		clk.Advance(time.Minute)
		assert.Equal(t, endedHardCap, ends(k))
	})

	t.Run("no hard cap by default", func(t *testing.T) {
		t.Parallel()
		clk := newFakeClock()
		k := newKeeper(clk.Now, Config{}.lifetime())
		k.joined()
		clk.Advance(400 * 24 * time.Hour)
		assert.Empty(t, ends(k), "a year with a client: no cap")
	})
}

// A client that joins before the tick cancels the expiry: the count and the
// clock are read together, so no verdict rests on a stale timer.
func TestKeeperJoinBeforeTheTickCancelsTheExpiry(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	k := newKeeper(clk.Now, Config{MaxUnattended: time.Hour}.lifetime())
	ctx := t.Context()
	ended := k.watch(ctx, clk)
	// The cap passes on the clock, and a client joins before the tick.
	clk.mu.Lock()
	clk.now = clk.now.Add(2 * time.Hour)
	clk.mu.Unlock()
	k.joined()
	clk.Advance(0)
	select {
	case reason := <-ended:
		t.Fatalf("an attended browser was ended: %s", reason)
	case <-time.After(200 * time.Millisecond):
	}
	// It leaves, the cap passes again, the tick ends the browser once.
	k.left()
	clk.Advance(time.Hour)
	select {
	case reason := <-ended:
		assert.Equal(t, endedUnattended, reason)
	case <-time.After(5 * time.Second):
		t.Fatal("the tick after the cap did not end the browser")
	}
}

// What counts as an admitted client, through the real gate over the
// in-process fake browser: a websocket that passed the token and Origin
// checks and is registered on the multiplexer, on the browser or a page
// endpoint. A wrong token, a web page's Origin, a target that does not exist
// and the /json reads are not attendance. A client gone without a close
// frame is counted gone once the multiplexer drops it.
func TestGateCountsAdmittedClientsOnly(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	clk := newFakeClock()
	k := newKeeper(clk.Now, Config{}.lifetime())
	tg.mux.mu.Lock()
	tg.mux.attendance = k
	tg.mux.mu.Unlock()
	count := func() int { return k.admitted() }
	settled := func(want int, what string) {
		t.Helper()
		eventually(t, 10*time.Second, func() bool { return count() == want }, fmt.Sprintf("%s: %d admitted clients", what, want))
	}

	host := fmt.Sprintf("127.0.0.1:%d", tg.gate.port())
	dialFails := func(url string, header http.Header) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, response, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if conn != nil {
			_ = conn.CloseNow()
		}
		require.Error(t, err)
	}
	// Not attendance.
	dialFails("ws://"+host+"/"+NewToken()+"/devtools/browser/"+tg.gate.browserID, nil)
	dialFails("ws://"+host+"/devtools/browser/"+tg.gate.browserID, nil)
	dialFails(tg.wsURL(""), http.Header{"Origin": []string{"https://evil.example"}})
	// A page endpoint of a target that does not exist completes the
	// handshake, is closed by the gate before registration, and never
	// counts.
	noTarget, noTargetResponse, err := websocket.Dial(context.Background(), tg.wsURL("no-such-target"), nil)
	if noTargetResponse != nil && noTargetResponse.Body != nil {
		_ = noTargetResponse.Body.Close()
	}
	require.NoError(t, err)
	_, _, err = noTarget.Read(context.Background())
	require.Error(t, err, "the gate closes a client of an unknown target")
	get(t, tg.baseURL()+"/json/version")
	get(t, tg.baseURL()+"/json/list")
	assert.Equal(t, 0, count(), "refusals and reads are not attendance")

	// Admitted: a browser client and a page client.
	browserClient := tg.dial("")
	settled(1, "a browser client")
	var created struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(browserClient.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"}), &created))
	pageClient := tg.dial(created.TargetID)
	settled(2, "a page client")

	// One leaves with a close frame; the other dies without one.
	pageClient.close()
	settled(1, "the page client left")
	_ = browserClient.conn.CloseNow()
	settled(0, "the browser client's socket died")

	// Simultaneous joins and leaves agree with the registrations.
	var wg sync.WaitGroup
	clients := make([]*cdpConn, 8)
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			clients[i] = tg.dial("")
		}(i)
	}
	wg.Wait()
	settled(len(clients), "eight clients at once")
	for _, c := range clients {
		wg.Add(1)
		go func(c *cdpConn) {
			defer wg.Done()
			c.close()
		}(c)
	}
	wg.Wait()
	settled(0, "eight clients gone at once")
	assert.Equal(t, 0, count())
}

// A permanent helper (HelperHeader) is admitted like any client and is left
// out of attendance: a browser whose only client is a helper is unattended;
// a runtime client beside it attends, and its leaving starts the clock while
// the helper stays; a helper's reconnect is no keep-alive. The marker is read
// after the token: a spoofed helper without the token is refused and changes
// no counter, and a marker with another value refuses the handshake.
func TestGateHelperClientsAreNotAttendance(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	clk := newFakeClock()
	k := newKeeper(clk.Now, Config{MaxUnattended: time.Hour}.lifetime())
	tg.mux.mu.Lock()
	tg.mux.attendance = k
	tg.mux.mu.Unlock()
	lastLeft := func() time.Time {
		k.mu.Lock()
		defer k.mu.Unlock()
		return k.lastLeft
	}
	settled := func(want int, what string) {
		t.Helper()
		eventually(t, 10*time.Second, func() bool { return k.admitted() == want }, fmt.Sprintf("%s: %d admitted clients", what, want))
	}
	// dial returns the handshake's status with the body closed, and the
	// connection when one was made.
	dial := func(url string, header http.Header) (*websocket.Conn, int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, response, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
		status := 0
		if response != nil {
			status = response.StatusCode
			if response.Body != nil {
				_ = response.Body.Close()
			}
		}
		return conn, status, err
	}
	start := lastLeft()

	// A spoofed helper without the token: refused as anything else is.
	host := fmt.Sprintf("127.0.0.1:%d", tg.gate.port())
	conn, status, err := dial("ws://"+host+"/"+NewToken()+"/devtools/browser/"+tg.gate.browserID, HelperHandshake())
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Nil(t, conn)
	// The token with a marker of another value: refused, fail closed.
	conn, status, err = dial(tg.wsURL(""), http.Header{HelperHeader: []string{"yes"}})
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Nil(t, conn)
	conn, status, err = dial(tg.wsURL(""), http.Header{HelperHeader: []string{HelperValue, HelperValue}})
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Nil(t, conn)
	assert.Equal(t, 0, k.admitted())
	assert.Equal(t, start, lastLeft(), "refusals touch no counter")

	// The helper alone: admitted, answered, and not attendance.
	helper := dialWS(t, tg.wsURL(""), HelperHandshake())
	helper.mustCall("", "Browser.getVersion", nil)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, k.admitted(), "a helper is not attendance")
	clk.Advance(time.Hour)
	reason, end := k.verdict()
	assert.True(t, end, "a browser whose only client is a helper is unattended")
	assert.Equal(t, endedUnattended, reason)

	// A runtime client beside the helper attends; a week passes.
	runtime := tg.dial("")
	settled(1, "a runtime client beside the helper")
	clk.Advance(7 * 24 * time.Hour)
	_, end = k.verdict()
	assert.False(t, end, "attended for a week while the helper stays")

	// The runtime client leaves while the helper stays: the clock starts now.
	runtime.close()
	settled(0, "the runtime client left")
	left := lastLeft()
	assert.Equal(t, clk.Now(), left, "the unattended clock restarted at the runtime client's leaving")
	clk.Advance(30 * time.Minute)
	_, end = k.verdict()
	assert.False(t, end)

	// The helper reconnects: no keep-alive, the clock is untouched.
	helper.close()
	time.Sleep(50 * time.Millisecond)
	helper = dialWS(t, tg.wsURL(""), HelperHandshake())
	helper.mustCall("", "Browser.getVersion", nil)
	assert.Equal(t, 0, k.admitted())
	assert.Equal(t, left, lastLeft(), "a helper's reconnect does not reset the unattended clock")
	clk.Advance(30 * time.Minute)
	reason, end = k.verdict()
	assert.True(t, end)
	assert.Equal(t, endedUnattended, reason)

	// A regular client's connect and leave restart it, consistently.
	runtime = tg.dial("")
	settled(1, "a regular client again")
	runtime.close()
	settled(0, "and gone")
	assert.Equal(t, clk.Now(), lastLeft())
	_, end = k.verdict()
	assert.False(t, end, "the clock restarted")
}
