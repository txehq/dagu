// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"sync"
	"time"
)

// When a gate ends a healthy browser by time (TXE-6201).
//
// A browser with an admitted client is never ended by time: a step or a
// session connected for a week runs for a week, as it did before the gate.
// An admitted client is a DevTools websocket that passed the token and the
// Origin check, was accepted and is registered on the multiplexer; a wrong
// token, an unauthenticated socket, a handshake that failed and the /json
// reads are not attendance, and neither is a permanent helper of the hub's
// own that marks its handshake (HelperHeader), so a browser whose only
// client is such a helper is unattended; a helper's reconnects never touch
// the clock. The gate does not judge an admitted client that is idle or
// hung: an open authorized client keeps the browser attended, and the layer
// that owns sessions applies its own idle deadline by closing its client.
// Once the last admitted client has left, the unattended clock runs,
// and the browser is closed when it passes MaxUnattended. An explicit
// MaxLifetime is a hard cap on the whole run, attended or not.
//
// One clock decides both, on ticks under one lock with the client count, so
// a client that joins before a tick cancels the expiry and no timer armed
// earlier can end an attended browser.

// DefaultMaxUnattended is how long a gate stays with no admitted client
// before it closes the browser, when its configuration sets no other value.
const DefaultMaxUnattended = 24 * time.Hour

// attendanceInterval spaces the gate's checks of the lifetime policy.
const attendanceInterval = time.Second

// lifetimePolicy is a configuration's answer to when a browser ends by time.
type lifetimePolicy struct {
	// hardCap ends the run at that age whatever the clients; zero is none.
	hardCap time.Duration
	// unattended ends the run that long after the last admitted client left.
	unattended time.Duration
}

// lifetime resolves the configuration's lifetime fields, the one place the
// defaults are decided: a zero MaxUnattended is DefaultMaxUnattended, and a
// zero MaxLifetime is no hard cap. Negative values were refused by validate.
func (c Config) lifetime() lifetimePolicy {
	p := lifetimePolicy{hardCap: c.MaxLifetime, unattended: c.MaxUnattended}
	if p.unattended == 0 {
		p.unattended = DefaultMaxUnattended
	}
	return p
}

// clock is the gate's source of time, so tests can run a week in a moment.
type clock interface {
	Now() time.Time
	NewTicker(d time.Duration) ticker
}

// ticker is the part of time.Ticker the gate uses.
type ticker interface {
	C() <-chan time.Time
	Stop()
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) NewTicker(d time.Duration) ticker { return realTicker{time.NewTicker(d)} }

type realTicker struct{ *time.Ticker }

func (t realTicker) C() <-chan time.Time { return t.Ticker.C }

// keeper counts the admitted clients and decides, from the policy and the
// clock, when the browser ends by time.
type keeper struct {
	now    func() time.Time
	policy lifetimePolicy

	mu      sync.Mutex
	started time.Time
	clients int
	// lastLeft is when the count last reached zero: the start, until a
	// client has been admitted.
	lastLeft time.Time
}

func newKeeper(now func() time.Time, policy lifetimePolicy) *keeper {
	start := now()
	return &keeper{now: now, policy: policy, started: start, lastLeft: start}
}

// joined records an admitted client. The multiplexer calls it under its own
// lock, as it registers the client, so the count and the registration
// cannot disagree.
func (k *keeper) joined() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.clients++
}

// left records an admitted client that is gone, however it went: a close
// frame, a dead socket noticed on a failed read, or the gate closing. The
// unattended clock restarts when the last one leaves.
func (k *keeper) left() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.clients--
	if k.clients == 0 {
		k.lastLeft = k.now()
	}
}

// admitted returns the current count of admitted clients.
func (k *keeper) admitted() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.clients
}

// Reasons a browser is ended by time.
const (
	endedHardCap    = "the lifetime cap passed"
	endedUnattended = "no client was connected for the unattended cap"
)

// verdict says whether the browser ends now, and why. It reads the count and
// the clock under the keeper's lock, so a client admitted a moment ago is
// seen.
func (k *keeper) verdict() (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if k.policy.hardCap > 0 && now.Sub(k.started) >= k.policy.hardCap {
		return endedHardCap, true
	}
	if k.clients == 0 && now.Sub(k.lastLeft) >= k.policy.unattended {
		return endedUnattended, true
	}
	return "", false
}

// watch checks the verdict on every tick of clk until it says to end, and
// delivers the reason once; it returns when ctx ends. The ticker exists
// when watch returns, so a tick after that is never missed.
func (k *keeper) watch(ctx context.Context, clk clock) <-chan string {
	ended := make(chan string, 1)
	t := clk.NewTicker(attendanceInterval)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C():
			}
			if reason, end := k.verdict(); end {
				ended <- reason
				return
			}
		}
	}()
	return ended
}
