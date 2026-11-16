// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package machineauth_test

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePorts stands in for the host's loopback ports: a port is bindable
// unless held. The allocator's tests use it instead of real ports, which
// another process could take between a test's probe and its bind.
type fakePorts struct {
	mu   sync.Mutex
	held map[int]bool
	// tried records every port the allocator asked for, in order.
	tried []int
}

type fakeListener struct {
	f    *fakePorts
	port int
}

func (l *fakeListener) Accept() (net.Conn, error) { return nil, errors.New("fake listener") }
func (l *fakeListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: l.port} }
func (l *fakeListener) Close() error {
	l.f.mu.Lock()
	defer l.f.mu.Unlock()
	delete(l.f.held, l.port)
	return nil
}

func (f *fakePorts) listen(port int) (net.Listener, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tried = append(f.tried, port)
	if f.held[port] {
		return nil, errors.New("address already in use")
	}
	f.held[port] = true
	return &fakeListener{f: f, port: port}, nil
}

// useFakeBlock points the allocator at [lo, hi] over fake ports for this test.
func useFakeBlock(t *testing.T, lo, hi int) *fakePorts {
	t.Helper()
	_, _, err := portBlock()
	require.NoError(t, err)
	f := &fakePorts{held: map[int]bool{}}
	ports.mu.Lock()
	saved := struct {
		lo, hi, next int
		listen       func(int) (net.Listener, error)
	}{ports.lo, ports.hi, ports.next, ports.listen}
	ports.lo, ports.hi, ports.next, ports.listen = lo, hi, lo, f.listen
	ports.mu.Unlock()
	t.Cleanup(func() {
		ports.mu.Lock()
		ports.lo, ports.hi, ports.next, ports.listen = saved.lo, saved.hi, saved.next, saved.listen
		ports.mu.Unlock()
	})
	return f
}

func portOf(ln net.Listener) int { return ln.Addr().(*net.TCPAddr).Port }

// The rig's port block is walked round: a port freed is handed out again, a
// port still held is skipped, and every port stays inside the block.
func TestPortBlockWrapsAndSkipsHeldPorts(t *testing.T) {
	f := useFakeBlock(t, 29260, 29262)
	held := listenLoopback(t)
	assert.Equal(t, 29260, portOf(held))
	var got []int
	for range 4 {
		ln := listenLoopback(t)
		got = append(got, portOf(ln))
		require.NoError(t, ln.Close())
	}
	// 29260 is held: the walk goes 61, 62, then round past the held 60 to 61, 62.
	assert.Equal(t, []int{29261, 29262, 29261, 29262}, got)
	for _, p := range f.tried {
		assert.True(t, p >= 29260 && p <= 29262, "asked for port %d outside the block", p)
	}
}

// With a block set, the allocator fails closed when every port of it is held:
// an error, and no listener outside the block.
func TestPortBlockExhaustedFailsClosed(t *testing.T) {
	f := useFakeBlock(t, 29260, 29261)
	a := listenLoopback(t)
	b := listenLoopback(t)
	assert.ElementsMatch(t, []int{29260, 29261}, []int{portOf(a), portOf(b)})
	ln, err := allocLoopback()
	require.Error(t, err, "an exhausted block must not hand out a port")
	assert.Nil(t, ln, "no listener outside the block")
	assert.Contains(t, err.Error(), "does not listen outside its block")
	for _, p := range f.tried {
		assert.True(t, p == 29260 || p == 29261, "asked for port %d outside the block", p)
	}
	// Released, a port of the block is handed out again.
	require.NoError(t, b.Close())
	again, err := allocLoopback()
	require.NoError(t, err)
	assert.Equal(t, portOf(b), portOf(again))
}

// The real binder is the default: with no fake, a port of the block is a real
// loopback listener.
func TestPortBlockBindsRealPortsByDefault(t *testing.T) {
	_, _, err := portBlock()
	require.NoError(t, err)
	ports.mu.Lock()
	saved := struct {
		lo, hi, next int
		listen       func(int) (net.Listener, error)
	}{ports.lo, ports.hi, ports.next, ports.listen}
	ports.mu.Unlock()
	t.Cleanup(func() {
		ports.mu.Lock()
		ports.lo, ports.hi, ports.next, ports.listen = saved.lo, saved.hi, saved.next, saved.listen
		ports.mu.Unlock()
	})
	// A block of one real port, bound by this test first so it is known to be
	// this process's; released, the allocator binds that same port.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := portOf(probe)
	ports.mu.Lock()
	ports.lo, ports.hi, ports.next, ports.listen = port, port, port, nil
	ports.mu.Unlock()
	_, err = allocLoopback()
	require.Error(t, err, "the one port is held by this test: the block is exhausted")
	require.NoError(t, probe.Close())
	ln, err := allocLoopback()
	if err != nil {
		t.Skipf("another process took port %d between release and bind: %v", port, err)
	}
	defer func() { _ = ln.Close() }()
	assert.Equal(t, port, portOf(ln))
	_, isTCP := ln.(*net.TCPListener)
	assert.True(t, isTCP, "a real listener")
}

func TestParsePortBlock(t *testing.T) {
	t.Parallel()
	lo, hi, err := parsePortBlock("29260-29319")
	require.NoError(t, err)
	assert.Equal(t, [2]int{29260, 29319}, [2]int{lo, hi})
	for _, bad := range []string{"", "29260", "29319-29260", "80-90", "29260-70000", "29260-29319x", "a-b", "29260 - 29319"} {
		_, _, err := parsePortBlock(bad)
		assert.Error(t, err, "%q", bad)
	}
}
