// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package machineauth_test

import (
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The rig's port block is walked round: a port freed is handed out again, a
// port still held is skipped, and every port stays inside the block.
func TestPortBlockWrapsAndSkipsHeldPorts(t *testing.T) {
	lo, _, err := portBlock()
	require.NoError(t, err)
	if lo != 0 {
		t.Skip("DAGU_MACHINEAUTH_PORTS is set for this process; the walk is tested on a block of its own")
	}
	base := ownedBase(t)
	useBlock(t, base, base+2)
	held := listenLoopback(t) // base, kept open
	defer func() { _ = held.Close() }()
	assert.Equal(t, base, held.Addr().(*net.TCPAddr).Port)
	var got []int
	for range 4 {
		ln := listenLoopback(t)
		got = append(got, ln.Addr().(*net.TCPAddr).Port)
		_ = ln.Close()
	}
	// base is held: the walk goes base+1, base+2, then round past the held base.
	assert.Equal(t, []int{base + 1, base + 2, base + 1, base + 2}, got)
}

// With a block set, the allocator fails closed when every port of it is held:
// an error, and no listener outside the block.
func TestPortBlockExhaustedFailsClosed(t *testing.T) {
	lo, _, err := portBlock()
	require.NoError(t, err)
	if lo != 0 {
		t.Skip("DAGU_MACHINEAUTH_PORTS is set for this process; the walk is tested on a block of its own")
	}
	base := ownedBase(t)
	useBlock(t, base, base+1)
	a := listenLoopback(t)
	defer func() { _ = a.Close() }()
	b := listenLoopback(t)
	defer func() { _ = b.Close() }()
	for _, ln := range []net.Listener{a, b} {
		port := ln.Addr().(*net.TCPAddr).Port
		assert.True(t, port == base || port == base+1, "port %d outside the block", port)
	}
	ln, err := allocLoopback()
	if ln != nil {
		_ = ln.Close()
	}
	require.Error(t, err, "an exhausted block must not hand out a port")
	assert.Nil(t, ln, "no listener outside the block")
	assert.Contains(t, err.Error(), "does not listen outside its block")
	// Released, a port of the block is handed out again.
	_ = b.Close()
	again, err := allocLoopback()
	require.NoError(t, err)
	defer func() { _ = again.Close() }()
	assert.Equal(t, base+1, again.Addr().(*net.TCPAddr).Port)
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

// ownedBase finds three consecutive loopback ports free now and returns the
// first: a block a test can point the allocator at.
func ownedBase(t *testing.T) int {
	t.Helper()
	for range 100 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		base := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		if base < 1024 || base+2 > 65535 {
			continue
		}
		ok := true
		for i := range 3 {
			l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(base+i)))
			if err != nil {
				ok = false
				break
			}
			_ = l.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no three consecutive free loopback ports")
	return 0
}

// useBlock points the allocator at [lo, hi] for this test.
func useBlock(t *testing.T, lo, hi int) {
	t.Helper()
	ports.mu.Lock()
	savedLo, savedHi, savedNext := ports.lo, ports.hi, ports.next
	ports.lo, ports.hi, ports.next = lo, hi, lo
	ports.mu.Unlock()
	t.Cleanup(func() {
		ports.mu.Lock()
		ports.lo, ports.hi, ports.next = savedLo, savedHi, savedNext
		ports.mu.Unlock()
	})
}
