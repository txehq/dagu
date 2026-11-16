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
	// A block of three ports this test owns: found free now, then released.
	var block [3]int
	for {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		base := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		if base+2 > 65535 || base < 1024 {
			continue
		}
		ok := true
		for i := range block {
			l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(base+i)))
			if err != nil {
				ok = false
				break
			}
			_ = l.Close()
			block[i] = base + i
		}
		if ok {
			break
		}
	}
	ports.mu.Lock()
	savedLo, savedHi, savedNext := ports.lo, ports.hi, ports.next
	ports.lo, ports.hi, ports.next = block[0], block[2], block[0]
	ports.mu.Unlock()
	t.Cleanup(func() {
		ports.mu.Lock()
		ports.lo, ports.hi, ports.next = savedLo, savedHi, savedNext
		ports.mu.Unlock()
	})
	held := listenLoopback(t) // block[0], kept open
	defer func() { _ = held.Close() }()
	assert.Equal(t, block[0], held.Addr().(*net.TCPAddr).Port)
	var got []int
	for range 4 {
		ln := listenLoopback(t)
		got = append(got, ln.Addr().(*net.TCPAddr).Port)
		_ = ln.Close()
	}
	// block[0] is held: the walk goes 1, 2, then round past the held 0 to 1, 2.
	assert.Equal(t, []int{block[1], block[2], block[1], block[2]}, got)
}
