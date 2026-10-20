// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStopLocalAgentSessionCleanupHonorsShutdownContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- stopLocalAgentSessionCleanup(ctx, func() {}, done, nil)
	}()

	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(100 * time.Millisecond):
		close(done)
		<-result
		t.Fatal("agent session cleanup did not honor the shutdown context")
	}
}

// With machines pinned, the hub's own cleanup consumer takes over no
// machine's agent session cleanup; otherwise it takes over any host's.
func TestLocalCleanupTakeoverWithMachinesPinned(t *testing.T) {
	t.Parallel()
	assert.Nil(t, localCleanupTakeover(""))
	assert.Nil(t, localCleanupTakeover("off"))
	assert.Nil(t, localCleanupTakeover("observe"))
	mayTakeOver := localCleanupTakeover("enforce")
	require.NotNil(t, mayTakeOver)
	assert.False(t, mayTakeOver("mch_A@laptop"))
	assert.False(t, mayTakeOver("mch_A"))
	assert.True(t, mayTakeOver("worker-x"))
	assert.True(t, mayTakeOver("local"))
}
