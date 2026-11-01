// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type plainFinalizer struct{}

func (plainFinalizer) Finalize(context.Context, string, string) error { return nil }

type boundedFinalizer struct {
	plainFinalizer
	bounds bool
}

func (f boundedFinalizer) BoundsItsOwnFinalize() bool { return f.bounds }

func shortenFinalize(t *testing.T, d time.Duration) {
	t.Helper()
	before := artifactFinalizeTimeout
	artifactFinalizeTimeout = d
	t.Cleanup(func() { artifactFinalizeTimeout = before })
}

// Any finalizer that does not bound itself keeps the fixed time, an uploader
// with no segments among them.
func TestAFinalizerThatDoesNotBoundItselfKeepsTheFixedTime(t *testing.T) {
	for name, finalizer := range map[string]ArtifactFinalizer{"plain": plainFinalizer{}, "no segments": boundedFinalizer{bounds: false}} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := artifactFinalizeContext(context.Background(), finalizer)
			defer cancel()
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			assert.WithinDuration(t, time.Now().Add(artifactFinalizeTimeout), deadline, time.Second)
		})
	}
}

func TestASelfBoundedFinalizerHasNoFixedTime(t *testing.T) {
	ctx, cancel := artifactFinalizeContext(context.Background(), boundedFinalizer{bounds: true})
	defer cancel()
	_, ok := ctx.Deadline()
	assert.False(t, ok)
	assert.NoError(t, ctx.Err())
}

// A run that ended leaves the upload the fixed time and no more.
func TestARunThatEndsDuringFinalizeBoundsIt(t *testing.T) {
	shortenFinalize(t, 150*time.Millisecond)
	run, stop := context.WithCancel(context.Background())
	ctx, cancel := artifactFinalizeContext(run, boundedFinalizer{bounds: true})
	defer cancel()

	time.Sleep(50 * time.Millisecond)
	stopped := time.Now()
	stop()
	assert.NoError(t, ctx.Err(), "a stopped run's results still get their time")
	select {
	case <-ctx.Done():
		assert.GreaterOrEqual(t, time.Since(stopped), 140*time.Millisecond)
	case <-time.After(5 * time.Second):
		t.Fatal("the bound did not hold")
	}
}

func TestARunAlreadyOverWhenFinalizeStartsIsBounded(t *testing.T) {
	shortenFinalize(t, 100*time.Millisecond)
	run, stop := context.WithCancel(context.Background())
	stop()
	ctx, cancel := artifactFinalizeContext(run, boundedFinalizer{bounds: true})
	defer cancel()
	assert.NoError(t, ctx.Err())
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the bound did not hold")
	}
}

func TestATimedOutRunBoundsFinalizeToo(t *testing.T) {
	shortenFinalize(t, 100*time.Millisecond)
	run, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	ctx, cancel := artifactFinalizeContext(run, boundedFinalizer{bounds: true})
	defer cancel()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the bound did not hold")
	}
}
