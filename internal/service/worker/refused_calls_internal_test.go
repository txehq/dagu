// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/serviceregistry"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// runHeartbeatClient answers RunHeartbeatTo with whatever error the test
// sets, nil meaning accepted. While block is set, a call signals entered and
// waits for block to be closed or for its context to end.
type runHeartbeatClient struct {
	coordinator.Client
	mu      sync.Mutex
	err     error
	block   chan struct{}
	entered chan struct{}
}

func (c *runHeartbeatClient) set(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func (c *runHeartbeatClient) RunHeartbeatTo(ctx context.Context, _ serviceregistry.HostInfo, _ *coordinatorv1.RunHeartbeatRequest) (*coordinatorv1.RunHeartbeatResponse, error) {
	c.mu.Lock()
	block, err := c.block, c.err
	c.mu.Unlock()
	if block != nil {
		select {
		case c.entered <- struct{}{}:
		default:
		}
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return &coordinatorv1.RunHeartbeatResponse{}, nil
}

// refusalHarness is a worker with one running task, driven tick by tick on a
// hand-moved clock, as sendRunHeartbeats and enforceRefusalDeadlines drive it
// once a second.
type refusalHarness struct {
	t         *testing.T
	worker    *Worker
	client    *runHeartbeatClient
	mu        sync.Mutex
	now       time.Time
	start     time.Time
	cancelled time.Duration // elapsed when the task's context was cancelled, or -1
	// refusedAtCancel is the task's firstRefusedAt at the instant it was
	// cancelled, read while the canceller holds pollersMu.
	refusedAtCancel time.Time
}

func (h *refusalHarness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *refusalHarness) advance(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = h.now.Add(d)
}

func (h *refusalHarness) elapsed() time.Duration { return h.clock().Sub(h.start) }

func (h *refusalHarness) cancelledAt() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cancelled
}

func newRefusalHarness(t *testing.T) *refusalHarness {
	t.Helper()
	h := &refusalHarness{t: t, client: &runHeartbeatClient{}, cancelled: -1}
	h.start = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	h.now = h.start
	h.worker = NewWorker("mch_A@host@1", 1, h.client, nil, nil)
	h.worker.now = h.clock
	h.worker.runningTasks["attempt-1"] = &runningTaskState{
		task:                 &coordinatorv1.RunningTask{AttemptKey: "attempt-1", DagRunId: "run-1", DagName: "job"},
		owner:                serviceregistry.HostInfo{ID: "coord-1", Host: "127.0.0.1", Port: 50055},
		lastOwnerHeartbeatAt: h.start,
	}
	// Every canceller holds pollersMu when it calls this.
	h.worker.cancelFuncs["attempt-1"] = func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.cancelled < 0 {
			h.cancelled = h.now.Sub(h.start)
			h.refusedAtCancel = h.worker.runningTasks["attempt-1"].firstRefusedAt
		}
	}
	return h
}

// runFor ticks once a second, answering each heartbeat with answer(elapsed)
// and then checking the refusal deadlines, until d has elapsed or the task
// is cancelled.
func (h *refusalHarness) runFor(d time.Duration, answer func(elapsed time.Duration) error) {
	h.t.Helper()
	for elapsed := h.elapsed(); elapsed <= d && h.cancelledAt() < 0; elapsed = h.elapsed() {
		h.client.set(answer(elapsed))
		h.worker.sendOwnerRunHeartbeats(context.Background())
		h.worker.cancelExpiredRefusals(context.Background())
		h.advance(runHeartbeatInterval)
	}
}

var (
	errRefused     = status.Error(codes.Unauthenticated, "transportauth: the credential is not enrolled for a worker machine")
	errForbidden   = status.Error(codes.PermissionDenied, "transportauth: the request does not match the caller's machine")
	errUnreachable = status.Error(codes.Unavailable, "transportauth: the identity provider's keys are unavailable")
)

func TestRefusedHeartbeatsStopTheStepWithinTheBound(t *testing.T) {
	for name, refusal := range map[string]error{
		"unauthenticated":                    errRefused,
		"permission denied":                  errForbidden,
		"revoked locally, wrapped by client": fmt.Errorf("run heartbeat failed: %w", status.Error(codes.Unauthenticated, "transportauth: the identity provider refused this machine's credential")),
	} {
		t.Run(name, func(t *testing.T) {
			h := newRefusalHarness(t)
			h.runFor(2*time.Minute, func(time.Duration) error { return refusal })
			require.GreaterOrEqual(t, h.cancelled, time.Duration(0), "the step was never cancelled")
			assert.LessOrEqual(t, h.cancelled, RefusedCallsStopAfter, "cancelled later than the documented bound")
			assert.GreaterOrEqual(t, h.cancelled, RefusedCallsStopAfter-runHeartbeatInterval, "cancelled earlier than the documented threshold")
		})
	}
}

func TestRefusalClockStartsAtTheFirstRefusal(t *testing.T) {
	h := newRefusalHarness(t)
	// Accepted for 30 s, then refused.
	h.runFor(2*time.Minute, func(elapsed time.Duration) error {
		if elapsed < 30*time.Second {
			return nil
		}
		return errRefused
	})
	require.GreaterOrEqual(t, h.cancelled, time.Duration(0))
	sinceRefusal := h.cancelled - 30*time.Second
	assert.LessOrEqual(t, sinceRefusal, RefusedCallsStopAfter)
	assert.GreaterOrEqual(t, sinceRefusal, RefusedCallsStopAfter-runHeartbeatInterval)
}

func TestAnAcceptedHeartbeatResetsTheRefusalClock(t *testing.T) {
	h := newRefusalHarness(t)
	// Refused for 50 s, accepted once, refused again.
	h.runFor(3*time.Minute, func(elapsed time.Duration) error {
		if elapsed == 50*time.Second {
			return nil
		}
		return errRefused
	})
	require.GreaterOrEqual(t, h.cancelled, time.Duration(0))
	sinceSecondRefusal := h.cancelled - 51*time.Second
	assert.GreaterOrEqual(t, sinceSecondRefusal, RefusedCallsStopAfter-runHeartbeatInterval)
	assert.LessOrEqual(t, sinceSecondRefusal, RefusedCallsStopAfter)
}

func TestAnUnreachableCoordinatorOrProviderKeepsTheLeaseRule(t *testing.T) {
	for name, outage := range map[string]error{
		"provider keys unavailable at the hub": errUnreachable,
		"no unexpired token, provider down":    status.Error(codes.Unavailable, "transportauth: the identity provider did not answer and no unexpired token is held"),
		"deadline exceeded":                    status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
		"plain transport error":                fmt.Errorf("connection refused"),
	} {
		t.Run(name, func(t *testing.T) {
			h := newRefusalHarness(t)
			h.runFor(3*time.Minute, func(time.Duration) error { return outage })
			require.GreaterOrEqual(t, h.cancelled, time.Duration(0))
			// Unchanged: cancelled on the first tick past the stale-lease
			// threshold, never on the refusal bound.
			assert.Greater(t, h.cancelled, ownerHeartbeatTimeout)
			assert.LessOrEqual(t, h.cancelled, ownerHeartbeatTimeout+2*runHeartbeatInterval)
		})
	}
}

func TestOutagesAfterARefusalDoNotSuspendTheBound(t *testing.T) {
	h := newRefusalHarness(t)
	// One refusal, then the coordinator is unreachable. Only an accepted
	// heartbeat clears a refusal, so the bound runs from that refusal.
	h.runFor(3*time.Minute, func(elapsed time.Duration) error {
		if elapsed == 0 {
			return errRefused
		}
		return errUnreachable
	})
	require.GreaterOrEqual(t, h.cancelled, time.Duration(0))
	assert.LessOrEqual(t, h.cancelled, RefusedCallsStopAfter, "an outage after the refusal must not delay the stop")
	assert.GreaterOrEqual(t, h.cancelled, RefusedCallsStopAfter-runHeartbeatInterval)
}

func TestARefusedRunStopsWhileAHeartbeatCallIsBlocked(t *testing.T) {
	h := newRefusalHarness(t)
	// Refused at t=0.
	h.runFor(0, func(time.Duration) error { return errRefused })
	require.Equal(t, time.Duration(-1), h.cancelledAt())

	// The next heartbeat call blocks, as a slow coordinator or another
	// owner's slow call would; the deadline is checked on its own.
	h.client.mu.Lock()
	h.client.block = make(chan struct{})
	h.client.entered = make(chan struct{}, 1)
	h.client.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.worker.sendOwnerRunHeartbeats(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	select {
	case <-h.client.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the heartbeat call never started")
	}

	for h.cancelledAt() < 0 && h.elapsed() <= 2*time.Minute {
		h.advance(runHeartbeatInterval)
		h.worker.cancelExpiredRefusals(context.Background())
	}
	select {
	case <-done:
		t.Fatal("the heartbeat call returned; the test needs it in flight")
	default:
	}
	cancelled := h.cancelledAt()
	require.GreaterOrEqual(t, cancelled, time.Duration(0), "the step was never cancelled")
	assert.LessOrEqual(t, cancelled, RefusedCallsStopAfter)
	assert.GreaterOrEqual(t, cancelled, RefusedCallsStopAfter-runHeartbeatInterval)
}

func TestAHeartbeatAcceptedBeforeTheCancelKeepsTheRun(t *testing.T) {
	// An expired refusal races an accepted heartbeat. Whichever takes
	// pollersMu first wins: the run is cancelled only while its refusal is
	// still recorded, never after the accepted heartbeat cleared it.
	for range 50 {
		h := newRefusalHarness(t)
		h.worker.runningTasks["attempt-1"].firstRefusedAt = h.start
		h.advance(RefusedCallsStopAfter)
		task := h.worker.runningTasks["attempt-1"].task

		var wg sync.WaitGroup
		wg.Go(func() {
			h.worker.markOwnerHeartbeatSuccess([]*coordinatorv1.RunningTask{task}, h.clock())
		})
		wg.Go(func() {
			h.worker.cancelExpiredRefusals(context.Background())
		})
		wg.Wait()

		if h.cancelledAt() >= 0 {
			h.mu.Lock()
			refusedAt := h.refusedAtCancel
			h.mu.Unlock()
			require.False(t, refusedAt.IsZero(), "cancelled after an accepted heartbeat cleared the refusal")
		}
	}
}

func TestARunIsCancelledForRefusalOnce(t *testing.T) {
	h := newRefusalHarness(t)
	calls := 0
	h.worker.cancelFuncs["attempt-1"] = func() { calls++ }
	h.worker.runningTasks["attempt-1"].firstRefusedAt = h.start
	h.advance(RefusedCallsStopAfter)
	for range 5 {
		h.worker.cancelExpiredRefusals(context.Background())
		h.advance(runHeartbeatInterval)
	}
	assert.Equal(t, 1, calls)
}

func TestOutagesThenRefusalsStopByWhicheverRuleComesFirst(t *testing.T) {
	h := newRefusalHarness(t)
	// Unreachable for 40 s after the last accepted heartbeat (t=0), then
	// refused. The refusal bound would end at 40 s + 60 s; the stale-lease
	// rule, measured from t=0, ends first.
	h.runFor(3*time.Minute, func(elapsed time.Duration) error {
		if elapsed < 40*time.Second {
			return errUnreachable
		}
		return errRefused
	})
	require.GreaterOrEqual(t, h.cancelled, time.Duration(0))
	assert.Greater(t, h.cancelled, ownerHeartbeatTimeout)
	assert.LessOrEqual(t, h.cancelled, ownerHeartbeatTimeout+2*runHeartbeatInterval)
	assert.Less(t, h.cancelled, 40*time.Second+RefusedCallsStopAfter)
}

func TestAcceptedHeartbeatsNeverCancel(t *testing.T) {
	h := newRefusalHarness(t)
	h.runFor(5*time.Minute, func(time.Duration) error { return nil })
	assert.Equal(t, time.Duration(-1), h.cancelled)
}

func TestIsDefinitiveRefusal(t *testing.T) {
	assert.True(t, isDefinitiveRefusal(errRefused))
	assert.True(t, isDefinitiveRefusal(errForbidden))
	assert.True(t, isDefinitiveRefusal(fmt.Errorf("wrapped: %w", errRefused)))
	assert.False(t, isDefinitiveRefusal(errUnreachable))
	assert.False(t, isDefinitiveRefusal(status.Error(codes.FailedPrecondition, "owner rejected")))
	assert.False(t, isDefinitiveRefusal(context.DeadlineExceeded))
	assert.False(t, isDefinitiveRefusal(nil))
}
