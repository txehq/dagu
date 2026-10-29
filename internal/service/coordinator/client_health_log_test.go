// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator_test

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/serviceregistry"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

type healthLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *healthLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// lines returns the logged lines whose message is msg, exactly.
func (b *healthLogBuffer) lines(msg string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for line := range strings.SplitSeq(b.buf.String(), "\n") {
		if strings.Contains(line, `msg="`+msg+`"`) {
			out = append(out, line)
		}
	}
	return out
}

type healthTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *healthTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *healthTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// healthLogRig is a real client against a coordinator whose health check the
// test turns on and off, logging through the real logger in its text format.
type healthLogRig struct {
	health *health.Server
	client coordinator.Client
	ctx    context.Context
	out    *healthLogBuffer
}

func newHealthLogRig(t *testing.T) *healthLogRig {
	t.Helper()
	hs := health.NewServer()
	hs.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	server, addr := startMockServerWithHealth(t, &mockCoordinatorService{
		heartbeatFunc: func(context.Context, *coordinatorv1.HeartbeatRequest) (*coordinatorv1.HeartbeatResponse, error) {
			return &coordinatorv1.HeartbeatResponse{}, nil
		},
	}, hs)
	t.Cleanup(server.Stop)
	host, port := parseHostPort(addr)
	config := coordinator.DefaultConfig()
	config.RequestTimeout = time.Second
	client := coordinator.New(&mockServiceMonitor{
		members: []serviceregistry.HostInfo{{ID: "coord-0", Host: host, Port: port, Status: serviceregistry.ServiceStatusActive}},
	}, config)
	out := &healthLogBuffer{}
	ctx := logger.WithFixedLogger(context.Background(),
		logger.NewLogger(logger.WithFormat("text"), logger.WithQuiet(), logger.WithWriter(out)))
	return &healthLogRig{health: hs, client: client, ctx: ctx, out: out}
}

// beat sends one heartbeat, as the worker does every second while it works.
func (r *healthLogRig) beat(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(r.ctx, 2*time.Second)
	defer cancel()
	_, err := r.client.Heartbeat(ctx, &coordinatorv1.HeartbeatRequest{WorkerId: "w"})
	return err
}

// TXE-5406, through the real client: while the coordinator's health check
// fails, the first failure is logged at once and then one summary a minute;
// the first passing check logs one line that counts the episode, and the
// client's own recovery line is logged once, as before.
func TestClientSummarisesFailedHealthChecks(t *testing.T) {
	r := newHealthLogRig(t)
	clock := &healthTestClock{now: time.Date(2026, 10, 30, 2, 0, 0, 0, time.UTC)}
	coordinator.SetHealthLogClockForTest(r.client, clock.Now)

	for range 11 { // 0 s to 50 s
		require.Error(t, r.beat(t))
		clock.Advance(5 * time.Second)
	}
	assert.Len(t, r.out.lines("Failed to check coordinator health"), 1, "the first failure only")
	assert.Empty(t, r.out.lines("Coordinator health check still failing"))

	clock.Advance(5 * time.Second) // 60 s
	require.Error(t, r.beat(t))
	summaries := r.out.lines("Coordinator health check still failing")
	require.Len(t, summaries, 1)
	assert.Contains(t, summaries[0], "level=WARN")
	assert.Contains(t, summaries[0], "attempts=12")
	assert.Contains(t, summaries[0], "suppressed=11")
	assert.Contains(t, summaries[0], "failing-since=2026-10-30T02:00:00")
	assert.Contains(t, summaries[0], "NOT_SERVING")
	assert.Contains(t, summaries[0], "coordinator-id=coord-0")

	for range 3 {
		clock.Advance(10 * time.Second)
		require.Error(t, r.beat(t))
	}
	assert.Len(t, r.out.lines("Coordinator health check still failing"), 1, "one summary a minute")

	r.health.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	clock.Advance(10 * time.Second)
	require.NoError(t, r.beat(t))
	require.NoError(t, r.beat(t))
	passed := r.out.lines("Coordinator health check passing again")
	require.Len(t, passed, 1)
	assert.Contains(t, passed[0], "level=INFO")
	assert.Contains(t, passed[0], "attempts=15")
	assert.Contains(t, passed[0], "suppressed=3", "the failures after the summary are counted here")
	// The client's recovery line, which the tunnel supervisor reads
	// (TXE-5398), is logged once, as it always was.
	assert.Len(t, r.out.lines("CoordinatorCli connection recovered"), 1)

	// A new outage is a new episode: its first failure is logged at once.
	r.health.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	require.Error(t, r.beat(t))
	assert.Len(t, r.out.lines("Failed to check coordinator health"), 2)
	assert.Len(t, r.out.lines("Coordinator health check still failing"), 1)
}

// The counterfactual: the same outage without the bound writes one warning
// per failed check, the burst TXE-5406 measured. The test above would fail on
// it.
func TestClientWithoutTheBoundLogsEveryFailedHealthCheck(t *testing.T) {
	r := newHealthLogRig(t)
	coordinator.SetHealthLogClockForTest(r.client, nil)
	for range 12 {
		require.Error(t, r.beat(t))
	}
	assert.Len(t, r.out.lines("Failed to check coordinator health"), 12)
	assert.Empty(t, r.out.lines("Coordinator health check still failing"))
}
