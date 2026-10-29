// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package coordinator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/cmn/backoff"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/serviceregistry"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// The Mac tunnel supervisor (txe/worker/tunnel-supervise.py, TXE-5398) treats the worker's
// coordinator calls as failing without interruption only while no "CoordinatorCli connection
// recovered" line follows the first heartbeat failure. This drives the real client against a
// coordinator whose heartbeat fails and recovers, writes the worker's heartbeat failure line
// through the same logger as worker.go does, and feeds the real log, in the text and JSON
// formats, with and without debug (which adds the source to each record), to the supervisor's
// reader at each step.
func TestClientRecoveryLineIsTheSupervisorsSignal(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "..", "txe", "worker", "tunnel-supervise.py"))
	require.NoError(t, err)
	py, err := exec.LookPath("python3")
	require.NoError(t, err)

	for _, tc := range []struct {
		name, format string
		debug        bool
	}{{"text", "text", false}, {"text-debug", "text", true}, {"json", "json", false}, {"json-debug", "json", true}} {
		format := tc.format
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu        sync.Mutex
				heartbeat error
			)
			setHeartbeat := func(err error) { mu.Lock(); heartbeat = err; mu.Unlock() }
			mock := &mockCoordinatorService{
				heartbeatFunc: func(context.Context, *coordinatorv1.HeartbeatRequest) (*coordinatorv1.HeartbeatResponse, error) {
					mu.Lock()
					defer mu.Unlock()
					if heartbeat != nil {
						return nil, heartbeat
					}
					return &coordinatorv1.HeartbeatResponse{}, nil
				},
				pollFunc: func(context.Context, *coordinatorv1.PollRequest) (*coordinatorv1.PollResponse, error) {
					return &coordinatorv1.PollResponse{}, nil
				},
			}
			server, addr := startMockServer(t, mock)
			defer server.Stop()
			host, port := parseHostPort(addr)
			config := coordinator.DefaultConfig()
			config.RequestTimeout = 500 * time.Millisecond
			client := coordinator.New(&mockServiceMonitor{
				members: []serviceregistry.HostInfo{{Host: host, Port: port, Status: serviceregistry.ServiceStatusActive}},
			}, config)

			out := &lockedLog{}
			opts := []logger.Option{logger.WithFormat(format), logger.WithQuiet(), logger.WithWriter(out)}
			if tc.debug {
				opts = append(opts, logger.WithDebug()) // the worker's debug: true adds source= to each record
			}
			ctx := logger.WithFixedLogger(context.Background(), logger.NewLogger(opts...))
			logPath := filepath.Join(t.TempDir(), "worker.log")

			// beat sends one heartbeat and, on failure, logs what worker.go's sendHeartbeats logs.
			beat := func() {
				callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				if _, err := client.Heartbeat(callCtx, &coordinatorv1.HeartbeatRequest{WorkerId: "mch_test"}); err != nil {
					logger.Warn(ctx, "Heartbeat send failed; will retry with backoff")
				}
			}
			// since asks the supervisor's reader when the current failure episode began, or "".
			since := func() string {
				require.NoError(t, os.WriteFile(logPath, []byte(out.String()), 0o600))
				program := `
import importlib.util, sys, time
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("ts", sys.argv[1]); ts = importlib.util.module_from_spec(spec); spec.loader.exec_module(ts)
v = ts.worker_unhealthy_since(sys.argv[2], time.time(), 45)
print("" if v is None else repr(v))
`
				cmd := exec.Command(py, "-I", "-c", program, script, logPath)
				cmd.Env = []string{"PATH=/usr/bin:/bin"}
				b, err := cmd.CombinedOutput()
				require.NoError(t, err, string(b))
				return strings.TrimSpace(string(b))
			}
			recoveries := func() int { return strings.Count(out.String(), "CoordinatorCli connection recovered") }

			beat() // a success with no earlier failure logs nothing
			assert.Equal(t, 0, recoveries())
			assert.Empty(t, since())

			setHeartbeat(status.Error(codes.Unavailable, "hub stalled"))
			beat()
			first := since()
			require.NotEmpty(t, first, "a heartbeat failure starts an episode")
			time.Sleep(20 * time.Millisecond)
			beat()
			assert.Equal(t, first, since(), "the episode keeps its start while failures continue")
			assert.Equal(t, 0, recoveries())

			// Another call of the worker (a poll) succeeds while heartbeats still fail: the client
			// logs the recovery, so the episode ends; it is not uninterrupted.
			callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, err := client.Poll(callCtx, backoff.NewConstantBackoffPolicy(10*time.Millisecond), &coordinatorv1.PollRequest{WorkerId: "mch_test"})
			cancel()
			require.NoError(t, err)
			assert.Equal(t, 1, recoveries())
			assert.Empty(t, since())

			time.Sleep(20 * time.Millisecond)
			beat()
			second := since()
			require.NotEmpty(t, second, "a failure after the recovery starts a new episode")
			assert.NotEqual(t, first, second)

			setHeartbeat(nil)
			beat()
			assert.Equal(t, 2, recoveries(), "the heartbeat's own success logs the recovery")
			assert.Empty(t, since())
			beat()
			assert.Equal(t, 2, recoveries(), "only the first success after a failure is logged")

			if tc.debug && format == "text" {
				assert.Contains(t, out.String(), " source=", "debug text records carry the source")
			}
			if format == "json" {
				for line := range strings.SplitSeq(strings.TrimSpace(out.String()), "\n") {
					var rec map[string]any
					require.NoError(t, json.Unmarshal([]byte(line), &rec), line)
				}
			}
		})
	}
}
