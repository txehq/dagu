// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package workerchannel_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/health"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/service/frontend"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"

	"github.com/go-chi/chi/v5"
)

type realHub struct {
	store   *store.DispatchTaskStore
	handler *coordinator.Handler
	clients map[string]coordinatorv1.CoordinatorServiceClient
}

// newRealHub is the real coordinator with its real file stores, its modes off,
// as the staging hub's are, reached over the channel.
func newRealHub(t *testing.T) *realHub {
	t.Helper()
	dir := t.TempDir()
	tasks := store.NewDispatchTaskStore(file.NewCollection(dir))
	handler := coordinator.NewHandler(coordinator.HandlerConfig{
		DispatchTaskStore: tasks,
		DAGRunLeaseStore:  store.NewDAGRunLeaseStore(file.NewCollection(filepath.Join(dir, "leases"))),
		Owner:             dispatch.CoordinatorEndpoint{ID: "coord", Host: "127.0.0.1", Port: 50055},
		MachinePinning:    dispatch.MachinePinningOff,
	})
	ids := newIdentities()
	auth, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode: authz.ModeEnforce, Verifier: ids, Machines: ids, MachinesOnly: true,
	})
	require.NoError(t, err)
	limits := workerchannel.DefaultLimits()
	limits.PollWait = 300 * time.Millisecond
	channel, err := workerchannel.NewHandler(workerchannel.Config{
		Auth: auth, Coordinator: handler, Health: health.NewServer(), Limits: limits,
	})
	require.NoError(t, err)
	server := httptest.NewServer(channel)
	t.Cleanup(server.Close)
	hub := &realHub{store: tasks, handler: handler, clients: map[string]coordinatorv1.CoordinatorServiceClient{}}
	for machine, token := range map[string]string{machineA: tokenA, machineB: tokenB} {
		conn, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: server.URL, Credentials: &staticAuth{token: token}})
		require.NoError(t, err)
		hub.clients[machine] = coordinatorv1.NewCoordinatorServiceClient(conn)
	}
	return hub
}

func (h *realHub) enqueue(t *testing.T, run, machine string) {
	t.Helper()
	task := &dispatch.DispatchTask{
		Target: "job", DAGRunID: run, AttemptKey: "attempt-" + run, AttemptID: "a1",
		QueueName: "q", Owner: dispatch.CoordinatorEndpoint{ID: "coord", Host: "127.0.0.1", Port: 50055},
		Definition: "steps:\n  - command: echo\n",
	}
	if machine != "" {
		task.WorkerSelector = map[string]string{txepkg.LabelMachine: machine}
	}
	require.NoError(t, h.store.Enqueue(context.Background(), task))
}

func (h *realHub) poll(t *testing.T, machine string) *coordinatorv1.Task {
	t.Helper()
	resp, err := h.clients[machine].Poll(context.Background(), poll(machine))
	require.NoError(t, err)
	return resp.GetTask()
}

// With the hub's modes off, a machine on the channel gets only what is pinned
// to it. The same task stays open to a caller on the private path.
func TestChannelPinsAMachineWithTheModesOff(t *testing.T) {
	hub := newRealHub(t)
	hub.enqueue(t, "unpinned", "")
	hub.enqueue(t, "for-a", machineA)
	hub.enqueue(t, "for-b", machineB)

	task := hub.poll(t, machineA)
	require.NotNil(t, task)
	assert.Equal(t, "for-a", task.GetDagRunId())
	assert.Nil(t, hub.poll(t, machineA), "an unpinned task or another machine's")

	task = hub.poll(t, machineB)
	require.NotNil(t, task)
	assert.Equal(t, "for-b", task.GetDagRunId())
	assert.Nil(t, hub.poll(t, machineB))

	// The private path is as it was: mode off hands the unpinned task over.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	direct, err := hub.handler.Poll(ctx, &coordinatorv1.PollRequest{
		WorkerId: "worker-private", PollerId: "p", Labels: map[string]string{"role": "any"},
	})
	require.NoError(t, err)
	assert.Equal(t, "unpinned", direct.GetTask().GetDagRunId())
}

// A claim, a run heartbeat and a log of one machine's attempt, sent by the
// other machine with its own valid credential and worker id.
func TestChannelKeepsOneMachineOutOfAnothersAttempt(t *testing.T) {
	hub := newRealHub(t)
	hub.enqueue(t, "for-a", machineA)
	task := hub.poll(t, machineA)
	require.NotNil(t, task)

	ack, err := hub.clients[machineB].AckTaskClaim(context.Background(), &coordinatorv1.AckTaskClaimRequest{
		WorkerId: machineB, ClaimToken: task.GetClaimToken(), AttemptKey: task.GetAttemptKey(),
	})
	require.NoError(t, err)
	assert.False(t, ack.GetAccepted(), "another machine's claim")

	ack, err = hub.clients[machineA].AckTaskClaim(context.Background(), &coordinatorv1.AckTaskClaimRequest{
		WorkerId: machineA, ClaimToken: task.GetClaimToken(), AttemptKey: task.GetAttemptKey(),
	})
	require.NoError(t, err)
	assert.True(t, ack.GetAccepted(), "%s", ack.GetError())

	running := &coordinatorv1.RunningTask{
		DagRunId: task.GetDagRunId(), DagName: task.GetTarget(), AttemptKey: task.GetAttemptKey(),
		ExecutionMarker: task.GetExecutionMarker(),
	}
	beat, err := hub.clients[machineB].RunHeartbeat(context.Background(), &coordinatorv1.RunHeartbeatRequest{
		WorkerId: machineB, RunningTasks: []*coordinatorv1.RunningTask{running},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, beat.GetCancelledRuns(), "another machine's run is not refreshed: it is told to stop")

	beat, err = hub.clients[machineA].RunHeartbeat(context.Background(), &coordinatorv1.RunHeartbeatRequest{
		WorkerId: machineA, RunningTasks: []*coordinatorv1.RunningTask{running},
	})
	require.NoError(t, err)
	assert.Empty(t, beat.GetCancelledRuns())
}

// The real frontend, with its global middleware, reaches the channel, and the
// channel is what decides.
func TestAFrontendServerCarriesTheChannel(t *testing.T) {
	ids := newIdentities()
	auth, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode: authz.ModeEnforce, Verifier: ids, Machines: ids, MachinesOnly: true,
	})
	require.NoError(t, err)
	svc := &service{task: make(chan *coordinatorv1.Task, 1)}
	channel, err := workerchannel.NewHandler(workerchannel.Config{Auth: auth, Coordinator: svc, Health: health.NewServer()})
	require.NoError(t, err)
	server := test.SetupServer(t, test.WithServerOptions(frontend.WithRoutes(
		func(_ context.Context, r chi.Router, apiV1BasePath string) { channel.Mount(r, apiV1BasePath) })))

	base := fmt.Sprintf("http://%s:%d/api/v1%s", server.Config.Server.Host, server.Config.Server.Port, workerchannel.MountPath)
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: base, Credentials: &staticAuth{token: tokenA}})
	require.NoError(t, err)
	_, err = coordinatorv1.NewCoordinatorServiceClient(conn).Heartbeat(context.Background(), heartbeat(machineA))
	require.NoError(t, err)

	_, code := rawCall(t, base, coordinatorv1.CoordinatorService_Heartbeat_FullMethodName, "application/proto", nil, nil)
	assert.Equal(t, "unauthenticated", code)
}
