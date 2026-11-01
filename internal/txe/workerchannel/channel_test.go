// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package workerchannel_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

const (
	machineA = "mch_A"
	machineB = "mch_B"
	tokenA   = "token-a"
	tokenB   = "token-b"
)

// identities answers for tokens and enrolments, so that a test can revoke one.
type identities struct {
	mu       sync.Mutex
	expires  map[string]time.Time
	reviewer map[string]bool
	enrolled map[string]string // client id -> machine id
}

func newIdentities() *identities {
	expiry := time.Now().Add(time.Hour)
	return &identities{
		expires:  map[string]time.Time{tokenA: expiry, tokenB: expiry},
		reviewer: map[string]bool{},
		enrolled: map[string]string{tokenA: machineA, tokenB: machineB},
	}
}

func (i *identities) Verify(_ context.Context, token string) (authn.Principal, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	expires, ok := i.expires[token]
	if !ok {
		return authn.Principal{}, errors.New("unknown token")
	}
	class := authn.ClassWorker
	if i.reviewer[token] {
		class = authn.ClassReviewer
	}
	return authn.Principal{Class: class, ClientID: token, Expires: expires}, nil
}

func (i *identities) ResolveMachine(_ context.Context, p authn.Principal) (authz.Machine, authz.Reason, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	machine, ok := i.enrolled[p.ClientID]
	if !ok {
		return authz.Machine{}, authz.Reason("revoked"), nil
	}
	return authz.Machine{MachineID: machine, OwnerID: "own_" + machine, Class: authn.ClassWorker}, "", nil
}

func (i *identities) revoke(token string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.enrolled, token)
}

// service records what reached the coordinator, which must be nothing for a
// call that is refused.
type service struct {
	coordinatorv1.UnimplementedCoordinatorServiceServer
	calls   atomic.Int64
	chunks  atomic.Int64
	callers sync.Map // method -> machine id
	task    chan *coordinatorv1.Task
	onChunk func(n int)
	block   chan struct{}
}

func (s *service) record(ctx context.Context, method string) {
	s.calls.Add(1)
	if caller, ok := transportauth.CallerFrom(ctx); ok {
		s.callers.Store(method, caller.Machine.MachineID)
	}
}

func (s *service) Heartbeat(ctx context.Context, _ *coordinatorv1.HeartbeatRequest) (*coordinatorv1.HeartbeatResponse, error) {
	s.record(ctx, "Heartbeat")
	if s.block != nil {
		<-s.block
	}
	return &coordinatorv1.HeartbeatResponse{}, nil
}

func (s *service) Dispatch(ctx context.Context, _ *coordinatorv1.DispatchRequest) (*coordinatorv1.DispatchResponse, error) {
	s.record(ctx, "Dispatch")
	return &coordinatorv1.DispatchResponse{}, nil
}

func (s *service) Poll(ctx context.Context, _ *coordinatorv1.PollRequest) (*coordinatorv1.PollResponse, error) {
	s.record(ctx, "Poll")
	select {
	case task := <-s.task:
		return &coordinatorv1.PollResponse{Task: task}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *service) StreamLogs(stream coordinatorv1.CoordinatorService_StreamLogsServer) error {
	s.record(stream.Context(), "StreamLogs")
	var received uint64
	for {
		_, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&coordinatorv1.StreamLogsResponse{ChunksReceived: received})
		}
		if err != nil {
			return err
		}
		received++
		s.chunks.Add(1)
		if s.onChunk != nil {
			s.onChunk(int(received))
		}
	}
}

type staticAuth struct {
	token string
	err   error
	calls atomic.Int64
}

func (a *staticAuth) HTTPAuthorization(context.Context, string) (string, error) {
	a.calls.Add(1)
	if a.err != nil {
		return "", a.err
	}
	return "Bearer " + a.token, nil
}

type harness struct {
	ids     *identities
	service *service
	server  *httptest.Server
}

func newHarness(t *testing.T, limits workerchannel.Limits) *harness {
	t.Helper()
	ids := newIdentities()
	auth, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode: authz.ModeEnforce, Verifier: ids, Machines: ids, MachinesOnly: true,
	})
	require.NoError(t, err)
	svc := &service{task: make(chan *coordinatorv1.Task, 1)}
	handler, err := workerchannel.NewHandler(workerchannel.Config{
		Auth: auth, Coordinator: svc, Health: health.NewServer(), Limits: limits,
	})
	require.NoError(t, err)
	server := httptest.NewServer(http.StripPrefix("/channel", handler))
	t.Cleanup(server.Close)
	return &harness{ids: ids, service: svc, server: server}
}

func (h *harness) client(t *testing.T, token string) coordinatorv1.CoordinatorServiceClient {
	t.Helper()
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{
		BaseURL: h.server.URL + "/channel", Credentials: &staticAuth{token: token},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return coordinatorv1.NewCoordinatorServiceClient(conn)
}

func heartbeat(machine string) *coordinatorv1.HeartbeatRequest {
	return &coordinatorv1.HeartbeatRequest{WorkerId: machine, Labels: map[string]string{txepkg.LabelMachine: machine}}
}

func TestUnaryRunsWithTheAuthenticatedMachine(t *testing.T) {
	h := newHarness(t, workerchannel.Limits{})
	_, err := h.client(t, tokenA).Heartbeat(context.Background(), heartbeat(machineA))
	require.NoError(t, err)
	machine, ok := h.service.callers.Load("Heartbeat")
	require.True(t, ok)
	assert.Equal(t, machineA, machine)
}

func TestRefusedCallsNeverReachTheService(t *testing.T) {
	expired := func(h *harness) { h.ids.expires[tokenA] = time.Now().Add(-time.Minute) }
	revoked := func(h *harness) { h.ids.revoke(tokenA) }
	reviewer := func(h *harness) { h.ids.reviewer[tokenA] = true }
	cases := []struct {
		name  string
		setup func(*harness)
		token string
		req   *coordinatorv1.HeartbeatRequest
		code  codes.Code
	}{
		{"unknown token", nil, "nobody", heartbeat(machineA), codes.Unauthenticated},
		{"expired token", expired, tokenA, heartbeat(machineA), codes.Unauthenticated},
		{"revoked enrolment", revoked, tokenA, heartbeat(machineA), codes.Unauthenticated},
		{"reviewer class", reviewer, tokenA, heartbeat(machineA), codes.PermissionDenied},
		{"another machine's worker id", nil, tokenA, heartbeat(machineB), codes.PermissionDenied},
		{"another machine's label", nil, tokenA, &coordinatorv1.HeartbeatRequest{
			WorkerId: machineA, Labels: map[string]string{txepkg.LabelMachine: machineB},
		}, codes.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, workerchannel.Limits{})
			if tc.setup != nil {
				tc.setup(h)
			}
			_, err := h.client(t, tc.token).Heartbeat(context.Background(), tc.req)
			assert.Equal(t, tc.code, status.Code(err), "%v", err)
			assert.Zero(t, h.service.calls.Load())
		})
	}
}

// rawCall sends a request no Conn would send, and returns what the hub said:
// its HTTP status and, when it answered with a Connect error, that error's code.
func rawCall(t *testing.T, url, method, contentType string, headers map[string][]string, body []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+method, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Connect-Protocol-Version", "1")
	maps.Copy(req.Header, headers)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var wire struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(data, &wire)
	return resp.StatusCode, wire.Code
}

func TestTheRouteIsNeverAnOpenDoor(t *testing.T) {
	hubKey := strings.Repeat("k", 40)
	bearer := map[string][]string{"Authorization": {"Bearer " + tokenA}}
	cases := []struct {
		name    string
		method  string
		headers map[string][]string
		code    string
	}{
		{"no credential", coordinatorv1.CoordinatorService_Heartbeat_FullMethodName, nil, "unauthenticated"},
		{"no credential on health", grpc_health_v1.Health_Check_FullMethodName, nil, "unauthenticated"},
		{"two credentials", coordinatorv1.CoordinatorService_Heartbeat_FullMethodName,
			map[string][]string{"Authorization": {"Bearer " + tokenA, "Bearer " + tokenB}}, "unauthenticated"},
		{"the hub scheme", coordinatorv1.CoordinatorService_Dispatch_FullMethodName,
			map[string][]string{"Authorization": {"TXE-Hub " + hubKey}}, "unauthenticated"},
		{"a hub-only method", coordinatorv1.CoordinatorService_Dispatch_FullMethodName, bearer, "permission_denied"},
		{"a resource with no authorizer", coordinatorv1.CoordinatorService_GetWorkspaceBundle_FullMethodName, bearer, "unimplemented"},
		{"a method nobody listed", "/coordinator.v1.CoordinatorService/Nope", bearer, "permission_denied"},
		{"another service", "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", bearer, "permission_denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, workerchannel.Limits{})
			_, code := rawCall(t, h.server.URL+"/channel", tc.method, "application/proto", tc.headers, nil)
			assert.Equal(t, tc.code, code)
			assert.Zero(t, h.service.calls.Load())
		})
	}
}

func TestOnlyConnectWithProtobufIsSpoken(t *testing.T) {
	bearer := map[string][]string{"Authorization": {"Bearer " + tokenA}}
	for _, contentType := range []string{"application/grpc", "application/grpc+proto", "application/grpc-web+proto", "application/json", "application/connect+json", ""} {
		t.Run(contentType, func(t *testing.T) {
			h := newHarness(t, workerchannel.Limits{})
			status, _ := rawCall(t, h.server.URL+"/channel", coordinatorv1.CoordinatorService_Heartbeat_FullMethodName, contentType, bearer, nil)
			assert.Equal(t, http.StatusUnsupportedMediaType, status)
			assert.Zero(t, h.service.calls.Load())
		})
	}
	h := newHarness(t, workerchannel.Limits{})
	data, err := proto.Marshal(heartbeat(machineA))
	require.NoError(t, err)
	compressed := map[string][]string{"Authorization": {"Bearer " + tokenA}, "Content-Encoding": {"gzip"}}
	_, code := rawCall(t, h.server.URL+"/channel", coordinatorv1.CoordinatorService_Heartbeat_FullMethodName, "application/proto", compressed, data)
	assert.Equal(t, "unimplemented", code)
	assert.Zero(t, h.service.calls.Load())
}

// The exact list of what the channel carries, against the transport policy.
func TestCarriedMethodsAreExactlyTheTable(t *testing.T) {
	carried := map[string]bool{}
	for _, name := range []string{
		"Poll", "Heartbeat", "AckTaskClaim", "RunHeartbeat", "ReportStatus", "StreamLogs", "StreamArtifacts",
		"ResolveSecretReference", "ResolveRuntimeProfile", "ClaimAgentSessionCleanup", "CompleteAgentSessionCleanup",
	} {
		carried["/coordinator.v1.CoordinatorService/"+name] = true
	}
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: "https://hub.example", Credentials: &staticAuth{token: tokenA}})
	require.NoError(t, err)
	desc := coordinatorv1.CoordinatorService_ServiceDesc
	var names []string
	for _, m := range desc.Methods {
		names = append(names, "/"+desc.ServiceName+"/"+m.MethodName)
	}
	for _, s := range desc.Streams {
		names = append(names, "/"+desc.ServiceName+"/"+s.StreamName)
	}
	require.Len(t, names, 23)
	for _, name := range names {
		surface, known := transportauth.SurfaceOf(name)
		require.True(t, known, name)
		assert.Equal(t, surface == transportauth.SurfaceWorker, carried[name], name)
		if !carried[name] {
			assert.Equal(t, codes.Unimplemented, status.Code(conn.Invoke(context.Background(), name, nil, nil)), name)
			_, err := conn.NewStream(context.Background(), nil, name)
			assert.Equal(t, codes.Unimplemented, status.Code(err), name)
		}
	}
}

func TestHealthAnswersAnEnrolledMachine(t *testing.T) {
	h := newHarness(t, workerchannel.Limits{})
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{
		BaseURL: h.server.URL + "/channel", Credentials: &staticAuth{token: tokenA},
	})
	require.NoError(t, err)
	resp, err := grpc_health_v1.NewHealthClient(conn).Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
}

func poll(machine string) *coordinatorv1.PollRequest {
	return &coordinatorv1.PollRequest{
		WorkerId: machine, PollerId: "p1", Labels: map[string]string{txepkg.LabelMachine: machine},
	}
}

func TestPollWithNoTaskAnswersEmptyWithinItsLimit(t *testing.T) {
	limits := workerchannel.DefaultLimits()
	limits.PollWait = 100 * time.Millisecond
	h := newHarness(t, limits)
	started := time.Now()
	resp, err := h.client(t, tokenA).Poll(context.Background(), poll(machineA))
	require.NoError(t, err)
	assert.Nil(t, resp.GetTask())
	assert.Less(t, time.Since(started), 2*time.Second)
}

func TestPollHandsOverATask(t *testing.T) {
	h := newHarness(t, workerchannel.Limits{})
	h.service.task <- &coordinatorv1.Task{DagRunId: "run-1", AttemptKey: "attempt-1"}
	resp, err := h.client(t, tokenA).Poll(context.Background(), poll(machineA))
	require.NoError(t, err)
	assert.Equal(t, "attempt-1", resp.GetTask().GetAttemptKey())
}

func chunk(machine string) *coordinatorv1.LogChunk {
	return &coordinatorv1.LogChunk{WorkerId: machine, Data: []byte("line\n")}
}

func TestClientStreamCarriesEveryChunk(t *testing.T) {
	h := newHarness(t, workerchannel.Limits{})
	stream, err := h.client(t, tokenA).StreamLogs(context.Background())
	require.NoError(t, err)
	for range 3 {
		require.NoError(t, stream.Send(chunk(machineA)))
	}
	resp, err := stream.CloseAndRecv()
	require.NoError(t, err)
	assert.EqualValues(t, 3, resp.GetChunksReceived())
	machine, _ := h.service.callers.Load("StreamLogs")
	assert.Equal(t, machineA, machine)
}

func TestEveryChunkIsChecked(t *testing.T) {
	h := newHarness(t, workerchannel.Limits{})
	var seen atomic.Int64
	h.service.onChunk = func(n int) { seen.Store(int64(n)) }
	stream, err := h.client(t, tokenA).StreamLogs(context.Background())
	require.NoError(t, err)
	require.NoError(t, stream.Send(chunk(machineA)))
	if err := stream.Send(chunk(machineB)); err != nil {
		require.ErrorIs(t, err, io.EOF)
	}
	_, err = stream.CloseAndRecv()
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
	assert.EqualValues(t, 1, seen.Load())
}

func TestAStreamStopsWhenItsEnrolmentIsRevoked(t *testing.T) {
	h := newHarness(t, workerchannel.Limits{})
	stream, err := h.client(t, tokenA).StreamLogs(context.Background())
	require.NoError(t, err)
	require.NoError(t, stream.Send(chunk(machineA)))
	require.Eventually(t, func() bool { return h.service.calls.Load() == 1 }, time.Second, time.Millisecond)
	h.ids.revoke(tokenA)
	// The enrolment is read again at most a second after the last read.
	time.Sleep(1100 * time.Millisecond)
	if err := stream.Send(chunk(machineA)); err != nil {
		require.ErrorIs(t, err, io.EOF)
	}
	_, err = stream.CloseAndRecv()
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "%v", err)
}

func TestAStreamCutInsideAMessageIsAnError(t *testing.T) {
	h := newHarness(t, workerchannel.Limits{})
	message, err := proto.Marshal(chunk(machineA))
	require.NoError(t, err)
	var body bytes.Buffer
	body.WriteByte(0)
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(len(message)))) // #nosec G115 -- a test's own message
	body.Write(message[:len(message)/2])
	status, _ := rawCall(t, h.server.URL+"/channel", coordinatorv1.CoordinatorService_StreamLogs_FullMethodName, "application/connect+proto",
		map[string][]string{"Authorization": {"Bearer " + tokenA}}, body.Bytes())
	assert.Equal(t, http.StatusOK, status) // a stream's error is in its last frame
	assert.EqualValues(t, 0, h.service.chunks.Load())
}

// A body that stops cleanly between messages is what Connect calls a finished
// request, so nothing may depend on that: a log is finalized only by its final
// chunk.
func TestALogIsNotFinalizedByTheEndOfARequest(t *testing.T) {
	dir, client := realLogHandler(t)
	stream, err := client.StreamLogs(context.Background())
	require.NoError(t, err)
	require.NoError(t, stream.Send(realChunk(0, "partial", false)))
	_, err = stream.CloseAndRecv()
	require.NoError(t, err)
	files := filesUnder(t, dir)
	require.Len(t, files, 1)
	assert.False(t, strings.HasSuffix(files[0], ".final"))

	stream, err = client.StreamLogs(context.Background())
	require.NoError(t, err)
	require.NoError(t, stream.Send(realChunk(7, "", true)))
	_, err = stream.CloseAndRecv()
	require.NoError(t, err)
	assert.Len(t, filesUnder(t, dir), 2)
}

// A stalled body must not hold a machine's call past the limit, though no read
// of it notices a cancelled context.
func TestAStalledBodyIsReleased(t *testing.T) {
	limits := workerchannel.DefaultLimits()
	limits.PollWait = 50 * time.Millisecond
	limits.Unary = 100 * time.Millisecond
	limits.MaxCallsPerMachine = 1
	h := newHarness(t, limits)
	conn, err := net.Dial("tcp", h.server.Listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = io.WriteString(conn, "POST /channel"+coordinatorv1.CoordinatorService_Heartbeat_FullMethodName+" HTTP/1.1\r\nHost: x\r\n"+
		"Authorization: Bearer "+tokenA+"\r\nContent-Type: application/proto\r\nConnect-Protocol-Version: 1\r\nContent-Length: 100\r\n\r\nabc")
	require.NoError(t, err)
	client := h.client(t, tokenA)
	require.Eventually(t, func() bool {
		_, err := client.Heartbeat(context.Background(), heartbeat(machineA))
		return err == nil
	}, 5*time.Second, 50*time.Millisecond)
}

func TestSizeLimits(t *testing.T) {
	limits := workerchannel.DefaultLimits()
	limits.MaxMessageBytes = 1024
	limits.MaxRequestBytes = 4096
	h := newHarness(t, limits)

	huge := heartbeat(machineA)
	huge.Labels["padding"] = strings.Repeat("x", 2048)
	data, err := proto.Marshal(huge)
	require.NoError(t, err)
	_, code := rawCall(t, h.server.URL+"/channel", coordinatorv1.CoordinatorService_Heartbeat_FullMethodName, "application/proto",
		map[string][]string{"Authorization": {"Bearer " + tokenA}}, data)
	assert.Equal(t, "resource_exhausted", code)
	assert.Zero(t, h.service.calls.Load())

	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{
		BaseURL: h.server.URL + "/channel", Credentials: &staticAuth{token: tokenA}, Limits: limits,
	})
	require.NoError(t, err)
	stream, err := coordinatorv1.NewCoordinatorServiceClient(conn).StreamLogs(context.Background())
	require.NoError(t, err)
	var sendErr error
	for range 10 {
		c := chunk(machineA)
		c.Data = bytes.Repeat([]byte("x"), 900)
		if sendErr = stream.Send(c); sendErr != nil {
			break
		}
	}
	assert.Equal(t, codes.ResourceExhausted, status.Code(sendErr), "%v", sendErr)
}

// The server drains a refused request's body, so a refused caller is bound too.
func TestAStalledBodyOfARefusedRequestIsReleased(t *testing.T) {
	limits := workerchannel.DefaultLimits()
	limits.PollWait = 50 * time.Millisecond
	limits.Unary = 100 * time.Millisecond
	h := newHarness(t, limits)
	conn, err := net.Dial("tcp", h.server.Listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = io.WriteString(conn, "POST /channel"+coordinatorv1.CoordinatorService_Heartbeat_FullMethodName+" HTTP/1.1\r\nHost: x\r\n"+
		"Content-Type: application/proto\r\nConnect-Protocol-Version: 1\r\nContent-Length: 100\r\n\r\nabc")
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	// The server closes the connection: reading to its end does not time out.
	_, err = io.ReadAll(conn)
	require.NoError(t, err)
}

func TestAMachineCannotHoldMoreThanItsCalls(t *testing.T) {
	limits := workerchannel.DefaultLimits()
	limits.MaxCallsPerMachine = 1
	h := newHarness(t, limits)
	h.service.block = make(chan struct{})
	client := h.client(t, tokenA)
	first := make(chan error, 1)
	go func() {
		_, err := client.Heartbeat(context.Background(), heartbeat(machineA))
		first <- err
	}()
	require.Eventually(t, func() bool { return h.service.calls.Load() == 1 }, time.Second, time.Millisecond)

	_, err := client.Heartbeat(context.Background(), heartbeat(machineA))
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	close(h.service.block)
	require.NoError(t, <-first)
}

func TestAnAnswerThatIsNotTheHubsIsUnavailable(t *testing.T) {
	for _, code := range []int{http.StatusOK, http.StatusForbidden, http.StatusUnauthorized, http.StatusNotFound, http.StatusBadGateway, 524} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
				_, _ = io.WriteString(w, "<html>edge</html>")
			}))
			defer edge.Close()
			conn, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: edge.URL, Credentials: &staticAuth{token: tokenA}})
			require.NoError(t, err)
			_, err = coordinatorv1.NewCoordinatorServiceClient(conn).Heartbeat(context.Background(), heartbeat(machineA))
			assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
		})
	}
}

// A hub's refusal is told from an edge's status, and stays a refusal.
func TestAHubsRefusalIsStillARefusal(t *testing.T) {
	h := newHarness(t, workerchannel.Limits{})
	_, err := h.client(t, "nobody").Heartbeat(context.Background(), heartbeat(machineA))
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "%v", err)
	_, err = h.client(t, tokenA).Heartbeat(context.Background(), heartbeat(machineB))
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
}

func TestARedirectIsNeverFollowed(t *testing.T) {
	var reached atomic.Int64
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer elsewhere.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: redirect.URL, Credentials: &staticAuth{token: tokenA}})
	require.NoError(t, err)
	client := coordinatorv1.NewCoordinatorServiceClient(conn)
	_, err = client.Heartbeat(context.Background(), heartbeat(machineA))
	assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
	stream, err := client.StreamLogs(context.Background())
	require.NoError(t, err)
	_, err = stream.CloseAndRecv()
	assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
	assert.Zero(t, reached.Load())
}

func TestAHubThatCannotBeReachedIsUnavailable(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	url := gone.URL
	gone.Close()
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: url, Credentials: &staticAuth{token: tokenA}})
	require.NoError(t, err)
	client := coordinatorv1.NewCoordinatorServiceClient(conn)
	_, err = client.Heartbeat(context.Background(), heartbeat(machineA))
	assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
	stream, err := client.StreamLogs(context.Background())
	require.NoError(t, err)
	if sendErr := stream.Send(chunk(machineA)); sendErr != nil {
		require.ErrorIs(t, sendErr, io.EOF)
	}
	_, err = stream.CloseAndRecv()
	assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
}

func TestACredentialThatCannotBeHadSendsNothing(t *testing.T) {
	var reached atomic.Int64
	hub := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer hub.Close()
	refusal := status.Error(codes.Unavailable, "provider down")
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: hub.URL, Credentials: &staticAuth{err: refusal}})
	require.NoError(t, err)
	client := coordinatorv1.NewCoordinatorServiceClient(conn)
	_, err = client.Heartbeat(context.Background(), heartbeat(machineA))
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = client.StreamLogs(context.Background())
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Zero(t, reached.Load())
}

func TestABaseURLIsRefusedBeforeACredentialCanLeak(t *testing.T) {
	for _, base := range []string{
		"http://hub.example", "ftp://127.0.0.1", "https://user:pw@hub.example", "https://hub.example?x=1",
		"https://hub.example#frag", "hub.example", "http://127.0.0.1.hub.example",
	} {
		_, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: base, Credentials: &staticAuth{token: tokenA}})
		assert.Error(t, err, base)
	}
}

func realLogHandler(t *testing.T) (string, coordinatorv1.CoordinatorServiceClient) {
	t.Helper()
	dir := t.TempDir()
	ids := newIdentities()
	auth, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode: authz.ModeEnforce, Verifier: ids, Machines: ids, MachinesOnly: true,
	})
	require.NoError(t, err)
	handler, err := workerchannel.NewHandler(workerchannel.Config{
		Auth: auth, Health: health.NewServer(),
		Coordinator: coordinator.NewHandler(coordinator.HandlerConfig{LogDir: dir}),
	})
	require.NoError(t, err)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: server.URL, Credentials: &staticAuth{token: tokenA}})
	require.NoError(t, err)
	return dir, coordinatorv1.NewCoordinatorServiceClient(conn)
}

func realChunk(offset uint64, data string, final bool) *coordinatorv1.LogChunk {
	c := &coordinatorv1.LogChunk{
		WorkerId: machineA, DagName: "dag", DagRunId: "run", AttemptId: "attempt", StepName: "step",
		RootDagRunName: "dag", RootDagRunId: "run", StreamType: coordinatorv1.LogStreamType_LOG_STREAM_TYPE_STDOUT,
		Data: []byte(data), IsFinal: final,
	}
	c.SetByteOffset(offset)
	return c
}

func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	require.NoError(t, filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			found = append(found, path)
		}
		return err
	}))
	return found
}

// The hub's real log handler, reached through the channel: a checkpointed log
// resumes on a new request, which is how a worker's log writer already works.
func TestARealLogHandlerResumesOnANewRequest(t *testing.T) {
	dir, client := realLogHandler(t)
	send := func(offset uint64, data string) {
		stream, err := client.StreamLogs(context.Background())
		require.NoError(t, err)
		require.NoError(t, stream.Send(realChunk(offset, data, false)))
		_, err = stream.CloseAndRecv()
		require.NoError(t, err)
	}
	send(0, "first ")
	send(6, "second")
	found := filesUnder(t, dir)
	require.Len(t, found, 1)
	data, err := os.ReadFile(filepath.Clean(found[0]))
	require.NoError(t, err)
	assert.Equal(t, "first second", string(data))
}

// The transport a worker really uses: TLS and HTTP/2, a stream's body written
// while the request is open.
func TestOverTLSAndHTTP2(t *testing.T) {
	ids := newIdentities()
	auth, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode: authz.ModeEnforce, Verifier: ids, Machines: ids, MachinesOnly: true,
	})
	require.NoError(t, err)
	svc := &service{task: make(chan *coordinatorv1.Task, 1)}
	handler, err := workerchannel.NewHandler(workerchannel.Config{Auth: auth, Coordinator: svc, Health: health.NewServer()})
	require.NoError(t, err)
	var protocol atomic.Value
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protocol.Store(r.Proto)
		handler.ServeHTTP(w, r)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{
		BaseURL: server.URL, Credentials: &staticAuth{token: tokenA}, HTTP: server.Client(),
	})
	require.NoError(t, err)
	client := coordinatorv1.NewCoordinatorServiceClient(conn)
	_, err = client.Heartbeat(context.Background(), heartbeat(machineA))
	require.NoError(t, err)
	assert.Equal(t, "HTTP/2.0", protocol.Load())

	received := make(chan int, 2)
	svc.onChunk = func(n int) { received <- n }
	stream, err := client.StreamLogs(context.Background())
	require.NoError(t, err)
	require.NoError(t, stream.Send(chunk(machineA)))
	select {
	case n := <-received:
		// The first chunk arrived while the request was still open.
		assert.Equal(t, 1, n)
	case <-time.After(5 * time.Second):
		t.Fatal("the chunk did not arrive while the stream was open")
	}
	require.NoError(t, stream.Send(chunk(machineA)))
	resp, err := stream.CloseAndRecv()
	require.NoError(t, err)
	assert.EqualValues(t, 2, resp.GetChunksReceived())
}
