// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package workerchannel_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"maps"
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
	server := httptest.NewServer(handler)
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

// rawCall sends a request no Conn would send, and returns its status code.
func rawCall(t *testing.T, url, method string, headers map[string][]string, body []byte) codes.Code {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+method, bytes.NewReader(body))
	require.NoError(t, err)
	maps.Copy(req.Header, headers)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, workerchannel.ChannelVersion, resp.Header.Get(workerchannel.HeaderChannel))
	code, err := strconv.Atoi(resp.Header.Get(workerchannel.HeaderCode))
	require.NoError(t, err)
	return codes.Code(code) // #nosec G115 -- a test's own response
}

func TestTheRouteIsNeverAnOpenDoor(t *testing.T) {
	hubKey := strings.Repeat("k", 40)
	cases := []struct {
		name    string
		method  string
		headers map[string][]string
		code    codes.Code
	}{
		{"no credential", coordinatorv1.CoordinatorService_Heartbeat_FullMethodName, nil, codes.Unauthenticated},
		{"no credential on health", grpc_health_v1.Health_Check_FullMethodName, nil, codes.Unauthenticated},
		{"two credentials", coordinatorv1.CoordinatorService_Heartbeat_FullMethodName,
			map[string][]string{"Authorization": {"Bearer " + tokenA, "Bearer " + tokenB}}, codes.Unauthenticated},
		{"the hub scheme", coordinatorv1.CoordinatorService_Dispatch_FullMethodName,
			map[string][]string{"Authorization": {"TXE-Hub " + hubKey}}, codes.Unauthenticated},
		{"a hub-only method", coordinatorv1.CoordinatorService_Dispatch_FullMethodName,
			map[string][]string{"Authorization": {"Bearer " + tokenA}}, codes.PermissionDenied},
		{"a resource with no authorizer", coordinatorv1.CoordinatorService_GetWorkspaceBundle_FullMethodName,
			map[string][]string{"Authorization": {"Bearer " + tokenA}}, codes.Unimplemented},
		{"a method nobody listed", "/coordinator.v1.CoordinatorService/Nope",
			map[string][]string{"Authorization": {"Bearer " + tokenA}}, codes.PermissionDenied},
		{"another service", "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
			map[string][]string{"Authorization": {"Bearer " + tokenA}}, codes.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, workerchannel.Limits{})
			assert.Equal(t, tc.code, rawCall(t, h.server.URL, tc.method, tc.headers, nil))
			assert.Zero(t, h.service.calls.Load())
		})
	}
}

func TestHealthAnswersAnEnrolledMachine(t *testing.T) {
	h := newHarness(t, workerchannel.Limits{})
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{
		BaseURL: h.server.URL, Credentials: &staticAuth{token: tokenA},
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

func TestAStreamCutShortIsNotAFinishedStream(t *testing.T) {
	h := newHarness(t, workerchannel.Limits{})
	message, err := proto.Marshal(chunk(machineA))
	require.NoError(t, err)
	var body bytes.Buffer
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(len(message)))) // #nosec G115 -- a test's own message
	body.Write(message)
	// A body that ends cleanly at a frame boundary, with no end frame.
	assert.NotEqual(t, codes.OK, rawCall(t, h.server.URL, coordinatorv1.CoordinatorService_StreamLogs_FullMethodName,
		map[string][]string{"Authorization": {"Bearer " + tokenA}}, body.Bytes()))
}

func TestSizeLimits(t *testing.T) {
	limits := workerchannel.DefaultLimits()
	limits.MaxMessageBytes = 1024
	limits.MaxStreamBytes = 4096
	h := newHarness(t, limits)

	huge := heartbeat(machineA)
	huge.Labels["padding"] = strings.Repeat("x", 2048)
	resp := func() codes.Code {
		data, err := proto.Marshal(huge)
		require.NoError(t, err)
		return rawCall(t, h.server.URL, coordinatorv1.CoordinatorService_Heartbeat_FullMethodName,
			map[string][]string{"Authorization": {"Bearer " + tokenA}}, data)
	}()
	assert.Equal(t, codes.ResourceExhausted, resp)
	assert.Zero(t, h.service.calls.Load())

	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{
		BaseURL: h.server.URL, Credentials: &staticAuth{token: tokenA}, Limits: limits,
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
	for _, code := range []int{http.StatusForbidden, http.StatusUnauthorized, http.StatusBadGateway, 524} {
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

func TestAStatusWithoutTheChannelMarkIsNotBelieved(t *testing.T) {
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(workerchannel.HeaderCode, strconv.Itoa(int(codes.Unauthenticated)))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer edge.Close()
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: edge.URL, Credentials: &staticAuth{token: tokenA}})
	require.NoError(t, err)
	_, err = coordinatorv1.NewCoordinatorServiceClient(conn).Heartbeat(context.Background(), heartbeat(machineA))
	assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
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

// The hub's real log handler, reached through the channel: a checkpointed log
// resumes on a new request, which is how a worker's log writer already works.
func TestARealLogHandlerResumesOnANewRequest(t *testing.T) {
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
	defer server.Close()
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: server.URL, Credentials: &staticAuth{token: tokenA}})
	require.NoError(t, err)
	client := coordinatorv1.NewCoordinatorServiceClient(conn)

	send := func(offset uint64, data string, final bool) {
		stream, err := client.StreamLogs(context.Background())
		require.NoError(t, err)
		c := &coordinatorv1.LogChunk{
			WorkerId: machineA, DagName: "dag", DagRunId: "run", AttemptId: "attempt", StepName: "step",
			RootDagRunName: "dag", RootDagRunId: "run", StreamType: coordinatorv1.LogStreamType_LOG_STREAM_TYPE_STDOUT,
			Data: []byte(data), IsFinal: final,
		}
		c.SetByteOffset(offset)
		require.NoError(t, stream.Send(c))
		_, err = stream.CloseAndRecv()
		require.NoError(t, err)
	}
	send(0, "first ", false)
	send(6, "second", false)

	var found []string
	require.NoError(t, filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			found = append(found, path)
		}
		return err
	}))
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
