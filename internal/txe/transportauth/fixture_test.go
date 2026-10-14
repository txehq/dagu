// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

const (
	testIssuer   = "https://issuer.example/realms/test"
	testAudience = "dagu-hub"
	keyID        = "k1"

	ownerA    = "own_A"
	ownerB    = "own_B"
	machineA1 = "mch_A1"
	machineA2 = "mch_A2"
	machineB1 = "mch_B1"

	// One provider client per machine and class.
	clientA1Worker   = "dagu-worker-mch_A1"
	clientA2Worker   = "dagu-worker-mch_A2"
	clientB1Worker   = "dagu-worker-mch_B1"
	clientA1Reviewer = "dagu-reviewer-mch_A1"
	clientCLI        = "dagu-cli"

	subjectA = "subject-a"
	subjectB = "subject-b"
)

var testHubKey = []byte("0123456789abcdef0123456789abcdef-hub-key")

// registry is the registry's answer to what authz asks: which owners exist and
// whose each machine is.
type registry struct {
	machines map[string]string
}

func (r *registry) OwnerExists(_ context.Context, ownerID string) (bool, error) {
	return ownerID == ownerA || ownerID == ownerB, nil
}

func (r *registry) JobFacts(context.Context, string) (authz.JobFacts, error) {
	return authz.JobFacts{}, authz.ErrNotFound
}

func (r *registry) ProjectOwner(context.Context, string) (string, error) {
	return "", authz.ErrNotFound
}

func (r *registry) MachineOwner(_ context.Context, machineID string) (string, error) {
	owner, ok := r.machines[machineID]
	if !ok {
		return "", authz.ErrNotFound
	}
	return owner, nil
}

// provider is an in-process identity provider: it signs access tokens the way
// the real one does, with a key the verifier is given.
type provider struct {
	t   *testing.T
	key *rsa.PrivateKey
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &provider{t: t, key: key}
}

func (p *provider) keys() authn.StaticKeys {
	return authn.StaticKeys{keyID: {Public: &p.key.PublicKey, Algorithm: "RS256"}}
}

type tokenSpec struct {
	subject  string
	client   string
	issuedAt time.Time
	lifetime time.Duration
	issuer   string
	audience string
}

func (p *provider) sign(spec tokenSpec) string {
	p.t.Helper()
	if spec.issuer == "" {
		spec.issuer = testIssuer
	}
	if spec.audience == "" {
		spec.audience = testAudience
	}
	if spec.lifetime == 0 {
		spec.lifetime = 5 * time.Minute
	}
	iat := spec.issuedAt.Truncate(time.Second)
	claims := jwt.MapClaims{
		"iss": spec.issuer,
		"sub": spec.subject,
		"aud": spec.audience,
		"azp": spec.client,
		"typ": "Bearer",
		"iat": iat.Unix(),
		"exp": iat.Add(spec.lifetime).Unix(),
		"sid": "session-shared-by-every-machine",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	signed, err := token.SignedString(p.key)
	require.NoError(p.t, err)
	return signed
}

// clock is a hand-moved clock shared by the verifier, the store and the
// interceptors.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// keysDown is a key source whose issuer cannot be reached.
type keysDown struct{}

func (keysDown) Key(context.Context, string) (authn.Key, error) {
	return authn.Key{}, &authn.Error{Reason: authn.ReasonKeysUnavailable}
}

// fixture is a coordinator stub behind the interceptors, an authz store on
// real files, and a provider that signs tokens.
type fixture struct {
	t        *testing.T
	provider *provider
	clock    *clock
	store    *authz.Store
	verifier *authn.Verifier
	service  *recordingService
	listener *bufconn.Listener

	mu        sync.Mutex
	decisions []transportauth.Decision
}

type fixtureOptions struct {
	mode      transportauth.Mode
	keys      authn.KeySource
	resources transportauth.ResourceAuthorizer
}

func newFixture(t *testing.T, opts fixtureOptions) *fixture {
	t.Helper()
	if opts.mode == "" {
		opts.mode = authz.ModeEnforce
	}
	f := &fixture{
		t:        t,
		provider: newProvider(t),
		clock:    &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)},
		service:  &recordingService{},
	}
	if opts.keys == nil {
		opts.keys = f.provider.keys()
	}
	reg := &registry{machines: map[string]string{machineA1: ownerA, machineA2: ownerA, machineB1: ownerB}}
	store, err := authz.NewFileStore(t.TempDir(), reg, authz.WithClock(f.clock.Now))
	require.NoError(t, err)
	f.store = store

	verifier, err := authn.NewVerifier(authn.Config{
		Issuer:   testIssuer,
		Audience: testAudience,
		Clients: map[string]authn.Class{
			clientA1Worker:   authn.ClassWorker,
			clientA2Worker:   authn.ClassWorker,
			clientB1Worker:   authn.ClassWorker,
			clientA1Reviewer: authn.ClassReviewer,
			clientCLI:        authn.ClassCLI,
		},
		Keys: opts.keys,
		Now:  f.clock.Now,
	})
	require.NoError(t, err)
	f.verifier = verifier

	server, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode:      opts.mode,
		Verifier:  verifier,
		Machines:  store,
		HubKey:    testHubKey,
		Resources: opts.resources,
		Observe: func(_ context.Context, d transportauth.Decision) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.decisions = append(f.decisions, d)
		},
		Now: f.clock.Now,
	})
	require.NoError(t, err)

	f.listener = bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(server.UnaryInterceptor()),
		grpc.StreamInterceptor(server.StreamInterceptor()),
	)
	coordinatorv1.RegisterCoordinatorServiceServer(grpcServer, f.service)
	grpc_health_v1.RegisterHealthServer(grpcServer, health.NewServer())
	go func() { _ = grpcServer.Serve(f.listener) }()
	t.Cleanup(grpcServer.Stop)
	return f
}

// bindAndEnrol binds subject to owner and enrols a worker credential of
// client for machine.
func (f *fixture) bindAndEnrol(subject, owner, client, machine string) {
	f.t.Helper()
	ctx := context.Background()
	person := authn.Principal{Identity: authn.Identity{Issuer: testIssuer, Subject: subject}, Class: authn.ClassPerson}
	scope, err := f.store.Resolve(ctx, person)
	require.NoError(f.t, err)
	if scope.Kind() != authz.ScopeOwner {
		_, err = f.store.RequestBinding(ctx, person, authz.Shown{Username: subject})
		require.NoError(f.t, err)
		_, err = f.store.ApproveBinding(ctx, authz.PlatformAdmin("admin"), person.Identity, owner)
		require.NoError(f.t, err)
		scope, err = f.store.Resolve(ctx, person)
		require.NoError(f.t, err)
	}
	credential, err := f.verifier.Verify(ctx, f.token(subject, client))
	require.NoError(f.t, err)
	_, err = f.store.Enrol(ctx, scope, authz.EnrolmentRequest{MachineID: machine, Credential: credential})
	require.NoError(f.t, err)
}

func (f *fixture) revokeEnrolment(subject, machine string) {
	f.t.Helper()
	ctx := context.Background()
	person := authn.Principal{Identity: authn.Identity{Issuer: testIssuer, Subject: subject}, Class: authn.ClassPerson}
	scope, err := f.store.Resolve(ctx, person)
	require.NoError(f.t, err)
	_, err = f.store.RevokeEnrolment(ctx, scope, machine, authn.ClassWorker, "test")
	require.NoError(f.t, err)
}

func (f *fixture) token(subject, client string) string {
	return f.provider.sign(tokenSpec{subject: subject, client: client, issuedAt: f.clock.Now()})
}

// dial connects to the coordinator stub as a caller that sends credential as
// it is, with no transport security, to a loopback authority.
func (f *fixture) dial(opts ...grpc.DialOption) coordinatorv1.CoordinatorServiceClient {
	f.t.Helper()
	conn := f.conn(opts...)
	return coordinatorv1.NewCoordinatorServiceClient(conn)
}

func (f *fixture) conn(opts ...grpc.DialOption) *grpc.ClientConn {
	f.t.Helper()
	base := []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return f.listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority("127.0.0.1:50055"),
	}
	conn, err := grpc.NewClient("passthrough:///bufnet", append(base, opts...)...)
	require.NoError(f.t, err)
	f.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// bearer is a TokenSource that always gives the same credential.
type bearer string

func (b bearer) Token(context.Context) (string, error) { return string(b), nil }

func (f *fixture) worker(token string) coordinatorv1.CoordinatorServiceClient {
	return f.dial(grpc.WithPerRPCCredentials(transportauth.NewWorkerCredentials(bearer(token))))
}

func (f *fixture) hub(key []byte) coordinatorv1.CoordinatorServiceClient {
	return f.dial(grpc.WithPerRPCCredentials(transportauth.NewHubCredentials(key)))
}

func (f *fixture) lastDecision() transportauth.Decision {
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(f.t, f.decisions)
	return f.decisions[len(f.decisions)-1]
}

// recordingService is a coordinator that answers every call and records the
// caller the interceptors established.
type recordingService struct {
	coordinatorv1.UnimplementedCoordinatorServiceServer

	mu      sync.Mutex
	callers []transportauth.Caller
	chunks  int
	// bundleChunks is how many chunks GetWorkspaceBundle sends (one when
	// zero); beforeChunk runs before each.
	bundleChunks int
	beforeChunk  func(i int)
}

func (s *recordingService) setBundle(chunks int, beforeChunk func(i int)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundleChunks, s.beforeChunk = chunks, beforeChunk
}

func (s *recordingService) record(ctx context.Context) {
	caller, _ := transportauth.CallerFrom(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callers = append(s.callers, caller)
}

func (s *recordingService) lastCaller() transportauth.Caller {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.callers) == 0 {
		return transportauth.Caller{}
	}
	return s.callers[len(s.callers)-1]
}

func (s *recordingService) received() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chunks
}

func (s *recordingService) Poll(ctx context.Context, _ *coordinatorv1.PollRequest) (*coordinatorv1.PollResponse, error) {
	s.record(ctx)
	return &coordinatorv1.PollResponse{}, nil
}

func (s *recordingService) Heartbeat(ctx context.Context, _ *coordinatorv1.HeartbeatRequest) (*coordinatorv1.HeartbeatResponse, error) {
	s.record(ctx)
	return &coordinatorv1.HeartbeatResponse{}, nil
}

func (s *recordingService) RunHeartbeat(ctx context.Context, _ *coordinatorv1.RunHeartbeatRequest) (*coordinatorv1.RunHeartbeatResponse, error) {
	s.record(ctx)
	return &coordinatorv1.RunHeartbeatResponse{}, nil
}

func (s *recordingService) Dispatch(ctx context.Context, _ *coordinatorv1.DispatchRequest) (*coordinatorv1.DispatchResponse, error) {
	s.record(ctx)
	return &coordinatorv1.DispatchResponse{}, nil
}

func (s *recordingService) GetDAG(ctx context.Context, _ *coordinatorv1.GetDAGRequest) (*coordinatorv1.GetDAGResponse, error) {
	s.record(ctx)
	return &coordinatorv1.GetDAGResponse{}, nil
}

func (s *recordingService) StreamLogs(stream coordinatorv1.CoordinatorService_StreamLogsServer) error {
	s.record(stream.Context())
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&coordinatorv1.StreamLogsResponse{})
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.chunks++
		s.mu.Unlock()
	}
}

func (s *recordingService) GetWorkspaceBundle(_ *coordinatorv1.GetWorkspaceBundleRequest, stream coordinatorv1.CoordinatorService_GetWorkspaceBundleServer) error {
	s.record(stream.Context())
	s.mu.Lock()
	chunks, beforeChunk := max(s.bundleChunks, 1), s.beforeChunk
	s.mu.Unlock()
	for i := range chunks {
		if beforeChunk != nil {
			beforeChunk(i)
		}
		if err := stream.Send(&coordinatorv1.WorkspaceBundleChunk{}); err != nil {
			return err
		}
	}
	return nil
}
