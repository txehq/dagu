// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/service/worker"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

const (
	authTestIssuer   = "https://issuer.example/realms/test"
	authTestAudience = "dagu-hub"
	authTestSubject  = "owner-subject"
)

// authTestProvider signs access tokens with a key the coordinator is given.
type authTestProvider struct {
	t   *testing.T
	key *rsa.PrivateKey
}

func (p *authTestProvider) keys() authn.StaticKeys {
	return authn.StaticKeys{"k1": {Public: &p.key.PublicKey, Algorithm: "RS256"}}
}

func (p *authTestProvider) token(client string) string {
	p.t.Helper()
	now := time.Now().Truncate(time.Second)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": authTestIssuer, "sub": authTestSubject, "aud": authTestAudience, "azp": client,
		"typ": "Bearer", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(p.key)
	require.NoError(p.t, err)
	return signed
}

// tokenEndpoint answers a machine's refresh with a token for its client.
func (p *authTestProvider) tokenEndpoint(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": p.token(r.Form.Get("client_id")), "token_type": "Bearer", "expires_in": 300,
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/token"
}

// authTestCoordinator records the callers the interceptors let through.
type authTestCoordinator struct {
	coordinatorv1.UnimplementedCoordinatorServiceServer
	mu      sync.Mutex
	callers []transportauth.Caller
}

func (s *authTestCoordinator) record(ctx context.Context) {
	caller, _ := transportauth.CallerFrom(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callers = append(s.callers, caller)
}

func (s *authTestCoordinator) last() transportauth.Caller {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.callers) == 0 {
		return transportauth.Caller{}
	}
	return s.callers[len(s.callers)-1]
}

func (s *authTestCoordinator) Heartbeat(ctx context.Context, _ *coordinatorv1.HeartbeatRequest) (*coordinatorv1.HeartbeatResponse, error) {
	s.record(ctx)
	return &coordinatorv1.HeartbeatResponse{}, nil
}

func (s *authTestCoordinator) GetDAGRunStatus(ctx context.Context, _ *coordinatorv1.GetDAGRunStatusRequest) (*coordinatorv1.GetDAGRunStatusResponse, error) {
	s.record(ctx)
	return &coordinatorv1.GetDAGRunStatusResponse{}, nil
}

func (s *authTestCoordinator) GetWorkers(ctx context.Context, _ *coordinatorv1.GetWorkersRequest) (*coordinatorv1.GetWorkersResponse, error) {
	s.record(ctx)
	return &coordinatorv1.GetWorkersResponse{}, nil
}

type authTestHub struct {
	cfg      *config.Config
	provider *authTestProvider
	service  *authTestCoordinator
	addr     string
	machine  string
	owner    string
}

// newAuthTestHub makes a registry with one owner and one machine, binds the
// owner's identity, enrols the machine's worker client, and starts a
// coordinator gRPC server with the options the coordinator command installs.
func newAuthTestHub(t *testing.T, mode string) *authTestHub {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the hub key and machine credential are refused on Windows")
	}
	ctx := context.Background()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &authTestProvider{t: t, key: key}

	reg, err := registry.NewFileStore(dir)
	require.NoError(t, err)
	owner, err := registry.NewID(registry.PrefixOwner, time.Now())
	require.NoError(t, err)
	machine, err := registry.NewID(registry.PrefixMachine, time.Now())
	require.NoError(t, err)
	by := registry.Actor{Kind: registry.ActorSystem, ID: "test"}
	_, err = reg.CreateOwner(ctx, registry.Owner{OwnerID: owner, DisplayName: "Owner"}, by)
	require.NoError(t, err)
	_, err = reg.CreateMachine(ctx, registry.Machine{MachineID: machine, OwnerID: owner, DisplayName: "Linux"}, by)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.Paths.DataDir = dir
	cfg.Coordinator.Enabled = true
	cfg.Coordinator.Auth = config.CoordinatorAuth{Mode: mode}
	cfg.Core.Peer.Insecure = true
	cfg.TXE.Authn = config.TXEAuthnConfig{
		Issuer: authTestIssuer, Audience: authTestAudience, JWKSURL: "https://issuer.example/unused",
		Clients: []config.TXEAuthnClient{
			{ID: "dagu-worker-" + machine, Class: "worker"},
			{ID: "dagu-worker-other", Class: "worker"},
		},
	}

	// The binding and the enrolment, as the owner and the administrator make
	// them through the hub.
	svc, err := txeauth.NewService(cfg.TXE, dir, reg, txeauth.WithKeySource(p.keys()))
	require.NoError(t, err)
	person := authn.Principal{Identity: authn.Identity{Issuer: authTestIssuer, Subject: authTestSubject}, Class: authn.ClassPerson}
	_, err = svc.Store().RequestBinding(ctx, person, authz.Shown{Username: "owner"})
	require.NoError(t, err)
	_, err = svc.Store().ApproveBinding(ctx, authz.PlatformAdmin("admin"), person.Identity, owner)
	require.NoError(t, err)
	scope, err := svc.Store().Resolve(ctx, person)
	require.NoError(t, err)
	credential, err := svc.Verify(ctx, p.token("dagu-worker-"+machine))
	require.NoError(t, err)
	_, err = svc.Store().Enrol(ctx, scope, authz.EnrolmentRequest{MachineID: machine, Credential: credential})
	require.NoError(t, err)

	opts, err := coordinatorAuthOptions(ctx, cfg, "127.0.0.1", txeauth.WithKeySource(p.keys()))
	require.NoError(t, err)
	require.Len(t, opts, 2)

	service := &authTestCoordinator{}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer(opts...)
	coordinatorv1.RegisterCoordinatorServiceServer(server, service)
	// The coordinator command registers health too, and clients check it
	// before they call; it is public.
	grpc_health_v1.RegisterHealthServer(server, health.NewServer())
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	return &authTestHub{cfg: cfg, provider: p, service: service, addr: lis.Addr().String(), machine: machine, owner: owner}
}

// hubClient is the client a hub process builds.
func (h *authTestHub) hubClient(t *testing.T) coordinator.Client {
	t.Helper()
	creds, err := hubCoordinatorCredentials(h.cfg)
	require.NoError(t, err)
	clientConfig := coordinator.ConfigFromPeer(h.cfg.Core.Peer)
	clientConfig.Credentials = creds
	reg, err := coordinator.NewStaticRegistry([]string{h.addr})
	require.NoError(t, err)
	return coordinator.New(reg, clientConfig)
}

// workerClient is the client the worker command builds from the same
// configuration, with credentialFile as its machine credential.
func (h *authTestHub) workerClient(t *testing.T, credentialFile string) coordinator.Client {
	t.Helper()
	cfg := *h.cfg
	cfg.Worker.Coordinators = []string{h.addr}
	cfg.Worker.Auth.CredentialFile = credentialFile
	client, err := worker.NewCoordinatorClient(context.Background(), &cfg)
	require.NoError(t, err)
	return client
}

func (h *authTestHub) credentialFile(t *testing.T, client, machine string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "machine.json")
	require.NoError(t, transportauth.WriteMachineCredential(path, transportauth.MachineCredential{
		Schema: transportauth.CredentialSchema, Issuer: authTestIssuer, TokenEndpoint: h.provider.tokenEndpoint(t),
		ClientID: client, Class: authn.ClassWorker, MachineID: machine, RefreshToken: "offline",
	}))
	return path
}

func heartbeat(machine string) *coordinatorv1.HeartbeatRequest {
	return &coordinatorv1.HeartbeatRequest{WorkerId: machine, Labels: map[string]string{"txe.machine": machine}}
}

func grpcCode(t *testing.T, err error) codes.Code {
	t.Helper()
	require.Error(t, err)
	for e := err; e != nil; {
		if st, ok := status.FromError(e); ok && st.Code() != codes.Unknown {
			return st.Code()
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return codes.Unknown
}

func TestCoordinatorAuthOffInstallsNothingAndSendsNothing(t *testing.T) {
	for _, mode := range []string{"", config.TXEAuthzModeOff} {
		cfg := &config.Config{}
		cfg.Paths.DataDir = t.TempDir()
		cfg.Coordinator.Auth.Mode = mode
		opts, err := coordinatorAuthOptions(context.Background(), cfg, "dagu-hub.example")
		require.NoError(t, err)
		assert.Nil(t, opts)
		creds, err := hubCoordinatorCredentials(cfg)
		require.NoError(t, err)
		assert.Nil(t, creds)
	}
}

func TestCoordinatorAuthNeedsProviderTokenSettings(t *testing.T) {
	cfg := &config.Config{}
	cfg.Paths.DataDir = t.TempDir()
	cfg.Coordinator.Auth.Mode = config.TXEAuthzModeEnforce
	_, err := coordinatorAuthOptions(context.Background(), cfg, "127.0.0.1")
	require.ErrorContains(t, err, "txe.authn is not configured")

	cfg.Paths.DataDir = ""
	_, err = coordinatorAuthOptions(context.Background(), cfg, "127.0.0.1")
	require.ErrorContains(t, err, "data directory")
}

func TestCoordinatorAuthWithoutTLSNeedsALoopbackAdvertisement(t *testing.T) {
	for _, mode := range []string{config.TXEAuthzModeObserve, config.TXEAuthzModeEnforce} {
		cfg := &config.Config{}
		cfg.Paths.DataDir = t.TempDir()
		cfg.Coordinator.Auth.Mode = mode
		for _, advertise := range []string{"", "dagu-hub", "dagu-hub.example", "10.0.0.7", "[::ffff:10.0.0.7]"} {
			_, err := coordinatorAuthOptions(context.Background(), cfg, advertise)
			require.ErrorContains(t, err, "loopback", "mode %s, advertise %q", mode, advertise)
		}
		// A loopback advertisement passes this check and fails on the
		// next, the missing provider settings.
		for _, advertise := range []string{"127.0.0.1", "localhost", "::1"} {
			_, err := coordinatorAuthOptions(context.Background(), cfg, advertise)
			require.ErrorContains(t, err, "txe.authn is not configured", advertise)
		}
		// With TLS the credential may go to a named host.
		cfg.Core.Peer.CertFile, cfg.Core.Peer.KeyFile = "/etc/dagu/tls.crt", "/etc/dagu/tls.key"
		_, err := coordinatorAuthOptions(context.Background(), cfg, "dagu-hub.example")
		require.ErrorContains(t, err, "txe.authn is not configured")
	}
}

func TestEnforcedCoordinatorLetsInTheHubAndTheEnrolledMachineOnly(t *testing.T) {
	h := newAuthTestHub(t, config.TXEAuthzModeEnforce)
	ctx := context.Background()

	t.Run("the hub, by its key", func(t *testing.T) {
		_, err := h.hubClient(t).GetWorkers(ctx)
		require.NoError(t, err)
		assert.Equal(t, transportauth.CallerHub, h.service.last().Kind)
	})

	t.Run("the enrolled machine, by its credential", func(t *testing.T) {
		client := h.workerClient(t, h.credentialFile(t, "dagu-worker-"+h.machine, h.machine))
		_, err := client.Heartbeat(ctx, heartbeat(h.machine))
		require.NoError(t, err)
		caller := h.service.last()
		assert.Equal(t, transportauth.CallerMachine, caller.Kind)
		assert.Equal(t, h.machine, caller.Machine.MachineID)
		assert.Equal(t, h.owner, caller.Machine.OwnerID)
	})

	t.Run("the enrolled machine naming another machine", func(t *testing.T) {
		client := h.workerClient(t, h.credentialFile(t, "dagu-worker-"+h.machine, h.machine))
		_, err := client.Heartbeat(ctx, heartbeat("mch_someone_else"))
		assert.Equal(t, codes.PermissionDenied, grpcCode(t, err))
	})

	t.Run("a credential of a client never enrolled", func(t *testing.T) {
		client := h.workerClient(t, h.credentialFile(t, "dagu-worker-other", h.machine))
		_, err := client.Heartbeat(ctx, heartbeat(h.machine))
		assert.Equal(t, codes.Unauthenticated, grpcCode(t, err))
	})

	t.Run("a worker with no credential is not the hub", func(t *testing.T) {
		// Same configuration as the hub, coordinator.auth on and the hub key
		// on disk; only the purpose differs. The worker presents nothing.
		client := h.workerClient(t, "")
		_, err := client.Heartbeat(ctx, heartbeat(h.machine))
		assert.Equal(t, codes.Unauthenticated, grpcCode(t, err))
	})

	t.Run("a child workflow dispatched by a hub run", func(t *testing.T) {
		// The dispatcher a run's child workflows go through, built as
		// Context.SubWorkflowRunnerFactory builds it.
		creds, err := hubCoordinatorCredentials(h.cfg)
		require.NoError(t, err)
		reg, err := coordinator.NewStaticRegistry([]string{h.addr})
		require.NoError(t, err)
		dispatcher, err := coordinator.NewRuntimeDispatcher(reg, h.cfg.Core.Peer, "", creds)
		require.NoError(t, err)
		_, err = dispatcher.GetDAGRunStatus(ctx, "child", "run-1", nil)
		require.NoError(t, err)
		assert.Equal(t, transportauth.CallerHub, h.service.last().Kind)

		unauthenticated, err := coordinator.NewRuntimeDispatcher(reg, h.cfg.Core.Peer, "", nil)
		require.NoError(t, err)
		_, err = unauthenticated.GetDAGRunStatus(ctx, "child", "run-1", nil)
		assert.Equal(t, codes.Unauthenticated, grpcCode(t, err))
	})

	t.Run("a hub process with the wrong key", func(t *testing.T) {
		clientConfig := coordinator.ConfigFromPeer(h.cfg.Core.Peer)
		clientConfig.Credentials = transportauth.NewHubCredentials([]byte("0000000000000000000000000000000000000000000000000000000000000000"))
		reg, err := coordinator.NewStaticRegistry([]string{h.addr})
		require.NoError(t, err)
		_, err = coordinator.New(reg, clientConfig).GetWorkers(ctx)
		assert.Equal(t, codes.Unauthenticated, grpcCode(t, err))
	})
}

func TestObservingCoordinatorStillServesEveryone(t *testing.T) {
	h := newAuthTestHub(t, config.TXEAuthzModeObserve)
	_, err := h.workerClient(t, "").Heartbeat(context.Background(), heartbeat(h.machine))
	require.NoError(t, err)
	assert.Equal(t, transportauth.CallerNone, h.service.last().Kind)
}

func TestWorkerIdentityMustNameTheEnrolledMachine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the machine credential is refused on Windows")
	}
	path := filepath.Join(t.TempDir(), "machine.json")
	require.NoError(t, transportauth.WriteMachineCredential(path, transportauth.MachineCredential{
		Schema: transportauth.CredentialSchema, Issuer: authTestIssuer, TokenEndpoint: "https://issuer.example/token",
		ClientID: "dagu-worker-mch_A", Class: authn.ClassWorker, MachineID: "mch_A", RefreshToken: "r",
	}))

	id, labels, err := machineWorkerIdentity(path, "", "host@42", map[string]string{"os": "linux"})
	require.NoError(t, err)
	assert.Equal(t, "mch_A@host@42", id, "an unnamed worker is named after its machine")
	assert.Equal(t, map[string]string{"os": "linux", "txe.machine": "mch_A"}, labels)

	id, _, err = machineWorkerIdentity(path, "mch_A", "mch_A", map[string]string{"txe.machine": "mch_A"})
	require.NoError(t, err)
	assert.Equal(t, "mch_A", id, "the laptop's configuration stands as it is")

	_, _, err = machineWorkerIdentity(path, "mch_B", "mch_B", nil)
	require.ErrorContains(t, err, "does not name machine mch_A")
	_, _, err = machineWorkerIdentity(path, "", "host@1", map[string]string{"txe.machine": "mch_B"})
	require.ErrorContains(t, err, "does not name machine mch_A")
	_, _, err = machineWorkerIdentity(filepath.Join(t.TempDir(), "missing.json"), "", "h", nil)
	require.ErrorContains(t, err, "enrol this machine again")

	original := map[string]string{"os": "linux"}
	_, _, err = machineWorkerIdentity(path, "", "h", original)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"os": "linux"}, original, "the configured labels are not changed in place")
}
