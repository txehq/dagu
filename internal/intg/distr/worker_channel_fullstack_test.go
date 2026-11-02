// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/service/frontend"
	"github.com/dagucloud/dagu/v2/internal/service/worker"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/channelhub"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// These tests put the worker channel where start-all puts it: built by the
// production builder from the hub's configuration, mounted on the real
// frontend server behind its middleware, with tokens a provider signs and the
// hub verifies by fetching its keys, and a machine enrolled through the real
// owner store. The worker uses the production client. Nothing here is an edge.

const stackAudience = "dagu-hub"

// stackProvider signs tokens for the clients it knows, and serves its keys and
// a token endpoint, as an identity provider does.
type stackProvider struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	mu       sync.Mutex
	subjects map[string]string
}

func newStackProvider(t testing.TB) *stackProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &stackProvider{key: key, subjects: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		token, err := p.sign(r.FormValue("client_id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 300})
	})
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *stackProvider) know(client, subject string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects[client] = subject
}

func (p *stackProvider) sign(client string) (string, error) {
	p.mu.Lock()
	subject, ok := p.subjects[client]
	p.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("unknown client %q", client)
	}
	now := time.Now().Truncate(time.Second)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": p.server.URL, "sub": subject, "aud": stackAudience, "azp": client,
		"typ": "Bearer", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	token.Header["kid"] = "k1"
	return token.SignedString(p.key)
}

func (p *stackProvider) authn() config.TXEAuthnConfig {
	return config.TXEAuthnConfig{Issuer: p.server.URL, Audience: stackAudience, JWKSURL: p.server.URL + "/jwks",
		Clients: []config.TXEAuthnClient{
			{ID: "dagu-cli", Class: "cli"},
			{ID: "dagu-worker-a", Class: "worker"},
			{ID: "dagu-worker-b", Class: "worker"},
		}}
}

// fullStack is the hub's frontend with the channel on it, and two enrolled
// machines of two owners: a, which runs the jobs, and b.
type fullStack struct {
	provider   *stackProvider
	machine    string
	other      string
	hubURL     string
	credential string
}

func newFullStack(t *testing.T) *fullStack {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a machine credential is refused on Windows")
	}
	mint := func(p registry.Prefix) string {
		id, err := registry.NewID(p, time.Now())
		require.NoError(t, err)
		return id
	}
	return &fullStack{provider: newStackProvider(t), machine: mint(registry.PrefixMachine), other: mint(registry.PrefixMachine)}
}

// enrol makes each machine's owner, binds a person to it, and enrols the
// machine's worker client, as the owner and the administrator do on a hub.
func (s *fullStack) enrol(t testing.TB, cfg *config.Config) {
	t.Helper()
	ctx := context.Background()
	reg, err := registry.NewFileStore(cfg.Paths.DataDir)
	require.NoError(t, err)
	svc, err := txeauth.NewService(cfg.TXE, cfg.Paths.DataDir, reg)
	require.NoError(t, err)
	system := registry.Actor{Kind: registry.ActorSystem, ID: "test"}
	for _, m := range []struct{ machine, client, subject string }{
		{s.machine, "dagu-worker-a", "person-a"}, {s.other, "dagu-worker-b", "person-b"},
	} {
		owner, err := registry.NewID(registry.PrefixOwner, time.Now())
		require.NoError(t, err)
		_, err = reg.CreateOwner(ctx, registry.Owner{OwnerID: owner, DisplayName: m.subject}, system)
		require.NoError(t, err)
		_, err = reg.CreateMachine(ctx, registry.Machine{MachineID: m.machine, OwnerID: owner, DisplayName: m.subject}, system)
		require.NoError(t, err)
		s.provider.know(m.client, m.subject)
		person := authn.Principal{Identity: authn.Identity{Issuer: s.provider.server.URL, Subject: m.subject}, Class: authn.ClassPerson}
		_, err = svc.Store().RequestBinding(ctx, person, authz.Shown{Username: m.subject})
		require.NoError(t, err)
		_, err = svc.Store().ApproveBinding(ctx, authz.PlatformAdmin("admin"), person.Identity, owner)
		require.NoError(t, err)
		scope, err := svc.Store().Resolve(ctx, person)
		require.NoError(t, err)
		token, err := s.provider.sign(m.client)
		require.NoError(t, err)
		credential, err := svc.Verify(ctx, token)
		require.NoError(t, err)
		_, err = svc.Store().Enrol(ctx, scope, authz.EnrolmentRequest{MachineID: m.machine, Credential: credential})
		require.NoError(t, err)
	}
	s.provider.know("dagu-cli", "person-a")
}

// serve builds the channel with the production builder on the coordinator's
// handler, and mounts it on a real frontend server with builtin auth.
func (s *fullStack) serve(t *testing.T, coord *test.Coordinator) {
	t.Helper()
	handler, err := channelhub.New(coord.Context, coord.Config, coord.Handler(), health.NewServer(), nil)
	require.NoError(t, err)
	server := test.SetupServer(t,
		test.WithServerOptions(frontend.WithRoutes(func(_ context.Context, r chi.Router, apiV1 string) { handler.Mount(r, apiV1) })),
		test.WithConfigMutator(func(cfg *config.Config) {
			cfg.Server.Auth.Mode = config.AuthModeBuiltin
			cfg.Server.Auth.Builtin.Token.Secret = "full-stack-test-secret"
			cfg.TXE.Authn = s.provider.authn()
		}))
	s.hubURL = fmt.Sprintf("http://%s:%d", server.Config.Server.Host, server.Config.Server.Port)
}

func (s *fullStack) credentialFile(t testing.TB, client, machine string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "worker-credential.json")
	require.NoError(t, transportauth.WriteMachineCredential(path, transportauth.MachineCredential{
		Schema: transportauth.CredentialSchema, Issuer: s.provider.server.URL, TokenEndpoint: s.provider.server.URL + "/token",
		ClientID: client, Class: authn.ClassWorker, MachineID: machine, RefreshToken: "offline",
	}))
	return path
}

// withFullStack runs the fixture's workers on the production client, over the
// channel on the real frontend server.
func withFullStack(s *fullStack) fixtureOption {
	return func(c *fixtureConfig) {
		c.workerLabels = map[string]string{txepkg.LabelMachine: s.machine}
		c.configMutators = append(c.configMutators, func(cfg *config.Config) { cfg.TXE.Authn = s.provider.authn() })
		c.workerChannel = func(tb testing.TB, coord *test.Coordinator) (coordinator.Client, string) {
			t := tb.(*testing.T)
			t.Helper()
			s.enrol(t, coord.Config)
			s.serve(t, coord)
			cfg := *coord.Config
			cfg.Worker.Coordinators = nil
			cfg.Worker.HubURL = s.hubURL
			s.credential = s.credentialFile(t, "dagu-worker-a", s.machine)
			cfg.Worker.Auth.CredentialFile = s.credential
			client, err := worker.NewCoordinatorClient(context.Background(), &cfg)
			require.NoError(t, err)
			return client, s.machine
		}
	}
}

func (s *fullStack) dag(body string) string {
	return fmt.Sprintf(`type: chain
worker_selector:
  %s: %s
steps:
  - name: run
    command: |
%s
`, txepkg.LabelMachine, s.machine, indentYAMLBlock(body, 6))
}

// A real job, through the real frontend's middleware: its status, its log and
// an artifact larger than one chunk, which goes by segments, all arrive.
func TestChannelFullStackRunsAJob(t *testing.T) {
	needPosixShell(t)
	stack := newFullStack(t)
	const size = 5 << 20
	script := strings.Join([]string{
		`mkdir -p "${DAG_RUN_ARTIFACTS_DIR}/reports"`,
		fmt.Sprintf(`head -c %d /dev/urandom > "${DAG_RUN_ARTIFACTS_DIR}/reports/large.bin"`, size),
		`(sha256sum "${DAG_RUN_ARTIFACTS_DIR}/reports/large.bin" || shasum -a 256 "${DAG_RUN_ARTIFACTS_DIR}/reports/large.bin") | cut -d' ' -f1`,
		`echo full-stack-done`,
	}, "\n")
	f := newTestFixture(t, stack.dag(script), withFullStack(stack), withLogPersistence(), withArtifactPersistence(), withIsolatedWorker())
	t.Cleanup(f.cleanup)
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(distrTestTimeout(5 * time.Minute))
	status := f.waitForStatusIn([]ir.Status{ir.Succeeded, ir.Failed, ir.Aborted}, distrTestTimeout(3*time.Minute))
	require.Equal(t, ir.Succeeded, status.Status, "error %q", status.Error)

	data, err := os.ReadFile(filepath.Join(status.ArchiveDir, "reports", "large.bin"))
	require.NoError(t, err)
	require.Len(t, data, size)
	sum := sha256.Sum256(data)
	logs := findLogFiles(t, f.coord.Config.Paths.LogDir, status.Name, status.DAGRunID, "run", "stdout")
	require.NotEmpty(t, logs)
	logged, err := os.ReadFile(filepath.Clean(logs[0]))
	require.NoError(t, err)
	assert.Contains(t, string(logged), hex.EncodeToString(sum[:]), "the digest the job computed")
	assert.Contains(t, string(logged), "full-stack-done")
	_, err = os.Stat(filepath.Join(status.ArchiveDir, ir.ArtifactSegmentDir))
	assert.ErrorIs(t, err, os.ErrNotExist, "no upload is left behind")
}

type bearer string

func (b bearer) HTTPAuthorization(context.Context, string) (string, error) {
	return "Bearer " + string(b), nil
}

// Through the same middleware, the channel refuses what it must: no
// credential, a person's CLI token, and an enrolled machine speaking for
// another. Each refusal is the channel's own, not a page of the frontend.
func TestChannelFullStackRefusesWhatItMust(t *testing.T) {
	needPosixShell(t)
	stack := newFullStack(t)
	f := newTestFixture(t, stack.dag("true"), withFullStack(stack))
	t.Cleanup(f.cleanup)
	base := stack.hubURL + "/api/v1" + workerchannel.MountPath
	heartbeat := func(machine string) *coordinatorv1.HeartbeatRequest {
		return &coordinatorv1.HeartbeatRequest{WorkerId: machine, Labels: map[string]string{txepkg.LabelMachine: machine}}
	}
	call := func(t *testing.T, token, machine string) error {
		t.Helper()
		conn, err := workerchannel.NewConn(workerchannel.ClientConfig{BaseURL: base, Credentials: bearer(token)})
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err = coordinatorv1.NewCoordinatorServiceClient(conn).Heartbeat(ctx, heartbeat(machine))
		return err
	}

	t.Run("no credential", func(t *testing.T) {
		resp, err := http.Post(base+"/coordinator.v1.CoordinatorService/Heartbeat", "application/proto", bytes.NewReader(nil))
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, string(body), "unauthenticated", "a Connect error, not a frontend page")
		assert.NotContains(t, strings.ToLower(string(body)), "<html")
		// The frontend's own middleware wrapped the answer: the channel is not on
		// a router of its own.
		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	})
	t.Run("the machine itself", func(t *testing.T) {
		token, err := stack.provider.sign("dagu-worker-b")
		require.NoError(t, err)
		require.NoError(t, call(t, token, stack.other))
	})
	t.Run("a person's CLI token", func(t *testing.T) {
		token, err := stack.provider.sign("dagu-cli")
		require.NoError(t, err)
		err = call(t, token, stack.machine)
		require.Error(t, err)
		assert.Contains(t, []codes.Code{codes.Unauthenticated, codes.PermissionDenied}, status.Code(err), "%v", err)
	})
	t.Run("another machine's credential", func(t *testing.T) {
		token, err := stack.provider.sign("dagu-worker-b")
		require.NoError(t, err)
		err = call(t, token, stack.machine)
		require.Error(t, err)
		assert.Contains(t, []codes.Code{codes.Unauthenticated, codes.PermissionDenied}, status.Code(err), "%v", err)
	})
}
