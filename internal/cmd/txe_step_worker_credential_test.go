// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

const (
	stepCredentialAudience = "dagu-hub"
	stepQueuedAt           = "2026-11-01T00:00:00Z"
)

// stepProvider is an identity provider as a hub and a machine meet one: a key
// set the hub fetches and a token endpoint the machine renews at. It signs a
// real token for the client that asks.
type stepProvider struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	subjects map[string]string
	renewals atomic.Int64
}

func newStepProvider(t *testing.T) *stepProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &stepProvider{key: key, subjects: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		exponent := big.NewInt(int64(key.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(exponent),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		client := r.FormValue("client_id")
		subject, ok := p.subjects[client]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		token, err := p.sign(client, subject)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		p.renewals.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 300, "refresh_token": "offline"})
	})
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *stepProvider) sign(client, subject string) (string, error) {
	now := time.Now().Truncate(time.Second)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": p.server.URL, "sub": subject, "aud": stepCredentialAudience, "azp": client,
		"typ": "Bearer", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	token.Header["kid"] = "k1"
	return token.SignedString(p.key)
}

// stepMachine is one owner's enrolled machine and its registered job.
type stepMachine struct {
	owner, machine, client, job string
	cli                         *txeCLI
}

// stepHub is a real hub with two owners, each with a machine enrolled and a job
// that declares one deliverable.
type stepHub struct {
	t        *testing.T
	server   test.Server
	provider *stepProvider
	registry *registry.Store
	baseURL  string
}

func newStepHub(t *testing.T) *stepHub {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a machine credential is refused on Windows")
	}
	provider := newStepProvider(t)
	clients := []config.TXEAuthnClient{{ID: "dagu-cli", Class: "cli"}, {ID: "dagu-worker-a", Class: "worker"}, {ID: "dagu-worker-b", Class: "worker"}}
	server := test.SetupServer(t, test.WithConfigMutator(func(cfg *config.Config) {
		cfg.Server.Auth.Mode = config.AuthModeBuiltin
		cfg.Server.Auth.Builtin.Token.Secret = "step-credential-test-secret"
		cfg.TXE.Authn = config.TXEAuthnConfig{Issuer: provider.server.URL, Audience: stepCredentialAudience,
			JWKSURL: provider.server.URL + "/jwks", Clients: clients}
	}))
	reg, err := registry.NewFileStore(server.Config.Paths.DataDir, registry.WithDAGStore(registry.NewDAGStore(server.DAGRepository)))
	require.NoError(t, err)
	return &stepHub{t: t, server: server, provider: provider, registry: reg,
		baseURL: fmt.Sprintf("http://%s:%d/api/v1", server.Config.Server.Host, server.Config.Server.Port)}
}

// add binds a person to a new owner, enrols the owner's machine, registers its
// job, and lays out the machine's TXE home as enrolment leaves it.
func (h *stepHub) add(client, subject string) *stepMachine {
	t, ctx := h.t, context.Background()
	h.provider.subjects[client] = subject
	mint := func(p registry.Prefix) string {
		id, err := registry.NewID(p, time.Now())
		require.NoError(t, err)
		return id
	}
	system := registry.Actor{Kind: registry.ActorSystem, ID: "test"}
	m := &stepMachine{owner: mint(registry.PrefixOwner), machine: mint(registry.PrefixMachine), client: client, job: mint(registry.PrefixJob)}
	_, err := h.registry.CreateOwner(ctx, registry.Owner{OwnerID: m.owner, DisplayName: subject}, system)
	require.NoError(t, err)
	_, err = h.registry.CreateMachine(ctx, registry.Machine{MachineID: m.machine, OwnerID: m.owner, DisplayName: subject}, system)
	require.NoError(t, err)
	project, err := h.registry.EnsureProject(ctx, m.owner, "github.com/step/"+subject, subject, system)
	require.NoError(t, err)
	version := registry.JobVersion{Title: "t", Purpose: "p",
		Package:         registry.Package{Digest: fmt.Sprintf("sha256:%064x", 1), Path: "/pkg", Entrypoint: "run.sh"},
		DAG:             registry.DAGRef{Spec: fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", m.machine)},
		ExpectedOutcome: registry.ExpectedOutcome{Deliverables: []registry.Deliverable{{Name: "report", Path: "report.txt", Delivery: "machine", Required: true}}},
	}
	_, err = h.registry.Register(ctx, registry.RegisterInput{JobID: m.job, RequestID: "r-" + m.job, OwnerID: m.owner, ProjectID: project.ProjectID,
		MachineID: m.machine, JobKey: "k", Version: version}, system)
	require.NoError(t, err)
	job, err := h.registry.GetJob(ctx, m.job)
	require.NoError(t, err)
	_, err = h.registry.MarkReady(ctx, m.job, job.Revision, registry.PackageEvidence{Digest: version.Package.Digest, Path: "/pkg", MachineID: m.machine}, system)
	require.NoError(t, err)

	svc, err := txeauth.NewService(h.server.Config.TXE, h.server.Config.Paths.DataDir, h.registry)
	require.NoError(t, err)
	person := authn.Principal{Identity: authn.Identity{Issuer: h.provider.server.URL, Subject: subject}, Class: authn.ClassPerson}
	_, err = svc.Store().RequestBinding(ctx, person, authz.Shown{Username: subject})
	require.NoError(t, err)
	_, err = svc.Store().ApproveBinding(ctx, authz.PlatformAdmin("admin"), person.Identity, m.owner)
	require.NoError(t, err)
	scope, err := svc.Store().Resolve(ctx, person)
	require.NoError(t, err)
	token, err := h.provider.sign(client, subject)
	require.NoError(t, err)
	credential, err := svc.Verify(ctx, token)
	require.NoError(t, err)
	_, err = svc.Store().Enrol(ctx, scope, authz.EnrolmentRequest{MachineID: m.machine, Credential: credential})
	require.NoError(t, err)

	userDir := t.TempDir()
	m.cli = &txeCLI{t: t, binary: h.server.Config.Paths.Executable, home: txeDurableHome(t, userDir), userDir: userDir}
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q,"display_name":"laptop"}`, m.machine, m.owner)
	require.NoError(t, os.WriteFile(filepath.Join(m.cli.home, "machine.json"), []byte(identity), 0o600))
	_, err = m.cli.run("installer", "context", "add", "txe", "--server="+h.baseURL, "--api-key=dagu_never_accepted",
		"--dagu-home="+filepath.Join(m.cli.home, "client"))
	require.NoError(t, err)
	path := filepath.Join(m.cli.home, "worker-credential.json")
	require.NoError(t, transportauth.WriteMachineCredential(path, transportauth.MachineCredential{
		Schema: transportauth.CredentialSchema, Issuer: h.provider.server.URL, TokenEndpoint: h.provider.server.URL + "/token",
		ClientID: client, Class: authn.ClassWorker, MachineID: m.machine, RefreshToken: "offline",
	}))
	require.NoError(t, txepkg.Home{Root: m.cli.home}.SetStepCredential("worker", path, h.baseURL))
	return m
}

// addRun leaves a run of the machine's job, as the hub holds it while its last
// step runs.
func (h *stepHub) addRun(m *stepMachine, runID string) string {
	t, ctx := h.t, context.Background()
	version, err := h.registry.GetVersion(ctx, m.job, 1)
	require.NoError(t, err)
	d := &ir.DAG{Name: m.job, YamlData: []byte(version.DAG.Spec)}
	attempt, err := h.server.DAGRunRepository.CreateAttempt(ctx, d, time.Now(), runID, persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	status := ir.InitialStatus(d)
	status.DAGRunID, status.AttemptID, status.Status, status.QueuedAt = runID, attempt.ID(), ir.Running, stepQueuedAt
	status.StartedAt = time.Now().Add(-time.Minute).Format(time.RFC3339)
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, status))
	require.NoError(t, attempt.Close(ctx))
	return attempt.ID()
}

// step runs the real binary as a step of a DAG, with what the worker gives one.
func (m *stepMachine) step(args ...string) (string, error) {
	m.cli.t.Helper()
	return m.cli.runIn([]string{"DAG_RUN_ID=step-run", "DAG_RUN_STEP_NAME=run"}, args...)
}

// sealed produces the deliverable the way a job does.
func (m *stepMachine) sealed(job, attempt string) {
	t := m.cli.t
	t.Helper()
	identity := []string{"--job", job, "--run", "step-run", "--attempt", attempt, "--queued-at", stepQueuedAt}
	begun, err := m.cli.json("job", append([]string{"txe", "artifacts", "begin"}, identity...)...)
	require.NoError(t, err)
	dir := begun["output_dir"].(string)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "report.txt"), []byte("report of "+job+"\n"), 0o600))
	_, err = m.cli.run("job", append([]string{"txe", "artifacts", "seal"}, identity...)...)
	require.NoError(t, err)
}

// A job's step on a machine with no API key: the real binary renews the
// machine's credential at the provider and presents it to a real hub, which
// verifies it against the provider's keys. It reads and publishes for its own
// owner, and gets nothing of another's.
func TestARealStepIsHeldToItsMachinesOwner(t *testing.T) {
	hub := newStepHub(t)
	mine, theirs := hub.add("dagu-worker-a", "subject-a"), hub.add("dagu-worker-b", "subject-b")
	attempt := hub.addRun(mine, "step-run")
	ctx := context.Background()

	out, err := mine.step("txe", "inspect", mine.job, "--json")
	require.NoError(t, err)
	assert.Contains(t, out, mine.job)
	assert.Positive(t, hub.provider.renewals.Load(), "the credential came from the provider")

	_, err = mine.step("txe", "inspect", theirs.job, "--json")
	require.Error(t, err, "another owner's job")
	assert.Contains(t, err.Error(), "404")

	listed, err := mine.step("txe", "list", "--json")
	require.NoError(t, err)
	assert.Contains(t, listed, mine.job)
	assert.NotContains(t, listed, theirs.job)

	mine.sealed(mine.job, attempt)
	_, err = mine.step("txe", "artifacts", "publish", "--job", mine.job, "--job-version", "1", "--run", "step-run",
		"--attempt", attempt, "--queued-at", stepQueuedAt)
	require.NoError(t, err)
	manifests, err := hub.registry.ListArtifacts(ctx, mine.job, "step-run")
	require.NoError(t, err)
	require.Len(t, manifests, 1, "its results are on the hub")

	theirAttempt := hub.addRun(theirs, "step-run")
	mine.sealed(theirs.job, theirAttempt)
	_, err = mine.step("txe", "artifacts", "publish", "--job", theirs.job, "--job-version", "1", "--run", "step-run",
		"--attempt", theirAttempt, "--queued-at", stepQueuedAt)
	require.Error(t, err, "another owner's results")
	assert.Contains(t, err.Error(), "404")

	// The command stops at its read of the job, so the write route is sent what
	// a machine that skipped that read would send.
	token, err := hub.provider.sign(mine.client, "subject-a")
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{"attempt_id": theirAttempt, "queued_at": stepQueuedAt, "job_version": 1})
	require.NoError(t, err)
	post, err := http.NewRequestWithContext(ctx, http.MethodPost,
		hub.baseURL+"/txe/jobs/"+theirs.job+"/runs/step-run/artifacts", bytes.NewReader(body))
	require.NoError(t, err)
	post.Header.Set("Authorization", "Bearer "+token)
	post.Header.Set("Content-Type", "application/json")
	refused, err := http.DefaultClient.Do(post)
	require.NoError(t, err)
	require.NoError(t, refused.Body.Close())
	assert.Equal(t, http.StatusNotFound, refused.StatusCode)

	manifests, err = hub.registry.ListArtifacts(ctx, theirs.job, "step-run")
	require.NoError(t, err)
	assert.Empty(t, manifests)
}
