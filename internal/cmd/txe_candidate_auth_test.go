// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/test"
)

// callAs is call with a bearer credential: a session token or an API key.
// An empty bearer sends none.
func (h *txeHub) callAs(bearer, method, path string, body any) (int, map[string]any, string) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(h.t, err)
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.base+path, reader)
	require.NoError(h.t, err)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var value map[string]any
	_ = json.Unmarshal(raw, &value)
	return resp.StatusCode, value, string(raw)
}

func txeRandom(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

// txeBuiltinAuth makes a hub's configuration use built-in authentication.
func txeBuiltinAuth(secret string) test.HelperOption {
	return test.WithConfigMutator(func(c *config.Config) {
		c.Server.Auth.Mode = config.AuthModeBuiltin
		c.Server.Auth.Builtin.Token.Secret = secret
	})
}

// txePrincipals are the credentials of a candidate hub with built-in
// authentication. None of them is logged or kept.
type txePrincipals struct {
	// admin is the signed-in person's session token.
	admin string
	// cli is an API key of a service account with the developer role, for
	// the REST surface only.
	cli string
}

// txeBootstrapAuth creates the first admin of a hub that has no users, signs
// in, and mints the CLI's API key, the way an installer would.
func txeBootstrapAuth(t *testing.T, hub *txeHub) txePrincipals {
	t.Helper()
	username, password := "candidate-admin", txeRandom(t)
	code, value, _ := hub.callAs("", http.MethodPost, "/auth/setup", map[string]any{"username": username, "password": password})
	require.Equal(t, http.StatusOK, code, "setup of the first admin")
	admin, _ := value["token"].(string)
	require.NotEmpty(t, admin, "setup returned no session token")

	// Setup works once.
	code, _, _ = hub.callAs("", http.MethodPost, "/auth/setup", map[string]any{"username": "second", "password": txeRandom(t)})
	require.GreaterOrEqual(t, code, 400, "a second setup was accepted")

	code, value, _ = hub.callAs("", http.MethodPost, "/auth/login", map[string]any{"username": username, "password": password})
	require.Equal(t, http.StatusOK, code, "login")
	if token, _ := value["token"].(string); token != "" {
		admin = token
	}

	code, value, raw := hub.callAs(admin, http.MethodPost, "/api-keys", map[string]any{
		"name": "txe-cli", "role": "developer", "allowedSurfaces": []string{"rest_api"},
		"attributionClass": "service_account", "serviceAccountName": "txe-cli",
	})
	key, _ := value["key"].(string)
	if key == "" {
		// The body is not printed whole: on success it holds the key.
		t.Fatalf("creating the CLI's API key: HTTP %d, %d bytes, code %v", code, len(raw), value["code"])
	}
	return txePrincipals{admin: admin, cli: key}
}

// A hub with built-in authentication, bootstrapped without a person: the
// first admin through setup, an API key for the CLI, and a worker that is
// configured with no credential at all. What each principal may do is read
// off the hub's answers.
func TestTXECandidateAuthBootstrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("starts Unix processes")
	}
	if testing.Short() {
		t.Skip("starts real hub and worker processes")
	}
	apiPort, coordPort := findPort(t), findPort(t)
	hubHelper := test.SetupCommand(t, test.WithBuiltExecutable(), test.WithCoordinatorEnabled(), txeBuiltinAuth(txeRandom(t)))
	workerHelper := test.SetupCommand(t, test.WithBuiltExecutable())
	binary := hubHelper.Config.Paths.Executable
	hub := &txeHub{t: t, base: "http://127.0.0.1:" + apiPort + "/api/v1"}

	txeStartProcess(t, "hub", binary, hubHelper.Config.Core.BaseEnv.AsSlice(),
		"start-all", "--config", hubHelper.Config.Paths.ConfigFileUsed, "--host=127.0.0.1", "--port="+apiPort,
		"--coordinator.host=127.0.0.1", "--coordinator.advertise=127.0.0.1", "--coordinator.port="+coordPort, "--peer.insecure=true")
	require.Eventually(t, func() bool {
		code, _, _ := hub.callAs("", http.MethodGet, "/health", nil)
		return code == http.StatusOK
	}, 60*time.Second, 300*time.Millisecond, "the hub's API did not come up")

	// Before anyone exists, and without a credential, nothing is readable.
	code, _, raw := hub.callAs("", http.MethodGet, "/dags", nil)
	require.Equal(t, http.StatusUnauthorized, code, "an unauthenticated read was answered: %s", raw)

	who := txeBootstrapAuth(t, hub)

	code, _, _ = hub.callAs(who.cli, http.MethodGet, "/dags", nil)
	assert.Equal(t, http.StatusOK, code, "the CLI's key cannot read")
	code, _, _ = hub.callAs("dagu_"+txeRandom(t), http.MethodGet, "/dags", nil)
	assert.Equal(t, http.StatusUnauthorized, code, "an unknown key was accepted")
	code, _, _ = hub.callAs("", http.MethodGet, "/dags", nil)
	assert.Equal(t, http.StatusUnauthorized, code)
	// A developer key does not administer keys.
	code, _, _ = hub.callAs(who.cli, http.MethodPost, "/api-keys", map[string]any{
		"name": "escalate", "role": "admin", "allowedSurfaces": []string{"rest_api"}, "attributionClass": "service_account", "serviceAccountName": "escalate",
	})
	assert.Equal(t, http.StatusForbidden, code, "a developer key created an API key")

	// A worker that is given no credential runs a DAG the CLI's key starts.
	require.NoError(t, os.WriteFile(filepath.Join(hubHelper.Config.Paths.DAGsDir, "auth-probe.yaml"), []byte(`worker_selector:
  txe.machine: "candidate"
steps:
  - name: hello
    command: echo hello
`), 0o600))
	txeStartProcess(t, "worker", binary, workerHelper.Config.Core.BaseEnv.AsSlice(),
		"worker", "--config", workerHelper.Config.Paths.ConfigFileUsed, "--worker.id=candidate-worker",
		"--worker.labels=txe.machine=candidate", "--worker.coordinators=127.0.0.1:"+coordPort,
		"--worker.health-port=0", "--peer.insecure=true")
	code, _, raw = hub.callAs("", http.MethodPost, "/dags/auth-probe/start", map[string]any{"dagRunId": "auth-probe-1"})
	require.Equal(t, http.StatusUnauthorized, code, "an unauthenticated start was accepted: %s", raw)
	code, _, raw = hub.callAs(who.cli, http.MethodPost, "/dags/auth-probe/start", map[string]any{"dagRunId": "auth-probe-1"})
	require.Less(t, code, 300, "start with the CLI's key: %s", raw)
	require.Eventually(t, func() bool {
		code, value, _ := hub.callAs(who.cli, http.MethodGet, "/dag-runs/auth-probe/auth-probe-1", nil)
		details, _ := value["dagRunDetails"].(map[string]any)
		return code == http.StatusOK && details["statusLabel"] == "succeeded"
	}, 60*time.Second, 300*time.Millisecond, "the worker did not run the DAG")
	t.Logf("built-in auth: unauthenticated 401; developer service-account key reads and starts runs, cannot create keys (403); an unknown key 401; the worker ran the run with no credential configured")
}
