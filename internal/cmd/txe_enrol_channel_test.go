// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/health"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// channelCheckHub is the real channel, with real token verification and the
// enrolment the owner made, at a loopback address.
func channelCheckHub(t *testing.T) (*authTestHub, string) {
	t.Helper()
	h := newAuthTestHub(t, config.TXEAuthzModeEnforce)
	cfg := *h.cfg
	// The channel enforces whatever the modes are.
	cfg.Coordinator.Auth.Mode = config.TXEAuthzModeOff
	cfg.TXE.Authz.Mode = config.TXEAuthzModeOff
	channel, err := newWorkerChannel(context.Background(), &cfg, h.service, health.NewServer(), txeauth.WithKeySource(h.provider.keys()))
	require.NoError(t, err)
	router := chi.NewRouter()
	channel.Mount(router, "/api/v1")
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return h, server.URL
}

func TestTheChannelCheckAsksOnlyTheHubsHealth(t *testing.T) {
	h, hub := channelCheckHub(t)
	path := h.credentialFile(t, "dagu-worker-"+h.machine, h.machine)
	health, err := txeChannelCheck(context.Background(), hub, path)
	require.NoError(t, err)
	assert.Equal(t, "SERVING", health)
	assert.Empty(t, h.service.last().Machine.MachineID, "no coordinator call: no Poll, no heartbeat, no task")
}

func TestTheChannelCheckSaysWhoRefused(t *testing.T) {
	h, hub := channelCheckHub(t)
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(refusing.Close)
	nothing := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(nothing.Close)
	withEndpoint := func(t *testing.T, client, machine, endpoint string) string {
		path := filepath.Join(t.TempDir(), "machine.json")
		require.NoError(t, transportauth.WriteMachineCredential(path, transportauth.MachineCredential{
			Schema: transportauth.CredentialSchema, Issuer: authTestIssuer, TokenEndpoint: endpoint,
			ClientID: client, Class: authn.ClassWorker, MachineID: machine, RefreshToken: "offline",
		}))
		return path
	}
	for name, tc := range map[string]struct {
		hub  string
		path func(t *testing.T) string
		why  string
	}{
		"missing": {hub, func(t *testing.T) string { return filepath.Join(t.TempDir(), "none.json") }, "no such file"},
		"another machine's client, not enrolled": {hub, func(t *testing.T) string {
			return h.credentialFile(t, "dagu-worker-other", "mch_00000000000000000000000000")
		}, "refused this machine on its worker channel"},
		"refused by the provider": {hub, func(t *testing.T) string {
			return withEndpoint(t, "dagu-worker-"+h.machine, h.machine, refusing.URL+"/token")
		}, "the identity provider refused"},
		"provider unreachable": {hub, func(t *testing.T) string {
			return withEndpoint(t, "dagu-worker-"+h.machine, h.machine, "http://127.0.0.1:1/token")
		}, "could not renew"},
		"no channel there": {nothing.URL, func(t *testing.T) string {
			return h.credentialFile(t, "dagu-worker-"+h.machine, h.machine)
		}, "did not answer"},
		"not a hub address": {"::", func(t *testing.T) string {
			return h.credentialFile(t, "dagu-worker-"+h.machine, h.machine)
		}, "not a hub address"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := txeChannelCheck(context.Background(), tc.hub, tc.path(t))
			require.ErrorContains(t, err, tc.why)
			assert.NotContains(t, err.Error(), "offline", "no token in what is said")
		})
	}
	assert.Empty(t, h.service.last().Machine.MachineID, "nothing reached the coordinator")
}

// The provider rotates the refresh token and the file cannot take it: the
// check fails, though the hub answered, because the worker would present a
// retired token.
func TestTheChannelCheckFailsWhenARotationCannotBeSaved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory, so the save cannot be made to fail this way")
	}
	h, hub := channelCheckHub(t)
	rotating := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": h.provider.token(r.Form.Get("client_id")), "token_type": "Bearer", "expires_in": 300,
			"refresh_token": "rotated",
		})
	}))
	t.Cleanup(rotating.Close)
	dir := t.TempDir()
	path := filepath.Join(dir, "machine.json")
	require.NoError(t, transportauth.WriteMachineCredential(path, transportauth.MachineCredential{
		Schema: transportauth.CredentialSchema, Issuer: authTestIssuer, TokenEndpoint: rotating.URL + "/token",
		ClientID: "dagu-worker-" + h.machine, Class: authn.ClassWorker, MachineID: h.machine, RefreshToken: "offline",
	}))
	// The renewal's lock opens; only saving the rotated token fails.
	require.NoError(t, os.WriteFile(path+".lock", nil, 0o600))
	require.NoError(t, os.Chmod(dir, 0o500))       // #nosec G302 -- the test makes the save fail
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restored for cleanup
	_, err := txeChannelCheck(context.Background(), hub, path)
	require.ErrorContains(t, err, "could not be saved")
	assert.NotContains(t, err.Error(), "rotated", "no token in what is said")
}
