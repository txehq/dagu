// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

// A step's read of the hub with the machine's credential names where it
// stopped: a renewal that never ends stops before the request is sent, and a
// hub that never answers stops after it is written. net/http reports both as
// a client timeout (TXE-6337).
func TestTXEStepRequestNamesWhetherTheRenewalOrTheHubStalled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a machine credential is refused on Windows")
	}
	const (
		issuer  = "https://issuer.invalid/realms/txe"
		client  = "txe-worker-test"
		machine = "mch_01PHASETEST000000000000000"
	)
	enc := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	token := enc(map[string]string{"alg": "none"}) + "." +
		enc(map[string]any{"iss": issuer, "azp": client, "exp": time.Now().Add(time.Hour).Unix()}) + ".sig"
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	hold := func(r *http.Request) {
		// The server notices that the client went away only once the
		// request's body has been read; the token request has one.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}

	for _, tc := range []struct {
		name               string
		idpHolds, hubHolds bool
		want               txeclient.RequestPhase
	}{
		{name: "the renewal stalls", idpHolds: true, want: txeclient.PhaseNotStarted},
		{name: "the hub stalls after the token", hubHolds: true, want: txeclient.PhaseRequestWritten},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.idpHolds {
					hold(r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": token, "token_type": "Bearer", "expires_in": 300, "refresh_token": "rt-next",
				})
			}))
			t.Cleanup(idp.Close)
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.hubHolds {
					hold(r)
					return
				}
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(hub.Close)

			path := filepath.Join(t.TempDir(), "worker-credential.json")
			credential := transportauth.MachineCredential{
				Schema: transportauth.CredentialSchema, Issuer: issuer, TokenEndpoint: idp.URL + "/token",
				ClientID: client, Class: "worker", MachineID: machine, RefreshToken: "rt-0",
			}
			raw, err := json.Marshal(credential)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, raw, 0o600))
			// The hub request's own bound ends first, as it did in TXE-6337.
			source, err := transportauth.NewRefreshingSource(path, transportauth.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
			require.NoError(t, err)
			remote := &remoteClient{baseURL: hub.URL + "/api/v1", client: &http.Client{Timeout: 400 * time.Millisecond}}
			worker, err := remote.withMachineCredential(source, credential)
			require.NoError(t, err)

			_, err = txeclient.New(worker.baseURL, "", worker.client).Machine(context.Background(), machine)
			require.Error(t, err)
			var re *txeclient.RequestError
			require.True(t, errors.As(err, &re), "%v", err)
			// net/http words the timeout itself in more than one way, by
			// which of its signals the transport saw first; the phase does
			// not depend on that.
			assert.Equal(t, tc.want, re.Phase, "%v", err)
			assert.Contains(t, err.Error(), "(the request stopped "+tc.want.String())
			if tc.want == txeclient.PhaseNotStarted {
				assert.Contains(t, err.Error(), "renew this machine's access token: ")
			}
		})
	}
}
