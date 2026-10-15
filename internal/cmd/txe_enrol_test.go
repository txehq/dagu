// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

const (
	txeEnrolTestMachine = "mch_enroltest"
	txeEnrolTestOwner   = "own_enroltest"
	txeEnrolTestClient  = "dagu-worker-mch_enroltest"
)

// txeEnrolFixture is a machine with a TXE home, a provider whose client is
// the machine's worker client, and a hub that takes enrolment applications.
type txeEnrolFixture struct {
	*txeAuthFixture
	provider *cliauthtest.Provider

	mu       sync.Mutex
	applied  []string // azp of each application's token
	approved bool
	// approveAfter approves the machine once this many applications arrived.
	approveAfter   int
	applyStatus    int
	machineUnknown bool
}

func newTXEEnrolFixture(t *testing.T) *txeEnrolFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a machine credential is refused on Windows")
	}
	f := &txeEnrolFixture{txeAuthFixture: newTXEAuthFixture(t), provider: cliauthtest.New(t)}
	f.provider.ClientID = txeEnrolTestClient
	f.provider.Rotate = true
	withFakeBrowser(t, f.provider)
	require.NoError(t, os.MkdirAll(f.home, 0o700))
	machine := `{"schema":1,"machine_id":"` + txeEnrolTestMachine + `","owner_id":"` + txeEnrolTestOwner + `"}`
	require.NoError(t, os.WriteFile(filepath.Join(f.home, "machine.json"), []byte(machine), 0o600))
	f.hub.Publish(f.provider.Issuer(), "dagu-cli", cliauth.HubUseAll)
	f.hub.Handle = f.serve
	return f
}

func (f *txeEnrolFixture) path() string { return filepath.Join(f.home, txeEnrolCredentialFile) }

func (f *txeEnrolFixture) serve(w http.ResponseWriter, r *http.Request) bool {
	claims := enrolTestClaims(r.Header.Get("Authorization"))
	switch r.URL.Path {
	case "/api/v1/txe/machines/" + txeEnrolTestMachine + "/enrolment-applications":
		f.mu.Lock()
		f.applied = append(f.applied, claims.Azp)
		if f.approveAfter > 0 && len(f.applied) >= f.approveAfter {
			f.approved = true
		}
		status := f.applyStatus
		f.mu.Unlock()
		if status != 0 {
			cliauthtest.WriteJSON(w, status, map[string]any{"code": "unauthorized", "message": "refused", "details": map[string]string{"code": "invalid_token"}})
			return true
		}
		cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{
			"machine_id": txeEnrolTestMachine, "class": "worker", "issuer": claims.Iss, "subject": claims.Sub, "client_id": claims.Azp,
			"received_at": time.Now().UTC(), "credential_expires": time.Unix(claims.Exp, 0).UTC(),
		})
		return true
	case "/api/v1/txe/machines/" + txeEnrolTestMachine:
		if f.machineUnknown {
			cliauthtest.WriteJSON(w, http.StatusNotFound, map[string]any{"code": "not_found", "message": "not found"})
		} else {
			cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"machine_id": txeEnrolTestMachine, "owner_id": txeEnrolTestOwner})
		}
		return true
	case "/api/v1/txe/identity":
		f.mu.Lock()
		approved := f.approved
		f.mu.Unlock()
		if approved && claims.Azp == txeEnrolTestClient {
			cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"state": "bound", "scope": map[string]any{"kind": "owner", "machine_id": txeEnrolTestMachine}})
		} else {
			cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"state": "unbound", "scope": map[string]any{"kind": "unbound", "unbound_reason": "not_enrolled"}})
		}
		return true
	}
	return false
}

type enrolClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Azp string `json:"azp"`
	Exp int64  `json:"exp"`
}

func enrolTestClaims(header string) enrolClaims {
	var c enrolClaims
	token, ok := strings.CutPrefix(header, "Bearer ")
	parts := strings.Split(token, ".")
	if !ok || len(parts) != 3 {
		return c
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err == nil {
		_ = json.Unmarshal(payload, &c)
	}
	return c
}

// enrolRequests are the hub requests on the enrolment routes, with what
// they carried.
func (f *txeEnrolFixture) enrolRequests() []cliauthtest.Request {
	var out []cliauthtest.Request
	for _, r := range f.hub.Requests() {
		if strings.Contains(r.Path, "/machines/") || r.Path == "/api/v1/txe/identity" {
			out = append(out, r)
		}
	}
	return out
}

func TestTXEEnrolWritesTheWorkerCredentialAndApplies(t *testing.T) {
	f := newTXEEnrolFixture(t)
	out := f.json("enrol", "--client-id", txeEnrolTestClient)
	assert.Equal(t, "applied", out["state"])
	assert.Equal(t, txeEnrolTestMachine, out["machine_id"])
	assert.Equal(t, f.provider.Issuer(), out["issuer"])
	application := out["application"].(map[string]any)
	assert.Equal(t, f.provider.Subject, application["subject"])
	assert.Equal(t, txeEnrolTestClient, application["client_id"])
	assert.NotContains(t, mustJSON(t, out), "refresh", "no token is shown")
	hubBase := strings.TrimSuffix(f.hub.API(), "/api/v1")
	assert.Equal(t, hubBase+"/txe/machines/"+txeEnrolTestMachine+"?class=worker&client_id="+txeEnrolTestClient, out["approve_url"])

	assert.Equal(t, "openid offline_access", f.provider.LastAuth().Get("scope"))
	assert.Equal(t, txeEnrolTestClient, f.provider.LastAuth().Get("client_id"))

	credential, err := transportauth.ReadMachineCredential(f.path())
	require.NoError(t, err)
	assert.Equal(t, transportauth.CredentialSchema, credential.Schema)
	assert.Equal(t, f.provider.Issuer(), credential.Issuer)
	assert.Equal(t, f.provider.Issuer()+"/token", credential.TokenEndpoint)
	assert.Equal(t, txeEnrolTestClient, credential.ClientID)
	assert.Equal(t, "worker", string(credential.Class))
	assert.Equal(t, txeEnrolTestMachine, credential.MachineID)
	assert.NotEmpty(t, credential.RefreshToken)
	info, err := os.Stat(f.path())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	reqs := f.enrolRequests()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodPost, reqs[0].Method)
	assert.True(t, strings.HasPrefix(reqs[0].Authorization, "Bearer ey"), "the worker's own token")
	assert.Equal(t, []string{txeEnrolTestClient}, f.applied)
	for _, r := range f.hub.Requests() {
		assert.NotContains(t, r.Authorization, "dagu_", "the context's API key is never sent: %s", r.Path)
	}

	// --resume applies again with the written credential and no sign-in.
	auths := f.provider.LastAuth()
	again := f.json("enrol", "--client-id", txeEnrolTestClient, "--resume")
	assert.Equal(t, "applied", again["state"])
	assert.Equal(t, auths, f.provider.LastAuth(), "no new sign-in")
	assert.Len(t, f.applied, 2)
	rotated, err := transportauth.ReadMachineCredential(f.path())
	require.NoError(t, err)
	assert.NotEqual(t, credential.RefreshToken, rotated.RefreshToken, "the renewal's rotated token is saved")

	_, err = f.run("enrol", "--client-id", "another-client", "--resume")
	assert.ErrorContains(t, err, "enrol again without --resume")
}

func TestTXEEnrolWaitsForApproval(t *testing.T) {
	f := newTXEEnrolFixture(t)
	before := txeEnrolInterval
	txeEnrolInterval = 20 * time.Millisecond
	t.Cleanup(func() { txeEnrolInterval = before })
	f.approveAfter = 3

	out := f.json("enrol", "--client-id", txeEnrolTestClient, "--wait", "10s")
	assert.Equal(t, "enrolled", out["state"])
	assert.Len(t, f.applied, 3, "applied until approved, then asked no more")
	var identity int
	for _, r := range f.enrolRequests() {
		if r.Path == "/api/v1/txe/identity" {
			identity++
		}
	}
	assert.Equal(t, 4, identity, "asked before each application, and once more")

	_, err := f.run("enrol", "--client-id", txeEnrolTestClient, "--resume", "--wait", "1s")
	require.NoError(t, err)
}

func TestTXEEnrolRefusesALongLivedToken(t *testing.T) {
	f := newTXEEnrolFixture(t)
	f.provider.AccessLifetime = 10 * time.Minute
	_, err := f.run("enrol", "--client-id", txeEnrolTestClient)
	require.ErrorContains(t, err, "limited to 5m0s")
	_, statErr := os.Stat(f.path())
	assert.True(t, os.IsNotExist(statErr), "nothing written")
	assert.Len(t, f.provider.Revoked(), 1, "the sign-in is revoked")
	assert.Empty(t, f.applied)
}

func TestTXEEnrolNeedsARefreshToken(t *testing.T) {
	f := newTXEEnrolFixture(t)
	f.provider.OmitRefresh = true
	_, err := f.run("enrol", "--client-id", txeEnrolTestClient)
	require.ErrorContains(t, err, "no refresh token")
	_, statErr := os.Stat(f.path())
	assert.True(t, os.IsNotExist(statErr))
}

func TestTXEEnrolWaitsForAWorkersLock(t *testing.T) {
	f := newTXEEnrolFixture(t)
	before := txeEnrolLockWait
	txeEnrolLockWait = 200 * time.Millisecond
	t.Cleanup(func() { txeEnrolLockWait = before })
	lock := flock.New(f.path() + ".lock")
	locked, err := lock.TryLock()
	require.NoError(t, err)
	require.True(t, locked)
	t.Cleanup(func() { _ = lock.Unlock() })

	_, err = f.run("enrol", "--client-id", txeEnrolTestClient)
	require.ErrorContains(t, err, "a worker holds")
	_, statErr := os.Stat(f.path())
	assert.True(t, os.IsNotExist(statErr))
	assert.Len(t, f.provider.Revoked(), 1, "the sign-in that could not be written is revoked")
}

func TestTXEEnrolExplainsARefusedApplication(t *testing.T) {
	f := newTXEEnrolFixture(t)
	f.applyStatus = http.StatusUnauthorized
	_, err := f.run("enrol", "--client-id", txeEnrolTestClient)
	require.ErrorContains(t, err, "txe.authn.clients")
	_, err = transportauth.ReadMachineCredential(f.path())
	assert.NoError(t, err, "the credential stays for --resume once the hub takes the client")
}

func TestTXEEnrolNeedsTheMachine(t *testing.T) {
	f := newTXEEnrolFixture(t)
	require.NoError(t, os.Remove(filepath.Join(f.home, "machine.json")))
	_, err := f.run("enrol", "--client-id", txeEnrolTestClient)
	require.ErrorContains(t, err, "install the local worker first")
	assert.Empty(t, f.provider.LastAuth(), "no sign-in")
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// A credential file elsewhere is named in the printed resume command, and a
// rotated refresh token that cannot be saved there is an error, not a
// success: the worker would read the retired one.
func TestTXEEnrolCustomFileAndUnsavedRotation(t *testing.T) {
	f := newTXEEnrolFixture(t)
	dir := filepath.Join(filepath.Dir(f.home), "cred dir")
	path := filepath.Join(dir, "worker.json")
	out, err := f.run("enrol", "--client-id", txeEnrolTestClient, "--credential-file", path)
	require.NoError(t, err, out)
	assert.Contains(t, out, "--credential-file '"+path+"' --resume --wait 15m")
	assert.Contains(t, out, "Approve at "+strings.TrimSuffix(f.hub.API(), "/api/v1")+"/txe/machines/"+txeEnrolTestMachine+"?class=worker&client_id=")
	_, err = transportauth.ReadMachineCredential(path)
	require.NoError(t, err)

	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	applied := len(f.applied)
	_, err = f.run("enrol", "--client-id", txeEnrolTestClient, "--credential-file", path, "--resume")
	require.ErrorContains(t, err, "no longer holds a usable credential")
	assert.Len(t, f.applied, applied, "nothing applied with a credential the worker cannot use")
}

// A renewal the provider does not answer is the outcome when no retry is
// left, however short the wait.
func TestTXEEnrolReportsAFailedRenewal(t *testing.T) {
	f := newTXEEnrolFixture(t)
	f.json("enrol", "--client-id", txeEnrolTestClient)
	f.provider.RefreshHandler = func(w http.ResponseWriter) bool {
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	}
	applied := len(f.applied)

	_, err := f.run("enrol", "--client-id", txeEnrolTestClient, "--resume", "--wait", "30s")
	require.ErrorIs(t, err, transportauth.ErrProviderUnavailable, "a wait shorter than one interval")

	before := txeEnrolInterval
	txeEnrolInterval = 20 * time.Millisecond
	t.Cleanup(func() { txeEnrolInterval = before })
	refreshes := f.provider.Refreshes()
	_, err = f.run("enrol", "--client-id", txeEnrolTestClient, "--resume", "--wait", "200ms")
	require.ErrorIs(t, err, transportauth.ErrProviderUnavailable, "failing through the last round")
	assert.Greater(t, f.provider.Refreshes()-refreshes, 1, "retried while time was left")
	assert.Len(t, f.applied, applied, "the hub was not asked")
}

// A signed-in CLI asks the hub about the machine before anyone signs in for
// it; a machine the hub does not know for the owner stops there.
func TestTXEEnrolChecksTheMachineFirst(t *testing.T) {
	f := newTXEEnrolFixture(t)
	cli := cliauthtest.New(t)
	withFakeBrowser(t, cli)
	f.hub.Publish(cli.Issuer(), cli.ClientID, cliauth.HubUseAll)
	f.json("login")
	withFakeBrowser(t, f.provider)

	f.machineUnknown = true
	_, err := f.run("enrol", "--client-id", txeEnrolTestClient, "--issuer", f.provider.Issuer())
	require.ErrorContains(t, err, "the hub has no machine "+txeEnrolTestMachine)
	assert.Empty(t, f.provider.LastAuth(), "no sign-in for the machine")
	var asked bool
	for _, r := range f.hub.Requests() {
		if r.Path == "/api/v1/txe/machines/"+txeEnrolTestMachine {
			asked = true
			assert.True(t, strings.HasPrefix(r.Authorization, "Bearer ey"), "asked with the CLI's sign-in")
		}
	}
	assert.True(t, asked)

	f.machineUnknown = false
	out := f.json("enrol", "--client-id", txeEnrolTestClient, "--issuer", f.provider.Issuer())
	assert.Equal(t, "applied", out["state"])
}

// enrol check loads the credential as the worker does and requires this
// machine's; it signs in nowhere and asks nothing.
func TestTXEEnrolCheck(t *testing.T) {
	f := newTXEEnrolFixture(t)
	f.json("enrol", "--client-id", txeEnrolTestClient)
	requests, auths := len(f.hub.Requests()), f.provider.LastAuth()

	out := f.json("enrol", "check")
	assert.Equal(t, f.path(), out["credential_file"])
	assert.Equal(t, txeEnrolTestMachine, out["machine_id"])
	assert.Equal(t, txeEnrolTestClient, out["client_id"])
	assert.NotContains(t, mustJSON(t, out), "refresh")
	assert.Len(t, f.hub.Requests(), requests, "no hub request")
	assert.Equal(t, auths, f.provider.LastAuth(), "no sign-in")

	write := func(t *testing.T, edit func(map[string]any)) string {
		t.Helper()
		raw, err := os.ReadFile(f.path())
		require.NoError(t, err)
		var c map[string]any
		require.NoError(t, json.Unmarshal(raw, &c))
		edit(c)
		b, err := json.Marshal(c)
		require.NoError(t, err)
		// Each subtest its own file: WriteFile keeps an existing file's mode,
		// so a file another subtest loosened would decide this one.
		path := filepath.Join(t.TempDir(), "edited.json")
		require.NoError(t, os.WriteFile(path, b, 0o600))
		return path
	}
	for name, tc := range map[string]struct {
		path func(t *testing.T) string
		why  string
	}{
		"bad escape": {func(t *testing.T) string {
			return write(t, func(c map[string]any) { c["token_endpoint"] = "https://idp.example/token%ZZ" })
		}, "token_endpoint"},
		"other machine": {func(t *testing.T) string {
			return write(t, func(c map[string]any) { c["machine_id"] = "mch_00000000000000000000000000" })
		}, "is for machine"},
		"group readable": {func(t *testing.T) string {
			p := write(t, func(map[string]any) {})
			require.NoError(t, os.Chmod(p, 0o640))
			return p
		}, "0600"},
		"missing": {func(t *testing.T) string { return filepath.Join(t.TempDir(), "none.json") }, "no such file"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.run("enrol", "check", "--credential-file", tc.path(t))
			require.ErrorContains(t, err, tc.why)
		})
	}

	_, err := f.run("enrol")
	assert.ErrorContains(t, err, "--client-id is required")
}
