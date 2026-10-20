// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/runenv"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

// stepAuthFixture is an enrolment fixture whose hub also lists jobs, the
// call a step makes here, and can refuse it.
type stepAuthFixture struct {
	*txeEnrolFixture
	refuseJobs bool
}

func newStepAuthFixture(t *testing.T) *stepAuthFixture {
	t.Helper()
	f := &stepAuthFixture{txeEnrolFixture: newTXEEnrolFixture(t)}
	enrol := f.hub.Handle
	f.hub.Handle = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/v1/txe/jobs" {
			if f.refuseJobs {
				cliauthtest.WriteJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthorized", "message": "refused"})
			} else {
				cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"jobs": []any{}})
			}
			return true
		}
		return enrol(w, r)
	}
	return f
}

// enrolled enrols the machine and waits for the hub's approval.
func (f *stepAuthFixture) enrolled(t *testing.T) {
	t.Helper()
	before := txeEnrolInterval
	txeEnrolInterval = 20 * time.Millisecond
	t.Cleanup(func() { txeEnrolInterval = before })
	f.approveAfter = 1
	out := f.json("enrol", "--client-id", txeEnrolTestClient, "--wait", "10s")
	require.Equal(t, "enrolled", out["state"])
	require.Equal(t, "credential", out["step_auth"])
}

// inStep runs a txe command as a DAG step would see it.
func (f *stepAuthFixture) inStep(t *testing.T, args ...string) (string, error) {
	t.Helper()
	t.Setenv(runenv.EnvKeyDAGRunID, "run-1")
	t.Setenv(runenv.EnvKeyDAGRunStepName, "run")
	defer func() {
		_ = os.Unsetenv(runenv.EnvKeyDAGRunID)
		_ = os.Unsetenv(runenv.EnvKeyDAGRunStepName)
	}()
	return f.run(args...)
}

func (f *stepAuthFixture) jobCalls() []cliauthtest.Request {
	var out []cliauthtest.Request
	for _, r := range f.hub.Requests() {
		if r.Path == "/api/v1/txe/jobs" {
			out = append(out, r)
		}
	}
	return out
}

// A machine not enrolled keeps the context's API key in its steps, and the
// step says so.
func TestTXEStepUsesTheAPIKeyUntilEnrolled(t *testing.T) {
	f := newStepAuthFixture(t)
	out, err := f.inStep(t, "list")
	require.NoError(t, err, out)
	assert.Contains(t, out, "txe: step class=worker mode=api_key (this machine is not enrolled for the worker class)")
	calls := f.jobCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "Bearer dagu_test_key", calls[0].Authorization)
}

// Once enrolled, every call a job step makes carries the machine's own token
// from the worker's client, never the API key, and never a person's sign-in.
func TestTXEStepPresentsTheMachineCredentialOnceEnrolled(t *testing.T) {
	f := newStepAuthFixture(t)
	f.enrolled(t)

	auth, err := txepkg.Home{Root: f.home}.StepAuth()
	require.NoError(t, err)
	entry, ok := auth.Enrolled("worker")
	require.True(t, ok)
	assert.Equal(t, f.path(), entry.CredentialFile)
	assert.Equal(t, f.hub.API(), entry.Hub)
	info, err := os.Stat(filepath.Join(f.home, "client", txepkg.StepAuthFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	out, err := f.inStep(t, "list")
	require.NoError(t, err, out)
	assert.Contains(t, out, "txe: step class=worker mode=credential")
	assert.NotContains(t, out, "api_key")
	calls := f.jobCalls()
	require.Len(t, calls, 1)
	assert.True(t, strings.HasPrefix(calls[0].Authorization, "Bearer ey"), "the machine's access token")
	assert.Equal(t, txeEnrolTestClient, enrolTestClaims(calls[0].Authorization).Azp)
	assert.NotContains(t, out, "eyJ", "no token is printed")
}

// For an enrolled machine, anything that keeps its credential from being
// used stops the step before any call, and a refusal is not retried with the
// API key.
func TestTXEStepFailsClosedOnceEnrolled(t *testing.T) {
	t.Run("CredentialFileGone", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		require.NoError(t, os.Rename(f.path(), f.path()+".moved"))
		out, err := f.inStep(t, "list")
		require.Error(t, err, out)
		assert.Contains(t, err.Error(), "enrolled for the worker class, and its credential")
		assert.Contains(t, err.Error(), "nothing was sent")
		assert.Empty(t, f.jobCalls())
	})

	t.Run("CredentialNotOwnerOnly", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		require.NoError(t, os.Chmod(f.path(), 0o644))
		_, err := f.inStep(t, "list")
		require.ErrorContains(t, err, "nothing was sent")
		assert.Empty(t, f.jobCalls())
	})

	t.Run("AnotherIdentityProvider", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		f.hub.Publish("https://elsewhere.invalid/realms/x", "dagu-cli", cliauth.HubUseAll)
		_, err := f.inStep(t, "list")
		require.ErrorContains(t, err, "but the hub at")
		assert.Empty(t, f.jobCalls())
	})

	t.Run("StepAuthFileNotOwnerOnly", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		require.NoError(t, os.Chmod(filepath.Join(f.home, "client", txepkg.StepAuthFile), 0o644))
		_, err := f.inStep(t, "list")
		require.ErrorContains(t, err, "cannot tell how this machine reaches the hub")
		assert.Empty(t, f.jobCalls())
	})

	t.Run("AnotherHub", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		require.NoError(t, txepkg.Home{Root: f.home}.SetStepCredential("worker", f.path(), "https://other.invalid/api/v1"))
		_, err := f.inStep(t, "list")
		require.ErrorContains(t, err, "is enrolled with the hub at https://other.invalid/api/v1, but this step reaches")
		assert.Empty(t, f.jobCalls())
	})

	t.Run("ARedirectElsewhere", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		var leaked []string
		elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			leaked = append(leaked, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(elsewhere.Close)
		enrol := f.hub.Handle
		f.hub.Handle = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == "/api/v1/txe/jobs" {
				http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusFound)
				return true
			}
			return enrol(w, r)
		}
		_, err := f.inStep(t, "list")
		require.Error(t, err)
		assert.Empty(t, leaked, "the token was not sent to the redirect's target")
	})

	t.Run("RotationNotSaved", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		// The provider rotates the refresh token; the credential's directory
		// no longer takes the new one.
		require.NoError(t, os.Chmod(f.home, 0o500))
		t.Cleanup(func() { _ = os.Chmod(f.home, 0o700) })
		_, err := f.inStep(t, "list")
		require.ErrorContains(t, err, "renewed credential could not be saved")
		assert.Empty(t, f.jobCalls())
	})

	t.Run("RefusedIsNotRetried", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		f.refuseJobs = true
		_, err := f.inStep(t, "list")
		require.Error(t, err)
		calls := f.jobCalls()
		require.Len(t, calls, 1, "one call, not a second with the API key")
		assert.True(t, strings.HasPrefix(calls[0].Authorization, "Bearer ey"))
	})
}

// A reviewer step needs the reviewer class: a machine enrolled for the worker
// class only keeps the API key there, and one recorded as enrolled for the
// reviewer class is refused until this build reads reviewer credentials.
func TestTXEStepClass(t *testing.T) {
	f := newStepAuthFixture(t)
	f.enrolled(t)
	root := txeAuthRoot()
	txe := TXE()
	root.AddCommand(txe)
	classes := func() map[string]string {
		got := map[string]string{}
		for _, c := range txe.Commands() {
			got[c.Name()] = string(txeStepClass(c))
			for _, leaf := range c.Commands() {
				got[c.Name()+" "+leaf.Name()] = string(txeStepClass(leaf))
			}
		}
		return got
	}
	// In this machine's reviewer or decide DAG, txe review commands need the
	// reviewer class, every other command the worker class.
	for _, dag := range []string{review.ReviewerDAGName(txeEnrolTestMachine), review.DecideDAGName(txeEnrolTestMachine)} {
		t.Setenv(runenv.EnvKeyDAGName, dag)
		for name, class := range classes() {
			want := "worker"
			if name == "review" || strings.HasPrefix(name, "review ") {
				want = "reviewer"
			}
			assert.Equal(t, want, class, dag+": "+name)
		}
	}
	// In a job's DAG, or another machine's reviewer DAG, even txe review is
	// worker class: a job's own command cannot present the reviewer's.
	for _, dag := range []string{"job_01K7A5ZQ8M3N4P5R6S7T8V9W0J", review.ReviewerDAGName("mch_01K7A5ZQ8M3N4P5R6S7T8V9W0X")} {
		t.Setenv(runenv.EnvKeyDAGName, dag)
		for name, class := range classes() {
			assert.Equal(t, "worker", class, dag+": "+name)
		}
	}

	reviewerCall := func() error {
		t.Setenv(runenv.EnvKeyDAGRunID, "run-1")
		t.Setenv(runenv.EnvKeyDAGRunStepName, "review")
		t.Setenv(runenv.EnvKeyDAGName, review.ReviewerDAGName(txeEnrolTestMachine))
		var callErr error
		txe := TXE()
		for _, c := range txe.Commands() {
			if c.Name() == "review" {
				c.AddCommand(NewCommand(&cobra.Command{Use: "probe", Args: cobra.NoArgs}, nil, func(ctx *Context, _ []string) error {
					client, err := txeClient(ctx)
					if err == nil {
						_, err = client.ListJobs(ctx, txeclient.JobFilter{})
					}
					callErr = err
					return nil
				}))
			}
		}
		root := txeAuthRoot()
		root.AddCommand(txe)
		root.SetArgs([]string{"txe", "review", "probe", "--dagu-home", filepath.Dir(f.contexts), "--contexts-dir", f.contexts, "--data-dir", f.data})
		require.NoError(t, root.Execute())
		return callErr
	}
	// Enrolled for the worker class only: a reviewer step keeps the API key.
	require.NoError(t, reviewerCall())
	calls := f.jobCalls()
	require.NotEmpty(t, calls)
	assert.Equal(t, "Bearer dagu_test_key", calls[len(calls)-1].Authorization)

	// Recorded as enrolled for the reviewer class with the worker's file: a
	// reviewer step does not present a worker's credential; nothing is sent.
	require.NoError(t, txepkg.Home{Root: f.home}.SetStepCredential("reviewer", f.path(), f.hub.API()))
	before := len(f.jobCalls())
	require.ErrorContains(t, reviewerCall(), "the reviewer step's credential")
	assert.Len(t, f.jobCalls(), before)
}

const txeEnrolTestReviewerClient = "dagu-reviewer-mch_enroltest"

// A machine enrolled for the reviewer class with its own reviewer client:
// enrol writes the reviewer credential beside the worker's and records the
// class; a reviewer step presents that credential, from the reviewer client,
// and a job step keeps what the worker class says.
func TestTXEStepPresentsTheReviewerCredential(t *testing.T) {
	f := newStepAuthFixture(t)
	f.provider.ClientID = txeEnrolTestReviewerClient
	before := txeEnrolInterval
	txeEnrolInterval = 20 * time.Millisecond
	t.Cleanup(func() { txeEnrolInterval = before })
	f.approveAfter = 1
	out := f.json("enrol", "--class", "reviewer", "--client-id", txeEnrolTestReviewerClient, "--wait", "10s")
	require.Equal(t, "enrolled", out["state"])
	assert.Equal(t, "reviewer", out["class"])
	reviewerFile := filepath.Join(f.home, txeEnrolReviewerCredentialFile)
	assert.Equal(t, reviewerFile, out["credential_file"])
	credential, err := transportauth.ReadMachineCredential(reviewerFile)
	require.NoError(t, err)
	assert.Equal(t, "reviewer", string(credential.Class))
	assert.NoFileExists(t, f.path(), "the worker's credential is not written")
	auth, err := txepkg.Home{Root: f.home}.StepAuth()
	require.NoError(t, err)
	entry, ok := auth.Enrolled("reviewer")
	require.True(t, ok)
	assert.Equal(t, reviewerFile, entry.CredentialFile)
	_, ok = auth.Enrolled("worker")
	assert.False(t, ok)

	// A reviewer step presents the reviewer credential.
	t.Setenv(runenv.EnvKeyDAGRunID, "run-1")
	t.Setenv(runenv.EnvKeyDAGRunStepName, "review")
	t.Setenv(runenv.EnvKeyDAGName, review.ReviewerDAGName(txeEnrolTestMachine))
	var callErr error
	txe := TXE()
	for _, c := range txe.Commands() {
		if c.Name() == "review" {
			c.AddCommand(NewCommand(&cobra.Command{Use: "probe", Args: cobra.NoArgs}, nil, func(ctx *Context, _ []string) error {
				client, err := txeClient(ctx)
				if err == nil {
					_, err = client.ListJobs(ctx, txeclient.JobFilter{})
				}
				callErr = err
				return nil
			}))
		}
	}
	root := txeAuthRoot()
	root.AddCommand(txe)
	root.SetArgs([]string{"txe", "review", "probe", "--dagu-home", filepath.Dir(f.contexts), "--contexts-dir", f.contexts, "--data-dir", f.data})
	require.NoError(t, root.Execute())
	require.NoError(t, callErr)
	calls := f.jobCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, txeEnrolTestReviewerClient, enrolTestClaims(calls[0].Authorization).Azp)

	// A job step on this machine is not enrolled for the worker class.
	out2, err := f.inStep(t, "list")
	require.NoError(t, err, out2)
	assert.Contains(t, out2, "class=worker mode=api_key")
}

// A command other than txe, run by a step against a context, presents the
// machine's credential when that context reaches the enrolled hub, and keeps
// its own key for any other hub.
func TestTXEStepRemoteForOtherCommands(t *testing.T) {
	f := newStepAuthFixture(t)
	f.enrolled(t)
	other := &cobra.Command{Use: "status"}
	(&cobra.Command{Use: "dagu"}).AddCommand(other)
	ctx := context.Background()

	enrolledHub, err := newRemoteClient(&cliContext{Name: "txe", ServerURL: f.hub.API(), APIKey: "dagu_test_key"})
	require.NoError(t, err)
	got, err := txeStepRemote(ctx, other, enrolledHub)
	require.NoError(t, err)
	assert.Empty(t, got.apiKey, "the API key is not sent to the enrolled hub")
	assert.IsType(t, &txeMachineTransport{}, got.client.Transport)

	elsewhere, err := newRemoteClient(&cliContext{Name: "other", ServerURL: "https://other.invalid/api/v1", APIKey: "dagu_other_key"})
	require.NoError(t, err)
	got, err = txeStepRemote(ctx, other, elsewhere)
	require.NoError(t, err)
	assert.Same(t, elsewhere, got, "a context for another hub keeps its own key")
}

// Two spellings of one destination are one hub for a step's credential.
func TestTXEHubKey(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://hub.example/api/v1", "https://hub.example:443/api/v1"},
		{"https://Hub.Example/api/v1/", "https://hub.example/api/v1"},
		{"http://127.0.0.1/api/v1", "http://127.0.0.1:80/api/v1"},
		{"https://[::1]/api/v1", "https://[::1]:443/api/v1"},
	} {
		a, err := txeHubKey(pair[0])
		require.NoError(t, err)
		b, err := txeHubKey(pair[1])
		require.NoError(t, err)
		assert.Equal(t, a, b, pair)
	}
	for _, pair := range [][2]string{
		{"http://hub.example/api/v1", "https://hub.example/api/v1"},
		{"https://hub.example:8443/api/v1", "https://hub.example/api/v1"},
	} {
		a, _ := txeHubKey(pair[0])
		b, _ := txeHubKey(pair[1])
		assert.NotEqual(t, a, b, pair)
	}
}

// "dagu context test" run by a step builds its own client for the context.
// For the enrolled hub it never carries the stored key, and its route
// (/auth/me) is not one that takes a machine's token, so it carries nothing.
func TestTXEStepContextTestSendsNoKeyToTheEnrolledHub(t *testing.T) {
	f := newStepAuthFixture(t)
	f.enrolled(t)
	t.Setenv("DAGU_CONTEXTS_DIR", f.contexts)
	t.Setenv("DAGU_DATA_DIR", f.data)
	t.Setenv(runenv.EnvKeyDAGRunID, "run-1")
	t.Setenv(runenv.EnvKeyDAGRunStepName, "check")
	root := txeAuthRoot()
	root.AddCommand(ContextCommand())
	var out strings.Builder
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"context", "test", txeContextName, "--dagu-home", filepath.Dir(f.contexts)})
	_ = root.Execute()
	var me []cliauthtest.Request
	for _, r := range f.hub.Requests() {
		if r.Path == "/api/v1/auth/me" {
			me = append(me, r)
		}
	}
	require.Len(t, me, 1, out.String())
	assert.Empty(t, me[0].Authorization, "neither the key nor the machine's token")
}

// An answer outside 2xx that echoes the request's credential, an error or a
// redirect (which is not followed), has it replaced before the step prints it.
func TestTXEStepRedactsAnEchoedBearer(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newStepAuthFixture(t)
			f.enrolled(t)
			enrol := f.hub.Handle
			f.hub.Handle = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == "/api/v1/txe/jobs" {
					if status == http.StatusFound {
						w.Header().Set("Location", "/elsewhere")
					}
					cliauthtest.WriteJSON(w, status, map[string]any{"code": "refused", "message": "refused " + r.Header.Get("Authorization")})
					return true
				}
				return enrol(w, r)
			}
			out, err := f.inStep(t, "list")
			require.Error(t, err)
			calls := f.jobCalls()
			require.Len(t, calls, 1)
			token := strings.TrimPrefix(calls[0].Authorization, "Bearer ")
			require.NotEmpty(t, token)
			assert.NotContains(t, err.Error(), token)
			assert.NotContains(t, out, token)
			assert.Contains(t, err.Error(), "[redacted]")
		})
	}
}

// What is presented is checked against the credential that was checked:
// another issuer, another client, or no JWT at all is not sent.
func TestTXEStepChecksTheTokenItPresents(t *testing.T) {
	f := newStepAuthFixture(t)
	f.enrolled(t)
	source, err := transportauth.NewRefreshingSource(f.path())
	require.NoError(t, err)
	tr := &txeMachineTransport{source: source, issuer: f.provider.Issuer(), clientID: txeEnrolTestClient, machineID: txeEnrolTestMachine}
	jwt := func(claims map[string]string) string {
		body, err := json.Marshal(claims)
		require.NoError(t, err)
		return "e30." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
	}
	require.NoError(t, tr.checkToken(jwt(map[string]string{"iss": f.provider.Issuer(), "azp": txeEnrolTestClient})))
	require.ErrorContains(t, tr.checkToken(jwt(map[string]string{"iss": "https://elsewhere.invalid", "azp": txeEnrolTestClient})), "nothing was sent")
	require.ErrorContains(t, tr.checkToken(jwt(map[string]string{"iss": f.provider.Issuer(), "azp": "another-client"})), "nothing was sent")
	require.ErrorContains(t, tr.checkToken("opaque-token"), "not a JWT")
	tr.machineID = "mch_other"
	require.ErrorContains(t, tr.checkToken(jwt(map[string]string{"iss": f.provider.Issuer(), "azp": txeEnrolTestClient})), "now names machine")
}

// The hub decides an application's class from the token's client. Enrolling
// a client as the other class is refused, and nothing is recorded for steps.
func TestTXEEnrolRefusesAClientOfAnotherClass(t *testing.T) {
	for name, tc := range map[string]struct{ class, client string }{
		"ReviewerWithAWorkerClient": {"reviewer", txeEnrolTestClient},
		"WorkerWithAReviewerClient": {"worker", txeEnrolTestReviewerClient},
	} {
		t.Run(name, func(t *testing.T) {
			f := newStepAuthFixture(t)
			f.provider.ClientID = tc.client
			_, err := f.run("enrol", "--class", tc.class, "--client-id", tc.client)
			require.ErrorContains(t, err, "not \""+tc.class+"\"")
			auth, err := txepkg.Home{Root: f.home}.StepAuth()
			require.NoError(t, err)
			assert.Empty(t, auth.Classes)
		})
	}
}

// A machine whose own store holds no API key registers with its enrolled
// worker credential: the registrar reads the hub with that credential, as
// the job's steps will (TXE-4760). Without a worker enrolment, with only a
// reviewer one, or enrolled with another hub, it is refused. A store with
// an API key keeps it.
func TestTXEMachineStepClient(t *testing.T) {
	ctx := context.Background()
	signInOnly := func(f *stepAuthFixture) *cliContext {
		return &cliContext{Name: txeContextName, ServerURL: f.hub.API(), SignInOnly: true}
	}
	machineCalls := func(f *stepAuthFixture) []cliauthtest.Request {
		var out []cliauthtest.Request
		for _, r := range f.hub.Requests() {
			if r.Method == http.MethodGet && r.Path == "/api/v1/txe/machines/"+txeEnrolTestMachine {
				out = append(out, r)
			}
		}
		return out
	}

	t.Run("EnrolledWorkerNoKey", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		home := txepkg.Home{Root: f.home}
		client, err := txeMachineStepClient(ctx, home, signInOnly(f))
		require.NoError(t, err)
		before := len(machineCalls(f))
		_, err = client.Machine(ctx, txeEnrolTestMachine)
		require.NoError(t, err)
		calls := machineCalls(f)
		require.Len(t, calls, before+1)
		last := calls[len(calls)-1]
		assert.Equal(t, txeEnrolTestClient, enrolTestClaims(last.Authorization).Azp, "the worker's own token")
		assert.NotContains(t, last.Authorization, "dagu_")
	})

	t.Run("NotEnrolled", func(t *testing.T) {
		f := newStepAuthFixture(t)
		_, err := txeMachineStepClient(ctx, txepkg.Home{Root: f.home}, signInOnly(f))
		require.ErrorContains(t, err, "not enrolled for the worker class")
	})

	t.Run("ReviewerOnly", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.provider.ClientID = txeEnrolTestReviewerClient
		before := txeEnrolInterval
		txeEnrolInterval = 20 * time.Millisecond
		t.Cleanup(func() { txeEnrolInterval = before })
		f.approveAfter = 1
		out := f.json("enrol", "--class", "reviewer", "--client-id", txeEnrolTestReviewerClient, "--wait", "10s")
		require.Equal(t, "enrolled", out["state"])
		_, err := txeMachineStepClient(ctx, txepkg.Home{Root: f.home}, signInOnly(f))
		require.ErrorContains(t, err, "not enrolled for the worker class")
	})

	t.Run("EnrolledWithAnotherHub", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		other := signInOnly(f)
		other.ServerURL = "https://other.invalid/api/v1"
		_, err := txeMachineStepClient(ctx, txepkg.Home{Root: f.home}, other)
		require.ErrorContains(t, err, "is enrolled with the hub at")
	})

	t.Run("CredentialGone", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		require.NoError(t, os.Rename(f.path(), f.path()+".moved"))
		_, err := txeMachineStepClient(ctx, txepkg.Home{Root: f.home}, signInOnly(f))
		require.ErrorContains(t, err, "nothing was sent")
	})

	t.Run("APIKeyStoreUnchanged", func(t *testing.T) {
		f := newStepAuthFixture(t)
		f.enrolled(t)
		client, err := txeMachineStepClient(ctx, txepkg.Home{Root: f.home}, &cliContext{Name: txeContextName, ServerURL: f.hub.API(), APIKey: "dagu_test_key"})
		require.NoError(t, err)
		assert.Equal(t, "dagu_test_key", client.APIKey)
	})
}
