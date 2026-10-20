// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
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
	root := txeAuthRoot()
	txe := TXE()
	root.AddCommand(txe)
	for _, c := range txe.Commands() {
		want := "worker"
		if c.Name() == "review" {
			want = "reviewer"
		}
		assert.Equal(t, want, string(txeStepClass(c)), c.Name())
		for _, leaf := range c.Commands() {
			assert.Equal(t, want, string(txeStepClass(leaf)), c.Name()+" "+leaf.Name())
		}
	}

	f := newStepAuthFixture(t)
	f.enrolled(t)
	reviewerCall := func() error {
		t.Setenv(runenv.EnvKeyDAGRunID, "run-1")
		t.Setenv(runenv.EnvKeyDAGRunStepName, "review")
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

	// Recorded as enrolled for the reviewer class: refused, nothing sent.
	require.NoError(t, txepkg.Home{Root: f.home}.SetStepCredential("reviewer", f.path(), f.hub.API()))
	before := len(f.jobCalls())
	require.ErrorContains(t, reviewerCall(), "enrolled for the reviewer class, but this build reads only worker credentials")
	assert.Len(t, f.jobCalls(), before)
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
