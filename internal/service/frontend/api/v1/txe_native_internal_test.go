// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// neutral is what txeNeutralize does to a caller held to its owner on its
// way to a handler: the same caller, with a hub user that has no role and
// no workspace.
func neutral(ctx context.Context) context.Context {
	c := txeauth.Classify(ctx)
	user, _ := auth.UserFromContext(ctx)
	return auth.WithUser(ctx, txeNeutralUser(c, user))
}

func TestTxeNeutralizeTakesTheHubRoleAway(t *testing.T) {
	w := newTwoOwners(t, "")
	var seen *auth.User
	h := w.api.txeNeutralize(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen, _ = auth.UserFromContext(r.Context()) }))
	serve := func(ctx context.Context) *auth.User {
		seen = nil
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/dags", nil).WithContext(ctx))
		return seen
	}

	// A person provisioned as an administrator keeps its name and identity
	// and loses the role and every workspace.
	admin := ownersPerson("a")
	got := serve(admin)
	require.Equal(t, auth.RoleNone, got.Role)
	require.Equal(t, "user-a", got.Username)
	require.Equal(t, auth.AuthProviderOIDC, got.AuthProvider)
	require.False(t, auth.NormalizeWorkspaceAccess(got.WorkspaceAccess).All)
	require.Empty(t, got.WorkspaceAccess.Grants)
	require.Equal(t, txeauth.KindPerson, txeauth.Classify(auth.WithUser(admin, got)).Kind)

	// A token gets a hub user of the same kind, named as its agent.
	got = serve(w.cliA)
	require.Equal(t, auth.RoleNone, got.Role)
	require.Equal(t, "token:dagu-cli:a", got.Username)

	// Everyone else is untouched.
	require.Equal(t, auth.RoleAdmin, serve(w.admin).Role)
	require.Equal(t, auth.RoleAdmin, serve(w.legacy).Role)
}

func TestTxeNativeRunsAreOwnerScoped(t *testing.T) {
	w := newTwoOwners(t, "")
	w.markReady(w.jobA, w.machineA)
	w.addRun(w.jobA, "run-1", "production")
	personA, personB, cliA, reviewerA, reviewerB := neutral(w.personA), neutral(w.personB), neutral(w.cliA), neutral(w.reviewerA), neutral(w.reviewerB)

	// These handlers answer a refusal with a typed 404 response and no
	// error, so the response itself is what is checked.
	details := func(ctx context.Context) error {
		resp, err := w.api.GetDAGRunDetails(ctx, apigen.GetDAGRunDetailsRequestObject{Name: w.jobA, DagRunId: "run-1"})
		if err != nil {
			return err
		}
		if _, ok := resp.(*apigen.GetDAGRunDetails200JSONResponse); !ok {
			return &Error{HTTPStatus: http.StatusNotFound, Message: "no details"}
		}
		return nil
	}
	logs := func(ctx context.Context) error {
		resp, err := w.api.GetDAGRunLog(ctx, apigen.GetDAGRunLogRequestObject{Name: w.jobA, DagRunId: "run-1"})
		if err != nil {
			return err
		}
		if _, ok := resp.(apigen.GetDAGRunLog200JSONResponse); !ok {
			return &Error{HTTPStatus: http.StatusNotFound, Message: "no log"}
		}
		return nil
	}
	// The owner's person, CLI and the job's own machine see the run, with
	// no workspace grant for "production"; another owner does not learn it
	// exists.
	for _, ctx := range []context.Context{personA, cliA, reviewerA} {
		require.NoError(t, details(ctx))
		require.NoError(t, logs(ctx))
	}
	for _, ctx := range []context.Context{personB, reviewerB, neutral(w.nobody)} {
		require.Equal(t, http.StatusNotFound, statusOf(details(ctx)))
		require.Equal(t, http.StatusNotFound, statusOf(logs(ctx)))
	}
	// A legacy credential in mode off reads as today.
	require.NoError(t, details(w.legacy))

	// Runs of one DAG: the owner sees them, another owner sees none.
	byName := func(ctx context.Context) int {
		resp, err := w.api.ListDAGRunsByName(ctx, apigen.ListDAGRunsByNameRequestObject{Name: w.jobA})
		require.NoError(t, err)
		return len(resp.(apigen.ListDAGRunsByName200JSONResponse).DagRuns)
	}
	require.Equal(t, 1, byName(personA))
	require.Zero(t, byName(personB))

	// Execute: a person of another owner is not told; the owner's
	// reviewer may stop the job's run.
	stop := func(ctx context.Context) error {
		_, err := w.api.TerminateDAGRun(ctx, apigen.TerminateDAGRunRequestObject{Name: w.jobA, DagRunId: "run-1"})
		return err
	}
	require.Equal(t, http.StatusNotFound, statusOf(stop(personB)))
	require.NotEqual(t, http.StatusNotFound, statusOf(stop(reviewerA)))
	require.NotEqual(t, http.StatusForbidden, statusOf(stop(reviewerA)))
}

func TestTxeNativeDAGsAreOwnerScoped(t *testing.T) {
	w := newTwoOwners(t, "")
	w.addRun(w.jobA, "run-1", "production")
	personA, personB := neutral(w.personA), neutral(w.personB)

	history := func(ctx context.Context, dag string) error {
		resp, err := w.api.GetDAGDAGRunHistory(ctx, apigen.GetDAGDAGRunHistoryRequestObject{FileName: dag})
		if err != nil {
			return err
		}
		if _, ok := resp.(apigen.GetDAGDAGRunHistory200JSONResponse); !ok {
			return &Error{HTTPStatus: http.StatusNotFound, Message: "no history"}
		}
		return nil
	}
	require.NoError(t, history(personA, w.jobA))
	require.Equal(t, http.StatusNotFound, statusOf(history(personB, w.jobA)))

	// The whole-hub DAG list shows such a caller nothing; its jobs are in
	// /txe/jobs.
	resp, err := w.api.ListDAGs(personA, apigen.ListDAGsRequestObject{})
	require.NoError(t, err)
	require.Empty(t, resp.(*apigen.ListDAGs200JSONResponse).Dags)
	resp, err = w.api.ListDAGs(w.legacy, apigen.ListDAGsRequestObject{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.(*apigen.ListDAGs200JSONResponse).Dags, "a legacy key in mode off lists as today")

	// A job DAG's spec is the registry's: it is not written natively by
	// anyone held to an owner, its owner included.
	spec := "steps:\n  - name: run\n    run: echo hi\n"
	_, err = w.api.UpdateDAGSpec(personA, apigen.UpdateDAGSpecRequestObject{FileName: w.jobA, Body: &apigen.UpdateDAGSpecJSONRequestBody{Spec: spec}})
	require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, statusOf(err))
	_, err = w.api.DeleteDAG(personA, apigen.DeleteDAGRequestObject{FileName: w.jobA})
	require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, statusOf(err))
	_, err = w.reg.GetJob(context.Background(), w.jobA)
	require.NoError(t, err)
}

func TestTxeNativeCheckOwnerlessAndModes(t *testing.T) {
	ctx := context.Background()
	off := newTwoOwners(t, "")
	legacy := func(error) func() error { return func() error { return nil } }

	// A DAG with no owner is the platform's.
	require.Equal(t, http.StatusNotFound, statusOf(off.api.txeNativeCheck(neutral(off.personA), "nightly-backup", authz.PermissionView, legacy(nil))))
	require.NoError(t, off.api.txeNativeCheck(off.legacy, "nightly-backup", authz.PermissionView, legacy(nil)))
	// Per-machine DAGs belong to the machine's owner.
	reviewerDAG := "txe-reviewer-" + off.machineA[len("mch_"):]
	require.NoError(t, off.api.txeNativeCheck(neutral(off.personA), reviewerDAG, authz.PermissionView, legacy(nil)))
	require.Equal(t, http.StatusNotFound, statusOf(off.api.txeNativeCheck(neutral(off.personB), reviewerDAG, authz.PermissionView, legacy(nil))))

	enforce := newTwoOwners(t, "enforce")
	// In enforce a legacy key sees no owner's DAG and no ownerless one; the
	// administrator sees both and runs none of an owner's.
	require.Equal(t, http.StatusNotFound, statusOf(enforce.api.txeNativeCheck(enforce.legacy, enforce.jobA, authz.PermissionView, legacy(nil))))
	require.Equal(t, http.StatusNotFound, statusOf(enforce.api.txeNativeCheck(enforce.legacy, "nightly-backup", authz.PermissionView, legacy(nil))))
	require.NoError(t, enforce.api.txeNativeCheck(enforce.admin, enforce.jobA, authz.PermissionView, legacy(nil)))
	require.NoError(t, enforce.api.txeNativeCheck(enforce.admin, "nightly-backup", authz.PermissionView, legacy(nil)))
	require.Equal(t, http.StatusForbidden, statusOf(enforce.api.txeNativeCheck(enforce.admin, enforce.jobA, authz.PermissionExecute, legacy(nil))))

	observe := newTwoOwners(t, "observe")
	require.NoError(t, observe.api.txeNativeCheck(observe.legacy, observe.jobA, authz.PermissionView, legacy(nil)))
	require.NoError(t, observe.api.txeNativeCheck(observe.legacy, "nightly-backup", authz.PermissionExecute, legacy(nil)))
	_ = ctx
}

func TestTxeNativeValidateIsClosedToOwnerHeldCallers(t *testing.T) {
	w := newTwoOwners(t, "")
	spec := "steps:\n  - name: run\n    run: echo hi\n"
	_, err := w.api.ValidateDAGSpec(neutral(w.personA), apigen.ValidateDAGSpecRequestObject{Body: &apigen.ValidateDAGSpecJSONRequestBody{Spec: spec}})
	require.Equal(t, http.StatusForbidden, statusOf(err))
	_, err = w.api.ValidateDAGSpec(w.legacy, apigen.ValidateDAGSpecRequestObject{Body: &apigen.ValidateDAGSpecJSONRequestBody{Spec: spec}})
	require.NoError(t, err)
}
