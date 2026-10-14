// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

func ownersPerson(subject string) context.Context {
	return auth.WithUser(context.Background(), &auth.User{Username: "user-" + subject, Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderOIDC,
		OIDCIssuer: ownersIssuer, OIDCSubject: subject})
}

func TestTxeAccessBindings(t *testing.T) {
	w := newTwoOwners(t, "")
	carol := ownersPerson("carol")

	// Only a person asks, for itself; a token, a legacy key or the
	// administrator cannot.
	for _, ctx := range []context.Context{w.nobody, w.legacy, w.admin} {
		_, err := w.api.RequestTxeBinding(ctx, apigen.RequestTxeBindingRequestObject{})
		require.Equal(t, http.StatusForbidden, statusOf(err))
	}
	resp, err := w.api.RequestTxeBinding(carol, apigen.RequestTxeBindingRequestObject{})
	require.NoError(t, err)
	request := apigen.TxeBindingRequest(resp.(apigen.RequestTxeBinding201JSONResponse))
	require.Equal(t, "carol", request.Subject)
	require.Equal(t, apigen.TxeBindingRequestStatePending, request.State)

	// Only the administrator lists and approves, in every mode.
	for _, ctx := range []context.Context{w.cliA, w.personA, w.legacy} {
		_, err := w.api.ListTxeBindingRequests(ctx, apigen.ListTxeBindingRequestsRequestObject{})
		require.Equal(t, http.StatusForbidden, statusOf(err))
	}
	list, err := w.api.ListTxeBindingRequests(w.admin, apigen.ListTxeBindingRequestsRequestObject{})
	require.NoError(t, err)
	require.Len(t, list.(apigen.ListTxeBindingRequests200JSONResponse).Requests, 1)

	approve := func(ctx context.Context, generation int) error {
		_, err := w.api.ApproveTxeBinding(ctx, apigen.ApproveTxeBindingRequestObject{OwnerId: w.ownerB,
			Body: &apigen.ApproveTxeBindingJSONRequestBody{Issuer: ownersIssuer, Subject: "carol", RequestGeneration: generation}})
		return err
	}
	require.Equal(t, http.StatusForbidden, statusOf(approve(w.personB, 1)))
	err = approve(w.admin, 2)
	require.Equal(t, http.StatusConflict, statusOf(err))
	require.Equal(t, "conflict", detailOf(err))
	require.NoError(t, approve(w.admin, 1))

	// The owner's person and the administrator see its bindings; nobody
	// else learns the owner has any.
	bindings := func(ctx context.Context, owner string) ([]apigen.TxeBinding, error) {
		resp, err := w.api.ListTxeOwnerBindings(ctx, apigen.ListTxeOwnerBindingsRequestObject{OwnerId: owner})
		if err != nil {
			return nil, err
		}
		return resp.(apigen.ListTxeOwnerBindings200JSONResponse).Bindings, nil
	}
	got, err := bindings(carol, w.ownerB)
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, ctx := range []context.Context{w.personA, w.cliB} {
		_, err := bindings(ctx, w.ownerB)
		require.Equal(t, http.StatusNotFound, statusOf(err))
	}
	got, err = bindings(w.admin, w.ownerB)
	require.NoError(t, err)
	var carolID string
	for _, b := range got {
		if b.Subject == "carol" {
			carolID = b.BindingId
		}
	}
	require.NotEmpty(t, carolID)

	revoke := func(ctx context.Context, id string) error {
		_, err := w.api.RevokeTxeBinding(ctx, apigen.RevokeTxeBindingRequestObject{OwnerId: w.ownerB, BindingId: id,
			Body: &apigen.RevokeTxeBindingJSONRequestBody{Reason: "left"}})
		return err
	}
	require.Equal(t, http.StatusForbidden, statusOf(revoke(w.personB, carolID)))
	require.Equal(t, http.StatusNotFound, statusOf(revoke(w.admin, "no-such-binding")))
	require.NoError(t, revoke(w.admin, carolID))
	require.Empty(t, w.listJobs(carol))
}

func TestTxeAccessShares(t *testing.T) {
	w := newTwoOwners(t, "")
	grant := func(ctx context.Context, permissions ...apigen.TxeAccessPermission) (apigen.TxeShare, error) {
		resp, err := w.api.GrantTxeShare(ctx, apigen.GrantTxeShareRequestObject{Body: &apigen.GrantTxeShareJSONRequestBody{
			Resource: apigen.TxeAccessResource{Kind: apigen.TxeAccessResourceKindJob, Id: w.jobA}, GranteeOwnerId: w.ownerB, Permissions: permissions}})
		if err != nil {
			return apigen.TxeShare{}, err
		}
		return apigen.TxeShare(resp.(apigen.GrantTxeShare201JSONResponse)), nil
	}
	// Only the owner's person grants, never administer.
	_, err := grant(w.cliA, apigen.TxeAccessPermissionView)
	require.Equal(t, http.StatusForbidden, statusOf(err))
	_, err = grant(w.personB, apigen.TxeAccessPermissionView)
	require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, statusOf(err))
	_, err = grant(w.personA, apigen.TxeAccessPermissionAdminister)
	require.Equal(t, http.StatusBadRequest, statusOf(err))
	_, err = grant(w.nobody, apigen.TxeAccessPermissionView)
	require.Equal(t, "unbound", detailOf(err))

	share, err := grant(w.personA, apigen.TxeAccessPermissionView)
	require.NoError(t, err)
	require.Equal(t, w.ownerB, share.Grantee.OwnerId)
	require.Equal(t, "Owner B", share.Grantee.DisplayName)

	list := func(ctx context.Context) apigen.ListTxeShares200JSONResponse {
		resp, err := w.api.ListTxeShares(ctx, apigen.ListTxeSharesRequestObject{})
		require.NoError(t, err)
		return resp.(apigen.ListTxeShares200JSONResponse)
	}
	require.Len(t, list(w.cliA).Granted, 1)
	require.Len(t, list(w.cliB).Received, 1)
	require.Empty(t, list(w.nobody).Granted)
	require.Empty(t, list(w.admin).Received)

	// B now sees A's job, and is told how.
	require.NoError(t, w.getJob(w.cliB, w.jobA))
	resp, err := w.api.GetTxeJob(w.cliB, apigen.GetTxeJobRequestObject{JobId: w.jobA})
	require.NoError(t, err)
	access := resp.(apigen.GetTxeJob200JSONResponse).Access
	require.NotNil(t, access)
	require.Equal(t, apigen.TxeJobAccessViaShare, access.Via)
	require.Equal(t, w.ownerA, access.SharedBy.OwnerId)
	require.Equal(t, []apigen.TxeAccessPermission{apigen.TxeAccessPermissionView}, access.Permissions)

	revoke := func(ctx context.Context, id string) error {
		_, err := w.api.RevokeTxeShare(ctx, apigen.RevokeTxeShareRequestObject{ShareId: id, Body: &apigen.RevokeTxeShareJSONRequestBody{Reason: "done"}})
		return err
	}
	require.Equal(t, http.StatusNotFound, statusOf(revoke(w.personB, share.ShareId)))
	require.NoError(t, revoke(w.personA, share.ShareId))
	require.Equal(t, http.StatusNotFound, statusOf(w.getJob(w.cliB, w.jobA)))
}

func TestTxeAccessLabel(t *testing.T) {
	w := newTwoOwners(t, "")
	resp, err := w.api.GetTxeJob(w.cliA, apigen.GetTxeJobRequestObject{JobId: w.jobA})
	require.NoError(t, err)
	access := resp.(apigen.GetTxeJob200JSONResponse).Access
	require.Equal(t, apigen.TxeJobAccessViaOwner, access.Via)
	require.Equal(t, []apigen.TxeAccessPermission{apigen.TxeAccessPermissionView, apigen.TxeAccessPermissionAuthor, apigen.TxeAccessPermissionExecute}, access.Permissions)
	// A legacy key in mode off is labelled with nothing.
	resp, err = w.api.GetTxeJob(w.legacy, apigen.GetTxeJobRequestObject{JobId: w.jobA})
	require.NoError(t, err)
	require.Nil(t, resp.(apigen.GetTxeJob200JSONResponse).Access)

	enforce := newTwoOwners(t, "enforce")
	resp, err = enforce.api.GetTxeJob(enforce.admin, apigen.GetTxeJobRequestObject{JobId: enforce.jobA})
	require.NoError(t, err)
	access = resp.(apigen.GetTxeJob200JSONResponse).Access
	require.Equal(t, apigen.TxeJobAccessViaPlatformAdmin, access.Via)
	require.Equal(t, []apigen.TxeAccessPermission{apigen.TxeAccessPermissionView}, access.Permissions)
}

func TestTxeAccessEnrolment(t *testing.T) {
	w := newTwoOwners(t, "")
	ctx := context.Background()
	m2, err := registry.NewID(registry.PrefixMachine, time.Now())
	require.NoError(t, err)
	_, err = w.reg.CreateMachine(ctx, registry.Machine{MachineID: m2, OwnerID: w.ownerA, DisplayName: "build box"}, registry.Actor{Kind: registry.ActorSystem, ID: "test"})
	require.NoError(t, err)
	worker2 := txeauth.WithToken(ctx, ownersPrincipal("a", authn.ClassWorker, "dagu-worker-a2"))

	apply := func(ctx context.Context, machine string) error {
		_, err := w.api.ApplyTxeEnrolment(ctx, apigen.ApplyTxeEnrolmentRequestObject{MachineId: machine})
		return err
	}
	// Only a machine credential applies, and only for its own owner's machine.
	require.Equal(t, http.StatusForbidden, statusOf(apply(w.cliA, m2)))
	require.Equal(t, http.StatusForbidden, statusOf(apply(w.personA, m2)))
	require.Equal(t, http.StatusNotFound, statusOf(apply(worker2, w.machineB)))
	require.NoError(t, apply(worker2, m2))

	applications := func(ctx context.Context) error {
		_, err := w.api.ListTxeEnrolmentApplications(ctx, apigen.ListTxeEnrolmentApplicationsRequestObject{MachineId: m2})
		return err
	}
	require.NoError(t, applications(w.personA))
	for _, ctx := range []context.Context{w.cliA, w.personB, w.admin, w.legacy} {
		require.Equal(t, http.StatusNotFound, statusOf(applications(ctx)))
	}

	enrol := func(ctx context.Context, subject string) error {
		_, err := w.api.EnrolTxeMachine(ctx, apigen.EnrolTxeMachineRequestObject{MachineId: m2, Body: &apigen.EnrolTxeMachineJSONRequestBody{
			Class: apigen.TxeEnrolRequestClassWorker, ClientId: "dagu-worker-a2", Issuer: ownersIssuer, Subject: subject}})
		return err
	}
	require.Equal(t, http.StatusConflict, statusOf(enrol(w.personA, "mallory")))
	require.Equal(t, http.StatusForbidden, statusOf(enrol(w.cliA, "a")))
	require.Equal(t, http.StatusNotFound, statusOf(enrol(w.personB, "a")))
	require.NoError(t, enrol(w.personA, "a"))
	scope, err := w.svc.Scope(worker2, txeauth.Classify(worker2))
	require.NoError(t, err)
	require.Equal(t, authz.ScopeMachine, scope.Kind())
	require.Equal(t, m2, scope.MachineID())

	enrolments := func(ctx context.Context) ([]apigen.TxeEnrolment, error) {
		resp, err := w.api.ListTxeEnrolments(ctx, apigen.ListTxeEnrolmentsRequestObject{MachineId: m2})
		if err != nil {
			return nil, err
		}
		return resp.(apigen.ListTxeEnrolments200JSONResponse).Enrolments, nil
	}
	got, err := enrolments(w.cliA)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "dagu-worker-a2", got[0].ClientId)
	_, err = enrolments(w.admin)
	require.NoError(t, err)
	_, err = enrolments(w.cliB)
	require.Equal(t, http.StatusNotFound, statusOf(err))

	_, err = w.api.RevokeTxeEnrolment(w.personA, apigen.RevokeTxeEnrolmentRequestObject{MachineId: m2, Class: "worker",
		Body: &apigen.RevokeTxeEnrolmentJSONRequestBody{Reason: "rebuilt"}})
	require.NoError(t, err)
	scope, err = w.svc.Scope(worker2, txeauth.Classify(worker2))
	require.NoError(t, err)
	require.Equal(t, authz.ScopeUnbound, scope.Kind())
}

// An unreadable registry is an outage to the administrator listing a
// machine's enrolments, never a missing machine.
func TestTxeAccessEnrolmentListRegistryFailure(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	w := newTwoOwners(t, "")
	machines := filepath.Join(registry.Dir(w.dataDir), "machines")
	require.NoError(t, os.Chmod(machines, 0))
	t.Cleanup(func() { _ = os.Chmod(machines, 0o750) })
	_, err := w.api.ListTxeEnrolments(w.admin, apigen.ListTxeEnrolmentsRequestObject{MachineId: w.machineA})
	require.Equal(t, http.StatusServiceUnavailable, statusOf(err))
	require.Equal(t, "authz_unavailable", detailOf(err))
}
