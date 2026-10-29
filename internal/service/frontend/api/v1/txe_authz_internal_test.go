// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	filedagrun "github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
	rt "github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// twoOwners is a hub with two owners, A and B, each with a project, a
// machine and a job on it, and principals of every kind.
type twoOwners struct {
	t       *testing.T
	api     *API
	svc     *txeauth.Service
	reg     *registry.Store
	runs    *persis.DAGRunRepository
	dataDir string

	ownerA, ownerB     string
	projectA, projectB string
	machineA, machineB string
	jobA, jobB         string

	personA, personB, cliA, cliB          context.Context
	reviewerA, workerA, reviewerB, nobody context.Context
	legacy, admin                         context.Context
}

const ownersIssuer = "https://issuer.example/realms/test"

func newTwoOwners(t *testing.T, mode string) *twoOwners {
	t.Helper()
	dir := t.TempDir()
	repo := persis.NewDAGRepository(dag.NewStore(filepath.Join(dir, "dags")), persis.DAGRepositoryOptions{})
	w := &twoOwners{t: t, dataDir: filepath.Join(dir, "data")}
	reg, err := registry.NewFileStore(w.dataDir, registry.WithDAGStore(registry.NewDAGStore(repo)))
	require.NoError(t, err)
	w.reg = reg
	svc, err := txeauth.NewService(config.TXEConfig{Authz: config.TXEAuthzConfig{Mode: mode}}, w.dataDir, reg)
	require.NoError(t, err)
	w.svc = svc
	cfg := &config.Config{}
	cfg.Server.Auth.Mode = config.AuthModeBuiltin
	cfg.Server.Permissions = map[config.Permission]bool{config.PermissionWriteDAGs: true, config.PermissionRunDAGs: true}
	w.api = New(repo, nil, nil, nil, rt.Manager{}, cfg, nil, nil, prometheus.NewRegistry(), nil,
		WithTxeRegistry(reg), WithTxeAuth(svc), WithAuthService(struct{ AuthService }{}))

	ctx := context.Background()
	mint := func(p registry.Prefix) string {
		id, err := registry.NewID(p, time.Now())
		require.NoError(t, err)
		return id
	}
	system := registry.Actor{Kind: registry.ActorSystem, ID: "test"}
	w.ownerA, w.ownerB = mint(registry.PrefixOwner), mint(registry.PrefixOwner)
	w.machineA, w.machineB = mint(registry.PrefixMachine), mint(registry.PrefixMachine)
	for _, o := range []struct{ owner, name, machine string }{{w.ownerA, "Owner A", w.machineA}, {w.ownerB, "Owner B", w.machineB}} {
		_, err := reg.CreateOwner(ctx, registry.Owner{OwnerID: o.owner, DisplayName: o.name}, system)
		require.NoError(t, err)
		_, err = reg.CreateMachine(ctx, registry.Machine{MachineID: o.machine, OwnerID: o.owner, DisplayName: "laptop"}, system)
		require.NoError(t, err)
	}
	pa, err := reg.EnsureProject(ctx, w.ownerA, "github.com/a/a", "a", system)
	require.NoError(t, err)
	pb, err := reg.EnsureProject(ctx, w.ownerB, "github.com/b/b", "b", system)
	require.NoError(t, err)
	w.projectA, w.projectB = pa.ProjectID, pb.ProjectID
	w.jobA, w.jobB = mint(registry.PrefixJob), mint(registry.PrefixJob)
	for _, j := range []struct{ job, owner, project, machine string }{
		{w.jobA, w.ownerA, w.projectA, w.machineA}, {w.jobB, w.ownerB, w.projectB, w.machineB},
	} {
		_, err := reg.Register(ctx, registry.RegisterInput{JobID: j.job, RequestID: "r-" + j.job, OwnerID: j.owner, ProjectID: j.project,
			MachineID: j.machine, JobKey: "k", Version: ownersVersion(j.machine, 1)}, system)
		require.NoError(t, err)
	}

	// Identities: subject a is bound to A, b to B, z to nobody.
	bind := func(subject, owner string) {
		id := authn.Identity{Issuer: ownersIssuer, Subject: subject}
		_, err := svc.Store().RequestBinding(ctx, authn.Principal{Identity: id, Class: authn.ClassPerson}, authz.Shown{})
		require.NoError(t, err)
		_, err = svc.Store().ApproveBinding(ctx, authz.PlatformAdmin("admin"), id, owner)
		require.NoError(t, err)
	}
	bind("a", w.ownerA)
	bind("b", w.ownerB)

	person := func(subject string) context.Context {
		return auth.WithUser(ctx, &auth.User{Username: "user-" + subject, Role: auth.RoleViewer, AuthProvider: auth.AuthProviderOIDC,
			OIDCIssuer: ownersIssuer, OIDCSubject: subject})
	}
	token := func(subject string, class authn.Class, client string) context.Context {
		return txeauth.WithToken(ctx, ownersPrincipal(subject, class, client))
	}
	w.personA, w.personB = person("a"), person("b")
	w.cliA, w.cliB = token("a", authn.ClassCLI, "dagu-cli"), token("b", authn.ClassCLI, "dagu-cli")
	w.reviewerA = token("a", authn.ClassReviewer, "dagu-reviewer-a")
	w.workerA = token("a", authn.ClassWorker, "dagu-worker-a")
	w.reviewerB = token("b", authn.ClassReviewer, "dagu-reviewer-b")
	w.nobody = token("z", authn.ClassCLI, "dagu-cli")
	w.legacy = auth.WithAPIKey(auth.WithUser(ctx, &auth.User{Username: "apikey:cli", Role: auth.RoleAdmin, WorkspaceAccess: auth.AllWorkspaceAccess()}),
		&auth.APIKey{ID: "k", Role: auth.RoleAdmin})
	w.admin = auth.WithUser(ctx, &auth.User{Username: "admin", Role: auth.RoleAdmin, WorkspaceAccess: auth.AllWorkspaceAccess()})

	// The machines are enrolled by their owners' persons.
	enrol := func(personCtx context.Context, machine string, p authn.Principal) {
		scope, err := svc.Scope(personCtx, txeauth.Classify(personCtx))
		require.NoError(t, err)
		_, err = svc.Store().Enrol(ctx, scope, authz.EnrolmentRequest{MachineID: machine, Credential: p})
		require.NoError(t, err)
	}
	enrol(w.personA, w.machineA, ownersPrincipal("a", authn.ClassReviewer, "dagu-reviewer-a"))
	enrol(w.personA, w.machineA, ownersPrincipal("a", authn.ClassWorker, "dagu-worker-a"))
	enrol(w.personB, w.machineB, ownersPrincipal("b", authn.ClassReviewer, "dagu-reviewer-b"))
	return w
}

func ownersPrincipal(subject string, class authn.Class, client string) authn.Principal {
	return authn.Principal{Identity: authn.Identity{Issuer: ownersIssuer, Subject: subject}, Class: class, ClientID: client,
		Expires: time.Now().Add(time.Hour)}
}

func ownersVersion(machine string, digest byte) registry.JobVersion {
	return registry.JobVersion{
		Title: "t", Purpose: "p",
		Package: registry.Package{Digest: fmt.Sprintf("sha256:%064x", digest), Path: "/pkg", Entrypoint: "run.sh"},
		DAG:     registry.DAGRef{Spec: fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", machine)},
	}
}

func statusOf(err error) int {
	if apiErr, ok := errors.AsType[*Error](err); ok {
		return apiErr.HTTPStatus
	}
	if err == nil {
		return http.StatusOK
	}
	return -1
}

func detailOf(err error) string {
	var apiErr *Error
	if errors.As(err, &apiErr) && apiErr.Details != nil {
		code, _ := apiErr.Details["code"].(string)
		return code
	}
	return ""
}

func (w *twoOwners) getJob(ctx context.Context, jobID string) error {
	_, err := w.api.GetTxeJob(ctx, apigen.GetTxeJobRequestObject{JobId: jobID})
	return err
}

func (w *twoOwners) listJobs(ctx context.Context) []string {
	w.t.Helper()
	resp, err := w.api.ListTxeJobs(ctx, apigen.ListTxeJobsRequestObject{})
	require.NoError(w.t, err)
	var ids []string
	for _, j := range resp.(apigen.ListTxeJobs200JSONResponse).Jobs {
		ids = append(ids, j.JobId)
	}
	return ids
}

func (w *twoOwners) pause(ctx context.Context, jobID string) error {
	_, err := w.api.TransitionTxeJob(ctx, apigen.TransitionTxeJobRequestObject{JobId: jobID,
		Body: &apigen.TransitionTxeJobJSONRequestBody{Op: apigen.TxeLifecycleRequestOp("pause")}})
	return err
}

func (w *twoOwners) claimReview(ctx context.Context, jobID, machine string) error {
	_, err := w.api.AcquireTxeClaim(ctx, apigen.AcquireTxeClaimRequestObject{JobId: jobID,
		Body: &apigen.AcquireTxeClaimJSONRequestBody{Kind: apigen.TxeClaimKind("review"), TtlSec: 60,
			Reviewer: apigen.TxeReviewer{MachineId: &machine}}})
	return err
}

func TestTxeOwnersReadsAreOwnerScoped(t *testing.T) {
	w := newTwoOwners(t, "")

	require.NoError(t, w.getJob(w.cliA, w.jobA))
	require.NoError(t, w.getJob(w.personA, w.jobA))
	require.NoError(t, w.getJob(w.reviewerA, w.jobA))
	// Another owner's job, an unbound token and another owner's machine
	// all get the answer an absent job gets.
	absent := w.getJob(w.cliA, "job_00000000000000000000000000")
	require.Equal(t, http.StatusNotFound, statusOf(absent))
	for _, ctx := range []context.Context{w.cliB, w.personB, w.nobody, w.reviewerB} {
		err := w.getJob(ctx, w.jobA)
		require.Equal(t, http.StatusNotFound, statusOf(err))
		require.Equal(t, absent.Error(), txeJobNotFound("job_00000000000000000000000000").Error())
	}

	require.Equal(t, []string{w.jobA}, w.listJobs(w.cliA))
	require.Equal(t, []string{w.jobB}, w.listJobs(w.cliB))
	require.Empty(t, w.listJobs(w.nobody))
	// The history reads follow the job.
	_, err := w.api.ListTxeJobEvents(w.cliB, apigen.ListTxeJobEventsRequestObject{JobId: w.jobA})
	require.Equal(t, http.StatusNotFound, statusOf(err))
	_, err = w.api.ListTxeJobEvents(w.cliA, apigen.ListTxeJobEventsRequestObject{JobId: w.jobA})
	require.NoError(t, err)

	// Mode off: the legacy key and the administrator read as today.
	require.ElementsMatch(t, []string{w.jobA, w.jobB}, w.listJobs(w.legacy))
	require.ElementsMatch(t, []string{w.jobA, w.jobB}, w.listJobs(w.admin))
}

func TestTxeOwnersModesForLegacyCredentials(t *testing.T) {
	observe := newTwoOwners(t, "observe")
	require.ElementsMatch(t, []string{observe.jobA, observe.jobB}, observe.listJobs(observe.legacy))
	require.NoError(t, observe.pause(observe.legacy, observe.jobA))

	enforce := newTwoOwners(t, "enforce")
	require.Empty(t, enforce.listJobs(enforce.legacy))
	require.Equal(t, http.StatusNotFound, statusOf(enforce.getJob(enforce.legacy, enforce.jobA)))
	require.Equal(t, http.StatusNotFound, statusOf(enforce.pause(enforce.legacy, enforce.jobA)))
	// The administrator may look, as break-glass, and change nothing.
	require.ElementsMatch(t, []string{enforce.jobA, enforce.jobB}, enforce.listJobs(enforce.admin))
	err := enforce.pause(enforce.admin, enforce.jobA)
	require.Equal(t, http.StatusForbidden, statusOf(err))
	require.Equal(t, "forbidden", detailOf(err))
	// A provider principal is held to its owner in every mode.
	require.Equal(t, []string{enforce.jobA}, enforce.listJobs(enforce.cliA))
}

func TestTxeOwnersWritesNeedTheOwnersPermission(t *testing.T) {
	w := newTwoOwners(t, "")

	// Another owner's job is not found; the reviewer of A's own machine may
	// see A's job but not author it.
	require.Equal(t, http.StatusNotFound, statusOf(w.pause(w.cliB, w.jobA)))
	err := w.pause(w.reviewerA, w.jobA)
	require.Equal(t, http.StatusForbidden, statusOf(err))
	require.Equal(t, "forbidden", detailOf(err))
	err = w.pause(w.nobody, w.jobA)
	require.Equal(t, http.StatusForbidden, statusOf(err))
	require.Equal(t, "unbound", detailOf(err))
	require.NoError(t, w.pause(w.cliA, w.jobA))
}

func TestTxeOwnersReviewClaimsNeedTheJobsOwnReviewer(t *testing.T) {
	w := newTwoOwners(t, "")

	// The owner's CLI and the machine's worker may see the job and may not
	// take its review.
	for _, ctx := range []context.Context{w.cliA, w.workerA, w.personA} {
		err := w.claimReview(ctx, w.jobA, w.machineA)
		require.Equal(t, http.StatusForbidden, statusOf(err))
	}
	// Another owner's reviewer, naming A's machine or its own, is not told
	// the job exists.
	require.Equal(t, http.StatusNotFound, statusOf(w.claimReview(w.reviewerB, w.jobA, w.machineA)))
	require.Equal(t, http.StatusNotFound, statusOf(w.claimReview(w.reviewerB, w.jobA, w.machineB)))
	// The job's own reviewer passes authorization and reaches the registry,
	// which judges the claim itself: this fixture's job is not ready yet.
	err := w.claimReview(w.reviewerA, w.jobA, w.machineA)
	require.Equal(t, http.StatusConflict, statusOf(err))
	require.Equal(t, "not_ready", detailOf(err))
}

func TestTxeOwnersCreateUnderOwnOwnerOnly(t *testing.T) {
	w := newTwoOwners(t, "")
	mint := func(p registry.Prefix) string {
		id, err := registry.NewID(p, time.Now())
		require.NoError(t, err)
		return id
	}

	// Nobody but the platform administrator makes an owner.
	for _, ctx := range []context.Context{w.cliA, w.personA} {
		_, err := w.api.CreateTxeOwner(ctx, apigen.CreateTxeOwnerRequestObject{Body: &apigen.CreateTxeOwnerJSONRequestBody{
			OwnerId: mint(registry.PrefixOwner), DisplayName: "Mallory"}})
		require.Equal(t, http.StatusForbidden, statusOf(err))
	}

	// A machine and a project are made only under the caller's own owner.
	_, err := w.api.CreateTxeMachine(w.cliA, apigen.CreateTxeMachineRequestObject{Body: &apigen.CreateTxeMachineJSONRequestBody{
		MachineId: mint(registry.PrefixMachine), OwnerId: w.ownerB, DisplayName: "planted"}})
	require.Equal(t, http.StatusForbidden, statusOf(err))
	_, err = w.api.CreateTxeMachine(w.cliA, apigen.CreateTxeMachineRequestObject{Body: &apigen.CreateTxeMachineJSONRequestBody{
		MachineId: mint(registry.PrefixMachine), OwnerId: w.ownerA, DisplayName: "second"}})
	require.NoError(t, err)
	_, err = w.api.EnsureTxeProject(w.cliA, apigen.EnsureTxeProjectRequestObject{Body: &apigen.EnsureTxeProjectJSONRequestBody{
		OwnerId: w.ownerB, Key: "github.com/b/planted"}})
	require.Equal(t, http.StatusForbidden, statusOf(err))

	// A job is registered only under the caller's own owner.
	job := mint(registry.PrefixJob)
	version, err := txeConvert[apigen.TxeJobVersionInput](ownersVersion(w.machineB, 2))
	require.NoError(t, err)
	_, err = w.api.RegisterTxeJob(w.cliA, apigen.RegisterTxeJobRequestObject{Body: &apigen.RegisterTxeJobJSONRequestBody{
		JobId: job, RequestId: "planted", OwnerId: w.ownerB, ProjectId: w.projectB, MachineId: w.machineB, JobKey: "planted", Version: version}})
	require.Equal(t, http.StatusForbidden, statusOf(err))
	_, err = w.reg.GetJob(context.Background(), job)
	require.Equal(t, registry.CodeNotFound, registry.ErrorCode(err))

	// An unbound token can make nothing.
	_, err = w.api.CreateTxeMachine(w.nobody, apigen.CreateTxeMachineRequestObject{Body: &apigen.CreateTxeMachineJSONRequestBody{
		MachineId: mint(registry.PrefixMachine), OwnerId: w.ownerA, DisplayName: "x"}})
	require.Equal(t, "unbound", detailOf(err))
}

func TestTxeOwnersRecordsAndInstallation(t *testing.T) {
	w := newTwoOwners(t, "")

	_, err := w.api.GetTxeOwner(w.cliA, apigen.GetTxeOwnerRequestObject{OwnerId: w.ownerB})
	require.Equal(t, http.StatusNotFound, statusOf(err))
	_, err = w.api.GetTxeOwner(w.cliA, apigen.GetTxeOwnerRequestObject{OwnerId: w.ownerA})
	require.NoError(t, err)
	_, err = w.api.GetTxeMachine(w.cliA, apigen.GetTxeMachineRequestObject{MachineId: w.machineB})
	require.Equal(t, http.StatusNotFound, statusOf(err))
	_, err = w.api.GetTxeMachine(w.reviewerA, apigen.GetTxeMachineRequestObject{MachineId: w.machineA})
	require.NoError(t, err)
	_, err = w.api.GetTxeProject(w.cliA, apigen.GetTxeProjectRequestObject{ProjectId: w.projectB})
	require.Equal(t, http.StatusNotFound, statusOf(err))
	_, err = w.api.GetTxeProject(w.cliA, apigen.GetTxeProjectRequestObject{ProjectId: w.projectA})
	require.NoError(t, err)

	owners := func(ctx context.Context) []string {
		resp, err := w.api.GetTxeInstallation(ctx, apigen.GetTxeInstallationRequestObject{})
		require.NoError(t, err)
		var ids []string
		for _, o := range resp.(apigen.GetTxeInstallation200JSONResponse).Owners {
			ids = append(ids, o.OwnerId)
		}
		return ids
	}
	require.Equal(t, []string{w.ownerA}, owners(w.cliA))
	require.Empty(t, owners(w.nobody))
	require.ElementsMatch(t, []string{w.ownerA, w.ownerB}, owners(w.admin))
}

func TestTxeOwnersApproveIsAPersonsOnly(t *testing.T) {
	w := newTwoOwners(t, "")

	require.NoError(t, w.api.txeAuthorizeJob(w.personA, w.jobA, authz.PermissionApprove, txeNeed{}))
	err := w.api.txeAuthorizeJob(w.cliA, w.jobA, authz.PermissionApprove, txeNeed{})
	require.Equal(t, http.StatusForbidden, statusOf(err))
	require.Equal(t, http.StatusNotFound, statusOf(w.api.txeAuthorizeJob(w.personB, w.jobA, authz.PermissionApprove, txeNeed{})))
	// A token never reaches a decision at all.
	_, err = w.api.DecideTxeProposal(w.cliA, apigen.DecideTxeProposalRequestObject{JobId: w.jobA, ProposalId: "prp_00000000000000000000000000",
		Body: &apigen.DecideTxeProposalJSONRequestBody{Verdict: apigen.TxeVerdict("approve")}})
	require.Error(t, err)
	require.NotEqual(t, http.StatusOK, statusOf(err))
}

func TestTxeOwnersRevocationIsSeenOnTheNextRequest(t *testing.T) {
	w := newTwoOwners(t, "")
	require.NoError(t, w.getJob(w.cliA, w.jobA))
	_, err := w.svc.Store().RevokeBinding(context.Background(), authz.PlatformAdmin("admin"),
		authn.Identity{Issuer: ownersIssuer, Subject: "a"}, "left")
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, statusOf(w.getJob(w.cliA, w.jobA)))
	require.Equal(t, http.StatusNotFound, statusOf(w.getJob(w.reviewerA, w.jobA)))
	require.Empty(t, w.listJobs(w.personA))
}

func TestTxeOwnersStoreFailureInEnforceIs503(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	w := newTwoOwners(t, "")
	dir := authz.Dir(w.dataDir)
	require.NoError(t, os.Chmod(dir, 0))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })

	err := w.getJob(w.cliA, w.jobA)
	require.Equal(t, http.StatusServiceUnavailable, statusOf(err))
	require.Equal(t, "authz_unavailable", detailOf(err))
	// A list is not shortened by an outage: it fails.
	_, err = w.api.ListTxeJobs(w.cliA, apigen.ListTxeJobsRequestObject{})
	require.Equal(t, http.StatusServiceUnavailable, statusOf(err))
	// A legacy key in mode off does not touch the store.
	require.NoError(t, w.getJob(w.legacy, w.jobA))
}

func TestTxePersonGateKeepsPersonsToTheirOwnersRoutes(t *testing.T) {
	w := newTwoOwners(t, "")
	reached := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { reached = true; rw.WriteHeader(http.StatusOK) })
	gate := w.api.txePersonGate("/api/v1")(next)
	serve := func(ctx context.Context, method, target string) int {
		reached = false
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest(method, target, nil).WithContext(ctx))
		return rec.Code
	}

	// A person, with the hub's administrator role on its account even, is
	// kept to /txe and the read of its own session.
	admin := auth.WithUser(context.Background(), &auth.User{Username: "a", Role: auth.RoleAdmin, AuthProvider: auth.AuthProviderOIDC,
		OIDCIssuer: ownersIssuer, OIDCSubject: "a", WorkspaceAccess: auth.AllWorkspaceAccess()})
	for _, ctx := range []context.Context{w.personA, admin} {
		for _, target := range []string{"/api/v1/txe/jobs", "/api/v1/txe/identity", "/api/v1/auth/me"} {
			require.Equal(t, http.StatusOK, serve(ctx, http.MethodGet, target), target)
			require.True(t, reached, target)
		}
		// Since S4 the native DAG, run and queue routes answer by owner too.
		for _, target := range []string{"/api/v1/dags", "/api/v1/dag-runs", "/api/v1/queues"} {
			require.Equal(t, http.StatusOK, serve(ctx, http.MethodGet, target), target)
			require.True(t, reached, target)
		}
		// The router does not resolve dot segments, so a path with one is
		// not read as the route it would name once cleaned: it is refused.
		require.Equal(t, http.StatusForbidden, serve(ctx, http.MethodGet, "/api/v1/txe/../dags"))
		require.False(t, reached)
		for _, tc := range []struct{ method, target string }{
			{http.MethodGet, "/api/v1/users"}, {http.MethodPost, "/api/v1/auth/change-password"}, {http.MethodGet, "/api/v1/workers"},
			{http.MethodGet, "/api/v1/audit"}, {http.MethodGet, "/api/v1/dagsx"},
		} {
			require.Equal(t, http.StatusForbidden, serve(ctx, tc.method, tc.target), tc.target)
			require.False(t, reached, tc.target)
		}
	}
	// Everyone else goes on to the route's own checks.
	for _, ctx := range []context.Context{w.legacy, w.admin, context.Background()} {
		require.Equal(t, http.StatusOK, serve(ctx, http.MethodGet, "/api/v1/dags"))
		require.True(t, reached)
	}

	refuse := w.api.TxePersonRefused()(next)
	rec := httptest.NewRecorder()
	refuse.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil).WithContext(w.personA))
	require.Equal(t, http.StatusForbidden, rec.Code)
	rec = httptest.NewRecorder()
	refuse.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil).WithContext(w.admin))
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestTxeOwnersResourceEventsChangeOnlyTheReportersJobs(t *testing.T) {
	w := newTwoOwners(t, "")
	ctx := context.Background()
	system := registry.Actor{Kind: registry.ActorSystem, ID: "test"}
	shared := registry.Target{Kind: "kubernetes.volume", StableID: map[string]string{"cluster_uid": "c-1", "uid": "shared"}}
	register := func(owner, project, machine string) string {
		id, err := registry.NewID(registry.PrefixJob, time.Now())
		require.NoError(t, err)
		v := ownersVersion(machine, 3)
		v.Targets = []registry.Target{shared}
		_, err = w.reg.Register(ctx, registry.RegisterInput{JobID: id, RequestID: "r-" + id, OwnerID: owner, ProjectID: project,
			MachineID: machine, JobKey: "volume", Version: v}, system)
		require.NoError(t, err)
		return id
	}
	jobA, jobB := register(w.ownerA, w.projectA, w.machineA), register(w.ownerB, w.projectB, w.machineB)
	before, err := w.reg.GetJob(ctx, jobA)
	require.NoError(t, err)
	require.NoError(t, w.reg.RebuildResourceIndex(ctx))

	target, err := txeConvert[apigen.TxeTarget](shared)
	require.NoError(t, err)
	authoritative := true
	resp, err := w.api.RecordTxeResourceEvent(w.cliB, apigen.RecordTxeResourceEventRequestObject{Body: &apigen.RecordTxeResourceEventJSONRequestBody{
		Target: target, Observation: apigen.TxeResourceObservation("deleted"), Authoritative: &authoritative}})
	require.NoError(t, err)
	ev := resp.(apigen.RecordTxeResourceEvent200JSONResponse)
	var touched []string
	for _, d := range ev.Dispositions {
		touched = append(touched, d.JobId)
	}
	require.NotContains(t, touched, jobA)
	require.Contains(t, touched, jobB)

	// A's job on the same volume is exactly as it was.
	after, err := w.reg.GetJob(ctx, jobA)
	require.NoError(t, err)
	require.Equal(t, before.Revision, after.Revision)
	require.Equal(t, before.Lifecycle, after.Lifecycle)
}

func (w *twoOwners) markReady(jobID, machine string) {
	w.t.Helper()
	ctx := context.Background()
	job, err := w.reg.GetJob(ctx, jobID)
	require.NoError(w.t, err)
	_, err = w.reg.MarkReady(ctx, jobID, job.Revision, registry.PackageEvidence{Digest: fmt.Sprintf("sha256:%064x", 1), Path: "/pkg", MachineID: machine},
		registry.Actor{Kind: registry.ActorSystem, ID: "test"})
	require.NoError(w.t, err)
}

func TestTxeOwnersAReviewClaimIsReleasedOnlyByItsReviewer(t *testing.T) {
	w := newTwoOwners(t, "")
	w.markReady(w.jobA, w.machineA)
	machine := w.machineA
	resp, err := w.api.AcquireTxeClaim(w.reviewerA, apigen.AcquireTxeClaimRequestObject{JobId: w.jobA,
		Body: &apigen.AcquireTxeClaimJSONRequestBody{Kind: apigen.TxeClaimKind("review"), TtlSec: 60, Reviewer: apigen.TxeReviewer{MachineId: &machine}}})
	require.NoError(t, err)
	claim := resp.(apigen.AcquireTxeClaim200JSONResponse)
	release := func(ctx context.Context) error {
		_, err := w.api.ReleaseTxeClaim(ctx, apigen.ReleaseTxeClaimRequestObject{JobId: w.jobA, ClaimId: claim.ClaimId,
			Body: &apigen.ReleaseTxeClaimJSONRequestBody{Fence: claim.Fence}})
		return err
	}
	// The worker of the same machine knows the claim and its fence, and may
	// still not end the reviewer's claim.
	require.Equal(t, http.StatusForbidden, statusOf(release(w.workerA)))
	require.Equal(t, http.StatusNotFound, statusOf(release(w.reviewerB)))
	require.NoError(t, release(w.reviewerA))
}

func TestTxeOwnersMachineIDCollisionDisclosesNothing(t *testing.T) {
	w := newTwoOwners(t, "")
	_, err := w.api.CreateTxeMachine(w.cliA, apigen.CreateTxeMachineRequestObject{Body: &apigen.CreateTxeMachineJSONRequestBody{
		MachineId: w.machineB, OwnerId: w.ownerA, DisplayName: "mine"}})
	require.Equal(t, http.StatusConflict, statusOf(err))
	var apiErr *Error
	require.ErrorAs(t, err, &apiErr)
	require.NotContains(t, apiErr.Details, "current")
	require.NotContains(t, apiErr.Message, w.ownerB)
	require.Equal(t, "the machine id is already in use", apiErr.Message)
	// Naming one's own machine again is a replay and returns it, as today.
	resp, err := w.api.CreateTxeMachine(w.cliA, apigen.CreateTxeMachineRequestObject{Body: &apigen.CreateTxeMachineJSONRequestBody{
		MachineId: w.machineA, OwnerId: w.ownerA, DisplayName: "renamed"}})
	require.NoError(t, err)
	require.Equal(t, w.ownerA, resp.(apigen.CreateTxeMachine201JSONResponse).OwnerId)
}

func TestTxeOwnersAReporterLosesItsEventWithItsBinding(t *testing.T) {
	w := newTwoOwners(t, "")
	target, err := txeConvert[apigen.TxeTarget](registry.Target{Kind: "kubernetes.volume", StableID: map[string]string{"uid": "nobody-uses-it"}})
	require.NoError(t, err)
	require.NoError(t, w.reg.RebuildResourceIndex(context.Background()))
	resp, err := w.api.RecordTxeResourceEvent(w.cliA, apigen.RecordTxeResourceEventRequestObject{Body: &apigen.RecordTxeResourceEventJSONRequestBody{
		Target: target, Observation: apigen.TxeResourceObservation("present")}})
	require.NoError(t, err)
	eventID := resp.(apigen.RecordTxeResourceEvent200JSONResponse).EventId
	get := func(ctx context.Context) error {
		_, err := w.api.GetTxeResourceEvent(ctx, apigen.GetTxeResourceEventRequestObject{EventId: eventID})
		return err
	}
	require.NoError(t, get(w.cliA))
	require.Equal(t, http.StatusNotFound, statusOf(get(w.cliB)))
	_, err = w.svc.Store().RevokeBinding(context.Background(), authz.PlatformAdmin("admin"), authn.Identity{Issuer: ownersIssuer, Subject: "a"}, "left")
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, statusOf(get(w.cliA)))
}

func TestTxeOwnersSharedApproveNeedsNoMachine(t *testing.T) {
	w := newTwoOwners(t, "")
	scopeA, err := w.svc.Scope(w.personA, txeauth.Classify(w.personA))
	require.NoError(t, err)
	_, err = w.svc.Store().GrantShare(context.Background(), scopeA, authz.ShareGrant{
		Resource: authz.ResourceRef{Kind: authz.KindJob, ID: w.jobA}, GranteeOwnerID: w.ownerB,
		Permissions: []authz.Permission{authz.PermissionView, authz.PermissionApprove}})
	require.NoError(t, err)

	// B's person may now see and decide A's job, but nothing else of A's.
	require.NoError(t, w.getJob(w.personB, w.jobA))
	require.NoError(t, w.api.txeAuthorizeJob(w.personB, w.jobA, authz.PermissionApprove, txeNeed{}))
	require.Equal(t, http.StatusForbidden, statusOf(w.api.txeAuthorizeJob(w.personB, w.jobA, authz.PermissionAuthor, txeNeed{})))
	_, err = w.api.GetTxeMachine(w.personB, apigen.GetTxeMachineRequestObject{MachineId: w.machineA})
	require.Equal(t, http.StatusNotFound, statusOf(err))
	// The native task check for such a caller asks only that the run of
	// a machine's DAG exists: the decision on the job is what authorizes.
	err = w.api.txeMachineDAGRunExists(w.personB, "txe-decide-"+w.machineA[len("mch_"):], "run-1")
	require.Equal(t, http.StatusNotFound, statusOf(err))
	err = w.api.txeMachineDAGRunExists(w.personB, w.jobA, "run-1")
	require.Equal(t, http.StatusNotFound, statusOf(err))
}

// A retry request reads the job's run without the hub's workspaces for a
// caller held to its owner, who was decided on the job already, and with
// them for everyone else.
func TestTxeOwnersRetryReadsTheRunByTheJobNotTheWorkspace(t *testing.T) {
	w := newTwoOwners(t, "")
	ctx := context.Background()
	attemptID := w.addRun(w.jobA, "run-1", "production")

	// The person has no Dagu grant for production; the owner decides.
	got, err := w.api.txeJobRunStatus(w.personA, w.jobA, "run-1")
	require.NoError(t, err)
	require.Equal(t, attemptID, got.AttemptID)
	_, err = w.api.txeJobRunStatus(w.personA, w.jobA, "run-2")
	require.Equal(t, http.StatusNotFound, statusOf(err))

	// A legacy user without production keeps today's answer.
	opsOnly := auth.WithUser(ctx, &auth.User{Username: "dev", Role: auth.RoleDeveloper, WorkspaceAccess: &auth.WorkspaceAccess{
		Grants: []auth.WorkspaceGrant{{Workspace: "ops", Role: auth.RoleDeveloper}}}})
	_, err = w.api.txeJobRunStatus(opsOnly, w.jobA, "run-1")
	require.Equal(t, http.StatusNotFound, statusOf(err))
}

// addRun saves a failed run of a job in a workspace, in a run repository the
// API reads, and returns its attempt id.
func (w *twoOwners) addRun(jobID, runID, workspace string) string {
	w.t.Helper()
	ctx := context.Background()
	if w.runs == nil {
		dir := w.t.TempDir()
		w.runs = persis.NewDAGRunRepository(filedagrun.NewStore(filepath.Join(dir, "runs")),
			filedagrun.NewWorkDirStore(filepath.Join(dir, "work"), filepath.Join(dir, "runs")), persis.DAGRunRepositoryOptions{})
		w.api.dagRunRepository = w.runs
		w.api.dagRunMgr = rt.NewManager(w.runs, newTestProcRepository(filepath.Join(dir, "proc")), &config.Config{})
	}
	d := &ir.DAG{Name: jobID, YamlData: []byte("steps:\n  - name: run\n    run: /pkg/run.sh\n")}
	attempt, err := w.runs.CreateAttempt(ctx, d, time.Now(), runID, persis.DAGRunCreateAttemptOptions{})
	require.NoError(w.t, err)
	status := ir.InitialStatus(d)
	status.DAGRunID, status.AttemptID, status.Status, status.QueuedAt = runID, attempt.ID(), ir.Failed, "q1"
	status.StartedAt, status.FinishedAt = time.Now().Add(-time.Minute).Format(time.RFC3339), time.Now().Format(time.RFC3339)
	status.Labels = []string{"workspace=" + workspace}
	status.Log = filepath.Join(w.t.TempDir(), runID+".log")
	require.NoError(w.t, os.WriteFile(status.Log, []byte("secret output of "+jobID+"\n"), 0o600))
	require.NoError(w.t, attempt.Open(ctx))
	require.NoError(w.t, attempt.Write(ctx, status))
	require.NoError(w.t, attempt.Close(ctx))
	return attempt.ID()
}

// An artifact report decided again in its transaction is refused there for
// a caller held to its owner, even though the run's workspace would let a
// legacy caller through: the enrolment is revoked between the two checks.
func TestTxeOwnersArtifactTransactionRefusalStands(t *testing.T) {
	w := newTwoOwners(t, "")
	w.markReady(w.jobA, w.machineA)
	attemptID := w.addRun(w.jobA, "run-1", "production")
	t.Cleanup(func() { txeBeforeArtifactTx = nil })
	txeBeforeArtifactTx = func() {
		_, err := w.svc.Store().RevokeEnrolment(context.Background(), authz.PlatformAdmin("admin"), w.machineA, authn.ClassWorker, "lost")
		require.NoError(t, err)
	}
	_, err := w.api.RecordTxeRunArtifacts(w.workerA, apigen.RecordTxeRunArtifactsRequestObject{JobId: w.jobA, RunId: "run-1",
		Body: &apigen.RecordTxeRunArtifactsJSONRequestBody{AttemptId: attemptID, QueuedAt: "q1", JobVersion: 1, Artifacts: []apigen.TxeArtifactRecordInput{}}})
	require.Equal(t, http.StatusForbidden, statusOf(err))
	require.Equal(t, "unbound", detailOf(err))
	manifests, err := w.reg.ListArtifacts(context.Background(), w.jobA, "run-1")
	require.NoError(t, err)
	require.Empty(t, manifests)
}

// A retry request by a bound person reads the run by the job, not by the
// person's workspaces: it is not refused as not found.
func TestTxeOwnersRetryRequestByAPersonIsNotAWorkspaceQuestion(t *testing.T) {
	w := newTwoOwners(t, "")
	w.markReady(w.jobA, w.machineA)
	attemptID := w.addRun(w.jobA, "run-1", "production")
	queued := "q1"
	_, err := w.api.RequestTxeRunRetry(w.personA, apigen.RequestTxeRunRetryRequestObject{JobId: w.jobA, RunId: "run-1",
		Body: &apigen.RequestTxeRunRetryJSONRequestBody{AttemptId: &attemptID, QueuedAt: &queued, ExpectedJobVersion: 1, IdempotencyKey: "k1"}})
	require.NotEqual(t, http.StatusNotFound, statusOf(err), "%v", err)
	// Another owner's person is not told the run exists.
	_, err = w.api.RequestTxeRunRetry(w.personB, apigen.RequestTxeRunRetryRequestObject{JobId: w.jobA, RunId: "run-1",
		Body: &apigen.RequestTxeRunRetryJSONRequestBody{AttemptId: &attemptID, QueuedAt: &queued, ExpectedJobVersion: 1, IdempotencyKey: "k2"}})
	require.Equal(t, http.StatusNotFound, statusOf(err))
}

// A person the owner shares approve with may decide every verdict, pausing
// and retiring included, without being an author of the job.
func TestTxeOwnersSharedApproverMayPauseAndRetire(t *testing.T) {
	w := newTwoOwners(t, "")
	scopeA, err := w.svc.Scope(w.personA, txeauth.Classify(w.personA))
	require.NoError(t, err)
	_, err = w.svc.Store().GrantShare(context.Background(), scopeA, authz.ShareGrant{
		Resource: authz.ResourceRef{Kind: authz.KindJob, ID: w.jobA}, GranteeOwnerID: w.ownerB,
		Permissions: []authz.Permission{authz.PermissionView, authz.PermissionApprove}})
	require.NoError(t, err)

	svc := w.api.txeDecisionService(w.reg)
	decide := func(ctx context.Context, verdict registry.Verdict) error {
		_, err := w.reg.WithJobTx(context.Background(), w.jobA, registry.Actor{Kind: registry.ActorHuman, ID: "b"}, func(tx *registry.JobTx) error {
			if err := svc.AuthorizeDecision(ctx, tx, verdict); err != nil {
				return err
			}
			return errors.New("stop: authorized")
		})
		return err
	}
	for _, verdict := range []registry.Verdict{registry.VerdictPause, registry.VerdictRetire, registry.VerdictApprove} {
		require.EqualError(t, decide(w.personB, verdict), "stop: authorized", verdict)
	}
	// A CLI token of the same owner holds no approve, shared or not.
	require.Equal(t, http.StatusForbidden, statusOf(decide(w.cliA, registry.VerdictPause)))
}

// A lost registration race stays listed, directly after the job holding its
// key, and names that job only to a caller who can see it: B, who was shared
// the duplicate but not A's job, sees the duplicate without duplicate_of and
// where its own age puts it, so its place says nothing about A's job.
func TestTxeOwnersDuplicateIsListedAfterItsJobAndNamesItOnlyToThoseWhoSeeIt(t *testing.T) {
	w := newTwoOwners(t, "")
	ctx := context.Background()
	dup, err := registry.NewID(registry.PrefixJob, time.Now())
	require.NoError(t, err)
	_, err = w.reg.Register(ctx, registry.RegisterInput{JobID: dup, RequestID: "r-dup", OwnerID: w.ownerA, ProjectID: w.projectA,
		MachineID: w.machineA, JobKey: "k", Version: ownersVersion(w.machineA, 2)}, registry.Actor{Kind: registry.ActorSystem, ID: "test"})
	require.Equal(t, registry.CodeDuplicate, registry.ErrorCode(err))
	scopeA, err := w.svc.Scope(w.personA, txeauth.Classify(w.personA))
	require.NoError(t, err)
	_, err = w.svc.Store().GrantShare(ctx, scopeA, authz.ShareGrant{
		Resource: authz.ResourceRef{Kind: authz.KindJob, ID: dup}, GranteeOwnerID: w.ownerB,
		Permissions: []authz.Permission{authz.PermissionView}})
	require.NoError(t, err)

	duplicateOf := func(caller context.Context) map[string]string {
		resp, err := w.api.ListTxeJobs(caller, apigen.ListTxeJobsRequestObject{})
		require.NoError(t, err)
		out := map[string]string{}
		for _, j := range resp.(apigen.ListTxeJobs200JSONResponse).Jobs {
			out[j.JobId] = string(j.Registration.State) + " " + valueOf(j.Registration.DuplicateOf)
		}
		return out
	}

	// Registered after B's job, the duplicate is listed right after A's.
	require.Equal(t, []string{w.jobA, dup, w.jobB}, w.listJobs(w.admin))
	require.Equal(t, []string{w.jobA, dup}, w.listJobs(w.personA))
	require.Equal(t, "duplicate "+w.jobA, duplicateOf(w.personA)[dup])
	require.Equal(t, "duplicate "+w.jobA, duplicateOf(w.admin)[dup])

	require.Equal(t, []string{w.jobB, dup}, w.listJobs(w.personB))
	require.Equal(t, "duplicate ", duplicateOf(w.personB)[dup], "B cannot see the job holding the key")
	got, err := w.api.GetTxeJob(w.personB, apigen.GetTxeJobRequestObject{JobId: dup})
	require.NoError(t, err)
	require.Empty(t, valueOf(got.(apigen.GetTxeJob200JSONResponse).Registration.DuplicateOf))

	// Nothing is deleted: the record is still there, as it was.
	stored, err := w.reg.GetJob(ctx, dup)
	require.NoError(t, err)
	require.Equal(t, registry.RegistrationDuplicate, stored.Registration.State)
	require.Equal(t, w.jobA, stored.Registration.DuplicateOf)
}
