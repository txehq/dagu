// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	apiv1 "github.com/dagucloud/dagu/v2/internal/service/frontend/api/v1"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

func newTxeTestAPI(t *testing.T, opts ...apiv1.APIOption) *apiv1.API {
	t.Helper()
	return newTxeTestAPIAt(t, t.TempDir(), true, opts...)
}

func newTxeTestAPIAt(t *testing.T, dir string, writeDAGs bool, opts ...apiv1.APIOption) *apiv1.API {
	t.Helper()
	repo := persis.NewDAGRepository(dag.NewStore(filepath.Join(dir, "dags")), persis.DAGRepositoryOptions{})
	store, err := registry.NewFileStore(filepath.Join(dir, "data"), registry.WithDAGStore(registry.NewDAGStore(repo)))
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Server.Permissions = map[config.Permission]bool{config.PermissionWriteDAGs: writeDAGs}
	return apiv1.New(repo, nil, nil, nil, runtime.Manager{}, cfg, nil, nil, prometheus.NewRegistry(), nil, append([]apiv1.APIOption{apiv1.WithTxeRegistry(store)}, opts...)...)
}

func mint(t *testing.T, p registry.Prefix) string {
	t.Helper()
	id, err := registry.NewID(p, time.Now())
	require.NoError(t, err)
	return id
}

// The /txe API registers a job end to end, refuses stale writes with 409 and
// the registry code in details, and retires without losing history.
func TestTxeAPIRegistrationAndRetirement(t *testing.T) {
	ctx := context.Background()
	a := newTxeTestAPI(t)
	cliActor := &apigen.TxeActor{Kind: apigen.TxeActorKindCli, Id: "cc3-test"}
	owner, machine := mint(t, registry.PrefixOwner), mint(t, registry.PrefixMachine)

	_, err := a.CreateTxeOwner(ctx, apigen.CreateTxeOwnerRequestObject{Body: &apigen.TxeOwnerCreateRequest{OwnerId: owner, DisplayName: "Connor Wang", Actor: cliActor}})
	require.NoError(t, err)
	_, err = a.CreateTxeMachine(ctx, apigen.CreateTxeMachineRequestObject{Body: &apigen.TxeMachineCreateRequest{MachineId: machine, OwnerId: owner, DisplayName: "laptop", Actor: cliActor}})
	require.NoError(t, err)
	projResp, err := a.EnsureTxeProject(ctx, apigen.EnsureTxeProjectRequestObject{Body: &apigen.TxeProjectEnsureRequest{OwnerId: owner, Key: "github.com/txehq/txe", Actor: cliActor}})
	require.NoError(t, err)
	project := projResp.(apigen.EnsureTxeProject200JSONResponse).ProjectId

	jobID := mint(t, registry.PrefixJob)
	spec := fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", machine)
	digest := fmt.Sprintf("sha256:%064x", 7)
	reg := &apigen.TxeRegisterRequest{
		JobId: jobID, RequestId: "r1", OwnerId: owner, ProjectId: project, MachineId: machine, JobKey: "health:pvc",
		Version: apigen.TxeJobVersionInput{
			Title: "pvc health", Purpose: "watch pvc",
			Package: apigen.TxePackage{Digest: digest, Path: "/pkg", Entrypoint: "run.sh"},
			Dag:     apigen.TxeDAGRef{Spec: spec},
		},
		Actor: cliActor,
	}
	regResp, err := a.RegisterTxeJob(ctx, apigen.RegisterTxeJobRequestObject{Body: reg})
	require.NoError(t, err)
	job := regResp.(apigen.RegisterTxeJob201JSONResponse)
	assert.Equal(t, apigen.TxeRegistrationStateIncomplete, job.Registration.State)

	readyResp, err := a.MarkTxeJobReady(ctx, apigen.MarkTxeJobReadyRequestObject{JobId: jobID, Body: &apigen.TxeReadyRequest{
		Package: apigen.TxePackageEvidence{Digest: digest, Path: "/pkg", MachineId: machine}, Actor: cliActor}})
	require.NoError(t, err)
	receipt := readyResp.(apigen.MarkTxeJobReady200JSONResponse)
	assert.Equal(t, apigen.TxeRegistrationStateReady, receipt.Registration)
	assert.Equal(t, owner, receipt.OwnerId)

	verResp, err := a.GetTxeJobVersion(ctx, apigen.GetTxeJobVersionRequestObject{JobId: jobID, Version: 1})
	require.NoError(t, err)
	assert.Equal(t, "watch pvc", verResp.(apigen.GetTxeJobVersion200JSONResponse).Purpose)

	_, err = a.UpdateTxeJobVersion(ctx, apigen.UpdateTxeJobVersionRequestObject{JobId: jobID, Body: &apigen.TxeVersionRequest{
		RequestId: "u1", ExpectedVersion: 5, Version: reg.Version, Actor: cliActor}})
	var apiErr *apiv1.Error
	require.True(t, errors.As(err, &apiErr), "got %v", err)
	assert.Equal(t, http.StatusConflict, apiErr.HTTPStatus)
	assert.Equal(t, string(registry.CodeVersionConflict), apiErr.Details["code"])
	assert.NotNil(t, apiErr.Details["current"])

	human := &apigen.TxeActor{Kind: apigen.TxeActorKindHuman, Id: "connor"}
	reason := apigen.TxeLifecycleRequestReasonManual
	trResp, err := a.TransitionTxeJob(ctx, apigen.TransitionTxeJobRequestObject{JobId: jobID, Body: &apigen.TxeLifecycleRequest{
		Op: apigen.TxeLifecycleRequestOpRetire, Reason: &reason, Actor: human}})
	require.NoError(t, err)
	retired := trResp.(apigen.TransitionTxeJob200JSONResponse)
	assert.Equal(t, apigen.TxeLifecycleRetired, retired.Lifecycle)
	require.NotNil(t, retired.Retirement)

	evResp, err := a.ListTxeJobEvents(ctx, apigen.ListTxeJobEventsRequestObject{JobId: jobID})
	require.NoError(t, err)
	assert.Len(t, evResp.(apigen.ListTxeJobEvents200JSONResponse).Events, 3)

	_, err = a.GetTxeJob(ctx, apigen.GetTxeJobRequestObject{JobId: mint(t, registry.PrefixJob)})
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusNotFound, apiErr.HTTPStatus)
}

type txeFixture struct {
	t                       *testing.T
	a                       *apiv1.API
	owner, machine, project string
}

func newTxeFixture(t *testing.T, a *apiv1.API, ctx context.Context) *txeFixture {
	t.Helper()
	f := &txeFixture{t: t, a: a, owner: mint(t, registry.PrefixOwner), machine: mint(t, registry.PrefixMachine)}
	cliActor := &apigen.TxeActor{Kind: apigen.TxeActorKindCli, Id: "cc3-test"}
	_, err := a.CreateTxeOwner(ctx, apigen.CreateTxeOwnerRequestObject{Body: &apigen.TxeOwnerCreateRequest{OwnerId: f.owner, DisplayName: "Connor Wang", Actor: cliActor}})
	require.NoError(t, err)
	_, err = a.CreateTxeMachine(ctx, apigen.CreateTxeMachineRequestObject{Body: &apigen.TxeMachineCreateRequest{MachineId: f.machine, OwnerId: f.owner, DisplayName: "laptop", Actor: cliActor}})
	require.NoError(t, err)
	projResp, err := a.EnsureTxeProject(ctx, apigen.EnsureTxeProjectRequestObject{Body: &apigen.TxeProjectEnsureRequest{OwnerId: f.owner, Key: "github.com/txehq/txe", Actor: cliActor}})
	require.NoError(t, err)
	f.project = projResp.(apigen.EnsureTxeProject200JSONResponse).ProjectId
	return f
}

// register registers a job whose DAG is labelled with workspace (none when
// empty) and returns its ID and the registration error.
func (f *txeFixture) register(ctx context.Context, workspace string) (string, error) {
	labels := ""
	if workspace != "" {
		labels = fmt.Sprintf("labels:\n  - workspace=%s\n", workspace)
	}
	spec := labels + fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", f.machine)
	jobID := mint(f.t, registry.PrefixJob)
	_, err := f.a.RegisterTxeJob(ctx, apigen.RegisterTxeJobRequestObject{Body: &apigen.TxeRegisterRequest{
		JobId: jobID, RequestId: "r1", OwnerId: f.owner, ProjectId: f.project, MachineId: f.machine, JobKey: "key:" + jobID,
		Version: apigen.TxeJobVersionInput{
			Title: "t", Purpose: "p",
			Package: apigen.TxePackage{Digest: fmt.Sprintf("sha256:%064x", 7), Path: "/pkg", Entrypoint: "run.sh"},
			Dag:     apigen.TxeDAGRef{Spec: spec},
		},
		Actor: &apigen.TxeActor{Kind: apigen.TxeActorKindCli, Id: "cc3-test"},
	}})
	return jobID, err
}

func (f *txeFixture) ready(ctx context.Context, jobID string) error {
	_, err := f.a.MarkTxeJobReady(ctx, apigen.MarkTxeJobReadyRequestObject{JobId: jobID, Body: &apigen.TxeReadyRequest{
		Package: apigen.TxePackageEvidence{Digest: fmt.Sprintf("sha256:%064x", 7), Path: "/pkg", MachineId: f.machine}}})
	return err
}

func (f *txeFixture) pause(ctx context.Context, jobID string, actor *apigen.TxeActor) (apigen.TxeJob, error) {
	resp, err := f.a.TransitionTxeJob(ctx, apigen.TransitionTxeJobRequestObject{JobId: jobID, Body: &apigen.TxeLifecycleRequest{
		Op: apigen.TxeLifecycleRequestOpPause, Actor: actor}})
	if err != nil {
		return apigen.TxeJob{}, err
	}
	return apigen.TxeJob(resp.(apigen.TransitionTxeJob200JSONResponse)), nil
}

func requireStatus(t *testing.T, err error, status int) {
	t.Helper()
	var apiErr *apiv1.Error
	require.True(t, errors.As(err, &apiErr), "got %v", err)
	assert.Equal(t, status, apiErr.HTTPStatus)
}

var (
	txeAdmin = auth.WithUser(context.Background(), &auth.User{Username: "admin", Role: auth.RoleAdmin, WorkspaceAccess: auth.AllWorkspaceAccess()})
	txeOps   = auth.WithUser(context.Background(), &auth.User{Username: "dev", Role: auth.RoleDeveloper, WorkspaceAccess: &auth.WorkspaceAccess{
		Grants: []auth.WorkspaceGrant{{Workspace: "ops", Role: auth.RoleDeveloper}},
	}})
)

// Registering a job writes a DAG, so it needs the same workspace write
// access as creating that DAG natively; changing a job needs write access
// to its workspace.
func TestTxeAPIChecksWorkspace(t *testing.T) {
	a := newTxeTestAPI(t, apiv1.WithAuthService(struct{ apiv1.AuthService }{}))
	f := newTxeFixture(t, a, txeAdmin)

	opsJob, err := f.register(txeOps, "ops")
	require.NoError(t, err)
	_, err = f.register(txeOps, "secret")
	requireStatus(t, err, http.StatusForbidden)

	secretJob, err := f.register(txeAdmin, "secret")
	require.NoError(t, err)
	requireStatus(t, f.ready(txeOps, secretJob), http.StatusForbidden)
	require.NoError(t, f.ready(txeAdmin, secretJob))
	_, err = f.pause(txeOps, secretJob, nil)
	requireStatus(t, err, http.StatusForbidden)

	require.NoError(t, f.ready(txeOps, opsJob))
	_, err = f.pause(txeOps, opsJob, nil)
	require.NoError(t, err)
}

// On an authenticated request the actor ID is the principal's, and an API
// key cannot act as a human.
func TestTxeAPIBindsActorToPrincipal(t *testing.T) {
	a := newTxeTestAPI(t, apiv1.WithAuthService(struct{ apiv1.AuthService }{}))
	f := newTxeFixture(t, a, txeAdmin)
	jobID, err := f.register(txeAdmin, "")
	require.NoError(t, err)
	require.NoError(t, f.ready(txeAdmin, jobID))

	session := "s1"
	job, err := f.pause(txeAdmin, jobID, &apigen.TxeActor{Kind: apigen.TxeActorKindCli, Id: "someone-else", Session: &session})
	require.NoError(t, err)
	assert.Equal(t, "admin", job.Updated.By.Id)
	assert.Equal(t, apigen.TxeActorKindCli, job.Updated.By.Kind)
	require.NotNil(t, job.Updated.By.Session)
	assert.Equal(t, "s1", *job.Updated.By.Session)

	key := &auth.APIKey{ID: "k1", Name: "reviewer", Role: auth.RoleDeveloper}
	keyCtx := auth.WithAPIKey(auth.WithUser(context.Background(), &auth.User{ID: "apikey:k1", Username: "apikey:reviewer", Role: auth.RoleDeveloper}), key)
	_, err = a.TransitionTxeJob(keyCtx, apigen.TransitionTxeJobRequestObject{JobId: jobID, Body: &apigen.TxeLifecycleRequest{
		Op: apigen.TxeLifecycleRequestOpResume, Actor: &apigen.TxeActor{Kind: apigen.TxeActorKindHuman, Id: "admin"}}})
	requireStatus(t, err, http.StatusForbidden)
}

// Readiness may rewrite the job's DAG, so it is refused while DAG writes
// are disabled.
func TestTxeAPIReadyNeedsDAGWrite(t *testing.T) {
	dir := t.TempDir()
	a := newTxeTestAPIAt(t, dir, true)
	f := newTxeFixture(t, a, context.Background())
	jobID, err := f.register(context.Background(), "")
	require.NoError(t, err)

	readOnly := newTxeTestAPIAt(t, dir, false)
	f.a = readOnly
	requireStatus(t, f.ready(context.Background(), jobID), http.StatusForbidden)
}

// Action parameters keep their exact JSON through request decoding, so a
// large integer is not rounded before it is bound and stored.
func TestTxeAPIKeepsParamsExact(t *testing.T) {
	ctx := context.Background()
	a := newTxeTestAPI(t)
	f := newTxeFixture(t, a, ctx)
	jobID, err := f.register(ctx, "")
	require.NoError(t, err)
	require.NoError(t, f.ready(ctx, jobID))
	claimResp, err := a.AcquireTxeClaim(ctx, apigen.AcquireTxeClaimRequestObject{JobId: jobID, Body: &apigen.TxeClaimRequest{
		Kind: apigen.TxeClaimKindReview, TtlSec: 60}})
	require.NoError(t, err)
	claim := claimResp.(apigen.AcquireTxeClaim200JSONResponse)

	raw := fmt.Sprintf(`{"claim_id":%q,"fence":%d,"proposal":{"proposal_id":%q,"action":{"name":"resize","params":{"n":9007199254740993,"x":1.0}}}}`,
		claim.ClaimId, claim.Fence, mint(t, registry.PrefixProposal))
	var body apigen.TxeProposalRequest
	require.NoError(t, json.Unmarshal([]byte(raw), &body))
	resp, err := a.CreateTxeProposal(ctx, apigen.CreateTxeProposalRequestObject{JobId: jobID, Body: &body})
	require.NoError(t, err)
	got := resp.(apigen.CreateTxeProposal200JSONResponse)
	assert.JSONEq(t, `{"n":9007199254740993,"x":1.0}`, string(got.Action.Params))
	assert.Contains(t, string(got.Action.Params), "9007199254740993")
}
