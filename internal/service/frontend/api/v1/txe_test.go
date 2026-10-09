// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
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
	require.NoError(t, store.RebuildResourceIndex(context.Background()))
	cfg := &config.Config{}
	cfg.Server.Permissions = map[config.Permission]bool{config.PermissionWriteDAGs: writeDAGs, config.PermissionRunDAGs: true}
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
	return f.registerTargets(ctx, workspace)
}

// registerTargets is register for a job that depends on targets.
func (f *txeFixture) registerTargets(ctx context.Context, workspace string, targets ...apigen.TxeTarget) (string, error) {
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
			Targets: &targets,
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

// A version update is authorized against the committed version it replaces,
// so a job whose DAG file is missing cannot be moved into another workspace.
func TestTxeAPIUpdateChecksCommittedVersion(t *testing.T) {
	dir := t.TempDir()
	a := newTxeTestAPIAt(t, dir, true, apiv1.WithAuthService(struct{ apiv1.AuthService }{}))
	f := newTxeFixture(t, a, txeAdmin)
	jobID, err := f.register(txeAdmin, "secret")
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(dir, "dags", jobID+".yaml")))

	spec := fmt.Sprintf("labels:\n  - workspace=ops\nworker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", f.machine)
	_, err = a.UpdateTxeJobVersion(txeOps, apigen.UpdateTxeJobVersionRequestObject{JobId: jobID, Body: &apigen.TxeVersionRequest{
		RequestId: "u1", ExpectedVersion: 1,
		Version: apigen.TxeJobVersionInput{
			Title: "t", Purpose: "p",
			Package: apigen.TxePackage{Digest: fmt.Sprintf("sha256:%064x", 8), Path: "/pkg", Entrypoint: "run.sh"},
			Dag:     apigen.TxeDAGRef{Spec: spec},
		}}})
	requireStatus(t, err, http.StatusForbidden)

	// A version that does not exist yet was not authorized: it is a conflict,
	// whatever is committed after the check.
	opsJob, err := f.register(txeOps, "ops")
	require.NoError(t, err)
	_, err = a.UpdateTxeJobVersion(txeOps, apigen.UpdateTxeJobVersionRequestObject{JobId: opsJob, Body: &apigen.TxeVersionRequest{
		RequestId: "u1", ExpectedVersion: 2,
		Version: apigen.TxeJobVersionInput{
			Title: "t", Purpose: "p",
			Package: apigen.TxePackage{Digest: fmt.Sprintf("sha256:%064x", 8), Path: "/pkg", Entrypoint: "run.sh"},
			Dag:     apigen.TxeDAGRef{Spec: spec},
		}}})
	requireStatus(t, err, http.StatusConflict)
}

// Only a signed-in person reactivates a retired job. An API key cannot claim
// to be human, and the descriptive actor fields never make it one.
func TestTxeAPIReactivateNeedsHumanPrincipal(t *testing.T) {
	a := newTxeTestAPI(t, apiv1.WithAuthService(struct{ apiv1.AuthService }{}))
	f := newTxeFixture(t, a, txeAdmin)
	jobID, err := f.register(txeAdmin, "")
	require.NoError(t, err)
	require.NoError(t, f.ready(txeAdmin, jobID))
	reason := apigen.TxeLifecycleRequestReasonManual
	_, err = a.TransitionTxeJob(txeAdmin, apigen.TransitionTxeJobRequestObject{JobId: jobID, Body: &apigen.TxeLifecycleRequest{
		Op: apigen.TxeLifecycleRequestOpRetire, Reason: &reason}})
	require.NoError(t, err)

	key := &auth.APIKey{ID: "k1", Name: "reviewer", Role: auth.RoleDeveloper}
	keyCtx := auth.WithAPIKey(auth.WithUser(context.Background(), &auth.User{ID: "apikey:k1", Username: "apikey:reviewer", Role: auth.RoleDeveloper}), key)
	reactivate := func(ctx context.Context, actor *apigen.TxeActor) error {
		_, err := a.TransitionTxeJob(ctx, apigen.TransitionTxeJobRequestObject{JobId: jobID, Body: &apigen.TxeLifecycleRequest{
			Op: apigen.TxeLifecycleRequestOpReactivate, Actor: actor}})
		return err
	}
	requireStatus(t, reactivate(keyCtx, &apigen.TxeActor{Kind: apigen.TxeActorKindHuman, Id: "admin"}), http.StatusForbidden)

	human, machine, client := "human", "human", "human"
	requireStatus(t, reactivate(keyCtx, &apigen.TxeActor{Kind: apigen.TxeActorKindCli, Id: "admin", Session: &human, MachineId: &machine, Client: &client}), http.StatusConflict)
	requireStatus(t, reactivate(keyCtx, nil), http.StatusConflict)

	got, err := a.GetTxeJob(txeAdmin, apigen.GetTxeJobRequestObject{JobId: jobID})
	require.NoError(t, err)
	assert.Equal(t, apigen.TxeLifecycleRetired, got.(apigen.GetTxeJob200JSONResponse).Lifecycle, "the job stays retired")

	require.NoError(t, reactivate(txeAdmin, nil))
	got, err = a.GetTxeJob(txeAdmin, apigen.GetTxeJobRequestObject{JobId: jobID})
	require.NoError(t, err)
	job := got.(apigen.GetTxeJob200JSONResponse)
	assert.Equal(t, apigen.TxeLifecycleActive, job.Lifecycle)
	assert.Equal(t, apigen.TxeActorKindHuman, job.Updated.By.Kind)
	assert.Equal(t, "admin", job.Updated.By.Id)
}

// The decision list reports whether each decision's Dagu task is still to be
// completed now, not the state the immutable record was written with.
func TestTxeAPIDecisionsReportNativeResume(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	a := newTxeTestAPIAt(t, dir, true)
	store, err := registry.NewFileStore(filepath.Join(dir, "data"))
	require.NoError(t, err)
	f := newTxeFixture(t, a, ctx)
	jobID, err := f.register(ctx, "")
	require.NoError(t, err)
	require.NoError(t, f.ready(ctx, jobID))
	claimResp, err := a.AcquireTxeClaim(ctx, apigen.AcquireTxeClaimRequestObject{JobId: jobID, Body: &apigen.TxeClaimRequest{
		Kind: apigen.TxeClaimKindReview, TtlSec: 60}})
	require.NoError(t, err)
	claim := claimResp.(apigen.AcquireTxeClaim200JSONResponse)
	propResp, err := a.CreateTxeProposal(ctx, apigen.CreateTxeProposalRequestObject{JobId: jobID, Body: &apigen.TxeProposalRequest{
		ClaimId: claim.ClaimId, Fence: claim.Fence, Proposal: apigen.TxeProposalInput{
			ProposalId: mint(t, registry.PrefixProposal), Action: apigen.TxeActionSpec{Name: "resize"},
			NativeTask: &apigen.TxeNativeTask{Dag: registry.DecideTaskDAG(f.machine), RunId: "run-1", StepId: registry.DecideTaskStep},
		}}})
	require.NoError(t, err)
	p := propResp.(apigen.CreateTxeProposal200JSONResponse)

	person := registry.Actor{Kind: registry.ActorHuman, ID: "connor"}
	decide := func(verdict registry.Verdict, revision int, next registry.ProposalState) string {
		t.Helper()
		id := mint(t, registry.PrefixDecision)
		_, err := store.WithJobTx(ctx, jobID, person, func(tx *registry.JobTx) error {
			_, err := tx.AppendDecision(registry.Decision{DecisionID: id, ProposalID: p.ProposalId, ProposalRevision: revision,
				BindingDigest: p.BindingDigest, Verdict: verdict}, next)
			return err
		})
		require.NoError(t, err)
		return id
	}
	nativeResume := func() []string {
		t.Helper()
		resp, err := a.ListTxeJobDecisions(ctx, apigen.ListTxeJobDecisionsRequestObject{JobId: jobID})
		require.NoError(t, err)
		var out []string
		for _, d := range resp.(apigen.ListTxeJobDecisions200JSONResponse).Decisions {
			if d.NativeResume == nil {
				out = append(out, "")
				continue
			}
			out = append(out, string(*d.NativeResume))
		}
		return out
	}

	// A snooze leaves the task waiting: nothing to resume, nothing reported.
	decide(registry.VerdictSnooze, p.Revision, registry.ProposalSnoozed)
	job, err := store.GetJob(ctx, jobID)
	require.NoError(t, err)
	assert.Empty(t, job.NativeResumes)
	assert.Equal(t, []string{""}, nativeResume())

	rejected := decide(registry.VerdictReject, p.Revision+1, registry.ProposalRejected)
	assert.Equal(t, []string{"pending", ""}, nativeResume(), "newest first")
	_, err = store.WithJobTx(ctx, jobID, person, func(tx *registry.JobTx) error { return tx.MarkNativeResumed(rejected) })
	require.NoError(t, err)
	assert.Equal(t, []string{"completed", ""}, nativeResume())

	// The state is projected at read time: a new store and API over the same
	// data report it, and the immutable records still hold what was written.
	a = newTxeTestAPIAt(t, dir, true)
	assert.Equal(t, []string{"completed", ""}, nativeResume())
	restarted, err := registry.NewFileStore(filepath.Join(dir, "data"))
	require.NoError(t, err)
	stored, err := restarted.GetDecision(ctx, jobID, rejected)
	require.NoError(t, err)
	assert.Equal(t, "pending", stored.NativeResume)
}

// Registry reads follow workspace visibility: a job, its versions and its
// history are not found by a caller who cannot see its workspace, and a
// version from a workspace the job has left stays hidden.
func TestTxeAPIReadsFollowWorkspaceVisibility(t *testing.T) {
	a := newTxeTestAPI(t, apiv1.WithAuthService(struct{ apiv1.AuthService }{}))
	f := newTxeFixture(t, a, txeAdmin)
	opsJob, err := f.register(txeAdmin, "ops")
	require.NoError(t, err)
	secretJob, err := f.register(txeAdmin, "secret")
	require.NoError(t, err)

	list, err := a.ListTxeJobs(txeOps, apigen.ListTxeJobsRequestObject{})
	require.NoError(t, err)
	var ids []string
	for _, j := range list.(apigen.ListTxeJobs200JSONResponse).Jobs {
		ids = append(ids, j.JobId)
	}
	assert.Equal(t, []string{opsJob}, ids)

	_, err = a.GetTxeJob(txeOps, apigen.GetTxeJobRequestObject{JobId: secretJob})
	requireStatus(t, err, http.StatusNotFound)
	_, err = a.GetTxeJobVersion(txeOps, apigen.GetTxeJobVersionRequestObject{JobId: secretJob, Version: 1})
	requireStatus(t, err, http.StatusNotFound)
	_, err = a.ListTxeJobEvents(txeOps, apigen.ListTxeJobEventsRequestObject{JobId: secretJob})
	requireStatus(t, err, http.StatusNotFound)
	_, err = a.GetTxeJob(txeOps, apigen.GetTxeJobRequestObject{JobId: opsJob})
	require.NoError(t, err)

	// The admin moves the secret job to ops: its current version is visible,
	// its secret first version is not.
	spec := fmt.Sprintf("labels:\n  - workspace=ops\nworker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", f.machine)
	_, err = a.UpdateTxeJobVersion(txeAdmin, apigen.UpdateTxeJobVersionRequestObject{JobId: secretJob, Body: &apigen.TxeVersionRequest{
		RequestId: "u1", ExpectedVersion: 1,
		Version: apigen.TxeJobVersionInput{
			Title: "t", Purpose: "p",
			Package: apigen.TxePackage{Digest: fmt.Sprintf("sha256:%064x", 8), Path: "/pkg", Entrypoint: "run.sh"},
			Dag:     apigen.TxeDAGRef{Spec: spec},
		}}})
	require.NoError(t, err)
	_, err = a.GetTxeJobVersion(txeOps, apigen.GetTxeJobVersionRequestObject{JobId: secretJob, Version: 2})
	require.NoError(t, err)
	_, err = a.GetTxeJobVersion(txeOps, apigen.GetTxeJobVersionRequestObject{JobId: secretJob, Version: 1})
	requireStatus(t, err, http.StatusNotFound)
}

func txeVolume(uid string) apigen.TxeTarget {
	name := "pvc-" + uid
	return apigen.TxeTarget{Kind: "kubernetes.volume", StableId: map[string]string{"cluster_uid": "c-1", "uid": uid}, DisplayName: &name}
}

// A resource event affects only dependents the reporter may write, and a
// retired job's runs are refused by the REST start path.
func TestTxeAPIResourceEventAndRunGuard(t *testing.T) {
	a := newTxeTestAPI(t, apiv1.WithAuthService(struct{ apiv1.AuthService }{}))
	f := newTxeFixture(t, a, txeAdmin)
	opsJob, err := f.registerTargets(txeAdmin, "ops", txeVolume("v-1"))
	require.NoError(t, err)
	require.NoError(t, f.ready(txeAdmin, opsJob))
	secretJob, err := f.registerTargets(txeAdmin, "secret", txeVolume("v-1"))
	require.NoError(t, err)
	require.NoError(t, f.ready(txeAdmin, secretJob))

	authoritative := true
	resp, err := a.RecordTxeResourceEvent(txeOps, apigen.RecordTxeResourceEventRequestObject{Body: &apigen.TxeResourceEventRequest{
		Target: txeVolume("v-1"), Observation: apigen.TxeResourceObservationDeleted, Authoritative: &authoritative}})
	require.NoError(t, err)
	ev := apigen.TxeResourceEvent(resp.(apigen.RecordTxeResourceEvent200JSONResponse))
	require.Len(t, ev.Dispositions, 1, "the job in a workspace the reporter cannot write is neither changed nor disclosed")
	assert.Equal(t, opsJob, ev.Dispositions[0].JobId)
	assert.Equal(t, apigen.TxeResourceDispositionOutcomeRetired, ev.Dispositions[0].Outcome)

	got, err := a.GetTxeJob(txeAdmin, apigen.GetTxeJobRequestObject{JobId: secretJob})
	require.NoError(t, err)
	assert.Equal(t, apigen.TxeLifecycleActive, got.(apigen.GetTxeJob200JSONResponse).Lifecycle)

	read, err := a.GetTxeResourceEvent(txeOps, apigen.GetTxeResourceEventRequestObject{EventId: ev.EventId})
	require.NoError(t, err)
	assert.Len(t, read.(apigen.GetTxeResourceEvent200JSONResponse).Dispositions, 1)

	_, err = a.EnqueueDAGDAGRun(txeAdmin, apigen.EnqueueDAGDAGRunRequestObject{FileName: opsJob})
	requireStatus(t, err, http.StatusConflict)
	_, err = a.EnqueueDAGDAGRun(txeAdmin, apigen.EnqueueDAGDAGRunRequestObject{FileName: opsJob + ".yaml"})
	requireStatus(t, err, http.StatusConflict)
	// An admitted job still never runs in the API process: with no
	// coordinator to dispatch to its worker, the start is refused.
	_, err = a.ExecuteDAG(txeAdmin, apigen.ExecuteDAGRequestObject{FileName: secretJob})
	requireStatus(t, err, http.StatusConflict)
	other := "renamed-run"
	_, err = a.EnqueueDAGDAGRun(txeAdmin, apigen.EnqueueDAGDAGRunRequestObject{FileName: secretJob, Body: &apigen.EnqueueDAGDAGRunJSONRequestBody{DagName: &other}})
	requireStatus(t, err, http.StatusConflict)

	// Someone who can see none of the affected jobs and did not report the
	// event cannot read it.
	secretOnly := auth.WithUser(context.Background(), &auth.User{Username: "sec", Role: auth.RoleDeveloper, WorkspaceAccess: &auth.WorkspaceAccess{
		Grants: []auth.WorkspaceGrant{{Workspace: "secret", Role: auth.RoleDeveloper}},
	}})
	_, err = a.GetTxeResourceEvent(secretOnly, apigen.GetTxeResourceEventRequestObject{EventId: ev.EventId})
	requireStatus(t, err, http.StatusNotFound)
}

// Reviews are read back by ID, a replay that differs is refused, reviewer
// trouble is kept apart from the job's availability, and decisions page
// forward in ascending order.
func TestTxeAPIReviewsObservationsAndDecisionOrder(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	a := newTxeTestAPIAt(t, dir, true)
	store, err := registry.NewFileStore(filepath.Join(dir, "data"))
	require.NoError(t, err)
	f := newTxeFixture(t, a, ctx)
	jobID, err := f.register(ctx, "")
	require.NoError(t, err)
	require.NoError(t, f.ready(ctx, jobID))
	claimResp, err := a.AcquireTxeClaim(ctx, apigen.AcquireTxeClaimRequestObject{JobId: jobID, Body: &apigen.TxeClaimRequest{
		Kind: apigen.TxeClaimKindReview, TtlSec: 600}})
	require.NoError(t, err)
	claim := claimResp.(apigen.AcquireTxeClaim200JSONResponse)

	reviewID, err := registry.ReviewID(jobID, 0)
	require.NoError(t, err)
	record := func(outcome apigen.TxeReviewOutcome) error {
		_, err := a.RecordTxeReview(ctx, apigen.RecordTxeReviewRequestObject{JobId: jobID, Body: &apigen.TxeReviewRequest{
			ClaimId: claim.ClaimId, Fence: claim.Fence, Review: apigen.TxeReview{ReviewId: reviewID, Outcome: outcome,
				EvidenceRunIds: &[]string{"run-1"}, PacketBytes: new(int64(2048)), AgentInputTokens: new(int64(900))}}})
		return err
	}
	require.NoError(t, record(apigen.TxeReviewOutcomeContinue))
	require.NoError(t, record(apigen.TxeReviewOutcomeContinue), "an identical replay is a no-op")
	requireStatus(t, record(apigen.TxeReviewOutcomeAct), http.StatusConflict)
	got, err := a.GetTxeReview(ctx, apigen.GetTxeReviewRequestObject{JobId: jobID, ReviewId: reviewID})
	require.NoError(t, err)
	review := got.(apigen.GetTxeReview200JSONResponse)
	assert.Equal(t, int64(2048), *review.PacketBytes)
	assert.Equal(t, int64(900), *review.AgentInputTokens)
	_, err = a.GetTxeReview(ctx, apigen.GetTxeReviewRequestObject{JobId: jobID, ReviewId: mint(t, registry.PrefixReview)})
	requireStatus(t, err, http.StatusNotFound)

	reviewer := apigen.TxeObservationRequestScopeReviewer
	observed, err := a.ObserveTxeJob(ctx, apigen.ObserveTxeJobRequestObject{JobId: jobID, Body: &apigen.TxeObservationRequest{
		State: apigen.TxeAvailabilityStateAuthRequired, Scope: &reviewer, Detail: new("reviewer login expired")}})
	require.NoError(t, err)
	job := observed.(apigen.ObserveTxeJob200JSONResponse)
	assert.Equal(t, apigen.TxeAvailabilityStateReady, job.Availability.State, "the job itself is still available")
	require.NotNil(t, job.ReviewerAvailability)
	assert.Equal(t, apigen.TxeAvailabilityStateAuthRequired, job.ReviewerAvailability.State)

	person := registry.Actor{Kind: registry.ActorHuman, ID: "connor"}
	var ids []string
	for range 3 {
		var p *registry.Proposal
		_, err := store.WithJobTx(ctx, jobID, person, func(tx *registry.JobTx) error {
			var err error
			p, err = tx.PutProposal(claim.ClaimId, claim.Fence, registry.Proposal{ProposalID: mint(t, registry.PrefixProposal), Action: registry.ActionSpec{Name: "resize"}})
			if err != nil {
				return err
			}
			id := mint(t, registry.PrefixDecision)
			ids = append(ids, id)
			_, err = tx.AppendDecision(registry.Decision{DecisionID: id, ProposalID: p.ProposalID, ProposalRevision: p.Revision,
				BindingDigest: p.BindingDigest, Verdict: registry.VerdictReject}, registry.ProposalRejected)
			return err
		})
		require.NoError(t, err)
	}
	list := func(order apigen.ListTxeJobDecisionsParamsOrder, since string, limit int) []string {
		t.Helper()
		params := apigen.ListTxeJobDecisionsParams{Order: &order}
		if since != "" {
			params.Since = &since
		}
		if limit > 0 {
			params.Limit = &limit
		}
		resp, err := a.ListTxeJobDecisions(ctx, apigen.ListTxeJobDecisionsRequestObject{JobId: jobID, Params: params})
		require.NoError(t, err)
		var out []string
		for _, d := range resp.(apigen.ListTxeJobDecisions200JSONResponse).Decisions {
			out = append(out, d.DecisionId)
		}
		return out
	}
	asc, desc := apigen.ListTxeJobDecisionsParamsOrderAsc, apigen.ListTxeJobDecisionsParamsOrderDesc
	assert.Equal(t, []string{ids[2], ids[1], ids[0]}, list(desc, "", 0))
	assert.Equal(t, ids, list(asc, "", 0))
	assert.Equal(t, []string{ids[1]}, list(asc, ids[0], 1), "the limit applies forward from the cursor")
}

// A retired job's superseded proposal with a Dagu human task is listed for
// its machine until a closure with a final outcome is recorded.
func TestTxeAPIProposalClosures(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	a := newTxeTestAPIAt(t, dir, true)
	store, err := registry.NewFileStore(filepath.Join(dir, "data"))
	require.NoError(t, err)
	f := newTxeFixture(t, a, ctx)
	jobID, err := f.register(ctx, "")
	require.NoError(t, err)
	require.NoError(t, f.ready(ctx, jobID))
	claimResp, err := a.AcquireTxeClaim(ctx, apigen.AcquireTxeClaimRequestObject{JobId: jobID, Body: &apigen.TxeClaimRequest{
		Kind: apigen.TxeClaimKindReview, TtlSec: 600}})
	require.NoError(t, err)
	claim := claimResp.(apigen.AcquireTxeClaim200JSONResponse)
	propResp, err := a.CreateTxeProposal(ctx, apigen.CreateTxeProposalRequestObject{JobId: jobID, Body: &apigen.TxeProposalRequest{
		ClaimId: claim.ClaimId, Fence: claim.Fence, Proposal: apigen.TxeProposalInput{
			ProposalId: mint(t, registry.PrefixProposal), Action: apigen.TxeActionSpec{Name: "resize"},
			NativeTask: &apigen.TxeNativeTask{Dag: registry.DecideTaskDAG(f.machine), RunId: "run-1", StepId: registry.DecideTaskStep},
		}}})
	require.NoError(t, err)
	p := propResp.(apigen.CreateTxeProposal200JSONResponse)
	_, err = store.WithJobTx(ctx, jobID, registry.Actor{Kind: registry.ActorHuman, ID: "connor"}, func(tx *registry.JobTx) error {
		return tx.Transition(registry.Transition{Op: registry.OpRetire, Reason: registry.RetireManual})
	})
	require.NoError(t, err)

	pending := func() []apigen.TxePendingClosure {
		t.Helper()
		resp, err := a.ListTxePendingClosures(ctx, apigen.ListTxePendingClosuresRequestObject{Params: apigen.ListTxePendingClosuresParams{Machine: f.machine}})
		require.NoError(t, err)
		return resp.(apigen.ListTxePendingClosures200JSONResponse).Closures
	}
	require.Len(t, pending(), 1)
	assert.Equal(t, p.ProposalId, pending()[0].ProposalId)

	closure, err := a.RecordTxeProposalClosure(ctx, apigen.RecordTxeProposalClosureRequestObject{JobId: jobID, ProposalId: p.ProposalId,
		Body: &apigen.TxeClosureRequest{Outcome: apigen.TxeClosureOutcomeAlreadyAnswered}})
	require.NoError(t, err)
	assert.Equal(t, apigen.TxeClosureOutcomeAlreadyAnswered, closure.(apigen.RecordTxeProposalClosure200JSONResponse).Outcome)
	assert.Empty(t, pending())
	_, err = a.RecordTxeProposalClosure(ctx, apigen.RecordTxeProposalClosureRequestObject{JobId: jobID, ProposalId: p.ProposalId,
		Body: &apigen.TxeClosureRequest{Outcome: apigen.TxeClosureOutcomeClosed}})
	requireStatus(t, err, http.StatusConflict)
}
