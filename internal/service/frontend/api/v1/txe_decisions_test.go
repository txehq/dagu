// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	apiv1 "github.com/dagucloud/dagu/v2/internal/service/frontend/api/v1"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/decision"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// decideSpec is the shape of the per-proposal decide DAG: a processless
// human task that receives the decision ID, then a step that consumes it.
const decideSpec = `steps:
  - id: decide
    action: human.task
    with:
      prompt: "Decide the proposal"
      form:
        type: object
        properties:
          decision_id:
            type: string
          verdict:
            type: string
            enum: [approve, reject, redirect, retry, pause, snooze, retire]
        required: [decision_id, verdict]
  - id: execute
    depends: decide
    run: test -n "${steps.decide.outputs.decision_id}"`

type txeDecisionFixture struct {
	server   test.Server
	jobID    string
	client   txeHTTPClient
	decide   string
	runID    string
	proposal api.TxeProposal
}

// newTxeDecisionFixture registers a ready job, starts its decide run until
// the human task waits, and files a proposal pointing at that task.
func newTxeDecisionFixture(t *testing.T) *txeDecisionFixture {
	t.Helper()
	server := builtinServer(t)
	return newTxeDecisionFixtureOn(t, server, txeAuthedClient{c: server.Client(), token: loginAndGetToken(t, server, "admin", "adminpass")})
}

// newTxeDecisionFixtureOn builds the fixture on server, every request made
// through c.
func newTxeDecisionFixtureOn(t *testing.T, server test.Server, c txeHTTPClient) *txeDecisionFixture {
	t.Helper()
	cli := map[string]any{"kind": "cli", "id": "cc4-test"}

	owner, machine := mint(t, registry.PrefixOwner), mint(t, registry.PrefixMachine)
	c.Post("/api/v1/txe/owners", map[string]any{"owner_id": owner, "display_name": "Connor", "actor": cli}).
		ExpectStatus(http.StatusCreated).Send(t)
	c.Post("/api/v1/txe/machines", map[string]any{"machine_id": machine, "owner_id": owner, "display_name": "laptop", "actor": cli}).
		ExpectStatus(http.StatusCreated).Send(t)
	var project api.TxeProject
	c.Post("/api/v1/txe/projects", map[string]any{"owner_id": owner, "key": "github.com/txehq/fixture", "actor": cli}).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &project)

	jobID := mint(t, registry.PrefixJob)
	digest := fmt.Sprintf("sha256:%064x", 1)
	c.Post("/api/v1/txe/jobs", map[string]any{
		"job_id": jobID, "request_id": "r1", "owner_id": owner, "project_id": project.ProjectId,
		"machine_id": machine, "job_key": "volume-monitor", "actor": cli,
		"version": map[string]any{
			"title": "Volume monitor", "purpose": "Watch the fixture volume",
			"package": map[string]any{"digest": digest, "path": "/pkg", "entrypoint": "run.sh"},
			"dag":     map[string]any{"spec": fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", machine)},
			"targets": []any{map[string]any{"kind": "k8s.pv", "stable_id": map[string]any{"uid": "pv-1"}}},
		},
	}).ExpectStatus(http.StatusCreated).Send(t)
	c.Post("/api/v1/txe/jobs/"+jobID+"/ready", map[string]any{
		"package": map[string]any{"digest": digest, "path": "/pkg", "machine_id": machine}, "actor": cli,
	}).ExpectStatus(http.StatusOK).Send(t)

	decideDAG := decision.DecideDAGName(machine)
	spec := decideSpec
	c.Post("/api/v1/dags", api.CreateNewDAGJSONRequestBody{Name: decideDAG, Spec: &spec}).
		ExpectStatus(http.StatusCreated).Send(t)
	var started api.ExecuteDAG200JSONResponse
	c.Post("/api/v1/dags/"+decideDAG+"/start", api.ExecuteDAGJSONRequestBody{}).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &started)
	waitForStoredDAGRunStatus(t, server, decideDAG, started.DagRunId, 10*time.Second, func(s *ir.DAGRunStatus) bool {
		return s.Status == ir.Waiting && hasNodeWithStatus(s, "decide", ir.NodeWaiting)
	})

	reviewer := map[string]any{"kind": "reviewer", "id": "cc5-test"}
	var claim api.TxeClaim
	c.Post("/api/v1/txe/jobs/"+jobID+"/claims", map[string]any{
		"kind": "review", "reviewer": map[string]any{"machine_id": machine}, "ttl_sec": 600, "actor": reviewer,
	}).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &claim)
	var proposal api.TxeProposal
	c.Post("/api/v1/txe/jobs/"+jobID+"/proposals", map[string]any{
		"claim_id": claim.ClaimId, "fence": claim.Fence, "actor": reviewer,
		"proposal": map[string]any{
			"proposal_id": mint(t, registry.PrefixProposal),
			"question":    "Resize the volume to 20Gi?",
			"waiting_on":  "person",
			"action": map[string]any{
				"name": "resize", "params": map[string]any{"size_gi": 20},
				"target": map[string]any{"kind": "k8s.pv", "stable_id": map[string]any{"uid": "pv-1"}},
			},
			"native_task": map[string]any{"dag": decideDAG, "run_id": started.DagRunId, "step_id": "decide"},
		},
	}).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &proposal)

	return &txeDecisionFixture{server: server, client: c, jobID: jobID, decide: decideDAG, runID: started.DagRunId, proposal: proposal}
}

// txeHTTPClient makes the fixture's requests with some credential.
type txeHTTPClient interface {
	Get(path string) *test.Request
	Post(path string, body any) *test.Request
}

// txeBasicClient sends every request with the hub's one basic credential.
type txeBasicClient struct {
	c          *test.APIClient
	user, pass string
}

func (b txeBasicClient) Get(path string) *test.Request {
	return b.c.Get(path).WithBasicAuth(b.user, b.pass)
}
func (b txeBasicClient) Post(path string, body any) *test.Request {
	return b.c.Post(path, body).WithBasicAuth(b.user, b.pass)
}

// txeNoAuthClient sends requests with no credential, as on a hub without
// authentication.
type txeNoAuthClient struct{ c *test.APIClient }

func (n txeNoAuthClient) Get(path string) *test.Request            { return n.c.Get(path) }
func (n txeNoAuthClient) Post(path string, body any) *test.Request { return n.c.Post(path, body) }

// txeAuthedClient sends every request as a signed-in person: a decision is
// accepted only from one.
type txeAuthedClient struct {
	c     *test.APIClient
	token string
}

func (a txeAuthedClient) Get(path string) *test.Request {
	return a.c.Get(path).WithBearerToken(a.token)
}
func (a txeAuthedClient) Post(path string, body any) *test.Request {
	return a.c.Post(path, body).WithBearerToken(a.token)
}

func (f *txeDecisionFixture) decisionPath() string {
	return fmt.Sprintf("/api/v1/txe/jobs/%s/proposals/%s/decisions", f.jobID, f.proposal.ProposalId)
}

func (f *txeDecisionFixture) body(verdict, key string) map[string]any {
	return map[string]any{
		"expected_proposal_revision": f.proposal.Revision,
		"binding_digest":             f.proposal.BindingDigest,
		"verdict":                    verdict,
		"idempotency_key":            key,
	}
}

// An approval through the API is stored, completes the real waiting human
// task with the decision ID, survives reopening the registry from disk, and
// refuses a second decision bound to the old revision.
func TestTxeDecisionApproveCompletesNativeTask(t *testing.T) {
	f := newTxeDecisionFixture(t)
	c := f.client

	var resp api.TxeDecisionResponse
	c.Post(f.decisionPath(), f.body("approve", "dashboard-approve-1")).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &resp)
	require.False(t, resp.Replayed)
	require.Equal(t, api.TxeVerdict("approve"), resp.Decision.Verdict)
	require.NotNil(t, resp.Decision.NativeResume)
	require.Equal(t, api.TxeDecisionNativeResume("completed"), *resp.Decision.NativeResume)
	require.NotNil(t, resp.Proposal)
	require.Equal(t, api.TxeProposalState("decided"), resp.Proposal.State)

	status := waitForStoredDAGRunStatus(t, f.server, f.decide, f.runID, 10*time.Second, func(s *ir.DAGRunStatus) bool {
		return hasNodeWithStatus(s, "decide", ir.NodeSucceeded)
	})
	var input map[string]string
	for _, n := range status.Nodes {
		if n.Step.ID == "decide" {
			require.NoError(t, json.Unmarshal(n.HumanTaskInput, &input))
		}
	}
	require.Equal(t, resp.Decision.DecisionId, input["decision_id"])
	require.Equal(t, "approve", input["verdict"])

	// A fresh registry over the same data directory, as after a hub restart.
	reopened, err := registry.NewFileStore(f.server.Config.Paths.DataDir)
	require.NoError(t, err)
	stored, err := reopened.GetDecision(t.Context(), f.jobID, resp.Decision.DecisionId)
	require.NoError(t, err)
	require.Equal(t, f.proposal.BindingDigest, stored.BindingDigest)
	require.Equal(t, registry.ActorHuman, stored.Actor.Kind)
	// The stored record keeps its write-time state; a fresh API over the
	// reopened registry must still report the completion recorded since.
	reopenedAPI := apiv1.New(persis.NewDAGRepository(dag.NewStore(f.server.Config.Paths.DAGsDir), persis.DAGRepositoryOptions{}),
		nil, nil, nil, runtime.Manager{}, &config.Config{}, nil, nil, prometheus.NewRegistry(), nil, apiv1.WithTxeRegistry(reopened))
	listed, err := reopenedAPI.ListTxeProposalDecisions(t.Context(), api.ListTxeProposalDecisionsRequestObject{
		JobId: f.jobID, ProposalId: f.proposal.ProposalId})
	require.NoError(t, err)
	afterRestart := listed.(api.ListTxeProposalDecisions200JSONResponse).Decisions
	require.Len(t, afterRestart, 1)
	require.NotNil(t, afterRestart[0].NativeResume)
	require.Equal(t, api.TxeDecisionNativeResume("completed"), *afterRestart[0].NativeResume)

	// The old revision no longer accepts a decision.
	stale := f.body("reject", "dashboard-reject-stale")
	var apiErr api.Error
	c.Post(f.decisionPath(), stale).ExpectStatus(http.StatusConflict).Send(t).Unmarshal(t, &apiErr)
	require.NotNil(t, apiErr.Details)
	require.Contains(t, []any{string(registry.CodeStaleBinding), string(registry.CodeProposalState)}, (*apiErr.Details)["code"])

	var list api.TxeDecisionList
	c.Get(f.decisionPath()).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &list)
	require.Len(t, list.Decisions, 1)
	// The stored record was written pending; the listing reports the
	// completion recorded since.
	require.NotNil(t, list.Decisions[0].NativeResume)
	require.Equal(t, api.TxeDecisionNativeResume("completed"), *list.Decisions[0].NativeResume)
}

// A reject closes the proposal, still completes the native task, and replaying
// the same request returns the stored decision without a second one.
func TestTxeDecisionRejectAndReplay(t *testing.T) {
	f := newTxeDecisionFixture(t)
	c := f.client
	var first, again api.TxeDecisionResponse
	c.Post(f.decisionPath(), f.body("reject", "dashboard-reject-1")).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &first)
	require.Nil(t, first.Proposal)
	c.Post(f.decisionPath(), f.body("reject", "dashboard-reject-1")).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &again)
	require.True(t, again.Replayed)
	require.Equal(t, first.Decision.DecisionId, again.Decision.DecisionId)

	waitForStoredDAGRunStatus(t, f.server, f.decide, f.runID, 10*time.Second, func(s *ir.DAGRunStatus) bool {
		return hasNodeWithStatus(s, "decide", ir.NodeSucceeded)
	})
	var list api.TxeDecisionList
	c.Get(f.decisionPath()).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &list)
	require.Len(t, list.Decisions, 1)
}

// A request cannot decide as an agent or reviewer.
func TestTxeDecisionRefusesAgentActor(t *testing.T) {
	f := newTxeDecisionFixture(t)
	body := f.body("approve", "reviewer-self-approve")
	body["actor"] = map[string]any{"kind": "reviewer", "id": "cc5-test"}
	f.client.Post(f.decisionPath(), body).ExpectStatus(http.StatusForbidden).Send(t)

	var list api.TxeDecisionList
	f.client.Get(f.decisionPath()).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &list)
	require.Empty(t, list.Decisions)
	require.False(t, strings.Contains(fmt.Sprint(list), "reviewer-self-approve"))
}

// newTxeDecisionAPI is a registry API whose server allows running DAGs, which
// recording a decision requires.
func newTxeDecisionAPI(t *testing.T) *apiv1.API {
	t.Helper()
	return newTxeDecisionAPIWithAuth(t, config.AuthModeBuiltin)
}

func newTxeDecisionAPIWithAuth(t *testing.T, mode config.AuthMode) *apiv1.API {
	t.Helper()
	dir := t.TempDir()
	repo := persis.NewDAGRepository(dag.NewStore(filepath.Join(dir, "dags")), persis.DAGRepositoryOptions{})
	store, err := registry.NewFileStore(filepath.Join(dir, "data"), registry.WithDAGStore(registry.NewDAGStore(repo)))
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Server.Auth.Mode = mode
	cfg.Server.Permissions = map[config.Permission]bool{config.PermissionWriteDAGs: true, config.PermissionRunDAGs: true}
	return apiv1.New(repo, nil, nil, nil, runtime.Manager{}, cfg, nil, nil, prometheus.NewRegistry(), nil,
		apiv1.WithTxeRegistry(store), apiv1.WithAuthService(struct{ apiv1.AuthService }{}))
}

// fileTxeProposal files a proposal without a native task on jobID as a
// reviewer would, and returns it.
func fileTxeProposal(t *testing.T, f *txeFixture, ctx context.Context, jobID string) api.TxeProposal {
	t.Helper()
	reviewer := &api.TxeActor{Kind: api.TxeActorKindReviewer, Id: "cc5-test"}
	claimResp, err := f.a.AcquireTxeClaim(ctx, api.AcquireTxeClaimRequestObject{JobId: jobID, Body: &api.TxeClaimRequest{
		Kind: api.TxeClaimKindReview, Reviewer: api.TxeReviewer{MachineId: &f.machine}, TtlSec: 600, Actor: reviewer}})
	require.NoError(t, err)
	claim := claimResp.(api.AcquireTxeClaim200JSONResponse)
	question := "Resize?"
	resp, err := f.a.CreateTxeProposal(ctx, api.CreateTxeProposalRequestObject{JobId: jobID, Body: &api.TxeProposalRequest{
		ClaimId: claim.ClaimId, Fence: claim.Fence, Actor: reviewer,
		Proposal: api.TxeProposalInput{ProposalId: mint(t, registry.PrefixProposal), Question: &question,
			Action: api.TxeActionSpec{Name: "resize"}},
	}})
	require.NoError(t, err)
	return api.TxeProposal(resp.(api.CreateTxeProposal200JSONResponse))
}

func decideTxe(ctx context.Context, f *txeFixture, jobID string, p api.TxeProposal, verdict api.TxeVerdict, key string, actor *api.TxeActor) error {
	_, err := f.a.DecideTxeProposal(ctx, api.DecideTxeProposalRequestObject{JobId: jobID, ProposalId: p.ProposalId, Body: &api.TxeDecisionRequest{
		ExpectedProposalRevision: p.Revision, BindingDigest: p.BindingDigest, Verdict: verdict, IdempotencyKey: key, Actor: actor}})
	return err
}

// An API key is not a person: it cannot record a human decision whatever
// actor it claims, including none.
func TestTxeDecisionRefusesAPIKey(t *testing.T) {
	a := newTxeDecisionAPI(t)
	f := newTxeFixture(t, a, txeAdmin)
	jobID, err := f.register(txeAdmin, "")
	require.NoError(t, err)
	require.NoError(t, f.ready(txeAdmin, jobID))
	p := fileTxeProposal(t, f, txeAdmin, jobID)

	key := &auth.APIKey{ID: "k1", Name: "reviewer", Role: auth.RoleDeveloper}
	keyCtx := auth.WithAPIKey(auth.WithUser(context.Background(), &auth.User{ID: "apikey:k1", Username: "apikey:reviewer", Role: auth.RoleDeveloper}), key)
	for i, actor := range []*api.TxeActor{nil, {Kind: api.TxeActorKindHuman, Id: "admin"}, {Kind: api.TxeActorKindCli, Id: "cli"}} {
		requireStatus(t, decideTxe(keyCtx, f, jobID, p, api.TxeVerdictApprove, fmt.Sprintf("apikey-key-%d", i), actor), http.StatusForbidden)
	}
	require.NoError(t, decideTxe(txeAdmin, f, jobID, p, api.TxeVerdictApprove, "admin-approve-1", nil))
}

// Deciding needs execute access to the job's workspace; pausing or retiring
// the job through a decision needs write access there.
func TestTxeDecisionChecksWorkspace(t *testing.T) {
	a := newTxeDecisionAPI(t)
	f := newTxeFixture(t, a, txeAdmin)
	secretJob, err := f.register(txeAdmin, "secret")
	require.NoError(t, err)
	require.NoError(t, f.ready(txeAdmin, secretJob))
	opsJob, err := f.register(txeAdmin, "ops")
	require.NoError(t, err)
	require.NoError(t, f.ready(txeAdmin, opsJob))

	secret := fileTxeProposal(t, f, txeAdmin, secretJob)
	// A job in an invisible workspace is not found for both reading and
	// deciding, so neither reveals that it exists.
	requireStatus(t, decideTxe(txeOps, f, secretJob, secret, api.TxeVerdictApprove, "ops-on-secret", nil), http.StatusNotFound)
	_, err = a.ListTxeProposalDecisions(txeOps, api.ListTxeProposalDecisionsRequestObject{JobId: secretJob, ProposalId: secret.ProposalId})
	requireStatus(t, err, http.StatusNotFound)
	_, err = a.ListTxeProposalDecisions(txeAdmin, api.ListTxeProposalDecisionsRequestObject{JobId: secretJob, ProposalId: secret.ProposalId})
	require.NoError(t, err)

	operator := auth.WithUser(context.Background(), &auth.User{Username: "op", Role: auth.RoleOperator, WorkspaceAccess: &auth.WorkspaceAccess{
		Grants: []auth.WorkspaceGrant{{Workspace: "ops", Role: auth.RoleOperator}},
	}})
	ops := fileTxeProposal(t, f, txeAdmin, opsJob)
	requireStatus(t, decideTxe(operator, f, opsJob, ops, api.TxeVerdictRetire, "operator-retire", nil), http.StatusForbidden)
	require.NoError(t, decideTxe(operator, f, opsJob, ops, api.TxeVerdictApprove, "operator-approve", nil))
}

// registerTxeJobHTTP registers a ready job over HTTP and returns its ID.
func registerTxeJobHTTP(t *testing.T, c txeHTTPClient) string {
	t.Helper()
	cli := map[string]any{"kind": "cli", "id": "cc4-test"}
	owner, machine := mint(t, registry.PrefixOwner), mint(t, registry.PrefixMachine)
	c.Post("/api/v1/txe/owners", map[string]any{"owner_id": owner, "display_name": "Connor", "actor": cli}).
		ExpectStatus(http.StatusCreated).Send(t)
	c.Post("/api/v1/txe/machines", map[string]any{"machine_id": machine, "owner_id": owner, "display_name": "laptop", "actor": cli}).
		ExpectStatus(http.StatusCreated).Send(t)
	var project api.TxeProject
	c.Post("/api/v1/txe/projects", map[string]any{"owner_id": owner, "key": "github.com/txehq/fixture", "actor": cli}).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &project)
	jobID := mint(t, registry.PrefixJob)
	digest := fmt.Sprintf("sha256:%064x", 1)
	c.Post("/api/v1/txe/jobs", map[string]any{
		"job_id": jobID, "request_id": "r1", "owner_id": owner, "project_id": project.ProjectId,
		"machine_id": machine, "job_key": "volume-monitor", "actor": cli,
		"version": map[string]any{
			"title": "Volume monitor", "purpose": "Watch the fixture volume",
			"package": map[string]any{"digest": digest, "path": "/pkg", "entrypoint": "run.sh"},
			"dag":     map[string]any{"spec": fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", machine)},
		},
	}).ExpectStatus(http.StatusCreated).Send(t)
	c.Post("/api/v1/txe/jobs/"+jobID+"/ready", map[string]any{
		"package": map[string]any{"digest": digest, "path": "/pkg", "machine_id": machine}, "actor": cli,
	}).ExpectStatus(http.StatusOK).Send(t)
	return jobID
}

// seedFailedTxeRun writes a failed attempt of the job's saved DAG, as a run
// that already happened on the worker.
func seedFailedTxeRun(t *testing.T, server test.Server, jobID, runID string, opts ...ir.StatusOption) {
	t.Helper()
	ctx := t.Context()
	dag, err := server.DAGRepository.GetDetails(ctx, jobID, persis.DAGLoadOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, dag.YamlData)
	// Run times have whole-second precision; start after the second the
	// job's version was created so the run is unambiguously of it.
	started := time.Now().Add(2 * time.Second)
	attempt, err := server.DAGRunRepository.CreateAttempt(ctx, dag, started, runID, persis.DAGRunCreateAttemptOptions{})
	require.NoError(t, err)
	opts = append([]ir.StatusOption{ir.WithAttemptID(attempt.ID()), ir.WithFinishedAt(started.Add(time.Second)), ir.WithError("probe failed")}, opts...)
	status := ir.NewStatusBuilder(dag).Create(runID, ir.Failed, 0, started, opts...)
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, status))
	require.NoError(t, attempt.Close(ctx))
}

// txeExecution reads the run's latest execution as the dashboard shows it.
func txeExecution(t *testing.T, c txeHTTPClient, jobID, runID string) (attemptID, queuedAt string) {
	t.Helper()
	var details api.GetDAGRunDetails200JSONResponse
	c.Get(fmt.Sprintf("/api/v1/dag-runs/%s/%s", jobID, runID)).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &details)
	require.NotNil(t, details.DagRunDetails.AttemptId)
	require.NotNil(t, details.DagRunDetails.ExecutionRef)
	if q := details.DagRunDetails.QueuedAt; q != nil {
		queuedAt = *q
	}
	require.Equal(t, registry.ExecutionRef(*details.DagRunDetails.AttemptId, queuedAt), *details.DagRunDetails.ExecutionRef)
	return *details.DagRunDetails.AttemptId, queuedAt
}

// retryBody is a retry request naming the execution the person reviewed.
func retryBody(key string, version int, attemptID, queuedAt string) map[string]any {
	return map[string]any{"idempotency_key": key, "expected_job_version": version, "attempt_id": attemptID, "queued_at": queuedAt}
}

// Retrying one exact failed run records a decided dagu.retry_run proposal
// bound to that run; it is idempotent and refuses a stale snapshot or a run
// that is not the job's.
func TestTxeRunRetryRequest(t *testing.T) {
	server := builtinServer(t)
	c := txeAuthedClient{c: server.Client(), token: loginAndGetToken(t, server, "admin", "adminpass")}
	jobID := registerTxeJobHTTP(t, c)
	seedFailedTxeRun(t, server, jobID, "run-failed-1")
	seen, queued := txeExecution(t, c, jobID, "run-failed-1")

	var job api.TxeJob
	c.Get("/api/v1/txe/jobs/"+jobID).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &job)
	path := fmt.Sprintf("/api/v1/txe/jobs/%s/runs/%s/retry-requests", jobID, "run-failed-1")
	body := retryBody("dashboard-retry-1", job.Version, seen, queued)

	// A request that does not name the reviewed execution completely is
	// refused before anything is looked up or recorded.
	for name, b := range map[string]map[string]any{
		"no attempt":    {"idempotency_key": "dashboard-retry-1", "expected_job_version": job.Version, "queued_at": queued},
		"empty attempt": retryBody("dashboard-retry-1", job.Version, "", queued),
		"no queued_at":  {"idempotency_key": "dashboard-retry-1", "expected_job_version": job.Version, "attempt_id": seen},
	} {
		var apiErr api.Error
		c.Post(path, b).ExpectStatus(http.StatusBadRequest).Send(t).Unmarshal(t, &apiErr)
		require.NotNil(t, apiErr.Details, name)
		require.Equal(t, "missing_execution", (*apiErr.Details)["code"], name)
	}
	var none api.TxeDecisionList
	c.Get("/api/v1/txe/jobs/"+jobID+"/decisions").ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &none)
	require.Empty(t, none.Decisions)

	var first api.TxeDecisionResponse
	c.Post(path, body).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &first)
	require.False(t, first.Replayed)
	require.Equal(t, api.TxeVerdict("retry"), first.Decision.Verdict)
	require.NotNil(t, first.Proposal)
	require.Equal(t, api.TxeProposalState("decided"), first.Proposal.State)
	require.Equal(t, decision.ActionRetryRun, first.Proposal.Action.Name)
	require.Contains(t, string(first.Proposal.Action.Params), `"run_id":"run-failed-1"`)
	require.Contains(t, string(first.Proposal.Action.Params), `"attempt_id":"`+seen+`"`)

	var again api.TxeDecisionResponse
	c.Post(path, body).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &again)
	require.True(t, again.Replayed)
	require.Equal(t, first.Decision.DecisionId, again.Decision.DecisionId)

	// Once the run has a newer successful attempt it is no longer
	// retryable, but an identical replay still returns its decision.
	ctx := t.Context()
	dag, err := server.DAGRepository.GetDetails(ctx, jobID, persis.DAGLoadOptions{})
	require.NoError(t, err)
	retried, err := server.DAGRunRepository.CreateAttempt(ctx, dag, time.Now().Add(3*time.Second), "run-failed-1", persis.DAGRunCreateAttemptOptions{Retry: true})
	require.NoError(t, err)
	require.NoError(t, retried.Open(ctx))
	require.NoError(t, retried.Write(ctx, ir.NewStatusBuilder(dag).Create("run-failed-1", ir.Succeeded, 0, time.Now(), ir.WithAttemptID(retried.ID()))))
	require.NoError(t, retried.Close(ctx))
	var late api.TxeDecisionResponse
	c.Post(path, body).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &late)
	require.True(t, late.Replayed)
	require.Equal(t, first.Decision.DecisionId, late.Decision.DecisionId)

	// The key binds the whole request: reusing it for another execution is
	// refused, not answered with the stored decision.
	var mismatch api.Error
	c.Post(path, retryBody("dashboard-retry-1", job.Version, seen, "2026-10-09T12:00:00Z")).
		ExpectStatus(http.StatusConflict).Send(t).Unmarshal(t, &mismatch)
	require.NotNil(t, mismatch.Details)
	require.Equal(t, string(decision.CodeIdempotencyMismatch), (*mismatch.Details)["code"])

	stale := retryBody("dashboard-retry-2", job.Version, seen, queued)
	stale["run_spec_sha256"] = fmt.Sprintf("sha256:%064x", 9)
	c.Post(path, stale).ExpectStatus(http.StatusConflict).Send(t)

	c.Post(fmt.Sprintf("/api/v1/txe/jobs/%s/runs/%s/retry-requests", jobID, "no-such-run"),
		retryBody("dashboard-retry-3", job.Version, seen, queued)).
		ExpectStatus(http.StatusNotFound).Send(t)
}

// seedRetriedTxeAttempt adds a newer attempt with status to a run, as a
// native retry does, and returns its attempt ID.
func seedRetriedTxeAttempt(t *testing.T, server test.Server, jobID, runID string, status ir.Status) string {
	t.Helper()
	ctx := t.Context()
	dag, err := server.DAGRepository.GetDetails(ctx, jobID, persis.DAGLoadOptions{})
	require.NoError(t, err)
	started := time.Now().Add(3 * time.Second)
	attempt, err := server.DAGRunRepository.CreateAttempt(ctx, dag, started, runID, persis.DAGRunCreateAttemptOptions{Retry: true})
	require.NoError(t, err)
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, ir.NewStatusBuilder(dag).Create(runID, status, 0, started,
		ir.WithAttemptID(attempt.ID()), ir.WithFinishedAt(started.Add(time.Second)))))
	require.NoError(t, attempt.Close(ctx))
	return attempt.ID()
}

// The person decides on the attempt they saw. If the run has moved on to
// another failed attempt before the click arrives, the click is refused and
// records nothing; a request for the new attempt is a decision of its own.
func TestTxeRunRetryRefusesMovedAttempt(t *testing.T) {
	server := builtinServer(t)
	c := txeAuthedClient{c: server.Client(), token: loginAndGetToken(t, server, "admin", "adminpass")}
	jobID := registerTxeJobHTTP(t, c)
	seedFailedTxeRun(t, server, jobID, "run-moved-1")
	seen, queued := txeExecution(t, c, jobID, "run-moved-1")

	next := seedRetriedTxeAttempt(t, server, jobID, "run-moved-1", ir.Failed)
	require.NotEqual(t, seen, next)
	_, nextQueued := txeExecution(t, c, jobID, "run-moved-1")

	var job api.TxeJob
	c.Get("/api/v1/txe/jobs/"+jobID).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &job)
	path := fmt.Sprintf("/api/v1/txe/jobs/%s/runs/%s/retry-requests", jobID, "run-moved-1")
	var apiErr api.Error
	c.Post(path, retryBody("dashboard-moved-1", job.Version, seen, queued)).
		ExpectStatus(http.StatusConflict).Send(t).Unmarshal(t, &apiErr)
	require.NotNil(t, apiErr.Details)
	require.Equal(t, string(decision.CodeRunStale), (*apiErr.Details)["code"])
	var decisions api.TxeDecisionList
	c.Get("/api/v1/txe/jobs/"+jobID+"/decisions").ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &decisions)
	require.Empty(t, decisions.Decisions)

	var res api.TxeDecisionResponse
	c.Post(path, retryBody("dashboard-moved-2", job.Version, next, nextQueued)).
		ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &res)
	require.NotNil(t, res.Proposal)
	require.Contains(t, string(res.Proposal.Action.Params), `"attempt_id":"`+next+`"`)
}

// Dagu's queued retry keeps the attempt and records a later queue marker in
// place. A request naming the earlier marker, or none, reviewed another
// execution and is refused; one naming the re-queued execution binds it.
func TestTxeRunRetryRefusesRequeuedExecution(t *testing.T) {
	server := builtinServer(t)
	c := txeAuthedClient{c: server.Client(), token: loginAndGetToken(t, server, "admin", "adminpass")}
	jobID := registerTxeJobHTTP(t, c)
	const q1, q2 = "2026-10-09T12:00:00.000000001Z", "2026-10-09T12:00:05.000000001Z"
	seedFailedTxeRun(t, server, jobID, "run-queued-1", ir.WithQueuedAt(q1))
	seen, queued := txeExecution(t, c, jobID, "run-queued-1")
	require.Equal(t, q1, queued)

	ctx := t.Context()
	attempt, err := server.DAGRunRepository.FindAttempt(ctx, ir.NewDAGRunRef(jobID, "run-queued-1"))
	require.NoError(t, err)
	status, err := attempt.ReadStatus(ctx)
	require.NoError(t, err)
	status.QueuedAt = q2
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, *status))
	require.NoError(t, attempt.Close(ctx))
	again, requeued := txeExecution(t, c, jobID, "run-queued-1")
	require.Equal(t, seen, again)
	require.Equal(t, q2, requeued)

	var job api.TxeJob
	c.Get("/api/v1/txe/jobs/"+jobID).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &job)
	path := fmt.Sprintf("/api/v1/txe/jobs/%s/runs/%s/retry-requests", jobID, "run-queued-1")
	for key, q := range map[string]string{"dashboard-queued-1": q1, "dashboard-queued-2": ""} {
		var apiErr api.Error
		c.Post(path, retryBody(key, job.Version, seen, q)).ExpectStatus(http.StatusConflict).Send(t).Unmarshal(t, &apiErr)
		require.NotNil(t, apiErr.Details, key)
		require.Equal(t, string(decision.CodeRunStale), (*apiErr.Details)["code"], key)
	}
	var decisions api.TxeDecisionList
	c.Get("/api/v1/txe/jobs/"+jobID+"/decisions").ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &decisions)
	require.Empty(t, decisions.Decisions)

	var res api.TxeDecisionResponse
	c.Post(path, retryBody("dashboard-queued-3", job.Version, seen, q2)).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &res)
	require.NotNil(t, res.Proposal)
	require.Contains(t, string(res.Proposal.Action.Params), `"queued_at":"`+q2+`"`)
}

// A decision is recorded only for an individually signed-in person. On a hub
// with no authentication, or with basic auth's one shared credential, a
// request cannot show it comes from a person rather than a reviewer or a job
// script holding the hub context, so it is refused and nothing is recorded.
func TestTxeDecisionNeedsAPersonAuthMode(t *testing.T) {
	for _, mode := range []config.AuthMode{config.AuthModeNone, config.AuthModeBasic, ""} {
		t.Run(string(mode), func(t *testing.T) {
			a := newTxeDecisionAPIWithAuth(t, mode)
			f := newTxeFixture(t, a, txeAdmin)
			jobID, err := f.register(txeAdmin, "")
			require.NoError(t, err)
			require.NoError(t, f.ready(txeAdmin, jobID))
			p := fileTxeProposal(t, f, txeAdmin, jobID)
			err = decideTxe(txeAdmin, f, jobID, p, api.TxeVerdictApprove, "shared-credential-1", nil)
			requireStatus(t, err, http.StatusForbidden)
			var apiErr *apiv1.Error
			require.ErrorAs(t, err, &apiErr)
			require.Equal(t, "person_auth_required", apiErr.Details["code"])
			list, err := a.ListTxeProposalDecisions(txeAdmin, api.ListTxeProposalDecisionsRequestObject{JobId: jobID, ProposalId: p.ProposalId})
			require.NoError(t, err)
			require.Empty(t, list.(api.ListTxeProposalDecisions200JSONResponse).Decisions)
		})
	}
}

// The person is the signed-in user, whatever identity the body claims.
func TestTxeDecisionActorIsTheSignedInUser(t *testing.T) {
	a := newTxeDecisionAPI(t)
	f := newTxeFixture(t, a, txeAdmin)
	jobID, err := f.register(txeAdmin, "")
	require.NoError(t, err)
	require.NoError(t, f.ready(txeAdmin, jobID))
	p := fileTxeProposal(t, f, txeAdmin, jobID)
	require.NoError(t, decideTxe(txeAdmin, f, jobID, p, api.TxeVerdictApprove, "claims-another-1",
		&api.TxeActor{Kind: api.TxeActorKindHuman, Id: "someone-else"}))
	list, err := a.ListTxeProposalDecisions(txeAdmin, api.ListTxeProposalDecisionsRequestObject{JobId: jobID, ProposalId: p.ProposalId})
	require.NoError(t, err)
	decisions := list.(api.ListTxeProposalDecisions200JSONResponse).Decisions
	require.Len(t, decisions, 1)
	user, _ := auth.UserFromContext(txeAdmin)
	require.Equal(t, user.Username, decisions[0].Actor.Id)
	// No signed-in user at all is refused.
	requireStatus(t, decideTxe(context.Background(), f, jobID, p, api.TxeVerdictApprove, "nobody-1", nil), http.StatusForbidden)
}

// Reproduces the reported attack on the real routes. On a hub with no
// authentication, or with basic auth where one shared credential is held by
// the person and the reviewer alike, the reviewer files a proposal and then
// approves it while claiming to be a person. The approval is refused, no
// decision is recorded, and the job's native human task keeps waiting.
func TestTxeDecisionSelfApprovalOutsideBuiltinAuth(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T) (test.Server, txeHTTPClient){
		"none": func(t *testing.T) (test.Server, txeHTTPClient) {
			server := test.SetupServer(t, test.WithConfigMutator(func(cfg *config.Config) { cfg.Server.Auth.Mode = config.AuthModeNone }))
			return server, txeNoAuthClient{c: server.Client()}
		},
		"basic": func(t *testing.T) (test.Server, txeHTTPClient) {
			server := test.SetupServer(t, test.WithConfigMutator(func(cfg *config.Config) {
				cfg.Server.Auth.Mode = config.AuthModeBasic
				cfg.Server.Auth.Basic.Username, cfg.Server.Auth.Basic.Password = "shared", "secret"
			}))
			return server, txeBasicClient{c: server.Client(), user: "shared", pass: "secret"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			server, c := setup(t)
			f := newTxeDecisionFixtureOn(t, server, c)
			body := f.body("approve", "self-approve-"+name)
			body["actor"] = map[string]any{"kind": "human", "id": "connor"}
			var apiErr api.Error
			c.Post(f.decisionPath(), body).ExpectStatus(http.StatusForbidden).Send(t).Unmarshal(t, &apiErr)
			require.NotNil(t, apiErr.Details)
			require.Equal(t, "person_auth_required", (*apiErr.Details)["code"])
			var list api.TxeDecisionList
			c.Get(f.decisionPath()).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &list)
			require.Empty(t, list.Decisions)
			status := waitForStoredDAGRunStatus(t, server, f.decide, f.runID, 5*time.Second, func(s *ir.DAGRunStatus) bool {
				return s.Status == ir.Waiting
			})
			require.True(t, hasNodeWithStatus(status, "decide", ir.NodeWaiting))
		})
	}
}

// A retry request is a person's decision too: on a hub that cannot tell a
// person from a reviewer, it is refused before anything is recorded.
func TestTxeRunRetryNeedsAPerson(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T) (test.Server, txeHTTPClient){
		"none": func(t *testing.T) (test.Server, txeHTTPClient) {
			server := test.SetupServer(t, test.WithConfigMutator(func(cfg *config.Config) { cfg.Server.Auth.Mode = config.AuthModeNone }))
			return server, txeNoAuthClient{c: server.Client()}
		},
		"basic": func(t *testing.T) (test.Server, txeHTTPClient) {
			server := test.SetupServer(t, test.WithConfigMutator(func(cfg *config.Config) {
				cfg.Server.Auth.Mode = config.AuthModeBasic
				cfg.Server.Auth.Basic.Username, cfg.Server.Auth.Basic.Password = "shared", "secret"
			}))
			return server, txeBasicClient{c: server.Client(), user: "shared", pass: "secret"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			server, c := setup(t)
			jobID := registerTxeJobHTTP(t, c)
			seedFailedTxeRun(t, server, jobID, "run-shared-1")
			seen, queued := txeExecution(t, c, jobID, "run-shared-1")
			var job api.TxeJob
			c.Get("/api/v1/txe/jobs/"+jobID).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &job)
			body := retryBody("shared-retry-"+name, job.Version, seen, queued)
			body["actor"] = map[string]any{"kind": "human", "id": "connor"}
			var apiErr api.Error
			c.Post(fmt.Sprintf("/api/v1/txe/jobs/%s/runs/%s/retry-requests", jobID, "run-shared-1"), body).
				ExpectStatus(http.StatusForbidden).Send(t).Unmarshal(t, &apiErr)
			require.NotNil(t, apiErr.Details)
			require.Equal(t, "person_auth_required", (*apiErr.Details)["code"])
			var proposals api.TxeProposalList
			c.Get("/api/v1/txe/jobs/"+jobID+"/proposals").ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &proposals)
			require.Empty(t, proposals.Open)
			require.Empty(t, proposals.Finished)
		})
	}
}
