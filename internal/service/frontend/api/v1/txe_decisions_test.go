// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/ir"
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
	decide   string
	runID    string
	proposal api.TxeProposal
}

// newTxeDecisionFixture registers a ready job, starts its decide run until
// the human task waits, and files a proposal pointing at that task.
func newTxeDecisionFixture(t *testing.T) *txeDecisionFixture {
	t.Helper()
	server := test.SetupServer(t)
	c := server.Client()
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

	return &txeDecisionFixture{server: server, jobID: jobID, decide: decideDAG, runID: started.DagRunId, proposal: proposal}
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
	c := f.server.Client()

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
	c := f.server.Client()
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
	f.server.Client().Post(f.decisionPath(), body).ExpectStatus(http.StatusForbidden).Send(t)

	var list api.TxeDecisionList
	f.server.Client().Get(f.decisionPath()).ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &list)
	require.Empty(t, list.Decisions)
	require.False(t, strings.Contains(fmt.Sprint(list), "reviewer-self-approve"))
}
