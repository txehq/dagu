// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/runcontrol"
)

// genericRetry is a registered job's failed run, on a hub that dispatches
// to a recording coordinator, with the person's decision to retry it.
type genericRetry struct {
	w         *twoOwners
	recorder  *retryCoordinatorRecorder
	run       string
	attemptID string
	queuedAt  string
}

func newGenericRetry(t *testing.T) *genericRetry {
	t.Helper()
	w := newTwoOwners(t, "")
	w.markReady(w.jobA, w.machineA)
	w.addRun(w.jobA, "run-1", "production")
	recorder := &retryCoordinatorRecorder{}
	w.api.coordinatorCli = recorder
	w.api.defaultExecMode = config.ExecutionModeDistributed
	// The registry reads the run's history from the hub's run store, as the
	// server wires it, so a person's retry decision binds the run.
	reg, err := registry.NewFileStore(w.dataDir, registry.WithDAGStore(registry.NewDAGStore(w.api.dagRepository)),
		registry.WithRunControl(&runcontrol.Control{DAGs: w.api.dagRepository, Runs: w.runs, Manager: &w.api.dagRunMgr, ExecMode: config.ExecutionModeDistributed}))
	require.NoError(t, err)
	w.reg, w.api.txeRegistry = reg, reg
	// The run is of the job's current definition, which the registry admits.
	jobSpec, err := w.api.dagRepository.GetSpec(context.Background(), w.jobA)
	require.NoError(t, err)
	g := &genericRetry{w: w, recorder: recorder, run: "run-3", queuedAt: "q3"}
	w.writeRun(&ir.DAG{Name: w.jobA, YamlData: []byte(jobSpec)}, g.run, persis.DAGRunCreateAttemptOptions{}, func(s *ir.DAGRunStatus) {
		s.Status, s.QueuedAt = ir.Failed, g.queuedAt
		// Started after the job's version was created, to the second.
		s.StartedAt, s.FinishedAt = time.Now().Add(2*time.Second).Format(time.RFC3339), time.Now().Add(3*time.Second).Format(time.RFC3339)
		s.Nodes = []*ir.Node{{Step: ir.Step{Name: "run"}, Status: ir.NodeFailed}}
		g.attemptID = s.AttemptID
	})
	return g
}

func (g *genericRetry) retry(ctx context.Context, body *apigen.RetryDAGRunJSONRequestBody) error {
	_, err := g.w.api.RetryDAGRun(ctx, apigen.RetryDAGRunRequestObject{Name: g.w.jobA, DagRunId: g.run, Body: body})
	return err
}

// conditional is the body the machine's reviewer sends for an action
// attempt: the expected execution and the action's retry request.
func (g *genericRetry) conditional(actionID, attempt, binding string) *apigen.RetryDAGRunJSONRequestBody {
	return &apigen.RetryDAGRunJSONRequestBody{DagRunId: g.run, ExpectedAttemptId: &g.attemptID, ExpectedQueuedAt: &g.queuedAt,
		RetryRequest: &apigen.RetryRequestSpec{ActionId: actionID, ActionAttempt: attempt, BindingDigest: binding}}
}

// decideAndGrant records A's person's decision to retry the run, through
// the TXE decision endpoint, and the machine's execution of it: an approved
// dagu.retry_run executing its first attempt under a live grant.
func (g *genericRetry) decideAndGrant(t *testing.T) (*registry.Action, *registry.Claim, *registry.Grant) {
	t.Helper()
	return g.decideAndGrantMode(t, nil)
}

// decideAndGrantMode is decideAndGrant for a person's request with mode
// (nil: a retry naming no intent).
func (g *genericRetry) decideAndGrantMode(t *testing.T, mode *apigen.TxeRetryRequestMode) (*registry.Action, *registry.Claim, *registry.Grant) {
	t.Helper()
	w := g.w
	ctx := context.Background()
	_, err := w.api.RequestTxeRunRetry(w.personA, apigen.RequestTxeRunRetryRequestObject{JobId: w.jobA, RunId: g.run,
		Body: &apigen.RequestTxeRunRetryJSONRequestBody{AttemptId: &g.attemptID, QueuedAt: &g.queuedAt, ExpectedJobVersion: 1,
			IdempotencyKey: "retry-key-1", Mode: mode}})
	require.NoError(t, err)
	job, err := w.reg.GetJob(ctx, w.jobA)
	require.NoError(t, err)
	var p *registry.Proposal
	for _, x := range job.Proposals {
		if x.State == registry.ProposalDecided && x.Action.Name == registry.ActionRetryRun {
			p = x
		}
	}
	require.NotNil(t, p, "the person's retry was not recorded as a decided proposal")
	reviewer := registry.Actor{Kind: registry.ActorReviewer, ID: "reviewer-a"}
	var claim *registry.Claim
	var grant *registry.Grant
	actionID, err := registry.ApprovedActionID(p.ProposalID, p.Decision.DecisionID)
	require.NoError(t, err)
	_, err = w.reg.WithJobTx(ctx, w.jobA, reviewer, func(tx *registry.JobTx) error {
		var err error
		if claim, err = tx.AcquireClaim(registry.ClaimExecution, registry.Reviewer{MachineID: w.machineA}, time.Hour); err != nil {
			return err
		}
		grant, err = tx.Authorize(registry.EffectRequest{ActionID: actionID, JobVersion: job.Version, PackageDigest: job.PackageDigest,
			Approved: &registry.ApprovedEffect{ProposalID: p.ProposalID, DecisionID: p.Decision.DecisionID, ClaimID: claim.ClaimID, Fence: claim.Fence}})
		return err
	})
	require.NoError(t, err)
	job, err = w.reg.GetJob(ctx, w.jobA)
	require.NoError(t, err)
	action := job.Actions[actionID]
	require.NotNil(t, action)
	require.Equal(t, registry.ActionExecuting, action.State)
	return action, claim, grant
}

// TXE-7517: a direct generic retry of a registered job's run is refused
// before anything is dispatched, whoever asks and whatever it retries, and
// the refusal names the TXE decision controls.
func TestTxeGenericRetryOfAJobsRunNeedsADecision(t *testing.T) {
	g := newGenericRetry(t)
	w := g.w
	step, downstream := "run", true
	for name, c := range map[string]struct {
		ctx  context.Context
		body *apigen.RetryDAGRunJSONRequestBody
	}{
		"the owner's person, the whole run": {w.personA, nil},
		"an administrator's key":            {w.legacy, nil},
		"the owner's CLI":                   {w.cliA, &apigen.RetryDAGRunJSONRequestBody{DagRunId: g.run}},
		"a step of the run":                 {w.personA, &apigen.RetryDAGRunJSONRequestBody{DagRunId: g.run, StepName: &step}},
		"the job step with what follows": {w.personA, &apigen.RetryDAGRunJSONRequestBody{DagRunId: g.run, StepName: &step,
			IncludeDownstream: &downstream}},
		"conditional, made for no action": {w.personA, &apigen.RetryDAGRunJSONRequestBody{DagRunId: g.run,
			ExpectedAttemptId: &g.attemptID, ExpectedQueuedAt: &g.queuedAt}},
	} {
		err := g.retry(c.ctx, c.body)
		require.Equal(t, http.StatusConflict, statusOf(err), "%s: %v", name, err)
		require.Equal(t, txeDecisionRequired, detailOf(err), name)
		assert.Contains(t, err.Error(), "/txe/jobs/"+w.jobA, name)
		assert.Contains(t, err.Error(), "Run again", name)
	}
	assert.Empty(t, g.recorder.dispatched, "a direct retry of a job's run was dispatched")
}

// The machine's carrying out of a person's decision to retry the run is
// admitted once, for the action's current attempt; a request that does not
// bind it is refused before anything is dispatched.
func TestTxeGenericRetryCarriesOutOnlyTheBoundDecision(t *testing.T) {
	g := newGenericRetry(t)
	w := g.w
	action, claim, grant := g.decideAndGrant(t)
	attempt := strconv.Itoa(action.Attempt)

	step := "run"
	stepped := g.conditional(action.ActionID, attempt, action.BindingDigest)
	stepped.StepName = &step
	// The person's decision names no intent: it is carried out only as a
	// retry of the whole run, not from the job's step.
	downstream := true
	fromJobStep := g.conditional(action.ActionID, attempt, action.BindingDigest)
	fromJobStep.StepName, fromJobStep.IncludeDownstream = &step, &downstream
	otherExecution := g.conditional(action.ActionID, attempt, action.BindingDigest)
	other := "ffffff"
	otherExecution.ExpectedAttemptId = &other
	for name, body := range map[string]*apigen.RetryDAGRunJSONRequestBody{
		"a forged action":           g.conditional("act_forged", attempt, action.BindingDigest),
		"another attempt":           g.conditional(action.ActionID, "2", action.BindingDigest),
		"another binding":           g.conditional(action.ActionID, attempt, "sha256:forged"),
		"a step of the run":         stepped,
		"from the job step":         fromJobStep,
		"the approval as republish": republishBody(g.conditional(action.ActionID, attempt, action.BindingDigest)),
	} {
		err := g.retry(w.reviewerA, body)
		require.Error(t, err, name)
		assert.Equal(t, txeRepublishUnsupported, detailOf(err), "%s: %v", name, err)
	}
	// Another execution is refused as one that changed, before the binding.
	require.Equal(t, "execution_changed", detailOf(g.retry(w.reviewerA, otherExecution)))
	require.Empty(t, g.recorder.dispatched, "a request that does not bind the decision was dispatched")

	// The legacy retry, a decision naming no intent carried out with no
	// step, is admitted and dispatched exactly as before TXE-7517: a retry of
	// the whole run, no step, nothing downstream, no failure accepted.
	require.NoError(t, g.retry(w.reviewerA, g.conditional(action.ActionID, attempt, action.BindingDigest)))
	require.Len(t, g.recorder.dispatched, 1, "the bound decision was not carried out")
	task := g.recorder.dispatched[0]
	assert.Equal(t, dispatch.DispatchOperationRetry, task.Operation)
	assert.Empty(t, task.Step, "a retry naming no intent was given a step")
	assert.False(t, task.IncludeDownstream)
	assert.False(t, task.AcceptFailedPrerequisites)
	assert.True(t, task.RequireLatestIsPrevious, "the retry is conditional on the decided execution")

	// Once the action is settled, the same request is a replay: refused.
	_, err := w.reg.WithJobTx(context.Background(), w.jobA, registry.Actor{Kind: registry.ActorReviewer, ID: "reviewer-a"}, func(tx *registry.JobTx) error {
		_, err := tx.SettleAction(registry.Settlement{ActionID: action.ActionID, GrantID: grant.GrantID, ClaimID: claim.ClaimID, Fence: claim.Fence,
			State: registry.ActionNotApplied, Receipt: "test"})
		return err
	})
	require.NoError(t, err)
	err = g.retry(w.reviewerA, g.conditional(action.ActionID, attempt, action.BindingDigest))
	require.Equal(t, txeRepublishUnsupported, detailOf(err), "%v", err)
	require.Equal(t, txeRetryUnbound, refusalReason(err), "%v", err)
	require.Len(t, g.recorder.dispatched, 1, "a replayed request was dispatched")
}

// A person's explicit rerun (TXE-7515 mode rerun) is carried out only from
// the job's step with everything after it, so the job runs again even when
// its step had succeeded. Sent with no step, as an older machine that
// ignores rerun sends it, it is refused before anything is dispatched: Dagu
// would keep that step and only publish the old seal (TXE-7517).
func TestTxeGenericRetryCarriesOutARerunOnlyFromTheJobStep(t *testing.T) {
	g := newGenericRetry(t)
	w := g.w
	rerun := apigen.TxeRetryRequestModeRerun
	action, _, _ := g.decideAndGrantMode(t, &rerun)
	var params registry.RetryRunParams
	require.NoError(t, json.Unmarshal(action.Spec.Params, &params))
	require.Equal(t, registry.RetryStepRun, params.Step, "the person's rerun was not recorded as one")
	require.NotContains(t, string(action.Spec.Params), `"rerun"`)
	attempt := strconv.Itoa(action.Attempt)

	err := g.retry(w.reviewerA, g.conditional(action.ActionID, attempt, action.BindingDigest))
	require.Equal(t, http.StatusBadRequest, statusOf(err), "%v", err)
	require.Equal(t, txeRepublishUnsupported, detailOf(err), "an older reviewer reads it as nothing started")
	require.Equal(t, txeRetryUnbound, refusalReason(err))
	assert.Contains(t, err.Error(), `stepName "run", includeDownstream`)
	require.Empty(t, g.recorder.dispatched, "a rerun sent with no step was dispatched")

	step, downstream := "run", true
	alone := g.conditional(action.ActionID, attempt, action.BindingDigest)
	alone.StepName = &step
	require.Equal(t, txeRetryUnbound, refusalReason(g.retry(w.reviewerA, alone)), "the job step without what follows it")
	require.Empty(t, g.recorder.dispatched)

	fromJobStep := g.conditional(action.ActionID, attempt, action.BindingDigest)
	fromJobStep.StepName, fromJobStep.IncludeDownstream = &step, &downstream
	require.NoError(t, g.retry(w.reviewerA, fromJobStep))
	require.Len(t, g.recorder.dispatched, 1)
	task := g.recorder.dispatched[0]
	assert.Equal(t, "run", task.Step)
	assert.True(t, task.IncludeDownstream)
	assert.False(t, task.AcceptFailedPrerequisites)
	assert.True(t, task.RequireLatestIsPrevious)
}

func republishBody(b *apigen.RetryDAGRunJSONRequestBody) *apigen.RetryDAGRunJSONRequestBody {
	step, accept := "publish", true
	b.StepName, b.AcceptFailedPrerequisites = &step, &accept
	return b
}

// An edited retry of a registered job's run stays refused: the registry is
// the only writer of a job's DAG.
func TestTxeEditRetryOfAJobsRunIsRefused(t *testing.T) {
	g := newGenericRetry(t)
	w := g.w
	spec, err := w.api.dagRepository.GetSpec(context.Background(), w.jobA)
	require.NoError(t, err)
	for _, ctx := range []context.Context{w.personA, w.legacy} {
		_, err := w.api.EditRetryDAGRun(ctx, apigen.EditRetryDAGRunRequestObject{Name: w.jobA, DagRunId: g.run,
			Body: &apigen.EditRetryDAGRunJSONRequestBody{Spec: spec}})
		require.Error(t, err)
		assert.NotEqual(t, http.StatusOK, statusOf(err))
	}
	assert.Empty(t, g.recorder.dispatched)
}
