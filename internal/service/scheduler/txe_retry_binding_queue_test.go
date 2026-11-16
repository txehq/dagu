// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package scheduler

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/runcontrol"
)

// testClock is a registry clock a test moves forward.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// approvedRerun is a person's approved dagu.retry_run of a failed run of the
// job, executing under the reviewer's live grant, and the retry request the
// hub derives for it, as the hub's admission records it on the queued
// status.
type approvedRerun struct {
	actionID string
	grant    *registry.Grant
	failed   *ir.DAGRunStatus
	request  *ir.RetryRequest
}

func newRegistryJobWithRuns(t *testing.T, f *queueFixture) (txeQueueJob, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Now().UTC()}
	return newTxeQueueJob(t, registry.WithClock(clock.Now), registry.WithRunControl(&runcontrol.Control{Runs: f.dagRunRepository})), clock
}

func approveRerun(t *testing.T, f *queueFixture, j txeQueueJob, runID string) approvedRerun {
	t.Helper()
	return approveRetry(t, f, j, runID, func(*registry.RetryRunParams) {})
}

// approveRetry is approveRerun for the params form sets: a republish
// (Step publish) or an explicit rerun (Step run).
func approveRetry(t *testing.T, f *queueFixture, j txeQueueJob, runID string, form func(*registry.RetryRunParams)) approvedRerun {
	t.Helper()
	person := registry.Actor{Kind: registry.ActorHuman, ID: "owner"}
	reviewer := registry.Actor{Kind: registry.ActorReviewer, ID: "reviewer"}
	failed := finishedRun(t, f, j.dag, runID, ir.Failed)
	var proposal *registry.Proposal
	var decision *registry.Decision
	_, err := j.store.WithJobTx(f.ctx, j.job.JobID, person, func(tx *registry.JobTx) error {
		var err error
		params := registry.RetryRunParams{
			RunID: runID, AttemptID: failed.AttemptID, QueuedAt: failed.QueuedAt,
			RunSpecSHA256: j.job.DAGSpecSHA256, PackageDigest: j.job.PackageDigest,
		}
		form(&params)
		proposal, decision, err = tx.ProposeRetry(params, "key-"+runID)
		return err
	})
	require.NoError(t, err)
	actionID, err := registry.ApprovedActionID(proposal.ProposalID, decision.DecisionID)
	require.NoError(t, err)
	var grant *registry.Grant
	_, err = j.store.WithJobTx(f.ctx, j.job.JobID, reviewer, func(tx *registry.JobTx) error {
		claim, err := tx.AcquireClaim(registry.ClaimExecution, registry.Reviewer{MachineID: j.machine}, time.Hour)
		if err != nil {
			return err
		}
		grant, err = tx.Authorize(registry.EffectRequest{ActionID: actionID, JobVersion: j.job.Version, PackageDigest: j.job.PackageDigest,
			Approved: &registry.ApprovedEffect{ProposalID: proposal.ProposalID, DecisionID: decision.DecisionID, ClaimID: claim.ClaimID, Fence: claim.Fence}})
		return err
	})
	require.NoError(t, err)
	job, err := j.store.GetJob(f.ctx, j.job.JobID)
	require.NoError(t, err)
	action := job.Actions[actionID]
	require.NotNil(t, action)
	require.Equal(t, registry.ActionExecuting, action.State)
	request, err := ir.NewRetryRequest(failed.DAGRun(), failed.AttemptID, failed.QueuedAt, actionID, strconv.Itoa(action.Attempt), action.BindingDigest)
	require.NoError(t, err)
	return approvedRerun{actionID: actionID, grant: grant, failed: failed, request: request}
}

// A retry a person approved with no intent named (the legacy form, unchanged
// by TXE-7515's explicit forms), queued by the hub with its retry request
// while the grant is live, is dispatched.
func TestQueueDispatch_TxeApprovedRetryIsAdmitted(t *testing.T) {
	f := newQueueFixture(t)
	j, _ := newRegistryJobWithRuns(t, f)
	approved := approveRerun(t, f, j, "run-failed")
	queued := cliEnqueueRetry(t, f, j.dag, approved.failed, approved.request)

	assert.True(t, distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), queuedItem(t, f, j.dag), queued.AttemptID, queued, j.dag))
}

// The grant is read when the queue dispatches, not when the retry was
// queued: a grant that expired while the retry waited refuses it. The run is
// aborted with the reason and the retried execution kept; the refusal is
// recorded on the job, in a commit that also turns the action whose grant
// lapsed uncertain, so it is not left approved and executing and a person
// is asked what to do with it.
func TestQueueDispatch_TxeExpiredGrantIsRefusedAndReconciled(t *testing.T) {
	f := newQueueFixture(t)
	j, clock := newRegistryJobWithRuns(t, f)
	approved := approveRerun(t, f, j, "run-failed")
	queued := cliEnqueueRetry(t, f, j.dag, approved.failed, approved.request)
	clock.advance(approved.grant.ExpiresAt.Sub(clock.Now()) + time.Second)

	admitted := distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), queuedItem(t, f, j.dag), queued.AttemptID, queued, j.dag)

	assertRetryDropped(t, f, j, queued, admitted, registry.AdmitRetryNotApproved)
	job, err := j.store.GetJob(f.ctx, j.job.JobID)
	require.NoError(t, err)
	assert.Equal(t, registry.ActionUncertain, job.Actions[approved.actionID].State)
	attempt, err := f.dagRunRepository.FindAttempt(f.ctx, queued.DAGRun())
	require.NoError(t, err)
	status, err := attempt.ReadStatus(f.ctx)
	require.NoError(t, err)
	assert.Contains(t, status.Error, "live grant")
}

// A person's approval of a republish or of an explicit rerun, with its
// grant live and its retry request intact, is still refused when it reaches
// the queue: a queued retry names no step, so it would carry out neither
// form. It is refused, not applied, never coerced into a whole-run retry.
func TestQueueDispatch_TxeExplicitFormsAreRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		form   func(*registry.RetryRunParams)
		reason string
	}{
		"republish":      {func(p *registry.RetryRunParams) { p.Step = registry.RetryStepPublish }, "approved as a republish"},
		"explicit rerun": {func(p *registry.RetryRunParams) { p.Step = registry.RetryStepRun }, "approved as a rerun of the job"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newQueueFixture(t)
			j, _ := newRegistryJobWithRuns(t, f)
			approved := approveRetry(t, f, j, "run-failed", tc.form)
			queued := cliEnqueueRetry(t, f, j.dag, approved.failed, approved.request)

			admitted := distributedDispatcher(f, j.store).admitQueuedRun(f.ctx, j.dag.ProcGroup(), queued.DAGRun(), queuedItem(t, f, j.dag), queued.AttemptID, queued, j.dag)

			assertRetryDropped(t, f, j, queued, admitted, registry.AdmitRetryNotApproved)
			attempt, err := f.dagRunRepository.FindAttempt(f.ctx, queued.DAGRun())
			require.NoError(t, err)
			status, err := attempt.ReadStatus(f.ctx)
			require.NoError(t, err)
			assert.Contains(t, status.Error, "not applied")
			assert.Contains(t, status.Error, tc.reason)
		})
	}
}
