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

// registryBindsQueuedRetries is whether this tree has TXE-7517's
// registry.CheckRetryRun wired into registry.AdmitQueuedRetry. Until it
// merges, every queued retry of a registered job is refused, so the tests
// that need the binding to accept, or to give its own reason, wait for it.
const registryBindsQueuedRetries = false

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
	person := registry.Actor{Kind: registry.ActorHuman, ID: "owner"}
	reviewer := registry.Actor{Kind: registry.ActorReviewer, ID: "reviewer"}
	failed := finishedRun(t, f, j.dag, runID, ir.Failed)
	var proposal *registry.Proposal
	var decision *registry.Decision
	_, err := j.store.WithJobTx(f.ctx, j.job.JobID, person, func(tx *registry.JobTx) error {
		var err error
		proposal, decision, err = tx.ProposeRetry(registry.RetryRunParams{
			RunID: runID, AttemptID: failed.AttemptID, QueuedAt: failed.QueuedAt,
			RunSpecSHA256: j.job.DAGSpecSHA256, PackageDigest: j.job.PackageDigest,
		}, "key-"+runID)
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

// A rerun a person approved, queued by the hub with its retry request while
// the grant is live, is dispatched.
func TestQueueDispatch_TxeApprovedRerunIsAdmitted(t *testing.T) {
	f := newQueueFixture(t)
	j, _ := newRegistryJobWithRuns(t, f)
	approved := approveRerun(t, f, j, "run-failed")
	queued := cliEnqueueRetry(t, f, j.dag, approved.failed, approved.request)
	if !registryBindsQueuedRetries {
		t.Skip("TXE-7517: registry.CheckRetryRun is not wired yet")
	}

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
	if registryBindsQueuedRetries {
		attempt, err := f.dagRunRepository.FindAttempt(f.ctx, queued.DAGRun())
		require.NoError(t, err)
		status, err := attempt.ReadStatus(f.ctx)
		require.NoError(t, err)
		assert.Contains(t, status.Error, "grant")
	}
}
