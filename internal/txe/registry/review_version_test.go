// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// updateAndReady moves job to version n and marks it ready.
func updateAndReady(t *testing.T, f *fixture, job *Job, n byte) *Job {
	t.Helper()
	v := f.version(n)
	_, err := f.store.UpdateVersion(f.ctx, job.JobID, f.mint(PrefixEvent), job.Version, v, cli)
	require.NoError(t, err)
	updated, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	_, err = f.store.MarkReady(f.ctx, job.JobID, updated.Revision, PackageEvidence{Digest: v.Package.Digest, Path: v.Package.Path, MachineID: f.machine}, cli)
	require.NoError(t, err)
	updated, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	return updated
}

// reviewWrites makes each review write under claim c, as a review that read
// version read would, and returns their errors in order: proposal, review,
// checkpoint.
func reviewWrites(t *testing.T, f *fixture, jobID string, c *Claim, read int) []error {
	t.Helper()
	job, err := f.store.GetJob(f.ctx, jobID)
	require.NoError(t, err)
	review, err := ReviewID(jobID, job.Checkpoint.Version)
	require.NoError(t, err)
	var errs []error
	for _, write := range []func(tx *JobTx) error{
		func(tx *JobTx) error {
			_, err := tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: f.mint(PrefixProposal), JobVersion: read, Action: ActionSpec{Name: "resize"}})
			return err
		},
		func(tx *JobTx) error {
			return tx.RecordReview(c.ClaimID, c.Fence, Review{ReviewID: review, JobVersion: read, Outcome: ReviewContinue})
		},
		func(tx *JobTx) error {
			_, err := tx.AdvanceCheckpoint(c.ClaimID, c.Fence, job.Checkpoint.Version, Checkpoint{JobVersion: read})
			return err
		},
	} {
		_, err := f.tx(jobID, agent, write)
		errs = append(errs, err)
	}
	return errs
}

// A version update ends the live review claim in the same commit: the
// review read the old version, so its proposal, review and checkpoint
// writes are all refused and nothing of it binds to the new version. Its
// executing actions are interrupted, and a fresh review of the new version
// can follow.
func TestUpdateEndsALiveReviewClaim(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	actionID, _, err := routine(t, f, job, c, "restart")
	require.NoError(t, err)

	updated := updateAndReady(t, f, job, 2)
	require.NotNil(t, updated.Claim)
	assert.Equal(t, ClaimReleased, updated.Claim.State, "the review claim ended with the update")
	assert.Equal(t, ActionUncertain, updated.Actions[actionID].State, "its executing action is reconciled, never settled by the old review")
	events, err := f.store.ListEvents(f.ctx, job.JobID, 0)
	require.NoError(t, err)
	var detail string
	for _, e := range events {
		if e.Kind == EventVersion {
			detail = e.Detail
		}
	}
	assert.Contains(t, detail, c.ClaimID)

	for i, err := range reviewWrites(t, f, job.JobID, c, 0) {
		assert.Equal(t, CodeClaimStale, code(t, err), "write %d of the old review", i)
	}
	after, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Len(t, after.Proposals, len(updated.Proposals), "no proposal was written")
	assert.Equal(t, updated.Checkpoint, after.Checkpoint, "the checkpoint did not advance")
	assert.Empty(t, after.LastRecordedReview, "no review was recorded")

	c2 := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	for i, err := range reviewWrites(t, f, job.JobID, c2, 2) {
		require.NoError(t, err, "write %d of a review of version 2", i)
	}
	reviewed, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, 2, reviewed.Checkpoint.JobVersion)
}

// A review write that names the version its review read is refused when the
// job is at another one, and writes nothing.
func TestReviewWritesRefuseAnotherReadVersion(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	job = updateAndReady(t, f, job, 2)
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	for i, err := range reviewWrites(t, f, job.JobID, c, 1) {
		assert.Equal(t, CodeVersionConflict, code(t, err), "write %d naming version 1", i)
	}
	after, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Empty(t, after.Proposals)
	assert.Equal(t, job.Checkpoint, after.Checkpoint)
	assert.Empty(t, after.LastRecordedReview)
}

// A review write needs a ready job, whatever claim it holds.
func TestReviewWritesNeedAReadyJob(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
		tx.Job.Registration.State = RegistrationIncomplete
		_, err := tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: f.mint(PrefixProposal), Action: ActionSpec{Name: "resize"}})
		return err
	})
	assert.Equal(t, CodeNotReady, code(t, err))
}

// An update leaves an execution claim alone: only a review reads the job's
// version to judge it.
func TestUpdateLeavesAnExecutionClaim(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimExecution, time.Hour)
	_, err := f.store.UpdateVersion(f.ctx, job.JobID, f.mint(PrefixEvent), job.Version, f.version(2), cli)
	require.NoError(t, err)
	after, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	require.NotNil(t, after.Claim)
	assert.Equal(t, c.ClaimID, after.Claim.ClaimID)
	assert.Equal(t, ClaimLive, after.Claim.State)
}
