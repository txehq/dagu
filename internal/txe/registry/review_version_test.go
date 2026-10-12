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

// A replayed proposal is checked like a new one: naming another read version
// is refused, and naming the current one returns the stored proposal.
func TestProposalReplayChecksTheReadVersion(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	job = updateAndReady(t, f, job, 2)
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	id := f.mint(PrefixProposal)
	put := func(read int) (*Proposal, error) {
		var p *Proposal
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			var err error
			p, err = tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: id, JobVersion: read, Action: ActionSpec{Name: "resize"}})
			return err
		})
		return p, err
	}
	first, err := put(2)
	require.NoError(t, err)
	_, err = put(1)
	assert.Equal(t, CodeVersionConflict, code(t, err), "a retry naming another read version")
	again, err := put(2)
	require.NoError(t, err)
	assert.Equal(t, first.ProposalID, again.ProposalID)
	assert.Equal(t, 2, again.JobVersion)
}

// A review recorded before an update is not replayed after it: the replay
// would be a review of a version it never read, whatever version it names.
func TestReviewReplayAfterAnUpdateIsRefused(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	review, err := ReviewID(job.JobID, 0)
	require.NoError(t, err)
	record := func(claim *Claim, read int) error {
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			return tx.RecordReview(claim.ClaimID, claim.Fence, Review{ReviewID: review, JobVersion: read, Outcome: ReviewContinue})
		})
		return err
	}
	require.NoError(t, record(c, 0))
	require.NoError(t, record(c, 0), "a replay before any update is the same review")
	updateAndReady(t, f, job, 2)
	c2 := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	for _, read := range []int{0, 1, 2} {
		assert.Equal(t, CodeVersionConflict, code(t, record(c2, read)), "replay naming version %d", read)
	}
}

// A replacement reviewer finishing an episode whose review was recorded
// before an update labels the checkpoint with the reviewed version and
// makes the new version due at once; the next episode then reviews it.
func TestInterruptedEpisodeKeepsItsReviewedVersion(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	review, err := ReviewID(job.JobID, 0)
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		return tx.RecordReview(c.ClaimID, c.Fence, Review{ReviewID: review, Outcome: ReviewContinue})
	})
	require.NoError(t, err)
	updateAndReady(t, f, job, 2)
	c2 := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	advance := func(expected, read int) (*Checkpoint, error) {
		var cp *Checkpoint
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			var err error
			cp, err = tx.AdvanceCheckpoint(c2.ClaimID, c2.Fence, expected, Checkpoint{JobVersion: read})
			return err
		})
		return cp, err
	}
	_, err = advance(0, 2)
	assert.Equal(t, CodeVersionConflict, code(t, err), "the episode reviewed version 1, not 2")
	cp, err := advance(0, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, cp.JobVersion, "labelled with the version its review read")
	require.NotNil(t, cp.NextReviewAt)
	assert.False(t, cp.NextReviewAt.After(f.now), "the new version is due at once")

	next, err := ReviewID(job.JobID, 1)
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		return tx.RecordReview(c2.ClaimID, c2.Fence, Review{ReviewID: next, JobVersion: 2, Outcome: ReviewContinue})
	})
	require.NoError(t, err)
	cp, err = advance(1, 2)
	require.NoError(t, err)
	assert.Equal(t, 2, cp.JobVersion)
}

// A review recorded before the job cached its version (an older aggregate
// without last_recorded_review_job_version) is resolved from the stored
// review itself: its replay after an update is refused, and its episode
// keeps the version it read.
func TestReviewVersionResolvedForAnOlderRecord(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	review, err := ReviewID(job.JobID, 0)
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		if err := tx.RecordReview(c.ClaimID, c.Fence, Review{ReviewID: review, Outcome: ReviewContinue}); err != nil {
			return err
		}
		tx.Job.LastRecordedReviewJobVersion = 0 // as written before the field existed
		return nil
	})
	require.NoError(t, err)
	stored, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	require.Zero(t, stored.LastRecordedReviewJobVersion)

	updateAndReady(t, f, job, 2)
	c2 := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		return tx.RecordReview(c2.ClaimID, c2.Fence, Review{ReviewID: review, Outcome: ReviewContinue})
	})
	assert.Equal(t, CodeVersionConflict, code(t, err), "the old review is not replayed for version 2")
	var cp *Checkpoint
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		var err error
		cp, err = tx.AdvanceCheckpoint(c2.ClaimID, c2.Fence, 0, Checkpoint{JobVersion: 1})
		return err
	})
	require.NoError(t, err, "naming the version the episode reviewed")
	assert.Equal(t, 1, cp.JobVersion)
	require.NotNil(t, cp.NextReviewAt)
}

// A proposal from a review of another version is refused for that, before it
// is judged against the version the job is now at: what the new version
// would refuse in it is not the reason the proposal is refused.
func TestProposalNamingAnotherVersionIsRefusedForThatFirst(t *testing.T) {
	f := newFixture(t)
	job := f.ready("k")
	job = updateAndReady(t, f, job, 2)
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	// A reserved action with no parameters: the job at any version refuses it.
	put := func(read int) error {
		_, err := f.tx(job.JobID, agent, func(tx *JobTx) error {
			_, err := tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: f.mint(PrefixProposal), JobVersion: read, Action: ActionSpec{Name: ActionRetryRun}})
			return err
		})
		return err
	}
	assert.Equal(t, CodeVersionConflict, code(t, put(1)), "naming the version the review read")
	err := put(2)
	require.Error(t, err)
	assert.NotEqual(t, CodeVersionConflict, code(t, err), "naming the current version, it is refused for what it is")
}
