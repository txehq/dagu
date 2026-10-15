// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// client is a caller other than the reviewer that holds a review claim, as
// an acceptance fixture's client does.
var client = registry.Actor{Kind: registry.ActorReviewer, ID: "fixture-client", Session: "fixture-client-session"}

// advanceAsClient ends the job's current episode through AdvanceCheckpoint
// alone, naming lastReviewID and recording no review, as the API lets any
// holder of a review claim do. It returns the new checkpoint version.
func advanceAsClient(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID, lastReviewID string) int {
	t.Helper()
	s, err := registry.NewFileStore(l.DataDir)
	require.NoError(t, err)
	ctx := context.Background()
	var c *registry.Claim
	_, err = s.WithJobTx(ctx, jobID, client, func(tx *registry.JobTx) error {
		var err error
		c, err = tx.AcquireClaim(registry.ClaimReview, registry.Reviewer{MachineID: f.Machine}, 10*time.Minute)
		return err
	})
	require.NoError(t, err)
	var cp *registry.Checkpoint
	_, err = s.WithJobTx(ctx, jobID, client, func(tx *registry.JobTx) error {
		var err error
		next := time.Now().Add(24 * time.Hour)
		cp, err = tx.AdvanceCheckpoint(c.ClaimID, c.Fence, tx.Job.Checkpoint.Version, registry.Checkpoint{
			JobVersion: tx.Job.Version, LastReviewID: lastReviewID, RunCursor: "run-cursor", NextReviewAt: &next,
		})
		return err
	})
	require.NoError(t, err)
	_, err = s.WithJobTx(ctx, jobID, client, func(tx *registry.JobTx) error { return tx.ReleaseClaim(c.ClaimID, c.Fence) })
	require.NoError(t, err)
	return cp.Version
}

func reviewID(t *testing.T, jobID string, episode int) string {
	t.Helper()
	id, err := registry.ReviewID(jobID, episode)
	require.NoError(t, err)
	return id
}

// issuesOf are the issues of one code on the job's record.
func issuesOf(issues []continuity.Issue, code, jobID string) []continuity.Issue {
	var out []continuity.Issue
	for _, i := range issues {
		if i.Code == code && i.ID == "registry/jobs/"+jobID {
			out = append(out, i)
		}
	}
	return out
}

// checkpointBlocks reports whether the job's checkpoint review blocks as a
// dangling reference.
func checkpointBlocks(issues []continuity.Issue, jobID string) bool {
	for _, i := range issuesOf(issues, "dangling_ref", jobID) {
		if i.Severity == continuity.SeverityBlock && strings.HasPrefix(i.Detail, "checkpoint_review ") {
			return true
		}
	}
	return false
}

// The shape a fixture client left on the hub: a review ID the client minted
// itself, written through AdvanceCheckpoint with no review recorded, on a
// job then retired. No build of the registry could have recorded a review
// under that ID, so it is reported by name, with the record and the ID,
// and does not block; nothing else about the inventory changes.
func TestCheckpointNamingAnUnrecordableReviewWarns(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	jobID := f.Jobs["data-collector"]
	cur := job(t, l, jobID)
	require.Zero(t, cur["checkpoint"].(map[string]any)["version"], "the job has never ended an episode")
	require.NotContains(t, cur["chains"].(map[string]any), "reviews", "the job has no reviews")
	baseline := continuity.Validate(scan(t, l), continuity.Policy{})

	minted, err := registry.NewID(registry.PrefixReview, time.Now())
	require.NoError(t, err)
	require.Equal(t, 1, advanceAsClient(t, l, f, jobID, minted))
	s, err := registry.NewFileStore(l.DataDir)
	require.NoError(t, err)
	_, err = s.ChangeLifecycle(context.Background(), jobID, registry.Transition{Op: registry.OpRetire, Reason: registry.RetireManual, Detail: "acceptance fixture finished"}, client)
	require.NoError(t, err)
	retired := job(t, l, jobID)
	require.Equal(t, "retired", retired["lifecycle"])
	require.Equal(t, minted, retired["checkpoint"].(map[string]any)["last_review_id"])

	inv := scan(t, l)
	issues := continuity.Validate(inv, continuity.Policy{})
	assert.Empty(t, continuity.Blocking(issues))
	warned := issuesOf(issues, "checkpoint_review_unrecordable", jobID)
	require.Len(t, warned, 1)
	assert.Equal(t, continuity.SeverityWarn, warned[0].Severity)
	assert.Contains(t, warned[0].Detail, minted)
	assert.Contains(t, warned[0].Detail, reviewID(t, jobID, 0), "the warning names the review the episode would have had")
	assert.Equal(t, len(baseline)+1, len(issues), "the one warning is the only new issue: %v", issues)

	// The reference stays in the inventory, so the record and its digest
	// are compared as before.
	held := false
	for _, r := range inv.Records {
		if r.ID == "jobs/"+jobID {
			for _, ref := range r.Refs {
				held = held || (ref.Rel == "checkpoint_review" && ref.ID == minted && !ref.Optional)
			}
		}
	}
	assert.True(t, held)
	assert.Empty(t, continuity.Compare(inv, scan(t, l), continuity.CompareOptions{}).Issues)
}

// A checkpoint is held to the registry's contract and nothing looser: the
// review of the episode it ended, or of any other episode the job reached,
// must be present; only an ID the job could never record is let through,
// by name; a version the registry never writes is judged as before.
func TestCheckpointReviewIsHeldToTheContract(t *testing.T) {
	cases := []struct {
		name string
		// set leaves the data-collector job's checkpoint naming a review
		// and returns that review's ID.
		set   func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string
		block bool
		warn  string
	}{
		{"the review of the episode it ended, never recorded", func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string {
			id := reviewID(t, jobID, 0)
			advanceAsClient(t, l, f, jobID, id)
			return id
		}, true, ""},
		{"the review of an earlier episode, never recorded", func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string {
			advanceAsClient(t, l, f, jobID, "")
			advanceAsClient(t, l, f, jobID, "")
			id := reviewID(t, jobID, 0)
			require.Equal(t, 3, advanceAsClient(t, l, f, jobID, id))
			return id
		}, true, "checkpoint_review_noncanonical"},
		{"the review of the episode now open, not recorded yet", func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string {
			id := reviewID(t, jobID, 1)
			require.Equal(t, 1, advanceAsClient(t, l, f, jobID, id))
			return id
		}, true, "checkpoint_review_noncanonical"},
		{"a review of the episode after the open one", func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string {
			id := reviewID(t, jobID, 2)
			require.Equal(t, 1, advanceAsClient(t, l, f, jobID, id))
			return id
		}, false, "checkpoint_review_unrecordable"},
		{"another job's recorded review", func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string {
			id := reviewID(t, f.Jobs["health-check"], 0)
			advanceAsClient(t, l, f, jobID, id)
			return id
		}, false, "checkpoint_review_unrecordable"},
		{"another job's review that does not exist", func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string {
			id := reviewID(t, f.Jobs["health-check"], 1)
			advanceAsClient(t, l, f, jobID, id)
			return id
		}, false, "checkpoint_review_unrecordable"},
		{"an ID that is not a review ID", func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string {
			advanceAsClient(t, l, f, jobID, "not-a-review")
			return "not-a-review"
		}, false, "checkpoint_review_unrecordable"},
		{"a checkpoint at version 0 that names a review", func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string {
			return setCheckpoint(t, l, jobID, "0")
		}, true, ""},
		{"a checkpoint at a negative version", func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string {
			return setCheckpoint(t, l, jobID, "-1")
		}, true, ""},
		{"a checkpoint beyond the episodes enumerated", func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string {
			return setCheckpoint(t, l, jobID, strconv.Itoa(1<<20+1))
		}, true, ""},
		{"a checkpoint whose version overflows", func(t *testing.T, l *fixture.Layout, f *fixture.Facts, jobID string) string {
			return setCheckpoint(t, l, jobID, "9223372036854775808")
		}, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, f := build(t)
			jobID := f.Jobs["data-collector"]
			id := tc.set(t, l, f, jobID)
			issues := continuity.Validate(scan(t, l), continuity.Policy{})
			blocks := continuity.Blocking(issues)
			if tc.name == "a checkpoint whose version overflows" {
				// The registry's own type cannot hold it: the record does
				// not decode, and blocks as such.
				assert.Len(t, issuesOf(blocks, "undecodable", jobID), 1, "%v", issues)
				return
			}
			assert.Equal(t, tc.block, checkpointBlocks(issues, jobID), "%v", issues)
			if tc.block {
				assert.Len(t, blocks, 1, "only the checkpoint review blocks: %v", blocks)
			} else {
				assert.Empty(t, blocks)
			}
			for _, code := range []string{"checkpoint_review_noncanonical", "checkpoint_review_unrecordable"} {
				got := issuesOf(issues, code, jobID)
				if code != tc.warn {
					assert.Empty(t, got, code)
					continue
				}
				require.Len(t, got, 1, code)
				assert.Equal(t, continuity.SeverityWarn, got[0].Severity)
				assert.Contains(t, got[0].Detail, id)
			}
		})
	}
}

// setCheckpoint writes a checkpoint the registry never writes straight into
// the job's record, at version, naming a client-minted review ID.
func setCheckpoint(t *testing.T, l *fixture.Layout, jobID, version string) string {
	t.Helper()
	minted, err := registry.NewID(registry.PrefixReview, time.Now())
	require.NoError(t, err)
	p := regPath(l, "jobs/"+jobID)
	data, err := os.ReadFile(p) //nolint:gosec // test fixture path
	require.NoError(t, err)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]any
	require.NoError(t, dec.Decode(&m))
	m["checkpoint"] = map[string]any{"version": json.Number(version), "last_review_id": minted}
	out, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p, out, 0o600))
	return minted
}

// The review of every episode the reviewer ended is required as before: a
// recorded review lost blocks the inventory it is missing from, and Compare
// blocks its loss across a transition.
func TestRecordedCheckpointReviewLossBlocks(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	jobID := f.Jobs["health-check"]
	cur := job(t, l, jobID)
	cp := cur["checkpoint"].(map[string]any)
	require.Equal(t, reviewID(t, jobID, 0), cp["last_review_id"], "the reviewer ended episode 0 with its review")
	head := cur["chains"].(map[string]any)["reviews"].(string)

	before := scan(t, l)
	issues := continuity.Validate(before, continuity.Policy{})
	assert.Empty(t, continuity.Blocking(issues))
	assert.Empty(t, issuesOf(issues, "checkpoint_review_unrecordable", jobID))
	assert.Empty(t, issuesOf(issues, "checkpoint_review_noncanonical", jobID))

	require.NoError(t, os.Remove(regPath(l, head)))
	after := scan(t, l)
	assert.True(t, checkpointBlocks(continuity.Validate(after, continuity.Policy{}), jobID))
	missing := 0
	for _, i := range continuity.Compare(before, after, continuity.CompareOptions{}).Issues {
		if i.Code == "record_missing" && i.ID == "registry/"+head {
			missing++
		}
	}
	assert.Equal(t, 1, missing)
	assert.Positive(t, compareCodes(continuity.CompareProgress(before, after))["record_missing"])
}

// A checkpoint naming another job's review is reported while the review is
// there, and the review's loss is still a missing record across a
// transition.
func TestCrossJobCheckpointReviewLossBlocks(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	jobID := f.Jobs["data-collector"]
	other := f.Jobs["health-check"]
	id := reviewID(t, other, 0)
	advanceAsClient(t, l, f, jobID, id)
	before := scan(t, l)
	issues := continuity.Validate(before, continuity.Policy{})
	assert.Empty(t, continuity.Blocking(issues))
	warned := issuesOf(issues, "checkpoint_review_unrecordable", jobID)
	require.Len(t, warned, 1)
	assert.Contains(t, warned[0].Detail, id)

	head := job(t, l, other)["chains"].(map[string]any)["reviews"].(string)
	require.NoError(t, os.Remove(regPath(l, head)))
	after := scan(t, l)
	assert.Positive(t, compareCodes(continuity.Compare(before, after, continuity.CompareOptions{}))["record_missing"])
	assert.True(t, checkpointBlocks(continuity.Validate(after, continuity.Policy{}), other), "the review's own job still requires it")
}

// Neither the job's checkpoint nor a recorded review may change unnoticed:
// a checkpoint rewritten to name an unrecordable review, through the
// registry or in place, and a review rewritten, block across a transition.
func TestCheckpointReviewChangesAreDetected(t *testing.T) {
	t.Run("through the registry", func(t *testing.T) {
		t.Parallel()
		l, f := build(t)
		jobID := f.Jobs["health-check"]
		before := scan(t, l)
		minted, err := registry.NewID(registry.PrefixReview, time.Now())
		require.NoError(t, err)
		advanceAsClient(t, l, f, jobID, minted)
		after := scan(t, l)
		assert.Len(t, issuesOf(continuity.Validate(after, continuity.Policy{}), "checkpoint_review_unrecordable", jobID), 1)
		changed := 0
		for _, i := range continuity.Compare(before, after, continuity.CompareOptions{}).Issues {
			if i.Code == "record_changed" && i.ID == "registry/jobs/"+jobID {
				changed++
			}
		}
		assert.Equal(t, 1, changed)
	})
	t.Run("in place", func(t *testing.T) {
		t.Parallel()
		l, f := build(t)
		jobID := f.Jobs["health-check"]
		before := scan(t, l)
		edit(t, regPath(l, "jobs/"+jobID), func(m map[string]any) {
			m["checkpoint"].(map[string]any)["last_review_id"] = "rev_01M4ZZZZZZZZZZZZZZZZZZZZZZ"
		})
		after := scan(t, l)
		assert.Positive(t, compareCodes(continuity.Compare(before, after, continuity.CompareOptions{}))["record_changed"])
		assert.Positive(t, compareCodes(continuity.CompareProgress(before, after))["aggregate_rewritten"])
	})
	t.Run("a recorded review rewritten", func(t *testing.T) {
		t.Parallel()
		l, f := build(t)
		head := job(t, l, f.Jobs["health-check"])["chains"].(map[string]any)["reviews"].(string)
		before := scan(t, l)
		edit(t, regPath(l, head), func(m map[string]any) { m["reasoning"] = "rewritten" })
		after := scan(t, l)
		assert.Positive(t, compareCodes(continuity.Compare(before, after, continuity.CompareOptions{}))["record_changed"])
		assert.Positive(t, compareCodes(continuity.CompareProgress(before, after))["immutable_changed"])
	})
}
