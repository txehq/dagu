// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

func compareCodes(rep *continuity.Report) map[string]int {
	return codes(rep.Issues, continuity.SeverityBlock)
}

// An unchanged store compares clean.
func TestCompareUnchanged(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	before := scan(t, l)
	rep := continuity.Compare(before, scan(t, l))
	assert.Empty(t, rep.Issues)
	assert.Empty(t, rep.Added)
	assert.Empty(t, rep.Changed)
}

// Work done after the earlier inventory, through the registry, is reported
// as added and changed records, never as a loss: the freeze-point inventory
// reconciles it.
func TestCompareLaterWorkIsReported(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	before := scan(t, l)
	s, err := registry.NewFileStore(l.DataDir)
	require.NoError(t, err)
	ctx := context.Background()
	jobID := f.Jobs["paused"]
	_, err = s.ChangeLifecycle(ctx, jobID, registry.Transition{Op: registry.OpResume}, registry.Actor{Kind: registry.ActorHuman, ID: "fixture-person"})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(l.DataDir, "dag-runs", "new-run.jsonl"), []byte("{}\n"), 0o600))

	after := scan(t, l)
	rep := continuity.Compare(before, after)
	assert.Empty(t, rep.Issues)
	assert.Contains(t, rep.Changed, "registry/jobs/"+jobID)
	assert.Contains(t, rep.Added, "hub-data/dag-runs/new-run.jsonl")
	added := 0
	for _, a := range rep.Added {
		if filepath.Dir(filepath.Dir(a)) == "registry/history/"+jobID {
			added++
		}
	}
	assert.Positive(t, added, "the resume's history is added")
	assert.Empty(t, continuity.Blocking(continuity.Validate(after, continuity.Policy{})))
}

// Each loss or rewrite between two inventories blocks.
func TestCompareBreaksAreBlocking(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(t *testing.T, l *fixture.Layout, f *fixture.Facts)
		want   string
	}{
		{"a record lost", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			require.NoError(t, os.Remove(regPath(l, "jobs/"+f.Jobs["validation"])))
		}, "record_missing"},
		{"an immutable history record rewritten", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			head := job(t, l, f.Jobs["health-check"])["chains"].(map[string]any)["events"].(string)
			edit(t, regPath(l, head), func(m map[string]any) { m["detail"] = "rewritten" })
		}, "immutable_changed"},
		{"a job changed without a later revision", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["paused"]), func(m map[string]any) { m["lifecycle"] = "active" })
		}, "aggregate_rewritten"},
		{"a job moved to another machine", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["paused"]), func(m map[string]any) {
				m["machine_id"] = f.Machine2
				m["revision"] = m["revision"].(float64) + 1
			})
		}, "identity_changed"},
		{"a job's earlier versions replaced", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["health-check"]), func(m map[string]any) {
				refs := m["version_refs"].([]any)
				m["version_refs"] = []any{refs[1], refs[0]}
				m["revision"] = m["revision"].(float64) + 1
			})
		}, "versions_rewritten"},
		{"a job reassigned to another owner", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["paused"]), func(m map[string]any) {
				m["owner_id"] = impostor
				m["revision"] = m["revision"].(float64) + 1
			})
		}, "owner_changed"},
		{"a retained run file lost", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			require.NoError(t, os.RemoveAll(filepath.Join(l.DataDir, "dag-runs")))
		}, "file_missing"},
		{"a machine output changed", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			require.NoError(t, os.WriteFile(filepath.Join(l.MachineHome, filepath.FromSlash(f.MachineArtifacts[1])), []byte("x"), 0o600))
		}, "immutable_changed"},
		{"a job's history rewound to an earlier head", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			p := regPath(l, "jobs/"+f.Jobs["health-check"])
			head := job(t, l, f.Jobs["health-check"])["chains"].(map[string]any)["events"].(string)
			data, err := os.ReadFile(regPath(l, head))
			require.NoError(t, err)
			var e registry.Event
			require.NoError(t, json.Unmarshal(data, &e))
			edit(t, p, func(m map[string]any) {
				m["chains"].(map[string]any)["events"] = e.Prev
				m["revision"] = m["revision"].(float64) + 1
			})
		}, "history_unreachable"},
		{"an enrolment key handed to another machine", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			dir := filepath.Join(l.DataDir, "txe", "authz", "v1", "enrolment_keys")
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			edit(t, filepath.Join(dir, entries[0].Name()), func(m map[string]any) { m["machine_id"] = f.Machine2 })
		}, "immutable_changed"},
		{"a live open proposal dropped", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["data-collector"]), func(m map[string]any) {
				props := m["proposals"].(map[string]any)
				for id, p := range props {
					if p.(map[string]any)["state"] == "open" {
						delete(props, id)
					}
				}
				m["revision"] = m["revision"].(float64) + 1
			})
		}, "live_entry_lost"},
		{"an exception dropped", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["health-check"]), func(m map[string]any) {
				require.NotEmpty(t, m["exceptions"])
				delete(m, "exceptions")
				m["revision"] = m["revision"].(float64) + 1
			})
		}, "live_entry_lost"},
		{"decision keys dropped", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["health-check"]), func(m map[string]any) {
				require.NotEmpty(t, m["decision_keys"])
				delete(m, "decision_keys")
				m["revision"] = m["revision"].(float64) + 1
			})
		}, "live_entry_lost"},
		{"the store reset to empty", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			require.NoError(t, os.RemoveAll(filepath.Join(l.DataDir, "txe")))
		}, "record_missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, f := build(t)
			before := scan(t, l)
			tc.break_(t, l, f)
			got := compareCodes(continuity.Compare(before, scan(t, l)))
			assert.Positive(t, got[tc.want], "want %s, got %v", tc.want, got)
		})
	}
}

// An inventory taken with another expected owner never compares clean.
func TestCompareRefusesAnotherOwner(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	before := scan(t, l)
	after, err := continuity.Scan(context.Background(), continuity.Options{Roots: roots(l), ExpectedOwner: impostor, Now: before.ScannedAt.Local})
	require.NoError(t, err)
	assert.Positive(t, compareCodes(continuity.Compare(before, after))["owner_changed"])
	assert.Positive(t, codes(continuity.Validate(after, continuity.Policy{}), continuity.SeverityBlock)["owner_mismatch"])
}

// Archiving through the registry is how a live proposal or action leaves a
// job: approving and executing a pending proposal later compares clean.
func TestCompareAcceptsArchiving(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	before := scan(t, l)
	s, err := registry.NewFileStore(l.DataDir)
	require.NoError(t, err)
	ctx := context.Background()
	jobID := f.Jobs["data-collector"]
	cur, err := s.GetJob(ctx, jobID)
	require.NoError(t, err)
	reviewer := registry.Actor{Kind: registry.ActorReviewer, ID: "fixture-reviewer"}
	var c *registry.Claim
	_, err = s.WithJobTx(ctx, jobID, reviewer, func(tx *registry.JobTx) error {
		// The fixture's claim expired long ago on the real clock.
		var err error
		c, err = tx.AcquireClaim(registry.ClaimExecution, registry.Reviewer{MachineID: f.Machine}, time.Hour)
		return err
	})
	require.NoError(t, err)
	var p *registry.Proposal
	for _, x := range cur.Proposals {
		if x.State == registry.ProposalDecided {
			p = x
		}
	}
	require.NotNil(t, p)
	actionID, err := registry.ApprovedActionID(p.ProposalID, p.Decision.DecisionID)
	require.NoError(t, err)
	var g *registry.Grant
	_, err = s.WithJobTx(ctx, jobID, reviewer, func(tx *registry.JobTx) error {
		var err error
		g, err = tx.Authorize(registry.EffectRequest{ActionID: actionID, JobVersion: cur.Version, PackageDigest: cur.PackageDigest,
			Approved: &registry.ApprovedEffect{ProposalID: p.ProposalID, DecisionID: p.Decision.DecisionID, ClaimID: c.ClaimID, Fence: c.Fence}})
		return err
	})
	require.NoError(t, err)
	_, err = s.WithJobTx(ctx, jobID, reviewer, func(tx *registry.JobTx) error {
		_, err := tx.SettleAction(registry.Settlement{ActionID: actionID, GrantID: g.GrantID, ClaimID: c.ClaimID, Fence: c.Fence, State: registry.ActionSucceeded, Receipt: "rebuilt"})
		return err
	})
	require.NoError(t, err)
	rep := continuity.Compare(before, scan(t, l))
	assert.Empty(t, rep.Issues)
	assert.Contains(t, rep.Changed, "registry/jobs/"+jobID)
}

// Permission bits are compared only between scans that both had them.
func TestCompareIgnoresUnknownModes(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	before := scan(t, l)
	before.ModeBits = false
	for i := range before.Files {
		before.Files[i].Mode = 0
	}
	assert.Empty(t, continuity.Compare(before, scan(t, l)).Issues)
}
