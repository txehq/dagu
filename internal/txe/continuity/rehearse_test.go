// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// lineage is a rehearsal transform: it records a migration identifier on
// the owner and renames the machines' display names, which are replaceable
// by the ownership contract. Owners and IDs stay as they are.
func lineage(store, id string, data []byte) ([]byte, error) {
	switch {
	case store == "registry" && len(id) > len("owners/") && id[:len("owners/")] == "owners/":
		var o registry.Owner
		if err := json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		o.Provenance = "fixture: installer; rehearsal mig_0001"
		return indent(o)
	case store == "registry" && len(id) > len("machines/") && id[:len("machines/")] == "machines/":
		var m registry.Machine
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		m.DisplayName += " (rehearsed)"
		return indent(m)
	}
	return data, nil
}

func indent(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// stealOwner is a transform that must never be applied.
func stealOwner(store, id string, data []byte) ([]byte, error) {
	if store == "registry" && len(id) > 5 && id[:5] == "jobs/" {
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		m["owner_id"] = impostor
		return indent(m)
	}
	return data, nil
}

type rehearsal struct {
	l       *fixture.Layout
	before  *continuity.Inventory
	plan    *continuity.Plan
	journal string
	target  string
}

func newRehearsal(t *testing.T, mode string, transform continuity.Transform) *rehearsal {
	t.Helper()
	l, _ := build(t)
	before := scan(t, l)
	plan, err := continuity.PlanTransition(before, l.DataDir, mode, transform, continuity.Policy{})
	require.NoError(t, err)
	r := &rehearsal{l: l, before: before, plan: plan, journal: filepath.Join(t.TempDir(), "journal.jsonl"), target: l.DataDir}
	if mode == continuity.ModeImport {
		r.target = filepath.Join(t.TempDir(), "relocated", "data")
	}
	return r
}

func (r *rehearsal) apply(ctx context.Context, transform continuity.Transform, interrupt func(int, string) error) (*continuity.ApplyResult, error) {
	return continuity.Apply(ctx, r.plan, continuity.ApplyOptions{SourceData: r.l.DataDir, TargetData: r.target,
		Journal: r.journal, Transform: transform, Interrupt: interrupt})
}

// after scans the transition's result as the hub data root, with the
// source's mount so its stored paths resolve.
func (r *rehearsal) after(t *testing.T) *continuity.Inventory {
	t.Helper()
	rs := roots(r.l)
	rs[0].Path = r.target
	inv, err := continuity.Scan(context.Background(), continuity.Options{Roots: rs, ExpectedOwner: fixture.StableOwner,
		Label: "test", Now: func() time.Time { return scanTime }})
	require.NoError(t, err)
	return inv
}

func (r *rehearsal) verify(t *testing.T) *continuity.Report {
	t.Helper()
	journal, err := continuity.ReadJournal(r.journal)
	require.NoError(t, err)
	return continuity.VerifyTransition(r.before, r.after(t), r.plan, journal)
}

var errCrash = errors.New("crash")

// The real phase-two release keeps the record format, so its in-place
// transition rewrites nothing and no import is needed: storage stays where
// it is.
func TestIdentityTransitionRewritesNothing(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeInPlace, continuity.Identity)
	assert.Empty(t, r.plan.Steps)
	assert.Zero(t, r.plan.Rewrites)
	res, err := r.apply(context.Background(), continuity.Identity, nil)
	require.NoError(t, err)
	assert.Zero(t, res.Written)
	assert.Empty(t, r.verify(t).Issues)
}

// Planning writes nothing anywhere.
func TestPlanIsDryRun(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	before := treeState(t, l.Root)
	inv := scan(t, l)
	plan, err := continuity.PlanTransition(inv, l.DataDir, continuity.ModeInPlace, lineage, continuity.Policy{})
	require.NoError(t, err)
	assert.Equal(t, 3, plan.Rewrites, "the owner and two machines")
	_, err = continuity.PlanTransition(inv, l.DataDir, continuity.ModeImport, lineage, continuity.Policy{})
	require.NoError(t, err)
	assert.Equal(t, before, treeState(t, l.Root))
}

// An in-place transition rewrites only what it planned, and the result
// validates and verifies against the inventory taken before it. Nothing
// runs: no run file is added.
func TestInPlaceTransition(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeInPlace, lineage)
	res, err := r.apply(context.Background(), lineage, nil)
	require.NoError(t, err)
	assert.Equal(t, 3, res.Written)
	after := r.after(t)
	assert.Empty(t, continuity.Blocking(continuity.Validate(after, continuity.Policy{})))
	rep := continuity.VerifyTransition(r.before, after, r.plan, mustJournal(t, r.journal))
	assert.Empty(t, rep.Issues)
	assert.Len(t, rep.Changed, 3)
	assert.Empty(t, rep.Added, "nothing executed, nothing added")
}

func mustJournal(t *testing.T, path string) []continuity.JournalEntry {
	t.Helper()
	j, err := continuity.ReadJournal(path)
	require.NoError(t, err)
	return j
}

// A transition stopped at any point, before or after any write, completes
// when it is run again, without a duplicate write; a further run does
// nothing.
func TestInterruptedTransitionResumes(t *testing.T) {
	for _, mode := range []string{continuity.ModeInPlace, continuity.ModeImport} {
		probe := newRehearsal(t, mode, lineage)
		steps := len(probe.plan.Steps)
		require.Positive(t, steps)
		stride := max(1, steps/7)
		for step := 0; step < steps; step += stride {
			for _, point := range []string{"before_write", "after_write"} {
				t.Run(fmt.Sprintf("%s/%d/%s", mode, step, point), func(t *testing.T) {
					t.Parallel()
					r := newRehearsal(t, mode, lineage)
					_, err := r.apply(context.Background(), lineage, func(i int, p string) error {
						if i == step && p == point {
							return errCrash
						}
						return nil
					})
					require.ErrorIs(t, err, errCrash)
					res, err := r.apply(context.Background(), lineage, nil)
					require.NoError(t, err)
					assert.Equal(t, steps, res.Written+res.AlreadyDone, "the resumed run accounts for every step")
					doneCount := map[string]int{}
					for _, e := range mustJournal(t, r.journal) {
						if e.Outcome == continuity.OutcomeDone {
							doneCount[e.Path]++
						}
					}
					assert.Len(t, doneCount, steps)
					for p, n := range doneCount {
						assert.Equal(t, 1, n, "%s is journaled done once", p)
					}
					again, err := r.apply(context.Background(), lineage, nil)
					require.NoError(t, err)
					assert.Zero(t, again.Written, "a repeated run writes nothing")
					assert.Equal(t, steps, again.AlreadyDone)
					assert.Empty(t, r.verify(t).Issues)
				})
			}
		}
	}
}

// A record that differs from both what the plan read and what it would
// write stops the transition there; it is not overwritten.
func TestConflictStopsWithoutOverwriting(t *testing.T) {
	t.Run("in place", func(t *testing.T) {
		t.Parallel()
		r := newRehearsal(t, continuity.ModeInPlace, lineage)
		p := filepath.Join(registry.Dir(r.l.DataDir), "owners", fixture.StableOwner+".json")
		require.NoError(t, os.WriteFile(p, []byte(`{"schema":1,"owner_id":"`+fixture.StableOwner+`","display_name":"edited during freeze","created":{"at":"2026-09-01T00:00:00Z","by":{"kind":"cli","id":"x"}}}`), 0o600))
		edited, err := os.ReadFile(p) //nolint:gosec // test path
		require.NoError(t, err)
		_, err = r.apply(context.Background(), lineage, nil)
		require.ErrorIs(t, err, continuity.ErrConflict)
		now, err := os.ReadFile(p) //nolint:gosec // test path
		require.NoError(t, err)
		assert.Equal(t, edited, now, "the conflicting record is kept")
		j := mustJournal(t, r.journal)
		require.NotEmpty(t, j)
		assert.Equal(t, continuity.OutcomeConflict, j[len(j)-1].Outcome)
	})
	t.Run("import into a store that holds another record", func(t *testing.T) {
		t.Parallel()
		r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
		first := r.plan.Steps[0]
		p := filepath.Join(r.target, filepath.FromSlash(first.Path))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(`{"another":"record"}`), 0o600))
		_, err := r.apply(context.Background(), continuity.Identity, nil)
		require.ErrorIs(t, err, continuity.ErrConflict)
		now, err := os.ReadFile(p) //nolint:gosec // test path
		require.NoError(t, err)
		assert.JSONEq(t, `{"another":"record"}`, string(now))
	})
	t.Run("source changed after the plan", func(t *testing.T) {
		t.Parallel()
		r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
		p := filepath.Join(r.l.DataDir, filepath.FromSlash(r.plan.Steps[0].Path))
		require.NoError(t, os.WriteFile(p, []byte(`{}`), 0o600))
		_, err := r.apply(context.Background(), continuity.Identity, nil)
		require.ErrorIs(t, err, continuity.ErrConflict)
	})
}

// An import copies the retained store to a new directory, leaves the source
// untouched, does not carry the queue across (it would dispatch), and
// verifies against the source's inventory.
func TestImportLeavesSourceAndVerifies(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
	before := treeState(t, r.l.Root)
	_, err := r.apply(context.Background(), continuity.Identity, nil)
	require.NoError(t, err)
	assert.Equal(t, before, treeState(t, r.l.Root), "the source is unchanged")
	rep := r.verify(t)
	assert.Empty(t, rep.Issues)
	assert.Empty(t, rep.Changed)
	assert.Empty(t, continuity.Blocking(continuity.Validate(r.after(t), continuity.Policy{})))
}

// A transform that would reassign ownership, or a store that does not
// validate, is refused before anything is written.
func TestRefusedTransitions(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	inv := scan(t, l)
	_, err := continuity.PlanTransition(inv, l.DataDir, continuity.ModeInPlace, stealOwner, continuity.Policy{})
	require.ErrorIs(t, err, continuity.ErrBlocked)

	edit(t, regPath(l, "jobs/"+f.Jobs["paused"]), func(m map[string]any) { m["owner_id"] = impostor })
	_, err = continuity.PlanTransition(scan(t, l), l.DataDir, continuity.ModeInPlace, continuity.Identity, continuity.Policy{})
	require.ErrorIs(t, err, continuity.ErrBlocked)
}

// A step whose bytes were lost after it was journaled is reported, not
// rewritten from the journal's word.
func TestVerifyFindsAStepLostAfterTheJournal(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeInPlace, lineage)
	_, err := r.apply(context.Background(), lineage, nil)
	require.NoError(t, err)
	p := filepath.Join(registry.Dir(r.l.DataDir), "owners", fixture.StableOwner+".json")
	require.NoError(t, os.Remove(p))
	_, err = r.apply(context.Background(), lineage, nil)
	require.ErrorIs(t, err, continuity.ErrConflict)
	assert.Positive(t, codes(r.verify(t).Issues, continuity.SeverityBlock)["record_missing"])
}

// An import does not carry queued dispatch across: the queue is
// operational, and copying it would run work in the new store.
func TestImportLeavesTheQueue(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	q := filepath.Join(l.DataDir, "queue", "item.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(q), 0o750))
	require.NoError(t, os.WriteFile(q, []byte(`{"dag":"fixture"}`), 0o600))
	before := scan(t, l)
	plan, err := continuity.PlanTransition(before, l.DataDir, continuity.ModeImport, continuity.Identity, continuity.Policy{})
	require.NoError(t, err)
	assert.Contains(t, plan.NotCopied, "queue/item.json")
	target := filepath.Join(t.TempDir(), "data")
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	_, err = continuity.Apply(context.Background(), plan, continuity.ApplyOptions{SourceData: l.DataDir, TargetData: target, Journal: journal})
	require.NoError(t, err)
	assert.NoFileExists(t, filepath.Join(target, "queue", "item.json"))
	rs := roots(l)
	rs[0].Path = target
	after, err := continuity.Scan(context.Background(), continuity.Options{Roots: rs, ExpectedOwner: fixture.StableOwner})
	require.NoError(t, err)
	assert.Empty(t, continuity.VerifyTransition(before, after, plan, mustJournal(t, journal)).Issues)
}
