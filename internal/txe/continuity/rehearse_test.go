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
	"runtime"
	"strings"
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
	skipApplyOnWindows(t)
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
	return continuity.VerifyTransition(r.before, r.after(t), r.plan, journal, continuity.Policy{})
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
	rep := continuity.VerifyTransition(r.before, after, r.plan, mustJournal(t, r.journal), continuity.Policy{})
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
			for _, point := range []string{"before_write", "staged", "installed", "after_write"} {
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
	skipApplyOnWindows(t)
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
	assert.Empty(t, continuity.VerifyTransition(before, after, plan, mustJournal(t, journal), continuity.Policy{}).Issues)
}

// A crash in the middle of appending to the journal leaves a torn line, or
// a complete entry without its newline; a resumed run repairs it before it
// appends, and the journal reads cleanly afterwards.
func TestTornJournalIsRepaired(t *testing.T) {
	for name, tear := range map[string]func([]byte) []byte{
		"incomplete line": func(b []byte) []byte { return append(b, []byte(`{"seq":`)...) },
		"missing newline": func(b []byte) []byte { return b[:len(b)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newRehearsal(t, continuity.ModeInPlace, lineage)
			_, err := r.apply(context.Background(), lineage, func(i int, p string) error {
				if i == 1 && p == "before_write" {
					return errCrash
				}
				return nil
			})
			require.ErrorIs(t, err, errCrash)
			data, err := os.ReadFile(r.journal)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(r.journal, tear(data), 0o600))
			_, err = r.apply(context.Background(), lineage, nil)
			require.NoError(t, err)
			j := mustJournal(t, r.journal)
			assert.NotEmpty(t, j)
			again, err := r.apply(context.Background(), lineage, nil)
			require.NoError(t, err)
			assert.Zero(t, again.Written)
			assert.Empty(t, r.verify(t).Issues)
		})
	}
}

// A crash after a write was staged, before it was installed, leaves
// nothing behind once the transition resumes.
func TestInterruptedStagingLeavesNothing(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
	_, err := r.apply(context.Background(), continuity.Identity, func(i int, p string) error {
		if i == 3 && p == "staged" {
			return errCrash
		}
		return nil
	})
	require.ErrorIs(t, err, errCrash)
	_, err = r.apply(context.Background(), continuity.Identity, nil)
	require.NoError(t, err)
	left, err := filepath.Glob(filepath.Join(r.target, ".txe-transition-staging*"))
	require.NoError(t, err)
	assert.Empty(t, left)
	assert.Empty(t, r.verify(t).Issues)
}

// The roots must be what the mode needs, compared by identity: an import
// target that is the source under another name, or inside it, and a
// journal inside a data directory are refused before anything is written.
func TestRootsAreChecked(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
	before := treeState(t, r.l.Root)
	try := func(target, journal string) error {
		_, err := continuity.Apply(context.Background(), r.plan, continuity.ApplyOptions{SourceData: r.l.DataDir, TargetData: target, Journal: journal})
		return err
	}
	assert.Error(t, try(filepath.Join(r.l.DataDir, "nested"), r.journal), "a target inside the source")
	assert.Error(t, try(r.target, filepath.Join(r.l.DataDir, "journal.jsonl")), "a journal inside the source")
	if runtime.GOOS != "windows" {
		alias := filepath.Join(t.TempDir(), "alias")
		require.NoError(t, os.Symlink(r.l.DataDir, alias))
		assert.Error(t, try(alias, r.journal), "the source under another name")
	}
	assert.Equal(t, before, treeState(t, r.l.Root), "nothing was written")
	_, err := continuity.Apply(context.Background(), &continuity.Plan{Format: continuity.PlanFormatV1, Mode: continuity.ModeImport,
		Steps: []continuity.Step{{Path: "../outside", Before: "x", After: "x"}}}, continuity.ApplyOptions{SourceData: r.l.DataDir, TargetData: r.target, Journal: r.journal})
	assert.ErrorContains(t, err, "unsafe path")
}

// A linked directory inside the target never leads a write outside it.
func TestLinkedTargetDirectoryIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symbolic links needs a privilege on Windows")
	}
	t.Parallel()
	r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
	outside := t.TempDir()
	require.NoError(t, os.MkdirAll(r.target, 0o750))
	require.NoError(t, os.Symlink(outside, filepath.Join(r.target, "artifacts")))
	_, err := r.apply(context.Background(), continuity.Identity, nil)
	require.ErrorIs(t, err, continuity.ErrConflict)
	entries, err := os.ReadDir(outside)
	require.NoError(t, err)
	assert.Empty(t, entries, "nothing was written through the link")
}

// A transform that edits the slice it is given still has its rewrite
// planned and applied.
func TestMutatingTransformIsPlanned(t *testing.T) {
	t.Parallel()
	mutating := func(store, id string, data []byte) ([]byte, error) {
		if store == "registry" && strings.HasPrefix(id, "owners/") {
			out, err := lineage(store, id, data)
			if err != nil {
				return nil, err
			}
			for i := range data {
				data[i] = ' '
			}
			return out, nil
		}
		return data, nil
	}
	r := newRehearsal(t, continuity.ModeInPlace, mutating)
	assert.Equal(t, 1, r.plan.Rewrites)
	res, err := r.apply(context.Background(), mutating, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Written)
	assert.Empty(t, r.verify(t).Issues)
}

// An import keeps each file's permission bits.
func TestImportKeepsPermissions(t *testing.T) {
	skipApplyOnWindows(t)
	if runtime.GOOS == "windows" {
		t.Skip("no permission bits")
	}
	t.Parallel()
	l, _ := build(t)
	script := filepath.Join(l.DataDir, "workspaces", "tool.sh")
	require.NoError(t, os.MkdirAll(filepath.Dir(script), 0o750))
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755)) //nolint:gosec // an executable fixture file
	before := scan(t, l)
	plan, err := continuity.PlanTransition(before, l.DataDir, continuity.ModeImport, continuity.Identity, continuity.Policy{})
	require.NoError(t, err)
	target := filepath.Join(t.TempDir(), "data")
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	_, err = continuity.Apply(context.Background(), plan, continuity.ApplyOptions{SourceData: l.DataDir, TargetData: target, Journal: journal})
	require.NoError(t, err)
	info, err := os.Stat(filepath.Join(target, "workspaces", "tool.sh"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
	rs := roots(l)
	rs[0].Path = target
	after, err := continuity.Scan(context.Background(), continuity.Options{Roots: rs, ExpectedOwner: fixture.StableOwner})
	require.NoError(t, err)
	assert.Empty(t, continuity.VerifyTransition(before, after, plan, mustJournal(t, journal), continuity.Policy{}).Issues)
}

// Verification holds each rewritten record to the exact bytes the plan
// computed, not merely to equivalent JSON.
func TestVerifyChecksExactBytes(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeInPlace, lineage)
	_, err := r.apply(context.Background(), lineage, nil)
	require.NoError(t, err)
	p := filepath.Join(registry.Dir(r.l.DataDir), "owners", fixture.StableOwner+".json")
	data, err := os.ReadFile(p) //nolint:gosec // test path
	require.NoError(t, err)
	var v any
	require.NoError(t, json.Unmarshal(data, &v))
	compact, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p, compact, 0o600))
	assert.Positive(t, codes(r.verify(t).Issues, continuity.SeverityBlock)["step_result_differs"])
}

func skipApplyOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a transition runs on the Unix host that holds the store")
	}
}

// An import target reached through an alias of a directory inside the
// source, or a journal that is a link or a second name of a source file,
// is refused before anything is written.
func TestAliasesIntoTheSourceAreRefused(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
	before := treeState(t, r.l.Root)
	try := func(target, journal string) error {
		_, err := continuity.Apply(context.Background(), r.plan, continuity.ApplyOptions{SourceData: r.l.DataDir, TargetData: target, Journal: journal})
		return err
	}
	alias := filepath.Join(t.TempDir(), "alias")
	require.NoError(t, os.Symlink(filepath.Join(r.l.DataDir, "dag-runs"), alias))
	assert.Error(t, try(filepath.Join(alias, "imported"), r.journal), "a target under an alias of a source subdirectory")
	assert.Error(t, try(r.target, filepath.Join(alias, "journal.jsonl")), "a journal under an alias of a source subdirectory")

	protected := filepath.Join(r.l.DataDir, "proc", "journal.jsonl")
	require.NoError(t, os.MkdirAll(filepath.Dir(protected), 0o750))
	require.NoError(t, os.WriteFile(protected, nil, 0o600))
	before = treeState(t, r.l.Root)
	linked := filepath.Join(t.TempDir(), "journal.jsonl")
	require.NoError(t, os.Symlink(protected, linked))
	assert.Error(t, try(r.target, linked), "a journal that is a link to a source file")
	hard := filepath.Join(t.TempDir(), "journal.jsonl")
	require.NoError(t, os.Link(protected, hard))
	assert.Error(t, try(r.target, hard), "a journal that is another name of a source file")
	assert.Equal(t, before, treeState(t, r.l.Root), "nothing was written")
}

// A retained symbolic link is imported as the same link, never followed.
func TestImportKeepsLinks(t *testing.T) {
	skipApplyOnWindows(t)
	t.Parallel()
	l, _ := build(t)
	link := filepath.Join(l.DataDir, "workspaces", "current")
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o750))
	require.NoError(t, os.Symlink("../views/somewhere", link))
	before := scan(t, l)
	plan, err := continuity.PlanTransition(before, l.DataDir, continuity.ModeImport, continuity.Identity, continuity.Policy{})
	require.NoError(t, err)
	target := filepath.Join(t.TempDir(), "data")
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	_, err = continuity.Apply(context.Background(), plan, continuity.ApplyOptions{SourceData: l.DataDir, TargetData: target, Journal: journal})
	require.NoError(t, err)
	got, err := os.Readlink(filepath.Join(target, "workspaces", "current"))
	require.NoError(t, err)
	assert.Equal(t, "../views/somewhere", got)
	rs := roots(l)
	rs[0].Path = target
	after, err := continuity.Scan(context.Background(), continuity.Options{Roots: rs, ExpectedOwner: fixture.StableOwner})
	require.NoError(t, err)
	assert.Empty(t, continuity.VerifyTransition(before, after, plan, mustJournal(t, journal), continuity.Policy{}).Issues)
}

// A transform whose result would not hold together, such as a decision
// pointing at a proposal that does not exist, is refused at planning.
func TestTransformBreakingRelationshipsIsRefused(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	breaking := func(store, id string, data []byte) ([]byte, error) {
		if store == "registry" && strings.Contains(id, "/decisions/") {
			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				return nil, err
			}
			m["proposal_id"] = "prp_01M4ZZZZZZZZZZZZZZZZZZZZZZ"
			return indent(m)
		}
		return data, nil
	}
	_, err := continuity.PlanTransition(scan(t, l), l.DataDir, continuity.ModeInPlace, breaking, continuity.Policy{})
	require.ErrorIs(t, err, continuity.ErrBlocked)
	assert.ErrorContains(t, err, "dangling_ref")
}

// Resuming an import checks the source of a step that is already in the
// target: a source changed after it was copied stops the transition.
func TestImportResumeRechecksTheSource(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
	const k = 5
	_, err := r.apply(context.Background(), continuity.Identity, func(i int, p string) error {
		if i == k && p == "after_write" {
			return errCrash
		}
		return nil
	})
	require.ErrorIs(t, err, errCrash)
	require.NoError(t, os.WriteFile(filepath.Join(r.l.DataDir, filepath.FromSlash(r.plan.Steps[k].Path)), []byte(`{"changed":true}`), 0o600))
	_, err = r.apply(context.Background(), continuity.Identity, nil)
	require.ErrorIs(t, err, continuity.ErrConflict)
}

// A staging directory whose owner marker is not this transition's is left
// alone and stops the run.
func TestForeignStagingIsLeftAlone(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
	_, err := r.apply(context.Background(), continuity.Identity, func(i int, p string) error {
		if i == 2 && p == "staged" {
			return errCrash
		}
		return nil
	})
	require.ErrorIs(t, err, errCrash)
	matches, err := filepath.Glob(filepath.Join(r.target, ".txe-transition-staging-*", ".owner"))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.NoError(t, os.WriteFile(matches[0], []byte("someone-else"), 0o600))
	_, err = r.apply(context.Background(), continuity.Identity, nil)
	require.ErrorIs(t, err, continuity.ErrConflict)
	assert.FileExists(t, matches[0], "the foreign staging directory is kept")
}

// A crash while the staging directory is being prepared leaves nothing that
// stops the transition from resuming.
func TestInterruptedStagingPreparationResumes(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
	_, err := r.apply(context.Background(), continuity.Identity, func(i int, p string) error {
		if i == -1 && p == "staging_init" {
			return errCrash
		}
		return nil
	})
	require.ErrorIs(t, err, errCrash)
	_, err = r.apply(context.Background(), continuity.Identity, nil)
	require.NoError(t, err)
	left, err := filepath.Glob(filepath.Join(r.target, ".txe-transition-staging*"))
	require.NoError(t, err)
	assert.Empty(t, left)
	assert.Empty(t, r.verify(t).Issues)
}

// A journal inside an import target that does not exist yet is refused
// before the target is created.
func TestJournalInsideANewTargetIsRefused(t *testing.T) {
	t.Parallel()
	r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
	require.NoDirExists(t, r.target)
	_, err := continuity.Apply(context.Background(), r.plan, continuity.ApplyOptions{SourceData: r.l.DataDir, TargetData: r.target,
		Journal: filepath.Join(r.target, "journal.jsonl")})
	assert.ErrorContains(t, err, "inside the target")
	assert.NoDirExists(t, r.target, "nothing was created")
}

// A crash while the staging directory is being removed, at the end of a
// run, leaves nothing that stops the next run: the remains are renamed out
// of the way first and recognized as this transition's.
func TestInterruptedStagingTeardownResumes(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, done string){
		"after the rename": func(*testing.T, string) {},
		"after the marker was removed": func(t *testing.T, done string) {
			require.NoError(t, os.Remove(filepath.Join(done, ".owner")))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newRehearsal(t, continuity.ModeImport, continuity.Identity)
			_, err := r.apply(context.Background(), continuity.Identity, func(i int, p string) error {
				if p == "staging_teardown" {
					return errCrash
				}
				return nil
			})
			require.ErrorIs(t, err, errCrash)
			dones, err := filepath.Glob(filepath.Join(r.target, ".txe-transition-staging-*.done"))
			require.NoError(t, err)
			require.Len(t, dones, 1)
			damage(t, dones[0])
			again, err := r.apply(context.Background(), continuity.Identity, nil)
			require.NoError(t, err)
			assert.Zero(t, again.Written)
			left, err := filepath.Glob(filepath.Join(r.target, ".txe-transition-staging*"))
			require.NoError(t, err)
			assert.Empty(t, left)
			assert.Empty(t, r.verify(t).Issues)
		})
	}
}
