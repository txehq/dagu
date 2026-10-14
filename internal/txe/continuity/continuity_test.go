// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Registers step executors so the fixture's DAG specs load as they do in
	// the server.
	_ "github.com/dagucloud/dagu/v2/internal/runtime/builtin"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
)

var scanTime = time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)

var (
	templateOnce   sync.Once
	templateDir    string
	templateLayout *fixture.Layout
	templateFacts  *fixture.Facts
	templateErr    error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if templateDir != "" {
		_ = fixture.Unseal(templateDir)
		_ = os.RemoveAll(templateDir)
	}
	os.Exit(code)
}

// build returns a private copy of the fixture, which is built once.
func build(t *testing.T) (*fixture.Layout, *fixture.Facts) {
	t.Helper()
	templateOnce.Do(func() {
		templateDir, templateErr = os.MkdirTemp("", "continuity-fixture-")
		if templateErr == nil {
			templateLayout, templateFacts, templateErr = fixture.Build(context.Background(), filepath.Join(templateDir, "root"))
		}
	})
	require.NoError(t, templateErr)
	root := filepath.Join(t.TempDir(), "root")
	t.Cleanup(func() { _ = fixture.Unseal(root) })
	copyPreserving(t, templateLayout.Root, root, nil)
	rebase := func(p string) string {
		rel, err := filepath.Rel(templateLayout.Root, p)
		require.NoError(t, err)
		return filepath.Join(root, rel)
	}
	l := &fixture.Layout{Root: root, DataDir: rebase(templateLayout.DataDir), DAGsDir: rebase(templateLayout.DAGsDir),
		MachineHome: rebase(templateLayout.MachineHome), HubMount: templateLayout.HubMount}
	return l, templateFacts
}

func roots(l *fixture.Layout) []continuity.Root {
	return []continuity.Root{
		{Area: continuity.AreaHubData, Path: l.DataDir, Label: "hub-data", Mount: l.HubMount},
		{Area: continuity.AreaDAGs, Path: l.DAGsDir, Label: "hub-dags"},
		{Area: continuity.AreaMachineHome, Path: l.MachineHome, Label: "laptop-home"},
	}
}

func scan(t *testing.T, l *fixture.Layout) *continuity.Inventory {
	t.Helper()
	inv, err := continuity.Scan(context.Background(), continuity.Options{Roots: roots(l), ExpectedOwner: fixture.StableOwner,
		Label: "test", Now: func() time.Time { return scanTime }})
	require.NoError(t, err)
	return inv
}

func codes(issues []continuity.Issue, severity string) map[string]int {
	out := map[string]int{}
	for _, i := range issues {
		if i.Severity == severity {
			out[i.Code]++
		}
	}
	return out
}

// The representative fixture validates with no blocking issue, and its
// inventory holds every record kind a phase-one installation keeps.
func TestFixtureValidates(t *testing.T) {
	l, f := build(t)
	inv := scan(t, l)
	issues := continuity.Validate(inv, continuity.Policy{})
	for _, i := range continuity.Blocking(issues) {
		t.Errorf("blocking: %s %s %s: %s", i.Code, i.Class, i.ID, i.Detail)
	}
	warn := codes(issues, continuity.SeverityWarn)
	assert.Equal(t, 1, warn["uncommitted_history"], "the uncommitted lifecycle event is retained and reported")

	for _, class := range []string{
		continuity.ClassOwner, continuity.ClassProject, continuity.ClassMachine, continuity.ClassJob, continuity.ClassVersion,
		continuity.ClassEvent, continuity.ClassDecision, continuity.ClassReview, continuity.ClassAction, continuity.ClassProposal,
		continuity.ClassDedupe, continuity.ClassProjectKey, continuity.ClassResourceID, continuity.ClassResourceName,
		continuity.ClassResourceEvent, continuity.ClassResourceIndexReady, continuity.ClassArtifactManifest,
		continuity.ClassExecutionEvidence, continuity.ClassBindingRequest, continuity.ClassBinding, continuity.ClassPackage,
		continuity.ClassMachineIdentity, continuity.ClassEnrolment, continuity.ClassEnrolmentKey,
	} {
		assert.Positive(t, inv.Counts[class], "fixture holds a %s", class)
	}
	assert.Equal(t, len(f.Jobs), inv.Counts[continuity.ClassJob], "every job, incomplete and duplicate ones too")
	// Pending human work is held live in a job, not only in history.
	states := map[string]bool{}
	for _, p := range job(t, l, f.Jobs["data-collector"])["proposals"].(map[string]any) {
		states[p.(map[string]any)["state"].(string)] = true
	}
	assert.Equal(t, map[string]bool{"open": true, "snoozed": true, "decided": true}, states)
	for _, i := range issues {
		t.Logf("%s %s %s %s", i.Severity, i.Code, i.ID, i.Detail)
	}
	b, err := json.MarshalIndent(inv.Counts, "", "  ")
	require.NoError(t, err)
	t.Logf("counts: %s", b)
}

// copyPreserving copies a tree with each file's and directory's permission
// bits, so a sealed package stays sealed. keep, when set, selects files by
// slash-separated path relative to from.
func copyPreserving(t *testing.T, from, to string, keep func(rel string) bool) {
	t.Helper()
	type dirMode struct {
		path string
		mode fs.FileMode
	}
	var dirs []dirMode
	require.NoError(t, filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, dirMode{dst, info.Mode().Perm()})
			return os.MkdirAll(dst, 0o750)
		}
		if keep != nil && !keep(filepath.ToSlash(rel)) {
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // test fixture path
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		return os.WriteFile(dst, data, info.Mode().Perm())
	}))
	for _, dir := range slices.Backward(dirs) {
		require.NoError(t, os.Chmod(dir.path, dir.mode))
	}
}
