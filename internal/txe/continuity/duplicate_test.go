// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// race is the losing side of two sessions registering one job key at once,
// as the client leaves it: the package staged under the request, the hub's
// refusal received, and nothing moved to the path the version names.
type race struct {
	jobID, winner, requestID, digest string
}

func loseRace(t *testing.T, l *fixture.Layout, f *fixture.Facts) race {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("packages are staged only on the Unix machine that runs them")
	}
	ctx := context.Background()
	dags := registry.NewDAGStore(persis.NewDAGRepository(dag.NewStore(l.DAGsDir), persis.DAGRepositoryOptions{}))
	s, err := registry.NewFileStore(l.DataDir, registry.WithDAGStore(dags))
	require.NoError(t, err)
	winner, err := s.GetJob(ctx, f.Jobs["health-check"])
	require.NoError(t, err)
	v, err := s.GetVersion(ctx, winner.JobID, winner.Version)
	require.NoError(t, err)

	src := filepath.Join(l.Root, "src", "race")
	require.NoError(t, os.MkdirAll(src, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(src, "run.sh"), []byte("#!/bin/sh\necho race\n"), 0o700)) //nolint:gosec // a fixture script
	requestID, err := registry.NewID(registry.Prefix("req"), time.Now())
	require.NoError(t, err)
	store := &txepkg.Store{Root: filepath.Join(l.MachineHome, "packages")}
	staged, err := store.Stage(requestID, txepkg.BuildOptions{SourceRoot: src, Include: []string{"run.sh"}, Entrypoint: []string{"./run.sh"},
		Provenance: txepkg.Provenance{Repository: "github.com/fixture/app", SourceRoot: src, Session: "race-session"}})
	require.NoError(t, err)

	jobID, err := registry.NewID(registry.PrefixJob, time.Now())
	require.NoError(t, err)
	dir, err := store.PackageDir(jobID, staged.Digest)
	require.NoError(t, err)
	// The same job as the winner's, under the other session's IDs.
	nv := registry.JobVersion{Title: v.Title, Purpose: v.Purpose, Origin: v.Origin, DAG: registry.DAGRef{Spec: v.DAG.Spec},
		Schedule: v.Schedule, Targets: v.Targets, ExpectedOutcome: v.ExpectedOutcome, ReviewPolicy: v.ReviewPolicy}
	nv.Package = registry.Package{Digest: staged.Digest, Path: dir, Entrypoint: "run.sh"}
	journal := &txepkg.Journal{Dir: filepath.Join(l.MachineHome, "receipts")}
	entry, err := journal.Begin(txepkg.Entry{RequestID: requestID, Operation: txepkg.OpRegister, JobID: jobID, JobKey: winner.Registration.JobKey,
		Version: 1, MachineID: winner.MachineID, OwnerID: fixture.StableOwner, Step: txepkg.StepStaged, PackageDigest: staged.Digest, Session: "race-session"})
	require.NoError(t, err)
	_, err = s.Register(ctx, registry.RegisterInput{JobID: jobID, RequestID: requestID, OwnerID: fixture.StableOwner,
		ProjectID: winner.ProjectID, MachineID: winner.MachineID, JobKey: winner.Registration.JobKey, Version: nv}, client)
	require.Equal(t, registry.CodeDuplicate, registry.ErrorCode(err), "%v", err)
	// The client stops here: the request is refused, its journal entry
	// keeps the refusal, and the package stays staged where no worker
	// resolves it.
	entry.Step, entry.Error = txepkg.StepRejected, err.Error()
	require.NoError(t, journal.Save(entry))
	_, err = s.MarkReady(ctx, jobID, 0, registry.PackageEvidence{Digest: staged.Digest, Path: dir, MachineID: winner.MachineID}, client)
	require.Equal(t, registry.CodeDuplicate, registry.ErrorCode(err), "the registry takes no evidence for a duplicate: %v", err)
	_, err = os.Stat(filepath.Join(l.MachineHome, "packages", jobID))
	require.ErrorIs(t, err, os.ErrNotExist)

	j := job(t, l, jobID)
	reg := j["registration"].(map[string]any)
	require.Equal(t, "duplicate", reg["state"])
	require.Equal(t, winner.JobID, reg["duplicate_of"])
	require.NotContains(t, reg, "package")
	return race{jobID: jobID, winner: winner.JobID, requestID: requestID, digest: staged.Digest}
}

func issuesFor(issues []continuity.Issue, code, idPrefix string) []continuity.Issue {
	var out []continuity.Issue
	for _, i := range issues {
		if i.Code == code && strings.HasPrefix(i.ID, idPrefix) {
			out = append(out, i)
		}
	}
	return out
}

// A duplicate registration never had its package delivered: the registry
// refuses its evidence and its client keeps the package staged. Its
// version's package is reported by name, not required, whether the job is
// active or retired, and the staged copy is retained and compared.
func TestDuplicateRegistrationNeedsNoPackage(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	baseline := continuity.Validate(scan(t, l), continuity.Policy{})
	r := loseRace(t, l, f)

	check := func(t *testing.T, inv *continuity.Inventory) {
		t.Helper()
		issues := continuity.Validate(inv, continuity.Policy{})
		assert.Empty(t, continuity.Blocking(issues))
		warned := issuesFor(issues, "package_not_delivered", "registry/history/"+r.jobID+"/versions/")
		require.Len(t, warned, 1, "%v", issues)
		assert.Equal(t, continuity.SeverityWarn, warned[0].Severity)
		assert.Contains(t, warned[0].Detail, r.digest)
		assert.Contains(t, warned[0].Detail, r.winner)
		assert.Len(t, issues, len(baseline)+1, "the one warning is the only new issue: %v", issues)
	}
	check(t, scan(t, l))
	hub, machine := hubAndMachine(t, l)
	joint, err := continuity.Reconcile(hub, machine)
	require.NoError(t, err)
	check(t, joint)

	staged := "packages/.staging/" + r.requestID + "/" + txepkg.ManifestName
	pending := "receipts/pending/" + r.requestID + ".json"
	files := filesByKey(joint)
	require.Contains(t, files, "laptop-home/"+staged, "the staged copy is retained")
	assert.Equal(t, r.digest, files["laptop-home/"+staged].SHA256, "a package's digest is its manifest's")
	require.Contains(t, files, "laptop-home/"+pending, "the refused request's journal entry is retained")

	s, err := registry.NewFileStore(l.DataDir)
	require.NoError(t, err)
	_, err = s.ChangeLifecycle(context.Background(), r.jobID, registry.Transition{Op: registry.OpRetire, Reason: registry.RetireManual, Detail: "acceptance fixture finished"}, client)
	require.NoError(t, err)
	before := scan(t, l)
	check(t, before)

	// The staged copy or the journal entry lost blocks a transition.
	require.NoError(t, os.RemoveAll(filepath.Join(l.MachineHome, "packages", ".staging", r.requestID)))
	require.NoError(t, os.Remove(homePath(l, pending)))
	var missing []string
	for _, i := range continuity.Compare(before, scan(t, l), continuity.CompareOptions{}).Issues {
		require.Equal(t, "file_missing", i.Code, "%s %s", i.ID, i.Detail)
		missing = append(missing, i.ID)
	}
	assert.ElementsMatch(t, []string{"laptop-home/" + staged, "laptop-home/packages/.staging/" + r.requestID + "/files/run.sh", "laptop-home/" + pending}, missing)
}

// Every package the registry was told was delivered is still required: the
// rule names a duplicate the registry wrote, and nothing about lifecycle.
func TestDeliveredPackagesAreStillRequired(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string
	}{
		{"a duplicate whose record carries package evidence", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string {
			r := loseRace(t, l, f)
			edit(t, regPath(l, "jobs/"+r.jobID), func(m map[string]any) {
				m["registration"].(map[string]any)["package"] = map[string]any{"digest": r.digest, "path": "/elsewhere", "machine_id": f.Machine,
					"asserted_at": "2026-10-12T09:35:05Z", "asserted_by": map[string]any{"kind": "cli", "id": "admin"}}
			})
			return r.jobID
		}},
		{"a duplicate whose package evidence names no machine", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string {
			r := loseRace(t, l, f)
			edit(t, regPath(l, "jobs/"+r.jobID), func(m map[string]any) {
				m["registration"].(map[string]any)["package"] = map[string]any{"digest": r.digest, "path": "/elsewhere",
					"asserted_at": "2026-10-12T09:35:05Z", "asserted_by": map[string]any{"kind": "cli", "id": "admin"}}
			})
			return r.jobID
		}},
		{"a duplicate that names no job it duplicates", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string {
			r := loseRace(t, l, f)
			edit(t, regPath(l, "jobs/"+r.jobID), func(m map[string]any) { delete(m["registration"].(map[string]any), "duplicate_of") })
			return r.jobID
		}},
		{"a retired job's package lost", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string {
			jobID := f.Jobs["manual-retire"]
			require.NoError(t, fixture.Unseal(homePath(l, "packages/"+jobID)))
			require.NoError(t, os.RemoveAll(homePath(l, "packages/"+jobID)))
			return jobID
		}},
		{"the winner's package lost", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string {
			jobID := f.Jobs["collector-dup"]
			require.NoError(t, fixture.Unseal(homePath(l, "packages/"+jobID)))
			require.NoError(t, os.RemoveAll(homePath(l, "packages/"+jobID)))
			return jobID
		}},
		{"an incomplete job's earlier version lost", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string {
			jobID := f.Jobs["superseded"]
			require.Len(t, f.Packages[jobID], 2)
			store := &txepkg.Store{Root: filepath.Join(l.MachineHome, "packages")}
			dir, err := store.PackageDir(jobID, f.Packages[jobID][0])
			require.NoError(t, err)
			require.NoError(t, fixture.Unseal(dir))
			require.NoError(t, os.RemoveAll(dir))
			return jobID
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, f := build(t)
			jobID := tc.break_(t, l, f)
			issues := continuity.Validate(scan(t, l), continuity.Policy{})
			blocked := issuesFor(continuity.Blocking(issues), "package_missing", "registry/history/"+jobID+"/versions/")
			assert.Len(t, blocked, 1, "%v", issues)
			assert.Empty(t, issuesFor(issues, "package_not_delivered", ""), "%v", issues)
		})
	}
}

// A duplicate's package that is there is checked like any other, and its
// loss blocks a transition: only Validate's demand for one is waived.
func TestDuplicatePackageLossBlocksCompare(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	jobID := f.Jobs["duplicate"]
	require.Equal(t, "duplicate", job(t, l, jobID)["registration"].(map[string]any)["state"])
	require.NotEmpty(t, f.Packages[jobID], "the fixture's duplicate has a package in place")
	before := scan(t, l)
	issues := continuity.Validate(before, continuity.Policy{})
	assert.Empty(t, continuity.Blocking(issues))
	assert.Empty(t, issuesFor(issues, "package_not_delivered", ""), "a package in place is not reported")

	require.NoError(t, fixture.Unseal(homePath(l, "packages/"+jobID)))
	require.NoError(t, os.RemoveAll(homePath(l, "packages/"+jobID)))
	after := scan(t, l)
	assert.Len(t, issuesFor(continuity.Validate(after, continuity.Policy{}), "package_not_delivered", "registry/history/"+jobID+"/versions/"), 1)
	missing := 0
	for _, i := range continuity.Compare(before, after, continuity.CompareOptions{}).Issues {
		if i.Code == "file_missing" && strings.HasPrefix(i.ID, "laptop-home/packages/"+jobID+"/") {
			missing++
		}
	}
	assert.Positive(t, missing)
	assert.Positive(t, compareCodes(continuity.CompareProgress(before, after))["file_missing"])
}
