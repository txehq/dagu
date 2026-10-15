// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// listWorld is two owners with a machine DAG of A's and an ownerless DAG on
// file.
type listWorld struct {
	*twoOwners
	reviewerA, plain string
}

func newListWorld(t *testing.T, mode string) listWorld {
	t.Helper()
	w := newTwoOwners(t, mode)
	lw := listWorld{twoOwners: w, reviewerA: "txe-reviewer-" + w.machineA[len("mch_"):], plain: "nightly-backup"}
	spec := []byte("steps:\n  - name: s\n    run: echo s\n")
	require.NoError(t, w.api.dagRepository.Create(context.Background(), lw.reviewerA, spec))
	require.NoError(t, w.api.dagRepository.Create(context.Background(), lw.plain, spec))
	return lw
}

func (w listWorld) listedDAGs(t *testing.T, ctx context.Context, params apigen.ListDAGsParams) ([]string, apigen.Pagination) {
	t.Helper()
	resp, err := w.api.ListDAGs(ctx, apigen.ListDAGsRequestObject{Params: params})
	require.NoError(t, err)
	body := resp.(*apigen.ListDAGs200JSONResponse)
	var out []string
	for _, d := range body.Dags {
		out = append(out, d.FileName)
	}
	sort.Strings(out)
	return out, body.Pagination
}

func (w listWorld) listedRuns(t *testing.T, ctx context.Context) []string {
	t.Helper()
	resp, err := w.api.ListDAGRuns(ctx, apigen.ListDAGRunsRequestObject{})
	require.NoError(t, err)
	var out []string
	for _, r := range resp.(apigen.ListDAGRuns200JSONResponse).DagRuns {
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}

// The whole-hub lists show each caller what it may read DAG by DAG: a caller
// held to its owner its owner's DAGs and runs, whatever workspace it names,
// with pages and counts of what it is shown; a legacy key in enforce none;
// the administrator and a legacy key in off or observe everything, as before.
func TestTxeWholeHubListsByOwner(t *testing.T) {
	for _, mode := range []string{"", "observe", "enforce"} {
		t.Run("mode="+mode, func(t *testing.T) {
			w := newListWorld(t, mode)
			w.addRun(w.jobA, "run-a", "production")
			w.addRun(w.jobB, "run-b", "production")
			personA, cliA, personB, nobody := neutral(w.personA), neutral(w.cliA), neutral(w.personB), neutral(w.nobody)

			ownA := []string{w.jobA, w.reviewerA}
			sort.Strings(ownA)
			for _, ctx := range []context.Context{personA, cliA} {
				dags, _ := w.listedDAGs(t, ctx, apigen.ListDAGsParams{})
				require.Equal(t, ownA, dags)
				require.Equal(t, []string{w.jobA}, w.listedRuns(t, ctx))
				// Naming a workspace changes nothing: the owner decides.
				ws := "default"
				dags, _ = w.listedDAGs(t, ctx, apigen.ListDAGsParams{Workspace: &ws})
				require.Equal(t, ownA, dags)
			}
			dags, _ := w.listedDAGs(t, personB, apigen.ListDAGsParams{})
			require.Equal(t, []string{w.jobB}, dags)
			require.Equal(t, []string{w.jobB}, w.listedRuns(t, personB))
			dags, _ = w.listedDAGs(t, nobody, apigen.ListDAGsParams{})
			require.Empty(t, dags)
			require.Empty(t, w.listedRuns(t, nobody))

			// Pages are of what is shown.
			one := 1
			page, p := w.listedDAGs(t, personA, apigen.ListDAGsParams{PerPage: &one})
			require.Len(t, page, 1)
			require.True(t, p.HasNextPage)
			two := 2
			page, p = w.listedDAGs(t, personA, apigen.ListDAGsParams{PerPage: &one, Page: &two})
			require.Len(t, page, 1)
			require.False(t, p.HasNextPage)

			// Labels are of the listed DAGs only.
			labels, err := w.api.GetAllDAGLabels(personA, apigen.GetAllDAGLabelsRequestObject{})
			require.NoError(t, err)
			require.NotNil(t, labels)

			legacyDAGs, _ := w.listedDAGs(t, w.legacy, apigen.ListDAGsParams{})
			legacyRuns := w.listedRuns(t, w.legacy)
			if mode == "enforce" {
				require.Empty(t, legacyDAGs, "a legacy key in enforce reads no DAG")
				require.Empty(t, legacyRuns)
				l, err := w.api.GetAllDAGLabels(w.legacy, apigen.GetAllDAGLabelsRequestObject{})
				require.NoError(t, err)
				require.Empty(t, l.(*apigen.GetAllDAGLabels200JSONResponse).Labels)
			} else {
				require.Subset(t, legacyDAGs, []string{w.jobA, w.jobB, w.reviewerA, w.plain})
				require.Subset(t, legacyRuns, []string{w.jobA, w.jobB})
			}
			// One DAG's runs are decided as reading that DAG is.
			byName := func(ctx context.Context, name string) int {
				resp, err := w.api.ListDAGRunsByName(ctx, apigen.ListDAGRunsByNameRequestObject{Name: name})
				require.NoError(t, err)
				return len(resp.(apigen.ListDAGRunsByName200JSONResponse).DagRuns)
			}
			require.Equal(t, 1, byName(personA, w.jobA))
			require.Equal(t, 0, byName(personA, w.jobB), "another owner's runs")
			require.Equal(t, 0, byName(nobody, w.jobA))
			if mode == "enforce" {
				require.Equal(t, 0, byName(w.legacy, w.jobA), "a legacy key in enforce reads no owner's runs")
			} else {
				require.Equal(t, 1, byName(w.legacy, w.jobA))
			}
			require.Equal(t, 1, byName(w.admin, w.jobA))

			adminDAGs, _ := w.listedDAGs(t, w.admin, apigen.ListDAGsParams{})
			require.Subset(t, adminDAGs, []string{w.jobA, w.jobB, w.reviewerA, w.plain})
		})
	}
}

// A run is listed to a caller held to its owner as S4 decides reading it: by
// its root's DAG, and by its own DAG too when that is another owner's.
func TestTxeRunListedDecidesRootAndOwnDAG(t *testing.T) {
	jobA, jobB := "job_01M4AAAAAAAAAAAAAAAAAAAAAA", "job_01M4BBBBBBBBBBBBBBBBBBBBBB"
	listed := txeRunListed(map[string]bool{jobA: true})
	run := func(root, name string) *ir.DAGRunStatus {
		s := &ir.DAGRunStatus{Name: name}
		if root != "" {
			s.Root = ir.NewDAGRunRef(root, "r1")
		}
		return s
	}
	require.True(t, listed(run("", jobA)), "A's own root run")
	require.True(t, listed(run(jobA, jobA)), "A's root run, root named")
	require.True(t, listed(run(jobA, "local-child")), "an ownerless child of A's run")
	require.False(t, listed(run(jobB, jobA)), "A's job called from B's run")
	require.False(t, listed(run(jobA, jobB)), "B's job called from A's run")
	require.False(t, listed(run("", jobB)), "B's run")
	require.False(t, listed(run(jobA, "")), "a run that names no DAG")
	require.False(t, listed(run("", "nightly-backup")), "an ownerless root")
}

// A DAG on file whose declared name is an owner's is not that owner's DAG:
// the list does not show it as one.
func TestTxeWholeHubListsIgnoreADeclaredOwnerName(t *testing.T) {
	w := newListWorld(t, "enforce")
	spec := []byte("name: " + w.jobA + "\nsteps:\n  - name: s\n    run: echo s\n")
	require.NoError(t, w.api.dagRepository.Create(context.Background(), "masquerade", spec))
	dags, _ := w.listedDAGs(t, neutral(w.personA), apigen.ListDAGsParams{})
	require.NotContains(t, dags, "masquerade")
}

// A registry that cannot be enumerated is an outage to a caller held to its
// owner, on every list, never a shorter or a misleading one.
func TestTxeWholeHubListsRegistryFailure(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	for _, dir := range []string{"jobs", "machines"} {
		t.Run(dir, func(t *testing.T) {
			w := newListWorld(t, "enforce")
			w.addRun(w.jobA, "run-a", "production")
			personA := neutral(w.personA)
			path := filepath.Join(registry.Dir(w.dataDir), dir)
			require.NoError(t, os.Chmod(path, 0))
			t.Cleanup(func() { _ = os.Chmod(path, 0o750) })

			_, err := w.api.ListDAGs(personA, apigen.ListDAGsRequestObject{})
			require.Equal(t, http.StatusServiceUnavailable, statusOf(err), "GET /dags")
			_, err = w.api.ListDAGRuns(personA, apigen.ListDAGRunsRequestObject{})
			require.Equal(t, http.StatusServiceUnavailable, statusOf(err), "GET /dag-runs")
			_, err = w.api.ListDAGRunsByName(personA, apigen.ListDAGRunsByNameRequestObject{Name: w.jobA})
			require.Equal(t, http.StatusServiceUnavailable, statusOf(err), "GET /dag-runs/{name}")
		})
	}
}
