// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// neutral is what txeNeutralize does to a caller held to its owner on its
// way to a handler: the same caller, with a hub user that has no role and
// no workspace.
func neutral(ctx context.Context) context.Context {
	c := txeauth.Classify(ctx)
	user, _ := auth.UserFromContext(ctx)
	return auth.WithUser(ctx, txeNeutralUser(c, user))
}

func TestTxeNeutralizeTakesTheHubRoleAway(t *testing.T) {
	w := newTwoOwners(t, "")
	var seen *auth.User
	h := w.api.txeNeutralize(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen, _ = auth.UserFromContext(r.Context()) }))
	serve := func(ctx context.Context) *auth.User {
		seen = nil
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/dags", nil).WithContext(ctx))
		return seen
	}

	// A person provisioned as an administrator keeps its name and identity
	// and loses the role and every workspace.
	admin := ownersPerson("a")
	got := serve(admin)
	require.Equal(t, auth.RoleNone, got.Role)
	require.Equal(t, "user-a", got.Username)
	require.Equal(t, auth.AuthProviderOIDC, got.AuthProvider)
	require.False(t, auth.NormalizeWorkspaceAccess(got.WorkspaceAccess).All)
	require.Empty(t, got.WorkspaceAccess.Grants)
	require.Equal(t, txeauth.KindPerson, txeauth.Classify(auth.WithUser(admin, got)).Kind)

	// A token gets a hub user of the same kind, named as its agent.
	got = serve(w.cliA)
	require.Equal(t, auth.RoleNone, got.Role)
	require.Equal(t, "token:dagu-cli:a", got.Username)

	// Everyone else is untouched.
	require.Equal(t, auth.RoleAdmin, serve(w.admin).Role)
	require.Equal(t, auth.RoleAdmin, serve(w.legacy).Role)
}

func TestTxeNativeRunsAreOwnerScoped(t *testing.T) {
	w := newTwoOwners(t, "")
	w.markReady(w.jobA, w.machineA)
	w.addRun(w.jobA, "run-1", "production")
	personA, personB, cliA, reviewerA, reviewerB := neutral(w.personA), neutral(w.personB), neutral(w.cliA), neutral(w.reviewerA), neutral(w.reviewerB)

	// These handlers answer a refusal with a typed 404 response and no
	// error, so the response itself is what is checked.
	details := func(ctx context.Context) error {
		resp, err := w.api.GetDAGRunDetails(ctx, apigen.GetDAGRunDetailsRequestObject{Name: w.jobA, DagRunId: "run-1"})
		if err != nil {
			return err
		}
		if _, ok := resp.(*apigen.GetDAGRunDetails200JSONResponse); !ok {
			return &Error{HTTPStatus: http.StatusNotFound, Message: "no details"}
		}
		return nil
	}
	logs := func(ctx context.Context) error {
		resp, err := w.api.GetDAGRunLog(ctx, apigen.GetDAGRunLogRequestObject{Name: w.jobA, DagRunId: "run-1"})
		if err != nil {
			return err
		}
		if _, ok := resp.(apigen.GetDAGRunLog200JSONResponse); !ok {
			return &Error{HTTPStatus: http.StatusNotFound, Message: "no log"}
		}
		return nil
	}
	// The owner's person, CLI and the job's own machine see the run, with
	// no workspace grant for "production"; another owner does not learn it
	// exists.
	for _, ctx := range []context.Context{personA, cliA, reviewerA} {
		require.NoError(t, details(ctx))
		require.NoError(t, logs(ctx))
	}
	for _, ctx := range []context.Context{personB, reviewerB, neutral(w.nobody)} {
		require.Equal(t, http.StatusNotFound, statusOf(details(ctx)))
		require.Equal(t, http.StatusNotFound, statusOf(logs(ctx)))
	}
	// A legacy credential in mode off reads as today.
	require.NoError(t, details(w.legacy))

	// Runs of one DAG: the owner sees them, another owner sees none.
	byName := func(ctx context.Context) int {
		resp, err := w.api.ListDAGRunsByName(ctx, apigen.ListDAGRunsByNameRequestObject{Name: w.jobA})
		require.NoError(t, err)
		return len(resp.(apigen.ListDAGRunsByName200JSONResponse).DagRuns)
	}
	require.Equal(t, 1, byName(personA))
	require.Zero(t, byName(personB))

	// Execute: a person of another owner is not told; the owner's
	// reviewer may stop the job's run.
	stop := func(ctx context.Context) error {
		_, err := w.api.TerminateDAGRun(ctx, apigen.TerminateDAGRunRequestObject{Name: w.jobA, DagRunId: "run-1"})
		return err
	}
	require.Equal(t, http.StatusNotFound, statusOf(stop(personB)))
	require.NotEqual(t, http.StatusNotFound, statusOf(stop(reviewerA)))
	require.NotEqual(t, http.StatusForbidden, statusOf(stop(reviewerA)))
}

func TestTxeNativeDAGsAreOwnerScoped(t *testing.T) {
	w := newTwoOwners(t, "")
	w.addRun(w.jobA, "run-1", "production")
	personA, personB := neutral(w.personA), neutral(w.personB)

	history := func(ctx context.Context, dag string) error {
		resp, err := w.api.GetDAGDAGRunHistory(ctx, apigen.GetDAGDAGRunHistoryRequestObject{FileName: dag})
		if err != nil {
			return err
		}
		if _, ok := resp.(apigen.GetDAGDAGRunHistory200JSONResponse); !ok {
			return &Error{HTTPStatus: http.StatusNotFound, Message: "no history"}
		}
		return nil
	}
	require.NoError(t, history(personA, w.jobA))
	require.Equal(t, http.StatusNotFound, statusOf(history(personB, w.jobA)))

	// The whole-hub DAG list shows such a caller nothing; its jobs are in
	// /txe/jobs.
	resp, err := w.api.ListDAGs(personA, apigen.ListDAGsRequestObject{})
	require.NoError(t, err)
	require.Empty(t, resp.(*apigen.ListDAGs200JSONResponse).Dags)
	resp, err = w.api.ListDAGs(w.legacy, apigen.ListDAGsRequestObject{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.(*apigen.ListDAGs200JSONResponse).Dags, "a legacy key in mode off lists as today")

	// A job DAG's spec is the registry's: it is not written natively by
	// anyone held to an owner, its owner included.
	spec := "steps:\n  - name: run\n    run: echo hi\n"
	_, err = w.api.UpdateDAGSpec(personA, apigen.UpdateDAGSpecRequestObject{FileName: w.jobA, Body: &apigen.UpdateDAGSpecJSONRequestBody{Spec: spec}})
	require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, statusOf(err))
	_, err = w.api.DeleteDAG(personA, apigen.DeleteDAGRequestObject{FileName: w.jobA})
	require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, statusOf(err))
	_, err = w.reg.GetJob(context.Background(), w.jobA)
	require.NoError(t, err)
}

func TestTxeNativeCheckOwnerlessAndModes(t *testing.T) {
	ctx := context.Background()
	off := newTwoOwners(t, "")
	legacy := func(error) func() error { return func() error { return nil } }

	// A DAG with no owner is the platform's.
	require.Equal(t, http.StatusNotFound, statusOf(off.api.txeNativeCheck(neutral(off.personA), "nightly-backup", authz.PermissionView, legacy(nil))))
	require.NoError(t, off.api.txeNativeCheck(off.legacy, "nightly-backup", authz.PermissionView, legacy(nil)))
	// Per-machine DAGs belong to the machine's owner.
	reviewerDAG := "txe-reviewer-" + off.machineA[len("mch_"):]
	require.NoError(t, off.api.txeNativeCheck(neutral(off.personA), reviewerDAG, authz.PermissionView, legacy(nil)))
	require.Equal(t, http.StatusNotFound, statusOf(off.api.txeNativeCheck(neutral(off.personB), reviewerDAG, authz.PermissionView, legacy(nil))))

	enforce := newTwoOwners(t, "enforce")
	// In enforce a legacy key sees no owner's DAG and no ownerless one; the
	// administrator sees both and runs none of an owner's.
	require.Equal(t, http.StatusNotFound, statusOf(enforce.api.txeNativeCheck(enforce.legacy, enforce.jobA, authz.PermissionView, legacy(nil))))
	require.Equal(t, http.StatusNotFound, statusOf(enforce.api.txeNativeCheck(enforce.legacy, "nightly-backup", authz.PermissionView, legacy(nil))))
	require.NoError(t, enforce.api.txeNativeCheck(enforce.admin, enforce.jobA, authz.PermissionView, legacy(nil)))
	require.NoError(t, enforce.api.txeNativeCheck(enforce.admin, "nightly-backup", authz.PermissionView, legacy(nil)))
	require.Equal(t, http.StatusForbidden, statusOf(enforce.api.txeNativeCheck(enforce.admin, enforce.jobA, authz.PermissionExecute, legacy(nil))))

	observe := newTwoOwners(t, "observe")
	require.NoError(t, observe.api.txeNativeCheck(observe.legacy, observe.jobA, authz.PermissionView, legacy(nil)))
	require.NoError(t, observe.api.txeNativeCheck(observe.legacy, "nightly-backup", authz.PermissionExecute, legacy(nil)))
	_ = ctx
}

func TestTxeNativeValidateIsClosedToOwnerHeldCallers(t *testing.T) {
	w := newTwoOwners(t, "")
	spec := "steps:\n  - name: run\n    run: echo hi\n"
	_, err := w.api.ValidateDAGSpec(neutral(w.personA), apigen.ValidateDAGSpecRequestObject{Body: &apigen.ValidateDAGSpecJSONRequestBody{Spec: spec}})
	require.Equal(t, http.StatusForbidden, statusOf(err))
	_, err = w.api.ValidateDAGSpec(w.legacy, apigen.ValidateDAGSpecRequestObject{Body: &apigen.ValidateDAGSpecJSONRequestBody{Spec: spec}})
	require.NoError(t, err)
}

// A run of another owner's job DAG, called as a sub-DAG from one's own job,
// is not one's own: it is decided by its own DAG's owner too.
func TestTxeNativeSubRunOfAnotherOwnersDAG(t *testing.T) {
	w := newTwoOwners(t, "")
	sub := &ir.DAGRunStatus{Name: w.jobB, Root: ir.NewDAGRunRef(w.jobA, "run-1")}
	require.Equal(t, http.StatusNotFound, statusOf(w.api.requireDAGRunStatusVisible(neutral(w.personA), sub)))
	require.Equal(t, http.StatusNotFound, statusOf(w.api.requireDAGRunStatusVisible(neutral(w.personB), sub)))

	// A sub-run of a DAG with no owner, under one's own job, is one's own.
	own := &ir.DAGRunStatus{Name: "shared-helper", Root: ir.NewDAGRunRef(w.jobA, "run-1")}
	require.NoError(t, w.api.requireDAGRunStatusVisible(neutral(w.personA), own))
	require.Equal(t, http.StatusNotFound, statusOf(w.api.requireDAGRunStatusVisible(neutral(w.personB), own)))
	// A legacy key in mode off is decided by workspace alone, as before.
	require.NoError(t, w.api.requireDAGRunStatusVisible(w.legacy, sub))
}

// Search is not owner-scoped, so it is closed to a caller held to its owner.
func TestTxeNativeSearchIsClosedToOwnerHeldCallers(t *testing.T) {
	w := newTwoOwners(t, "")
	_, err := w.api.SearchDAGs(neutral(w.personA), apigen.SearchDAGsRequestObject{Params: apigen.SearchDAGsParams{Q: "echo"}})
	require.Equal(t, http.StatusForbidden, statusOf(err))
	_, err = w.api.SearchDAGs(neutral(w.cliA), apigen.SearchDAGsRequestObject{Params: apigen.SearchDAGsParams{Q: "echo"}})
	require.Equal(t, http.StatusForbidden, statusOf(err))
	_, err = w.api.SearchDAGs(w.legacy, apigen.SearchDAGsRequestObject{Params: apigen.SearchDAGsParams{Q: "echo"}})
	require.NoError(t, err)
}

// A DAG's owner is read from its definition's file, so a file declaring an
// owner's DAG name is not that DAG, and an owner's file declaring another
// name is no one's.
func TestTxeNativeAliasOfAnOwnersDAG(t *testing.T) {
	w := newTwoOwners(t, "")
	personA := neutral(w.personA)
	reviewerDAG := "txe-reviewer-" + w.machineA[len("mch_"):]
	at := func(file, declared string) *ir.DAG {
		return &ir.DAG{Location: filepath.Join("/dags", file+".yaml"), Name: declared}
	}

	require.NoError(t, w.api.requireDAGVisible(personA, at(w.jobA, w.jobA)))
	require.NoError(t, w.api.requireDAGVisible(personA, at(w.jobA, "")))
	require.NoError(t, w.api.requireDAGVisible(personA, at(reviewerDAG, reviewerDAG)))
	for _, alias := range []*ir.DAG{
		at("monitor", w.jobA),
		at("monitor", reviewerDAG),
		at(w.jobA, "monitor"),
		at(w.jobA, w.jobB),
	} {
		require.Equal(t, http.StatusNotFound, statusOf(w.api.requireDAGVisible(personA, alias)), alias.Location)
		require.Equal(t, http.StatusNotFound, statusOf(w.api.requireDAGExecute(personA, alias)), alias.Location)
	}
	// A legacy credential in mode off is decided by workspace alone.
	require.NoError(t, w.api.requireDAGVisible(w.legacy, at("monitor", w.jobA)))
}

// writeRun saves a finished run of d, edited by edit, in the fixture's run
// store (which addRun creates).
func (w *twoOwners) writeRun(d *ir.DAG, runID string, opts persis.DAGRunCreateAttemptOptions, edit func(*ir.DAGRunStatus)) {
	w.t.Helper()
	ctx := context.Background()
	attempt, err := w.runs.CreateAttempt(ctx, d, time.Now(), runID, opts)
	require.NoError(w.t, err)
	status := ir.InitialStatus(d)
	status.DAGRunID, status.AttemptID, status.Status = runID, attempt.ID(), ir.Succeeded
	status.Labels = []string{"workspace=production"}
	status.Log = filepath.Join(w.t.TempDir(), runID+".log")
	require.NoError(w.t, os.WriteFile(status.Log, []byte("output of "+d.Name+"\n"), 0o600))
	edit(&status)
	require.NoError(w.t, attempt.Open(ctx))
	require.NoError(w.t, attempt.Write(ctx, status))
	require.NoError(w.t, attempt.Close(ctx))
}

// A sub-run of another owner's DAG, called from one's own job's run, is
// not one's own on any sub-run route: its spec is not found, the sub-run
// list leaves it out, and its step log is refused. A sub-run of a DAG with
// no owner stays one's own.
func TestTxeNativeSubRunRoutesOfAnotherOwnersDAG(t *testing.T) {
	w := newTwoOwners(t, "")
	w.addRun(w.jobA, "run-1", "production")
	root := ir.NewDAGRunRef(w.jobA, "run-2")
	child := func(name, runID string) {
		d := &ir.DAG{Name: name, YamlData: []byte("steps:\n  - name: inner\n    run: echo " + name + "\n")}
		w.writeRun(d, runID, persis.DAGRunCreateAttemptOptions{RootDAGRun: root}, func(s *ir.DAGRunStatus) {
			s.Root, s.Parent = root, root
		})
	}
	w.writeRun(&ir.DAG{Name: w.jobA, YamlData: []byte("steps: []\n")}, "run-2", persis.DAGRunCreateAttemptOptions{}, func(s *ir.DAGRunStatus) {
		s.Nodes = []*ir.Node{{Step: ir.Step{Name: "call"}, SubRuns: []ir.SubDAGRun{
			{DAGRunID: "sub-b", DAGName: w.jobB},
			{DAGRunID: "sub-h", DAGName: "shared-helper"},
			// The parent's record names no DAG, or the wrong one: the run it
			// resolves to decides.
			{DAGRunID: "sub-x", DAGName: "shared-helper"},
			{DAGRunID: "sub-y"},
		}}}
	})
	child(w.jobB, "sub-b")
	child("shared-helper", "sub-h")
	child(w.jobB, "sub-x")
	child(w.jobB, "sub-y")
	personA := neutral(w.personA)

	spec := func(ctx context.Context, sub string) error {
		resp, err := w.api.GetSubDAGRunSpec(ctx, apigen.GetSubDAGRunSpecRequestObject{Name: w.jobA, DagRunId: "run-2", SubDAGRunId: sub})
		if err != nil {
			return err
		}
		if _, ok := resp.(*apigen.GetSubDAGRunSpec200JSONResponse); !ok {
			return &Error{HTTPStatus: http.StatusNotFound, Message: "no spec"}
		}
		return nil
	}
	require.Equal(t, http.StatusNotFound, statusOf(spec(personA, "sub-b")))
	require.Equal(t, http.StatusNotFound, statusOf(spec(personA, "sub-x")))
	require.NoError(t, spec(personA, "sub-h"))
	require.NoError(t, spec(w.legacy, "sub-b"), "a legacy key in mode off reads as today")

	listed := func(ctx context.Context) []string {
		resp, err := w.api.GetSubDAGRuns(ctx, apigen.GetSubDAGRunsRequestObject{Name: w.jobA, DagRunId: "run-2"})
		require.NoError(t, err)
		var ids []string
		for _, s := range resp.(*apigen.GetSubDAGRuns200JSONResponse).SubRuns {
			ids = append(ids, s.DagRunId)
		}
		return ids
	}
	require.Equal(t, []string{"sub-h"}, listed(personA))
	require.ElementsMatch(t, []string{"sub-b", "sub-h", "sub-x", "sub-y"}, listed(w.legacy))

	_, err := w.api.GetSubStepLogDataByRef(personA, root, "sub-b", "inner", StepLogReadOptions{})
	require.Equal(t, http.StatusNotFound, statusOf(err))
}

// A caller held to its owner has no workspace, the default one included:
// naming one opens no list and passes no workspace check.
func TestTxeNativeWorkspaceSelectionOpensNothing(t *testing.T) {
	w := newTwoOwners(t, "")
	w.addRun(w.jobA, "run-1", "")
	w.addRun(w.jobB, "run-b", "")
	personA, personB, cliA := neutral(w.personA), neutral(w.personB), neutral(w.cliA)
	unbound := neutral(w.nobody)

	for _, ws := range []string{"default", "production"} {
		for _, ctx := range []context.Context{personA, cliA, unbound} {
			dags, err := w.api.ListDAGs(ctx, apigen.ListDAGsRequestObject{Params: apigen.ListDAGsParams{Workspace: &ws}})
			require.NoError(t, err, ws)
			require.Empty(t, dags.(*apigen.ListDAGs200JSONResponse).Dags, ws)
			runs, err := w.api.ListDAGRuns(ctx, apigen.ListDAGRunsRequestObject{Params: apigen.ListDAGRunsParams{Workspace: &ws}})
			require.NoError(t, err, ws)
			require.Empty(t, runs.(apigen.ListDAGRuns200JSONResponse).DagRuns, ws)
			labels, err := w.api.GetAllDAGLabels(ctx, apigen.GetAllDAGLabelsRequestObject{Params: apigen.GetAllDAGLabelsParams{Workspace: &ws}})
			require.NoError(t, err, ws)
			require.Empty(t, labels.(*apigen.GetAllDAGLabels200JSONResponse).Labels, ws)
		}
		// One DAG's runs are decided by its owner, whatever workspace is
		// named.
		byName := func(ctx context.Context, dag string) int {
			resp, err := w.api.ListDAGRunsByName(ctx, apigen.ListDAGRunsByNameRequestObject{Name: dag, Params: apigen.ListDAGRunsByNameParams{Workspace: &ws}})
			require.NoError(t, err, ws)
			return len(resp.(apigen.ListDAGRunsByName200JSONResponse).DagRuns)
		}
		require.Equal(t, 1, byName(personA, w.jobA), ws)
		require.Zero(t, byName(personA, w.jobB), ws)
		require.Zero(t, byName(personB, w.jobA), ws)
		require.Zero(t, byName(unbound, w.jobA), ws)
	}
	for _, ctx := range []context.Context{personA, cliA, unbound} {
		require.Equal(t, http.StatusNotFound, statusOf(w.api.requireWorkspaceVisible(ctx, "")))
	}
	// A legacy credential still sees the default workspace.
	require.NoError(t, w.api.requireWorkspaceVisible(w.legacy, ""))
}

// A reference to a run of another owner's DAG that was started as a root of
// its own (dag.enqueue) is decided by that run itself, not by the run that
// referred to it.
func TestTxeNativeReferencedRootRunOfAnotherOwner(t *testing.T) {
	w := newTwoOwners(t, "")
	w.addRun(w.jobA, "run-1", "production")
	w.writeRun(&ir.DAG{Name: w.jobA, YamlData: []byte("steps: []\n")}, "run-2", persis.DAGRunCreateAttemptOptions{}, func(s *ir.DAGRunStatus) {
		s.Nodes = []*ir.Node{{Step: ir.Step{Name: "enqueue"}, SubRuns: []ir.SubDAGRun{{DAGRunID: "queued-b", DAGName: w.jobB}}}}
	})
	w.writeRun(&ir.DAG{Name: w.jobB, YamlData: []byte("steps:\n  - name: b\n    run: echo b\n")}, "queued-b", persis.DAGRunCreateAttemptOptions{}, func(s *ir.DAGRunStatus) {
		s.Root = ir.NewDAGRunRef(w.jobB, "queued-b")
	})
	personA := neutral(w.personA)

	resp, err := w.api.GetSubDAGRunSpec(personA, apigen.GetSubDAGRunSpecRequestObject{Name: w.jobA, DagRunId: "run-2", SubDAGRunId: "queued-b"})
	if err == nil {
		_, ok := resp.(*apigen.GetSubDAGRunSpec200JSONResponse)
		require.False(t, ok, "another owner's YAML was returned")
	} else {
		require.Equal(t, http.StatusNotFound, statusOf(err))
	}
	list, err := w.api.GetSubDAGRuns(personA, apigen.GetSubDAGRunsRequestObject{Name: w.jobA, DagRunId: "run-2"})
	require.NoError(t, err)
	require.Empty(t, list.(*apigen.GetSubDAGRuns200JSONResponse).SubRuns)

	// The same reference, for a legacy key in mode off, reads as today.
	resp, err = w.api.GetSubDAGRunSpec(w.legacy, apigen.GetSubDAGRunSpecRequestObject{Name: w.jobA, DagRunId: "run-2", SubDAGRunId: "queued-b"})
	require.NoError(t, err)
	require.IsType(t, &apigen.GetSubDAGRunSpec200JSONResponse{}, resp)
}

// A retry of a step in a child run reruns every run on its path, so each is
// decided by its owners: a person may not rerun another owner's child
// through its own job's run, and nothing is dispatched.
func TestTxeNativeChildRetryIsDecidedOnItsWholePath(t *testing.T) {
	w := newTwoOwners(t, "")
	w.markReady(w.jobA, w.machineA)
	w.addRun(w.jobA, "run-1", "production")
	recorder := &retryCoordinatorRecorder{}
	w.api.coordinatorCli = recorder
	w.api.defaultExecMode = config.ExecutionModeDistributed

	root := ir.NewDAGRunRef(w.jobA, "run-3")
	call := func(name string) ir.Step { return ir.Step{Name: "call-" + name, SubDAG: &ir.SubDAG{Name: name}} }
	// The run is of the job's current definition, which the registry admits.
	jobSpec, err := w.api.dagRepository.GetSpec(context.Background(), w.jobA)
	require.NoError(t, err)
	w.writeRun(&ir.DAG{Name: w.jobA, YamlData: []byte(jobSpec)}, "run-3", persis.DAGRunCreateAttemptOptions{}, func(s *ir.DAGRunStatus) {
		s.Root, s.Status = root, ir.Failed
		s.Nodes = []*ir.Node{
			{Step: call(w.jobB), Status: ir.NodeFailed, SubRuns: []ir.SubDAGRun{{DAGRunID: "child-b", DAGName: w.jobB}}},
			{Step: call("shared-helper"), Status: ir.NodeFailed, SubRuns: []ir.SubDAGRun{{DAGRunID: "child-h", DAGName: "shared-helper"}}},
		}
	})
	child := func(name, runID string, parent ir.DAGRunRef, nodes []*ir.Node) {
		w.writeRun(&ir.DAG{Name: name, YamlData: []byte("steps: []\n")}, runID, persis.DAGRunCreateAttemptOptions{RootDAGRun: root}, func(s *ir.DAGRunStatus) {
			s.Root, s.Parent, s.Status, s.Nodes = root, parent, ir.Failed, nodes
		})
	}
	// B's job called an ownerless helper in turn.
	child(w.jobB, "child-b", root, []*ir.Node{
		{Step: ir.Step{Name: "b"}, Status: ir.NodeFailed},
		{Step: call("deep-helper"), Status: ir.NodeFailed, SubRuns: []ir.SubDAGRun{{DAGRunID: "grandchild", DAGName: "deep-helper"}}},
	})
	child("deep-helper", "grandchild", ir.NewDAGRunRef(w.jobB, "child-b"), []*ir.Node{{Step: ir.Step{Name: "deep"}, Status: ir.NodeFailed}})
	child("shared-helper", "child-h", root, []*ir.Node{{Step: ir.Step{Name: "h"}, Status: ir.NodeFailed}})

	retry := func(ctx context.Context, sub, step string) error {
		_, err := w.api.RetryDAGRun(ctx, apigen.RetryDAGRunRequestObject{Name: w.jobA, DagRunId: "run-3",
			Body: &apigen.RetryDAGRunJSONRequestBody{DagRunId: "run-3", SubDAGRunId: &sub, StepName: &step}})
		return err
	}
	personA := neutral(w.personA)
	require.Equal(t, http.StatusNotFound, statusOf(retry(personA, "child-b", "b")))
	require.Equal(t, http.StatusNotFound, statusOf(retry(personA, "grandchild", "deep")), "a path through another owner's run")
	require.Empty(t, recorder.dispatched)

	// A's own path, through an ownerless helper, is A's to retry.
	require.NoError(t, retry(personA, "child-h", "h"))
	require.Len(t, recorder.dispatched, 1)
}
