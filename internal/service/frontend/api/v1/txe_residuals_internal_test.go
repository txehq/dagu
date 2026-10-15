// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/queue"
)

// routedThroughGate serves a request through the person gate, the
// neutralizer and the generated router, as ConfigureRoutes mounts them. The
// caller's identity is put on the request as authentication would.
func routedThroughGate(t *testing.T, w *twoOwners, ctx context.Context, rawURL string) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// The caller's identity, on the router's own request state.
				next.ServeHTTP(rw, req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, chi.RouteContext(req.Context()))))
			})
		})
		r.Use(w.api.txePersonGate("/api/v1"))
		r.Use(w.api.txeNeutralize)
		r.Mount("/", apigen.Handler(apigen.NewStrictHandlerWithOptions(w.api, nil, apigen.StrictHTTPServerOptions{
			RequestErrorHandlerFunc: func(rw http.ResponseWriter, req *http.Request, _ error) {
				w.api.handleError(rw, req, ErrInvalidRequestBody)
			},
			ResponseErrorHandlerFunc: w.api.handleError,
		})))
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, rawURL, nil))
	return rec
}

// The gate reads a path exactly as the router routes it: a path that names
// /dags or /txe only once decoded or cleaned is refused to a caller held to
// its owner, before any handler.
func TestTxeGateRefusesPathsTheRouterReadsDifferently(t *testing.T) {
	w := newTwoOwners(t, "")
	w.addRun(w.jobA, "run-1", "production")
	gateRefused := func(rec *httptest.ResponseRecorder) bool {
		return rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "not open to identity provider sign-ins")
	}
	for _, raw := range []string{
		"/api/v1/users/%2E%2E/dags/" + w.jobA,
		"/api/v1/workers/%2e%2e/dags/" + w.jobA,
		"/api/v1/workers%2F..%2Fdags%2F" + w.jobA,
		"/api/v1/users/%2E%2E/txe/jobs",
		"/api/v1/users/%2E%2E/auth/me",
		"/api/v1/dags//" + w.jobA,
		"/api/v1/dags/./" + w.jobA,
		"/api/v1/users/../dags/" + w.jobA,
	} {
		rec := routedThroughGate(t, w, w.personA, raw)
		require.True(t, gateRefused(rec), "%s answered %d %s", raw, rec.Code, rec.Body.String())
	}
	// The canonical paths are still decided by owner.
	require.Equal(t, http.StatusOK, routedThroughGate(t, w, w.personA, "/api/v1/dags/"+w.jobA+"/dag-runs").Code)
	require.Equal(t, http.StatusNotFound, routedThroughGate(t, w, w.personB, "/api/v1/dags/"+w.jobA+"/dag-runs").Code)
	// A legacy credential is not held to the gate.
	require.False(t, gateRefused(routedThroughGate(t, w, w.legacy, "/api/v1/dags//"+w.jobA)))

	// A provider token is admitted on exactly the same reading.
	onRoute := txeTokenRoute("/api/v1")
	for _, raw := range []string{"/api/v1/users/%2E%2E/dags/x", "/api/v1/users/%2E%2E/txe/jobs", "/api/v1/dags//x", "/api/v1/txe/../users"} {
		require.False(t, onRoute(httptest.NewRequest(http.MethodGet, raw, nil)), raw)
	}
	for _, raw := range []string{"/api/v1/dags/x", "/api/v1/txe/jobs", "/api/v1/dag-runs/x/r/", "/api/v1/queues"} {
		require.True(t, onRoute(httptest.NewRequest(http.MethodGet, raw, nil)), raw)
	}
}

// A DAG runs only under its own name where an owner is concerned: a
// machine's DAG does not run under another name, no DAG runs under an
// owner's name, and a caller held to its owner overrides no name.
func TestTxeRunNameOverrideStaysWithItsOwner(t *testing.T) {
	w := newTwoOwners(t, "")
	reviewerA := &ir.DAG{Name: "txe-reviewer-" + w.machineA[len("mch_"):]}
	reviewerA.Location = "/dags/" + reviewerA.Name + ".yaml"
	reviewerB := "txe-reviewer-" + w.machineB[len("mch_"):]
	personA := neutral(w.personA)
	plain := &ir.DAG{Name: "nightly-backup", Location: "/dags/nightly-backup.yaml"}

	for _, name := range []string{reviewerB, w.jobB, "nightly-backup"} {
		require.Equal(t, http.StatusConflict, statusOf(w.api.txeRefuseRunName(personA, reviewerA, name)), name)
		require.Equal(t, http.StatusConflict, statusOf(w.api.txeRefuseRunName(w.legacy, reviewerA, name)), name)
	}
	require.Equal(t, http.StatusConflict, statusOf(w.api.txeRefuseRunName(w.legacy, plain, reviewerB)), "no DAG runs under a machine's name")
	require.Equal(t, http.StatusConflict, statusOf(w.api.txeRefuseRunName(personA, plain, "nightly-copy")), "an owner-held caller overrides no name")
	// Its own name, or none, is fine; a legacy key renames an ownerless DAG
	// as before.
	require.NoError(t, w.api.txeRefuseRunName(personA, reviewerA, reviewerA.Name))
	require.NoError(t, w.api.txeRefuseRunName(personA, reviewerA, ""))
	require.NoError(t, w.api.txeRefuseRunName(w.legacy, plain, "nightly-copy"))
}

// A caller held to its owner is named only queues that hold its runs, and a
// capped count of another owner's queue does not surface it.
func TestTxeQueuesNameOnlyTheCallersQueues(t *testing.T) {
	w := newTwoOwners(t, "")
	w.addRun(w.jobA, "run-1", "production")
	queued := func(dag, runID string) {
		w.writeRun(&ir.DAG{Name: dag, YamlData: []byte("steps: []\n")}, runID, persis.DAGRunCreateAttemptOptions{}, func(s *ir.DAGRunStatus) {
			s.Status = ir.Queued
		})
	}
	queued(w.jobA, "qa-1")
	queued(w.jobB, "qb-1")
	queued(w.jobB, "qb-2")
	qs := store.NewQueueStore(file.NewCollection(t.TempDir()))
	ctx := context.Background()
	for _, e := range []struct{ dag, run string }{{w.jobA, "qa-1"}, {w.jobB, "qb-1"}, {w.jobB, "qb-2"}} {
		require.NoError(t, qs.Enqueue(ctx, e.dag, queue.QueuePriorityLow, ir.NewDAGRunRef(e.dag, e.run)))
	}
	w.api.queueStore = qs
	w.api.procRepository = nil // nothing runs locally in this fixture

	names := func(c context.Context) []string {
		resp, err := w.api.ListQueues(c, apigen.ListQueuesRequestObject{})
		require.NoError(t, err)
		var out []string
		for _, q := range resp.(apigen.ListQueues200JSONResponse).Queues {
			out = append(out, q.Name)
		}
		return out
	}
	personA := neutral(w.personA)
	require.Equal(t, []string{w.jobA}, names(personA))
	require.ElementsMatch(t, []string{w.jobA, w.jobB}, names(w.legacy))
	_, err := w.api.GetQueue(personA, apigen.GetQueueRequestObject{Name: w.jobB})
	require.Equal(t, http.StatusNotFound, statusOf(err))

	// A scan capped before reaching anything of A's.
	saved := queuedCountScanCap
	t.Cleanup(func() { queuedCountScanCap = saved })
	queuedCountScanCap = 1
	_, err = w.api.GetQueue(personA, apigen.GetQueueRequestObject{Name: w.jobB})
	require.Equal(t, http.StatusNotFound, statusOf(err))
	require.NotContains(t, names(personA), w.jobB)
}
