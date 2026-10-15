// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
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
	// Browser sign-in only: no provider tokens are configured, and persons
	// are held to the gate all the same.
	require.Empty(t, w.api.config.TXE.Authn.Issuer)
	w.addRun(w.jobA, "run-1", "production")
	gateRefused := func(rec *httptest.ResponseRecorder) bool {
		return rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "not open to identity provider sign-ins")
	}
	for _, raw := range []string{
		// Encoded dots, in either case and mixed.
		"/api/v1/users/%2E%2E/dags/" + w.jobA,
		"/api/v1/workers/%2e%2e/dags/" + w.jobA,
		"/api/v1/workers/%2e%2E/dags/" + w.jobA,
		"/api/v1/users/%2E%2E/txe/jobs",
		"/api/v1/users/%2E%2E/auth/me",
		// Encoded slashes, in either case.
		"/api/v1/workers%2F..%2Fdags%2F" + w.jobA,
		"/api/v1/workers%2f..%2fdags%2f" + w.jobA,
		"/api/v1/dags/" + w.jobA + "%2fdag-runs",
		// Double and triple encoding, which a handler's own decoding of a
		// path parameter would turn into a slash or a dot.
		"/api/v1/users/%252E%252E/dags/" + w.jobA,
		"/api/v1/dags/x%252F..%252F" + w.jobA,
		"/api/v1/dags/x%252f..%252f" + w.jobA,
		"/api/v1/dags/" + w.jobA + "%25252E",
		// Repeated slashes and dot segments as sent.
		"/api/v1/dags//" + w.jobA,
		"/api/v1//dags/" + w.jobA,
		"/api/v1/dags///" + w.jobA,
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
	for _, raw := range []string{"/api/v1/users/%2E%2E/dags/x", "/api/v1/users/%2e%2E/txe/jobs", "/api/v1/dags//x", "/api/v1/txe/../users",
		"/api/v1/txe%2fjobs", "/api/v1/users/%252e%252e/txe/jobs", "/api/v1//txe/jobs"} {
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

// A shared queue from configuration is hub configuration, not an owner's: it
// is listed to everyone. To a caller held to its owner its count is of that
// caller's runs only, and it is always a lower bound, so a scan capped by
// other owners' entries neither shows nor hides anything. The caller's own
// entry stays within reach.
func TestTxeSharedQueueCountsOnlyTheCallersRuns(t *testing.T) {
	w := newTwoOwners(t, "")
	w.addRun(w.jobA, "run-1", "production")
	w.api.config.Queues = config.Queues{Enabled: true, Config: []config.QueueConfig{{Name: "shared", MaxActiveRuns: 2}}}
	queued := func(dag, runID string) {
		w.writeRun(&ir.DAG{Name: dag, YamlData: []byte("steps: []\n")}, runID, persis.DAGRunCreateAttemptOptions{}, func(s *ir.DAGRunStatus) {
			s.Status = ir.Queued
		})
	}
	queued(w.jobB, "qb-1")
	queued(w.jobB, "qb-2")
	queued(w.jobA, "qa-1")
	qs := store.NewQueueStore(file.NewCollection(t.TempDir()))
	ctx := context.Background()
	// B's entries first, then A's.
	for _, e := range []struct{ dag, run string }{{w.jobB, "qb-1"}, {w.jobB, "qb-2"}, {w.jobA, "qa-1"}} {
		require.NoError(t, qs.Enqueue(ctx, "shared", queue.QueuePriorityLow, ir.NewDAGRunRef(e.dag, e.run)))
	}
	w.api.queueStore = qs
	w.api.procRepository = nil

	shared := func(c context.Context) apigen.Queue {
		resp, err := w.api.GetQueue(c, apigen.GetQueueRequestObject{Name: "shared"})
		require.NoError(t, err)
		return apigen.Queue(resp.(apigen.GetQueue200JSONResponse))
	}
	personA, personB := neutral(w.personA), neutral(w.personB)
	// Counted in full: A sees its one entry, B its two, and neither is told
	// the scan was or was not capped.
	for _, tc := range []struct {
		ctx  context.Context
		want int
	}{{personA, 1}, {personB, 2}} {
		q := shared(tc.ctx)
		require.Equal(t, tc.want, q.QueuedCount)
		require.NotNil(t, q.QueuedCountCapped)
		require.True(t, *q.QueuedCountCapped)
	}
	require.Equal(t, 3, shared(w.legacy).QueuedCount)

	// Capped before A's entry: A still gets the flag that keeps its items
	// in reach, and nothing that tells it B has entries.
	saved := queuedCountScanCap
	t.Cleanup(func() { queuedCountScanCap = saved })
	queuedCountScanCap = 1
	q := shared(personA)
	require.Zero(t, q.QueuedCount)
	require.True(t, *q.QueuedCountCapped)
	resp, err := w.api.ListQueues(personA, apigen.ListQueuesRequestObject{})
	require.NoError(t, err)
	var listed []string
	for _, q := range resp.(apigen.ListQueues200JSONResponse).Queues {
		listed = append(listed, q.Name)
		if q.Name == "shared" {
			require.True(t, *q.QueuedCountCapped)
		}
	}
	require.Contains(t, listed, "shared")
	require.NotContains(t, listed, w.jobB)
	// The legacy view is unchanged: the real flag.
	require.True(t, *shared(w.legacy).QueuedCountCapped)
}

// A queue reached after the request's scan budget is spent is decided by its
// name, the DAG it is named for: the caller's own queue is still listed
// (with its count a lower bound), another owner's still is not.
func TestTxeQueuesBeyondTheScanBudgetAreDecidedByName(t *testing.T) {
	w := newTwoOwners(t, "")
	w.addRun(w.jobA, "run-1", "production")
	queued := func(dag, runID string) {
		w.writeRun(&ir.DAG{Name: dag, YamlData: []byte("steps: []\n")}, runID, persis.DAGRunCreateAttemptOptions{}, func(s *ir.DAGRunStatus) {
			s.Status = ir.Queued
		})
	}
	queued(w.jobA, "qa-1")
	queued(w.jobB, "qb-1")
	qs := store.NewQueueStore(file.NewCollection(t.TempDir()))
	ctx := context.Background()
	require.NoError(t, qs.Enqueue(ctx, w.jobA, queue.QueuePriorityLow, ir.NewDAGRunRef(w.jobA, "qa-1")))
	require.NoError(t, qs.Enqueue(ctx, w.jobB, queue.QueuePriorityLow, ir.NewDAGRunRef(w.jobB, "qb-1")))
	w.api.queueStore = qs
	w.api.procRepository = nil
	// Queues are scanned in name order. The caller is the owner of the job
	// whose queue comes second; the budget is spent on the first.
	first, second, caller := w.jobA, w.jobB, w.personB
	if w.jobB < w.jobA {
		first, second, caller = w.jobB, w.jobA, w.personA
	}
	saved := queuedCountRequestScanCap
	t.Cleanup(func() { queuedCountRequestScanCap = saved })
	queuedCountRequestScanCap = 1

	resp, err := w.api.ListQueues(neutral(caller), apigen.ListQueuesRequestObject{})
	require.NoError(t, err)
	byName := map[string]apigen.Queue{}
	for _, q := range resp.(apigen.ListQueues200JSONResponse).Queues {
		byName[q.Name] = q
	}
	require.Contains(t, byName, second, "the caller's own queue, beyond the budget, is listed")
	require.True(t, *byName[second].QueuedCountCapped)
	require.NotContains(t, byName, first, "the other owner's queue is not named to the caller")
}

// The canonical-path check is linear in the path's length.
func TestTxeCanonicalPathIsLinear(t *testing.T) {
	long := "/api/v1/dags/" + strings.Repeat("a/", 200_000) + "a"
	done := make(chan bool, 1)
	go func() { done <- txeCanonicalPath(httptest.NewRequest(http.MethodGet, long, nil)) }()
	select {
	case ok := <-done:
		require.True(t, ok)
	case <-time.After(5 * time.Second):
		t.Fatal("a long path took more than five seconds")
	}
}

// A queue may be named otherwise than its DAG (an enqueue's queue override).
// Past the scan budget, it is decided by the runs it holds: listed when one
// is the caller's, whatever it is called, and not named otherwise.
func TestTxeCustomQueuesBeyondTheScanBudgetAreDecidedByTheirRuns(t *testing.T) {
	w := newTwoOwners(t, "")
	w.addRun(w.jobA, "run-1", "production")
	queued := func(dag, runID string) {
		w.writeRun(&ir.DAG{Name: dag, YamlData: []byte("steps: []\n")}, runID, persis.DAGRunCreateAttemptOptions{}, func(s *ir.DAGRunStatus) {
			s.Status = ir.Queued
		})
	}
	queued(w.jobB, "qb-1")
	queued(w.jobA, "qa-1")
	queued(w.jobB, "qb-2")
	qs := store.NewQueueStore(file.NewCollection(t.TempDir()))
	ctx := context.Background()
	// Scanned in name order: the budget is spent on the first.
	require.NoError(t, qs.Enqueue(ctx, "aa-first", queue.QueuePriorityLow, ir.NewDAGRunRef(w.jobB, "qb-1")))
	require.NoError(t, qs.Enqueue(ctx, "zz-custom", queue.QueuePriorityLow, ir.NewDAGRunRef(w.jobA, "qa-1")))
	require.NoError(t, qs.Enqueue(ctx, "zz-other", queue.QueuePriorityLow, ir.NewDAGRunRef(w.jobB, "qb-2")))
	w.api.queueStore = qs
	w.api.procRepository = nil
	saved := queuedCountRequestScanCap
	t.Cleanup(func() { queuedCountRequestScanCap = saved })
	queuedCountRequestScanCap = 1

	resp, err := w.api.ListQueues(neutral(w.personA), apigen.ListQueuesRequestObject{})
	require.NoError(t, err)
	byName := map[string]apigen.Queue{}
	for _, q := range resp.(apigen.ListQueues200JSONResponse).Queues {
		byName[q.Name] = q
	}
	require.Contains(t, byName, "zz-custom", "A's run in a custom queue beyond the budget is listed")
	require.True(t, *byName["zz-custom"].QueuedCountCapped)
	require.NotContains(t, byName, "zz-other", "a queue of B's runs only is not named to A")
	require.NotContains(t, byName, "aa-first")
	_, err = w.api.GetQueue(neutral(w.personA), apigen.GetQueueRequestObject{Name: "zz-other"})
	require.Equal(t, http.StatusNotFound, statusOf(err))

	// The walk that finds A's run is bounded too: with its budget spent, the
	// queue is not named, rather than walked without limit. A still reaches
	// it by name, with that request's own budget.
	savedWalk := queuedMembershipScanCap
	t.Cleanup(func() { queuedMembershipScanCap = savedWalk })
	queuedMembershipScanCap = 0
	resp, err = w.api.ListQueues(neutral(w.personA), apigen.ListQueuesRequestObject{})
	require.NoError(t, err)
	for _, q := range resp.(apigen.ListQueues200JSONResponse).Queues {
		require.NotEqual(t, "zz-custom", q.Name)
	}
	queuedCountRequestScanCap = saved
	got, err := w.api.GetQueue(neutral(w.personA), apigen.GetQueueRequestObject{Name: "zz-custom"})
	require.NoError(t, err)
	require.Equal(t, 1, apigen.Queue(got.(apigen.GetQueue200JSONResponse)).QueuedCount)
}
