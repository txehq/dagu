// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	apiv1 "github.com/dagucloud/dagu/v2/internal/service/frontend/api/v1"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
)

// runHistory is the service's real run API over a real run store, with the
// job's recorded reviews stubbed: reviews names what they covered.
type runHistory struct {
	t       *testing.T
	job     string
	repo    *persis.DAGRunRepository
	remote  *review.Remote
	reviews *stubTransport
	execs   map[string]string
}

func newRunHistory(t *testing.T) *runHistory {
	t.Helper()
	h := &runHistory{t: t, job: "job_01M4QQYWB60735V0287GA71338", execs: map[string]string{}}
	h.repo = persis.NewDAGRunRepository(dagrun.NewStore(filepath.Join(t.TempDir(), "dag-runs")), nil, persis.DAGRunRepositoryOptions{})
	cfg := &config.Config{}
	a := apiv1.New(nil, h.repo, nil, nil, runtime.NewManager(h.repo, nil, cfg), cfg, nil, nil, prometheus.NewRegistry(), nil)
	srv := httptest.NewServer(apigen.HandlerFromMux(apigen.NewStrictHandlerWithOptions(a, nil, apigen.StrictHTTPServerOptions{
		ResponseErrorHandlerFunc: writeAPIError,
	}), chi.NewRouter()))
	t.Cleanup(srv.Close)
	h.reviews = &stubTransport{t: t, replies: map[string]string{}}
	h.cover()
	h.remote = &review.Remote{Transport: splitTransport{runs: httpTransport{base: srv.URL, t: t}, rest: h.reviews}}
	return h
}

// run records a finished run created, queued and ended at at.
func (h *runHistory) run(runID string, at time.Time) {
	h.attempt(runID, at, false, ir.Succeeded)
}

// retry records a new execution of the run, queued at at, in that status.
func (h *runHistory) retry(runID string, at time.Time, status ir.Status) {
	h.attempt(runID, at, true, status)
}

func (h *runHistory) attempt(runID string, at time.Time, retry bool, status ir.Status) {
	h.t.Helper()
	ctx := context.Background()
	attempt, err := h.repo.CreateAttempt(ctx, &ir.DAG{Name: h.job}, at, runID, persis.DAGRunCreateAttemptOptions{Retry: retry})
	require.NoError(h.t, err)
	require.NoError(h.t, attempt.Open(ctx))
	stamp, finished := at.Format(time.RFC3339), ""
	if status != ir.Running {
		finished = stamp
	}
	require.NoError(h.t, attempt.Write(ctx, ir.DAGRunStatus{
		Name: h.job, DAGRunID: runID, AttemptID: attempt.ID(), Status: status, QueuedAt: stamp, StartedAt: stamp, FinishedAt: finished,
	}))
	require.NoError(h.t, attempt.Close(ctx))
	h.execs[runID] = review.ExecutionRef(attempt.ID(), stamp)
}

// cover records one review that covered these runs.
func (h *runHistory) cover(runIDs ...string) {
	keys := make([]string, 0, len(runIDs))
	for _, id := range runIDs {
		keys = append(keys, fmt.Sprintf("%q", id+"@"+h.execs[id]))
	}
	h.reviews.replies["/txe/jobs/"+h.job+"/reviews"] = `{"reviews":[{"detail":{"covered_executions":[` + strings.Join(keys, ",") + `]}}]}`
}

func (h *runHistory) runsAfter() []string {
	h.t.Helper()
	runs, err := h.remote.RunsAfter(context.Background(), h.job, "")
	require.NoError(h.t, err)
	ids := make([]string, 0, len(runs))
	for _, run := range runs {
		ids = append(ids, run.RunID)
	}
	return ids
}

// The service lists only today's runs of a DAG unless it is asked for a
// range. Runs that ended before the service's midnight and that no review
// has covered are still shown to the next review, oldest first, across the
// service's pages: a job reviewed once a day would otherwise never have most
// of its runs reviewed.
func TestRemoteRunsAfterReadsRunsFromBeforeMidnight(t *testing.T) {
	h := newRunHistory(t)
	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	for i := range 120 {
		h.run(fmt.Sprintf("yesterday-%03d", i), midnight.Add(-2*time.Hour+time.Duration(i)*time.Second))
	}
	h.run("today", now)

	ids := h.runsAfter()
	// One packet's worth, oldest first, and one more to say others wait.
	require.NotEmpty(t, ids)
	assert.Equal(t, "yesterday-000", ids[0])
	assert.Less(t, len(ids), 120)
}

// A retry keeps the time its run was created, which is what the service's
// range is on. A run created long before, covered by a review, and retried
// now has a new execution that no review has seen, and it is shown, however
// old the run.
func TestRemoteRunsAfterShowsARetryOfAnOldCoveredRun(t *testing.T) {
	h := newRunHistory(t)
	now := time.Now()
	h.run("old", now.Add(-90*24*time.Hour))
	h.run("recent", now.Add(-time.Hour))
	h.cover("old", "recent")
	assert.Empty(t, h.runsAfter())

	h.retry("old", now, ir.Succeeded)
	assert.Equal(t, []string{"old"}, h.runsAfter())
}
