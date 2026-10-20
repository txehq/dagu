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

// runsAfter lists what the next review is shown, and the cursor the
// checkpoint gets when that review covers all of it.
func (h *runHistory) runsAfter(cursor string) (ids []string, next string) {
	h.t.Helper()
	runs, err := h.remote.RunsAfter(context.Background(), h.job, cursor)
	require.NoError(h.t, err)
	for _, run := range runs {
		ids = append(ids, run.RunID)
		next = run.Cursor
	}
	return ids, next
}

// watermark is the cursor for a listing that starts at at.
func watermark(at time.Time) string {
	return "listed-from:" + at.UTC().Format(time.RFC3339)
}

func listedFrom(t *testing.T, cursor string) time.Time {
	t.Helper()
	raw, ok := strings.CutPrefix(cursor, "listed-from:")
	require.True(t, ok, cursor)
	at, err := time.Parse(time.RFC3339, raw)
	require.NoError(t, err)
	return at
}

// The service lists only today's runs of a DAG unless it is asked for a
// range. Runs that ended before the service's midnight and that no review
// has covered are still shown to the next review, oldest first: a job
// reviewed once a day would otherwise never have most of its runs reviewed.
// A checkpoint written before the listing was bounded reads the whole
// history, across the service's pages.
func TestRemoteRunsAfterReadsRunsFromBeforeMidnight(t *testing.T) {
	h := newRunHistory(t)
	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	for i := range 120 {
		h.run(fmt.Sprintf("yesterday-%03d", i), midnight.Add(-2*time.Hour+time.Duration(i)*time.Second))
	}
	h.run("today", now)

	for _, legacy := range []string{"", "034hlPaIKeIGhygBEZHFS8"} {
		ids, _ := h.runsAfter(legacy)
		// One packet's worth, oldest first, and one more to say others wait.
		require.NotEmpty(t, ids)
		assert.Equal(t, "yesterday-000", ids[0])
		assert.Less(t, len(ids), 120)
	}
}

// The listing is bounded by the watermark the reviews' checkpoint carries.
// A run created before the lookback and the watermark is not read; a run
// from the day before is. A review that covers everything it was shown,
// with nothing left behind, moves the watermark to an hour before the
// latest time the service reported; only the last result returned carries
// that.
func TestRemoteRunsAfterIsBoundedByTheCheckpointWatermark(t *testing.T) {
	h := newRunHistory(t)
	now := time.Now()
	h.run("month-old", now.Add(-30*24*time.Hour))
	h.run("yesterday", now.Add(-26*time.Hour))
	h.run("today", now.Add(-time.Minute))

	runs, err := h.remote.RunsAfter(context.Background(), h.job, "")
	require.NoError(t, err)
	require.Len(t, runs, 3)
	assert.Equal(t, "month-old", runs[0].RunID)
	stay := watermark(time.Time{})
	assert.Equal(t, stay, runs[0].Cursor, "a review that stops here leaves the start where it was")
	assert.Equal(t, stay, runs[1].Cursor)
	assert.WithinDuration(t, now.Add(-time.Minute-time.Hour), listedFrom(t, runs[2].Cursor), 2*time.Second)

	// A watermark from an hour ago: the lookback reaches back a week, so the
	// month-old run is not read, and yesterday's is.
	recent := watermark(now.Add(-time.Hour))
	ids, _ := h.runsAfter(recent)
	assert.Equal(t, []string{"yesterday", "today"}, ids)

	h.cover("month-old", "yesterday")
	ids, _ = h.runsAfter(recent)
	assert.Equal(t, []string{"today"}, ids)

	// A watermark from before the month-old run reads it again; covered, it
	// is not shown.
	ids, _ = h.runsAfter(watermark(now.Add(-60 * 24 * time.Hour)))
	assert.Equal(t, []string{"today"}, ids)
}

// A run created long ago that is retried and not finished yet, or a result
// beyond the packet, holds the watermark where the listing started: the
// service lists by when a run was created, and neither run says when that
// was. Once the retry ends, its new execution is shown.
func TestRemoteRunsAfterHoldsTheWatermarkForWhatItLeavesBehind(t *testing.T) {
	h := newRunHistory(t)
	now := time.Now()
	h.run("old", now.Add(-30*24*time.Hour))
	h.cover("old")
	h.retry("old", now.Add(-2*time.Minute), ir.Running)
	h.run("today", now.Add(-time.Minute))

	ids, next := h.runsAfter("")
	assert.Equal(t, []string{"today"}, ids)
	assert.Equal(t, watermark(time.Time{}), next, "an unfinished run holds the start")

	h.cover("old", "today")
	h.retry("old", now, ir.Failed)
	ids, _ = h.runsAfter(next)
	assert.Equal(t, []string{"old"}, ids)

	// More results than one packet: the review is shown the oldest, and the
	// rest hold the start.
	from := watermark(now.Add(-8 * 24 * time.Hour))
	for i := range 60 {
		h.run(fmt.Sprintf("backlog-%02d", i), now.Add(-7*time.Hour+time.Duration(i)*time.Minute))
	}
	runs, err := h.remote.RunsAfter(context.Background(), h.job, from)
	require.NoError(t, err)
	require.NotEmpty(t, runs)
	for _, run := range runs {
		assert.Equal(t, from, run.Cursor, run.RunID)
	}
}

// The watermark is taken from the service's clock. With this machine's
// clock ahead of the service's, a watermark from it would be later than
// runs the service creates right after the listing, and they would be
// skipped once the lookback no longer reaches them.
func TestRemoteRunsAfterTakesTheWatermarkFromTheServicesClock(t *testing.T) {
	h := newRunHistory(t)
	behind := time.Now().Add(-3 * time.Hour)
	h.run("latest", behind)
	_, next := h.runsAfter("")
	assert.WithinDuration(t, behind.Add(-time.Hour), listedFrom(t, next), 2*time.Second)
}

// A run retried after a review covered it keeps the time it was created.
// Its new execution is shown to the next review while that time is within
// the lookback, however late the watermark.
func TestRemoteRunsAfterShowsARetryOfAnOlderCoveredRun(t *testing.T) {
	h := newRunHistory(t)
	now := time.Now()
	h.run("failed", now.Add(-3*24*time.Hour))
	h.cover("failed")
	h.retry("failed", now.Add(-time.Minute), ir.Succeeded)

	ids, _ := h.runsAfter(watermark(now.Add(-time.Hour)))
	assert.Equal(t, []string{"failed"}, ids)
}
