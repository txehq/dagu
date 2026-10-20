// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"path/filepath"
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

// The service lists only today's runs of a DAG unless it is asked for a
// range. Runs that ended before the service's midnight and that no review
// has covered are still shown to the next review, oldest first: a job
// reviewed once a day would otherwise never have most of its runs reviewed.
func TestRemoteRunsAfterReadsRunsFromBeforeMidnight(t *testing.T) {
	ctx := context.Background()
	const job = "job_01M4QQYWB60735V0287GA71338"
	store := dagrun.NewStore(filepath.Join(t.TempDir(), "dag-runs"))
	repo := persis.NewDAGRunRepository(store, nil, persis.DAGRunRepositoryOptions{})

	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	dag := &ir.DAG{Name: job}
	// More runs from yesterday than one page of the listing holds, so the
	// next page is read with the same range.
	at := map[string]time.Time{"today": now}
	for i := range 120 {
		at[fmt.Sprintf("yesterday-%03d", i)] = midnight.Add(-2*time.Hour + time.Duration(i)*time.Second)
	}
	for runID, at := range at {
		attempt, err := repo.CreateAttempt(ctx, dag, at, runID, persis.DAGRunCreateAttemptOptions{})
		require.NoError(t, err)
		require.NoError(t, attempt.Open(ctx))
		require.NoError(t, attempt.Write(ctx, ir.DAGRunStatus{
			Name: job, DAGRunID: runID, AttemptID: attempt.ID(), Status: ir.Succeeded,
			QueuedAt: at.Format(time.RFC3339), FinishedAt: at.Format(time.RFC3339),
		}))
		require.NoError(t, attempt.Close(ctx))
	}

	cfg := &config.Config{}
	a := apiv1.New(nil, repo, nil, nil, runtime.NewManager(repo, nil, cfg), cfg, nil, nil, prometheus.NewRegistry(), nil)
	srv := httptest.NewServer(apigen.HandlerFromMux(apigen.NewStrictHandlerWithOptions(a, nil, apigen.StrictHTTPServerOptions{
		ResponseErrorHandlerFunc: writeAPIError,
	}), chi.NewRouter()))
	t.Cleanup(srv.Close)

	// No review is recorded yet, so every finished run is still to be shown.
	reviews := &stubTransport{t: t, replies: map[string]string{"/txe/jobs/" + job + "/reviews": `{"reviews":[]}`}}
	remote := &review.Remote{Transport: splitTransport{runs: httpTransport{base: srv.URL, t: t}, rest: reviews}}
	runs, err := remote.RunsAfter(ctx, job, "")
	require.NoError(t, err)

	// One packet's worth, oldest first, and one more to say others wait.
	require.NotEmpty(t, runs)
	assert.Equal(t, "yesterday-000", runs[0].RunID)
	assert.Less(t, len(runs), 120)
}
