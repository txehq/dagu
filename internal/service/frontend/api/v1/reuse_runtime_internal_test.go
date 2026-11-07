// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	profilepkg "github.com/dagucloud/dagu/v2/internal/profile"
	"github.com/dagucloud/dagu/v2/internal/spec"
	runtestutil "github.com/dagucloud/dagu/v2/internal/testutil"
)

type reuseRuntimeRig struct {
	api  *API
	dag  *ir.DAG
	none string // the identity of a run that takes no profile
	prod string // the identity of a run under the profile prod
	// The profile identities alone, for a DAG loaded another way.
	noneProfile, prodProfile string
}

// newReuseRuntimeRig has an API with profile stores, a profile prod, and the
// edit-retry DAG whose step build a step run of consume reuses.
func newReuseRuntimeRig(t *testing.T) reuseRuntimeRig {
	t.Helper()
	ctx := context.Background()
	api, _ := setupEditRetryAPI(t, t.TempDir(), editRetrySourceYAML())
	backend := testutil.NewMemoryBackend()
	profiles, err := store.NewProfileStore(backend.Collection("profiles"))
	require.NoError(t, err)
	enc, err := crypto.NewEncryptor("reuse-runtime-test")
	require.NoError(t, err)
	secrets, err := store.NewSecretStore(backend.Collection("secrets"), enc)
	require.NoError(t, err)
	api.profileStore = profiles
	api.secretStore = secrets
	api.coordinatorCli = &retryCoordinatorRecorder{}

	prod, err := profilepkg.New(profilepkg.CreateInput{Name: "prod"}, time.Now())
	require.NoError(t, err)
	require.NoError(t, prod.SetVariable("REGION", "eu", "alice", time.Now()))
	require.NoError(t, profiles.Create(ctx, prod))

	dag, err := spec.LoadYAML(ctx, []byte(editRetryEditedYAMLWithWorkerSelector()))
	require.NoError(t, err)
	resolver := profilepkg.NewResolver(profiles, secrets)
	none, err := resolver.RuntimeIdentity(ctx, profilepkg.RuntimeRequest{})
	require.NoError(t, err)
	prodIdentity, err := resolver.RuntimeIdentity(ctx, profilepkg.RuntimeRequest{ProfileName: "prod"})
	require.NoError(t, err)
	require.NotEqual(t, none, prodIdentity)
	return reuseRuntimeRig{
		api: api, dag: dag,
		none: spec.RunRuntimeIdentity(dag, none), prod: spec.RunRuntimeIdentity(dag, prodIdentity),
		noneProfile: none, prodProfile: prodIdentity,
	}
}

// sourceRun records a finished run of build with the given identity.
func (r reuseRuntimeRig) sourceRun(t *testing.T, runID, identity string) {
	t.Helper()
	ctx := context.Background()
	sourceDAG, err := spec.LoadYAML(ctx, []byte(editRetrySourceYAML()))
	require.NoError(t, err)
	seedEditRetrySourceAttempt(t, ctx, r.api.dagRunRepository, sourceDAG, runID)
	attempt, err := r.api.dagRunRepository.FindAttempt(ctx, ir.NewDAGRunRef(sourceDAG.Name, runID))
	require.NoError(t, err)
	status, err := attempt.ReadStatus(ctx)
	require.NoError(t, err)
	status.RuntimeIdentity = identity
	require.NoError(t, attempt.Open(ctx))
	require.NoError(t, attempt.Write(ctx, *status))
	require.NoError(t, attempt.Close(ctx))
}

func (r reuseRuntimeRig) seeded(t *testing.T, runID string) *ir.DAGRunStatus {
	t.Helper()
	attempt, err := r.api.dagRunRepository.FindAttempt(context.Background(), ir.NewDAGRunRef(r.dag.Name, runID))
	require.NoError(t, err)
	status, err := attempt.ReadStatus(context.Background())
	require.NoError(t, err)
	return status
}

func (r reuseRuntimeRig) start(automatic []string, profileName, runID string) error {
	return r.api.startSelectedSteps(context.Background(), r.dag, selectedStepsStart{
		selection: stepSelection{
			steps:           []string{"consume"},
			outputsFromRuns: map[string]string{"build": "source-run"},
			automaticReuse:  automatic,
		},
		profileName: profileName,
		dagRunID:    runID,
	})
}

// Outputs of a run under one profile state are reused automatically only for
// a step run of the same state, and that run is told to check it before any
// step (TXE-6145).
func TestAutomaticReuseRequiresTheSameRuntimeIdentity(t *testing.T) {
	t.Run("same identity: admitted, recorded and expected", func(t *testing.T) {
		rig := newReuseRuntimeRig(t)
		rig.sourceRun(t, "source-run", rig.prod)
		require.NoError(t, rig.start([]string{"build"}, "prod", "new-run"))

		seed := rig.seeded(t, "new-run")
		assert.Equal(t, rig.prod, seed.RuntimeIdentity)
		assert.Equal(t, rig.prod, seed.ExpectedRuntimeIdentity)
		recorder := rig.api.coordinatorCli.(*retryCoordinatorRecorder)
		require.Len(t, recorder.dispatched, 1)
		assert.Equal(t, dispatch.CapabilityLabelValue, recorder.dispatched[0].WorkerSelector[dispatch.RuntimeIdentityCheckLabel],
			"only a worker that checks the identity may take it")
	})

	for name, tc := range map[string]struct {
		source  func(rig reuseRuntimeRig) string
		profile string
	}{
		"profile A outputs for a profile B step run":  {source: func(rig reuseRuntimeRig) string { return rig.none }, profile: "prod"},
		"profile B outputs for a run without profile": {source: func(rig reuseRuntimeRig) string { return rig.prod }, profile: ""},
		"a source run recorded before identities":     {source: func(reuseRuntimeRig) string { return "" }, profile: ""},
	} {
		t.Run(name+": refused, nothing seeded", func(t *testing.T) {
			rig := newReuseRuntimeRig(t)
			rig.sourceRun(t, "source-run", tc.source(rig))
			err := rig.start([]string{"build"}, tc.profile, "new-run")
			var apiErr *Error
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, http.StatusConflict, apiErr.HTTPStatus)
			assert.Contains(t, apiErr.Message, "step build")
			_, err = rig.api.dagRunRepository.FindAttempt(context.Background(), ir.NewDAGRunRef(rig.dag.Name, "new-run"))
			assert.Error(t, err, "nothing was seeded")
		})
	}

	t.Run("profile edited between the reuse and the check: refused", func(t *testing.T) {
		rig := newReuseRuntimeRig(t)
		rig.sourceRun(t, "source-run", rig.prod)
		p, err := rig.api.profileStore.GetByName(context.Background(), "prod")
		require.NoError(t, err)
		require.NoError(t, p.SetVariable("REGION", "us", "bob", time.Now()))
		require.NoError(t, rig.api.profileStore.Update(context.Background(), p))
		var apiErr *Error
		require.ErrorAs(t, rig.start([]string{"build"}, "prod", "new-run"), &apiErr)
		assert.Equal(t, http.StatusConflict, apiErr.HTTPStatus)
	})

	t.Run("explicit reuse across profiles: allowed, and the run's identity unknown", func(t *testing.T) {
		rig := newReuseRuntimeRig(t)
		rig.sourceRun(t, "source-run", rig.none)
		require.NoError(t, rig.start(nil, "prod", "new-run"))

		seed := rig.seeded(t, "new-run")
		assert.Empty(t, seed.RuntimeIdentity, "its carried node is of another state")
		assert.Empty(t, seed.ExpectedRuntimeIdentity)
		recorder := rig.api.coordinatorCli.(*retryCoordinatorRecorder)
		require.Len(t, recorder.dispatched, 1)
		assert.NotContains(t, recorder.dispatched[0].WorkerSelector, dispatch.RuntimeIdentityCheckLabel)
	})

	t.Run("automatic reuse naming no step of the DAG: bad request", func(t *testing.T) {
		rig := newReuseRuntimeRig(t)
		rig.sourceRun(t, "source-run", rig.none)
		var apiErr *Error
		require.ErrorAs(t, rig.start([]string{"nope"}, "", "new-run"), &apiErr)
		assert.Equal(t, http.StatusBadRequest, apiErr.HTTPStatus)
	})
}

func TestSelectedStepsFromBodyAutomaticReuse(t *testing.T) {
	_, err := selectedStepsFromBody(nil, nil, nil, nil, nil, nil, &[]string{"build"})
	require.Error(t, err, "automaticReuse requires steps")

	steps := []string{"consume"}
	_, err = selectedStepsFromBody(&steps, nil, nil, nil, nil, nil, &[]string{" "})
	require.Error(t, err)

	got, err := selectedStepsFromBody(&steps, nil, nil, nil, nil, nil, &[]string{" build "})
	require.NoError(t, err)
	assert.Equal(t, []string{"build"}, got.automaticReuse)

	details := map[string]any{}
	addSelectedStepsAudit(details, got)
	assert.Equal(t, []string{"build"}, details["automatic_reuse"])
}

// The reuse-runtime read answers same, different or unknown, and a run the
// caller cannot reuse, or that does not exist, is unknown alike.
func TestCheckDAGReuseRuntime(t *testing.T) {
	rig := newReuseRuntimeRig(t)
	ctx := context.Background()
	dags := runtestutil.NewFileDAGRepository(filepath.Join(t.TempDir(), "dags"))
	require.NoError(t, dags.Create(ctx, rig.dag.Name, []byte(editRetrySourceYAML())))
	rig.api.dagRepository = dags
	// The comparison takes the saved DAG as the start route loads it.
	saved, err := dags.GetDetails(ctx, rig.dag.Name, persis.DAGLoadOptions{AllowBuildErrors: true})
	require.NoError(t, err)

	rig.sourceRun(t, "run-none", spec.RunRuntimeIdentity(saved, rig.noneProfile))
	rig.sourceRun(t, "run-prod", spec.RunRuntimeIdentity(saved, rig.prodProfile))
	rig.sourceRun(t, "run-old", "")

	resp, err := rig.api.CheckDAGReuseRuntime(ctx, gen.CheckDAGReuseRuntimeRequestObject{
		FileName: rig.dag.Name,
		Body:     &gen.CheckDAGReuseRuntimeJSONRequestBody{RunIds: []string{"run-none", "run-prod", "run-old", "run-none", "missing"}},
	})
	require.NoError(t, err)
	got := map[string]gen.ReuseRuntimeCheckRunsRuntime{}
	var order []string
	for _, run := range resp.(gen.CheckDAGReuseRuntime200JSONResponse).Runs {
		got[run.DagRunId] = run.Runtime
		order = append(order, run.DagRunId)
	}
	assert.Equal(t, []string{"run-none", "run-prod", "run-old", "missing"}, order, "repeats count once")
	assert.Equal(t, gen.ReuseRuntimeCheckRunsRuntimeSame, got["run-none"], "the DAG has no default profile")
	assert.Equal(t, gen.ReuseRuntimeCheckRunsRuntimeDifferent, got["run-prod"])
	assert.Equal(t, gen.ReuseRuntimeCheckRunsRuntimeUnknown, got["run-old"])
	assert.Equal(t, gen.ReuseRuntimeCheckRunsRuntimeUnknown, got["missing"])

	tooMany := make([]string, maxReuseRuntimeRuns+1)
	for i := range tooMany {
		tooMany[i] = "run-none"
	}
	_, err = rig.api.CheckDAGReuseRuntime(ctx, gen.CheckDAGReuseRuntimeRequestObject{
		FileName: rig.dag.Name,
		Body:     &gen.CheckDAGReuseRuntimeJSONRequestBody{RunIds: tooMany},
	})
	var apiErr *Error
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadRequest, apiErr.HTTPStatus)
}

// A draft is compared as it would run, but without running anything of it:
// a parameter that runs a command is not evaluated by the comparison.
func TestCheckDAGReuseRuntimeRunsNothingOfADraft(t *testing.T) {
	rig := newReuseRuntimeRig(t)
	ctx := context.Background()
	marker := filepath.Join(t.TempDir(), "evaluated")
	draft := "params:\n  - name: TAG\n    eval: \"`touch " + marker + "`\"\nsteps:\n  - name: build\n    run: echo $TAG\n"
	name := rig.dag.Name
	resp, err := rig.api.CheckDAGReuseRuntime(ctx, gen.CheckDAGReuseRuntimeRequestObject{
		FileName: rig.dag.Name,
		Body:     &gen.CheckDAGReuseRuntimeJSONRequestBody{RunIds: []string{"missing"}, Spec: &draft, Name: &name},
	})
	require.NoError(t, err)
	assert.Equal(t, gen.ReuseRuntimeCheckRunsRuntimeUnknown, resp.(gen.CheckDAGReuseRuntime200JSONResponse).Runs[0].Runtime)
	_, statErr := os.Stat(marker)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "the comparison ran a command of the draft")
}
