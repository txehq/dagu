// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package intake_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/intake"
	"github.com/dagucloud/dagu/v2/internal/ir"
)

func TestAdmitReuseRuntime(t *testing.T) {
	t.Parallel()

	dag := &ir.DAG{Name: "flow", Steps: []ir.Step{{Name: "login", ID: "auth"}, {Name: "fetch"}, {Name: "report"}}}
	run := func(id, identity string) *ir.DAGRunStatus {
		return &ir.DAGRunStatus{DAGRunID: id, RuntimeIdentity: identity}
	}
	viaRun := func(step, runID string) ir.ReusedInput {
		return ir.ReusedInput{Step: step, RunID: runID, Via: ir.ReusedInputViaRun}
	}
	const now = "rp1:now"

	t.Run("an automatic step from a run of the same identity is admitted and expected", func(t *testing.T) {
		t.Parallel()
		got, err := intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{
			DAG: dag, Automatic: []string{"login"}, Identity: now,
			FromRuns: intake.RunStepSources{"login": run("r1", now)},
			Reused:   []ir.ReusedInput{viaRun("login", "r1")},
		})
		require.NoError(t, err)
		assert.Equal(t, intake.ReuseRuntimeAdmission{Identity: now, Expected: now}, got)
	})

	t.Run("a step is named by its ID too", func(t *testing.T) {
		t.Parallel()
		_, err := intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{
			DAG: dag, Automatic: []string{"auth"}, Identity: now,
			FromRuns: intake.RunStepSources{"auth": run("r1", now)},
			Reused:   []ir.ReusedInput{viaRun("login", "r1")},
		})
		require.NoError(t, err)
	})

	for name, tc := range map[string]struct {
		identity string
		source   string
	}{
		"another profile state":           {identity: now, source: "rp1:other"},
		"a source run with no identity":   {identity: now, source: ""},
		"a new run of unknown identity":   {identity: "", source: now},
		"both unknown are never the same": {identity: "", source: ""},
	} {
		t.Run("an automatic step is refused for "+name, func(t *testing.T) {
			t.Parallel()
			_, err := intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{
				DAG: dag, Automatic: []string{"login"}, Identity: tc.identity,
				FromRuns: intake.RunStepSources{"login": run("r1", tc.source)},
				Reused:   []ir.ReusedInput{viaRun("login", "r1")},
			})
			var refusal *intake.ReuseRuntimeError
			require.ErrorAs(t, err, &refusal)
			assert.Contains(t, refusal.Message, "step login")
			assert.Contains(t, refusal.Message, "run r1")
		})
	}

	t.Run("the source run is checked for a step it carries", func(t *testing.T) {
		t.Parallel()
		_, err := intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{
			DAG: dag, Automatic: []string{"fetch"}, Identity: now,
			Source: run("src", "rp1:other"),
			Reused: []ir.ReusedInput{viaRun("fetch", "src")},
		})
		require.ErrorAs(t, err, new(*intake.ReuseRuntimeError))
	})

	t.Run("an explicit step of another identity is allowed but leaves the run unknown", func(t *testing.T) {
		t.Parallel()
		got, err := intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{
			DAG: dag, Automatic: []string{"login"}, Identity: now,
			FromRuns: intake.RunStepSources{"login": run("r1", now), "fetch": run("r2", "rp1:other")},
			Reused:   []ir.ReusedInput{viaRun("login", "r1"), viaRun("fetch", "r2")},
		})
		require.NoError(t, err)
		assert.Equal(t, intake.ReuseRuntimeAdmission{Identity: "", Expected: now}, got)
	})

	t.Run("without automatic steps nothing is expected", func(t *testing.T) {
		t.Parallel()
		got, err := intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{
			DAG: dag, Identity: now,
			FromRuns: intake.RunStepSources{"login": run("r1", "rp1:other")},
			Reused:   []ir.ReusedInput{viaRun("login", "r1")},
		})
		require.NoError(t, err)
		assert.Equal(t, intake.ReuseRuntimeAdmission{}, got)
	})

	t.Run("a run with nothing carried takes the new identity", func(t *testing.T) {
		t.Parallel()
		got, err := intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{DAG: dag, Identity: now})
		require.NoError(t, err)
		assert.Equal(t, intake.ReuseRuntimeAdmission{Identity: now}, got)
	})

	t.Run("supplied values or a copied work directory of another state leave the run unknown", func(t *testing.T) {
		t.Parallel()
		got, err := intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{DAG: dag, Identity: now, SuppliedOutputs: true})
		require.NoError(t, err)
		assert.Empty(t, got.Identity)

		got, err = intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{DAG: dag, Identity: now, Source: run("src", "")})
		require.NoError(t, err)
		assert.Empty(t, got.Identity)
	})

	t.Run("an automatic step that carries nothing is passed over", func(t *testing.T) {
		t.Parallel()
		got, err := intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{
			DAG: dag, Automatic: []string{"login"}, Identity: now,
		})
		require.NoError(t, err)
		assert.Equal(t, intake.ReuseRuntimeAdmission{Identity: now, Expected: now}, got)
	})

	t.Run("an automatic step with supplied values, or no such step, is a bad request", func(t *testing.T) {
		t.Parallel()
		_, err := intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{
			DAG: dag, Automatic: []string{"login"}, Identity: now,
			Reused: []ir.ReusedInput{{Step: "login", RunID: "r1", Via: ir.ReusedInputViaCache}},
		})
		require.ErrorAs(t, err, new(*intake.RunStepSourceError))
		_, err = intake.AdmitReuseRuntime(intake.ReuseRuntimeRequest{DAG: dag, Automatic: []string{"nope"}, Identity: now})
		require.ErrorAs(t, err, new(*intake.RunStepSourceError))
	})
}
