// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry_test

import (
	"encoding/json"
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// CheckRetryRun admits a retry only as the carrying out of the approved
// dagu.retry_run it is made for, in the one form that decision approves,
// and refuses every other request with CodeStaleBinding (TXE-7517). The
// hub's table (TestTxeRepublishBinding) covers each condition for every
// form; this pins the exported contract the queue dispatch shares.
func TestCheckRetryRun(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	job := &registry.Job{JobID: "job_1", Version: 3, PackageDigest: "sha256:pkg",
		Proposals: map[string]*registry.Proposal{"prp_1": {ProposalID: "prp_1", State: registry.ProposalDecided,
			Decision: &registry.Decision{DecisionID: "dec_1", Verdict: registry.VerdictRetry, Actor: registry.Actor{Kind: registry.ActorHuman, ID: "alice"}}}}}
	action := func(extra map[string]any) *registry.Action {
		params := map[string]any{"run_id": "run-1", "attempt_id": "a1", "queued_at": "q1"}
		maps.Copy(params, extra)
		raw, err := json.Marshal(params)
		require.NoError(t, err)
		spec := registry.ActionSpec{Name: registry.ActionRetryRun, Params: raw}
		binding, err := registry.BindingDigest(job, spec)
		require.NoError(t, err)
		return &registry.Action{ActionID: "act_1", Kind: registry.ActionApproved, JobVersion: 3, ProposalID: "prp_1", DecisionID: "dec_1",
			Spec: spec, BindingDigest: binding, State: registry.ActionExecuting, Attempt: 1,
			Grant: &registry.Grant{GrantID: "grt_1", ActionID: "act_1", Attempt: 1, ExpiresAt: now.Add(time.Minute)}}
	}
	execution := registry.RetriedExecution{AttemptID: "a1", QueuedAt: "q1"}
	at := func(a *registry.Action, runID string, form registry.RetryForm, when time.Time) error {
		var req registry.RetryActionRequest
		if a != nil {
			req = registry.RetryActionRequest{ActionAttempt: "1", BindingDigest: a.BindingDigest}
		}
		return registry.CheckRetryRun(job, a, runID, execution, req, form, when)
	}
	check := func(a *registry.Action, form registry.RetryForm) error { return at(a, "run-1", form, now) }

	unspecified := action(nil)
	rerun := action(map[string]any{"step": registry.RetryStepRun})
	publish := action(map[string]any{"step": registry.RetryStepPublish})
	require.NoError(t, check(unspecified, registry.RetryFormWholeRun), "a retry naming no intent, of the whole run")
	require.NoError(t, check(rerun, registry.RetryFormFromJobStep), "an explicit rerun, from the job's step")
	require.NoError(t, check(publish, registry.RetryFormPublish), "a republish, of the publish step alone")

	replayed := action(nil)
	replayed.State = registry.ActionSucceeded
	for name, err := range map[string]error{
		"no action": check(nil, registry.RetryFormWholeRun),
		// A retry with no step: Dagu then keeps a job step that succeeded
		// and only publishes again.
		"a rerun carried out with no step":        check(rerun, registry.RetryFormWholeRun),
		"a rerun carried out as a republish":      check(rerun, registry.RetryFormPublish),
		"no intent carried out from the job step": check(unspecified, registry.RetryFormFromJobStep),
		"no intent carried out as a republish":    check(unspecified, registry.RetryFormPublish),
		"a republish carried out with no step":    check(publish, registry.RetryFormWholeRun),
		"a republish carried out from the job":    check(publish, registry.RetryFormFromJobStep),
		"another step":                            check(action(map[string]any{"step": "check"}), registry.RetryFormFromJobStep),
		// TXE-7629: the legacy key is refused in every form, never read as
		// an unspecified retry.
		"a legacy rerun key, whole run":            check(action(map[string]any{"rerun": true}), registry.RetryFormWholeRun),
		"a legacy rerun key, from the job":         check(action(map[string]any{"rerun": true}), registry.RetryFormFromJobStep),
		"a legacy rerun key with a republish":      check(action(map[string]any{"step": registry.RetryStepPublish, "rerun": true}), registry.RetryFormPublish),
		"a legacy rerun false":                     check(action(map[string]any{"rerun": false}), registry.RetryFormWholeRun),
		"no form":                                  check(unspecified, ""),
		"a replay of a settled one":                check(replayed, registry.RetryFormWholeRun),
		"another run":                              at(unspecified, "run-2", registry.RetryFormWholeRun, now),
		"after the grant":                          at(unspecified, "run-1", registry.RetryFormWholeRun, now.Add(time.Hour)),
		"an explicit rerun of another run":         at(rerun, "run-2", registry.RetryFormFromJobStep, now),
		"an explicit rerun after its grant":        at(rerun, "run-1", registry.RetryFormFromJobStep, now.Add(time.Hour)),
		"an explicit rerun, its attempt forgotten": registry.CheckRetryRun(job, rerun, "run-1", execution, registry.RetryActionRequest{ActionAttempt: "2", BindingDigest: rerun.BindingDigest}, registry.RetryFormFromJobStep, now),
	} {
		require.Error(t, err, name)
		assert.Equal(t, registry.CodeStaleBinding, registry.ErrorCode(err), name)
	}
	err := check(rerun, registry.RetryFormWholeRun)
	assert.Contains(t, err.Error(), `stepName "run", includeDownstream`, "the refusal says how a rerun is carried out")
}
