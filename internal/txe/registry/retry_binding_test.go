// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// CheckRetryRun admits a retry only as the carrying out of the approved
// dagu.retry_run it is made for, as what it approved, and refuses every
// other request with CodeStaleBinding (TXE-7517). The hub's table
// (TestTxeRepublishBinding) covers each condition for both intents; this
// pins the exported contract the queue dispatch shares.
func TestCheckRetryRun(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	job := &registry.Job{JobID: "job_1", Version: 3, PackageDigest: "sha256:pkg",
		Proposals: map[string]*registry.Proposal{"prp_1": {ProposalID: "prp_1", State: registry.ProposalDecided,
			Decision: &registry.Decision{DecisionID: "dec_1", Verdict: registry.VerdictRetry, Actor: registry.Actor{Kind: registry.ActorHuman, ID: "alice"}}}}}
	action := func(step string) *registry.Action {
		raw, err := json.Marshal(map[string]string{"run_id": "run-1", "attempt_id": "a1", "queued_at": "q1", "step": step})
		require.NoError(t, err)
		spec := registry.ActionSpec{Name: registry.ActionRetryRun, Params: raw}
		binding, err := registry.BindingDigest(job, spec)
		require.NoError(t, err)
		return &registry.Action{ActionID: "act_1", Kind: registry.ActionApproved, JobVersion: 3, ProposalID: "prp_1", DecisionID: "dec_1",
			Spec: spec, BindingDigest: binding, State: registry.ActionExecuting, Attempt: 1,
			Grant: &registry.Grant{GrantID: "grt_1", ActionID: "act_1", Attempt: 1, ExpiresAt: now.Add(time.Minute)}}
	}
	execution := registry.RetriedExecution{AttemptID: "a1", QueuedAt: "q1"}
	check := func(a *registry.Action, intent registry.RetryIntent) error {
		var req registry.RetryActionRequest
		if a != nil {
			req = registry.RetryActionRequest{ActionAttempt: "1", BindingDigest: a.BindingDigest}
		}
		return registry.CheckRetryRun(job, a, "run-1", execution, req, intent, now)
	}

	require.NoError(t, check(action(""), registry.RetryIntentRerun))
	require.NoError(t, check(action(registry.RetryStepPublish), registry.RetryIntentPublish))
	replayed := action("")
	replayed.State = registry.ActionSucceeded
	for name, err := range map[string]error{
		"no action":                 check(nil, registry.RetryIntentRerun),
		"rerun approval published":  check(action(""), registry.RetryIntentPublish),
		"publish approval rerun":    check(action(registry.RetryStepPublish), registry.RetryIntentRerun),
		"another step":              check(action("run"), registry.RetryIntentRerun),
		"no intent":                 check(action(""), ""),
		"a replay of a settled one": check(replayed, registry.RetryIntentRerun),
		"another run":               registry.CheckRetryRun(job, action(""), "run-2", execution, registry.RetryActionRequest{ActionAttempt: "1", BindingDigest: action("").BindingDigest}, registry.RetryIntentRerun, now),
		"after the grant":           registry.CheckRetryRun(job, action(""), "run-1", execution, registry.RetryActionRequest{ActionAttempt: "1", BindingDigest: action("").BindingDigest}, registry.RetryIntentRerun, now.Add(time.Hour)),
	} {
		require.Error(t, err, name)
		assert.Equal(t, registry.CodeStaleBinding, registry.ErrorCode(err), name)
	}
}
