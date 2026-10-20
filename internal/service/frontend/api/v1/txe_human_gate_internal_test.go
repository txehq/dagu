// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dagucloud/dagu/v2/internal/humantask"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
)

// Answering a human gate on an owner's DAG takes approve, which only a
// person holds: the owner's command line, and its machine's worker and
// reviewer credentials, still execute the run but do not answer its gates.
// Another owner is told nothing. The administrator and a legacy key are
// decided by the mode as before: in enforce neither answers an owner's gate
// (TXE-4721).
func TestTxeHumanGatesAreAnsweredByAPerson(t *testing.T) {
	for _, mode := range []string{"", "enforce"} {
		t.Run("mode="+mode, func(t *testing.T) {
			w := newTwoOwners(t, mode)
			run := &ir.DAGRunStatus{Name: w.jobA, DAGRunID: "r1"}
			approve := func(ctx context.Context) int { return statusOf(w.api.requireDAGRunStatusApprove(ctx, run)) }
			execute := func(ctx context.Context) int { return statusOf(w.api.requireDAGRunStatusExecute(ctx, run)) }

			assert.Equal(t, http.StatusOK, approve(w.personA), "A's person")
			for name, ctx := range map[string]context.Context{"cli": w.cliA, "worker": w.workerA, "reviewer": w.reviewerA} {
				assert.Equal(t, http.StatusForbidden, approve(ctx), "A's %s answers no gate", name)
				assert.Equal(t, http.StatusOK, execute(ctx), "A's %s still executes", name)
			}
			assert.Equal(t, http.StatusNotFound, approve(w.personB), "B's person")
			assert.Equal(t, http.StatusNotFound, approve(w.cliB), "B's cli")

			if mode == "enforce" {
				assert.Equal(t, http.StatusForbidden, approve(w.admin), "the administrator views, and answers no owner's gate")
				assert.Equal(t, http.StatusNotFound, approve(w.legacy), "a legacy key sees no owner's run")
			} else {
				assert.Equal(t, http.StatusOK, approve(w.admin), "off: as before")
				assert.Equal(t, http.StatusOK, approve(w.legacy), "off: as before")
			}
		})
	}
}

// One completion is a reviewer's, not a person's: closing its own machine's
// decision run of a superseded proposal, at the decide step, with the
// superseded marker and no decision. It decides nothing, and that machine's
// reviewer executes it. Anything else on that run, or that input anywhere
// else, or from any other credential, is a person's gate as before.
func TestTxeReviewerClosesItsSupersededDecisionRun(t *testing.T) {
	w := newTwoOwners(t, "enforce")
	decideA := &ir.DAGRunStatus{Name: registry.DecideTaskDAG(w.machineA), DAGRunID: "r1"}
	closing := humantask.Input{Values: map[string]any{"verdict": review.VerdictSuperseded, "decision_id": review.NoDecisionID}}
	answering := humantask.Input{Values: map[string]any{"verdict": "approve", "decision_id": "dec_01"}}
	complete := func(ctx context.Context, status *ir.DAGRunStatus, step string, input humantask.Input) int {
		return statusOf(w.api.requireHumanTaskCompletion(ctx, status, step, input))
	}

	assert.Equal(t, http.StatusOK, complete(w.reviewerA, decideA, registry.DecideTaskStep, closing), "A's reviewer closes its own")
	assert.Equal(t, http.StatusForbidden, complete(w.reviewerA, decideA, registry.DecideTaskStep, answering), "but answers nothing")
	assert.Equal(t, http.StatusForbidden, complete(w.reviewerA, decideA, "another-step", closing), "and only at the decide step")
	extra := humantask.Input{Values: map[string]any{"verdict": review.VerdictSuperseded, "decision_id": review.NoDecisionID, "note": "x"}}
	assert.Equal(t, http.StatusForbidden, complete(w.reviewerA, decideA, registry.DecideTaskStep, extra), "and with the marker alone")
	for name, ctx := range map[string]context.Context{"worker": w.workerA, "cli": w.cliA} {
		assert.Equal(t, http.StatusForbidden, complete(ctx, decideA, registry.DecideTaskStep, closing), "A's %s closes nothing", name)
	}
	assert.Equal(t, http.StatusNotFound, complete(w.reviewerB, decideA, registry.DecideTaskStep, closing), "B's reviewer")
	assert.Equal(t, http.StatusOK, complete(w.personA, decideA, registry.DecideTaskStep, answering), "A's person answers")

	job := &ir.DAGRunStatus{Name: w.jobA, DAGRunID: "r2"}
	assert.Equal(t, http.StatusForbidden, complete(w.reviewerA, job, registry.DecideTaskStep, closing), "the marker elsewhere is a person's gate")
}
