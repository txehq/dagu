// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dagucloud/dagu/v2/internal/ir"
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
