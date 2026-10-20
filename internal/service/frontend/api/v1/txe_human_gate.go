// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"

	"github.com/dagucloud/dagu/v2/internal/humantask"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// requireHumanTaskCompletion decides completing a run's human task. It is
// answering a person's gate (approve), but for one completion: a reviewer
// closing its own machine's decision run of a superseded proposal, at the
// decide step, with the superseded marker and no decision
// (review.RunOpener.CloseDecision). That completion decides nothing, since
// the decide step's input only points at a decision, and the reviewer's
// credential executes it on its own machine's decide DAG. A caller held to
// its owner takes it only as that machine's reviewer.
func (a *API) requireHumanTaskCompletion(ctx context.Context, status *ir.DAGRunStatus, stepID string, input humantask.Input) error {
	if status == nil || !txeSupersededClosure(status, stepID, input) {
		return a.requireDAGRunStatusApprove(ctx, status)
	}
	machine, _ := txeauth.MachineOfDAG(status.Name)
	if a.txeAuth != nil && txeauth.Classify(ctx).New() {
		c, err := a.txeResolve(ctx)
		if err != nil {
			return err
		}
		if c.scope.Kind() != authz.ScopeMachine || c.scope.Class() != authn.ClassReviewer || c.scope.MachineID() != machine {
			return a.requireDAGRunStatusApprove(ctx, status)
		}
	}
	return a.requireDAGRunStatusExecute(ctx, status)
}

// txeSupersededClosure reports whether completing stepID of status with
// input is a reviewer closing a superseded proposal's decision run.
func txeSupersededClosure(status *ir.DAGRunStatus, stepID string, input humantask.Input) bool {
	machine, ok := txeauth.MachineOfDAG(status.Name)
	if !ok || status.Name != registry.DecideTaskDAG(machine) || stepID != registry.DecideTaskStep || len(input.Values) != 2 {
		return false
	}
	verdict, _ := input.Values["verdict"].(string)
	decision, _ := input.Values["decision_id"].(string)
	return verdict == review.VerdictSuperseded && decision == review.NoDecisionID
}
