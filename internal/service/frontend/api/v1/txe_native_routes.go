// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"

	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
)

// Owner decisions on the native routes S4 and S4b left to the hub's roles
// and workspaces (TXE-4741): a DAG's webhooks, notifications, incidents,
// settings and browser cache, deleting a run, and answering or restarting
// a run's agent session.
//
// Each route keeps its own role check first, so a caller held to its owner,
// which has no role, is refused there as before and gains nothing. The
// owner decision is then made as txeNativeCheck makes it for every native
// route: in off nothing more; in observe a would-deny is logged; in enforce
// a legacy credential sees no DAG, and the platform administrator only
// views an owner's.

// txeDAGRoute decides permission on the DAG a route names, after the
// route's own role check.
func (a *API) txeDAGRoute(ctx context.Context, fileName string, permission authz.Permission) error {
	if a.txeAuth == nil {
		return nil
	}
	return a.txeNativeCheck(ctx, txeCanonicalDAGName(fileName), permission, func() error { return nil })
}

// txeWebhookTrigger decides a webhook trigger of dag. A webhook token is no
// owner's principal, so where owners are enforced it starts no owner's DAG:
// it is answered as a webhook that does not exist, and in observe it is
// logged as one enforce would refuse. A job's DAG is admitted as any start
// of it is, in every mode: a retired or paused job is not run by its
// webhook either.
func (a *API) txeWebhookTrigger(ctx context.Context, dag *ir.DAG) error {
	if a.txeAuth == nil {
		return nil
	}
	res, owned, err := a.txeNativeResource(ctx, txeOwnedIdentity(dag))
	mode := a.txeAuth.Mode()
	switch {
	case err != nil && mode == authz.ModeEnforce:
		return errTxeAuthzUnavailable
	case err == nil && owned && mode == authz.ModeEnforce:
		return errTxeNativeNotFound
	case err == nil && owned && mode == authz.ModeObserve:
		a.txeLogDecision(ctx, txeCall{mode: mode}, authz.PermissionExecute, res, authz.Decision{
			Allowed: true, Mode: mode, Evaluated: true, WouldDeny: true, Reason: authz.ReasonUnbound})
	}
	return a.txeAdmitDAG(ctx, dag)
}

// txeWebhookVisible reports whether the caller may see the webhook of the
// DAG dagName in a list: whether it may view that DAG.
func (a *API) txeWebhookVisible(ctx context.Context, dagName string) bool {
	if a.txeAuth == nil {
		return true
	}
	return a.txeNativeVisible(ctx, txeCanonicalDAGName(dagName))
}

// txeOwnedIdentity is the name of the owner's DAG that dag is, for a
// decision on it: its file's name when that is an owner's DAG name, or
// else the name it declares when that is one, or else its file's name. A
// file that declares another name than its own answers here to whichever
// of the two an owner holds, so an alias of an owner's DAG is decided as
// that DAG and never as one of no owner. A run is stored under the name
// its DAG declares, so a run's DAG is read from its attempt.
func txeOwnedIdentity(dag *ir.DAG) string {
	stem := dag.SuspendFlagName()
	switch {
	case txeNativeOwnedName(stem):
		return stem
	case txeNativeOwnedName(dag.Name):
		return dag.Name
	default:
		return stem
	}
}

// txeRunRoute decides permission on a run's DAG after the route's own
// check: on runName, the name the run is stored under, and on the DAG its
// attempt ran as its owner holds it (txeOwnedIdentity), when the attempt
// can be read. Both must allow.
func (a *API) txeRunRoute(ctx context.Context, runName string, attempt dagrun.Attempt, permission authz.Permission) error {
	if a.txeAuth == nil {
		return nil
	}
	if err := a.txeDAGRoute(ctx, runName, permission); err != nil {
		return err
	}
	if attempt == nil {
		return nil
	}
	dag, err := attempt.ReadDAG(ctx)
	if err != nil || dag == nil {
		// The run exists, but which DAG it ran cannot be read: it cannot be
		// shown to be no owner's, so where owners are decided it is not
		// taken for one.
		if a.txeOwnerOnly(ctx) || a.txeAuth.Mode() == authz.ModeEnforce {
			return errTxeAuthzUnavailable
		}
		return nil
	}
	if identity := txeOwnedIdentity(dag); identity != txeCanonicalDAGName(runName) {
		return a.txeDAGRoute(ctx, identity, permission)
	}
	return nil
}
