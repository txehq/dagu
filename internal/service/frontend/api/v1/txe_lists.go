// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// Whole-hub lists by owner (TXE-4416, S4b-2).
//
// GET /dags, GET /dag-runs, their labels and tags, and the event stream's
// list topics show each caller what S4 lets it read DAG by DAG, decided in
// the store's own iteration so that pages and counts are of what is shown:
//
//   - a caller held to its owner sees the DAGs it may view by owner (its
//     owner's jobs and machine DAGs, and jobs shared with it), and their
//     runs, whatever workspace it names;
//   - a legacy caller in enforce sees none, as it reads none;
//   - everyone else (the platform administrator, legacy callers in off and
//     observe) sees what its workspaces allow, as before.

// txeListScope is how a whole-hub list is narrowed for the caller.
type txeListScope struct {
	// replaceWorkspace says the owner decides instead of the workspace
	// filter.
	replaceWorkspace bool
	dag              func(persis.DAGListItem) bool
	run              func(*ir.DAGRunStatus) bool
}

// apply narrows a DAG list.
func (s txeListScope) apply(opts *persis.DAGListOptions) {
	if s.dag == nil {
		return
	}
	if s.replaceWorkspace {
		opts.WorkspaceFilter = nil
	}
	opts.Include = s.dag
}

// applyRuns narrows a DAG-run list.
func (s txeListScope) applyRuns(query *persis.DAGRunListOptions) {
	if s.run == nil {
		return
	}
	if s.replaceWorkspace {
		query.WorkspaceFilter = nil
	}
	query.Include = s.run
}

// txeWholeHubListScope decides the caller's whole-hub lists.
func (a *API) txeWholeHubListScope(ctx context.Context) (txeListScope, error) {
	if a.txeAuth == nil {
		return txeListScope{}, nil
	}
	c, err := a.txeResolve(ctx)
	if err != nil {
		return txeListScope{}, err
	}
	switch {
	case c.ownerOnly():
		names, err := a.txeOwnerVisibleDAGNames(ctx)
		if err != nil {
			return txeListScope{}, err
		}
		return txeListScope{
			replaceWorkspace: true,
			dag:              func(item persis.DAGListItem) bool { return item.DAG != nil && names[txeNativeDAGName(item.DAG)] },
			run:              txeRunListed(names),
		}, nil
	case c.mode == authz.ModeEnforce && c.scope.Kind() != authz.ScopePlatformAdmin:
		none := func(persis.DAGListItem) bool { return false }
		return txeListScope{dag: none, run: func(*ir.DAGRunStatus) bool { return false }}, nil
	default:
		return txeListScope{}, nil
	}
}

// txeOneDAGListScope decides a list of one DAG's runs as S4 decides reading
// that DAG: whoever may read it sees its runs (a caller held to its owner
// whatever workspace it names), and whoever may not sees none. A failure to
// decide is an outage, never a list.
func (a *API) txeOneDAGListScope(ctx context.Context, dagName string) (txeListScope, error) {
	if a.txeAuth == nil {
		return txeListScope{}, nil
	}
	c, err := a.txeResolve(ctx)
	if err != nil {
		return txeListScope{}, err
	}
	if c.mode == authz.ModeOff && !c.ownerOnly() {
		return txeListScope{}, nil
	}
	switch err := a.txeNativeCheck(ctx, dagName, authz.PermissionView, func() error { return nil }); {
	case err == nil && c.ownerOnly():
		// Each run is still decided as S4 reads it: a run of this DAG may
		// be a sub-run of another owner's.
		names, err := a.txeOwnerVisibleDAGNames(ctx)
		if err != nil {
			return txeListScope{}, err
		}
		return txeListScope{replaceWorkspace: true, run: txeRunListed(names)}, nil
	case err == nil:
		return txeListScope{}, nil
	case err == errTxeAuthzUnavailable:
		return txeListScope{}, err
	default:
		return txeListScope{run: func(*ir.DAGRunStatus) bool { return false }}, nil
	}
}

// txeRunListed decides a run for a caller held to its owner as S4 decides
// reading it (requireRunStatus): by its root's DAG and, when the run is of
// another DAG, by that DAG too unless no owner has it. names is every DAG
// the caller may view.
func txeRunListed(names map[string]bool) func(*ir.DAGRunStatus) bool {
	return func(status *ir.DAGRunStatus) bool {
		root := txeNativeOwnerDAG(status)
		if !names[root] {
			return false
		}
		switch {
		case status.Name == root:
			return true
		case status.Name == "":
			return false
		case txeNativeOwnedName(status.Name):
			return names[status.Name]
		default:
			return true
		}
	}
}

// txeOwnerVisibleDAGNames is every DAG a caller held to its owner may view,
// by name: the jobs owner view lets it see and the machine DAGs of the
// machines it may see. A failure to decide is an outage, never a shorter
// list.
func (a *API) txeOwnerVisibleDAGNames(ctx context.Context) (map[string]bool, error) {
	s, err := a.txeStore()
	if err != nil {
		return nil, err
	}
	jobs, err := s.ListJobs(ctx, registry.JobFilter{})
	if err != nil {
		return nil, errTxeAuthzUnavailable
	}
	machines, err := s.ListMachines(ctx, "")
	if err != nil {
		return nil, errTxeAuthzUnavailable
	}
	candidates := make([]string, 0, len(jobs)+3*len(machines))
	for _, job := range jobs {
		candidates = append(candidates, job.JobID)
	}
	for _, m := range machines {
		candidates = append(candidates, txeauth.MachineDAGs(m.MachineID)...)
	}
	out := map[string]bool{}
	for _, name := range candidates {
		switch err := a.txeNativeCheck(ctx, name, authz.PermissionView, func() error { return nil }); err {
		case nil:
			out[name] = true
		case errTxeAuthzUnavailable:
			return nil, err
		}
	}
	return out, nil
}
