// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"strings"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
	"github.com/dagucloud/dagu/v2/internal/workspace"
)

// Native DAGs and runs by owner (TXE-3415 contract 1, section 3, native
// rows).
//
// The owner of a native DAG is read from the registry by the DAG's name: a
// job DAG is named for its job, and a machine's reviewer, decision runner and
// reconciler are named for the machine. Any other DAG has no owner. A run
// belongs to its root DAG.
//
// A caller held to its owner (a person, or a provider token) carries a hub
// user with no role and no workspace (txeNeutralUser), so every native check
// that asks for a role or a workspace refuses it. The checks below, which
// know the DAG a request is about, let it in where its owner allows. A route
// that does not use them stays closed to it.

// txeNativeOwnerOnlyPrefixes are the REST routes, under the API base, that
// decide a caller held to its owner by the owner of the DAG they touch.
var txeNativeOwnerOnlyPrefixes = []string{"dags", "dag-runs", "queues"}

// txeNeutralUser is the hub user a caller held to its owner carries on
// every route: no role, no workspace, so nothing the hub's roles grant
// reaches it. A person keeps its account name and identity; a token gets an
// agent name.
func txeNeutralUser(c txeauth.Caller, user *auth.User) *auth.User {
	out := &auth.User{Role: auth.RoleNone, WorkspaceAccess: &auth.WorkspaceAccess{}}
	if user != nil {
		out.ID, out.Username = user.ID, user.Username
		out.AuthProvider, out.OIDCIssuer, out.OIDCSubject = user.AuthProvider, user.OIDCIssuer, user.OIDCSubject
	}
	if c.Kind == txeauth.KindToken {
		out.ID, out.Username = txeTokenActorID(c), txeTokenActorID(c)
	}
	return out
}

// txeNeutralize replaces the hub user of a caller held to its owner with a
// neutral one. Every other caller passes unchanged.
func (a *API) txeNeutralize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.txeAuth == nil {
			next.ServeHTTP(w, r)
			return
		}
		c := txeauth.Classify(r.Context())
		if !c.New() {
			next.ServeHTTP(w, r)
			return
		}
		user, _ := auth.UserFromContext(r.Context())
		next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), txeNeutralUser(c, user))))
	})
}

// txeNativeOwnerDAG is the DAG a run's owner is read from: its root's.
func txeNativeOwnerDAG(status *ir.DAGRunStatus) string {
	if status == nil {
		return ""
	}
	if status.Root.Name != "" {
		return status.Root.Name
	}
	return status.Name
}

// txeNativeResource names the owner's resource a native DAG is, or reports
// that it belongs to no owner.
func (a *API) txeNativeResource(ctx context.Context, dagName string) (authz.Resource, bool, error) {
	store := a.txeAuth.Store()
	var (
		res authz.Resource
		err error
	)
	switch {
	case registry.ValidateID(registry.PrefixJob, dagName) == nil:
		res, err = store.Job(ctx, dagName)
	default:
		machine, ok := txeauth.MachineOfDAG(dagName)
		if !ok {
			return authz.Resource{}, false, nil
		}
		res, err = store.Machine(ctx, machine)
	}
	if err != nil {
		if code := authz.CodeOf(err); code == authz.CodeNotFound || code == authz.CodeInvalid {
			return authz.Resource{}, false, nil
		}
		return authz.Resource{}, false, err
	}
	return res, true, nil
}

var errTxeNativeNotFound = &Error{HTTPStatus: http.StatusNotFound, Code: api.ErrorCodeNotFound, Message: "not found"}

// txeNativeCheck decides permission on the native DAG dagName. legacy is
// the hub's own check for the same request, which still governs every
// caller that is not held to its owner; the owner decision is added for such
// a caller in observe and enforce.
//
// For a caller held to its owner only the owner decides. A DAG it may not
// view is not found, as if absent; one it may view but not use this way is
// forbidden.
func (a *API) txeNativeCheck(ctx context.Context, dagName string, permission authz.Permission, legacy func() error) error {
	c, err := a.txeResolve(ctx)
	if err != nil {
		return err
	}
	if !c.ownerOnly() {
		if err := legacy(); err != nil {
			return err
		}
		if c.mode == authz.ModeOff {
			return nil
		}
	}
	if c.ownerOnly() && c.scope.Kind() == authz.ScopeUnbound {
		return errTxeNativeNotFound
	}
	res, owned, err := a.txeNativeResource(ctx, dagName)
	if err != nil {
		// A caller held to its owner is always decided in enforce; it is
		// named here as well so a lookup failure can never let it through.
		if c.ownerOnly() || c.mode == authz.ModeEnforce {
			return errTxeAuthzUnavailable
		}
		return nil
	}
	if !owned {
		// A DAG with no owner is the platform's: only the administrator,
		// and legacy callers as the mode lets them, see it.
		if c.scope.Kind() == authz.ScopePlatformAdmin || (c.mode == authz.ModeObserve && !c.ownerOnly()) {
			return nil
		}
		return errTxeNativeNotFound
	}
	ok, err := a.txeDecide(ctx, c, permission, res)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	if permission != authz.PermissionView {
		if seen, err := a.txeAuth.Store().Decide(ctx, authz.ModeEnforce, c.scope, authz.PermissionView, res); err == nil && seen.Allowed {
			return errTxeForbidden
		}
	}
	return errTxeNativeNotFound
}

// txeNativeOwnerOnly reports whether the request's caller is held to its
// owner on native routes.
func (a *API) txeNativeOwnerOnly(ctx context.Context) bool {
	return a.txeOwnerOnly(ctx)
}

// txeNativeVisible reports whether the caller may see the native DAG
// dagName, for filtering a list. A failure to decide hides it.
func (a *API) txeNativeVisible(ctx context.Context, dagName string) bool {
	return a.txeNativeCheck(ctx, dagName, authz.PermissionView, func() error { return nil }) == nil
}

// txeNothingFilter is the workspace filter of a caller held to its owner:
// it matches no workspace and no unlabelled DAG, so a list that does not
// filter by owner shows such a caller nothing.
func txeNothingFilter() *workspace.WorkspaceFilter {
	return &workspace.WorkspaceFilter{Enabled: true, IncludeUnlabelled: false}
}

// requireDAGVisible applies the hub's workspace check, or for a caller held
// to its owner the owner's decision, to seeing a DAG.
func (a *API) requireDAGVisible(ctx context.Context, dag *ir.DAG) error {
	return a.requireNamedDAGVisible(ctx, dag.Name, dagWorkspaceName(dag))
}

// requireDAGExecute is requireDAGVisible for running a DAG.
func (a *API) requireDAGExecute(ctx context.Context, dag *ir.DAG) error {
	return a.requireNamedDAGExecute(ctx, dag.Name, dagWorkspaceName(dag))
}

// requireNamedDAGVisible decides seeing the DAG dagName whose workspace, for
// the hub's own check, is workspaceName.
func (a *API) requireNamedDAGVisible(ctx context.Context, dagName, workspaceName string) error {
	return a.txeNativeCheck(ctx, dagName, authz.PermissionView, func() error { return a.requireWorkspaceVisible(ctx, workspaceName) })
}

// requireNamedDAGExecute decides running the DAG dagName.
func (a *API) requireNamedDAGExecute(ctx context.Context, dagName, workspaceName string) error {
	return a.txeNativeCheck(ctx, dagName, authz.PermissionExecute, func() error { return a.requireExecuteForWorkspace(ctx, workspaceName) })
}

// txeNativeRoute says whether a request is on a native route that decides a
// caller held to its owner by the owner of the DAG it touches.
func txeNativeRoute(mountedAPIPath string, p string) bool {
	for _, prefix := range txeNativeOwnerOnlyPrefixes {
		root := strings.TrimSuffix(mountedAPIPath, "/") + "/" + prefix
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}
