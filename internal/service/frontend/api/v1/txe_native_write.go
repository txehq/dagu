// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// Native writes by owner (TXE-4412, S4b-1).
//
// A native write is one that changes a DAG definition, or runs one that is
// not the stored definition: create, change, rename (its source and its
// destination), delete, the DAG's settings, an inline spec run and an edited
// retry. Each is decided for every name it touches: the file's, and any name
// the definition declares, so that no file takes an owner's DAG name.
//
//   - A job's DAG is the registry's: nobody is permitted to write it
//     natively, the platform administrator included.
//   - A machine's DAG is permitted to whoever holds author on the machine,
//     as the owner store decides it: a person or cli of the machine's owner.
//     The platform administrator holds only view on an owner's resources.
//   - Any other DAG is the platform's, as S4 decides it for reads.
//
// What happens to a write that is not permitted depends on who asks and the
// mode. For legacy callers and the administrator: in off the hub's own check
// alone decides, as before; in observe the write proceeds and is logged as
// would-deny; in enforce it is refused. A caller held to its owner (a person
// or a provider token) is decided by owner in every mode: refused whenever
// not permitted.
//
// A machine's owner never changes (the registry does not re-point a machine
// ID), and a create or a rename onto a name that exists fails in the DAG
// store itself, so deciding by name before the write cannot be raced into
// writing another owner's DAG.

// txeNativeWrite decides a native write to the DAGs named names, after the
// hub's own check legacy for the callers it governs.
func (a *API) txeNativeWrite(ctx context.Context, legacy func() error, names ...string) error {
	if a.txeAuth == nil {
		return legacy()
	}
	c, err := a.txeResolve(ctx)
	if err != nil {
		return err
	}
	if c.ownerOnly() {
		// The hub's own switches still hold for a caller held to its owner;
		// only its role and workspaces, which it does not have, are not
		// asked.
		if err := a.requireDAGWritesEnabled(); err != nil {
			return err
		}
	} else {
		if err := legacy(); err != nil {
			return err
		}
		if c.mode == authz.ModeOff {
			return nil
		}
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if err := a.txeNativeWriteName(ctx, c, name); err != nil {
			return err
		}
	}
	return nil
}

// txeNativeWriteClosed is txeNativeWrite for a write that stays closed to a
// caller held to its owner: an inline or edited run, or a DAG's settings.
// Only creating, changing, renaming and deleting a machine's DAG are opened
// to such a caller.
func (a *API) txeNativeWriteClosed(ctx context.Context, legacy func() error, names ...string) error {
	if a.txeNativeOwnerOnly(ctx) {
		return errTxeForbidden
	}
	return a.txeNativeWrite(ctx, legacy, names...)
}

// requireDAGWritesEnabled is the hub's own switch on DAG writes, apart from
// who asks.
func (a *API) requireDAGWritesEnabled() error {
	if !a.config.Server.Permissions[config.PermissionWriteDAGs] {
		return errPermissionDenied
	}
	if a.dagWritesDisabled {
		return errDAGWritesDisabled
	}
	return nil
}

// txeNativeWriteName decides a native write to one DAG name.
func (a *API) txeNativeWriteName(ctx context.Context, c txeCall, name string) error {
	if registry.IsJobDAG(name) {
		// The registry is the only writer of a job's DAG.
		return a.txeNativeWriteRefused(ctx, c, name)
	}
	if machine, ok := txeauth.MachineOfDAG(name); ok {
		res, err := a.txeAuth.Store().Machine(ctx, machine)
		if err != nil {
			if code := authz.CodeOf(err); code == authz.CodeNotFound || code == authz.CodeInvalid {
				// A machine's name for a machine that is not registered:
				// reserved, and nobody's to write.
				return a.txeNativeWriteRefused(ctx, c, name)
			}
			if c.ownerOnly() || c.mode == authz.ModeEnforce {
				return errTxeAuthzUnavailable
			}
			return nil
		}
		allowed, err := a.txeDecide(ctx, c, authz.PermissionAuthor, res)
		if err != nil {
			return err
		}
		if allowed {
			return nil
		}
		return a.txeNativeWriteDenied(ctx, name)
	}
	// The platform's: as S4 decides it.
	switch {
	case c.ownerOnly():
		return errTxeNativeNotFound
	case c.scope.Kind() == authz.ScopePlatformAdmin, c.mode == authz.ModeObserve:
		return nil
	default:
		return errTxeNativeNotFound
	}
}

// txeNativeWriteRefused refuses a write that no caller may make natively:
// logged and let through in observe for a caller the mode governs, refused
// otherwise.
func (a *API) txeNativeWriteRefused(ctx context.Context, c txeCall, name string) error {
	res, owned, err := a.txeNativeResource(ctx, name)
	if err != nil && (c.ownerOnly() || c.mode == authz.ModeEnforce) {
		return errTxeAuthzUnavailable
	}
	if !owned {
		res = authz.Resource{}
	}
	if c.mode == authz.ModeObserve && !c.ownerOnly() {
		a.txeLogDecision(ctx, c, authz.PermissionAuthor, res, authz.Decision{
			Allowed: true, Mode: c.mode, Evaluated: true, WouldDeny: true, Reason: authz.ReasonClass})
		return nil
	}
	a.txeLogDecision(ctx, c, authz.PermissionAuthor, res, authz.Decision{Mode: c.mode, Evaluated: true, Reason: authz.ReasonClass})
	return a.txeNativeWriteDenied(ctx, name)
}

// txeNativeWriteDenied is the answer to a refused write: forbidden for a DAG
// the caller may see, not found for one it may not, so a write tells nothing
// a read would not.
func (a *API) txeNativeWriteDenied(ctx context.Context, name string) error {
	if a.txeNativeVisible(ctx, name) {
		return errTxeForbidden
	}
	return errTxeNativeNotFound
}
