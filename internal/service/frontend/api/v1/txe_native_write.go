// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/parser"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/yamlutil"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
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

// txeNativeWrite decides a native write to the DAGs named names, whose
// definition, when the write supplies one, is spec, after the hub's own check
// legacy for the callers it governs.
//
// It decides what the DAG store and the spec loader will use, not the
// request's strings: each name as the store resolves it (txeCanonicalDAGName),
// every name the spec declares (the first document's and each local DAG's),
// and every machine the spec runs on (worker_selector txe.machine). A
// machine's own DAG runs only on that machine.
func (a *API) txeNativeWrite(ctx context.Context, legacy func() error, spec []byte, names ...string) error {
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

	files := map[string]bool{}
	for _, name := range names {
		if name != "" {
			files[txeCanonicalDAGName(name)] = true
		}
	}
	decide := map[string]bool{}
	for name := range files {
		decide[name] = true
	}
	var placements []txePlacement
	if spec != nil {
		declared, err := a.txeSpecPlacements(ctx, spec)
		if err != nil {
			if refused := a.txeNativeWriteUnverified(ctx, c, err); refused != nil {
				return refused
			}
		}
		for _, p := range declared {
			// A DAG that declares no name takes the file's, decided above.
			if strings.TrimSpace(p.name) != "" {
				decide[txeCanonicalDAGName(p.name)] = true
			}
		}
		placements = declared
	}
	for name := range decide {
		if err := a.txeNativeWriteName(ctx, c, name); err != nil {
			return err
		}
	}

	// Where it runs. Every machine it is sent to needs author on that
	// machine; a machine's own DAG is sent only to that machine.
	targets := map[string]bool{}
	for _, p := range placements {
		if p.machine != "" {
			targets[p.machine] = true
		}
	}
	for machine := range targets {
		if err := a.txeNativeWriteName(ctx, c, txeauth.MachineDAGs(machine)[0]); err != nil {
			return err
		}
	}
	if spec != nil {
		for name := range files {
			own, ok := txeauth.MachineOfDAG(name)
			if !ok {
				continue
			}
			for _, p := range placements {
				// Every document is pinned to the machine; a step may leave
				// its placement to its child, but may not send it elsewhere.
				if (!p.step && p.machine != own) || (p.step && p.machine != "" && p.machine != own) {
					return a.txeNativeWriteMisplaced(ctx, c, name)
				}
			}
		}
	}
	return nil
}

// txePlacement is one DAG a spec defines, or one step of it: the name it
// declares or calls, and the machine it is sent to, if any.
type txePlacement struct {
	// name is a DAG the spec defines (its declared name) or a step calls.
	name string
	// machine is the txe.machine a document or a step selects, if any.
	machine string
	// step marks a step's placement or reference, not a document's.
	step bool
}

// txeSpecPlacements reads a spec as the loader reads it, with no name
// imposed and nothing evaluated: every DAG it defines (the first document
// and each local DAG), by its declared name and the machine it is sent to,
// and every step of each, handlers included, by the DAG it calls and the
// machine it sends that to. A spec that does not load, or whose worker
// selector or called DAG is computed, cannot be verified.
func (a *API) txeSpecPlacements(ctx context.Context, spec []byte) ([]txePlacement, error) {
	if err := txeSelectorsWritten(spec); err != nil {
		return nil, err
	}
	dag, err := a.dagRepository.LoadSpec(ctx, spec, "", persis.DAGLoadOptions{})
	if err != nil {
		return nil, err
	}
	if dag == nil {
		return nil, errTxeSpecUnverified
	}
	dags := []*ir.DAG{dag}
	for _, local := range dag.LocalDAGs {
		dags = append(dags, local)
	}
	var out []txePlacement
	for _, d := range dags {
		machine, err := txeSelectedMachine(d.WorkerSelector)
		if err != nil {
			return nil, err
		}
		out = append(out, txePlacement{name: d.Name, machine: machine})
		steps := make([]*ir.Step, 0, len(d.Steps)+6)
		for i := range d.Steps {
			steps = append(steps, &d.Steps[i])
		}
		h := d.HandlerOn
		for _, handler := range []*ir.Step{h.Init, h.Failure, h.Success, h.Abort, h.Exit, h.Wait} {
			if handler != nil {
				steps = append(steps, handler)
			}
		}
		for _, step := range steps {
			machine, err := txeSelectedMachine(step.WorkerSelector)
			if err != nil {
				return nil, err
			}
			called := ""
			if step.SubDAG != nil {
				called = step.SubDAG.Name
				if strings.ContainsAny(called, "$`") {
					return nil, errTxeSpecUnverified
				}
			}
			if machine != "" || called != "" {
				out = append(out, txePlacement{name: called, machine: machine, step: true})
			}
		}
	}
	return out, nil
}

// txeSelectedMachine is the machine a worker selector sends work to, or ""
// for none, read as the runtime reads it: keys and values trimmed, and an
// empty or repeated key an error. The coordinator matches every label a
// selector names, and every worker carries labels that are not its machine
// (os, arch, txe.owner), so a selector that names labels but no machine can
// reach any machine that has them: where it runs cannot be decided, and it
// is not verified. Neither is a computed selector.
func txeSelectedMachine(selector map[string]string) (string, error) {
	seen := make(map[string]bool, len(selector))
	machine := ""
	for k, v := range selector {
		if strings.ContainsAny(k+v, "$`") {
			return "", errTxeSpecUnverified
		}
		key := strings.TrimSpace(k)
		if key == "" || seen[key] {
			return "", errTxeSpecUnverified
		}
		seen[key] = true
		if key == txeMachineLabel {
			machine = strings.TrimSpace(v)
		}
	}
	if len(selector) > 0 && machine == "" {
		return "", errTxeSpecUnverified
	}
	return machine, nil
}

// txeSelectorsWritten refuses a spec whose worker selectors, wherever they
// are written, have a key or value with surrounding space. The loader trims
// a DAG's selector as it builds it, so two keys that differ only in space
// collapse into one, by map order; the runtime trims a step's. Written
// already trimmed, a selector reads the same to this check, the loader and
// the runtime.
func txeSelectorsWritten(spec []byte) error {
	file, err := parser.ParseBytes(yamlutil.ClearEmptyDocumentSeparators(spec), 0)
	if err != nil || file == nil {
		return errTxeSpecUnverified
	}
	for _, doc := range file.Docs {
		if doc == nil || doc.Body == nil {
			continue
		}
		raw, err := doc.MarshalYAML()
		if err != nil {
			return errTxeSpecUnverified
		}
		var tree any
		if err := yaml.Unmarshal(raw, &tree); err != nil {
			return errTxeSpecUnverified
		}
		if !txeSelectorsTrimmed(tree) {
			return errTxeSpecUnverified
		}
	}
	return nil
}

func txeSelectorsTrimmed(node any) bool {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if strings.EqualFold(strings.TrimSpace(k), "worker_selector") {
				if selector, ok := v.(map[string]any); ok {
					for key, value := range selector {
						text, isText := value.(string)
						if key != strings.TrimSpace(key) || (isText && text != strings.TrimSpace(text)) {
							return false
						}
					}
				}
			}
			if !txeSelectorsTrimmed(v) {
				return false
			}
		}
	case []any:
		for _, v := range n {
			if !txeSelectorsTrimmed(v) {
				return false
			}
		}
	}
	return true
}

const txeMachineLabel = "txe.machine"

var errTxeSpecUnverified = &Error{HTTPStatus: http.StatusBadRequest, Code: api.ErrorCodeBadRequest,
	Message: "the spec could not be verified: it does not load, or a worker selector is computed or does not name the machine it runs on",
	Details: map[string]any{"code": "spec_unverified"}}

// txeNativeWriteUnverified decides a write whose spec could not be read for
// its names and placement: logged and let through in observe for a caller
// the mode governs, refused otherwise.
func (a *API) txeNativeWriteUnverified(ctx context.Context, c txeCall, cause error) error {
	if c.mode == authz.ModeObserve && !c.ownerOnly() {
		a.txeLogDecision(ctx, c, authz.PermissionAuthor, authz.Resource{}, authz.Decision{
			Allowed: true, Mode: c.mode, Evaluated: true, WouldDeny: true, Reason: authz.ReasonInvalid})
		return nil
	}
	if apiErr, ok := cause.(*Error); ok && apiErr == errTxeSpecUnverified {
		return apiErr
	}
	return errTxeSpecUnverified
}

// txeNativeWriteMisplaced refuses a machine's DAG that would run elsewhere
// than on its machine, as txeNativeWriteRefused refuses.
func (a *API) txeNativeWriteMisplaced(ctx context.Context, c txeCall, name string) error {
	return a.txeNativeWriteRefused(ctx, c, name)
}

// txeCanonicalDAGName is the DAG a name resolves to in the DAG store: its
// base name, without a .yaml or .yml extension. An owner's DAG name is folded
// to its canonical case, since a case-insensitive filesystem stores the
// variants as one file: a near-collision of an owned name is that name.
func txeCanonicalDAGName(name string) string {
	base := filepath.Base(name)
	if ext := filepath.Ext(base); strings.EqualFold(ext, ".yaml") || strings.EqualFold(ext, ".yml") {
		base = strings.TrimSuffix(base, ext)
	}
	lower := strings.ToLower(base)
	for _, prefix := range append([]string{string(registry.PrefixJob) + "_"}, txeauth.MachineDAGPrefixes()...) {
		if strings.HasPrefix(lower, prefix) {
			return prefix + strings.ToUpper(base[len(prefix):])
		}
	}
	return base
}

// txeNativeWriteClosed is txeNativeWrite for a write that stays closed to a
// caller held to its owner: an inline or edited run, or a DAG's settings.
// Only creating, changing, renaming and deleting a machine's DAG are opened
// to such a caller.
func (a *API) txeNativeWriteClosed(ctx context.Context, legacy func() error, spec []byte, names ...string) error {
	if a.txeNativeOwnerOnly(ctx) {
		return errTxeForbidden
	}
	return a.txeNativeWrite(ctx, legacy, spec, names...)
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
