// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeauth

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/dagucloud/dagu/v2/internal/intake"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// IsOwnedDAGName reports whether name has the form of an owner's DAG: a
// registered job, or one of a machine's own DAGs.
func IsOwnedDAGName(name string) bool {
	if registry.IsJobDAG(name) {
		return true
	}
	_, ok := MachineOfDAG(name)
	return ok
}

// OwnedDAGIdentity is the name of the owner's DAG that dag is, for a decision
// on it: the first of its file's name, the name of the file it was loaded
// from (all a queued run's DAG keeps of its file, as enqueueing clears its
// location) and the name it declares that is an owner's DAG name, or else
// its file's name. A file that declares another name than its own answers
// here to whichever an owner holds, so an alias of an owner's DAG is decided
// as that DAG and never as one of no owner. It is the one definition the
// hub's routes and the scheduler share.
func OwnedDAGIdentity(dag *ir.DAG) string {
	stem := func(path string) string {
		if path == "" {
			return ""
		}
		return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	// The file's name only when it has a location: without one,
	// SuspendFlagName falls back to the declared name, which must not come
	// before the source file's.
	for _, name := range []string{stem(dag.Location), stem(dag.SourceFile), dag.Name} {
		if name != "" && IsOwnedDAGName(name) {
			return name
		}
	}
	return dag.SuspendFlagName()
}

var (
	// ErrUnboundOwnerDAG refuses a run no hub principal asks for on an
	// owner's DAG where owners are enforced.
	ErrUnboundOwnerDAG = errors.New("a run no hub principal asks for does not start an owner's DAG")
	// ErrUnboundOwnerUnknown refuses one whose DAG could not be shown to be
	// no owner's where owners are enforced.
	ErrUnboundOwnerUnknown = errors.New("whether the DAG is an owner's could not be decided")
)

// UnboundDecision is the owner rule's answer for a run no hub principal asks
// for, such as a webhook delivery.
type UnboundDecision struct {
	// Trigger goes into intake.QueueRequest.Unbound; without it the run is
	// not queued.
	Trigger intake.UnboundTrigger
	// Identity is the owner's DAG the run was decided as (OwnedDAGIdentity).
	Identity string
	// Owned reports that Identity is an owner's DAG.
	Owned bool
	// WouldDeny reports an owner's DAG allowed only because owners are
	// observed, not enforced; the caller reports it.
	WouldDeny bool
}

// DecideUnboundTrigger is the one owner rule for a run no hub principal asks
// for (TXE-5923): the hub's webhook route and the Dagu Cloud public-webhook
// relay both decide with it, and it alone makes the intake.UnboundTrigger
// such a run needs.
//
// mode is the owner mode, and known says whether it was read at all: a
// process that did not load the TXE configuration cannot tell, and decides
// as enforce, failing closed. owned reports whether an owner holds the
// identity; nil takes an owner's DAG name for an owner's DAG, which also
// fails closed. Under enforce an owner's DAG is refused, and so is one whose
// ownership could not be read; under observe it is allowed and reported;
// under off it is allowed.
func DecideUnboundTrigger(mode authz.Mode, known bool, dag *ir.DAG, owned func(identity string) (bool, error)) (UnboundDecision, error) {
	decision := UnboundDecision{Identity: OwnedDAGIdentity(dag)}
	enforced := !known || mode == authz.ModeEnforce
	if IsOwnedDAGName(decision.Identity) {
		decision.Owned = true
		if owned != nil {
			held, err := owned(decision.Identity)
			if err != nil {
				if enforced {
					return decision, ErrUnboundOwnerUnknown
				}
				held = false
			}
			decision.Owned = held
		}
	}
	if decision.Owned {
		switch {
		case enforced:
			return decision, ErrUnboundOwnerDAG
		case mode == authz.ModeObserve:
			decision.WouldDeny = true
		}
	}
	decision.Trigger = intake.NewUnboundTrigger()
	return decision, nil
}
