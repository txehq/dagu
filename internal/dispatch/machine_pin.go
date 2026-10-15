// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dispatch

import (
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
)

// MachineLabel is the label a TXE machine worker carries: its machine ID. It
// is txe/pkg's LabelMachine, held here because that package's tests import
// this one.
const MachineLabel = "txe.machine"

// MachinePinning says how dispatch treats a TXE machine worker, one whose
// labels carry txe.machine, and a task whose worker selector does not name
// that machine (TXE-4422).
//
// A worker selector matches every worker that has the labels it names, so a
// task with an empty selector, or one naming only labels every worker has
// (os, arch, txe.owner), would otherwise reach any owner's machine. Owner
// authorization decides who may write and run a DAG, but not where a task
// whose selector names no machine lands; this does.
type MachinePinning int

const (
	// MachinePinningOff hands a machine worker any task whose selector it
	// satisfies, as before.
	MachinePinningOff MachinePinning = iota
	// MachinePinningObserve hands tasks out as MachinePinningOff does; the
	// caller logs each one enforce would refuse.
	MachinePinningObserve
	// MachinePinningEnforce hands a machine worker only tasks whose selector
	// names its own machine.
	MachinePinningEnforce
)

// MachinePinningFor is the pinning owner authorization's mode
// (txe.authz.mode) asks for. Anything but observe and enforce is off.
func MachinePinningFor(mode string) MachinePinning {
	switch mode {
	case config.TXEAuthzModeObserve:
		return MachinePinningObserve
	case config.TXEAuthzModeEnforce:
		return MachinePinningEnforce
	default:
		return MachinePinningOff
	}
}

// SelectorAdmits reports whether a worker with workerLabels may be handed a
// task whose worker selector is selector: it has every label the selector
// names and, with MachinePinningEnforce, a machine worker is named by the
// selector's txe.machine.
func SelectorAdmits(workerLabels, selector map[string]string, pinning MachinePinning) bool {
	for key, value := range selector {
		if workerLabels[key] != value {
			return false
		}
	}
	return pinning != MachinePinningEnforce || !MachinePinMissing(workerLabels, selector)
}

// MachinePinMissing reports whether workerLabels are a machine worker's and
// selector does not name that machine: the task would land on the machine
// without having been placed there.
func MachinePinMissing(workerLabels, selector map[string]string) bool {
	machine, ok := workerLabels[MachineLabel]
	if !ok {
		return false
	}
	return selector[MachineLabel] != machine
}
