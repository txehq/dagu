// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeauth

import (
	"strings"

	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// machineDAGPrefixes name the DAGs the hub keeps for one machine: its
// reviewer, its decision runner and its reconciler. Each is named for the
// machine's id without its prefix.
var machineDAGPrefixes = []string{"txe-reviewer-", "txe-decide-", "txe-reconcile-"}

// MachineDAGs returns the names of a machine's per-machine DAGs.
func MachineDAGs(machineID string) []string {
	rest := strings.TrimPrefix(machineID, string(registry.PrefixMachine)+"_")
	out := make([]string, 0, len(machineDAGPrefixes))
	for _, prefix := range machineDAGPrefixes {
		out = append(out, prefix+rest)
	}
	return out
}

// MachineOfDAG returns the machine a per-machine DAG belongs to, and whether
// name is one. The DAG's owner is that machine's owner, read from the
// registry; nothing in the DAG's spec or labels is consulted.
func MachineOfDAG(name string) (string, bool) {
	for _, prefix := range machineDAGPrefixes {
		if rest, ok := strings.CutPrefix(name, prefix); ok {
			id := string(registry.PrefixMachine) + "_" + rest
			if registry.ValidateID(registry.PrefixMachine, id) != nil {
				return "", false
			}
			return id, true
		}
	}
	return "", false
}
