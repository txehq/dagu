// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import "strings"

const (
	machineIDPrefix = "mch_"
	// ReconcileDAGPrefix starts the per-machine periodic reconcile DAG's
	// name. With a 26-character machine id the name is 36 characters, under
	// Dagu's 40-character DAG name limit.
	ReconcileDAGPrefix = "txe-probe-"
)

// ReconcileDAGName is the name of the machine's periodic reconcile DAG,
// built like the reviewer's DAG names: the prefix and the machine id
// without its "mch_" prefix.
func ReconcileDAGName(machineID string) string {
	return ReconcileDAGPrefix + strings.TrimPrefix(machineID, machineIDPrefix)
}
