// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package runtime

import (
	"maps"

	"github.com/dagucloud/dagu/v2/internal/cmn/stringutil"
)

// CollectRunOutputs gathers a run's outputs, the content of its outputs.json,
// from its nodes in the order they run: each node's published outputs, then
// its string-form output under the camelCase form of its name. A later
// node's value for the same key wins. A step's declared outputs
// (DAGU_OUTPUT_FILE) are step-scoped and are not run outputs.
//
// The agent collects a run it executes itself from its live nodes; the
// coordinator collects a run a worker executed from its accepted terminal
// status (TXE-3757). Both go through this function, so the two cannot differ.
func CollectRunOutputs(nodes []NodeData) map[string]string {
	outputs := make(map[string]string)
	for _, nodeData := range nodes {
		maps.Copy(outputs, nodeData.OutputsValueStringMap())
		if nodeData.Step.Output == "" {
			continue
		}
		value, ok := nodeData.StringFormOutputValue()
		if !ok {
			continue
		}
		outputs[stringutil.ScreamingSnakeToCamel(nodeData.Step.Output)] = value
	}
	return outputs
}
