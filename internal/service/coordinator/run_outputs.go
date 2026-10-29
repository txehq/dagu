// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/dagucloud/dagu/v2/internal/runtime/transform"
)

// outputsNotWritten begins the error a worker gets when its terminal status
// was recorded but the run's outputs were not. It is sent as Unavailable, the
// code on which a worker retries delivering a terminal status
// (coordreport.isRetryableRPCError), so the worker sends the same report
// again and its replay writes the outputs.
const outputsNotWritten = "status recorded, but the run's outputs could not be written; report it again: "

// runOutputsFromStatus derives the outputs.json of a run a worker executed
// from its accepted terminal status (TXE-3757). A worker's agent keeps no run
// directory, so the outputs it collects never reach the hub, but every value
// they come from is in the status the worker pushed: the same nodes, in the
// same run order, through the same collection the agent uses. The status was
// masked by the worker before it was pushed, so nothing here is more than the
// run's status already shows. It returns nil when the run published nothing,
// as the agent writes no file then.
func runOutputsFromStatus(st *ir.DAGRunStatus) *ir.DAGRunOutputs {
	nodes := st.NodesInRunOrder()
	data := make([]runtime.NodeData, 0, len(nodes))
	for _, node := range nodes {
		data = append(data, transform.ToNode(node).NodeData())
	}
	outputs := runtime.CollectRunOutputs(data)
	if len(outputs) == 0 {
		return nil
	}
	var params string
	if len(st.ParamsList) > 0 {
		if b, err := json.Marshal(st.ParamsList); err == nil {
			params = string(b)
		}
	}
	return &ir.DAGRunOutputs{
		Metadata: ir.OutputsMetadata{
			DAGName:     st.Name,
			DAGRunID:    st.DAGRunID,
			AttemptID:   st.AttemptID,
			Status:      st.Status.String(),
			CompletedAt: st.FinishedAt,
			Params:      params,
		},
		Outputs: outputs,
	}
}

// writeRunOutputs writes the outputs of an accepted terminal status to the
// attempt that status was written to. It is called only after that write
// succeeded, so a rejected, superseded or stale report never reaches it. A
// replay of the accepted terminal report writes the same content again, which
// is how a failed write is repaired.
func writeRunOutputs(ctx context.Context, attempt dagrun.Attempt, st *ir.DAGRunStatus) error {
	if attempt == nil || st == nil || !isTerminalRunStatus(st.Status) {
		return nil
	}
	if err := attempt.WriteOutputs(ctx, runOutputsFromStatus(st)); err != nil {
		return fmt.Errorf("write outputs of run %s attempt %s: %w", st.DAGRunID, st.AttemptID, err)
	}
	return nil
}
