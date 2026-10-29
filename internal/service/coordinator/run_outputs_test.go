// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/proto/convert"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// workerTerminalStatus is what a worker pushes when a run with outputs ends:
// a step published an outputs document, another captured a string-form
// output under the same key later in the run, a step declared a step-scoped
// output, and the exit handler published one more value.
func workerTerminalStatus(attemptID string, status ir.Status) *ir.DAGRunStatus {
	return &ir.DAGRunStatus{
		Name:       "out-remote",
		DAGRunID:   "run-1",
		AttemptID:  attemptID,
		AttemptKey: "key-" + attemptID,
		Status:     status,
		FinishedAt: "2026-10-29T16:21:40Z",
		ParamsList: []string{"REGION=test"},
		Nodes: []*ir.Node{
			{Step: ir.Step{Name: "publish"}, Status: ir.NodeSucceeded, OutputsValue: new(`{"freePct":"99","region":"test"}`)},
			{Step: ir.Step{Name: "declared", ID: "declared"}, Status: ir.NodeSucceeded, StepOutputsValue: new(`{"free_pct":"15"}`)},
			{Step: ir.Step{Name: "stringform", Output: "FREE_PCT"}, Status: ir.NodeSucceeded, OutputValue: new("42")},
		},
		OnExit: &ir.Node{Step: ir.Step{Name: "onExit"}, Status: ir.NodeSucceeded, OutputsValue: new(`{"fromExit":"done"}`)},
	}
}

func reportStatus(t *testing.T, h *Handler, st *ir.DAGRunStatus) (*coordinatorv1.ReportStatusResponse, error) {
	t.Helper()
	proto, err := convert.DAGRunStatusToProto(st)
	require.NoError(t, err)
	return h.ReportStatus(context.Background(), &coordinatorv1.ReportStatusRequest{Status: proto, WorkerId: "w3757"})
}

func runningAttempt(store *mockDAGRunStore, attemptID string) *mockAttempt {
	return store.addAttempt(ir.DAGRunRef{Name: "out-remote", ID: "run-1"}, &ir.DAGRunStatus{
		Name: "out-remote", DAGRunID: "run-1", AttemptID: attemptID, AttemptKey: "key-" + attemptID, Status: ir.Running,
	})
}

// TXE-3757: a worker keeps no run directory, so the outputs of a run it
// executed were never written and the outputs API returned nothing. The hub now
// derives them from the accepted terminal status, with the agent's own rules.
func TestReportStatusWritesTheOutputsOfAWorkersRun(t *testing.T) {
	t.Parallel()

	t.Run("terminal status: outputs from the accepted status, as the agent collects them", func(t *testing.T) {
		t.Parallel()
		store := newMockDAGRunStore()
		attempt := runningAttempt(store, "att-1")
		h := NewHandler(HandlerConfig{DAGRunRepository: store.repository})

		resp, err := reportStatus(t, h, workerTerminalStatus("att-1", ir.Succeeded))
		require.NoError(t, err)
		require.True(t, resp.Accepted)

		out, err := attempt.ReadOutputs(context.Background())
		require.NoError(t, err)
		require.NotNil(t, out)
		assert.Equal(t, map[string]string{
			"freePct":  "42", // the later string-form output wins over the earlier published value
			"region":   "test",
			"fromExit": "done",
		}, out.Outputs, "a declared step output is step-scoped and is not a run output")
		assert.Equal(t, ir.OutputsMetadata{
			DAGName: "out-remote", DAGRunID: "run-1", AttemptID: "att-1", Status: "succeeded",
			CompletedAt: "2026-10-29T16:21:40Z", Params: `["REGION=test"]`,
		}, out.Metadata)
	})

	t.Run("a failed run's outputs are kept too", func(t *testing.T) {
		t.Parallel()
		store := newMockDAGRunStore()
		attempt := runningAttempt(store, "att-1")
		h := NewHandler(HandlerConfig{DAGRunRepository: store.repository})

		resp, err := reportStatus(t, h, workerTerminalStatus("att-1", ir.Failed))
		require.NoError(t, err)
		require.True(t, resp.Accepted)
		out, _ := attempt.ReadOutputs(context.Background())
		require.NotNil(t, out)
		assert.Equal(t, "failed", out.Metadata.Status)
	})

	t.Run("a running status writes nothing", func(t *testing.T) {
		t.Parallel()
		store := newMockDAGRunStore()
		attempt := runningAttempt(store, "att-1")
		h := NewHandler(HandlerConfig{DAGRunRepository: store.repository})

		resp, err := reportStatus(t, h, workerTerminalStatus("att-1", ir.Running))
		require.NoError(t, err)
		require.True(t, resp.Accepted)
		out, _ := attempt.ReadOutputs(context.Background())
		assert.Nil(t, out)
		assert.Zero(t, attempt.outputsWrites)
	})

	t.Run("a run that published nothing writes nothing", func(t *testing.T) {
		t.Parallel()
		store := newMockDAGRunStore()
		attempt := runningAttempt(store, "att-1")
		h := NewHandler(HandlerConfig{DAGRunRepository: store.repository})

		st := workerTerminalStatus("att-1", ir.Succeeded)
		st.Nodes, st.OnExit = []*ir.Node{{Step: ir.Step{Name: "quiet"}, Status: ir.NodeSucceeded}}, nil
		resp, err := reportStatus(t, h, st)
		require.NoError(t, err)
		require.True(t, resp.Accepted)
		out, _ := attempt.ReadOutputs(context.Background())
		assert.Nil(t, out)
	})

	t.Run("a stale report of an older attempt cannot write over the newer attempt's outputs", func(t *testing.T) {
		t.Parallel()
		store := newMockDAGRunStore()
		attempt := store.addAttempt(ir.DAGRunRef{Name: "out-remote", ID: "run-1"}, &ir.DAGRunStatus{
			Name: "out-remote", DAGRunID: "run-1", AttemptID: "att-2", AttemptKey: "key-att-2", Status: ir.Running,
		})
		newer := &ir.DAGRunOutputs{
			Metadata: ir.OutputsMetadata{DAGName: "out-remote", DAGRunID: "run-1", AttemptID: "att-2", Status: "succeeded"},
			Outputs:  map[string]string{"freePct": "7"},
		}
		require.NoError(t, attempt.WriteOutputs(context.Background(), newer))
		h := NewHandler(HandlerConfig{DAGRunRepository: store.repository})

		resp, err := reportStatus(t, h, workerTerminalStatus("att-1", ir.Succeeded))
		require.NoError(t, err)
		require.False(t, resp.Accepted)
		assert.Equal(t, remoteAttemptRejectedSuperseded, resp.Error)
		out, _ := attempt.ReadOutputs(context.Background())
		assert.Equal(t, newer, out, "the rejected report changed the newer attempt's outputs or metadata")
		assert.Equal(t, 1, attempt.outputsWrites)
	})

	t.Run("a replay of the accepted terminal report writes the same outputs again", func(t *testing.T) {
		t.Parallel()
		store := newMockDAGRunStore()
		attempt := runningAttempt(store, "att-1")
		h := NewHandler(HandlerConfig{DAGRunRepository: store.repository})

		for range 2 {
			resp, err := reportStatus(t, h, workerTerminalStatus("att-1", ir.Succeeded))
			require.NoError(t, err)
			require.True(t, resp.Accepted)
		}
		out, _ := attempt.ReadOutputs(context.Background())
		require.NotNil(t, out)
		assert.Equal(t, "42", out.Outputs["freePct"])
		assert.Equal(t, "att-1", out.Metadata.AttemptID)
		assert.Equal(t, 2, attempt.outputsWrites)
	})

	t.Run("a failed outputs write is reported as retryable and repaired by the replay", func(t *testing.T) {
		t.Parallel()
		store := newMockDAGRunStore()
		attempt := runningAttempt(store, "att-1")
		attempt.writeOutputsError = errors.New("disk full")
		h := NewHandler(HandlerConfig{DAGRunRepository: store.repository})

		_, err := reportStatus(t, h, workerTerminalStatus("att-1", ir.Succeeded))
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, grpcstatus.Code(err), "the worker retries delivering a terminal status only on Unavailable")
		assert.Contains(t, err.Error(), "status recorded, but the run's outputs could not be written")
		assert.Contains(t, err.Error(), "disk full")
		current, err := attempt.ReadStatus(context.Background())
		require.NoError(t, err)
		assert.Equal(t, ir.Succeeded, current.Status, "the terminal status itself is recorded")
		out, _ := attempt.ReadOutputs(context.Background())
		assert.Nil(t, out)

		attempt.mu.Lock()
		attempt.writeOutputsError = nil
		attempt.mu.Unlock()
		resp, err := reportStatus(t, h, workerTerminalStatus("att-1", ir.Succeeded))
		require.NoError(t, err)
		require.True(t, resp.Accepted)
		out, _ = attempt.ReadOutputs(context.Background())
		require.NotNil(t, out)
		assert.Equal(t, "42", out.Outputs["freePct"])
	})

	t.Run("values are taken as masked in the status, and nothing else is added", func(t *testing.T) {
		t.Parallel()
		store := newMockDAGRunStore()
		attempt := runningAttempt(store, "att-1")
		h := NewHandler(HandlerConfig{DAGRunRepository: store.repository})

		// The worker masked the status before pushing it.
		st := workerTerminalStatus("att-1", ir.Succeeded)
		st.Nodes = []*ir.Node{{Step: ir.Step{Name: "stringform", Output: "TOKEN"}, Status: ir.NodeSucceeded, OutputValue: new("*******")}}
		st.OnExit = nil
		st.ParamsList = []string{"API_TOKEN=*******"}
		resp, err := reportStatus(t, h, st)
		require.NoError(t, err)
		require.True(t, resp.Accepted)
		out, _ := attempt.ReadOutputs(context.Background())
		require.NotNil(t, out)
		assert.Equal(t, map[string]string{"token": "*******"}, out.Outputs)
		assert.Equal(t, `["API_TOKEN=*******"]`, out.Metadata.Params)
	})
}
