// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package persis

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/runtime/runstate"
)

// NewRunStateStore adapts a DAG-run repository to runtime execution state.
func NewRunStateStore(repository *DAGRunRepository, prepared dagrun.Attempt) runstate.Store {
	return &runStateStore{repository: repository, prepared: prepared}
}

type runStateStore struct {
	repository *DAGRunRepository
	prepared   dagrun.Attempt
}

// TXE's names, spelled out here because persistence does not depend on TXE:
// the worker selector label every DAG TXE renders carries
// (txepkg.LabelMachine), the label naming a job's DAG (txepkg.LabelJob), and
// the names of a machine's reviewer, decide and probe DAGs.
const (
	txeMachineLabel  = "txe.machine"
	txeJobLabel      = "txe.job"
	txeMachinePrefix = "mch_"
)

var txeMachineDAGPrefixes = []string{"txe-reviewer-", "txe-decide-", "txe-probe-"}

// keepsHistory reports whether a DAG's run history is exempt from automatic
// removal: a DAG TXE rendered, which is routed to a TXE machine and is either
// a job's DAG, naming its job in a label, or one of that machine's own DAGs.
// The DAGs TXE renders declare a 100-year retention, but a copy rendered
// before they did, and every run snapshot recorded from one, still carries
// Dagu's default. Another DAG that merely routes to a TXE machine keeps its
// own retention.
func keepsHistory(dag *ir.DAG) bool {
	machine := dag.WorkerSelector[txeMachineLabel]
	if !strings.HasPrefix(machine, txeMachinePrefix) {
		return false
	}
	// Dagu lowercases label values when it loads them.
	for _, job := range dag.Labels.Get(txeJobLabel) {
		if strings.EqualFold(job, dag.Name) {
			return true
		}
	}
	suffix := strings.TrimPrefix(machine, txeMachinePrefix)
	for _, prefix := range txeMachineDAGPrefixes {
		if dag.Name == prefix+suffix {
			return true
		}
	}
	return false
}

func (s *runStateStore) BeginAttempt(ctx context.Context, req runstate.BeginAttemptRequest) (runstate.Attempt, error) {
	prune := req.DAG != nil && !keepsHistory(req.DAG)
	if prune && req.DAG.HistRetentionRuns == 0 {
		if _, err := s.repository.RemoveOldDAGRuns(ctx, req.DAG.Name, req.DAG.HistRetentionDays, DAGRunRetentionOptions{}); err != nil {
			logger.Error(ctx, "DAG runs data cleanup failed", tag.Error(err))
		}
	}

	attempt := s.prepared
	if attempt != nil {
		if req.AttemptID != "" && attempt.ID() != req.AttemptID {
			return nil, fmt.Errorf(
				"prepared attempt ID %q does not match requested attempt ID %q",
				attempt.ID(),
				req.AttemptID,
			)
		}
		attempt.SetDAG(req.DAG)
	} else {
		created, err := s.repository.CreateAttempt(ctx, req.DAG, time.Now(), req.RunID, runStateAttemptOptions(req))
		if err != nil {
			return nil, err
		}
		attempt = created
	}

	if prune && req.DAG.HistRetentionRuns > 0 {
		retentionRuns := req.DAG.HistRetentionRuns
		if _, err := s.repository.RemoveOldDAGRuns(ctx, req.DAG.Name, 0, DAGRunRetentionOptions{
			RetentionRuns: &retentionRuns,
		}); err != nil {
			logger.Error(ctx, "DAG runs data cleanup failed", tag.Error(err))
		}
	}

	return runStateAttempt{
		Attempt:    attempt,
		repository: s.repository,
		workDirRef: workDirRef(req),
	}, nil
}

func (s *runStateStore) OpenAttempt(ctx context.Context, ref ir.DAGRunRef) (runstate.Attempt, error) {
	attempt, err := s.repository.FindAttempt(ctx, ref)
	if err != nil {
		return nil, err
	}
	return runStateAttempt{
		Attempt:    attempt,
		repository: s.repository,
		workDirRef: dagrun.WorkDirRef{RootDAGRun: ref, DAGRun: ref},
	}, nil
}

func (s *runStateStore) OpenChildAttempt(ctx context.Context, root ir.DAGRunRef, childRunID string) (runstate.Attempt, error) {
	attempt, err := s.repository.FindSubAttempt(ctx, root, childRunID)
	if err != nil {
		return nil, err
	}
	return runStateAttempt{
		Attempt:    attempt,
		repository: s.repository,
		workDirRef: dagrun.WorkDirRef{RootDAGRun: root, DAGRun: ir.DAGRunRef{ID: childRunID}},
	}, nil
}

func workDirRef(req runstate.BeginAttemptRequest) dagrun.WorkDirRef {
	name := ""
	if req.DAG != nil {
		name = req.DAG.Name
	}
	ref := ir.NewDAGRunRef(name, req.RunID)
	root := req.RootDAGRun
	if root.Zero() {
		root = ref
	}
	return dagrun.WorkDirRef{RootDAGRun: root, DAGRun: ref}
}

func runStateAttemptOptions(req runstate.BeginAttemptRequest) DAGRunCreateAttemptOptions {
	opts := DAGRunCreateAttemptOptions{
		Retry:     req.Retry,
		AttemptID: req.AttemptID,
	}
	if req.RootDAGRun.ID != "" && req.RootDAGRun.ID != req.RunID {
		opts.RootDAGRun = req.RootDAGRun
	}
	return opts
}

type runStateAttempt struct {
	dagrun.Attempt
	repository *DAGRunRepository
	workDirRef dagrun.WorkDirRef
}

func (a runStateAttempt) RecordStatus(ctx context.Context, status ir.DAGRunStatus) error {
	return a.Write(ctx, status)
}

func (a runStateAttempt) RecordOutputs(ctx context.Context, outputs *ir.DAGRunOutputs) error {
	return a.WriteOutputs(ctx, outputs)
}

func (a runStateAttempt) RequestCancel(ctx context.Context) error {
	return a.Abort(ctx)
}

func (a runStateAttempt) CancelRequested(ctx context.Context) (bool, error) {
	return a.IsAborting(ctx)
}

func (a runStateAttempt) MaterializeWorkDir(ctx context.Context) (string, error) {
	return a.repository.MaterializeWorkDir(ctx, a.workDirRef)
}

func (a runStateAttempt) SnapshotWorkDir(ctx context.Context, localDir string) error {
	return a.repository.SnapshotWorkDir(ctx, a.workDirRef, localDir)
}
