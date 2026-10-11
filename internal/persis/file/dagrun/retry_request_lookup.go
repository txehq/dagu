// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

var _ persis.DAGRunRetryRequestFinder = (*Store)(nil)

// FindRetryRequest implements persis.DAGRunRetryRequestFinder. It holds the
// run's data-root lock, which creating, abandoning and retaining executions
// take, and looks at every attempt of the run, newest first: its current
// status (an attempt hidden as an abandoned preparation included), then the
// retained copies of executions a queued retry replaced in it. An execution
// whose attempt carries an abandonment record for it is reported abandoned.
func (store *Store) FindRetryRequest(ctx context.Context, root, dagRun ir.DAGRunRef, id string) (*persis.RetryRequestMatch, error) {
	if id == "" {
		return nil, persis.ErrNotFound
	}
	if root.Zero() {
		root = dagRun
	}
	dr := store.dataRoot(root.Name)
	lockCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := dr.Lock(lockCtx); err != nil {
		return nil, fmt.Errorf("failed to acquire lock for dag-run %s: %w", dagRun.ID, err)
	}
	defer func() {
		if err := dr.Unlock(); err != nil {
			logger.Error(ctx, "Failed to unlock dag-run", tag.RunID(dagRun.ID), tag.Error(err))
		}
	}()
	run, err := store.findRunLocked(ctx, dr, root, dagRun)
	if errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
		return nil, persis.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	dirs, err := run.listAttemptDirs()
	if err != nil {
		return nil, fmt.Errorf("failed to list attempts: %w", err)
	}
	for _, dir := range dirs {
		att, err := run.AttemptByDir(dir, store.cache)
		if err != nil {
			return nil, fmt.Errorf("failed to open attempt %s: %w", dir, err)
		}
		status, err := readWrittenStatus(ctx, att)
		if err != nil {
			return nil, fmt.Errorf("read attempt %s status: %w", att.ID(), err)
		}
		if status != nil && status.RetryRequest != nil && status.RetryRequest.ID == id {
			return matchCurrent(att, status)
		}
		match, err := matchRetained(filepath.Dir(att.file), id)
		if err != nil || match != nil {
			return match, err
		}
	}
	return nil, persis.ErrNotFound
}

// matchCurrent reports an attempt's current execution, abandoned when the
// attempt's abandonment record names that execution.
func matchCurrent(att *Attempt, status *ir.DAGRunStatus) (*persis.RetryRequestMatch, error) {
	match := &persis.RetryRequestMatch{
		State:     persis.RetryRequestAdmitted,
		Execution: persis.ExecutionIdentity{AttemptID: att.ID(), QueuedAt: status.QueuedAt},
		Status:    *status,
	}
	record, err := readAbandonmentRecord(att.file)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("read attempt %s abandonment record: %w", att.ID(), err)
	case record.AbandonedAttemptID == att.ID() && record.AbandonedExecution.QueuedAt == status.QueuedAt:
		match.State, match.Abandonment = persis.RetryRequestAbandoned, record
	}
	if att.Hidden() && match.Abandonment == nil {
		return nil, fmt.Errorf("attempt %s is hidden without an abandonment record for its execution", att.ID())
	}
	return match, nil
}

// matchRetained looks for id in the retained copies of one attempt
// directory.
func matchRetained(attemptDir, id string) (*persis.RetryRequestMatch, error) {
	copies := listRetainedIn(attemptDir)
	if len(copies) == 0 {
		return nil, nil
	}
	attRoot, err := os.OpenRoot(attemptDir)
	if err != nil {
		return nil, fmt.Errorf("open attempt directory: %w", err)
	}
	defer func() { _ = attRoot.Close() }()
	for _, m := range copies {
		data, err := readPlain(attRoot, filepath.Join(retainedExecutionsDir, m.Execution, retainedStatusFile))
		if err != nil {
			return nil, fmt.Errorf("read retained execution %s: %w", m.Execution, err)
		}
		var status ir.DAGRunStatus
		if err := json.Unmarshal(data, &status); err != nil {
			return nil, fmt.Errorf("decode retained execution %s: %w", m.Execution, err)
		}
		if status.RetryRequest != nil && status.RetryRequest.ID == id {
			return &persis.RetryRequestMatch{
				State:     persis.RetryRequestAdmitted,
				Execution: persis.ExecutionIdentity{AttemptID: status.AttemptID, QueuedAt: status.QueuedAt},
				Retained:  true,
				Status:    status,
			}, nil
		}
	}
	return nil, nil
}
