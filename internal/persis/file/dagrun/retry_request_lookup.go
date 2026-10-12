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
	"strings"
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
		if err != nil || match == nil {
			if err != nil {
				return nil, err
			}
			continue
		}
		if err := markExecutionAbandoned(att, match); err != nil {
			return nil, err
		}
		return match, nil
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
	if match.Abandonment == nil {
		if err := markExecutionAbandoned(att, match); err != nil {
			return nil, err
		}
	}
	if att.Hidden() && match.Abandonment == nil {
		return nil, fmt.Errorf("attempt %s is hidden without an abandonment record for its execution", att.ID())
	}
	return match, nil
}

// markExecutionAbandoned reports match abandoned when the attempt holds an
// execution-scoped record for its execution: one of a reused attempt,
// abandoned without hiding the attempt. A record that is there but cannot be
// trusted is an error, never absent.
func markExecutionAbandoned(att *Attempt, match *persis.RetryRequestMatch) error {
	if match.Execution.QueuedAt == "" {
		return nil
	}
	path := executionRecordPath(att.file, match.Execution.QueuedAt)
	record, err := readRecordFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("read attempt %s execution abandonment record: %w", att.ID(), err)
	case record.Scope != persis.AbandonmentScopeExecution || record.AbandonedAttemptID != att.ID() ||
		record.AbandonedExecution != match.Execution:
		return fmt.Errorf("attempt %s execution abandonment record %s names another execution", att.ID(), filepath.Base(path))
	}
	match.State, match.Abandonment = persis.RetryRequestAbandoned, record
	return nil
}

// matchRetained looks for id in the retained copies of one attempt
// directory. Unlike the manifest listing, which skips what it cannot read,
// it is strict: a copies directory or a copy that cannot be read is an
// error, never absent, so a lost response is never reported as unknown.
func matchRetained(attemptDir, id string) (*persis.RetryRequestMatch, error) {
	attRoot, err := os.OpenRoot(attemptDir)
	if err != nil {
		return nil, fmt.Errorf("open attempt directory: %w", err)
	}
	defer func() { _ = attRoot.Close() }()
	execRoot, err := openSubRoot(attRoot, retainedExecutionsDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open retained executions: %w", err)
	}
	defer func() { _ = execRoot.Close() }()
	entries, err := readDirRoot(execRoot)
	if err != nil {
		return nil, fmt.Errorf("list retained executions: %w", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			// A copy still being written (temp + rename).
			continue
		}
		if !e.IsDir() {
			return nil, fmt.Errorf("retained execution %s is not a directory", e.Name())
		}
		data, err := readPlain(execRoot, filepath.Join(e.Name(), retainedManifestFile))
		if err != nil {
			return nil, fmt.Errorf("read retained execution %s manifest: %w", e.Name(), err)
		}
		var m persis.RetainedExecution
		if err := json.Unmarshal(data, &m); err != nil || m.Execution != e.Name() {
			return nil, fmt.Errorf("retained execution %s has an invalid manifest", e.Name())
		}
		data, err = readPlain(execRoot, filepath.Join(e.Name(), retainedStatusFile))
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
