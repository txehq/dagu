// Copyright (C) 2026 Yota Hamada
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

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/cmn/stringutil"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

// AbandonmentRecordFile is the immutable record written into an abandoned
// attempt's directory before the attempt is hidden.
const AbandonmentRecordFile = "abandonment.json"

var _ persis.DAGRunAttemptAbandoner = (*Store)(nil)

// AbandonAttempt implements persis.DAGRunAttemptAbandoner. It holds the run's
// data-root lock, the lock CompareAndSwapLatestAttemptStatus and CreateAttempt
// take, so no other store write to the run interleaves with the check, the
// record and the hide.
func (store *Store) AbandonAttempt(ctx context.Context, req persis.AbandonAttemptRequest) (*persis.AttemptAbandonment, error) {
	record := req.Record
	if record.AbandonedAttemptID == "" || req.DAGRun.ID == "" {
		return nil, fmt.Errorf("%w: run and attempt are required", persis.ErrAttemptNotAbandonable)
	}
	if err := validateAbandonmentRecord(record, req.DAGRun, record.AbandonedAttemptID); err != nil {
		return nil, err
	}
	rootRef := req.RootDAGRun
	if rootRef.Zero() {
		rootRef = req.DAGRun
	}

	root := store.dataRoot(rootRef.Name)
	lockCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := root.Lock(lockCtx); err != nil {
		return nil, fmt.Errorf("failed to acquire lock for dag-run %s: %w", req.DAGRun.ID, err)
	}
	defer func() {
		if err := root.Unlock(); err != nil {
			logger.Error(ctx, "Failed to unlock dag-run", tag.RunID(req.DAGRun.ID), tag.Error(err))
		}
	}()

	run, err := store.findRunLocked(ctx, root, rootRef, req.DAGRun)
	if err != nil {
		return nil, err
	}
	dirs, err := run.listAttemptDirs()
	if err != nil {
		return nil, fmt.Errorf("failed to list attempts: %w", err)
	}

	var latest *Attempt
	for _, dir := range dirs {
		att, err := run.AttemptByDir(dir, store.cache)
		if err != nil {
			continue
		}
		if att.ID() == record.AbandonedAttemptID {
			if att.Hidden() {
				// Already hidden: only a matching record makes this the
				// completed abandonment; anything else is someone else's.
				existing, err := readAbandonmentRecord(att.file)
				if err != nil {
					return nil, fmt.Errorf("%w: hidden attempt %s: %v", persis.ErrAttemptAbandonmentConflict, att.ID(), err)
				}
				if err := sameAbandonment(*existing, record); err != nil {
					return nil, err
				}
				return existing, nil
			}
			latest = att
			break
		}
		if !att.Hidden() && att.Exists() && latest == nil {
			return nil, fmt.Errorf("%w: attempt %s is not the latest (latest is %s)",
				persis.ErrAttemptNotAbandonable, record.AbandonedAttemptID, att.ID())
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("%w: attempt %s not found", persis.ErrAttemptNotAbandonable, record.AbandonedAttemptID)
	}

	recordPath := filepath.Join(filepath.Dir(latest.file), AbandonmentRecordFile)
	existing, err := readAbandonmentRecord(latest.file)
	switch {
	case err == nil:
		// A crash after the record and before its outcome was applied: the
		// record must be this abandonment's, intact, to complete it.
		if err := sameAbandonment(*existing, record); err != nil {
			return nil, err
		}
		record = *existing
	case errors.Is(err, os.ErrNotExist):
		// An attempt whose status was never written (its first Open or write
		// failed) was never dispatched either.
		status, err := readWrittenStatus(ctx, latest)
		switch {
		case err != nil:
			// Unreadable is not settled: the attempt may still be one to
			// abandon once its status can be read.
			return nil, fmt.Errorf("read attempt %s status: %w", latest.ID(), err)
		case status == nil:
		case status.Status != ir.NotStarted || status.WorkerID != "":
			return nil, fmt.Errorf("%w: attempt %s is %s with worker %q",
				persis.ErrAttemptNotAbandonable, latest.ID(), status.Status, status.WorkerID)
		default:
			record.AbandonedExecution.QueuedAt = status.QueuedAt
		}
		record.AbandonedExecution.AttemptID = latest.ID()
		predecessor, err := store.predecessorLocked(ctx, run, dirs, latest.ID())
		if err != nil {
			return nil, err
		}
		if predecessor != nil {
			record.Outcome = persis.AbandonmentHidden
			record.ExpectedExecution = predecessor
			record.PredecessorAbsent = false
		} else {
			record.Outcome = persis.AbandonmentMarkedFailed
			record.ExpectedExecution = nil
			record.PredecessorAbsent = true
		}
		if err := writeRecordExclusive(recordPath, record); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: attempt %s: %v", persis.ErrAttemptAbandonmentConflict, latest.ID(), err)
	}

	switch record.Outcome {
	case persis.AbandonmentHidden:
		if err := latest.Hide(ctx); err != nil {
			return nil, fmt.Errorf("failed to hide abandoned attempt %s: %w", latest.ID(), err)
		}
	case persis.AbandonmentMarkedFailed:
		if err := markNotDispatched(ctx, latest, record); err != nil {
			return nil, err
		}
	}
	return &record, nil
}

// markNotDispatched marks a run's only, never-dispatched attempt Failed with
// the record's reason, so the run stays visible. A status already Failed was
// marked by an earlier, interrupted call.
func markNotDispatched(ctx context.Context, att *Attempt, record persis.AttemptAbandonment) error {
	next := ir.DAGRunStatus{
		Name:      record.Run.Name,
		DAGRunID:  record.Run.ID,
		AttemptID: record.AbandonedAttemptID,
		CreatedAt: time.Now().UnixMilli(),
	}
	if record.RootRun != record.Run {
		next.Root = record.RootRun
	}
	status, err := readWrittenStatus(ctx, att)
	switch {
	case err != nil:
		return fmt.Errorf("read abandoned attempt status: %w", err)
	case status == nil:
	case status.Status == ir.Failed:
		return nil
	case status.Status != ir.NotStarted:
		return fmt.Errorf("%w: attempt %s became %s", persis.ErrAttemptAbandonmentConflict, att.ID(), status.Status)
	default:
		next = *status
	}
	next.Status = ir.Failed
	next.FinishedAt = stringutil.FormatTime(time.Now())
	next.Error = record.Detail
	if next.Error == "" {
		next.Error = "not dispatched"
	}
	if err := att.Open(ctx); err != nil {
		return fmt.Errorf("open abandoned attempt: %w", err)
	}
	writeErr := att.Write(ctx, next)
	closeErr := att.Close(ctx)
	if writeErr != nil {
		return fmt.Errorf("mark abandoned attempt failed: %w", writeErr)
	}
	return closeErr
}

// readWrittenStatus reads an attempt's status for an abandonment decision. It
// returns nil when no status was ever written: there is no status file, or it
// is empty, as when Open succeeded and the first write did not. Status data
// that exists but cannot be read is an error, since it may describe a run.
func readWrittenStatus(ctx context.Context, att *Attempt) (*ir.DAGRunStatus, error) {
	info, err := os.Stat(att.file)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	case info.Size() == 0:
		return nil, nil
	}
	status, err := att.ReadStatusUncached(ctx)
	if errors.Is(err, dagrun.ErrNoStatusData) {
		return nil, nil
	}
	return status, err
}

// ReadAttemptAbandonment implements persis.DAGRunAttemptAbandoner. It holds
// the run's data-root lock, which AbandonAttempt holds from writing a record
// to hiding the attempt, so it never lists an attempt directory that a hide
// then renames away before its record is read. A directory that vanishes
// anyway is an error, never an absent record.
func (store *Store) ReadAttemptAbandonment(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef, attemptID string) (*persis.AttemptAbandonment, error) {
	if rootDAGRun.Zero() {
		rootDAGRun = dagRun
	}
	root := store.dataRoot(rootDAGRun.Name)
	lockCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := root.Lock(lockCtx); err != nil {
		return nil, fmt.Errorf("failed to acquire lock for dag-run %s: %w", dagRun.ID, err)
	}
	defer func() {
		if err := root.Unlock(); err != nil {
			logger.Error(ctx, "Failed to unlock dag-run", tag.RunID(dagRun.ID), tag.Error(err))
		}
	}()
	run, err := store.findRunLocked(ctx, root, rootDAGRun, dagRun)
	if err != nil {
		return nil, err
	}
	dirs, err := run.listAttemptDirs()
	if err != nil {
		return nil, fmt.Errorf("failed to list attempts: %w", err)
	}
	for _, dir := range dirs {
		att, err := run.AttemptByDir(dir, nil)
		if err != nil {
			// An attempt directory this build cannot open may be the one
			// asked about; refuse to say it has no record.
			return nil, fmt.Errorf("%w: attempt directory %s: %v", persis.ErrAttemptAbandonmentConflict, dir, err)
		}
		if att.ID() != attemptID {
			continue
		}
		record, err := readAbandonmentRecord(att.file)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if _, statErr := os.Stat(filepath.Dir(att.file)); statErr != nil {
				return nil, fmt.Errorf("%w: attempt %s directory: %v", persis.ErrAttemptAbandonmentConflict, attemptID, statErr)
			}
			return nil, nil
		case err != nil:
			return nil, fmt.Errorf("%w: attempt %s: %v", persis.ErrAttemptAbandonmentConflict, attemptID, err)
		}
		if err := validateStoredAbandonment(*record, dagRun, rootDAGRun, attemptID); err != nil {
			return nil, err
		}
		return record, nil
	}
	return nil, nil
}

// ListAttemptAbandonments implements persis.DAGRunAttemptAbandoner.
func (store *Store) ListAttemptAbandonments(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef) ([]persis.AttemptAbandonment, error) {
	if rootDAGRun.Zero() {
		rootDAGRun = dagRun
	}
	root := store.dataRoot(rootDAGRun.Name)
	run, err := store.findRunLocked(ctx, root, rootDAGRun, dagRun)
	if err != nil {
		return nil, err
	}
	dirs, err := run.listAttemptDirs()
	if err != nil {
		return nil, fmt.Errorf("failed to list attempts: %w", err)
	}
	var records []persis.AttemptAbandonment
	for _, dir := range dirs {
		att, err := run.AttemptByDir(dir, nil)
		if err != nil {
			continue
		}
		record, err := readAbandonmentRecord(att.file)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			logger.Warn(ctx, "Skipping unreadable attempt abandonment record",
				tag.RunID(dagRun.ID), tag.AttemptID(att.ID()), tag.Error(err))
			continue
		}
		if record.AbandonedAttemptID != att.ID() {
			logger.Warn(ctx, "Skipping attempt abandonment record that names another attempt",
				tag.RunID(dagRun.ID), tag.AttemptID(att.ID()))
			continue
		}
		records = append(records, *record)
	}
	return records, nil
}

// predecessorLocked returns the visible execution that becomes the latest once
// the attempt is hidden: the newest visible attempt after it in the listing.
func (store *Store) predecessorLocked(ctx context.Context, run *DAGRun, dirs []string, attemptID string) (*persis.ExecutionIdentity, error) {
	seen := false
	for _, dir := range dirs {
		att, err := run.AttemptByDir(dir, nil)
		if err != nil {
			continue
		}
		if att.ID() == attemptID {
			seen = true
			continue
		}
		if !seen || att.Hidden() || !att.Exists() {
			continue
		}
		status, err := att.ReadStatus(ctx)
		if err != nil {
			return nil, fmt.Errorf("read earlier attempt %s: %w", att.ID(), err)
		}
		return &persis.ExecutionIdentity{AttemptID: status.AttemptID, QueuedAt: status.QueuedAt}, nil
	}
	return nil, nil
}

// findRunLocked resolves a root run or one of its sub-DAG runs.
func (store *Store) findRunLocked(ctx context.Context, root DataRoot, rootRef, dagRun ir.DAGRunRef) (*DAGRun, error) {
	run, err := root.FindByDAGRunID(ctx, rootRef.ID)
	if err != nil {
		return nil, err
	}
	if rootRef.ID != dagRun.ID || rootRef.Name != dagRun.Name {
		return run.FindSubDAGRun(ctx, dagRun.ID)
	}
	return run, nil
}

func readAbandonmentRecord(statusFile string) (*persis.AttemptAbandonment, error) {
	data, err := os.ReadFile(filepath.Join(filepath.Dir(statusFile), AbandonmentRecordFile)) //nolint:gosec // path is inside the attempt directory
	if err != nil {
		return nil, err
	}
	var record persis.AttemptAbandonment
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode %s: %w", AbandonmentRecordFile, err)
	}
	if record.Schema != persis.AttemptAbandonmentSchema {
		return nil, fmt.Errorf("unsupported %s schema %d", AbandonmentRecordFile, record.Schema)
	}
	return &record, nil
}

// writeRecordExclusive writes the record only if none exists, atomically: a
// complete temporary file is linked into place, which fails if the name is
// taken, so a crash leaves either no record or a whole one.
func writeRecordExclusive(path string, record persis.AttemptAbandonment) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".abandonment-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create abandonment record: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = fileutil.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write abandonment record: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync abandonment record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close abandonment record: %w", err)
	}
	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: a record already exists", persis.ErrAttemptAbandonmentConflict)
		}
		return fmt.Errorf("failed to publish abandonment record: %w", err)
	}
	return nil
}

func validateAbandonmentRecord(record persis.AttemptAbandonment, dagRun ir.DAGRunRef, attemptID string) error {
	switch {
	case record.Schema != persis.AttemptAbandonmentSchema:
		return fmt.Errorf("%w: schema %d", persis.ErrAttemptNotAbandonable, record.Schema)
	case record.Run != dagRun:
		return fmt.Errorf("%w: record names run %s", persis.ErrAttemptNotAbandonable, record.Run.String())
	case record.AbandonedAttemptID != attemptID:
		return fmt.Errorf("%w: record names attempt %s", persis.ErrAttemptNotAbandonable, record.AbandonedAttemptID)
	case record.Reason == "" || record.DecidedAt == "":
		return fmt.Errorf("%w: reason and decision time are required", persis.ErrAttemptNotAbandonable)
	}
	e := record.Evidence
	if e.DispatchTask != persis.EvidenceAbsent || e.Lease != persis.EvidenceAbsent ||
		e.ActiveRun != persis.EvidenceAbsent || e.Worker != persis.EvidenceAbsent || e.ObservedAt == "" {
		return fmt.Errorf("%w: every lookup must have found nothing", persis.ErrAttemptNotAbandonable)
	}
	return nil
}

// sameAbandonment checks that a record found on disk is this abandonment: the
// same run, attempt and a complete absence proof. Its time and evidence may
// predate this call, as after a crash between the record and the hide.
func sameAbandonment(existing, want persis.AttemptAbandonment) error {
	if err := validateStoredAbandonment(existing, want.Run, want.RootRun, want.AbandonedAttemptID); err != nil {
		return err
	}
	if existing.Reason != want.Reason {
		return fmt.Errorf("%w: existing record describes another abandonment", persis.ErrAttemptAbandonmentConflict)
	}
	return nil
}

// validateStoredAbandonment checks a record read from disk in full before it
// completes an abandonment or decides a claim: the run, root and attempt it
// names, a complete absence proof, the abandoned execution and a consistent
// outcome. Anything else is a conflict and authorizes nothing.
func validateStoredAbandonment(record persis.AttemptAbandonment, dagRun, root ir.DAGRunRef, attemptID string) error {
	if root.Zero() {
		root = dagRun
	}
	if err := validateAbandonmentRecord(record, dagRun, attemptID); err != nil {
		return fmt.Errorf("%w: %v", persis.ErrAttemptAbandonmentConflict, err)
	}
	if record.RootRun != root {
		return fmt.Errorf("%w: record names root %s", persis.ErrAttemptAbandonmentConflict, record.RootRun.String())
	}
	if record.AbandonedExecution.AttemptID != attemptID {
		return fmt.Errorf("%w: record does not name the abandoned execution", persis.ErrAttemptAbandonmentConflict)
	}
	switch {
	case record.Outcome == persis.AbandonmentHidden && record.ExpectedExecution != nil && !record.PredecessorAbsent:
	case record.Outcome == persis.AbandonmentMarkedFailed && record.ExpectedExecution == nil && record.PredecessorAbsent:
	default:
		return fmt.Errorf("%w: record has an inconsistent outcome %q", persis.ErrAttemptAbandonmentConflict, record.Outcome)
	}
	return nil
}
