// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/cmn/stringutil"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/gofrs/flock"
)

// AbandonmentRecordFile is the immutable record written into an abandoned
// attempt's directory before the attempt is hidden.
const AbandonmentRecordFile = "abandonment.json"

// executionRecordPrefix starts the name of an execution-scoped record,
// written beside the attempt's status: one per abandoned execution, named by
// its queued-at marker.
const executionRecordPrefix = "abandonment-"

var (
	_ persis.DAGRunAttemptAbandoner           = (*Store)(nil)
	_ persis.DAGRunExecutionAbandonmentReader = (*Store)(nil)
)

// executionAbandonCheckedHook, when set by a test, runs after an execution
// abandonment checked the execution and before it publishes its record,
// with the status file's lock held.
var executionAbandonCheckedHook func(statusFile string)

// attemptAbandonCheckedHook, when set by a test, runs after an attempt-level
// abandonment checked the attempt and before it writes its record, with the
// status file's lock held.
var attemptAbandonCheckedHook func(statusFile string)

// AbandonAttempt implements persis.DAGRunAttemptAbandoner. It holds the run's
// data-root lock, the lock CompareAndSwapLatestAttemptStatus and CreateAttempt
// take, so no other store write to the run interleaves with the check, the
// record and the hide.
//
// A status append holds only the status file's lock, so for a whole attempt
// that lock is taken too, after the data-root lock (the order every holder of
// both uses), and held from the check through the record and, for the
// marked_failed outcome, the Failed status. An append either lands before
// the check, which then sees it, or after the record. The hidden outcome
// releases the lock before the hide: the hide renames the directory that
// holds the lock file, which Windows refuses while it is open, and holding
// the lock across the rename would add nothing, since an append blocked on
// it lands in the same file, hidden, once the rename is done.
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
	if record.Scope == persis.AbandonmentScopeExecution {
		return store.abandonExecution(ctx, req.DAGRun, rootRef, record)
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

	fileLock := flock.New(statusLockPath(latest.file))
	if err := fileLock.Lock(); err != nil {
		return nil, fmt.Errorf("lock attempt %s status: %w", latest.ID(), err)
	}
	locked := true
	unlockStatus := func() {
		if locked {
			_ = fileLock.Unlock()
			_ = fileLock.Close()
			locked = false
		}
	}
	defer unlockStatus()

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
		if attemptAbandonCheckedHook != nil {
			attemptAbandonCheckedHook(latest.file)
		}
		if err := writeRecordExclusive(recordPath, record); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: attempt %s: %v", persis.ErrAttemptAbandonmentConflict, latest.ID(), err)
	}

	switch record.Outcome {
	case persis.AbandonmentHidden:
		unlockStatus()
		if err := latest.Hide(ctx); err != nil {
			return nil, fmt.Errorf("failed to hide abandoned attempt %s: %w", latest.ID(), err)
		}
	case persis.AbandonmentMarkedFailed:
		if err := markNotDispatchedLocked(ctx, latest, record); err != nil {
			return nil, err
		}
	}
	return &record, nil
}

// abandonExecution abandons one execution of a reused attempt, under the
// run's data-root lock: the attempt must be the run's latest and its status
// that execution, not handed to a worker. The record is written beside the
// attempt's status under the execution's own name, then the execution is
// marked Failed. Nothing is hidden, so earlier executions and their records
// stay; a later execution of the attempt is never covered.
func (store *Store) abandonExecution(ctx context.Context, dagRun, rootRef ir.DAGRunRef, record persis.AttemptAbandonment) (*persis.AttemptAbandonment, error) {
	marker := record.AbandonedExecution.QueuedAt
	var out *persis.AttemptAbandonment
	err := store.withRunAttemptsLocked(ctx, dagRun, rootRef, func(run *DAGRun, dirs []string) error {
		latest, err := latestVisibleAttempt(run, dirs, store)
		if err != nil {
			return err
		}
		if latest == nil || latest.ID() != record.AbandonedAttemptID {
			return fmt.Errorf("%w: attempt %s is not the run's latest", persis.ErrAttemptNotAbandonable, record.AbandonedAttemptID)
		}
		// Every status append and compaction holds the status file's lock:
		// held from the check to the append, no writer lands in between.
		fileLock := flock.New(statusLockPath(latest.file))
		if err := fileLock.Lock(); err != nil {
			return fmt.Errorf("lock attempt %s status: %w", latest.ID(), err)
		}
		defer func() {
			_ = fileLock.Unlock()
			_ = fileLock.Close()
		}()
		status, err := parseLatestStatusFromTail(ctx, latest.file)
		if err != nil {
			return fmt.Errorf("read attempt %s status: %w", latest.ID(), err)
		}
		recordPath := executionRecordPath(latest.file, marker)
		existing, err := readRecordFile(recordPath)
		switch {
		case err == nil:
			// A crash after the record and before the execution was marked:
			// the record must be this abandonment's, intact, to complete it.
			if err := sameAbandonment(*existing, record); err != nil {
				return err
			}
			if existing.Scope != persis.AbandonmentScopeExecution || existing.AbandonedExecution != record.AbandonedExecution {
				return fmt.Errorf("%w: existing record names another execution", persis.ErrAttemptAbandonmentConflict)
			}
			record = *existing
		case errors.Is(err, os.ErrNotExist):
			if _, lstatErr := os.Lstat(recordPath); !errors.Is(lstatErr, os.ErrNotExist) {
				return fmt.Errorf("%w: attempt %s execution %s: unreadable record: %v", persis.ErrAttemptAbandonmentConflict, latest.ID(), marker, err)
			}
			if !executionAwaitsDispatch(status, marker) {
				return fmt.Errorf("%w: attempt %s is not a queued execution marked %s", persis.ErrAttemptNotAbandonable, latest.ID(), marker)
			}
			predecessor, err := store.predecessorLocked(ctx, run, dirs, latest.ID())
			if err != nil {
				return err
			}
			retained, err := hasRetainedExecutions(latest.file)
			if err != nil {
				return err
			}
			record.Outcome = persis.AbandonmentMarkedFailed
			record.ExpectedExecution = nil
			record.PredecessorAbsent = predecessor == nil && !retained
			if executionAbandonCheckedHook != nil {
				executionAbandonCheckedHook(latest.file)
			}
			if err := writeRecordExclusive(recordPath, record); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: attempt %s execution %s: %v", persis.ErrAttemptAbandonmentConflict, latest.ID(), marker, err)
		}
		if err := markExecutionNotDispatchedLocked(ctx, latest, status, record); err != nil {
			return err
		}
		out = &record
		return nil
	})
	return out, err
}

// markExecutionNotDispatchedLocked marks the abandoned execution Failed with
// the record's reason, keeping the rest of its status. The caller holds the
// status file's lock and read status under it, so the append goes through a
// writer that does not take the lock again. A status already Failed for that
// execution was marked by an earlier, interrupted call.
func markExecutionNotDispatchedLocked(ctx context.Context, att *Attempt, status *ir.DAGRunStatus, record persis.AttemptAbandonment) error {
	marker := record.AbandonedExecution.QueuedAt
	switch {
	case status != nil && status.QueuedAt == marker && status.Status == ir.Failed:
		return nil
	case !executionAwaitsDispatch(status, marker):
		return fmt.Errorf("%w: attempt %s execution %s changed before it was marked", persis.ErrAttemptAbandonmentConflict, att.ID(), marker)
	}
	next := *status
	next.Status = ir.Failed
	next.FinishedAt = stringutil.FormatTime(time.Now())
	next.Error = record.Detail
	if next.Error == "" {
		next.Error = "not dispatched"
	}
	ir.NormalizeDAGRunConditions(&next)
	if err := terminatePartialLine(att.file); err != nil {
		return fmt.Errorf("mark abandoned execution failed: %w", err)
	}
	writer := NewWriter(att.file)
	if err := writer.Open(); err != nil {
		return fmt.Errorf("open abandoned attempt: %w", err)
	}
	writeErr := writer.Write(ctx, next)
	closeErr := writer.Close(ctx)
	if writeErr != nil {
		return fmt.Errorf("mark abandoned execution failed: %w", writeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	att.afterWriteLocked(ctx, next)
	return nil
}

// terminatePartialLine ends a status file whose last line is incomplete, as
// a crash mid-append leaves it, with a newline: readers skip that line, which
// does not decode, and the next append starts a line of its own. Nothing is
// removed. The caller holds the status file's lock.
func terminatePartialLine(statusFile string) error {
	f, err := os.OpenFile(statusFile, os.O_RDWR, 0) //nolint:gosec // path is the attempt's status file
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return err
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, info.Size()-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}
	if _, err := f.WriteAt([]byte{'\n'}, info.Size()); err != nil {
		return err
	}
	return f.Sync()
}

// executionRecordPath names the record of the attempt's execution marked
// queuedAt, beside its status file.
func executionRecordPath(statusFile, queuedAt string) string {
	sum := sha256.Sum256([]byte(queuedAt))
	return filepath.Join(filepath.Dir(statusFile), executionRecordPrefix+hex.EncodeToString(sum[:16])+".json")
}

// hasRetainedExecutions reports whether the attempt kept a copy of an
// execution a queued retry replaced: then the run had one before.
func hasRetainedExecutions(statusFile string) (bool, error) {
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(statusFile), retainedExecutionsDir))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("list retained executions: %w", err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			return true, nil
		}
	}
	return false, nil
}

// readExecutionRecords reads and fully validates every execution-scoped
// record of an attempt. A record that cannot be trusted is a result with Err;
// a directory that cannot be listed is an error, never no records.
func readExecutionRecords(att *Attempt, dagRun, rootDAGRun ir.DAGRunRef) ([]persis.AttemptAbandonmentResult, error) {
	paths, err := executionRecordPaths(att.file)
	if err != nil {
		return nil, err
	}
	var results []persis.AttemptAbandonmentResult
	for _, path := range paths {
		record, err := readStoredExecutionRecord(path, att, dagRun, rootDAGRun)
		results = append(results, persis.AttemptAbandonmentResult{AttemptID: att.ID(), Record: record, Err: err})
	}
	return results, nil
}

// executionRecordPaths lists the execution-scoped records beside a status
// file by name, reading the literal directory: no pattern is applied to the
// path, and a listing error is returned.
func executionRecordPaths(statusFile string) ([]string, error) {
	dir := filepath.Dir(statusFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list attempt directory: %w", err)
	}
	var paths []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, executionRecordPrefix) && strings.HasSuffix(name, ".json") {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	return paths, nil
}

// lookupExecutionRecord reads the record of the attempt's execution marked
// queuedAt: found false only when nothing is at its name (Lstat, so a
// dangling link is not absent), and fully validated otherwise.
func lookupExecutionRecord(att *Attempt, dagRun, rootDAGRun ir.DAGRunRef, queuedAt string) (*persis.AttemptAbandonment, bool, error) {
	path := executionRecordPath(att.file, queuedAt)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, true, fmt.Errorf("%w: attempt %s: %v", persis.ErrAttemptAbandonmentConflict, att.ID(), err)
	}
	record, err := readStoredExecutionRecord(path, att, dagRun, rootDAGRun)
	if err != nil {
		return nil, true, err
	}
	if record.AbandonedExecution.QueuedAt != queuedAt {
		return nil, true, fmt.Errorf("%w: attempt %s: record names another execution", persis.ErrAttemptAbandonmentConflict, att.ID())
	}
	return record, true, nil
}

// readStoredExecutionRecord reads one execution-scoped record and checks it
// names this attempt and the execution its file is named for.
func readStoredExecutionRecord(path string, att *Attempt, dagRun, rootDAGRun ir.DAGRunRef) (*persis.AttemptAbandonment, error) {
	record, err := readRecordFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: attempt %s: %s: %v", persis.ErrAttemptAbandonmentConflict, att.ID(), filepath.Base(path), err)
	}
	if err := validateStoredAbandonment(*record, dagRun, rootDAGRun, att.ID()); err != nil {
		return nil, err
	}
	if record.Scope != persis.AbandonmentScopeExecution || executionRecordPath(att.file, record.AbandonedExecution.QueuedAt) != path {
		return nil, fmt.Errorf("%w: attempt %s: %s names another execution", persis.ErrAttemptAbandonmentConflict, att.ID(), filepath.Base(path))
	}
	return record, nil
}

// ReadExecutionAbandonment implements persis.DAGRunExecutionAbandonmentReader,
// under the run's data-root lock like ReadAttemptAbandonment.
func (store *Store) ReadExecutionAbandonment(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef, attemptID, executionMarker string) (*persis.AttemptAbandonment, error) {
	if rootDAGRun.Zero() {
		rootDAGRun = dagRun
	}
	var record *persis.AttemptAbandonment
	err := store.withRunAttemptsLocked(ctx, dagRun, rootDAGRun, func(run *DAGRun, dirs []string) error {
		for _, dir := range dirs {
			att, err := run.AttemptByDir(dir, nil)
			if err != nil {
				return fmt.Errorf("%w: attempt directory %s: %v", persis.ErrAttemptAbandonmentConflict, dir, err)
			}
			if att.ID() != attemptID {
				continue
			}
			own, found, err := readStoredAbandonment(att, dagRun, rootDAGRun)
			if err != nil {
				return err
			}
			if found && own.Covers(attemptID, executionMarker) {
				record = own
				return nil
			}
			results, err := readExecutionRecords(att, dagRun, rootDAGRun)
			if err != nil {
				return fmt.Errorf("%w: attempt %s: %v", persis.ErrAttemptAbandonmentConflict, att.ID(), err)
			}
			for _, r := range results {
				if r.Err != nil {
					// A record that cannot be trusted may be this execution's.
					return r.Err
				}
				if r.Record.Covers(attemptID, executionMarker) {
					record = r.Record
					return nil
				}
			}
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return record, nil
}

// markNotDispatchedLocked marks a run's only, never-dispatched attempt Failed
// with the record's reason, so the run stays visible. A status already Failed
// was marked by an earlier, interrupted call. The caller holds the status
// file's lock, so the append goes through a writer that does not take it
// again, and the file is not compacted.
func markNotDispatchedLocked(ctx context.Context, att *Attempt, record persis.AttemptAbandonment) error {
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
	ir.NormalizeDAGRunConditions(&next)
	if err := terminatePartialLine(att.file); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("mark abandoned attempt failed: %w", err)
	}
	writer := NewWriter(att.file)
	if err := writer.Open(); err != nil {
		return fmt.Errorf("open abandoned attempt: %w", err)
	}
	writeErr := writer.Write(ctx, next)
	closeErr := writer.Close(ctx)
	if writeErr != nil {
		return fmt.Errorf("mark abandoned attempt failed: %w", writeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	att.afterWriteLocked(ctx, next)
	return nil
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
	var record *persis.AttemptAbandonment
	err := store.withRunAttemptsLocked(ctx, dagRun, rootDAGRun, func(run *DAGRun, dirs []string) error {
		for _, dir := range dirs {
			att, err := run.AttemptByDir(dir, nil)
			if err != nil {
				// An attempt directory this build cannot open may be the one
				// asked about; refuse to say it has no record.
				return fmt.Errorf("%w: attempt directory %s: %v", persis.ErrAttemptAbandonmentConflict, dir, err)
			}
			if att.ID() != attemptID {
				continue
			}
			var found bool
			record, found, err = readStoredAbandonment(att, dagRun, rootDAGRun)
			if !found {
				record = nil
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return record, nil
}

// ListAttemptAbandonmentsStrict implements persis.DAGRunAttemptAbandoner,
// under the same lock and with the same checks as ReadAttemptAbandonment.
func (store *Store) ListAttemptAbandonmentsStrict(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef) ([]persis.AttemptAbandonmentResult, error) {
	if rootDAGRun.Zero() {
		rootDAGRun = dagRun
	}
	var results []persis.AttemptAbandonmentResult
	err := store.withRunAttemptsLocked(ctx, dagRun, rootDAGRun, func(run *DAGRun, dirs []string) error {
		for _, dir := range dirs {
			att, err := run.AttemptByDir(dir, nil)
			if err != nil {
				results = append(results, persis.AttemptAbandonmentResult{
					AttemptID: attemptIDOrDir(dir),
					Err:       fmt.Errorf("%w: attempt directory %s: %v", persis.ErrAttemptAbandonmentConflict, dir, err),
				})
				continue
			}
			record, found, err := readStoredAbandonment(att, dagRun, rootDAGRun)
			if found || err != nil {
				results = append(results, persis.AttemptAbandonmentResult{AttemptID: att.ID(), Record: record, Err: err})
			}
			executions, err := readExecutionRecords(att, dagRun, rootDAGRun)
			if err != nil {
				results = append(results, persis.AttemptAbandonmentResult{AttemptID: att.ID(),
					Err: fmt.Errorf("%w: attempt %s: %v", persis.ErrAttemptAbandonmentConflict, att.ID(), err)})
				continue
			}
			results = append(results, executions...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// withRunAttemptsLocked runs fn with the run's attempt directories, newest
// first, holding the run's data-root lock.
func (store *Store) withRunAttemptsLocked(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef, fn func(run *DAGRun, dirs []string) error) error {
	root := store.dataRoot(rootDAGRun.Name)
	lockCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := root.Lock(lockCtx); err != nil {
		return fmt.Errorf("failed to acquire lock for dag-run %s: %w", dagRun.ID, err)
	}
	defer func() {
		if err := root.Unlock(); err != nil {
			logger.Error(ctx, "Failed to unlock dag-run", tag.RunID(dagRun.ID), tag.Error(err))
		}
	}()
	run, err := store.findRunLocked(ctx, root, rootDAGRun, dagRun)
	if err != nil {
		return err
	}
	dirs, err := run.listAttemptDirs()
	if err != nil {
		return fmt.Errorf("failed to list attempts: %w", err)
	}
	return fn(run, dirs)
}

// readStoredAbandonment reads and fully validates one attempt's record.
// found is false, with no error, only when the attempt's directory exists
// and holds no record. Anything that cannot be trusted is a conflict.
func readStoredAbandonment(att *Attempt, dagRun, rootDAGRun ir.DAGRunRef) (*persis.AttemptAbandonment, bool, error) {
	record, err := readAbandonmentRecord(att.file)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Absent only if nothing is at the record's name: a dangling link
		// reads as not found, but something is there.
		if _, lstatErr := os.Lstat(filepath.Join(filepath.Dir(att.file), AbandonmentRecordFile)); !errors.Is(lstatErr, os.ErrNotExist) {
			return nil, true, fmt.Errorf("%w: attempt %s: unreadable %s: %v", persis.ErrAttemptAbandonmentConflict, att.ID(), AbandonmentRecordFile, err)
		}
		if _, statErr := os.Stat(filepath.Dir(att.file)); statErr != nil {
			return nil, true, fmt.Errorf("%w: attempt %s directory: %v", persis.ErrAttemptAbandonmentConflict, att.ID(), statErr)
		}
		return nil, false, nil
	case err != nil:
		return nil, true, fmt.Errorf("%w: attempt %s: %v", persis.ErrAttemptAbandonmentConflict, att.ID(), err)
	}
	if err := validateStoredAbandonment(*record, dagRun, rootDAGRun, att.ID()); err != nil {
		return nil, true, err
	}
	return record, true, nil
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
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			logger.Warn(ctx, "Skipping unreadable attempt abandonment record",
				tag.RunID(dagRun.ID), tag.AttemptID(att.ID()), tag.Error(err))
		case record.AbandonedAttemptID != att.ID():
			logger.Warn(ctx, "Skipping attempt abandonment record that names another attempt",
				tag.RunID(dagRun.ID), tag.AttemptID(att.ID()))
		default:
			records = append(records, *record)
		}
		executions, err := readExecutionRecords(att, dagRun, rootDAGRun)
		if err != nil {
			logger.Warn(ctx, "Skipping unreadable execution abandonment records",
				tag.RunID(dagRun.ID), tag.AttemptID(att.ID()), tag.Error(err))
			continue
		}
		for _, r := range executions {
			if r.Err != nil {
				logger.Warn(ctx, "Skipping untrusted execution abandonment record",
					tag.RunID(dagRun.ID), tag.AttemptID(att.ID()), tag.Error(r.Err))
				continue
			}
			records = append(records, *r.Record)
		}
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
	return readRecordFile(filepath.Join(filepath.Dir(statusFile), AbandonmentRecordFile))
}

func readRecordFile(path string) (*persis.AttemptAbandonment, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is inside the attempt directory
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
	case record.Scope != "" && record.Scope != persis.AbandonmentScopeExecution:
		return fmt.Errorf("%w: scope %q", persis.ErrAttemptNotAbandonable, record.Scope)
	case record.Scope == persis.AbandonmentScopeExecution &&
		(record.AbandonedExecution.AttemptID != attemptID || record.AbandonedExecution.QueuedAt == ""):
		return fmt.Errorf("%w: an execution abandonment names the attempt and its queued-at marker", persis.ErrAttemptNotAbandonable)
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
	case record.Scope == persis.AbandonmentScopeExecution:
		if record.Outcome != persis.AbandonmentMarkedFailed || record.ExpectedExecution != nil {
			return fmt.Errorf("%w: execution record has an inconsistent outcome %q", persis.ErrAttemptAbandonmentConflict, record.Outcome)
		}
	case record.Outcome == persis.AbandonmentHidden && record.ExpectedExecution != nil && !record.PredecessorAbsent:
	case record.Outcome == persis.AbandonmentMarkedFailed && record.ExpectedExecution == nil && record.PredecessorAbsent:
	default:
		return fmt.Errorf("%w: record has an inconsistent outcome %q", persis.ErrAttemptAbandonmentConflict, record.Outcome)
	}
	return nil
}

// attemptIDOrDir is the attempt id a directory name carries, or the name.
func attemptIDOrDir(dir string) string {
	if id, ok := attemptIDFromDir(dir); ok {
		return id
	}
	return dir
}
