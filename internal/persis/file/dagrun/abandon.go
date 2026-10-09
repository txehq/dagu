// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
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
		// A crash after the record and before the hide: the record must be
		// this abandonment's, intact, to complete it.
		if err := sameAbandonment(*existing, record); err != nil {
			return nil, err
		}
		record = *existing
	case errors.Is(err, os.ErrNotExist):
		// An attempt whose status was never written (its first Open or write
		// failed) was never dispatched either.
		if latest.Exists() {
			status, err := latest.ReadStatus(ctx)
			switch {
			case errors.Is(err, dagrun.ErrNoStatusData) || errors.Is(err, io.EOF):
			case err != nil:
				return nil, fmt.Errorf("%w: read attempt status: %v", persis.ErrAttemptNotAbandonable, err)
			case status.Status != ir.NotStarted || status.WorkerID != "":
				return nil, fmt.Errorf("%w: attempt %s is %s with worker %q",
					persis.ErrAttemptNotAbandonable, latest.ID(), status.Status, status.WorkerID)
			}
		}
		predecessor, err := store.predecessorLocked(ctx, run, dirs, latest.ID())
		if err != nil {
			return nil, err
		}
		if predecessor == nil && !req.AllowWithoutPredecessor {
			return nil, fmt.Errorf("%w: attempt %s has no earlier execution to restore", persis.ErrAttemptNotAbandonable, latest.ID())
		}
		record.ExpectedExecution = predecessor
		if err := writeRecordExclusive(recordPath, record); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: attempt %s: %v", persis.ErrAttemptAbandonmentConflict, latest.ID(), err)
	}

	if err := latest.Hide(ctx); err != nil {
		return nil, fmt.Errorf("failed to hide abandoned attempt %s: %w", latest.ID(), err)
	}
	return &record, nil
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
			return nil, fmt.Errorf("%w: read earlier attempt %s: %v", persis.ErrAttemptNotAbandonable, att.ID(), err)
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
	if err := validateAbandonmentRecord(existing, want.Run, want.AbandonedAttemptID); err != nil {
		return fmt.Errorf("%w: %v", persis.ErrAttemptAbandonmentConflict, err)
	}
	if existing.RootRun != want.RootRun || existing.Reason != want.Reason {
		return fmt.Errorf("%w: existing record describes another abandonment", persis.ErrAttemptAbandonmentConflict)
	}
	return nil
}
