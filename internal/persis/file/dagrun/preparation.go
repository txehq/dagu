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
	"sort"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

const preparationExt = ".json"

var (
	_ persis.DAGRunPreparationJournal  = (*Store)(nil)
	_ persis.DAGRunPreparationLookup   = (*Store)(nil)
	_ persis.DAGRunPreparationSettler  = (*Store)(nil)
	_ persis.DAGRunPreparationBeginner = (*Store)(nil)
)

// defaultPreparationDir keeps the journal beside the run tree rather than in
// it: every directory under the base directory is read as a DAG's runs.
func defaultPreparationDir(baseDir string) string {
	clean := filepath.Clean(baseDir)
	return filepath.Join(filepath.Dir(clean), filepath.Base(clean)+".preparations")
}

// beginPreparation journals an attempt about to be created. The caller holds
// the run's data-root lock, which AbandonAttempt takes too, so the entry and
// the attempt directory appear together to anyone deciding about either.
func (store *Store) beginPreparation(run, root ir.DAGRunRef, attemptID string) (persis.AttemptPreparation, error) {
	return store.writePreparation(run, root, attemptID, "")
}

// writePreparation writes an entry for an attempt, or for one execution of
// it when queuedAt is set. The caller holds the run's data-root lock.
func (store *Store) writePreparation(run, root ir.DAGRunRef, attemptID, queuedAt string) (persis.AttemptPreparation, error) {
	if root.Zero() {
		root = run
	}
	entry := persis.AttemptPreparation{
		Schema:     persis.AttemptPreparationSchema,
		Run:        run,
		RootRun:    root,
		AttemptID:  attemptID,
		QueuedAt:   queuedAt,
		PreparedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return entry, err
	}
	if err := os.MkdirAll(store.preparationDir, 0750); err != nil {
		return entry, fmt.Errorf("failed to create the preparation journal: %w", err)
	}
	if err := fileutil.WriteFileAtomic(store.preparationPath(entry), data, 0600); err != nil {
		return entry, fmt.Errorf("failed to journal the attempt preparation: %w", err)
	}
	return entry, nil
}

// BeginAttemptPreparation implements persis.DAGRunPreparationBeginner. It
// holds the run's data-root lock, which AbandonAttempt, CreateAttempt and the
// status writers hold, so the execution it checks is the one it journals.
func (store *Store) BeginAttemptPreparation(ctx context.Context, run, root ir.DAGRunRef, attemptID, queuedAt string) (persis.AttemptPreparation, error) {
	if attemptID == "" || queuedAt == "" || run.ID == "" {
		return persis.AttemptPreparation{}, fmt.Errorf("%w: run, attempt and queued-at marker are required", persis.ErrAttemptNotAbandonable)
	}
	if root.Zero() {
		root = run
	}
	var entry persis.AttemptPreparation
	err := store.withRunAttemptsLocked(ctx, run, root, func(dr *DAGRun, dirs []string) error {
		latest, err := latestVisibleAttempt(dr, dirs, store)
		if err != nil {
			return err
		}
		if latest == nil || latest.ID() != attemptID {
			return fmt.Errorf("%w: attempt %s is not the run's latest", persis.ErrAttemptNotAbandonable, attemptID)
		}
		status, err := readWrittenStatus(ctx, latest)
		if err != nil {
			return fmt.Errorf("read attempt %s status: %w", attemptID, err)
		}
		if !executionAwaitsDispatch(status, queuedAt) {
			return fmt.Errorf("%w: attempt %s is not a queued execution marked %s", persis.ErrAttemptNotAbandonable, attemptID, queuedAt)
		}
		want := persis.AttemptPreparation{Run: run, RootRun: root, AttemptID: attemptID, QueuedAt: queuedAt}
		existing, err := readPreparation(store.preparationPath(want))
		switch {
		case err == nil && existing.Run == run && existing.RootRun == root && existing.AttemptID == attemptID && existing.QueuedAt == queuedAt:
			entry = *existing
			return nil
		case err == nil:
			return errors.New("the attempt preparation entry names another execution")
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("failed to read the attempt preparation: %w", err)
		}
		entry, err = store.writePreparation(run, root, attemptID, queuedAt)
		return err
	})
	return entry, err
}

// executionAwaitsDispatch reports whether status is the execution marked
// queuedAt, not yet handed to a worker.
func executionAwaitsDispatch(status *ir.DAGRunStatus, queuedAt string) bool {
	return status != nil && status.QueuedAt == queuedAt && status.WorkerID == "" &&
		(status.Status == ir.Queued || status.Status == ir.NotStarted)
}

// latestVisibleAttempt is the run's newest attempt that is not hidden and
// has a status file, or nil.
func latestVisibleAttempt(dr *DAGRun, dirs []string, store *Store) (*Attempt, error) {
	for _, dir := range dirs {
		att, err := dr.AttemptByDir(dir, store.cache)
		if err != nil {
			return nil, fmt.Errorf("failed to open attempt %s: %w", dir, err)
		}
		if !att.Hidden() && att.Exists() {
			return att, nil
		}
	}
	return nil, nil
}

// ListAttemptPreparations implements persis.DAGRunPreparationJournal. The
// journal holds only preparations in flight or left behind, so it is read
// whole.
func (store *Store) ListAttemptPreparations(ctx context.Context) ([]persis.AttemptPreparation, error) {
	entries, err := os.ReadDir(store.preparationDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read the preparation journal: %w", err)
	}
	var preparations []persis.AttemptPreparation
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), preparationExt) {
			continue
		}
		path := filepath.Join(store.preparationDir, e.Name())
		entry, err := readPreparation(path)
		if err == nil && store.preparationPath(*entry) != path {
			err = errors.New("entry does not match its file name")
		}
		if err != nil {
			logger.Warn(ctx, "Skipping unreadable attempt preparation entry",
				tag.File(e.Name()), tag.Error(err))
			continue
		}
		preparations = append(preparations, *entry)
	}
	sort.SliceStable(preparations, func(i, j int) bool {
		return preparations[i].PreparedAt < preparations[j].PreparedAt
	})
	return preparations, nil
}

// AttemptPrepared implements persis.DAGRunPreparationLookup: it reads the
// entries the attempt would have, its own and any for one of its executions
// (BeginAttemptPreparation), and reports true if there is one. Absent means
// nothing is at an entry's name (Lstat, so a dangling link is not absent);
// anything there that is not a readable entry for this attempt is an error.
func (store *Store) AttemptPrepared(_ context.Context, run, root ir.DAGRunRef, attemptID string) (bool, error) {
	if root.Zero() {
		root = run
	}
	want := persis.AttemptPreparation{Run: run, RootRun: root, AttemptID: attemptID}
	found, err := preparationAt(store.preparationPath(want), want)
	if err != nil || found {
		return found, err
	}
	matches, err := store.executionPreparationPaths(want)
	if err != nil {
		return false, fmt.Errorf("failed to read the attempt preparation: %w", err)
	}
	for _, path := range matches {
		found, err := preparationAt(path, want)
		if err != nil || found {
			return found, err
		}
	}
	return false, nil
}

// preparationAt reports whether path holds a readable entry for want's
// attempt (any execution of it).
func preparationAt(path string, want persis.AttemptPreparation) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read the attempt preparation: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("the attempt preparation entry is not a regular file (%s)", info.Mode().Type())
	}
	entry, err := readPreparation(path)
	if errors.Is(err, os.ErrNotExist) {
		// Ended between the two reads: absent only if nothing is there now.
		if _, again := os.Lstat(path); errors.Is(again, os.ErrNotExist) {
			return false, nil
		}
	}
	if err != nil {
		return false, fmt.Errorf("failed to read the attempt preparation: %w", err)
	}
	if entry.Run != want.Run || entry.RootRun != want.RootRun || entry.AttemptID != want.AttemptID {
		return false, errors.New("the attempt preparation entry names another attempt")
	}
	return true, nil
}

// EndSettledAttemptPreparation implements persis.DAGRunPreparationSettler. It
// holds the run's data-root lock, which AbandonAttempt and CreateAttempt
// hold, so no abandonment restores the attempt between the decision and the
// removal.
func (store *Store) EndSettledAttemptPreparation(ctx context.Context, p persis.AttemptPreparation) (bool, error) {
	if p.RootRun.Zero() {
		p.RootRun = p.Run
	}
	root := store.dataRoot(p.RootRun.Name)
	lockCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := root.Lock(lockCtx); err != nil {
		return false, fmt.Errorf("failed to acquire lock for dag-run %s: %w", p.Run.ID, err)
	}
	defer func() {
		if err := root.Unlock(); err != nil {
			logger.Error(ctx, "Failed to unlock dag-run", tag.RunID(p.Run.ID), tag.Error(err))
		}
	}()
	settled, err := store.preparationSettledLocked(ctx, root, p)
	if err != nil || !settled {
		return false, err
	}
	return true, store.EndAttemptPreparation(ctx, p)
}

func (store *Store) preparationSettledLocked(ctx context.Context, root DataRoot, p persis.AttemptPreparation) (bool, error) {
	run, err := store.findRunLocked(ctx, root, p.RootRun, p.Run)
	if errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	dirs, err := run.listAttemptDirs()
	if err != nil {
		return false, fmt.Errorf("failed to list attempts: %w", err)
	}
	// Attempts are listed newest first. The latest is the newest visible one
	// with a status; the preparation counts as present unless hidden or
	// gone, even before its first status is written.
	var latest, prepared *Attempt
	for _, dir := range dirs {
		att, err := run.AttemptByDir(dir, store.cache)
		if err != nil {
			// Unknown, not settled: the entry stays for the next pass.
			return false, fmt.Errorf("failed to open attempt %s: %w", dir, err)
		}
		if att.ID() == p.AttemptID {
			if att.Hidden() {
				return true, nil
			}
			prepared = att
			break
		}
		if latest == nil && !att.Hidden() && att.Exists() {
			latest = att
		}
	}
	if p.QueuedAt != "" {
		return store.executionSettledLocked(ctx, p, prepared, latest)
	}
	switch {
	case prepared == nil:
		return true, nil
	case latest == nil:
		status, err := readWrittenStatus(ctx, prepared)
		if err != nil {
			return false, fmt.Errorf("read attempt %s status: %w", prepared.ID(), err)
		}
		return status != nil && (status.Status != ir.NotStarted || status.WorkerID != ""), nil
	}
	journaled, err := store.AttemptPrepared(ctx, p.Run, p.RootRun, latest.ID())
	if err != nil {
		return false, err
	}
	return !journaled, nil
}

// executionSettledLocked decides an entry for one execution of a reused
// attempt: settled once the attempt is gone or hidden, its status names
// another execution, or the execution was handed to a worker. While a newer
// attempt is the latest, the entry stays only if that one is a preparation
// that may yet be abandoned, which would make this attempt the latest again.
func (store *Store) executionSettledLocked(ctx context.Context, p persis.AttemptPreparation, prepared, latest *Attempt) (bool, error) {
	if prepared == nil {
		return true, nil
	}
	if latest != nil {
		journaled, err := store.AttemptPrepared(ctx, p.Run, p.RootRun, latest.ID())
		if err != nil {
			return false, err
		}
		return !journaled, nil
	}
	status, err := readWrittenStatus(ctx, prepared)
	if err != nil {
		return false, fmt.Errorf("read attempt %s status: %w", prepared.ID(), err)
	}
	if status == nil {
		// A reused attempt always has a status; none is not settled.
		return false, nil
	}
	return !executionAwaitsDispatch(status, p.QueuedAt), nil
}

// EndAttemptPreparation implements persis.DAGRunPreparationJournal.
func (store *Store) EndAttemptPreparation(_ context.Context, preparation persis.AttemptPreparation) error {
	if preparation.RootRun.Zero() {
		preparation.RootRun = preparation.Run
	}
	if err := os.Remove(store.preparationPath(preparation)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to end the attempt preparation: %w", err)
	}
	return nil
}

// preparationPath names an entry by its root run, run and attempt, and for
// one execution of a reused attempt by its queued-at marker too.
func (store *Store) preparationPath(p persis.AttemptPreparation) string {
	name := store.attemptPreparationName(p)
	if p.QueuedAt != "" {
		marker := sha256.Sum256([]byte(p.QueuedAt))
		name += "-" + hex.EncodeToString(marker[:16])
	}
	return filepath.Join(store.preparationDir, name+preparationExt)
}

// executionPreparationPaths lists the entries of an attempt's executions by
// name, reading the literal journal directory: no pattern is applied to the
// path, and a listing error is returned.
func (store *Store) executionPreparationPaths(p persis.AttemptPreparation) ([]string, error) {
	entries, err := os.ReadDir(store.preparationDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	prefix := store.attemptPreparationName(p) + "-"
	var paths []string
	for _, e := range entries {
		if name := e.Name(); strings.HasPrefix(name, prefix) && strings.HasSuffix(name, preparationExt) {
			paths = append(paths, filepath.Join(store.preparationDir, name))
		}
	}
	return paths, nil
}

func (store *Store) attemptPreparationName(p persis.AttemptPreparation) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		p.RootRun.Name, p.RootRun.ID, p.Run.Name, p.Run.ID, p.AttemptID,
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func readPreparation(path string) (*persis.AttemptPreparation, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is inside the preparation journal
	if err != nil {
		return nil, err
	}
	var entry persis.AttemptPreparation
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if entry.Schema != persis.AttemptPreparationSchema {
		return nil, fmt.Errorf("unsupported schema %d", entry.Schema)
	}
	if entry.AttemptID == "" || entry.Run.ID == "" || entry.RootRun.ID == "" {
		return nil, errors.New("run and attempt are required")
	}
	if _, err := time.Parse(time.RFC3339Nano, entry.PreparedAt); err != nil {
		return nil, fmt.Errorf("prepared at: %w", err)
	}
	return &entry, nil
}
