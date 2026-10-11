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
	_ persis.DAGRunPreparationJournal = (*Store)(nil)
	_ persis.DAGRunPreparationLookup  = (*Store)(nil)
	_ persis.DAGRunPreparationSettler = (*Store)(nil)
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
	if root.Zero() {
		root = run
	}
	entry := persis.AttemptPreparation{
		Schema:     persis.AttemptPreparationSchema,
		Run:        run,
		RootRun:    root,
		AttemptID:  attemptID,
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
// one entry the attempt would have, and an entry that exists but cannot be
// read, or names another attempt, is an error rather than absent.
func (store *Store) AttemptPrepared(_ context.Context, run, root ir.DAGRunRef, attemptID string) (bool, error) {
	if root.Zero() {
		root = run
	}
	want := persis.AttemptPreparation{Run: run, RootRun: root, AttemptID: attemptID}
	entry, err := readPreparation(store.preparationPath(want))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read the attempt preparation: %w", err)
	}
	if entry.Run != run || entry.RootRun != root || entry.AttemptID != attemptID {
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
			continue
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

// preparationPath names an entry by its root run, run and attempt.
func (store *Store) preparationPath(p persis.AttemptPreparation) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		p.RootRun.Name, p.RootRun.ID, p.Run.Name, p.Run.ID, p.AttemptID,
	}, "\x00")))
	return filepath.Join(store.preparationDir, hex.EncodeToString(sum[:])+preparationExt)
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
