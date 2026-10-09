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
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

const preparationExt = ".json"

var _ persis.DAGRunPreparationJournal = (*Store)(nil)

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
