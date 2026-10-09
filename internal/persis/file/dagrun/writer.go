// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/gofrs/flock"
)

var (
	ErrWriterNotOpen = errors.New("writer is not open")
)

type Writer struct {
	target     string
	buffer     *bufio.Writer
	encoder    *json.Encoder
	file       *os.File
	mu         sync.Mutex
	bufferSize int
	// fileLock, when set, is held for each append; see withFileLock.
	fileLock *flock.Flock
}

// WriterOption defines functional options for configuring a Writer.
type WriterOption func(*Writer)

// withFileLock makes each append hold an exclusive lock on lockPath, the lock
// that compaction of the same file also holds, and reopen the target first if
// a compaction replaced it. Without it, an append can land between a
// compaction's read and its rename and be dropped, or go to the replaced file
// through a descriptor opened before the rename.
func withFileLock(lockPath string) WriterOption {
	return func(w *Writer) {
		w.fileLock = flock.New(lockPath)
	}
}

// NewWriter creates a new Writer instance for the specified target file path.
func NewWriter(target string, opts ...WriterOption) *Writer {
	w := &Writer{
		target:     target,
		bufferSize: 4096,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// Open prepares the writer for writing by creating necessary directories
// and opening the target file.
func (w *Writer) Open() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.isOpenLocked() {
		return nil
	}

	dir := filepath.Dir(w.target)
	if err := fileutil.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	file, err := fileutil.OpenOrCreateFile(w.target)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", w.target, err)
	}

	w.file = file
	w.buffer = bufio.NewWriterSize(file, w.bufferSize)
	w.encoder = json.NewEncoder(w.buffer)
	w.encoder.SetEscapeHTML(false)
	return nil
}

// Write serializes the status to JSON and appends it to the file.
// It automatically flushes data to ensure durability.
func (w *Writer) Write(ctx context.Context, st ir.DAGRunStatus) error {
	if err := w.write(st); err != nil {
		logger.Error(ctx, "Failed to write status", tag.Error(err))
		return err
	}

	return nil
}

// write encodes a single status entry and persists it to disk.
func (w *Writer) write(st ir.DAGRunStatus) error {
	return w.writeIf(st, nil)
}

// writeIf is write, made conditional: under the status file's lock, after any
// reopen, it calls check and appends only if check returns nil. A writer
// without a file lock cannot make the check atomic and refuses a check.
func (w *Writer) writeIf(st ir.DAGRunStatus, check func() error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.isOpenLocked() {
		return ErrWriterNotOpen
	}

	if w.fileLock != nil {
		if err := w.fileLock.Lock(); err != nil {
			return fmt.Errorf("failed to lock status file: %w", err)
		}
		defer func() { _ = w.fileLock.Unlock() }()
		if err := w.reopenIfReplacedLocked(); err != nil {
			return err
		}
	} else if check != nil {
		return errors.New("conditional write requires a status file lock")
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}

	if err := w.encoder.Encode(st); err != nil {
		return fmt.Errorf("failed to encode status: %w", err)
	}

	return w.flushAndSyncLocked()
}

// reopenIfReplacedLocked reopens the target when the open descriptor no longer
// refers to the file at the target path, as after another handle compacted it.
// The replacement is opened without creating it, so a target removed in the
// meantime is never recreated, and the current descriptor is kept until the
// replacement is open, so a failed reopen leaves the writer usable and the
// next write tries again.
func (w *Writer) reopenIfReplacedLocked() error {
	current, err := os.Stat(w.target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to stat status file: %w", err)
	}
	open, err := w.file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat open status file: %w", err)
	}
	if os.SameFile(current, open) {
		return nil
	}
	file, err := os.OpenFile(w.target, os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0) // #nosec G304 -- the writer's own target
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to reopen status file: %w", err)
	}
	if err := w.buffer.Flush(); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to flush replaced status file: %w", err)
	}
	_ = w.file.Close()
	w.file = file
	w.buffer = bufio.NewWriterSize(file, w.bufferSize)
	w.encoder = json.NewEncoder(w.buffer)
	w.encoder.SetEscapeHTML(false)
	return nil
}

// Close flushes any buffered data and closes the underlying file.
// It's safe to call close multiple times.
func (w *Writer) Close(ctx context.Context) error {
	if err := w.close(); err != nil {
		logger.Error(ctx, "Failed to close writer", tag.Error(err))
		return err
	}

	return nil
}

// close flushes any buffered data and closes the underlying file.
func (w *Writer) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.isOpenLocked() {
		return nil
	}

	var errs []error

	if err := w.flushAndSyncLocked(); err != nil {
		errs = append(errs, err)
	}

	if err := w.file.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close error: %w", err))
	}

	w.file = nil
	w.buffer = nil
	w.encoder = nil
	if w.fileLock != nil {
		_ = w.fileLock.Close()
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// flushAndSyncLocked flushes the buffered encoder output and syncs the file.
func (w *Writer) flushAndSyncLocked() error {
	var errs []error

	if err := w.buffer.Flush(); err != nil {
		errs = append(errs, fmt.Errorf("flush error: %w", err))
	}

	if err := w.file.Sync(); err != nil {
		errs = append(errs, fmt.Errorf("sync error: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// IsOpen returns true if the writer is currently open.
func (w *Writer) IsOpen() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.isOpenLocked()
}

// isOpenLocked reports whether the writer has an active file and encoder.
func (w *Writer) isOpenLocked() bool {
	return w.file != nil && w.buffer != nil && w.encoder != nil
}
