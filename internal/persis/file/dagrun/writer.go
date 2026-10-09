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
	}

	if err := w.encoder.Encode(st); err != nil {
		return fmt.Errorf("failed to encode status: %w", err)
	}

	return w.flushAndSyncLocked()
}

// reopenIfReplacedLocked reopens the target when the open descriptor no longer
// refers to the file at the target path, as after another handle compacted it.
// A target that no longer exists is left alone: recreating it would resurrect
// a removed run.
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
	if err := w.buffer.Flush(); err != nil {
		return fmt.Errorf("failed to flush replaced status file: %w", err)
	}
	_ = w.file.Close()
	file, err := fileutil.OpenOrCreateFile(w.target)
	if err != nil {
		w.file, w.buffer, w.encoder = nil, nil, nil
		return fmt.Errorf("failed to reopen status file: %w", err)
	}
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
