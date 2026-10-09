// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sync"

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/ir"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// logFinalRecordSuffix names the record written beside a log file when its
// final chunk is accepted. A log without a record matching an execution's
// marker was not finalized by that execution.
const logFinalRecordSuffix = ".final"

// logFinalRecord is the content of a log file's finalization record.
// SHA256 is "sha256:<hex>" of the file's bytes at finalization, the bytes Size
// describes, so a reader can prove that a copy it took is the finalized log.
type logFinalRecord struct {
	ExecutionMarker string `json:"executionMarker"`
	AttemptID       string `json:"attemptId"`
	Size            int64  `json:"size"`
	SHA256          string `json:"sha256"`
}

// logHandler handles log streaming from workers
type logHandler struct {
	logDir           string
	attemptValidator func(context.Context, attemptIdentity) error
	// lockAttempt holds an attempt's write lock across a chunk's validation
	// and write; see attemptWriteLocks.
	lockAttempt func(root ir.DAGRunRef) (unlock func())

	// Active writers: streamKey -> writer
	writers   map[string]*streamLogWriter
	writersMu sync.Mutex
}

// streamLogWriter writes streamed logs directly to a single log file.
type streamLogWriter struct {
	file       *os.File
	path       string
	positioned bool
	size       int64
	mu         sync.Mutex
}

func (w *streamLogWriter) write(chunk *coordinatorv1.LogChunk) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if chunk.HasByteOffset() != w.positioned {
		return 0, errors.New("log stream write mode changed")
	}
	if !w.positioned {
		n, err := w.file.Write(chunk.Data)
		w.size += int64(n) // #nosec G115 -- n is non-negative and bounded by the input buffer
		return n, err
	}
	byteOffset := chunk.GetByteOffset()
	if byteOffset > math.MaxInt64 {
		return 0, errors.New("log chunk byte offset exceeds supported file size")
	}
	offset := int64(byteOffset) // #nosec G115 -- bounds checked above
	if offset > w.size {
		return 0, errors.New("log chunk byte offset exceeds current file size")
	}
	if uint64(len(chunk.Data)) > uint64(math.MaxInt64-offset) { // #nosec G115 -- buffer length is non-negative
		return 0, errors.New("log chunk exceeds supported file size")
	}
	n, err := w.file.WriteAt(chunk.Data, offset)
	if end := offset + int64(n); end > w.size { // #nosec G115 -- n is non-negative and bounded above
		w.size = end
	}
	return n, err
}

func (w *streamLogWriter) close(finalSize *uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var truncateErr error
	if finalSize != nil {
		if *finalSize > math.MaxInt64 {
			truncateErr = errors.New("final log size exceeds supported file size")
		} else if int64(*finalSize) > w.size { // #nosec G115 -- bounds checked above
			truncateErr = errors.New("final log size exceeds current file size")
		} else {
			truncateErr = w.file.Truncate(int64(*finalSize)) // #nosec G115 -- bounds checked above
			if truncateErr == nil {
				w.size = int64(*finalSize) // #nosec G115 -- bounds checked above
			}
		}
	}
	return errors.Join(truncateErr, w.file.Sync(), w.file.Close())
}

// newLogHandler creates a new log handler
func newLogHandler(logDir string) *logHandler {
	return &logHandler{
		logDir:  logDir,
		writers: make(map[string]*streamLogWriter),
	}
}

// handleStream processes the log stream from a worker
func (h *logHandler) handleStream(stream coordinatorv1.CoordinatorService_StreamLogsServer) error {
	ctx := stream.Context()
	var chunksReceived uint64
	var bytesWritten uint64
	var validatedIdentity *attemptIdentity

	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			// Stream completed - send response
			return stream.SendAndClose(&coordinatorv1.StreamLogsResponse{
				ChunksReceived: chunksReceived,
				BytesWritten:   bytesWritten,
			})
		}
		if err != nil {
			return fmt.Errorf("failed to receive chunk: %w", err)
		}

		chunksReceived++

		unlock := func() {}
		if h.attemptValidator != nil {
			identity, identityErr := logChunkIdentity(chunk)
			if identityErr != nil {
				return status.Error(codes.InvalidArgument, identityErr.Error())
			}
			if validatedIdentity != nil && identity != *validatedIdentity {
				return status.Error(codes.FailedPrecondition, "log stream attempt identity changed")
			}
			// Every chunk is validated, and under the attempt's write lock, so
			// a claim of the attempt's next execution cannot fall between this
			// validation and the write: an earlier execution's chunk is either
			// written before that claim or refused after it.
			if h.lockAttempt != nil {
				unlock = h.lockAttempt(identity.root)
			}
			if err := h.attemptValidator(ctx, identity); err != nil {
				unlock()
				return err
			}
			validatedIdentity = &identity
		}

		n, err := h.applyChunk(chunk)
		unlock()
		if err != nil {
			return err
		}
		bytesWritten += n
	}
}

// applyChunk writes one chunk, or finalizes its stream, and returns the
// number of bytes written.
func (h *logHandler) applyChunk(chunk *coordinatorv1.LogChunk) (uint64, error) {
	if chunk.IsFinal {
		// A checkpointed stream resumes on a new RPC, which may carry only the
		// final chunk. A positioned final chunk names the final size, so the
		// file can be reopened, truncated to it and finalized. An unpositioned
		// one cannot say which bytes are this execution's, so without an open
		// writer it records nothing and the log stays incomplete.
		if chunk.HasByteOffset() && !h.hasWriter(chunk) {
			w, err := h.getOrCreateWriter(chunk)
			if err != nil {
				return 0, fmt.Errorf("failed to reopen log file for finalization: %w", err)
			}
			// This coordinator did not receive all of the execution's bytes,
			// so it cannot vouch for the log: leave it incomplete.
			if chunk.GetByteOffset() > uint64(w.size) { // #nosec G115 -- size is non-negative
				h.discardWriter(chunk)
				return 0, nil
			}
		}
		size, finalized, err := h.closeWriter(chunk)
		if err != nil {
			return 0, fmt.Errorf("failed to finalize log file: %w", err)
		}
		if finalized {
			logPath := h.logFilePath(chunk)
			// Hash the file as finalized rather than the bytes received: a
			// resumed stream rewrites earlier offsets, and the record must
			// describe the file a reader will copy.
			digest, hashedSize, err := fileSHA256(logPath)
			if err != nil {
				return 0, fmt.Errorf("failed to hash finalized log file: %w", err)
			}
			if hashedSize != size {
				return 0, fmt.Errorf("finalized log file changed size: %d bytes, want %d", hashedSize, size)
			}
			if err := writeLogFinalRecord(logPath, logFinalRecord{
				ExecutionMarker: chunk.ExecutionMarker,
				AttemptID:       chunk.AttemptId,
				Size:            size,
				SHA256:          digest,
			}); err != nil {
				return 0, fmt.Errorf("failed to record log finalization: %w", err)
			}
		}
		return 0, nil
	}

	// Skip empty data
	if len(chunk.Data) == 0 {
		return 0, nil
	}

	// Get or create writer for this stream
	writer, err := h.getOrCreateWriter(chunk)
	if err != nil {
		return 0, fmt.Errorf("failed to create writer: %w", err)
	}

	// Write the data using thread-safe method
	n, err := writer.write(chunk)
	if err != nil {
		return 0, fmt.Errorf("failed to write data: %w", err)
	}
	if n > 0 {
		return uint64(n), nil // #nosec G115 -- n is non-negative from successful Write
	}
	return 0, nil
}

// streamKey creates a unique key for identifying a log stream.
// Includes AttemptId to prevent collisions during retry scenarios.
func (h *logHandler) streamKey(chunk *coordinatorv1.LogChunk) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s",
		chunk.DagName,
		chunk.DagRunId,
		chunk.AttemptId,
		chunk.StepName,
		chunk.StreamType.String(),
	)
}

// hasWriter reports whether a writer is open for the chunk's stream.
func (h *logHandler) hasWriter(chunk *coordinatorv1.LogChunk) bool {
	h.writersMu.Lock()
	defer h.writersMu.Unlock()
	_, ok := h.writers[h.streamKey(chunk)]
	return ok
}

// discardWriter closes the chunk's writer without truncating or recording it.
func (h *logHandler) discardWriter(chunk *coordinatorv1.LogChunk) {
	key := h.streamKey(chunk)
	h.writersMu.Lock()
	w, ok := h.writers[key]
	delete(h.writers, key)
	h.writersMu.Unlock()
	if ok {
		_ = w.close(nil)
	}
}

// fileSHA256 returns "sha256:<hex>" of the file's content and its length.
func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the coordinator's own log file
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}

// writeLogFinalRecord atomically records that a log file was finalized.
func writeLogFinalRecord(logPath string, record logFinalRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return fileutil.WriteFileAtomic(logPath+logFinalRecordSuffix, data, 0o600)
}

// getOrCreateWriter returns an existing writer or creates a new one
func (h *logHandler) getOrCreateWriter(chunk *coordinatorv1.LogChunk) (*streamLogWriter, error) {
	key := h.streamKey(chunk)

	h.writersMu.Lock()
	defer h.writersMu.Unlock()

	// Check if writer already exists
	if w, ok := h.writers[key]; ok {
		if w.positioned != chunk.HasByteOffset() {
			return nil, errors.New("log stream write mode changed")
		}
		return w, nil
	}

	// Create the log file path
	logPath := h.logFilePath(chunk)

	// Ensure directory exists
	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// The file is about to be written again, so an earlier execution's
	// finalization record no longer describes it.
	if err := os.Remove(logPath + logFinalRecordSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to clear log finalization record: %w", err)
	}

	var file *os.File
	var err error
	if chunk.HasByteOffset() {
		file, err = fileutil.OpenOrCreateFileForRandomWrite(logPath)
	} else {
		file, err = fileutil.OpenOrCreateFileWithoutSync(logPath)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to inspect log file: %w", err)
	}

	w := &streamLogWriter{
		file:       file,
		path:       logPath,
		positioned: chunk.HasByteOffset(),
		size:       info.Size(),
	}

	h.writers[key] = w
	return w, nil
}

// closeWriter closes and removes a writer.
// closeWriter finalizes the chunk's stream and returns the file's final size.
// finalized is false when no writer was open for the stream.
func (h *logHandler) closeWriter(chunk *coordinatorv1.LogChunk) (size int64, finalized bool, err error) {
	key := h.streamKey(chunk)

	h.writersMu.Lock()
	w, ok := h.writers[key]
	if ok {
		delete(h.writers, key)
	}
	h.writersMu.Unlock()
	if !ok {
		return 0, false, nil
	}
	if !w.positioned {
		err = w.close(nil)
	} else {
		finalSize := chunk.GetByteOffset()
		err = w.close(&finalSize)
	}
	if err != nil {
		return 0, false, err
	}
	return w.size, true, nil
}

// logFilePath generates the log file path following the existing pattern.
// Path format: {logDir}/{dagName}/{dagRunID}/{attemptID}/{stepName}.{ext}
func (h *logHandler) logFilePath(chunk *coordinatorv1.LogChunk) string {
	dagName := chunk.DagName
	dagRunID := chunk.DagRunId

	// For sub-DAGs, store under root DAG's directory
	if chunk.RootDagRunId != "" {
		dagName = chunk.RootDagRunName
		dagRunID = chunk.RootDagRunId
	}

	attemptDir := chunk.AttemptId
	if attemptDir == "" {
		attemptDir = dagRunID
	}

	ext := StreamTypeToExtension(chunk.StreamType)

	// For scheduler logs, use just "scheduler.log" without stepName prefix
	var filename string
	if chunk.StreamType == coordinatorv1.LogStreamType_LOG_STREAM_TYPE_SCHEDULER {
		filename = "scheduler.log"
	} else {
		filename = fmt.Sprintf("%s.%s", fileutil.SafeName(chunk.StepName), ext)
	}

	return filepath.Join(
		h.logDir,
		fileutil.SafeName(dagName),
		fileutil.SafeName(dagRunID),
		fileutil.SafeName(attemptDir),
		filename,
	)
}

// StreamTypeToExtension returns the file extension for a given stream type.
func StreamTypeToExtension(streamType coordinatorv1.LogStreamType) string {
	switch streamType {
	case coordinatorv1.LogStreamType_LOG_STREAM_TYPE_STDOUT:
		return "stdout.log"
	case coordinatorv1.LogStreamType_LOG_STREAM_TYPE_STDERR:
		return "stderr.log"
	case coordinatorv1.LogStreamType_LOG_STREAM_TYPE_SCHEDULER:
		return "scheduler.log"
	case coordinatorv1.LogStreamType_LOG_STREAM_TYPE_UNSPECIFIED:
		return "log"
	}
	return "log"
}

// Close closes all open writers using the provided context for logging.
// This preserves trace context for observability.
func (h *logHandler) Close(ctx context.Context) {
	h.writersMu.Lock()
	defer h.writersMu.Unlock()

	for _, w := range h.writers {
		if err := w.close(nil); err != nil {
			logger.Warn(ctx, "Failed to close log file",
				slog.String("path", w.path),
				slog.String("error", err.Error()))
		}
	}
	h.writers = make(map[string]*streamLogWriter)
}
