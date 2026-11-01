// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// A segmented upload crosses streams, so that a file larger than one request of
// the worker channel still arrives whole.
//
// Its bytes wait under SegmentDir in the attempt's archive, in a directory named
// for everything that identifies the writer: owner, machine, worker, job, run,
// attempt and execution. So no other writer reaches them, and the directory
// holds that identity, which is how a later upload proves it stale. A repeated
// segment is told from a conflicting one by comparing bytes. Nothing is visible
// until the final chunk has been checked against the whole file's size and
// digest, and a committed artifact is never replaced by a different one.

const segmentIdentityFile = "identity.json"

// SegmentDir holds uploads in progress inside an attempt's archive.
const SegmentDir = ir.ArtifactSegmentDir

// segmentWriter is who a segmented upload belongs to, as it is kept beside the
// upload. Machine and Owner come from the authenticated caller, never from the
// chunk, and are empty on a coordinator that authenticates nobody.
type segmentWriter struct {
	AttemptKey      string `json:"attemptKey"`
	WorkerID        string `json:"workerId"`
	DAGRun          string `json:"dagRun"`
	DAGRunID        string `json:"dagRunId"`
	Root            string `json:"root"`
	RootID          string `json:"rootId"`
	AttemptID       string `json:"attemptId"`
	ExecutionMarker string `json:"executionMarker"`
	Machine         string `json:"machine"`
	Owner           string `json:"owner"`
}

func (w segmentWriter) identity() (attemptIdentity, error) {
	return newAttemptIdentity(w.AttemptKey, w.WorkerID, ir.NewDAGRunRef(w.DAGRun, w.DAGRunID),
		ir.NewDAGRunRef(w.Root, w.RootID), w.AttemptID, w.ExecutionMarker)
}

func (w segmentWriter) directory() (string, error) {
	data, err := json.Marshal(w)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return path.Join(SegmentDir, hex.EncodeToString(sum[:])), nil
}

func newSegmentWriter(ctx context.Context, identity attemptIdentity) segmentWriter {
	w := segmentWriter{
		AttemptKey: identity.attemptKey, WorkerID: identity.workerID,
		DAGRun: identity.dagRun.Name, DAGRunID: identity.dagRun.ID,
		Root: identity.root.Name, RootID: identity.root.ID,
		AttemptID: identity.attemptID, ExecutionMarker: identity.executionMarker,
	}
	if caller, ok := transportauth.CallerFrom(ctx); ok {
		w.Machine, w.Owner = caller.Machine.MachineID, caller.Machine.OwnerID
	}
	return w
}

// applySegment takes one chunk of a segmented upload. It validates the attempt
// and touches disk under the attempt's write lock, so an attempt that has been
// superseded or fenced changes nothing, and it returns how much of the upload
// is durable.
func (h *artifactHandler) applySegment(
	ctx context.Context,
	chunk *coordinatorv1.ArtifactChunk,
	identity attemptIdentity,
) (uint64, error) {
	if h.attemptValidator == nil || h.lockAttempt == nil {
		return 0, status.Error(codes.FailedPrecondition, "segmented uploads need attempt validation")
	}
	defer h.lockAttempt(identity.root)()
	if err := h.attemptValidator(ctx, identity); err != nil {
		return 0, err
	}
	archiveDir, err := h.archiveDir(ctx, chunk)
	if err != nil {
		return 0, err
	}
	resolved, err := fileutil.ResolvePathWithinBase(archiveDir, chunk.RelativePath)
	if err != nil {
		return 0, status.Error(codes.InvalidArgument, fmt.Sprintf("resolve artifact path %q: %v", chunk.RelativePath, err))
	}
	relPath, err := filepath.Rel(archiveDir, resolved)
	if err != nil {
		return 0, fmt.Errorf("resolve artifact path %q: %w", chunk.RelativePath, err)
	}
	relPath = filepath.ToSlash(relPath)
	if relPath == SegmentDir || path.Dir(relPath) == SegmentDir || isUnder(relPath, SegmentDir) {
		return 0, status.Error(codes.InvalidArgument, "this artifact path is reserved")
	}
	if err := os.MkdirAll(archiveDir, 0o750); err != nil {
		return 0, fmt.Errorf("create artifact directory: %w", err)
	}
	// The root keeps every open and rename inside this attempt's archive.
	root, err := os.OpenRoot(archiveDir)
	if err != nil {
		return 0, fmt.Errorf("open artifact directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	writer := newSegmentWriter(ctx, identity)
	dir, err := h.segmentDirectory(ctx, root, writer)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256([]byte(relPath))
	name := path.Join(dir, hex.EncodeToString(sum[:]))
	file, err := openSegment(root, name)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	if done, err := alreadyCommitted(ctx, root, file, name, relPath, chunk); err != nil || done {
		if done {
			removeIfFinished(root, dir)
		}
		return chunk.GetTotalSize(), err
	}
	size, err := writeSegment(file, chunk.GetByteOffset(), chunk.Data)
	if err != nil {
		return 0, err
	}
	if !chunk.IsFinal {
		return size, nil
	}
	if err := commitSegments(ctx, root, file, name, relPath, size, chunk); err != nil {
		return 0, err
	}
	removeIfFinished(root, dir)
	return size, nil
}

// alreadyCommitted answers a final chunk that carries no data, to a writer whose
// segments are gone, from the artifact: it is an upload repeated after its
// acknowledgment was lost, and the file need not cross the link again. Any other
// chunk, or a different artifact, goes on and is refused as it would be.
func alreadyCommitted(ctx context.Context, root *os.Root, file *os.File, name, relPath string, chunk *coordinatorv1.ArtifactChunk) (bool, error) {
	if !chunk.IsFinal || len(chunk.Data) > 0 || chunk.GetSha256() == "" || chunk.GetTotalSize() == 0 {
		return false, nil
	}
	held, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("read artifact segment: %w", err)
	}
	if held.Size() != 0 {
		return false, nil
	}
	info, err := root.Lstat(relPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	// The request is small and the file need not be: its hash stops with the
	// stream, and the attempt's lock lets one run at a time.
	same, err := sameArtifact(ctx, root, relPath, info, chunk.GetTotalSize(), chunk.GetSha256())
	if err != nil || !same {
		return false, err
	}
	return true, root.Remove(name)
}

func isUnder(p, dir string) bool {
	for p != "." && p != "/" {
		if p == dir {
			return true
		}
		p = path.Dir(p)
	}
	return false
}

// segmentDirectory is the writer's directory. Creating it is when stale ones
// are looked for: this is the moment a retry of the attempt starts over.
func (h *artifactHandler) segmentDirectory(ctx context.Context, root *os.Root, writer segmentWriter) (string, error) {
	dir, err := writer.directory()
	if err != nil {
		return "", err
	}
	if info, err := root.Lstat(dir); err == nil {
		if !info.IsDir() {
			return "", status.Error(codes.FailedPrecondition, "artifact segments are not a directory")
		}
		return dir, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("read artifact segments: %w", err)
	}
	h.sweepSegments(ctx, root)
	if err := root.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create artifact segments: %w", err)
	}
	data, err := json.Marshal(writer)
	if err != nil {
		return "", err
	}
	file, err := root.OpenFile(path.Join(dir, segmentIdentityFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return "", fmt.Errorf("record artifact segments: %w", err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(data); err != nil {
		return "", fmt.Errorf("record artifact segments: %w", err)
	}
	return dir, nil
}

// sweepSegments removes uploads the attempt's fence proves are dead: their own
// identity is refused as superseded. Age proves nothing, and a directory whose
// identity cannot be read, or that the fence does not refuse, is kept. What
// remains goes with the attempt's archive.
func (h *artifactHandler) sweepSegments(ctx context.Context, root *os.Root) {
	entries, err := fs.ReadDir(root.FS(), SegmentDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		dir := path.Join(SegmentDir, entry.Name())
		data, err := fs.ReadFile(root.FS(), path.Join(dir, segmentIdentityFile))
		if err != nil {
			continue
		}
		var writer segmentWriter
		if err := json.Unmarshal(data, &writer); err != nil {
			continue
		}
		if expected, err := writer.directory(); err != nil || expected != dir {
			continue
		}
		identity, err := writer.identity()
		if err != nil {
			continue
		}
		if status.Code(h.attemptValidator(ctx, identity)) == codes.FailedPrecondition {
			_ = root.RemoveAll(dir)
		}
	}
}

// openSegment opens the upload's file without following a link: a name that is
// not a regular file is refused, and a new file is created exclusively.
func openSegment(root *os.Root, name string) (*os.File, error) {
	info, err := root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o640)
		if err != nil {
			return nil, fmt.Errorf("create artifact segment: %w", err)
		}
		return file, nil
	case err != nil:
		return nil, fmt.Errorf("read artifact segment: %w", err)
	case !info.Mode().IsRegular():
		return nil, status.Error(codes.FailedPrecondition, "artifact segment is not a regular file")
	}
	file, err := root.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open artifact segment: %w", err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, status.Error(codes.FailedPrecondition, "artifact segment changed while opening it")
	}
	return file, nil
}

// writeSegment places data at offset and returns the file's size. Bytes the
// file already holds must match: a lost acknowledgment repeats a segment, and
// anything else is a conflict. Beyond the end is a gap and is refused.
func writeSegment(file *os.File, offset uint64, data []byte) (uint64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("read artifact segment: %w", err)
	}
	size := uint64(info.Size()) // #nosec G115 -- a file's size is non-negative
	if offset > size {
		return 0, status.Error(codes.FailedPrecondition,
			fmt.Sprintf("artifact segment at %d leaves a gap after %d", offset, size))
	}
	overlap := min(size-offset, uint64(len(data)))
	if overlap > 0 {
		held := make([]byte, overlap)
		if _, err := file.ReadAt(held, int64(offset)); err != nil { // #nosec G115 -- below the file's size
			return 0, fmt.Errorf("read artifact segment: %w", err)
		}
		if !bytes.Equal(held, data[:overlap]) {
			return 0, status.Error(codes.FailedPrecondition, "artifact segment conflicts with what is held")
		}
	}
	if rest := data[overlap:]; len(rest) > 0 {
		if _, err := file.WriteAt(rest, int64(offset+overlap)); err != nil { // #nosec G115 -- the end of the file
			return 0, fmt.Errorf("write artifact segment: %w", err)
		}
		size = offset + uint64(len(data))
	}
	// The acknowledgment says these bytes survive a restart.
	if err := file.Sync(); err != nil {
		return 0, fmt.Errorf("sync artifact segment: %w", err)
	}
	return size, nil
}

// commitSegments makes the upload the artifact, once. A wrong size or digest
// changes nothing that is committed. An artifact already there with the same
// size and digest is this upload repeated after a lost acknowledgment, and it
// succeeds. A different one is another result, and it is left alone.
func commitSegments(ctx context.Context, root *os.Root, file *os.File, name, relPath string, size uint64, chunk *coordinatorv1.ArtifactChunk) error {
	if chunk.GetSha256() == "" || chunk.GetTotalSize() != size {
		_ = root.Remove(name)
		return status.Error(codes.FailedPrecondition, "artifact segments do not add up to the file")
	}
	sum, err := digest(ctx, file)
	if err != nil {
		return err
	}
	if sum != chunk.GetSha256() {
		_ = root.Remove(name)
		return status.Error(codes.FailedPrecondition, "artifact segments do not match the file's digest")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close artifact segment: %w", err)
	}
	info, err := root.Lstat(relPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("read artifact: %w", err)
	case !info.Mode().IsRegular():
		_ = root.Remove(name)
		return status.Error(codes.FailedPrecondition, "the artifact's path is not a regular file")
	default:
		same, err := sameArtifact(ctx, root, relPath, info, size, sum)
		if err != nil {
			return err
		}
		_ = root.Remove(name)
		if !same {
			return status.Error(codes.FailedPrecondition, "a different artifact is already committed at this path")
		}
		return nil
	}
	if err := root.MkdirAll(path.Dir(relPath), 0o750); err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	if err := root.Rename(name, relPath); err != nil {
		return fmt.Errorf("finalize artifact: %w", err)
	}
	return nil
}

func sameArtifact(ctx context.Context, root *os.Root, relPath string, info fs.FileInfo, size uint64, sum string) (bool, error) {
	if uint64(info.Size()) != size { // #nosec G115 -- a file's size is non-negative
		return false, nil
	}
	existing, err := root.Open(relPath)
	if err != nil {
		return false, fmt.Errorf("read artifact: %w", err)
	}
	defer func() { _ = existing.Close() }()
	held, err := digest(ctx, existing)
	if err != nil {
		return false, err
	}
	return held == sum, nil
}

func digest(ctx context.Context, file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("read artifact segment: %w", err)
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, &contextFile{ctx: ctx, file: file}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", status.FromContextError(ctxErr).Err()
		}
		return "", fmt.Errorf("read artifact segment: %w", err)
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// contextFile ends a read of a file with its context.
type contextFile struct {
	ctx  context.Context
	file *os.File
}

func (r *contextFile) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.file.Read(p)
}

// removeIfFinished removes the writer's directory once it holds no upload, and
// SegmentDir once that was the last.
func removeIfFinished(root *os.Root, dir string) {
	entries, err := fs.ReadDir(root.FS(), dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != segmentIdentityFile {
		return
	}
	if root.RemoveAll(dir) == nil {
		_ = root.Remove(SegmentDir)
	}
}
