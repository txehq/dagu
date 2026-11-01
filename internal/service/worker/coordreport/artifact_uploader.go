// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package coordreport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/backoff"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/serviceregistry"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

var _ runtime.ArtifactFinalizer = (*ArtifactUploader)(nil)

// ArtifactUploader uploads DAG run artifacts from a worker to the coordinator.
type ArtifactUploader struct {
	client    coordinator.Client
	workerID  string
	dagRunID  string
	dagName   string
	attemptID string
	claimKey  string
	rootRef   ir.DAGRunRef
	owner     serviceregistry.HostInfo
	// retryWindow is how long retries go on with nothing new durable.
	retryWindow time.Duration
	mu          sync.RWMutex
	// executionMarker is the claimed task's execution marker.
	executionMarker string
}

// NewArtifactUploader creates a new ArtifactUploader.
func NewArtifactUploader(
	client coordinator.Client,
	workerID string,
	dagRunID string,
	dagName string,
	attemptID string,
	rootRef ir.DAGRunRef,
	owner ...serviceregistry.HostInfo,
) *ArtifactUploader {
	var target serviceregistry.HostInfo
	if len(owner) > 0 {
		target = owner[0]
	}
	return &ArtifactUploader{
		client:    client,
		workerID:  workerID,
		dagRunID:  dagRunID,
		dagName:   dagName,
		attemptID: attemptID,
		rootRef:   rootRef,
		owner:     target,

		retryWindow: finalDeliveryRetryTimeout,
	}
}

// SetAttemptID updates the attempt ID after the agent creates the attempt.
func (u *ArtifactUploader) SetAttemptID(attemptID string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.attemptID = attemptID
}

// SetClaimKey binds uploaded artifacts to the task claim that authorizes the run.
func (u *ArtifactUploader) SetClaimKey(claimKey string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.claimKey = claimKey
}

// SetExecutionMarker binds uploaded artifacts to one execution of the attempt,
// so the coordinator can refuse uploads of an earlier execution.
func (u *ArtifactUploader) SetExecutionMarker(marker string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.executionMarker = marker
}

func (u *ArtifactUploader) getExecutionMarker() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.executionMarker
}

// Finalize uploads artifacts for the finalized attempt before the terminal status is written.
func (u *ArtifactUploader) Finalize(ctx context.Context, attemptID, dir string) error {
	u.SetAttemptID(attemptID)
	return u.UploadDir(ctx, dir)
}

func (u *ArtifactUploader) getAttemptID() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.attemptID
}

func (u *ArtifactUploader) attemptKey(attemptID string) string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.claimKey != "" {
		return u.claimKey
	}
	root := u.rootRef
	if root.Zero() {
		root = ir.NewDAGRunRef(u.dagName, u.dagRunID)
	}
	return ir.GenerateAttemptKey(root.Name, root.ID, u.dagName, u.dagRunID, attemptID)
}

func (u *ArtifactUploader) openStream(ctx context.Context) (coordinatorv1.CoordinatorService_StreamArtifactsClient, error) {
	if u.owner.Host != "" {
		return u.client.StreamArtifactsTo(ctx, u.owner)
	}
	return u.client.StreamArtifacts(ctx)
}

// UploadDir uploads every regular file under dir while preserving relative paths.
func (u *ArtifactUploader) UploadDir(ctx context.Context, dir string) error {
	if dir == "" {
		return nil
	}

	attemptID := u.getAttemptID()
	run := newDirUpload()

	// One window covers everything, from before the directory is read. A
	// segmented file's upload ends after the window with nothing new durable on
	// the hub, not after the window: a long upload on a slow link outlives it,
	// moving. Only the hub's own word moves it: a higher offset than it has ever
	// reported, or a file committed. The caller's context, and the fences the hub
	// checks on every chunk, still end it at any time. An upload with no
	// segmented file keeps one fixed window.
	uploadCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stalled := time.AfterFunc(u.retryWindow, func() { cancel(errUploadStalled) })
	defer stalled.Stop()
	run.progressed = func() { stalled.Reset(u.retryWindow) }

	err := u.uploadDir(uploadCtx, dir, attemptID, run)
	if isRetryableStreamError(err) {
		err = backoff.Retry(uploadCtx, func(ctx context.Context) error {
			return u.uploadDir(ctx, dir, attemptID, run)
		}, finalDeliveryRetryPolicy(), isRetryableStreamError)
	}
	if !errors.Is(context.Cause(uploadCtx), errUploadStalled) {
		return err
	}
	if !run.segmented {
		return context.DeadlineExceeded
	}
	return fmt.Errorf("%w for %s", errUploadStalled, u.retryWindow)
}

// BoundsItsOwnFinalize says this uploader holds its finalization to the window
// above, so that the agent need not hold it to a fixed time. Only a client that
// sends segments does: anything else keeps the fixed time.
func (u *ArtifactUploader) BoundsItsOwnFinalize() bool { return SendsSegments(u.client) }

// SendsSegments says the client sends files larger than a stream in segments.
func SendsSegments(client coordinator.Client) bool { return segmentBytes(client) > 0 }

// errUploadStalled ends an upload whose retries moved nothing.
var errUploadStalled = errors.New("artifact upload: nothing new reached the hub")

// dirUpload is what one UploadDir knows across its retries.
type dirUpload struct {
	// segmented says a file went by segments.
	segmented bool
	// committed are the segmented files the hub has acknowledged whole.
	committed map[string]bool
	// finalSent are those whose final chunk went out, acknowledged or not.
	finalSent map[string]bool
	// durable is the most the hub has acknowledged of each file.
	durable map[string]uint64
	// progressed is called when more of a file is durable.
	progressed func()
}

func newDirUpload() *dirUpload {
	return &dirUpload{committed: map[string]bool{}, finalSent: map[string]bool{}, durable: map[string]uint64{}}
}

// acknowledged takes what the hub reports it holds of a file. Only a higher
// offset than it has ever reported is progress: a repeated acknowledgment, or an
// answer to asking, is not.
func (r *dirUpload) acknowledged(relPath string, offset uint64) {
	if offset <= r.durable[relPath] {
		return
	}
	r.durable[relPath] = offset
	r.moved()
}

// finished records the hub's acknowledgment of a whole file, once.
func (r *dirUpload) finished(relPath string) {
	if !r.committed[relPath] {
		r.committed[relPath] = true
		r.moved()
	}
}

func (r *dirUpload) moved() {
	if r.progressed != nil {
		r.progressed()
	}
}

func (u *ArtifactUploader) uploadDir(ctx context.Context, dir, attemptID string, run *dirUpload) error {
	seq := uint64(0)
	var stream coordinatorv1.CoordinatorService_StreamArtifactsClient
	defer func() {
		if stream != nil {
			_ = stream.CloseSend()
		}
	}()

	// finishStream ends the current stream and reads its reply.
	finishStream := func() error {
		if stream == nil {
			return nil
		}
		resp, err := stream.CloseAndRecv()
		stream = nil
		if err != nil {
			return fmt.Errorf("finalize artifact upload: %w", err)
		}
		if resp != nil && resp.Error != "" {
			return fmt.Errorf("artifact upload failed: %s", resp.Error)
		}
		return nil
	}
	limit := segmentBytes(u.client)
	var streamBytes int64

	sendChunk := func(chunk *coordinatorv1.ArtifactChunk) error {
		if stream == nil {
			var err error
			stream, err = u.openStream(ctx)
			if err != nil {
				return err
			}
		}
		err := stream.Send(chunk)
		if errors.Is(err, io.EOF) {
			if _, terminalErr := stream.CloseAndRecv(); terminalErr != nil {
				return terminalErr
			}
		}
		return err
	}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("resolve artifact relative path: %w", err)
		}
		relPath = filepath.ToSlash(relPath)

		if limit > 0 {
			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("read artifact %s: %w", path, err)
			}
			if info.Size() > limit {
				if err := finishStream(); err != nil {
					return err
				}
				if run.committed[relPath] {
					return nil
				}
				return u.uploadSegmented(ctx, path, relPath, attemptID, limit, run)
			}
			if streamBytes+info.Size() > limit {
				if err := finishStream(); err != nil {
					return err
				}
				streamBytes = 0
			}
			streamBytes += info.Size()
		}

		return func() error {
			file, err := os.Open(filepath.Clean(path))
			if err != nil {
				return fmt.Errorf("open artifact %s: %w", path, err)
			}
			defer func() { _ = file.Close() }()

			buf := make([]byte, maxChunkSize)
			for {
				n, readErr := file.Read(buf)
				if n > 0 {
					seq++
					chunk := &coordinatorv1.ArtifactChunk{
						WorkerId:           u.workerID,
						DagRunId:           u.dagRunID,
						DagName:            u.dagName,
						RelativePath:       relPath,
						Data:               append([]byte(nil), buf[:n]...),
						Sequence:           seq,
						RootDagRunName:     u.rootRef.Name,
						RootDagRunId:       u.rootRef.ID,
						AttemptId:          attemptID,
						OwnerCoordinatorId: u.owner.ID,
						AttemptKey:         u.attemptKey(attemptID),
						ExecutionMarker:    u.getExecutionMarker(),
					}
					if err := sendChunk(chunk); err != nil {
						return fmt.Errorf("send artifact chunk: %w", err)
					}
				}
				if readErr == nil {
					continue
				}
				if readErr != io.EOF {
					return fmt.Errorf("read artifact %s: %w", path, readErr)
				}
				break
			}

			seq++
			if err := sendChunk(&coordinatorv1.ArtifactChunk{
				WorkerId:           u.workerID,
				DagRunId:           u.dagRunID,
				DagName:            u.dagName,
				RelativePath:       relPath,
				IsFinal:            true,
				Sequence:           seq,
				RootDagRunName:     u.rootRef.Name,
				RootDagRunId:       u.rootRef.ID,
				AttemptId:          attemptID,
				OwnerCoordinatorId: u.owner.ID,
				AttemptKey:         u.attemptKey(attemptID),
				ExecutionMarker:    u.getExecutionMarker(),
			}); err != nil {
				return fmt.Errorf("send artifact final marker: %w", err)
			}

			return nil
		}()
	})
	if err != nil {
		return err
	}

	return finishStream()
}

// segmentBytes is the most one stream may carry, or 0 when a stream may carry
// anything, as on a gRPC connection.
func segmentBytes(client coordinator.Client) int64 {
	if client, ok := client.(interface{ ArtifactSegmentBytes() int64 }); ok {
		return client.ArtifactSegmentBytes()
	}
	return 0
}

// contextReader ends a long local read with its context, so that hashing what
// the hub already holds cannot outlast the upload's window.
type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}

// streamTime is how long one stream may stay open, or 0 when only its size
// bounds it.
func (u *ArtifactUploader) streamTime() time.Duration {
	if client, ok := u.client.(interface{ ArtifactStreamTime() time.Duration }); ok {
		return client.ArtifactStreamTime()
	}
	return 0
}

// uploadSegmented sends a file that one stream cannot carry. Each stream must
// be acknowledged before the next: the final chunk is sent only to a hub that
// has said it holds every byte, so a hub that does not know this form commits
// nothing. A stream ends at its size or its time, whichever comes first, so a
// link too slow to fill one in time still moves.
//
// It starts from what the hub holds, by asking: repeating a durable prefix on a
// link that cannot carry it past the stream limit never gets beyond it. The
// prefix is read here only for the digest, which settles the whole file, so a
// file changed during the upload still fails. What is durable moves by whole
// chunks, so a link that cannot carry one chunk within a stream's limit does not
// move, and the upload ends with errUploadStalled.
func (u *ArtifactUploader) uploadSegmented(ctx context.Context, path, relPath, attemptID string, limit int64, run *dirUpload) error {
	run.segmented = true
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("open artifact %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	newChunk := func(offset uint64) *coordinatorv1.ArtifactChunk {
		chunk := &coordinatorv1.ArtifactChunk{
			WorkerId: u.workerID, DagRunId: u.dagRunID, DagName: u.dagName, RelativePath: relPath,
			RootDagRunName: u.rootRef.Name, RootDagRunId: u.rootRef.ID, AttemptId: attemptID,
			OwnerCoordinatorId: u.owner.ID, AttemptKey: u.attemptKey(attemptID), ExecutionMarker: u.getExecutionMarker(),
		}
		chunk.SetByteOffset(offset)
		return chunk
	}
	// acknowledged ends one stream and returns what the hub holds.
	acknowledged := func(stream coordinatorv1.CoordinatorService_StreamArtifactsClient) (uint64, error) {
		resp, err := stream.CloseAndRecv()
		if err != nil {
			return 0, fmt.Errorf("finalize artifact segment: %w", err)
		}
		if !resp.HasCommittedOffset() {
			return 0, fmt.Errorf("upload artifact %s: this hub does not accept segmented uploads", relPath)
		}
		run.acknowledged(relPath, resp.GetCommittedOffset())
		return resp.GetCommittedOffset(), nil
	}
	// exactly ends one stream and checks the hub holds offset. Ahead is fine:
	// the final chunk's size and digest settle the whole file.
	exactly := func(stream coordinatorv1.CoordinatorService_StreamArtifactsClient, offset uint64) error {
		held, err := acknowledged(stream)
		if err != nil {
			return err
		}
		if held < offset {
			return fmt.Errorf("upload artifact %s: the hub holds %d of %d bytes", relPath, held, offset)
		}
		return nil
	}

	// An empty chunk passes the hub's fences as any other and answers its offset.
	stream, err := u.openStream(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(newChunk(0)); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("ask the hub's artifact offset: %w", err)
	}
	offset, err := acknowledged(stream)
	if err != nil {
		return err
	}

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("read artifact %s: %w", path, err)
	}
	if offset > uint64(info.Size()) { // #nosec G115 -- a file's size is non-negative
		return fmt.Errorf("upload artifact %s: the hub holds %d bytes of a %d byte file", relPath, offset, info.Size())
	}
	sum := sha256.New()
	source := &contextReader{ctx: ctx, source: file}
	if _, err := io.CopyN(sum, source, int64(offset)); err != nil { // #nosec G115 -- below the file's size
		return fmt.Errorf("read artifact %s: %w", path, err)
	}
	if offset == 0 && run.finalSent[relPath] {
		// The file was committed and only the acknowledgment was lost: the hub
		// holds no segment any more. Its final chunk alone settles it.
		written, err := io.Copy(sum, source)
		if err != nil {
			return fmt.Errorf("read artifact %s: %w", path, err)
		}
		offset = uint64(written) // #nosec G115 -- a size read from a file
	} else {
		if offset, err = u.sendSegments(ctx, file, path, limit, offset, sum, newChunk, exactly); err != nil {
			return err
		}
	}

	stream, err = u.openStream(ctx)
	if err != nil {
		return err
	}
	final := newChunk(offset)
	final.IsFinal = true
	final.TotalSize = offset
	final.Sha256 = hex.EncodeToString(sum.Sum(nil))
	run.finalSent[relPath] = true
	if err := stream.Send(final); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("send artifact final marker: %w", err)
	}
	if err := exactly(stream, offset); err != nil {
		return err
	}
	run.finished(relPath)
	return nil
}

// sendSegments sends the file from start, one acknowledged stream at a time,
// and returns how far it reached.
func (u *ArtifactUploader) sendSegments(
	ctx context.Context,
	file *os.File,
	path string,
	limit int64,
	start uint64,
	sum io.Writer,
	newChunk func(uint64) *coordinatorv1.ArtifactChunk,
	exactly func(coordinatorv1.CoordinatorService_StreamArtifactsClient, uint64) error,
) (uint64, error) {
	streamTime := u.streamTime()
	buf := make([]byte, maxChunkSize)
	offset, seq := start, uint64(0)
	for atEnd := false; !atEnd; {
		var stream coordinatorv1.CoordinatorService_StreamArtifactsClient
		var opened time.Time
		within := func() bool { return stream == nil || streamTime <= 0 || time.Since(opened) < streamTime }
		for sent := int64(0); sent < limit && !atEnd && within(); {
			n, readErr := file.Read(buf[:min(int64(len(buf)), limit-sent)])
			if n > 0 {
				if stream == nil {
					var err error
					if stream, err = u.openStream(ctx); err != nil {
						return 0, err
					}
					opened = time.Now()
				}
				seq++
				chunk := newChunk(offset)
				chunk.Sequence = seq
				chunk.Data = append([]byte(nil), buf[:n]...)
				if err := stream.Send(chunk); err != nil && !errors.Is(err, io.EOF) {
					return 0, fmt.Errorf("send artifact segment: %w", err)
				} else if err != nil {
					break // the reply says why
				}
				_, _ = sum.Write(buf[:n])
				sent += int64(n)
				offset += uint64(n) // #nosec G115 -- n is non-negative
			}
			if errors.Is(readErr, io.EOF) {
				atEnd = true
			} else if readErr != nil {
				if stream != nil {
					_ = stream.CloseSend()
				}
				return 0, fmt.Errorf("read artifact %s: %w", path, readErr)
			}
		}
		if stream != nil {
			if err := exactly(stream, offset); err != nil {
				return 0, err
			}
		}
	}
	return offset, nil
}
