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
	mu        sync.RWMutex
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
	err := u.uploadDir(ctx, dir, attemptID)
	if !isRetryableStreamError(err) {
		return err
	}

	retryCtx, cancel := context.WithTimeout(ctx, finalDeliveryRetryTimeout)
	defer cancel()
	return backoff.Retry(retryCtx, func(ctx context.Context) error {
		return u.uploadDir(ctx, dir, attemptID)
	}, finalDeliveryRetryPolicy(), isRetryableStreamError)
}

func (u *ArtifactUploader) uploadDir(ctx context.Context, dir, attemptID string) error {
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
	limit := u.segmentBytes()
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
				return u.uploadSegmented(ctx, path, relPath, attemptID, limit)
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
func (u *ArtifactUploader) segmentBytes() int64 {
	if client, ok := u.client.(interface{ ArtifactSegmentBytes() int64 }); ok {
		return client.ArtifactSegmentBytes()
	}
	return 0
}

// uploadSegmented sends a file that one stream cannot carry. Each stream must
// be acknowledged exactly before the next: the final chunk is sent only to a hub
// that has said it holds every byte, so a hub that does not know this form
// commits nothing. Any failure starts the file again from its first byte, and
// the hub keeps what it already holds by comparing it. A file changed during
// the upload fails its digest.
func (u *ArtifactUploader) uploadSegmented(ctx context.Context, path, relPath, attemptID string, limit int64) error {
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
	// acknowledged ends one stream and checks the hub holds exactly offset.
	acknowledged := func(stream coordinatorv1.CoordinatorService_StreamArtifactsClient, offset uint64) error {
		resp, err := stream.CloseAndRecv()
		if err != nil {
			return fmt.Errorf("finalize artifact segment: %w", err)
		}
		if !resp.HasCommittedOffset() {
			return fmt.Errorf("upload artifact %s: this hub does not accept segmented uploads", relPath)
		}
		if resp.GetCommittedOffset() != offset {
			return fmt.Errorf("upload artifact %s: the hub holds %d of %d bytes", relPath, resp.GetCommittedOffset(), offset)
		}
		return nil
	}

	sum := sha256.New()
	buf := make([]byte, maxChunkSize)
	offset, seq := uint64(0), uint64(0)
	for atEnd := false; !atEnd; {
		var stream coordinatorv1.CoordinatorService_StreamArtifactsClient
		for sent := int64(0); sent < limit && !atEnd; {
			n, readErr := file.Read(buf[:min(int64(len(buf)), limit-sent)])
			if n > 0 {
				if stream == nil {
					if stream, err = u.openStream(ctx); err != nil {
						return err
					}
				}
				seq++
				chunk := newChunk(offset)
				chunk.Sequence = seq
				chunk.Data = append([]byte(nil), buf[:n]...)
				if err := stream.Send(chunk); err != nil && !errors.Is(err, io.EOF) {
					return fmt.Errorf("send artifact segment: %w", err)
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
				return fmt.Errorf("read artifact %s: %w", path, readErr)
			}
		}
		if stream != nil {
			if err := acknowledged(stream, offset); err != nil {
				return err
			}
		}
	}

	stream, err := u.openStream(ctx)
	if err != nil {
		return err
	}
	final := newChunk(offset)
	final.Sequence = seq + 1
	final.IsFinal = true
	final.TotalSize = offset
	final.Sha256 = hex.EncodeToString(sum.Sum(nil))
	if err := stream.Send(final); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("send artifact final marker: %w", err)
	}
	return acknowledged(stream, offset)
}
