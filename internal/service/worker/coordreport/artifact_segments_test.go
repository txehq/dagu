// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordreport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/serviceregistry"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// segmentHub stands in for the hub, one stream at a time.
type segmentHub struct {
	coordinator.Client
	limit     int64
	knowsThem bool // a hub that answers with committed_offset
	held      bytes.Buffer
	streams   [][]*coordinatorv1.ArtifactChunk
	failClose map[int]error // by stream index, once
	loseAck   map[int]bool  // takes the stream, then loses its reply
	wrongAck  bool
	commits   int
	sawFinal  bool
}

func (h *segmentHub) ArtifactSegmentBytes() int64 { return h.limit }

func (h *segmentHub) StreamArtifactsTo(ctx context.Context, _ serviceregistry.HostInfo) (coordinatorv1.CoordinatorService_StreamArtifactsClient, error) {
	return h.StreamArtifacts(ctx)
}

func (h *segmentHub) StreamArtifacts(context.Context) (coordinatorv1.CoordinatorService_StreamArtifactsClient, error) {
	h.streams = append(h.streams, nil)
	return &segmentStream{hub: h, index: len(h.streams) - 1}, nil
}

type segmentStream struct {
	hub   *segmentHub
	index int
}

func (s *segmentStream) Send(chunk *coordinatorv1.ArtifactChunk) error {
	s.hub.streams[s.index] = append(s.hub.streams[s.index], chunk)
	return nil
}

func (s *segmentStream) CloseAndRecv() (*coordinatorv1.StreamArtifactsResponse, error) {
	if err, ok := s.hub.failClose[s.index]; ok {
		delete(s.hub.failClose, s.index)
		return nil, err
	}
	resp := &coordinatorv1.StreamArtifactsResponse{}
	for _, chunk := range s.hub.streams[s.index] {
		if chunk.GetByteOffset() == uint64(s.hub.held.Len()) && chunk.HasByteOffset() {
			s.hub.held.Write(chunk.Data)
		}
		if chunk.IsFinal {
			s.hub.sawFinal = true
			s.hub.commits++
		}
	}
	if s.hub.loseAck[s.index] {
		delete(s.hub.loseAck, s.index)
		return nil, status.Error(codes.Unavailable, "lost")
	}
	if s.hub.knowsThem {
		offset := uint64(s.hub.held.Len())
		if s.hub.wrongAck {
			offset--
		}
		resp.SetCommittedOffset(offset)
	}
	return resp, nil
}

func (s *segmentStream) Header() (metadata.MD, error) { return nil, nil }
func (s *segmentStream) Trailer() metadata.MD         { return nil }
func (s *segmentStream) CloseSend() error             { return nil }
func (s *segmentStream) Context() context.Context     { return context.Background() }
func (s *segmentStream) SendMsg(any) error            { return nil }
func (s *segmentStream) RecvMsg(any) error            { return nil }

func uploaderFor(hub *segmentHub) *ArtifactUploader {
	return NewArtifactUploader(hub, "worker-1", "run-1", "job", "attempt-1", ir.DAGRunRef{Name: "job", ID: "run-1"})
}

func dirWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	return dir
}

func TestALargeFileGoesInSegmentsAndCommitsLast(t *testing.T) {
	content := strings.Repeat("0123456789", 3) + "tail"
	hub := &segmentHub{limit: 10, knowsThem: true}
	require.NoError(t, uploaderFor(hub).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": content})))

	assert.Equal(t, content, hub.held.String())
	require.Len(t, hub.streams, 5, "four streams of data, then the final chunk alone")
	for _, stream := range hub.streams[:4] {
		for _, chunk := range stream {
			assert.True(t, chunk.HasByteOffset())
			assert.False(t, chunk.IsFinal)
		}
	}
	final := hub.streams[4]
	require.Len(t, final, 1)
	sum := sha256.Sum256([]byte(content))
	assert.True(t, final[0].IsFinal)
	assert.EqualValues(t, len(content), final[0].GetTotalSize())
	assert.Equal(t, hex.EncodeToString(sum[:]), final[0].GetSha256())
}

// A hub without this change keeps a stream's bytes only for that stream, so a
// final chunk on its own would commit an empty file. It must never get one.
func TestAHubThatDoesNotKnowSegmentsGetsNoFinalChunk(t *testing.T) {
	hub := &segmentHub{limit: 10, knowsThem: false}
	err := uploaderFor(hub).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": strings.Repeat("x", 25)}))
	require.ErrorContains(t, err, "does not accept segmented uploads")
	assert.Len(t, hub.streams, 1, "it stops at the first unacknowledged stream")
	assert.False(t, hub.sawFinal)
}

func TestAWrongAcknowledgmentStopsTheUpload(t *testing.T) {
	hub := &segmentHub{limit: 10, knowsThem: true, wrongAck: true}
	err := uploaderFor(hub).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": strings.Repeat("x", 25)}))
	require.Error(t, err)
	assert.False(t, hub.sawFinal)
}

// An empty file and a small one stay what they are on any hub.
func TestSmallFilesKeepTheFormEveryHubKnows(t *testing.T) {
	for name, content := range map[string]string{"empty": "", "small": "abc", "exact": "0123456789"} {
		t.Run(name, func(t *testing.T) {
			hub := &segmentHub{limit: 10, knowsThem: false}
			require.NoError(t, uploaderFor(hub).UploadDir(context.Background(), dirWith(t, map[string]string{"a.bin": content})))
			require.Len(t, hub.streams, 1)
			for _, chunk := range hub.streams[0] {
				assert.False(t, chunk.HasByteOffset())
			}
		})
	}
}

func TestAStreamRollsOverBetweenFiles(t *testing.T) {
	hub := &segmentHub{limit: 10, knowsThem: false}
	files := map[string]string{"a": "aaaaaaa", "b": "bbbbbbb", "c": "ccc"}
	require.NoError(t, uploaderFor(hub).UploadDir(context.Background(), dirWith(t, files)))
	assert.Len(t, hub.streams, 2)
}

func TestWithoutALimitNothingIsSegmented(t *testing.T) {
	hub := &segmentHub{}
	require.NoError(t, uploaderFor(hub).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": strings.Repeat("x", 1<<20)})))
	require.Len(t, hub.streams, 1)
	for _, chunk := range hub.streams[0] {
		assert.False(t, chunk.HasByteOffset())
	}
}

// The acknowledgment is lost after the hub took the segment: the whole upload
// runs again from the first byte, and the hub compares what it holds.
func TestALostAcknowledgmentStartsTheFileAgain(t *testing.T) {
	content := strings.Repeat("y", 25)
	hub := &segmentHub{limit: 10, knowsThem: true, failClose: map[int]error{1: status.Error(codes.Unavailable, "lost")}}
	require.NoError(t, uploaderFor(hub).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": content})))
	assert.True(t, hub.sawFinal)
	assert.Equal(t, 1, hub.commits)
	restarted := false
	for _, stream := range hub.streams[1:] {
		if len(stream) > 0 && stream[0].HasByteOffset() && stream[0].GetByteOffset() == 0 {
			restarted = true
		}
	}
	assert.True(t, restarted)
}

// The hub keeps two segments and the reply to the second is lost. The upload
// starts again at byte zero while the hub holds more than that, and it must
// finish, not stop at the first acknowledgment that runs ahead of it.
func TestAReplayBehindWhatTheHubHoldsFinishes(t *testing.T) {
	content := strings.Repeat("0123456789", 3)
	hub := &segmentHub{limit: 10, knowsThem: true, loseAck: map[int]bool{1: true}}
	require.NoError(t, uploaderFor(hub).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": content})))
	assert.Equal(t, content, hub.held.String())
	assert.Equal(t, 1, hub.commits)
}
