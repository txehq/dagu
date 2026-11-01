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
	"sync/atomic"
	"testing"
	"time"

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
	committed string // what the hub made of the upload; it holds no segment then
	streams   [][]*coordinatorv1.ArtifactChunk
	failClose map[int]error // by stream index, once
	loseAck   map[int]bool  // takes the stream, then loses its reply
	wrongAck  bool
	commits   int
	sawFinal  bool
	finished  bool   // this stream carried the final chunk
	acked     uint64 // what the commit acknowledges
	claimHeld uint64 // an offset to report whatever is held
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
			if s.hub.held.Len() > 0 {
				s.hub.committed = s.hub.held.String()
				s.hub.acked = uint64(s.hub.held.Len())
				s.hub.held.Reset()
			}
			s.hub.finished = true
		}
	}
	if s.hub.loseAck[s.index] {
		delete(s.hub.loseAck, s.index)
		return nil, status.Error(codes.Unavailable, "lost")
	}
	if s.hub.knowsThem {
		offset := uint64(s.hub.held.Len())
		if s.hub.finished {
			offset = s.hub.acked
			s.hub.finished = false
		}
		if s.hub.wrongAck && offset > 0 {
			offset--
		}
		if s.hub.claimHeld > 0 {
			offset = s.hub.claimHeld
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

	assert.Equal(t, content, hub.committed)
	require.Len(t, hub.streams, 6, "the question, four streams of data, then the final chunk alone")
	require.Len(t, hub.streams[0], 1)
	assert.Empty(t, hub.streams[0][0].Data, "the question carries nothing")
	for _, stream := range hub.streams[:5] {
		for _, chunk := range stream {
			assert.True(t, chunk.HasByteOffset())
			assert.False(t, chunk.IsFinal)
		}
	}
	final := hub.streams[5]
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

func sentBytes(hub *segmentHub) int {
	total := 0
	for _, stream := range hub.streams {
		for _, chunk := range stream {
			total += len(chunk.Data)
		}
	}
	return total
}

// The acknowledgment is lost after the hub took the segment: the upload asks the
// hub where it is and goes on from there, sending nothing twice.
func TestALostAcknowledgmentGoesOnFromTheHub(t *testing.T) {
	content := strings.Repeat("y", 25)
	hub := &segmentHub{limit: 10, knowsThem: true, loseAck: map[int]bool{1: true}}
	require.NoError(t, uploaderFor(hub).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": content})))
	assert.Equal(t, content, hub.committed)
	assert.Equal(t, 1, hub.commits)
	assert.Equal(t, len(content), sentBytes(hub), "no byte the hub held went again")
}

// The digest covers bytes that were not sent again.
func TestAResumedFilesDigestIsTheWholeFiles(t *testing.T) {
	content := "0123456789abcdefghijklmno"
	hub := &segmentHub{limit: 10, knowsThem: true, loseAck: map[int]bool{1: true}}
	require.NoError(t, uploaderFor(hub).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": content})))
	last := hub.streams[len(hub.streams)-1]
	require.Len(t, last, 1)
	sum := sha256.Sum256([]byte(content))
	assert.Equal(t, hex.EncodeToString(sum[:]), last[0].GetSha256())
}

// The final acknowledgment is lost: the hub has committed and holds no segment.
// The final chunk alone settles it, and the file does not cross the link again.
func TestALostFinalAcknowledgmentDoesNotSendTheFileAgain(t *testing.T) {
	content := strings.Repeat("z", 25)
	// Streams: question, three of data, final (lost), question, final.
	hub := &segmentHub{limit: 10, knowsThem: true, loseAck: map[int]bool{4: true}}
	require.NoError(t, uploaderFor(hub).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": content})))
	assert.Equal(t, content, hub.committed)
	assert.Equal(t, len(content), sentBytes(hub))
	assert.Equal(t, 2, hub.commits, "the final chunk went twice, and only it")
}

func TestAHubClaimingMoreThanTheFileStopsTheUpload(t *testing.T) {
	hub := &segmentHub{limit: 10, knowsThem: true, claimHeld: 1 << 40}
	err := uploaderFor(hub).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": strings.Repeat("x", 25)}))
	require.ErrorContains(t, err, "bytes of a 25 byte file")
	assert.False(t, hub.sawFinal)
}

// A retry of the directory does not send a file the hub has acknowledged.
func TestACommittedFileIsNotSentAgainOnARetry(t *testing.T) {
	files := map[string]string{"a.bin": strings.Repeat("a", 25), "b.bin": strings.Repeat("b", 25)}
	// a.bin: question, three of data, final. b.bin: question, then lost.
	hub := &segmentHub{limit: 10, knowsThem: true, loseAck: map[int]bool{5: true}}
	require.NoError(t, uploaderFor(hub).UploadDir(context.Background(), dirWith(t, files)))
	assert.Equal(t, 50, sentBytes(hub))
}

// slowHub takes one chunk a stream and loses every reply, so all it can say is
// where it is when asked, as a link that cuts each stream does.
type slowHub struct {
	segmentHub
	pause  time.Duration
	refuse bool // the hub takes nothing
	sent   atomic.Int64
}

func (h *slowHub) StreamArtifacts(context.Context) (coordinatorv1.CoordinatorService_StreamArtifactsClient, error) {
	return &slowStream{hub: h}, nil
}

func (h *slowHub) StreamArtifactsTo(ctx context.Context, _ serviceregistry.HostInfo) (coordinatorv1.CoordinatorService_StreamArtifactsClient, error) {
	return h.StreamArtifacts(ctx)
}

type slowStream struct {
	segmentStream
	hub    *slowHub
	asking bool
	final  bool
	cut    bool
}

func (s *slowStream) Send(chunk *coordinatorv1.ArtifactChunk) error {
	s.hub.sent.Add(int64(len(chunk.Data)))
	switch {
	case chunk.IsFinal:
		s.final = true
	case len(chunk.Data) == 0:
		s.asking = true
	case !s.hub.refuse && chunk.GetByteOffset() == uint64(s.hub.held.Len()):
		s.hub.held.Write(chunk.Data)
		s.cut = true
	default:
		s.cut = true
	}
	return nil
}

func (s *slowStream) CloseAndRecv() (*coordinatorv1.StreamArtifactsResponse, error) {
	time.Sleep(s.hub.pause)
	if s.cut {
		return nil, status.Error(codes.DeadlineExceeded, "cut")
	}
	resp := &coordinatorv1.StreamArtifactsResponse{}
	resp.SetCommittedOffset(uint64(s.hub.held.Len()))
	return resp, nil
}

func stalledUploader(hub *slowHub, window time.Duration) *ArtifactUploader {
	uploader := NewArtifactUploader(hub, "worker-1", "run-1", "job", "attempt-1", ir.DAGRunRef{Name: "job", ID: "run-1"})
	uploader.retryWindow = window
	return uploader
}

// Each stream is cut, and each moves the hub. The whole upload takes many
// windows, and no one window passes without something new.
func TestAnUploadLongerThanItsWindowFinishesWhileItMoves(t *testing.T) {
	const chunks = 9
	content := strings.Repeat("c", chunks*MaxChunkSize+1)
	hub := &slowHub{segmentHub: segmentHub{limit: MaxChunkSize, knowsThem: true}, pause: 40 * time.Millisecond}
	start := time.Now()
	// The window stays well above the retry backoff's 2 s and its jitter, as 3
	// minutes does.
	const window = 4 * time.Second
	require.NoError(t, stalledUploader(hub, window).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": content})))
	assert.Greater(t, time.Since(start), window, "longer than the window")
	assert.Equal(t, content, hub.held.String())
}

// The hub answers, and answers the same: repeated acknowledgments and locally
// sent bytes move nothing, and the window ends it.
func TestAnUploadThatDoesNotMoveEndsWithinItsWindow(t *testing.T) {
	hub := &slowHub{segmentHub: segmentHub{limit: MaxChunkSize, knowsThem: true}, pause: time.Millisecond, refuse: true}
	start := time.Now()
	err := stalledUploader(hub, 300*time.Millisecond).UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": strings.Repeat("c", 3*MaxChunkSize)}))
	require.ErrorIs(t, err, errUploadStalled)
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.Positive(t, hub.sent.Load(), "it did send")
}

func TestACancelledCallerStopsAMovingUpload(t *testing.T) {
	hub := &slowHub{segmentHub: segmentHub{limit: MaxChunkSize, knowsThem: true}, pause: 20 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := stalledUploader(hub, time.Minute).UploadDir(ctx, dirWith(t, map[string]string{"big.bin": strings.Repeat("c", 200*MaxChunkSize)}))
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second, "the caller ends it, whatever the window")
}

func TestAWindowCountsOnlyAHigherOffsetOrANewFile(t *testing.T) {
	run := newDirUpload()
	moved := 0
	run.progressed = func() { moved++ }
	run.acknowledged("a", 0)
	assert.Zero(t, moved, "an answer of nothing")
	run.acknowledged("a", 10)
	run.acknowledged("a", 10)
	run.acknowledged("a", 5)
	assert.Equal(t, 1, moved, "repeating or falling back is not progress")
	run.finished("a")
	run.finished("a")
	assert.Equal(t, 2, moved, "a file is finished once")
}

func TestOnlyAClientThatSendsSegmentsBoundsItsOwnFinalize(t *testing.T) {
	assert.True(t, uploaderFor(&segmentHub{limit: 10}).BoundsItsOwnFinalize())
	assert.False(t, uploaderFor(&segmentHub{}).BoundsItsOwnFinalize(), "gRPC keeps the fixed time")
}

// The window runs from the start: a hub that never answers the first question
// ends the upload, with no failure to start a retry.
func TestTheWindowCoversTheFirstCall(t *testing.T) {
	uploader := NewArtifactUploader(&silentHub{segmentHub: segmentHub{limit: 10}}, "worker-1", "run-1", "job", "attempt-1", ir.DAGRunRef{Name: "job", ID: "run-1"})
	uploader.retryWindow = 150 * time.Millisecond
	start := time.Now()
	err := uploader.UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": strings.Repeat("x", 25)}))
	require.ErrorIs(t, err, errUploadStalled)
	assert.Less(t, time.Since(start), 5*time.Second)
}

type silentHub struct {
	segmentHub
}

func (*silentHub) StreamArtifacts(ctx context.Context) (coordinatorv1.CoordinatorService_StreamArtifactsClient, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (h *silentHub) StreamArtifactsTo(ctx context.Context, _ serviceregistry.HostInfo) (coordinatorv1.CoordinatorService_StreamArtifactsClient, error) {
	return h.StreamArtifacts(ctx)
}

// With no segmented file the window is what it always was.
func TestAnUnsegmentedUploadKeepsItsFixedWindow(t *testing.T) {
	hub := &failingStreamHub{}
	uploader := NewArtifactUploader(hub, "worker-1", "run-1", "job", "attempt-1", ir.DAGRunRef{Name: "job", ID: "run-1"})
	uploader.retryWindow = 150 * time.Millisecond
	err := uploader.UploadDir(context.Background(), dirWith(t, map[string]string{"small.bin": "abc"}))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.NotErrorIs(t, err, errUploadStalled)
}

type failingStreamHub struct {
	coordinator.Client
}

func (*failingStreamHub) StreamArtifacts(context.Context) (coordinatorv1.CoordinatorService_StreamArtifactsClient, error) {
	return nil, status.Error(codes.Unavailable, "down")
}

func TestAStreamEndsAtItsTimeAsWellAsItsSize(t *testing.T) {
	content := strings.Repeat("t", 40)
	hub := &timedHub{segmentHub: segmentHub{limit: 1 << 20, knowsThem: true}, streamTime: time.Nanosecond}
	uploader := NewArtifactUploader(hub, "worker-1", "run-1", "job", "attempt-1", ir.DAGRunRef{Name: "job", ID: "run-1"})
	require.NoError(t, uploader.UploadDir(context.Background(), dirWith(t, map[string]string{"big.bin": content + strings.Repeat("t", 1<<21)})))
	assert.Greater(t, len(hub.streams), 3, "more streams than its size alone would make")
}

type timedHub struct {
	segmentHub
	streamTime time.Duration
}

func (h *timedHub) ArtifactStreamTime() time.Duration { return h.streamTime }
