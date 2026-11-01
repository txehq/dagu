// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/dagucloud/dagu/v2/internal/ir"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

type segmentFixture struct {
	t          *testing.T
	archiveDir string
	store      *mockDAGRunStore
	validate   func(context.Context, attemptIdentity) error
	mu         sync.Mutex
}

func newSegmentFixture(t *testing.T) *segmentFixture {
	t.Helper()
	store := newMockDAGRunStore()
	archiveDir := t.TempDir()
	store.addAttempt(ir.DAGRunRef{Name: "job", ID: "run-1"}, &ir.DAGRunStatus{
		Name: "job", DAGRunID: "run-1", AttemptID: "attempt-1", ArchiveDir: archiveDir,
	})
	return &segmentFixture{t: t, archiveDir: archiveDir, store: store,
		validate: func(context.Context, attemptIdentity) error { return nil }}
}

// handler is a new one each time: nothing but the disk outlives a stream, as
// nothing but the disk outlives a hub restart.
func (f *segmentFixture) handler() *artifactHandler {
	h := newArtifactHandler(f.store.repository)
	h.attemptValidator = func(ctx context.Context, id attemptIdentity) error { return f.validate(ctx, id) }
	h.lockAttempt = func(ir.DAGRunRef) func() {
		f.mu.Lock()
		return f.mu.Unlock
	}
	return h
}

func (f *segmentFixture) stream(chunks ...*coordinatorv1.ArtifactChunk) (*coordinatorv1.StreamArtifactsResponse, error) {
	stream := &mockStreamArtifactsServer{ctx: context.Background(), chunks: chunks}
	err := f.handler().handleStream(stream)
	return stream.response, err
}

func segmentChunk(marker, name string, offset uint64, data string) *coordinatorv1.ArtifactChunk {
	c := &coordinatorv1.ArtifactChunk{
		WorkerId: "worker-1", DagName: "job", DagRunId: "run-1", AttemptId: "attempt-1",
		AttemptKey:      ir.GenerateAttemptKey("job", "run-1", "job", "run-1", "attempt-1"),
		ExecutionMarker: marker, RelativePath: name, Data: []byte(data),
	}
	c.SetByteOffset(offset)
	return c
}

func finalChunk(marker, name, content string) *coordinatorv1.ArtifactChunk {
	c := segmentChunk(marker, name, uint64(len(content)), "")
	c.IsFinal = true
	c.TotalSize = uint64(len(content))
	sum := sha256.Sum256([]byte(content))
	c.Sha256 = hex.EncodeToString(sum[:])
	return c
}

func (f *segmentFixture) upload(marker, name, content string) error {
	half := len(content) / 2
	if _, err := f.stream(segmentChunk(marker, name, 0, content[:half])); err != nil {
		return err
	}
	if _, err := f.stream(segmentChunk(marker, name, uint64(half), content[half:])); err != nil {
		return err
	}
	_, err := f.stream(finalChunk(marker, name, content))
	return err
}

func (f *segmentFixture) read(name string) string {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.archiveDir, name))
	require.NoError(f.t, err)
	return string(data)
}

func (f *segmentFixture) files() []string {
	f.t.Helper()
	var found []string
	require.NoError(f.t, filepath.WalkDir(f.archiveDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(f.archiveDir, path)
			found = append(found, filepath.ToSlash(rel))
		}
		return err
	}))
	return found
}

func TestSegmentedUploadCommitsOnceAcrossStreams(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)

	resp, err := f.stream(segmentChunk("m1", "out/report.csv", 0, "hello "))
	require.NoError(t, err)
	assert.True(t, resp.HasCommittedOffset())
	assert.EqualValues(t, 6, resp.GetCommittedOffset())
	_, statErr := os.Stat(filepath.Join(f.archiveDir, "out/report.csv"))
	assert.ErrorIs(t, statErr, os.ErrNotExist, "nothing is visible before the final chunk")

	resp, err = f.stream(segmentChunk("m1", "out/report.csv", 6, "world"))
	require.NoError(t, err)
	assert.EqualValues(t, 11, resp.GetCommittedOffset())

	_, err = f.stream(finalChunk("m1", "out/report.csv", "hello world"))
	require.NoError(t, err)
	assert.Equal(t, "hello world", f.read("out/report.csv"))
	assert.Equal(t, []string{"out/report.csv"}, f.files(), "no segment is left behind")
}

// What every existing worker sends: no offset, and no offset in the reply.
func TestAnUploadWithoutOffsetsIsUnchanged(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	resp, err := f.stream(
		&coordinatorv1.ArtifactChunk{WorkerId: "worker-1", DagName: "job", DagRunId: "run-1", AttemptId: "attempt-1", RelativePath: "a.txt", Data: []byte("x")},
		&coordinatorv1.ArtifactChunk{WorkerId: "worker-1", DagName: "job", DagRunId: "run-1", AttemptId: "attempt-1", RelativePath: "a.txt", IsFinal: true},
	)
	require.NoError(t, err)
	assert.False(t, resp.HasCommittedOffset())
	assert.Equal(t, "x", f.read("a.txt"))
}

func TestARepeatedSegmentIsANoOpAndAConflictIsRefused(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	_, err := f.stream(segmentChunk("m1", "a.bin", 0, "abcdef"))
	require.NoError(t, err)

	resp, err := f.stream(segmentChunk("m1", "a.bin", 0, "abcdef"))
	require.NoError(t, err, "a lost acknowledgment repeats the segment")
	assert.EqualValues(t, 6, resp.GetCommittedOffset())

	resp, err = f.stream(segmentChunk("m1", "a.bin", 3, "defghi"))
	require.NoError(t, err, "a partly repeated segment adds only what is new")
	assert.EqualValues(t, 9, resp.GetCommittedOffset())

	_, err = f.stream(segmentChunk("m1", "a.bin", 0, "XXXXXX"))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	_, err = f.stream(segmentChunk("m1", "a.bin", 100, "z"))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "out of order")

	_, err = f.stream(finalChunk("m1", "a.bin", "abcdefghi"))
	require.NoError(t, err)
	assert.Equal(t, "abcdefghi", f.read("a.bin"))
}

func TestABadFinalLeavesWhatIsCommitted(t *testing.T) {
	t.Parallel()
	for name, spoil := range map[string]func(*coordinatorv1.ArtifactChunk){
		"digest": func(c *coordinatorv1.ArtifactChunk) { c.Sha256 = strings.Repeat("0", 64) },
		"size":   func(c *coordinatorv1.ArtifactChunk) { c.TotalSize++ },
		"none":   func(c *coordinatorv1.ArtifactChunk) { c.Sha256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newSegmentFixture(t)
			require.NoError(t, f.upload("m1", "a.bin", "committed!"))
			_, err := f.stream(segmentChunk("m1", "a.bin", 0, "second ver"))
			require.NoError(t, err)
			final := finalChunk("m1", "a.bin", "second ver")
			spoil(final)
			_, err = f.stream(final)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.Equal(t, "committed!", f.read("a.bin"))
		})
	}
}

func TestALostFinalAcknowledgmentRepeatsWithoutHarm(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	require.NoError(t, f.upload("m1", "a.bin", "the result"))
	before, err := os.Stat(filepath.Join(f.archiveDir, "a.bin"))
	require.NoError(t, err)

	require.NoError(t, f.upload("m1", "a.bin", "the result"), "the worker starts the file again")
	after, err := os.Stat(filepath.Join(f.archiveDir, "a.bin"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(before, after), "the committed file was not replaced")
	assert.Equal(t, []string{"a.bin"}, f.files())

	err = f.upload("m1", "a.bin", "other data")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, "the result", f.read("a.bin"), "another result is never replaced")
}

func TestARefusedAttemptChangesNothing(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	f.validate = func(context.Context, attemptIdentity) error {
		return status.Error(codes.FailedPrecondition, "stale attempt")
	}
	_, err := f.stream(segmentChunk("m1", "a.bin", 0, "data"))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Empty(t, f.files())
	entries, err := os.ReadDir(f.archiveDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "not even a directory")
}

func TestAWriteIsCheckedOnEverySegment(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	_, err := f.stream(segmentChunk("m1", "a.bin", 0, "abc"))
	require.NoError(t, err)
	f.validate = func(context.Context, attemptIdentity) error {
		return status.Error(codes.FailedPrecondition, "revoked")
	}
	_, err = f.stream(finalChunk("m1", "a.bin", "abc"))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, statErr := os.Stat(filepath.Join(f.archiveDir, "a.bin"))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestOneExecutionNeverSeesAnothersBytes(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	_, err := f.stream(segmentChunk("m1", "a.bin", 0, "from execution one"))
	require.NoError(t, err)
	resp, err := f.stream(segmentChunk("m2", "a.bin", 0, "two"))
	require.NoError(t, err)
	assert.EqualValues(t, 3, resp.GetCommittedOffset())
}

func TestAWriterIsBoundToEveryPartOfItsIdentity(t *testing.T) {
	t.Parallel()
	base := segmentWriter{
		AttemptKey: "k", WorkerID: "w", DAGRun: "job", DAGRunID: "r", Root: "job", RootID: "r",
		AttemptID: "a", ExecutionMarker: "m", Machine: "mch", Owner: "own",
	}
	want, err := base.directory()
	require.NoError(t, err)
	for name, change := range map[string]func(*segmentWriter){
		"key":     func(w *segmentWriter) { w.AttemptKey = "x" },
		"worker":  func(w *segmentWriter) { w.WorkerID = "x" },
		"job":     func(w *segmentWriter) { w.DAGRun = "x" },
		"run":     func(w *segmentWriter) { w.DAGRunID = "x" },
		"attempt": func(w *segmentWriter) { w.AttemptID = "x" },
		"marker":  func(w *segmentWriter) { w.ExecutionMarker = "x" },
		"machine": func(w *segmentWriter) { w.Machine = "x" },
		"owner":   func(w *segmentWriter) { w.Owner = "x" },
	} {
		w := base
		change(&w)
		got, err := w.directory()
		require.NoError(t, err)
		assert.NotEqual(t, want, got, name)
	}
}

func TestAPathOutsideTheArchiveOrReservedIsRefused(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	for _, name := range []string{"../escape", "a/../../escape", ir.ArtifactSegmentDir + "/x", ir.ArtifactSegmentDir} {
		_, err := f.stream(segmentChunk("m1", name, 0, "data"))
		assert.Equal(t, codes.InvalidArgument, status.Code(err), name)
	}
	assert.Empty(t, f.files())
}

func TestLinksAreNotFollowed(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	f := newSegmentFixture(t)
	outside := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(outside, []byte("untouched"), 0o600))

	t.Run("the artifact's own path", func(t *testing.T) {
		require.NoError(t, os.Symlink(outside, filepath.Join(f.archiveDir, "linked")))
		err := f.upload("m1", "linked", "payload!")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	})
	t.Run("a directory leading out", func(t *testing.T) {
		require.NoError(t, os.Symlink(filepath.Dir(outside), filepath.Join(f.archiveDir, "linkdir")))
		_, err := f.stream(segmentChunk("m1", "linkdir/x", 0, "payload!"))
		require.NoError(t, err, "only the target matters until the final chunk")
		_, err = f.stream(finalChunk("m1", "linkdir/x", "payload!"))
		assert.Error(t, err)
		_, statErr := os.Stat(filepath.Join(filepath.Dir(outside), "x"))
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})
	t.Run("the segment file", func(t *testing.T) {
		_, err := f.stream(segmentChunk("m3", "b.bin", 0, "abc"))
		require.NoError(t, err)
		var segment string
		for _, name := range f.files() {
			if strings.HasPrefix(name, ir.ArtifactSegmentDir) && !strings.HasSuffix(name, segmentIdentityFile) {
				if data, err := os.ReadFile(filepath.Join(f.archiveDir, name)); err == nil && string(data) == "abc" {
					segment = name
				}
			}
		}
		require.NotEmpty(t, segment)
		full := filepath.Join(f.archiveDir, segment)
		require.NoError(t, os.Remove(full))
		require.NoError(t, os.Symlink(outside, full))
		_, err = f.stream(segmentChunk("m3", "b.bin", 0, "abc"))
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	})
	t.Run("the segment directory leading out", func(t *testing.T) {
		g := newSegmentFixture(t)
		require.NoError(t, os.Symlink(filepath.Dir(outside), filepath.Join(g.archiveDir, ir.ArtifactSegmentDir)))
		_, err := g.stream(segmentChunk("m1", "a.bin", 0, "payload!"))
		assert.Error(t, err)
	})
	data, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, "untouched", string(data))
}

// Only the fence proves an upload dead. A stale execution's segments go when a
// new upload starts; an active one's stay, and so does anything unreadable.
func TestOnlyProvenStaleSegmentsAreSwept(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	_, err := f.stream(segmentChunk("old", "a.bin", 0, "stale"))
	require.NoError(t, err)
	_, err = f.stream(segmentChunk("live", "b.bin", 0, "active"))
	require.NoError(t, err)
	unknown := filepath.Join(f.archiveDir, ir.ArtifactSegmentDir, "unknown")
	require.NoError(t, os.MkdirAll(unknown, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(unknown, "held"), []byte("?"), 0o640))

	f.validate = func(_ context.Context, id attemptIdentity) error {
		if id.executionMarker == "old" {
			return status.Error(codes.FailedPrecondition, "superseded")
		}
		return nil
	}
	_, err = f.stream(segmentChunk("new", "c.bin", 0, "new"))
	require.NoError(t, err)

	var held []string
	for _, name := range f.files() {
		data, err := os.ReadFile(filepath.Join(f.archiveDir, name))
		require.NoError(t, err)
		held = append(held, string(data))
	}
	assert.NotContains(t, held, "stale")
	assert.Contains(t, held, "active")
	assert.Contains(t, held, "new")
	assert.Contains(t, held, "?")
}

func TestConcurrentUploadsOfOneFileStayWhole(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	content := strings.Repeat("abcdefgh", 64)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- f.upload("m1", "a.bin", content) })
	}
	wg.Wait()
	close(errs)
	var succeeded int
	for err := range errs {
		if err == nil {
			succeeded++
		}
	}
	assert.Positive(t, succeeded)
	assert.Equal(t, content, f.read("a.bin"))
}

func TestAnUploadSurvivesAHubRestart(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	_, err := f.stream(segmentChunk("m1", "a.bin", 0, "before "))
	require.NoError(t, err)
	// stream() builds a new handler each time, so only the disk carries over.
	_, err = f.stream(segmentChunk("m1", "a.bin", 7, "after"))
	require.NoError(t, err)
	_, err = f.stream(finalChunk("m1", "a.bin", "before after"))
	require.NoError(t, err)
	assert.Equal(t, "before after", f.read("a.bin"))
}

// Zero and absent differ on the wire, which is what tells a hub that knows
// segments from one that does not, an empty first segment included.
func TestCommittedOffsetIsPresenceNotZero(t *testing.T) {
	t.Parallel()
	wire := func(resp *coordinatorv1.StreamArtifactsResponse) *coordinatorv1.StreamArtifactsResponse {
		data, err := proto.Marshal(resp)
		require.NoError(t, err)
		out := &coordinatorv1.StreamArtifactsResponse{}
		require.NoError(t, proto.Unmarshal(data, out))
		return out
	}
	assert.False(t, wire(&coordinatorv1.StreamArtifactsResponse{}).HasCommittedOffset())
	zero := &coordinatorv1.StreamArtifactsResponse{}
	zero.SetCommittedOffset(0)
	assert.True(t, wire(zero).HasCommittedOffset())
}

// What a hub without this change does with a segmented stream: it does not see
// the offset, keeps the bytes for that stream only, and answers no offset.
func TestAHubThatIgnoresTheOffsetCommitsNothing(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	chunk := segmentChunk("m1", "a.bin", 0, "first segment")
	chunk.ClearByteOffset()
	resp, err := f.stream(chunk)
	require.NoError(t, err)
	assert.False(t, resp.HasCommittedOffset())
	assert.Empty(t, f.files())
}

// A stream outlives its first check: an attempt fenced between two chunks of
// one stream stops there.
func TestAFenceBetweenChunksOfOneStreamStopsTheWrite(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	var calls int
	f.validate = func(context.Context, attemptIdentity) error {
		calls++
		if calls > 2 { // the stream's own check and the first chunk's
			return status.Error(codes.FailedPrecondition, "fenced")
		}
		return nil
	}
	_, err := f.stream(segmentChunk("m1", "a.bin", 0, "first"), segmentChunk("m1", "a.bin", 5, "second"))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	for _, name := range f.files() {
		data, err := os.ReadFile(filepath.Join(f.archiveDir, name))
		require.NoError(t, err)
		assert.NotContains(t, string(data), "second")
	}
}

func TestAWrongDigestCommitsNothing(t *testing.T) {
	t.Parallel()
	f := newSegmentFixture(t)
	_, err := f.stream(segmentChunk("m1", "a.bin", 0, "content"))
	require.NoError(t, err)
	final := finalChunk("m1", "a.bin", "content")
	final.Sha256 = strings.Repeat("0", 64)
	_, err = f.stream(final)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, statErr := os.Stat(filepath.Join(f.archiveDir, "a.bin"))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

// On the private gRPC path nothing recovers a handler's panic, so an empty
// status from any caller would take the hub down.
func TestAnEmptyStatusIsRefusedNotAPanic(t *testing.T) {
	t.Parallel()
	store := newMockDAGRunStore()
	h := NewHandler(HandlerConfig{DAGRunRepository: store.repository})
	_, err := h.ReportStatus(context.Background(), &coordinatorv1.ReportStatusRequest{
		WorkerId: "worker-1", Status: &coordinatorv1.DAGRunStatusProto{},
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
}
