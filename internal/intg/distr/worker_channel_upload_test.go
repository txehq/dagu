// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// uploadStream is one artifact stream as the hub saw it, decoded off the wire.
type uploadStream struct {
	Path     string // the file the stream's chunks belong to
	From, To uint64 // the byte offsets the stream's chunks covered
	Bytes    uint64
	Final    bool
	Held     int64 // what the hub held when the stream ended
	Acked    *uint64
	Took     time.Duration
	Lost     bool
	Refused  string // the code a stream ended with, if not a reply
}

// uploadTrace records the streams of an upload, and can lose a reply.
type uploadTrace struct {
	held func() int64
	// loseReply says which streams' acknowledgments never reach the worker.
	loseReply func(n int, stream uploadStream) bool
	// atFinal is told when the hub has answered a final chunk.
	atFinal func()

	mu      sync.Mutex
	streams []uploadStream
	lost    int
}

type frameReader struct {
	source  io.ReadCloser
	pending []byte
	stream  *uploadStream
	begun   bool
}

// Read passes the body through and decodes each Connect frame it completes.
func (r *frameReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.pending = append(r.pending, p[:n]...)
	for len(r.pending) >= 5 {
		size := int(binary.BigEndian.Uint32(r.pending[1:5]))
		if len(r.pending) < 5+size {
			break
		}
		chunk := &coordinatorv1.ArtifactChunk{}
		if r.pending[0] == 0 && proto.Unmarshal(r.pending[5:5+size], chunk) == nil && chunk.HasByteOffset() {
			if !r.begun {
				r.stream.From, r.stream.Path, r.begun = chunk.GetByteOffset(), chunk.RelativePath, true
			}
			r.stream.To = chunk.GetByteOffset() + uint64(len(chunk.Data))
			r.stream.Bytes += uint64(len(chunk.Data))
			r.stream.Final = r.stream.Final || chunk.IsFinal
		}
		r.pending = r.pending[5+size:]
	}
	return n, err
}

func (r *frameReader) Close() error { return r.source.Close() }

// replyRecorder holds the reply until it is known whether it is lost.
type replyRecorder struct {
	http.ResponseWriter
	body bytes.Buffer
	code int
}

func (w *replyRecorder) WriteHeader(code int) { w.code = code }

func (w *replyRecorder) Write(data []byte) (int, error) { return w.body.Write(data) }

func (w *replyRecorder) Flush() {}

func (w *replyRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (t *uploadTrace) serve(next http.Handler, w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/StreamArtifacts") {
		next.ServeHTTP(w, r)
		return
	}
	stream := uploadStream{}
	r.Body = &frameReader{source: r.Body, stream: &stream}
	reply := &replyRecorder{ResponseWriter: w, code: http.StatusOK}
	start := time.Now()
	next.ServeHTTP(reply, r)
	stream.Took = time.Since(start)
	if t.held != nil {
		stream.Held = t.held()
	}
	data := reply.body.Bytes()
	if len(data) >= 5 && data[0] == 0 {
		answer := &coordinatorv1.StreamArtifactsResponse{}
		if size := int(binary.BigEndian.Uint32(data[1:5])); len(data) >= 5+size && proto.Unmarshal(data[5:5+size], answer) == nil && answer.HasCommittedOffset() {
			acked := answer.GetCommittedOffset()
			stream.Acked = &acked
		}
	}
	stream.Refused = endOfStreamCode(data)
	if stream.Final && t.atFinal != nil {
		t.atFinal()
	}
	t.mu.Lock()
	t.streams = append(t.streams, stream)
	n := len(t.streams)
	lose := t.loseReply != nil && t.loseReply(n, stream)
	if lose {
		t.lost++
		t.streams[n-1].Lost = true
	}
	t.mu.Unlock()
	if lose {
		// The hub finished. The worker hears only that the connection went.
		panic(http.ErrAbortHandler)
	}
	w.WriteHeader(reply.code)
	_, _ = w.Write(data)
}

// endOfStreamCode reads a Connect stream's last frame for its error code.
func endOfStreamCode(data []byte) string {
	for len(data) >= 5 {
		size := int(binary.BigEndian.Uint32(data[1:5]))
		if len(data) < 5+size {
			return ""
		}
		if data[0]&2 != 0 {
			var end struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			_ = json.Unmarshal(data[5:5+size], &end)
			return end.Error.Code
		}
		data = data[5+size:]
	}
	return ""
}

func (t *uploadTrace) report(tb testing.TB) (streams int, sent uint64) {
	tb.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, s := range t.streams {
		acked := "none"
		if s.Acked != nil {
			acked = fmt.Sprint(*s.Acked)
		}
		tb.Logf("rig: stream %d: sent %d..%d (%d bytes) final=%v held=%d acked=%s lost=%v ended=%q took=%s", i+1, s.From, s.To, s.Bytes, s.Final, s.Held, acked, s.Lost, s.Refused, s.Took.Round(time.Millisecond))
		sent += s.Bytes
	}
	return len(t.streams), sent
}

// finals counts the final chunks the hub answered for each file.
func (t *uploadTrace) finals() map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	finals := map[string]int{}
	for _, s := range t.streams {
		if s.Final && !s.Lost {
			finals[s.Path]++
		}
	}
	return finals
}

// requireForwardOnly fails an upload that repeated more than the one cut chunk.
func (t *uploadTrace) requireForwardOnly(tb testing.TB) {
	tb.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()
	var reached uint64
	for i, s := range t.streams {
		if s.Bytes > 0 {
			require.GreaterOrEqual(tb, s.From, reached, "stream %d went back over what the hub held", i+1)
			reached = uint64(s.Held) // #nosec G115 -- a file's size
		}
	}
}

func heldSegments(artifactDir string) func() int64 {
	return func() int64 {
		var held int64
		_ = filepath.WalkDir(artifactDir, func(p string, d os.DirEntry, _ error) error {
			if d != nil && !d.IsDir() && strings.Contains(p, ir.ArtifactSegmentDir) && d.Name() != "identity.json" {
				if info, err := d.Info(); err == nil {
					held += info.Size()
				}
			}
			return nil
		})
		return held
	}
}

func uploadFile(t *testing.T, size int, rig *channelRig, throttle time.Duration, opts ...fixtureOption) (*testFixture, ir.DAGRunStatus, time.Duration) {
	t.Helper()
	needRealTime(t)
	needPosixShell(t)
	script := strings.Join([]string{
		`mkdir -p "${DAG_RUN_ARTIFACTS_DIR}/reports"`,
		fmt.Sprintf(`head -c %d /dev/urandom > "${DAG_RUN_ARTIFACTS_DIR}/reports/large.bin"`, size),
		`(sha256sum "${DAG_RUN_ARTIFACTS_DIR}/reports/large.bin" || shasum -a 256 "${DAG_RUN_ARTIFACTS_DIR}/reports/large.bin") | cut -d' ' -f1`,
	}, "\n")
	f := newTestFixture(t, rigDAG(script), append(opts, withChannelRig(rig), withLogPersistence(), withArtifactPersistence(), withIsolatedWorker())...)
	t.Cleanup(f.cleanup)
	rig.uploads.held = heldSegments(f.coord.Config.Paths.ArtifactDir)
	rig.proxy.throttle.Store(int64(throttle))
	if rig.onFixture != nil {
		rig.onFixture(f)
	}
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	start := time.Now()
	f.startScheduler(distrTestTimeout(30 * time.Minute))
	status := f.waitForStatusIn([]ir.Status{ir.Succeeded, ir.Failed, ir.Aborted}, distrTestTimeout(20*time.Minute))
	return f, status, time.Since(start)
}

func requireWholeFile(t *testing.T, f *testFixture, status ir.DAGRunStatus, size int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(status.ArchiveDir, "reports", "large.bin"))
	require.NoError(t, err)
	require.Len(t, data, size)
	sum := sha256.Sum256(data)
	t.Logf("rig: committed %d bytes, sha256 %s", len(data), hex.EncodeToString(sum[:]))
	logs := findLogFiles(t, f.coord.Config.Paths.LogDir, status.Name, status.DAGRunID, "run", "stdout")
	require.NotEmpty(t, logs)
	logged, err := os.ReadFile(filepath.Clean(logs[0]))
	require.NoError(t, err)
	assert.Contains(t, string(logged), hex.EncodeToString(sum[:]), "the digest the job computed")
	_, err = os.Stat(filepath.Join(status.ArchiveDir, ir.ArtifactSegmentDir))
	assert.ErrorIs(t, err, os.ErrNotExist, "no upload is left behind")
}

func scaledRig(whole bool) *channelRig {
	limits := workerchannel.DefaultLimits()
	limits.Stream = 6 * time.Second
	return &channelRig{limits: limits, wholeStreams: whole, uploads: &uploadTrace{}}
}

// uploadChunk is the uploader's chunk, its durable unit: a stream cut by its
// deadline repeats at most the one chunk still in buffers when it was cut.
const uploadChunk = 3 << 20

func logUpload(t *testing.T, rig *channelRig, status ir.DAGRunStatus, took time.Duration, size int) {
	t.Helper()
	streams, sent := rig.uploads.report(t)
	t.Logf("rig: %s after %s, %d streams, %d bytes sent for a %d byte file", status.Status, took.Round(time.Second), streams, sent, size)
	require.Equal(t, ir.Succeeded, status.Status, "error %q", status.Error)
	assert.LessOrEqual(t, sent, uint64(size)+uint64(streams)*uploadChunk, "at most a chunk repeated for each stream")
}

// These proofs run the real uploader against the real handler over Connect,
// through a throttled proxy. The segment size, the retry policy and its window
// are the real ones. Timings are scaled where a test says so: the stream limit
// is 6 s, not 110 s, at a rate that fills the same part of a segment.

// With streams left to their size, a segment does not fit one at this rate, so
// each ends at its deadline mid-segment, and the next starts where the hub is.
func TestChannelUploadCrossesADeadlineMidSegment(t *testing.T) {
	rig := scaledRig(true)
	const size = 20 << 20
	// Two chunks fit a stream here. At one, a chunk lands or not by chance: that
	// is the floor, where an upload may stop moving and end.
	f, status, took := uploadFile(t, size, rig, 35*time.Millisecond)
	logUpload(t, rig, status, took, size)
	rig.uploads.requireForwardOnly(t)
	requireWholeFile(t, f, status, size)
}

// The default: a stream ends by time, so the deadline is never met.
func TestChannelUploadEndsItsStreamsBeforeTheDeadline(t *testing.T) {
	rig := scaledRig(false)
	const size = 20 << 20
	f, status, took := uploadFile(t, size, rig, 35*time.Millisecond)
	logUpload(t, rig, status, took, size)
	rig.uploads.requireForwardOnly(t)
	requireWholeFile(t, f, status, size)
}

// Acknowledgments lost mid-file, and the final one: the hub holds what the worker
// never heard about, and nothing is sent twice for it.
func TestChannelUploadSurvivesLostAcknowledgments(t *testing.T) {
	rig := scaledRig(false)
	var finals atomic.Int64
	rig.uploads.loseReply = func(n int, stream uploadStream) bool {
		if stream.Final {
			return finals.Add(1) == 1
		}
		return n == 4 || n == 7
	}
	const size = 20 << 20
	f, status, took := uploadFile(t, size, rig, 40*time.Millisecond)
	logUpload(t, rig, status, took, size)
	require.Equal(t, 3, rig.uploads.lost, "two segments' replies and the final's")
	requireWholeFile(t, f, status, size)
}

// Streams left to their size meet the real 110 s limit again and again, and the
// whole upload takes far longer than the 3 minute window. Each cut moves the hub,
// so it finishes. Nothing is scaled.
func TestChannelUploadOutlivesItsRetryWindowWhileItMoves(t *testing.T) {
	rig := &channelRig{wholeStreams: true, uploads: &uploadTrace{}}
	const size = 40 << 20
	f, status, took := uploadFile(t, size, rig, 320*time.Millisecond)
	logUpload(t, rig, status, took, size)
	assert.Greater(t, took, 3*time.Minute, "longer than the window")
	requireWholeFile(t, f, status, size)
}

// At the real stream limit, on a link slower than the one measured, where a 16
// MiB segment cannot fit a stream, and finishing takes past 3 minutes. Nothing is
// scaled. The attempt's lease holds throughout, and the terminal status comes
// only after the file is committed.
func TestChannelUploadAtARealSlowRate(t *testing.T) {
	rig := &channelRig{uploads: &uploadTrace{}}
	const size = 20 << 20
	var f *testFixture
	var atCommit atomic.Value
	rig.uploads.atFinal = func() {
		if status, err := f.latestStatus(); err == nil {
			atCommit.Store(status.Status)
		}
	}
	rig.onFixture = func(fixture *testFixture) { f = fixture }
	f, status, took := uploadFile(t, size, rig, 320*time.Millisecond)
	logUpload(t, rig, status, took, size)
	rig.uploads.requireForwardOnly(t)
	assert.Greater(t, took, 3*time.Minute, "finishing outlasted the fixed time")
	t.Logf("rig: status when the hub committed the file: %v", atCommit.Load())
	assert.Equal(t, ir.Running, atCommit.Load(), "no terminal status before the commit")
	requireWholeFile(t, f, status, size)
}

// A stopped run's upload ends within the fixed time, though it is still moving.
func TestChannelUploadStopsWithinItsBoundAfterACancel(t *testing.T) {
	rig := &channelRig{uploads: &uploadTrace{}}
	const size = 200 << 20
	var stopped atomic.Int64
	rig.onFixture = func(f *testFixture) {
		go func() {
			for f.coord.Context.Err() == nil {
				if rig.uploads.held != nil && rig.uploads.held() > 3<<20 {
					status, err := f.latestStatus()
					if err == nil && f.stop(status.DAGRunID) == nil {
						stopped.Store(time.Now().UnixNano())
						t.Logf("rig: stop requested with %d bytes held, status %s", rig.uploads.held(), status.Status)
						return
					}
				}
				time.Sleep(500 * time.Millisecond)
			}
		}()
	}
	_, status, took := uploadFile(t, size, rig, 320*time.Millisecond)
	_, sent := rig.uploads.report(t)
	require.NotZero(t, stopped.Load(), "the stop must land during the upload")
	since := time.Since(time.Unix(0, stopped.Load()))
	t.Logf("rig: %s %s after the stop, %s in all, %d bytes sent of %d, error %q", status.Status, since.Round(time.Second), took.Round(time.Second), sent, size, status.Error)
	assert.NotEqual(t, ir.Succeeded, status.Status)
	assert.Less(t, since, 3*time.Minute+30*time.Second, "the fixed time and a stream's end")
	assert.Less(t, sent, uint64(size))
}

// Before TXE-5662 a file of at most 16 MiB went whole in one stream with no time
// budget, so at this rate it met the 110 s limit, began again at byte 0 and failed
// the run after 3 minutes. Now a file larger than a chunk goes by segments. Real
// limits, about 100 KiB/s; nothing is scaled.
func TestChannelUploadAFileWithinOneStreamAtASlowRate(t *testing.T) {
	rig := &channelRig{uploads: &uploadTrace{}}
	const size = 14 << 20
	f, status, took := uploadFile(t, size, rig, 320*time.Millisecond)
	logUpload(t, rig, status, took, size)
	rig.uploads.requireForwardOnly(t)
	assert.Equal(t, map[string]int{"reports/large.bin": 1}, rig.uploads.finals(), "committed once")
	requireWholeFile(t, f, status, size)
}

// Seven files of 6 MiB at the rate measured through a real edge, 146 KiB/s, take
// longer than 3 minutes. Before TXE-5662 the fixed 3 minutes ended them. Now each
// acknowledged file moves the bound. Real limits; nothing is scaled.
func TestChannelUploadManyFilesAtTheMeasuredRate(t *testing.T) {
	needRealTime(t)
	needPosixShell(t)
	const files, size = 7, 6 << 20
	lines := []string{`mkdir -p "${DAG_RUN_ARTIFACTS_DIR}/r"`}
	for i := range files {
		name := fmt.Sprintf(`"${DAG_RUN_ARTIFACTS_DIR}/r/f%d.bin"`, i)
		lines = append(lines,
			fmt.Sprintf(`head -c %d /dev/urandom > %s`, size, name),
			fmt.Sprintf(`(sha256sum %s || shasum -a 256 %s) | cut -d' ' -f1`, name, name))
	}
	rig := &channelRig{uploads: &uploadTrace{}}
	f := newTestFixture(t, rigDAG(strings.Join(lines, "\n")), withChannelRig(rig), withLogPersistence(), withArtifactPersistence(), withIsolatedWorker())
	t.Cleanup(f.cleanup)
	rig.proxy.throttle.Store(int64(219 * time.Millisecond))
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	start := time.Now()
	f.startScheduler(distrTestTimeout(30 * time.Minute))
	status := f.waitForStatusIn([]ir.Status{ir.Succeeded, ir.Failed, ir.Aborted}, distrTestTimeout(20*time.Minute))
	took := time.Since(start)
	streams, sent := rig.uploads.report(t)
	t.Logf("rig: %s after %s, %d streams, %d bytes sent for %d files of %d bytes", status.Status, took.Round(time.Second), streams, sent, files, size)
	require.Equal(t, ir.Succeeded, status.Status, "error %q", status.Error)
	assert.Greater(t, took, 3*time.Minute, "longer than the old fixed time")
	assert.LessOrEqual(t, sent, uint64(files*size)+uint64(streams)*uploadChunk, "at most a chunk repeated for each stream")

	logs := findLogFiles(t, f.coord.Config.Paths.LogDir, status.Name, status.DAGRunID, "run", "stdout")
	require.NotEmpty(t, logs)
	logged, err := os.ReadFile(filepath.Clean(logs[0]))
	require.NoError(t, err)
	finals := rig.uploads.finals()
	for i := range files {
		rel := fmt.Sprintf("r/f%d.bin", i)
		data, err := os.ReadFile(filepath.Join(status.ArchiveDir, rel))
		require.NoError(t, err)
		require.Len(t, data, size)
		sum := sha256.Sum256(data)
		assert.Contains(t, string(logged), hex.EncodeToString(sum[:]), "the digest the job computed for %s", rel)
		assert.Equal(t, 1, finals[rel], "%s committed once", rel)
	}
	_, err = os.Stat(filepath.Join(status.ArchiveDir, ir.ArtifactSegmentDir))
	assert.ErrorIs(t, err, os.ErrNotExist, "no upload is left behind")
}
