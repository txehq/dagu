// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package runtime

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/cmn/masking"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlushableMultiWriter_Write(t *testing.T) {
	tests := []struct {
		name    string
		writers []io.Writer
		input   []byte
		wantErr bool
	}{
		{
			name:    "WriteToSingleWriter",
			writers: []io.Writer{&bytes.Buffer{}},
			input:   []byte("hello world"),
			wantErr: false,
		},
		{
			name:    "WriteToMultipleWriters",
			writers: []io.Writer{&bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}},
			input:   []byte("test data"),
			wantErr: false,
		},
		{
			name:    "EmptyWrite",
			writers: []io.Writer{&bytes.Buffer{}},
			input:   []byte{},
			wantErr: false,
		},
		{
			name:    "WriteWithError",
			writers: []io.Writer{&errorWriter{err: errors.New("write failed")}},
			input:   []byte("data"),
			wantErr: true,
		},
		{
			name:    "WriteWithShortWrite",
			writers: []io.Writer{&shortWriter{}},
			input:   []byte("data"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := newFlushableMultiWriter(tt.writers...)
			n, err := fw.Write(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tt.input), n)

				// Verify all writers received the data
				for _, w := range tt.writers {
					if buf, ok := w.(*bytes.Buffer); ok {
						assert.Equal(t, string(tt.input), buf.String())
					}
				}
			}
		})
	}
}

func TestFlushableMultiWriter_Flush(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() (*flushableMultiWriter, func())
		wantErr bool
	}{
		{
			name: "FlushBufferedWriter",
			setup: func() (*flushableMultiWriter, func()) {
				var buf bytes.Buffer
				bw := bufio.NewWriter(&buf)
				fw := newFlushableMultiWriter(bw)

				// Write some data that will be buffered
				_, err := fw.Write([]byte("buffered data"))
				require.NoError(t, err)

				return fw, func() {
					// Check that data was flushed to underlying buffer
					assert.Equal(t, "buffered data", buf.String())
				}
			},
			wantErr: false,
		},
		{
			name: "FlushMultipleWriters",
			setup: func() (*flushableMultiWriter, func()) {
				var buf1, buf2, buf3 bytes.Buffer
				bw1 := bufio.NewWriter(&buf1)
				bw2 := bufio.NewWriter(&buf2)
				fw := newFlushableMultiWriter(bw1, &buf3, bw2)

				// Write data
				_, err := fw.Write([]byte("test"))
				require.NoError(t, err)

				return fw, func() {
					// Both buffered writers should be flushed
					assert.Equal(t, "test", buf1.String())
					assert.Equal(t, "test", buf2.String())
					// Regular buffer gets data immediately
					assert.Equal(t, "test", buf3.String())
				}
			},
			wantErr: false,
		},
		{
			name: "FlushWithFlushableInterface",
			setup: func() (*flushableMultiWriter, func()) {
				f := &flushableWriter{flushed: false}
				fw := newFlushableMultiWriter(f)
				return fw, func() {
					assert.True(t, f.flushed, "flushable writer should be flushed")
				}
			},
			wantErr: false,
		},
		{
			name: "FlushWithSyncableInterface",
			setup: func() (*flushableMultiWriter, func()) {
				s := &syncableWriter{synced: false}
				fw := newFlushableMultiWriter(s)
				return fw, func() {
					assert.True(t, s.synced, "syncable writer should be synced")
				}
			},
			wantErr: false,
		},
		{
			name: "FlushWithError",
			setup: func() (*flushableMultiWriter, func()) {
				f := &flushableWriter{err: errors.New("flush failed")}
				fw := newFlushableMultiWriter(f)
				return fw, func() {}
			},
			wantErr: true,
		},
		{
			name: "FlushWithNoFlushableWriters",
			setup: func() (*flushableMultiWriter, func()) {
				fw := newFlushableMultiWriter(&bytes.Buffer{})
				return fw, func() {}
			},
			wantErr: false,
		},
		{
			name: "FlushWithMixedWriterTypes",
			setup: func() (*flushableMultiWriter, func()) {
				var buf bytes.Buffer
				bw := bufio.NewWriter(&buf)
				f := &flushableWriter{flushed: false}
				s := &syncableWriter{synced: false}

				fw := newFlushableMultiWriter(bw, &bytes.Buffer{}, f, s)
				_, err := fw.Write([]byte("mixed"))
				require.NoError(t, err)

				return fw, func() {
					assert.Equal(t, "mixed", buf.String())
					assert.True(t, f.flushed)
					assert.True(t, s.synced)
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw, verify := tt.setup()
			err := fw.Flush()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			verify()
		})
	}
}

func TestFlushableMultiWriter_Integration(t *testing.T) {
	// Test the full flow with pipes similar to how it's used in node.go
	t.Run("PipeWithBufferedWriter", func(t *testing.T) {
		pr, pw := io.Pipe()
		defer func() { _ = pr.Close() }()
		defer func() { _ = pw.Close() }()

		var captured bytes.Buffer
		done := make(chan struct{})

		// Start reading from pipe
		go func() {
			defer close(done)
			_, _ = io.Copy(&captured, pr)
		}()

		// Create flushable multi writer with buffered writer
		var logBuffer bytes.Buffer
		logWriter := bufio.NewWriter(&logBuffer)
		fw := newFlushableMultiWriter(pw, logWriter)

		// Write data
		data := "test data for pipe"
		n, err := fw.Write([]byte(data))
		require.NoError(t, err)
		require.Equal(t, len(data), n)

		// Data should be in pipe but not yet in logBuffer
		assert.Empty(t, logBuffer.String(), "data should still be buffered")

		// Flush the writer
		err = fw.Flush()
		require.NoError(t, err)

		// Now data should be in logBuffer
		assert.Equal(t, data, logBuffer.String())

		// Close pipe and wait for reader
		err = pw.Close()
		require.NoError(t, err)
		<-done

		// Verify captured data
		assert.Equal(t, data, captured.String())
	})
}

// A periodic flush must not write a partial line, or a secret split across
// writes reaches the log unmasked. Flush ends the attempt and writes it all.
func TestSafeBufferedWriter_MaskedPartialLine(t *testing.T) {
	var out bytes.Buffer
	masker := masking.NewMasker(masking.SourcedEnvVars{Secrets: []string{"TOKEN=s3cr3t"}})
	w := newSafeBufferedWriter(masking.NewMaskingWriter(&out, masker))

	_, err := w.Write([]byte("s3c"))
	require.NoError(t, err)
	require.NoError(t, w.FlushIfDue())
	assert.Empty(t, out.String())

	_, err = w.Write([]byte("r3t"))
	require.NoError(t, err)
	require.NoError(t, w.Flush())
	assert.Equal(t, "*******", out.String())
}

// Helper types for testing

type errorWriter struct {
	err error
}

func (e *errorWriter) Write(_ []byte) (n int, err error) {
	return 0, e.err
}

type shortWriter struct{}

func (s *shortWriter) Write(p []byte) (n int, err error) {
	if len(p) > 0 {
		return len(p) - 1, nil
	}
	return 0, nil
}

type flushableWriter struct {
	bytes.Buffer
	flushed bool
	err     error
}

func (f *flushableWriter) Flush() error {
	f.flushed = true
	return f.err
}

type syncableWriter struct {
	bytes.Buffer
	synced bool
	err    error
}

func (s *syncableWriter) Sync() error {
	s.synced = true
	return s.err
}

// recordingStream is a remote log stream that records what it is given and
// which of its flush methods are called.
type recordingStream struct {
	bytes.Buffer
	flushed, flushedIfDue, closed int
	writeErr, closeErr            error
}

func (s *recordingStream) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return s.Buffer.Write(p)
}
func (s *recordingStream) Flush() error      { s.flushed++; return nil }
func (s *recordingStream) FlushIfDue() error { s.flushedIfDue++; return nil }
func (s *recordingStream) Close() error      { s.closed++; return s.closeErr }

func newTestMaskedStream(secrets ...string) (*maskedStreamWriter, *recordingStream) {
	if len(secrets) == 0 {
		secrets = []string{"TOKEN=s3cr3t"}
	}
	stream := &recordingStream{}
	masker := masking.NewMasker(masking.SourcedEnvVars{Secrets: secrets})
	return newMaskedStreamWriter(stream, masker), stream
}

// However the writes divide a secret, the stream never receives it: not when
// it is split mid-value, and not when a periodic flush falls inside it.
func TestMaskedStreamWriter_SplitSecret(t *testing.T) {
	const text = "start s3cr3t middle s3cr3t end"
	for cut := 1; cut < len(text); cut++ {
		w, stream := newTestMaskedStream()

		_, err := w.Write([]byte(text[:cut]))
		require.NoError(t, err)
		require.NoError(t, w.FlushIfDue())
		assert.NotContains(t, stream.String(), "s3cr3t", "cut at %d", cut)
		_, err = w.Write([]byte(text[cut:]))
		require.NoError(t, err)
		require.NoError(t, w.Close())

		assert.Equal(t, "start ******* middle ******* end", stream.String(), "cut at %d", cut)
	}
}

// Streaming must give the same result as masking the whole text, wherever the
// writes fall. The hard case is a secret that contains another: masking the
// short one early must not stop the long one from being recognised.
func TestMaskedStreamWriter_MatchesWholeText(t *testing.T) {
	secrets := []string{"URL=postgres://u:hunter2@host/db", "PASSWORD=hunter2", "TOKEN=s3cr3t\n"}
	texts := []string{
		"url=postgres://u:hunter2@host/db end",
		"pw=hunter2 url=postgres://u:hunter2@host/db",
		"token=s3cr3t\ntoken=s3cr3t end hunter2hunter2",
		"postgres://u:hunter2@host/dbpostgres://u:hunter2@host/db",
	}
	whole := masking.NewMasker(masking.SourcedEnvVars{Secrets: secrets})
	for _, text := range texts {
		want := whole.MaskString(text)
		for first := 1; first < len(text); first++ {
			for second := first; second <= len(text); second += 7 {
				w, stream := newTestMaskedStream(secrets...)
				for _, part := range []string{text[:first], text[first:second], text[second:]} {
					_, err := w.Write([]byte(part))
					require.NoError(t, err)
					require.NoError(t, w.FlushIfDue())
				}
				require.NoError(t, w.Close())
				require.Equal(t, want, stream.String(), "text %q cut at %d and %d", text, first, second)
			}
		}
	}
}

// Only the bytes that could begin a secret are held back, so output with no
// line break does not accumulate in memory.
func TestMaskedStreamWriter_BoundsHeldOutput(t *testing.T) {
	w, stream := newTestMaskedStream()
	const held = len("s3cr3t") - 1

	chunk := bytes.Repeat([]byte("x"), 4096)
	for range 64 {
		_, err := w.Write(chunk)
		require.NoError(t, err)
		assert.LessOrEqual(t, w.mask.Held(), held)
	}
	assert.Equal(t, 64*4096-held, stream.Len())

	require.NoError(t, w.Flush())
	assert.Equal(t, 64*4096, stream.Len())
	assert.Equal(t, 1, stream.flushed)
}

// A secret of several lines is masked when its lines arrive in separate writes.
func TestMaskedStreamWriter_MultilineSecret(t *testing.T) {
	w, stream := newTestMaskedStream("KEY=line-one\nline-two\n")

	for _, part := range []string{"before\nline-one\n", "line-two\n", "after\n"} {
		_, err := w.Write([]byte(part))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	assert.Equal(t, "before\n*******after\n", stream.String())
}

// A secret read from a file ends with a newline; the value a script prints
// after stripping it is masked as well.
func TestMaskedStreamWriter_TrimmedSecret(t *testing.T) {
	w, stream := newTestMaskedStream("TOKEN=s3cr3t\n")

	_, err := w.Write([]byte("token=s3cr3t end"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	assert.Equal(t, "token=******* end", stream.String())
}

// Flush and Close send the bytes held back, masked, and close the stream once.
func TestMaskedStreamWriter_FlushAndClose(t *testing.T) {
	w, stream := newTestMaskedStream()

	_, err := w.Write([]byte("tail s3cr3t"))
	require.NoError(t, err)
	require.NoError(t, w.Flush())
	assert.Equal(t, "tail *******", stream.String())

	_, err = w.Write([]byte(" more s3cr3t"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	assert.Equal(t, "tail ******* more *******", stream.String())
	assert.Equal(t, 1, stream.closed)
}

// The stream is closed even when it reports an error, and the error is returned.
func TestMaskedStreamWriter_CloseError(t *testing.T) {
	w, stream := newTestMaskedStream()
	stream.closeErr = errors.New("stream lost")

	_, err := w.Write([]byte("tail s3cr3t"))
	require.NoError(t, err)
	require.ErrorContains(t, w.Close(), "stream lost")
	assert.Equal(t, "tail *******", stream.String())
	assert.Equal(t, 1, stream.closed)
}

// A stream that refuses writes reports the error and does not make the held
// output grow.
func TestMaskedStreamWriter_WriteError(t *testing.T) {
	w, stream := newTestMaskedStream()
	stream.writeErr = errors.New("stream closed")

	for range 8 {
		_, err := w.Write(bytes.Repeat([]byte("y"), 1024))
		require.ErrorContains(t, err, "stream closed")
		assert.LessOrEqual(t, w.mask.Held(), len("s3cr3t")-1)
	}
}

// Stdout and stderr share one writer when they are merged, so writes arrive
// from two goroutines.
func TestMaskedStreamWriter_ConcurrentWrites(t *testing.T) {
	w, stream := newTestMaskedStream()

	done := make(chan struct{})
	for range 2 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 200 {
				_, _ = w.Write([]byte("line s3cr3t\n"))
				_ = w.FlushIfDue()
			}
		}()
	}
	<-done
	<-done
	require.NoError(t, w.Close())

	assert.NotContains(t, stream.String(), "s3cr3t")
	assert.Equal(t, 400, bytes.Count(stream.Bytes(), []byte("line *******\n")))
}
