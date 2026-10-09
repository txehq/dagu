// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package runtime

import (
	"bufio"
	"io"
	"sync"

	"github.com/dagucloud/dagu/v2/internal/cmn/masking"
)

// flushableMultiWriter creates a MultiWriter that can flush all underlying writers
type flushableMultiWriter struct {
	writers []io.Writer
}

// newFlushableMultiWriter creates a new flushableMultiWriter
func newFlushableMultiWriter(writers ...io.Writer) *flushableMultiWriter {
	return &flushableMultiWriter{writers: writers}
}

// Write writes to all underlying writers
func (fw *flushableMultiWriter) Write(p []byte) (n int, err error) {
	for _, w := range fw.writers {
		n, err = w.Write(p)
		if err != nil {
			return
		}
		if n != len(p) {
			err = io.ErrShortWrite
			return
		}
	}
	return len(p), nil
}

// Flush flushes all underlying writers that support flushing
func (fw *flushableMultiWriter) Flush() error {
	var lastErr error
	for _, w := range fw.writers {
		// Try different flush interfaces
		switch v := w.(type) {
		case *bufio.Writer:
			if err := v.Flush(); err != nil {
				lastErr = err
			}
		case interface{ Flush() error }:
			if err := v.Flush(); err != nil {
				lastErr = err
			}
		case interface{ Sync() error }:
			if err := v.Sync(); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

// safeBufferedWriter wraps bufio.Writer with a mutex to make concurrent
// Write and Flush safe across goroutines.
type safeBufferedWriter struct {
	mu sync.Mutex
	w  io.Writer
	bw *bufio.Writer
}

// newSafeBufferedWriter creates a thread-safe buffered writer
func newSafeBufferedWriter(w io.Writer) *safeBufferedWriter {
	return &safeBufferedWriter{w: w, bw: bufio.NewWriter(w)}
}

func (s *safeBufferedWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bw.Write(p)
}

// FlushIfDue writes buffered output through. A partial line the wrapped
// writer holds back, such as one awaiting secret masking, stays held.
func (s *safeBufferedWriter) FlushIfDue() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bw.Flush()
}

// Flush writes all buffered output through, including a partial line the
// wrapped writer holds back.
func (s *safeBufferedWriter) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.bw.Flush(); err != nil {
		return err
	}
	if f, ok := s.w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

// maskedStreamWriter masks declared secrets in step output before handing it
// to a writer that sends it off the machine.
//
// The masking is a masking.Stream, so the result does not depend on how the
// writes divide the output, and at most one byte fewer than the longest secret
// is held back at any time. The held bytes could be the start of a secret
// whose rest has not been written yet; they are sent once later output decides
// them, or when the attempt ends.
type maskedStreamWriter struct {
	mu     sync.Mutex
	stream io.WriteCloser
	mask   *masking.Stream
}

func newMaskedStreamWriter(stream io.WriteCloser, masker *masking.Masker) *maskedStreamWriter {
	return &maskedStreamWriter{stream: stream, mask: masker.NewStream()}
}

// Write masks p and sends what is decided. The decided output is not kept
// when the stream refuses it, so a broken stream cannot make it accumulate.
func (w *maskedStreamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.sendLocked(w.mask.Write(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *maskedStreamWriter) sendLocked(out []byte) error {
	if len(out) == 0 {
		return nil
	}
	_, err := w.stream.Write(out)
	return err
}

// FlushIfDue lets the stream send what it has. The bytes held back stay held:
// sending them now could put the first half of a secret on the wire.
func (w *maskedStreamWriter) FlushIfDue() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if f, ok := w.stream.(interface{ FlushIfDue() error }); ok {
		return f.FlushIfDue()
	}
	return nil
}

// Flush sends everything, including the bytes held back. It ends an attempt:
// output written afterwards is masked on its own.
func (w *maskedStreamWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushLocked()
}

func (w *maskedStreamWriter) flushLocked() error {
	if err := w.sendLocked(w.mask.Flush()); err != nil {
		return err
	}
	if f, ok := w.stream.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

// Close sends what is left and closes the stream.
func (w *maskedStreamWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	flushErr := w.flushLocked()
	if err := w.stream.Close(); err != nil {
		return err
	}
	return flushErr
}
