// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package masking

import (
	"bytes"
	"sort"
)

// Stream masks text that arrives in pieces. Its output does not depend on
// where the pieces are divided: it is decided one position at a time, and a
// position is decided only once enough of the text after it has arrived to
// know whether a sensitive value starts there.
//
// A run of overlapping values is replaced by one mask. This is at least as
// strict as Masker.MaskString, which replaces the longest value first and can
// leave part of a value that overlapped it; for values that do not overlap,
// the two agree.
//
// A Stream is not safe for concurrent use.
type Stream struct {
	// values are the sensitive values, longest first.
	values [][]byte
	// starts marks the bytes a value can begin with.
	starts [256]bool
	maxLen int

	// buf is text not yet decided.
	buf []byte
	// covered is how many leading bytes of buf belong to a value that was
	// already replaced.
	covered int
}

// NewStream returns a Stream that masks the masker's values.
func (m *Masker) NewStream() *Stream {
	s := &Stream{}
	for val := range m.sensitiveVals {
		s.values = append(s.values, []byte(val))
		s.starts[val[0]] = true
		s.maxLen = max(s.maxLen, len(val))
	}
	sort.Slice(s.values, func(a, b int) bool { return len(s.values[a]) > len(s.values[b]) })
	return s
}

// Write adds p to the text and returns the masked output that is now decided.
// At most one byte fewer than the longest value is held back.
func (s *Stream) Write(p []byte) []byte {
	s.buf = append(s.buf, p...)
	return s.decide(false)
}

// Flush returns the masked form of everything held back, treating the text
// as ended. Text written afterwards is masked as a new text.
func (s *Stream) Flush() []byte {
	return s.decide(true)
}

// Held reports how many bytes are held back.
func (s *Stream) Held() int { return len(s.buf) }

func (s *Stream) decide(final bool) []byte {
	var out []byte
	i := 0
	for ; i < len(s.buf); i++ {
		// A value longer than what remains could still begin here.
		if !final && len(s.buf)-i < s.maxLen {
			break
		}
		switch n := s.matchAt(i); {
		case n > 0:
			// A value that overlaps the previous one extends its mask; one
			// that starts where the previous ended gets its own.
			if i >= s.covered {
				out = append(out, DefaultMaskString...)
			}
			s.covered = max(s.covered, i+n)
		case i >= s.covered:
			out = append(out, s.buf[i])
		}
	}
	s.buf = append(s.buf[:0], s.buf[i:]...)
	s.covered = max(s.covered-i, 0)
	return out
}

// matchAt returns the length of the longest value that begins at buf[i], or 0.
func (s *Stream) matchAt(i int) int {
	if !s.starts[s.buf[i]] {
		return 0
	}
	for _, val := range s.values {
		if bytes.HasPrefix(s.buf[i:], val) {
			return len(val)
		}
	}
	return 0
}
