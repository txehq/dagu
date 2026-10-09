// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package masking

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// streamInPieces masks text through a Stream, writing it in the given pieces.
func streamInPieces(m *Masker, pieces ...string) string {
	var out []byte
	s := m.NewStream()
	for _, piece := range pieces {
		out = append(out, s.Write([]byte(piece))...)
	}
	return string(append(out, s.Flush()...))
}

// Wherever the text is divided, the stream gives the result of masking it
// whole. The values include one that contains another and one that is the
// stripped form of another, which are the cases a piecewise masker gets wrong.
func TestStream_IndependentOfDivision(t *testing.T) {
	m := NewMasker(SourcedEnvVars{Secrets: []string{
		"URL=postgres://u:hunter2@host/db", "PASSWORD=hunter2", "TOKEN=s3cr3t\n", "KEY=line-one\nline-two\n",
	}})
	texts := []string{
		"url=postgres://u:hunter2@host/db end",
		"pw=hunter2 url=postgres://u:hunter2@host/db",
		"token=s3cr3t\ntoken=s3cr3t end hunter2hunter2",
		"postgres://u:hunter2@host/dbpostgres://u:hunter2@host/db",
		"before\nline-one\nline-two\nafter line-one only",
		"hunter", "s3cr3", "",
	}
	for _, text := range texts {
		want := m.MaskString(text)
		assert.Equal(t, want, streamInPieces(m, text), "whole %q", text)
		for first := 0; first <= len(text); first++ {
			for second := first; second <= len(text); second++ {
				got := streamInPieces(m, text[:first], text[first:second], text[second:])
				require.Equal(t, want, got, "text %q divided at %d and %d", text, first, second)
			}
		}
		// One byte at a time.
		require.Equal(t, want, streamInPieces(m, strings.Split(text, "")...), "text %q byte by byte", text)
	}
}

// Values that overlap are replaced together. Masking the whole text replaces
// the longer first and leaves the tail of the other; the stream leaves nothing.
func TestStream_OverlappingValues(t *testing.T) {
	m := NewMasker(SourcedEnvVars{Secrets: []string{"A=abcdef", "B=defghi"}})

	assert.Equal(t, "x*******y", streamInPieces(m, "xabcdefghiy"))
	assert.Equal(t, "x*******y", streamInPieces(m, "xabcd", "efg", "hiy"))
}

// What is held back never exceeds one byte fewer than the longest value,
// whatever the text looks like.
func TestStream_HoldsBoundedText(t *testing.T) {
	m := NewMasker(SourcedEnvVars{Secrets: []string{"TOKEN=s3cr3t"}})
	s := m.NewStream()

	total := 0
	for range 64 {
		total += len(s.Write(bytes.Repeat([]byte("s3cr3"), 800)))
		assert.LessOrEqual(t, s.Held(), len("s3cr3t")-1)
	}
	total += len(s.Flush())
	assert.Equal(t, 64*800*len("s3cr3"), total)
	assert.Zero(t, s.Held())
}

// After a flush the stream starts again: text on either side of it is not
// joined into a value.
func TestStream_FlushEndsText(t *testing.T) {
	m := NewMasker(SourcedEnvVars{Secrets: []string{"TOKEN=s3cr3t"}})
	s := m.NewStream()

	var out []byte
	out = append(out, s.Write([]byte("a s3c"))...)
	out = append(out, s.Flush()...)
	out = append(out, s.Write([]byte("r3t b s3cr3t"))...)
	out = append(out, s.Flush()...)
	assert.Equal(t, "a s3cr3t b *******", string(out))
}

// Without values nothing is held and nothing changes.
func TestStream_NoValues(t *testing.T) {
	s := NewMasker(SourcedEnvVars{}).NewStream()

	assert.Equal(t, "plain text", string(s.Write([]byte("plain text"))))
	assert.Zero(t, s.Held())
	assert.Empty(t, s.Flush())
}
