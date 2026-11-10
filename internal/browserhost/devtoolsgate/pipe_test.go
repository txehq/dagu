// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPipeFraming(t *testing.T) {
	t.Parallel()
	pair := newPipePair(t)
	t.Cleanup(pair.close)
	p := newPipe(pair.gateRead, pair.gateWrite)
	peerIn, peerOut := pair.browserRead, pair.browserWrite

	require.NoError(t, p.write([]byte(`{"id":1}`)))
	got := make([]byte, 64)
	n, err := peerIn.Read(got)
	require.NoError(t, err)
	assert.Equal(t, "{\"id\":1}\x00", string(got[:n]), "one NUL closes the frame")

	assert.ErrorIs(t, p.write([]byte("a\x00b")), errFrameHasNUL)

	_, err = peerOut.Write([]byte("{\"method\":\"A\"}\x00{\"method\":\"B\"}\x00"))
	require.NoError(t, err)
	first, err := p.read()
	require.NoError(t, err)
	assert.Equal(t, `{"method":"A"}`, string(first))
	second, err := p.read()
	require.NoError(t, err)
	assert.Equal(t, `{"method":"B"}`, string(second))

	// A frame cut off by the peer closing is not a message.
	_, err = peerOut.Write([]byte("{\"meth"))
	require.NoError(t, err)
	require.NoError(t, peerOut.Close())
	_, err = p.read()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	_, err = p.read()
	assert.ErrorIs(t, err, io.EOF, "a closed pipe at a frame boundary is end-of-file")
}

// Closing a pipe pair with a Read in progress on each side returns at once
// and ends both reads: the write ends go first, so the readers see
// end-of-file. With the read ends first, a read end's Close waits for the
// Read, on Windows for ever. The bounds keep a regression a failure, not a
// hang.
func TestPipePairCloseEndsReadsInProgress(t *testing.T) {
	t.Parallel()
	pair := newPipePair(t)
	reads := make(chan error, 2)
	for _, end := range []*os.File{pair.gateRead, pair.browserRead} {
		go func() {
			_, err := end.Read(make([]byte, 1))
			reads <- err
		}()
	}
	// The reads have begun by now, far more often than not; a read that
	// starts after the close ends at once too, with the file closed.
	time.Sleep(200 * time.Millisecond)

	closed := make(chan struct{})
	go func() {
		pair.close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("closing the pair waited on a read in progress")
	}
	for range 2 {
		select {
		case err := <-reads:
			assert.True(t, errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed), "the read ended with end-of-file or a closed file: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("a read in progress did not end with the close")
		}
	}
}
