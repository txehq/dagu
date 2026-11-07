// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPipeFraming(t *testing.T) {
	t.Parallel()
	in, peerOut, err := os.Pipe()
	require.NoError(t, err)
	peerIn, out, err := os.Pipe()
	require.NoError(t, err)
	p := newPipe(in, out)
	t.Cleanup(func() {
		p.close()
		_ = peerIn.Close()
		_ = peerOut.Close()
	})

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
