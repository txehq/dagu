// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
)

// Chrome's pipe transport (content/browser/devtools/devtools_pipe_handler.cc)
// carries one JSON message per frame, each followed by a NUL byte: Chrome
// reads commands from one pipe and writes replies and events to another.

// pipeReadBuffer is the reader's initial buffer. Messages grow past it (a
// screenshot is megabytes) and bufio grows with them.
const pipeReadBuffer = 1 << 16

var errFrameHasNUL = errors.New("devtools gate: a message cannot contain a NUL byte")

// pipe is the gate's end of Chrome's two pipes.
type pipe struct {
	in  *os.File // Chrome's replies and events arrive here
	out *os.File // commands go to Chrome here

	writeMu sync.Mutex
	reader  *bufio.Reader

	closeOnce sync.Once
}

func newPipe(in, out *os.File) *pipe {
	return &pipe{in: in, out: out, reader: bufio.NewReaderSize(in, pipeReadBuffer)}
}

// write sends one message to Chrome.
func (p *pipe) write(message []byte) error {
	if bytes.IndexByte(message, 0) >= 0 {
		return errFrameHasNUL
	}
	frame := make([]byte, 0, len(message)+1)
	frame = append(frame, message...)
	frame = append(frame, 0)
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_, err := p.out.Write(frame)
	return err
}

// read returns the next message from Chrome. io.EOF means Chrome closed its
// end, which it does when it exits.
func (p *pipe) read() ([]byte, error) {
	data, err := p.reader.ReadBytes(0)
	if err != nil {
		if errors.Is(err, io.EOF) && len(data) == 0 {
			return nil, io.EOF
		}
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return data[:len(data)-1], nil
}

// close closes both ends. Closing the command pipe is how the gate tells
// Chrome to go: Chrome's reader sees end-of-file and the browser closes.
func (p *pipe) close() {
	p.closeOnce.Do(func() {
		_ = p.out.Close()
		_ = p.in.Close()
	})
}
