// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/procutil"
)

// browserExitGrace is how long an ending browser gets to leave on its own
// after its pipe closed before it is ended by force.
const browserExitGrace = 10 * time.Second

// browserProcess is the browser the gate started and the gate's end of its
// pipes.
type browserProcess struct {
	cmd       *exec.Cmd
	pipe      *pipe
	startedAt int64
	done      chan struct{}
	waitErr   error
}

// launchBrowser starts cfg.Executable with cfg.Args and the pipe flags, and
// hands it its two pipe ends the way this platform does. Nothing is sent
// yet; the caller speaks to the browser through the returned pipe.
func launchBrowser(cfg Config) (*browserProcess, error) {
	// The browser reads commands from browserRead and writes replies to
	// browserWrite; the gate holds the other ends.
	browserRead, gateWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create the browser's command pipe: %w", err)
	}
	gateRead, browserWrite, err := os.Pipe()
	if err != nil {
		_ = browserRead.Close()
		_ = gateWrite.Close()
		return nil, fmt.Errorf("create the browser's reply pipe: %w", err)
	}
	args := make([]string, 0, len(cfg.Args)+2)
	args = append(args, pipeFlags(browserRead, browserWrite)...)
	args = append(args, cfg.Args...)
	cmd := exec.Command(cfg.Executable, args...) //nolint:gosec // starting the configured browser is the gate's purpose
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	attachPipes(cmd, browserRead, browserWrite)
	err = cmd.Start()
	// The browser holds its ends now; the gate keeps only its own, or the
	// browser would never see end-of-file.
	_ = browserRead.Close()
	_ = browserWrite.Close()
	if err != nil {
		_ = gateWrite.Close()
		_ = gateRead.Close()
		return nil, fmt.Errorf("start the browser: %w", err)
	}
	process := &browserProcess{
		cmd:  cmd,
		pipe: newPipe(gateRead, gateWrite),
		done: make(chan struct{}),
	}
	process.startedAt, _ = procutil.StartTime(cmd.Process.Pid)
	go func() {
		process.waitErr = cmd.Wait()
		close(process.done)
	}()
	return process, nil
}

func (p *browserProcess) pid() int {
	return p.cmd.Process.Pid
}

// exited reports whether the browser process has exited.
func (p *browserProcess) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// waitExit waits for the browser to exit until ctx ends.
func (p *browserProcess) waitExit(ctx context.Context) error {
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// end closes the pipes, which tells the browser to close itself, waits
// browserExitGrace for it, and ends it by force when it is still there.
func (p *browserProcess) end() error {
	p.pipe.close()
	ctx, cancel := context.WithTimeout(context.Background(), browserExitGrace)
	defer cancel()
	if p.waitExit(ctx) == nil {
		return nil
	}
	if err := endBrowser(p.cmd); err != nil {
		return fmt.Errorf("end the browser: %w", err)
	}
	<-p.done
	return nil
}

// exitError describes how the browser exited, for a gate that failed before
// it was ready.
func (p *browserProcess) exitError() error {
	if !p.exited() {
		return nil
	}
	if p.waitErr == nil {
		return errors.New("the browser exited")
	}
	return fmt.Errorf("the browser exited: %w", p.waitErr)
}
