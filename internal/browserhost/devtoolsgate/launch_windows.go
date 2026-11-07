// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package devtoolsgate

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// pipeFlags are the arguments that make Chrome read commands from one
// inherited pipe handle and write replies to the other. Chrome M117 and
// later take the two handle values as unsigned integers in
// --remote-debugging-io-pipes (content_switches.cc, Windows only); an
// inherited handle keeps its value in the child.
func pipeFlags(browserRead, browserWrite *os.File) []string {
	return []string{
		"--remote-debugging-pipe",
		fmt.Sprintf("--remote-debugging-io-pipes=%d,%d", browserRead.Fd(), browserWrite.Fd()),
	}
}

// attachPipes lets the browser inherit its two pipe handles and nothing
// else: os.Pipe marks its handles inheritable, and Go's StartProcess limits
// inheritance to the standard handles plus these two through the process
// attribute handle list. os/exec's ExtraFiles is not supported on Windows.
func attachPipes(cmd *exec.Cmd, browserRead, browserWrite *os.File) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
		AdditionalInheritedHandles: []syscall.Handle{
			syscall.Handle(browserRead.Fd()),
			syscall.Handle(browserWrite.Fd()),
		},
	}
}

// endBrowser ends the browser process at once. Its helper processes exit
// with it.
func endBrowser(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	err := cmd.Process.Kill()
	if err == os.ErrProcessDone {
		return nil
	}
	return err
}
