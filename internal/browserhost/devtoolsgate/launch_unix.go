// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package devtoolsgate

import (
	"os"
	"os/exec"
	"syscall"
)

// pipeFlags are the arguments that make Chrome read commands from file
// descriptor 3 and write replies to 4 (kReadFD and kWriteFD in Chrome's
// devtools_pipe_handler.cc).
func pipeFlags(_, _ *os.File) []string {
	return []string{"--remote-debugging-pipe"}
}

// attachPipes hands the browser its two pipe ends as descriptors 3 and 4;
// os/exec closes every other descriptor on exec. The browser gets a process
// group of its own, so ending it ends its helper processes with it.
func attachPipes(cmd *exec.Cmd, browserRead, browserWrite *os.File) {
	cmd.ExtraFiles = []*os.File{browserRead, browserWrite}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// endBrowser ends the browser's process group at once.
func endBrowser(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if err == syscall.ESRCH {
		return nil
	}
	return err
}
