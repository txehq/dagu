// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package devtoolsgate

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// detachGate gives the gate a process group of its own, so the caller's
// Ctrl+C does not reach it. It stays in the caller's job object: on Windows
// Dagu runs a step's processes in a job that ends them with the step, and
// the browser ends with its gate.
func detachGate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}
