// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package devtoolsgate

import (
	"os/exec"
	"syscall"
)

// detachGate puts the gate in a process group of its own, so a signal to the
// caller's group, as when a step is cancelled, does not end a browser that
// is to outlive the step.
func detachGate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
