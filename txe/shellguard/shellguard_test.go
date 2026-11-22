// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package shellguard_test runs the Python suite of txe/shellguard (TXE-8055): the PreToolUse guard that refuses
// shell-evaluated text (a backtick or $( ) in double quotes or an unquoted heredoc) before a shell parses it.
//
// The suite is text-only. Every fixture is a string handed to the guard's scanner or to its main() with in-memory
// streams; no fixture is evaluated as shell, and the suite starts no process, opens no file but the guard's own
// source, and uses no network. The only process here is this one python3 running the unittest file. A missing
// python3 FAILS the test: the only skip is Windows, which the guard's hosts do not run.
package shellguard_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func python(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the guard runs on macOS and Linux agent hosts")
	}
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	return py
}

// TestGuardHook runs test_guard_hook.py with python3 -I -B and fails on a non-zero exit or a missing OK line. The
// whole output is logged, so every case is visible in the test log.
func TestGuardHook(t *testing.T) {
	py := python(t)
	path, err := filepath.Abs("test_guard_hook.py")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, "-I", "-B", path, "-v")
	cmd.Env = os.Environ()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	t.Log(out.String())
	require.NoError(t, runErr, "test_guard_hook.py failed")
	require.Regexp(t, `(?m)^OK$`, out.String(), "test_guard_hook.py did not report OK with no skip")
}
