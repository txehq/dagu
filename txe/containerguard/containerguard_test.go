// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package containerguard_test runs the Python suites of txe/containerguard (TXE-8041): the shared positional
// launch guard (argv_guard.py) and the consumer check (consumers.py), which scans this repository's txe/ tree.
//
// The suites start no container and no other process, use no network, and write only inside temporary directories
// they create and remove. A missing python3 FAILS these tests: the only skip is Windows, which the guard's runners
// do not target.
package containerguard_test

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
		t.Skip("the container runners this guards target macOS and Linux hosts")
	}
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	return py
}

// runSuite runs one unittest file with python3 -I -B and fails on a non-zero exit or a missing OK line. The whole
// output is logged, so every case is visible in the test log.
func runSuite(t *testing.T, file string) {
	t.Helper()
	py := python(t)
	path, err := filepath.Abs(file)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, "-I", "-B", path, "-v")
	cmd.Env = os.Environ()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	t.Log(out.String())
	require.NoError(t, runErr, "%s failed", file)
	require.Regexp(t, `(?m)^OK$`, out.String(), "%s did not report OK with no skip", file)
}

func TestArgvGuard(t *testing.T) {
	runSuite(t, "test_argv_guard.py")
}

func TestConsumers(t *testing.T) {
	runSuite(t, "test_consumers.py")
}
