// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package runbudget_test runs the Python suite of txe/runbudget (TXE-8043): the txe.runbudget/v1 data contract and
// its reference validator.
//
// The suite starts no process, uses no network and writes no file. A missing python3 FAILS this test: the only skip
// is Windows, which the container runners that write budgets do not target.
package runbudget_test

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

func TestRunbudget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the container runners that write budgets target macOS and Linux hosts")
	}
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	path, err := filepath.Abs("test_runbudget.py")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, "-I", "-B", path, "-v")
	cmd.Env = os.Environ()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	t.Log(out.String())
	require.NoError(t, runErr, "test_runbudget.py failed")
	require.Regexp(t, `(?m)^OK$`, out.String(), "test_runbudget.py did not report OK with no skip")
}
