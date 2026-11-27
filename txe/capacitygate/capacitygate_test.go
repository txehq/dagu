// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package capacitygate_test runs the Python suite of txe/capacitygate (TXE-8043): the capacity preflight, its formula and
// its fixtures.
//
// The suite starts no process, uses no network and writes only inside temporary directories it creates and
// removes. A missing python3 FAILS this test: the only skip is Windows, which the gated container runners do not target.
package capacitygate_test

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

func TestCapacityGate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the gated container runners target macOS and Linux hosts")
	}
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	path, err := filepath.Abs("test_capacity_gate.py")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, "-I", "-B", path, "-v")
	cmd.Env = os.Environ()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	t.Log(out.String())
	require.NoError(t, runErr, "test_capacity_gate.py failed")
	require.Regexp(t, `(?m)^OK$`, out.String(), "test_capacity_gate.py did not report OK with no skip")
}
