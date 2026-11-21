// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package kubeguard_test runs the Python suites of txe/kubeguard (TXE-8039): kube_run.py with its pinned B5
// custody copy, and the kubectl-context-guard PreToolUse hook.
//
// The suites contact no cluster, run no kubectl and use no network. Their fixtures are inert files in
// directories they create and remove themselves. They always run in PURE mode here: KUBEGUARD_REAL_CHILDREN is
// removed from their environment, so RealChildrenThroughB5 (real, bounded children through B5, macOS only)
// never runs under go test. Off macOS, test_kube_run.py also drives kube-run's real transport, and checks that
// B5 refuses before any child exists (KR26).
package kubeguard_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func python(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("kube-run and the hook target macOS and Linux hosts")
	}
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	return py
}

// pureEnv is the test's environment without the real-children opt-in.
func pureEnv() []string {
	env := []string{}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "KUBEGUARD_REAL_CHILDREN=") {
			env = append(env, kv)
		}
	}
	return env
}

// runSuite runs one unittest file with python3 -I -B and fails on a non-zero exit or a missing OK line. The
// whole output is logged, so a skipped or failed case is visible in the test log.
func runSuite(t *testing.T, file string) {
	t.Helper()
	py := python(t)
	path, err := filepath.Abs(file)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, "-I", "-B", path, "-v")
	cmd.Env = pureEnv()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	t.Log(out.String())
	require.NoError(t, runErr, "%s failed", file)
	require.Regexp(t, `(?m)^OK( \(skipped=\d+\))?$`, out.String(), "%s did not report OK", file)
	require.NotContains(t, out.String(), "kubeguard fixture root (retained)", "%s ran real children", file)
}

func TestKubeRun(t *testing.T) {
	runSuite(t, "test_kube_run.py")
}

func TestContextGuardHook(t *testing.T) {
	runSuite(t, "test_kubectl_context_guard.py")
}
