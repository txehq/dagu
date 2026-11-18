// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package worker_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenMarker is in the stub's token. No output of tunnel-credential.sh may
// carry it, whatever happens to the candidate.
const tokenMarker = "TXE7864-TOKEN-NEVER-PRINTED"

// stubKubectl stands in for kubectl: the real one is never run. It answers the
// script's reads, issues a token carrying tokenMarker (exiting with
// $STUB_TOKEN_RC after writing it), and answers the two permission checks with
// $STUB_PORTFORWARD (0 = allowed) and "cannot read Secrets".
const stubKubectl = `#!/bin/sh
case "$*" in
  *"get ns kube-system"*) printf '%s' f06a22da-b29c-4ac7-9b2b-b5dad50aed6a ;;
  *"config view"*"context.cluster"*) printf '%s' c1 ;;
  *"config view"*"cluster.server"*) printf '%s' https://127.0.0.1:1 ;;
  *"config view"*"certificate-authority-data"*) ;;
  *"create token"*) printf '%s\n' "$STUB_TOKEN"; exit "${STUB_TOKEN_RC:-0}" ;;
  *"--subresource=portforward"*) echo yes; exit "${STUB_PORTFORWARD:-0}" ;;
  *"get secrets"*) echo no; exit 1 ;;
  *) echo "stub kubectl: unexpected call" >&2; exit 98 ;;
esac
`

// stubRm stands in for rm, by $STUB_RM: "fail" removes nothing and fails;
// "keep" removes nothing and reports success; "plant" reports success and
// leaves a file at the path (after a renewal that passed, the candidate has
// already been moved, so this is the only way one is still there); "lock"
// removes, then makes the parent unsearchable; anything else is the real rm
// ($REAL_RM).
const stubRm = `#!/bin/sh
for last in "$@"; do :; done
case "${STUB_RM:-}" in
  fail) echo "rm: $last: refused by the test's stub" >&2; exit 1 ;;
  keep) exit 0 ;;
  plant) : >"$last"; exit 0 ;;
  lock) "$REAL_RM" "$@" || exit; chmod 000 "$(dirname "$last")"; exit 0 ;;
  *) exec "$REAL_RM" "$@" ;;
esac
`

type tunnelRun struct {
	home, tunnelDir string
	code            int
	stdout, stderr  string
}

// candidates are the files the script left in the tunnel directory beside
// the live kubeconfig: kubeconfig.XXXXXX and its .expires.
func (r tunnelRun) candidates(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(r.tunnelDir)
	require.NoError(t, err)
	var out []string
	for _, e := range ents {
		if n := e.Name(); strings.HasPrefix(n, "kubeconfig.") && !strings.HasSuffix(n, ".expires") {
			out = append(out, filepath.Join(r.tunnelDir, n))
		}
	}
	return out
}

// runTunnelCredential runs tunnel-credential.sh with kubectl and rm stubbed.
// HOME is inherited, never replaced: the script's state goes to an explicit
// TXE_DAGU_HOME.
func runTunnelCredential(t *testing.T, env ...string) tunnelRun {
	t.Helper()
	script, err := filepath.Abs("tunnel-credential.sh")
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	realRm, err := exec.LookPath("rm")
	require.NoError(t, err)
	python, err := exec.LookPath("python3")
	require.NoError(t, err, "python3 writes the candidate")

	tools := t.TempDir()
	for name, body := range map[string]string{"kubectl": stubKubectl, "rm": stubRm} {
		require.NoError(t, os.WriteFile(filepath.Join(tools, name), []byte(body), 0o700)) //nolint:gosec // a test's stub
	}
	home := filepath.Join(t.TempDir(), "txe dagu")
	r := tunnelRun{home: home, tunnelDir: filepath.Join(home, "tunnel")}
	// A test that locks the directory unlocks it so that TempDir can remove it.
	t.Cleanup(func() { _ = os.Chmod(r.tunnelDir, 0o700) })

	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":2000000000}`))
	cmd := exec.Command(bash, script)
	cmd.Env = append([]string{
		"HOME=" + os.Getenv("HOME"),
		"TXE_DAGU_HOME=" + home,
		"PATH=" + tools + ":" + filepath.Dir(python) + ":/usr/bin:/bin",
		"REAL_RM=" + realRm,
		"STUB_TOKEN=eyJhbGciOiJSUzI1NiJ9." + payload + "." + tokenMarker,
	}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if err != nil {
		require.True(t, errors.As(err, &exit), "run: %v", err)
		r.code = exit.ExitCode()
	}
	r.stdout, r.stderr = stdout.String(), stderr.String()
	assert.NotContains(t, r.stdout+r.stderr, tokenMarker, "the token was printed")
	return r
}

func fatalLines(stderr string) []string {
	var out []string
	for l := range strings.SplitSeq(stderr, "\n") {
		if strings.HasPrefix(l, "txe-dagu: FATAL:") {
			out = append(out, l)
		}
	}
	return out
}

// A renewal that passes replaces the live kubeconfig, leaves no candidate and
// reports nothing.
func TestTunnelCredentialSuccessLeavesNoCandidate(t *testing.T) {
	r := runTunnelCredential(t)
	require.Equal(t, 0, r.code, "stdout:\n%s\nstderr:\n%s", r.stdout, r.stderr)
	assert.Empty(t, r.candidates(t))
	assert.Empty(t, fatalLines(r.stderr))
	live, err := os.ReadFile(filepath.Join(r.tunnelDir, "kubeconfig"))
	require.NoError(t, err)
	assert.Contains(t, string(live), tokenMarker, "the live kubeconfig holds the new token")
	assert.Contains(t, r.stdout, "wrote ")
}

// A refused renewal keeps the previous credential, removes its candidate and
// fails with die's status, with nothing to report about custody.
func TestTunnelCredentialRefusedRenewalRemovesItsCandidate(t *testing.T) {
	r := runTunnelCredential(t, "STUB_PORTFORWARD=1")
	assert.Equal(t, 1, r.code)
	assert.Contains(t, r.stderr, "cannot port-forward")
	assert.Empty(t, r.candidates(t))
	assert.Empty(t, fatalLines(r.stderr))
	assert.NoFileExists(t, filepath.Join(r.tunnelDir, "kubeconfig"))
}

// Each way the candidate can outlive the script, after a renewal that
// succeeded or one that had already failed. A success turns into a failure;
// an earlier failure keeps its own status. Either way each candidate path is
// named on a FATAL line, and the token never is.
func TestTunnelCredentialUnprovenRemovalFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		code int
		left bool // the candidate is still there afterwards
		lock bool // needs a directory its owner cannot search
	}{
		{name: "rm fails after a success", env: []string{"STUB_RM=fail"}, code: 1},
		{name: "rm reports success and a file is still there", env: []string{"STUB_RM=plant"}, code: 1, left: true},
		{name: "the parent cannot be searched", env: []string{"STUB_RM=lock"}, code: 1, lock: true},
		{name: "a leftover after a refused renewal", env: []string{"STUB_RM=keep", "STUB_PORTFORWARD=1"}, code: 1, left: true},
		{name: "a leftover after a failure with its own status", env: []string{"STUB_RM=keep", "STUB_TOKEN_RC=7"}, code: 7, left: true},
		{name: "rm fails after a failure with its own status", env: []string{"STUB_RM=fail", "STUB_TOKEN_RC=7"}, code: 7, left: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.lock && os.Geteuid() == 0 {
				t.Skip("root searches a mode-000 directory")
			}
			r := runTunnelCredential(t, tc.env...)
			assert.Equal(t, tc.code, r.code, "stdout:\n%s\nstderr:\n%s", r.stdout, r.stderr)
			fatal := fatalLines(r.stderr)
			require.Len(t, fatal, 2, "one FATAL line per candidate path:\n%s", r.stderr)
			if tc.lock {
				// The script cannot see into the directory, so neither can the
				// test; unlock it to read the paths it named.
				require.NoError(t, os.Chmod(r.tunnelDir, 0o700))
			}
			cands := r.candidates(t)
			if tc.left {
				// The failure came after the candidate was written.
				require.Len(t, cands, 1)
			}
			for _, l := range fatal {
				assert.True(t, strings.HasPrefix(l, "txe-dagu: FATAL: "+filepath.Join(r.tunnelDir, "kubeconfig.")), "FATAL line names no candidate: %s", l)
				assert.Contains(t, l, "may still be on disk")
			}
			if len(cands) == 1 {
				assert.Contains(t, fatal[0], cands[0]+" ")
				assert.Contains(t, fatal[1], cands[0]+".expires ")
			}
		})
	}
}
