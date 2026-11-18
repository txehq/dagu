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
echo "$*" >> "$STUB_CALLS"
case "$*" in
  *"get ns kube-system"*) printf '%s' f06a22da-b29c-4ac7-9b2b-b5dad50aed6a ;;
  *"config view"*"context.cluster"*) printf '%s' c1 ;;
  *"config view"*"cluster.server"*) printf '%s' https://127.0.0.1:1 ;;
  *"config view"*"certificate-authority-data"*) ;;
  *"create token"*)
    # Before the token reaches the writer, tamper with the candidate the way
    # $STUB_SWAP says: the writer opens it only after kubectl has finished.
    for c in "$TXE_DAGU_HOME"/tunnel/kubeconfig.??????; do
      case "${STUB_SWAP:-}" in
        symlink) "$REAL_RM" -f "$c"; ln -s "$STUB_OUTSIDE" "$c" ;;
        expires-link) ln -s "$STUB_OUTSIDE" "$c.expires" ;;
        hardlink) ln "$c" "$STUB_OUTSIDE.link" ;;
        mode) chmod 644 "$c" ;;
        chown) chown 65534 "$c" ;;
      esac
    done
    printf '%s\n' "$STUB_TOKEN"; exit "${STUB_TOKEN_RC:-0}" ;;
  *"--subresource=portforward"*)
    # After the writer: swap the written candidate for a link, as late as the
    # script allows, with $STUB_LATE_SWAP.
    for c in "$TXE_DAGU_HOME"/tunnel/kubeconfig.??????; do
      case "${STUB_LATE_SWAP:-}" in
        symlink) "$REAL_RM" -f "$c"; ln -s "$STUB_OUTSIDE" "$c" ;;
        mode) chmod 644 "$c" ;;
      esac
    done
    echo yes; exit "${STUB_PORTFORWARD:-0}" ;;
  *"get secrets"*)
    for c in "$TXE_DAGU_HOME"/tunnel/kubeconfig.??????; do [ ! -L "$c" ] || echo "followed a link" >> "$STUB_CALLS"; done
    echo no; exit 1 ;;
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

// stubMv stands in for mv: with $STUB_MV=fail-expires the move of the
// .expires fails; every other move is the real one ($REAL_MV).
const stubMv = `#!/bin/sh
for last in "$@"; do :; done
case "${STUB_MV:-}:$last" in
  fail-expires:*.expires) echo "mv: refused by the test's stub" >&2; exit 1 ;;
esac
exec "$REAL_MV" "$@"
`

type tunnelRun struct {
	home, tunnelDir string
	outside         string // a file outside the tunnel directory
	code            int
	stdout, stderr  string
	calls           string // the stub kubectl's calls, one per line
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
	return runTunnelCredentialWith(t, nil, env...)
}

// runTunnelCredentialWith runs it after prepare, given the TXE home and a
// file outside it, has set the scene.
func runTunnelCredentialWith(t *testing.T, prepare func(home, outside string), env ...string) tunnelRun {
	t.Helper()
	script, err := filepath.Abs("tunnel-credential.sh")
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	realRm, err := exec.LookPath("rm")
	require.NoError(t, err)
	realMv, err := exec.LookPath("mv")
	require.NoError(t, err)
	python, err := exec.LookPath("python3")
	require.NoError(t, err, "python3 writes the candidate")

	tools := t.TempDir()
	for name, body := range map[string]string{"kubectl": stubKubectl, "rm": stubRm, "mv": stubMv} {
		require.NoError(t, os.WriteFile(filepath.Join(tools, name), []byte(body), 0o700)) //nolint:gosec // a test's stub
	}
	home := filepath.Join(t.TempDir(), "txe dagu")
	r := tunnelRun{home: home, tunnelDir: filepath.Join(home, "tunnel"), outside: filepath.Join(t.TempDir(), "outside")}
	require.NoError(t, os.WriteFile(r.outside, []byte("not a credential\n"), 0o600))
	if prepare != nil {
		prepare(home, r.outside)
	}
	calls := filepath.Join(tools, "calls")
	// A test that locks the directory unlocks it so that TempDir can remove it.
	t.Cleanup(func() { _ = os.Chmod(r.tunnelDir, 0o700) })

	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":2000000000}`))
	cmd := exec.Command(bash, script)
	cmd.Env = append([]string{
		"HOME=" + os.Getenv("HOME"),
		"TXE_DAGU_HOME=" + home,
		"PATH=" + tools + ":" + filepath.Dir(python) + ":/usr/bin:/bin",
		"REAL_RM=" + realRm,
		"REAL_MV=" + realMv,
		"STUB_CALLS=" + calls,
		"STUB_OUTSIDE=" + r.outside,
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
	if b, err := os.ReadFile(calls); err == nil {
		r.calls = string(b)
	}
	assert.NotContains(t, r.stdout+r.stderr, tokenMarker, "the token was printed")
	if b, err := os.ReadFile(r.outside); err == nil {
		assert.NotContains(t, string(b), tokenMarker, "the token was written outside the tunnel directory")
	}
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
	// The pair: the live .expires is the new token's expiry.
	exp, err := os.ReadFile(filepath.Join(r.tunnelDir, "kubeconfig.expires"))
	require.NoError(t, err)
	assert.Equal(t, "2000000000\n", string(exp))
	assert.NoFileExists(t, filepath.Join(r.tunnelDir, "kubeconfig.expires.expires"))
}

// The kubeconfig and its .expires stay a pair: when the second move fails,
// the old expiry is not left beside the new credential, and the run fails.
func TestTunnelCredentialKeepsThePairWhenExpiresCannotMove(t *testing.T) {
	r := runTunnelCredentialWith(t, func(home, _ string) {
		require.NoError(t, os.MkdirAll(filepath.Join(home, "tunnel"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(home, "tunnel", "kubeconfig.expires"), []byte("1\n"), 0o600))
	}, "STUB_MV=fail-expires")
	assert.Equal(t, 1, r.code, "stderr:\n%s", r.stderr)
	assert.Contains(t, r.stderr, "its expiry record could not be moved")
	assert.NoFileExists(t, filepath.Join(r.tunnelDir, "kubeconfig.expires"), "the old expiry was left beside the new credential")
	assert.Empty(t, r.candidates(t))
	assert.Empty(t, fatalLines(r.stderr))
}

// A candidate swapped for a link after it was written is not used or moved
// over the live kubeconfig: the run fails, custody is reported, and the
// outside file keeps its content (independent review of PR 293).
func TestTunnelCredentialRefusesACandidateSwappedAfterTheWrite(t *testing.T) {
	for _, tc := range []struct {
		swap  string
		fatal bool // a link is a custody failure; a mode change is refused
	}{{"symlink", true}, {"mode", false}} {
		t.Run(tc.swap, func(t *testing.T) {
			r := runTunnelCredential(t, "STUB_LATE_SWAP="+tc.swap)
			assert.Equal(t, 1, r.code, "stderr:\n%s", r.stderr)
			assert.Contains(t, r.stderr, "no longer the private file this run wrote")
			assert.Equal(t, tc.fatal, len(fatalLines(r.stderr)) > 0, "custody FATAL:\n%s", r.stderr)
			assert.NotContains(t, r.calls, "get secrets", "the changed candidate was used again")
			assert.NotContains(t, r.calls, "followed a link")
			assert.NoFileExists(t, filepath.Join(r.tunnelDir, "kubeconfig"), "a changed candidate replaced the live kubeconfig")
			b, err := os.ReadFile(r.outside)
			require.NoError(t, err)
			assert.Equal(t, "not a credential\n", string(b))
			assert.Empty(t, r.candidates(t))
		})
	}
}

// When the old .expires can be neither replaced nor removed, the run fails
// and names it, since it now disagrees with the new credential.
func TestTunnelCredentialReportsAnExpiresItCannotRemove(t *testing.T) {
	r := runTunnelCredentialWith(t, func(home, _ string) {
		require.NoError(t, os.MkdirAll(filepath.Join(home, "tunnel"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(home, "tunnel", "kubeconfig.expires"), []byte("1\n"), 0o600))
	}, "STUB_MV=fail-expires", "STUB_RM=fail")
	assert.Equal(t, 1, r.code, "stderr:\n%s", r.stderr)
	live := filepath.Join(r.tunnelDir, "kubeconfig.expires")
	assert.Contains(t, r.stderr, "txe-dagu: FATAL: "+live+" may still hold the previous credential's expiry")
	assert.Contains(t, r.stderr, "the old one could not be removed")
	assert.NotContains(t, r.stderr, "was removed so that", "the run claimed a removal that failed")
}

// A candidate that is not the private file this run made is never written
// through: a symbolic link to a file outside, a planted .expires link, a
// second hard link, or a mode open to others. The run fails, the outside file
// keeps its content, and a link left in the candidate's place is reported
// and removed without touching its target.
func TestTunnelCredentialRefusesATamperedCandidate(t *testing.T) {
	for _, tc := range []struct {
		swap     string
		reported bool // custody FATAL for the link
		root     bool
	}{
		{swap: "symlink", reported: true},
		{swap: "expires-link", reported: true},
		{swap: "hardlink"},
		{swap: "mode"},
		{swap: "chown", reported: true, root: true},
	} {
		t.Run(tc.swap, func(t *testing.T) {
			if tc.root && os.Geteuid() != 0 {
				t.Skip("only root can give the candidate to another account")
			}
			r := runTunnelCredential(t, "STUB_SWAP="+tc.swap)
			assert.Equal(t, 1, r.code, "stdout:\n%s\nstderr:\n%s", r.stdout, r.stderr)
			assert.Contains(t, r.stderr, "refusing")
			b, err := os.ReadFile(r.outside)
			require.NoError(t, err, "the outside file was removed")
			assert.Equal(t, "not a credential\n", string(b))
			if tc.swap == "hardlink" {
				// The second link is the candidate's own inode, never written.
				b, err := os.ReadFile(r.outside + ".link")
				require.NoError(t, err)
				assert.Empty(t, string(b))
			}
			if tc.reported {
				assert.NotEmpty(t, fatalLines(r.stderr), "a replaced candidate is a custody failure:\n%s", r.stderr)
			}
			assert.Empty(t, r.candidates(t))
			assert.NoFileExists(t, filepath.Join(r.tunnelDir, "kubeconfig"), "a refused candidate replaced the live kubeconfig")
			assert.NotContains(t, r.calls, "auth can-i", "a refused candidate was used")
		})
	}
}

// The token is asked for only when the tunnel directory is this user's, not a
// link, and not writable by group or others.
func TestTunnelCredentialRefusesAnUnsafeDirectory(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(home, outside string)
	}{
		{"group writable", func(home, _ string) {
			require.NoError(t, os.MkdirAll(filepath.Join(home, "tunnel"), 0o700))
			require.NoError(t, os.Chmod(filepath.Join(home, "tunnel"), 0o770)) //nolint:gosec // the unsafe mode under test
		}},
		{"group readable", func(home, _ string) {
			require.NoError(t, os.MkdirAll(filepath.Join(home, "tunnel"), 0o700))
			require.NoError(t, os.Chmod(filepath.Join(home, "tunnel"), 0o750)) //nolint:gosec // the unsafe mode under test
		}},
		{"world writable", func(home, _ string) {
			require.NoError(t, os.MkdirAll(filepath.Join(home, "tunnel"), 0o700))
			require.NoError(t, os.Chmod(filepath.Join(home, "tunnel"), 0o703)) //nolint:gosec // the unsafe mode under test
		}},
		{"a symbolic link", func(home, outside string) {
			require.NoError(t, os.MkdirAll(home, 0o700))
			require.NoError(t, os.Symlink(filepath.Dir(outside), filepath.Join(home, "tunnel")))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runTunnelCredentialWith(t, tc.prepare)
			assert.Equal(t, 1, r.code, "stderr:\n%s", r.stderr)
			assert.Contains(t, r.stderr, "refusing to write a credential there")
			assert.NotContains(t, r.calls, "create token", "a token was asked for")
		})
	}
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
