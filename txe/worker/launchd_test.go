// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLaunchctl is a launchctl on PATH that answers from per-subcommand exit-code
// sequences and records every call (TXE-4185). Each sequence file holds one exit
// code per line; a call consumes the first line and the last line repeats once the
// file has only one left. A bootstrap while print would still answer 0 (the
// service is still present) fails with launchd's "5: Input/output error", which is
// what the real launchd does in the window after bootout returns.
type fakeLaunchctl struct {
	dir, state string
}

func newFakeLaunchctl(t *testing.T, bootout, print, bootstrap string) fakeLaunchctl {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the worker scripts run on the macOS worker only")
	}
	f := fakeLaunchctl{dir: t.TempDir(), state: t.TempDir()}
	for name, seq := range map[string]string{"bootout": bootout, "print": print, "bootstrap": bootstrap} {
		require.NoError(t, os.WriteFile(filepath.Join(f.state, name), []byte(strings.ReplaceAll(strings.TrimSpace(seq), " ", "\n")+"\n"), 0o600))
	}
	script := `#!/usr/bin/env bash
set -euo pipefail
state="$FAKE_LAUNCHCTL_STATE"
printf '%s\n' "$*" >>"$state/calls"
sub="$1"
next() { # pop the first exit code of "$1", keeping the last one
  local f="$state/$1" code
  code="$(head -n1 "$f")"
  if [ "$(wc -l <"$f")" -gt 1 ]; then tail -n +2 "$f" >"$f.tmp" && mv "$f.tmp" "$f"; fi
  printf '%s' "$code"
}
case "$sub" in
  bootout) rc="$(next bootout)"; [ "$rc" = 0 ] || echo "Boot-out failed: $rc: No such process" >&2; exit "$rc" ;;
  print)
    rc="$(next print)"
    case "$rc" in
      0) printf '\tstate = running\n\tpid = 4242\n' ;;
      113) echo "Bad request."; echo "Could not find service \"$2\" in domain for user gui: 501" >&2 ;;
      *) echo "Could not print domain: $rc: Domain does not support specified action" >&2 ;;
    esac
    exit "$rc" ;;
  bootstrap)
    if [ "$(head -n1 "$state/print")" = 0 ]; then echo "Bootstrap failed: 5: Input/output error" >&2; exit 5; fi
    rc="$(next bootstrap)"
    case "$rc" in
      0) ;;
      5) echo "Bootstrap failed: 5: Input/output error" >&2 ;;
      *) echo "Bootstrap failed: $rc: Service is disabled" >&2 ;;
    esac
    exit "$rc" ;;
  *) echo "fake launchctl: unexpected $sub" >&2; exit 99 ;;
esac
`
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, "launchctl"), []byte(script), 0o700))
	return f
}

// calls lists the recorded launchctl invocations, one argv line each.
func (f fakeLaunchctl) calls(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.state, "calls"))
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (f fakeLaunchctl) count(t *testing.T, sub string) int {
	t.Helper()
	n := 0
	for _, c := range f.calls(t) {
		if strings.HasPrefix(c, sub+" ") {
			n++
		}
	}
	return n
}

// reload sources lib.sh and runs launchd_reload against the fake, with a short
// poll so a timeout takes milliseconds. It returns stderr and the exit error.
func (f fakeLaunchctl) reload(t *testing.T, waitTries, bootstrapTries int) (stderr string, err error) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	lib, err := filepath.Abs("lib.sh")
	require.NoError(t, err)
	cmd := exec.Command(bash, "-c", `set -euo pipefail; . "$1"; launchd_reload "$2" "$3"`, "bash", lib,
		"com.txe.dagu.test", filepath.Join(f.state, "com.txe.dagu.test.plist"))
	cmd.Env = []string{
		"HOME=" + f.state, "PATH=" + f.dir + ":/usr/bin:/bin", "FAKE_LAUNCHCTL_STATE=" + f.state,
		"TXE_DAGU_LAUNCHD_WAIT_TRIES=" + strconv.Itoa(waitTries), "TXE_DAGU_LAUNCHD_POLL_SECONDS=0.01",
		"TXE_DAGU_LAUNCHD_BOOTSTRAP_TRIES=" + strconv.Itoa(bootstrapTries),
	}
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err = cmd.Run()
	return errOut.String(), err
}

// A loaded service is booted out, seen gone, and bootstrapped exactly once:
// three launchctl calls and no restart of anything.
func TestLaunchdReloadBootsOutWaitsThenBootstraps(t *testing.T) {
	f := newFakeLaunchctl(t, "0", "113", "0")
	_, err := f.reload(t, 40, 3)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"bootout gui/" + uid() + "/com.txe.dagu.test",
		"print gui/" + uid() + "/com.txe.dagu.test",
		"bootstrap gui/" + uid() + " " + filepath.Join(f.state, "com.txe.dagu.test.plist"),
	}, f.calls(t))
}

// A service that was never loaded (bootout "3: No such process") is bootstrapped at
// once: the reload is idempotent and does not fail on an absent service.
func TestLaunchdReloadBootstrapsAnAbsentService(t *testing.T) {
	f := newFakeLaunchctl(t, "3", "113", "0")
	_, err := f.reload(t, 40, 3)
	require.NoError(t, err)
	assert.Equal(t, 1, f.count(t, "bootout"))
	assert.Equal(t, 1, f.count(t, "print"))
	assert.Equal(t, 1, f.count(t, "bootstrap"))
}

// launchd still reports the service for a while after bootout. The plain
// bootout/bootstrap pair fails there with "5: Input/output error" (the -6 cutover,
// 2026-10-14); launchd_reload polls until the service is gone and then bootstraps
// once, so every print precedes the single bootstrap.
func TestLaunchdReloadWaitsForDelayedRemoval(t *testing.T) {
	f := newFakeLaunchctl(t, "0", "0 0 0 113", "0")
	_, err := f.reload(t, 40, 3)
	require.NoError(t, err)
	calls := f.calls(t)
	require.Len(t, calls, 6, calls)
	assert.True(t, strings.HasPrefix(calls[0], "bootout "))
	for _, c := range calls[1:5] {
		assert.True(t, strings.HasPrefix(c, "print "), c)
	}
	assert.True(t, strings.HasPrefix(calls[5], "bootstrap "))

	// Counterfactual: the pair install.sh used before, on the same launchd.
	g := newFakeLaunchctl(t, "0", "0 0 0 113", "0")
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	cmd := exec.Command(bash, "-c", `launchctl bootout "gui/$(id -u)/com.txe.dagu.test" 2>/dev/null || true; launchctl bootstrap "gui/$(id -u)" "$1"`, "bash", filepath.Join(g.state, "com.txe.dagu.test.plist"))
	cmd.Env = []string{"HOME=" + g.state, "PATH=" + g.dir + ":/usr/bin:/bin", "FAKE_LAUNCHCTL_STATE=" + g.state}
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err = cmd.Run()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 5, exitErr.ExitCode())
	assert.Contains(t, errOut.String(), "Bootstrap failed: 5: Input/output error")
}

// If launchd never removes the service within the bound, the install fails, names
// the label, says it was not bootstrapped, and never tries a bootstrap or anything else.
func TestLaunchdReloadFailsWhenTheServiceNeverGoes(t *testing.T) {
	f := newFakeLaunchctl(t, "0", "0", "0")
	stderr, err := f.reload(t, 5, 3)
	require.Error(t, err)
	assert.Contains(t, stderr, "com.txe.dagu.test: still loaded after 5 checks")
	assert.Contains(t, stderr, "not bootstrapped")
	assert.Equal(t, 5, f.count(t, "print"))
	assert.Equal(t, 0, f.count(t, "bootstrap"))
}

// A bootstrap that fails with 5 is retried, a bounded number of times, and succeeds
// when launchd is ready; beyond the bound the install fails naming the label.
func TestLaunchdReloadRetriesBootstrapOnErrorFive(t *testing.T) {
	f := newFakeLaunchctl(t, "0", "113", "5 5 0")
	_, err := f.reload(t, 40, 3)
	require.NoError(t, err)
	assert.Equal(t, 3, f.count(t, "bootstrap"))

	g := newFakeLaunchctl(t, "0", "113", "5")
	stderr, err := g.reload(t, 40, 3)
	require.Error(t, err)
	assert.Contains(t, stderr, "com.txe.dagu.test: launchctl bootstrap failed with 5 (Input/output error) 3 times")
	assert.Equal(t, 3, g.count(t, "bootstrap"))
}

// Errors that are not "service gone" are reported as what they are, with launchd's
// message, and stop the install before any bootstrap: a print on a domain launchd
// cannot act on (125), a bootout that is refused, and a bootstrap error other than 5.
func TestLaunchdReloadReportsUnrelatedErrorsDistinctly(t *testing.T) {
	f := newFakeLaunchctl(t, "0", "125", "0")
	stderr, err := f.reload(t, 40, 3)
	require.Error(t, err)
	assert.Contains(t, stderr, "com.txe.dagu.test: launchctl print failed (125): Could not print domain: 125")
	assert.Equal(t, 0, f.count(t, "bootstrap"))

	g := newFakeLaunchctl(t, "1", "113", "0")
	stderr, err = g.reload(t, 40, 3)
	require.Error(t, err)
	assert.Contains(t, stderr, "com.txe.dagu.test: launchctl bootout failed (1): Boot-out failed: 1")
	assert.Equal(t, 0, g.count(t, "print"))
	assert.Equal(t, 0, g.count(t, "bootstrap"))

	h := newFakeLaunchctl(t, "0", "113", "37")
	stderr, err = h.reload(t, 40, 3)
	require.Error(t, err)
	assert.Contains(t, stderr, "com.txe.dagu.test: launchctl bootstrap failed (37): Bootstrap failed: 37")
	assert.Equal(t, 1, h.count(t, "bootstrap"), "no retry on an error other than 5")
}

func uid() string {
	return strconv.Itoa(os.Getuid())
}
