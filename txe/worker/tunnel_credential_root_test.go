// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package worker_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The ownership negatives need a second account, which only root can arrange.
// They run only as uid 0 with TXE7864_ROOT_FIXTURE=1: in a disposable
// container with no network, never on a developer machine or a shared runner
// (TXE-7864). Root builds the fixture; the script itself runs as an
// unprivileged account (setpriv to rootFixtureUser), and another account
// (rootFixtureOther) owns what it must refuse.
const (
	rootFixtureUser  = 1000
	rootFixtureOther = 65534
)

// stubKubectlRoot is stubKubectl for a run as rootFixtureUser. On create token
// with $STUB_HANDOFF set it asks root, through two FIFOs, to give the candidate
// to another account before the writer opens it: it cannot chown itself.
const stubKubectlRoot = `#!/bin/sh
echo "$*" >> "$STUB_CALLS"
case "$*" in
  *"get ns kube-system"*) printf '%s' f06a22da-b29c-4ac7-9b2b-b5dad50aed6a ;;
  *"config view"*"context.cluster"*) printf '%s' c1 ;;
  *"config view"*"cluster.server"*) printf '%s' https://127.0.0.1:1 ;;
  *"config view"*"certificate-authority-data"*) ;;
  *"create token"*)
    if [ -n "${STUB_HANDOFF:-}" ]; then
      for c in "$TXE_DAGU_HOME"/tunnel/kubeconfig.??????; do
        printf '%s\n' "$c" > "$STUB_HANDOFF/ask"
        read -r _ < "$STUB_HANDOFF/done"
      done
    fi
    printf '%s\n' "$STUB_TOKEN" ;;
  *"--subresource=portforward"*) echo yes ;;
  *"get secrets"*) echo no; exit 1 ;;
  *) echo "stub kubectl: unexpected call" >&2; exit 98 ;;
esac
`

func requireRootFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("TXE7864_ROOT_FIXTURE") != "1" {
		t.Skip("root fixture only: uid 0 with TXE7864_ROOT_FIXTURE=1, in an isolated container")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skip("setpriv is needed to run the script as an unprivileged account")
	}
	return setpriv
}

// rootFixtureRun runs tunnel-credential.sh as rootFixtureUser after prepare
// (as root) has built the TXE home; handoff, when true, serves the stub's
// request to give the candidate to rootFixtureOther.
func rootFixtureRun(t *testing.T, prepare func(home string), handoff bool) tunnelRun {
	t.Helper()
	setpriv := requireRootFixture(t)
	script, err := filepath.Abs("tunnel-credential.sh")
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	python, err := exec.LookPath("python3")
	require.NoError(t, err)

	// Everything the unprivileged run reads or writes is reachable by it.
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.Chmod(base, 0o755)) //nolint:gosec // the unprivileged run must reach it
	tools := filepath.Join(base, "tools")
	require.NoError(t, os.Mkdir(tools, 0o755)) //nolint:gosec // as above
	require.NoError(t, os.WriteFile(filepath.Join(tools, "kubectl"), []byte(stubKubectlRoot), 0o755)) //nolint:gosec // a test's stub
	calls := filepath.Join(base, "calls")
	require.NoError(t, os.WriteFile(calls, nil, 0o666)) //nolint:gosec // the stub appends as the unprivileged account
	require.NoError(t, os.Chmod(calls, 0o666))           //nolint:gosec // as above, past the umask

	home := filepath.Join(base, "txe dagu")
	r := tunnelRun{home: home, tunnelDir: filepath.Join(home, "tunnel")}
	prepare(home)

	env := []string{
		"HOME=" + os.Getenv("HOME"),
		"TXE_DAGU_HOME=" + home,
		"PATH=" + tools + ":" + filepath.Dir(python) + ":/usr/bin:/bin",
		"STUB_CALLS=" + calls,
		"STUB_TOKEN=eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":2000000000}`)) + "." + tokenMarker,
	}
	served := make(chan error, 1)
	if handoff {
		dir := filepath.Join(base, "handoff")
		require.NoError(t, os.Mkdir(dir, 0o755)) //nolint:gosec // as above
		for _, f := range []string{"ask", "done"} {
			require.NoError(t, syscall.Mkfifo(filepath.Join(dir, f), 0o666))
			require.NoError(t, os.Chmod(filepath.Join(dir, f), 0o666)) //nolint:gosec // as above
		}
		env = append(env, "STUB_HANDOFF="+dir)
		go func() { served <- serveHandoff(dir) }()
	} else {
		served <- nil
	}

	cmd := exec.Command(setpriv, "--reuid="+itoa(rootFixtureUser), "--regid="+itoa(rootFixtureUser), "--clear-groups", "--", bash, script) //nolint:gosec // fixed arguments
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		r.code = exit.ExitCode()
	} else {
		require.NoError(t, err)
	}
	r.stdout, r.stderr = stdout.String(), stderr.String()
	require.NoError(t, <-served)
	if b, err := os.ReadFile(calls); err == nil {
		r.calls = string(b)
	}
	assert.NotContains(t, r.stdout+r.stderr, tokenMarker, "the token was printed")
	return r
}

// serveHandoff gives each candidate the stub names to rootFixtureOther, then
// lets the stub go on.
func serveHandoff(dir string) error {
	ask, err := os.Open(filepath.Join(dir, "ask"))
	if err != nil {
		return err
	}
	defer func() { _ = ask.Close() }()
	path, err := bufio.NewReader(ask).ReadString('\n')
	if err != nil {
		return err
	}
	if err := os.Lchown(strings.TrimSuffix(path, "\n"), rootFixtureOther, rootFixtureOther); err != nil {
		return err
	}
	done, err := os.OpenFile(filepath.Join(dir, "done"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = done.WriteString("ok\n")
	if cerr := done.Close(); err == nil {
		err = cerr
	}
	return err
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			return string(b[i:])
		}
	}
}

// A tunnel directory, or a directory above it, that belongs to another
// account is refused before any token is asked for; a candidate given to
// another account before the write is never written, the run fails, and
// cleanup reports it.
func TestTunnelCredentialOwnershipAsRoot(t *testing.T) {
	t.Run("the tunnel directory belongs to another account", func(t *testing.T) {
		r := rootFixtureRun(t, func(home string) {
			require.NoError(t, os.MkdirAll(filepath.Join(home, "tunnel"), 0o700))
			require.NoError(t, os.Chown(home, rootFixtureUser, rootFixtureUser))
			require.NoError(t, os.Chown(filepath.Join(home, "tunnel"), rootFixtureOther, rootFixtureOther))
		}, false)
		assert.Equal(t, 1, r.code, "stderr:\n%s", r.stderr)
		assert.NotContains(t, r.calls, "create token", "a token was asked for")
	})
	t.Run("a directory above it belongs to another account", func(t *testing.T) {
		r := rootFixtureRun(t, func(home string) {
			require.NoError(t, os.MkdirAll(filepath.Join(home, "tunnel"), 0o700))
			require.NoError(t, os.Chmod(home, 0o755)) //nolint:gosec // the account must reach its tunnel directory
			require.NoError(t, os.Chown(home, rootFixtureOther, rootFixtureOther))
			require.NoError(t, os.Chown(filepath.Join(home, "tunnel"), rootFixtureUser, rootFixtureUser))
		}, false)
		assert.Equal(t, 1, r.code, "stderr:\n%s", r.stderr)
		assert.Contains(t, r.stderr, "belongs to another account")
		assert.NotContains(t, r.calls, "create token", "a token was asked for")
	})
	t.Run("the candidate is given to another account", func(t *testing.T) {
		r := rootFixtureRun(t, func(home string) {
			require.NoError(t, os.MkdirAll(filepath.Join(home, "tunnel"), 0o700))
			require.NoError(t, os.Chown(home, rootFixtureUser, rootFixtureUser))
			require.NoError(t, os.Chown(filepath.Join(home, "tunnel"), rootFixtureUser, rootFixtureUser))
		}, true)
		assert.Equal(t, 1, r.code, "stderr:\n%s", r.stderr)
		assert.Contains(t, r.stderr, "refusing")
		assert.NotEmpty(t, fatalLines(r.stderr), "another account's candidate is a custody failure:\n%s", r.stderr)
		assert.NotContains(t, r.calls, "auth can-i", "the candidate was used")
		assert.NoFileExists(t, filepath.Join(r.tunnelDir, "kubeconfig"))
	})
}
