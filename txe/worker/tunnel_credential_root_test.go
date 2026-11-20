// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package worker_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

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
	// rootFixtureBound caps one run of the script: a stub that blocks on a
	// FIFO must fail the test, not hang it until go test's own timeout.
	rootFixtureBound = 2 * time.Minute
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

// releaseFIFO opens a FIFO read-write and closes it, which on Linux never
// blocks and ends a peer blocked opening the other end: that peer then reads
// EOF. The root fixture runs only on Linux (setpriv).
func releaseFIFO(path string) {
	if f, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
		_ = f.Close()
	}
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
	// t.TempDir makes its per-test parent 0700 (os.MkdirTemp), so that parent
	// is opened for traversal too; both stay root's and closed to writes, which
	// the script's ancestor check accepts.
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.Chmod(filepath.Dir(base), 0o711)) //nolint:gosec // traversal only, for the unprivileged run
	require.NoError(t, os.Chmod(base, 0o755))               //nolint:gosec // the unprivileged run must reach it
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
	var handoffDir string
	served := make(chan error, 1)
	if handoff {
		handoffDir = filepath.Join(base, "handoff")
		require.NoError(t, os.Mkdir(handoffDir, 0o755)) //nolint:gosec // as above
		for _, f := range []string{"ask", "done"} {
			require.NoError(t, syscall.Mkfifo(filepath.Join(handoffDir, f), 0o666))
			require.NoError(t, os.Chmod(filepath.Join(handoffDir, f), 0o666)) //nolint:gosec // as above
		}
		env = append(env, "STUB_HANDOFF="+handoffDir)
		go func() { served <- serveHandoff(handoffDir) }()
	} else {
		served <- nil
	}

	ctx, cancel := context.WithTimeout(t.Context(), rootFixtureBound)
	defer cancel()
	cmd := exec.CommandContext(ctx, setpriv, "--reuid="+strconv.Itoa(rootFixtureUser), "--regid="+strconv.Itoa(rootFixtureUser), "--clear-groups", "--", bash, script) //nolint:gosec // fixed arguments
	cmd.Env = env
	// A stub child still blocked on a FIFO keeps the output pipes open after
	// bash is killed; Run returns anyway once this has passed.
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	require.NoError(t, ctx.Err(), "the script did not finish within %s:\nstderr:\n%s", rootFixtureBound, stderr.String())
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		r.code = exit.ExitCode()
	} else {
		require.NoError(t, err)
	}
	r.stdout, r.stderr = stdout.String(), stderr.String()
	if handoff {
		// The script has exited. If its stub never asked, the server is still
		// blocked opening ask: release it, and it reports that it got nothing.
		releaseFIFO(filepath.Join(handoffDir, "ask"))
	}
	require.NoError(t, <-served, "the handoff to another account did not happen")
	if b, err := os.ReadFile(calls); err == nil {
		r.calls = string(b)
	}
	assert.NotContains(t, r.stdout+r.stderr, tokenMarker, "the token was printed")
	return r
}

// errNoHandoff is serveHandoff's report when the stub never asked.
var errNoHandoff = errors.New("the stub never asked for the candidate to be handed to another account")

// serveHandoff gives the candidate the stub names to rootFixtureOther, then
// lets the stub go on. When it fails after the stub asked, it still releases
// the stub, so that the script goes on and the test reports the failure.
func serveHandoff(dir string) (err error) {
	ask, err := os.Open(filepath.Join(dir, "ask"))
	if err != nil {
		return err
	}
	defer func() { _ = ask.Close() }()
	path, err := bufio.NewReader(ask).ReadString('\n')
	if err != nil {
		return errNoHandoff
	}
	defer func() {
		if err != nil {
			releaseFIFO(filepath.Join(dir, "done"))
		}
	}()
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

// A tunnel directory, or a directory above it, that belongs to another
// account is refused before any token is asked for; a candidate given to
// another account before the write is never written, the run fails, and
// cleanup reports it.
func TestTunnelCredentialOwnershipAsRoot(t *testing.T) {
	t.Run("the tunnel directory belongs to another account", func(t *testing.T) {
		r := rootFixtureRun(t, func(home string) {
			require.NoError(t, os.MkdirAll(filepath.Join(home, "tunnel"), 0o700))
			require.NoError(t, os.Chown(home, rootFixtureUser, rootFixtureUser))
			// Searchable, so that the script resolves it and its ownership
			// check, not a failed cd, is what refuses it.
			require.NoError(t, os.Chmod(filepath.Join(home, "tunnel"), 0o755)) //nolint:gosec // the other account's directory under test
			require.NoError(t, os.Chown(filepath.Join(home, "tunnel"), rootFixtureOther, rootFixtureOther))
		}, false)
		assert.Equal(t, 1, r.code, "stderr:\n%s", r.stderr)
		assert.Contains(t, r.stderr, "is not a directory this user owns")
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
		fatal := fatalLines(r.stderr)
		require.Len(t, fatal, 1, "another account's candidate is a custody failure:\n%s", r.stderr)
		assert.Contains(t, fatal[0], "a file of another account")
		assert.NotContains(t, r.calls, "auth can-i", "the candidate was used")
		assert.NoFileExists(t, filepath.Join(r.tunnelDir, "kubeconfig"))
		assert.Empty(t, r.candidates(t), "the other account's candidate was left in the tunnel directory")
	})
}
