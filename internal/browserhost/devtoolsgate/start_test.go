// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/procutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartRunsGateAndBrowserProcesses starts the real helper process,
// which launches the fake browser as a process and hands it the pipes the
// way Chrome takes them on this platform.
func TestStartRunsGateAndBrowserProcesses(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	require.NoError(t, err)
	marker := filepath.Join(t.TempDir(), "exit")
	token := NewToken()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handle, err := Start(ctx, self, Config{
		Token:      token,
		Executable: self,
		Args:       fakeBrowserArgs("--exit-marker=" + marker),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = handle.Kill() })

	assert.Equal(t, token, TokenOf(handle.URL))
	assert.Greater(t, handle.PID, 0)
	assert.Greater(t, handle.BrowserPID, 0)
	assert.NotEqual(t, handle.PID, handle.BrowserPID)
	assert.True(t, procutil.IsAlive(handle.PID), "the gate runs")
	assert.True(t, procutil.IsAlive(handle.BrowserPID), "the browser runs")

	status, body := get(t, handle.URL+"/json/version")
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "FakeBrowser/1.0")

	// The browser's arguments carry the pipe flags and never the token.
	c := dialWS(t, "ws"+strings.TrimPrefix(handle.URL, "http")+"/devtools/browser/"+browserIDOf(t, handle.URL), nil)
	var argv struct {
		Argv []string `json:"argv"`
	}
	require.NoError(t, json.Unmarshal(c.mustCall("", "Fake.argv", nil), &argv))
	joined := strings.Join(argv.Argv, " ")
	assert.Contains(t, joined, "--remote-debugging-pipe")
	assert.NotContains(t, joined, "--remote-debugging-port")
	assert.NotContains(t, joined, token)

	// Ending the gate closes the pipe; the browser sees end-of-file and
	// exits on its own.
	require.NoError(t, handle.Kill())
	eventually(t, 15*time.Second, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}, "the browser's exit on end-of-file")
	eventually(t, 15*time.Second, func() bool { return !procutil.IsAlive(handle.PID) }, "the gate's exit")
	assert.NoError(t, handle.Kill(), "ending an ended gate is not an error")
}

// browserIDOf reads the browser id from the gate's /json/version.
func browserIDOf(t *testing.T, baseURL string) string {
	t.Helper()
	_, body := get(t, baseURL+"/json/version")
	var version map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &version))
	ws := version["webSocketDebuggerUrl"]
	return ws[strings.LastIndex(ws, "/")+1:]
}

func TestStartReportsBrowserThatCannotStart(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	token := NewToken()
	_, err = Start(ctx, self, Config{Token: token, Executable: self, Args: fakeBrowserArgs("--fail-start")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not answer over its pipe")
	assert.Contains(t, err.Error(), "the browser exited")
	assert.NotContains(t, err.Error(), token)

	_, err = Start(ctx, self, Config{Token: token, Executable: filepath.Join(t.TempDir(), "missing"), Args: fakeBrowserArgs()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start the browser")
}

func TestStartHonoursLifetimeCap(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	require.NoError(t, err)
	marker := filepath.Join(t.TempDir(), "exit")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handle, err := Start(ctx, self, Config{
		Token:       NewToken(),
		Executable:  self,
		Args:        fakeBrowserArgs("--exit-marker=" + marker),
		MaxLifetime: 500 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = handle.Kill() })
	eventually(t, 15*time.Second, func() bool { return !procutil.IsAlive(handle.PID) }, "the gate's exit at the cap")
	assert.False(t, procutil.IsAlive(handle.BrowserPID), "the browser ends with its gate")
}

func TestStartRefusesBadConfig(t *testing.T) {
	t.Parallel()
	_, err := Start(context.Background(), "dagu", Config{Executable: "x"})
	assert.ErrorIs(t, err, ErrTokenRequired)
}
