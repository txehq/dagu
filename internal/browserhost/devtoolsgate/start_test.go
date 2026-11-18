// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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

// A browser that was ended is seen gone at once, though a helper process of
// it lives on holding what it inherited: its standard output and error,
// and on Unix the pipe's descriptors too. The gate stops answering well
// before its heartbeat could tell (heartbeatInterval + heartbeatTimeout),
// and long before the helper ends (TXE-7832: Chrome's helpers outlived it
// on a Windows runner, and the gate answered for its dead browser).
func TestStartSeesTheBrowserEndWhileItsHelperLives(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	require.NoError(t, err)
	pidFile := filepath.Join(t.TempDir(), "helper.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handle, err := Start(ctx, self, Config{Token: NewToken(), Executable: self, Args: fakeBrowserArgs("--helper-pid-file=" + pidFile)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = handle.Kill() })
	var helperPID int
	eventually(t, 15*time.Second, func() bool {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		helperPID, err = strconv.Atoi(string(data))
		return err == nil && helperPID > 0
	}, "the browser's helper process")
	t.Cleanup(func() {
		if helper, err := os.FindProcess(helperPID); err == nil {
			_ = helper.Kill()
		}
	})
	status, _ := get(t, handle.URL+"/json/version")
	require.Equal(t, http.StatusOK, status)

	browser, err := os.FindProcess(handle.BrowserPID)
	require.NoError(t, err)
	ended := time.Now()
	require.NoError(t, browser.Kill())
	client := &http.Client{Timeout: time.Second}
	bound := heartbeatInterval + heartbeatTimeout - 5*time.Second
	eventually(t, bound, func() bool {
		response, err := client.Get(handle.URL + "/json/version")
		if err != nil {
			return true
		}
		_ = response.Body.Close()
		return false
	}, "the gate stops answering for its ended browser")
	t.Logf("the gate stopped answering %s after the browser was ended", time.Since(ended).Round(time.Millisecond))
	assert.True(t, procutil.IsAlive(helperPID), "the helper still lives, so its handles did not decide")
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

// TestStartEndsAnUnattendedBrowser: with no client ever admitted, the
// browser and its gate end at MaxUnattended, as they did under the old cap.
func TestStartEndsAnUnattendedBrowser(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handle, err := Start(ctx, self, Config{
		Token:         NewToken(),
		Executable:    self,
		Args:          fakeBrowserArgs(),
		MaxUnattended: 500 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = handle.Kill() })
	eventually(t, 15*time.Second, func() bool { return !procutil.IsAlive(handle.PID) }, "the gate's exit at the unattended cap")
	assert.False(t, procutil.IsAlive(handle.BrowserPID), "the browser ends with its gate")
}

// TestStartKeepsAnAttendedBrowser: a connected DevTools client keeps the
// browser past the unattended cap, and the cap runs from the client's
// leaving. The process form, with real short values, over real pipes.
func TestStartKeepsAnAttendedBrowser(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const unattended = 2 * time.Second
	handle, err := Start(ctx, self, Config{
		Token:         NewToken(),
		Executable:    self,
		Args:          fakeBrowserArgs(),
		MaxUnattended: unattended,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = handle.Kill() })
	c := dialWS(t, "ws"+strings.TrimPrefix(handle.URL, "http")+"/devtools/browser/"+browserIDOf(t, handle.URL), nil)
	// Twice the cap with the client connected and idle: the gate and the
	// browser are still there, and the client still gets answers.
	time.Sleep(2 * unattended)
	assert.True(t, procutil.IsAlive(handle.PID), "the gate runs while a client is connected")
	assert.True(t, procutil.IsAlive(handle.BrowserPID), "the browser runs while a client is connected")
	c.mustCall("", "Browser.getVersion", nil)
	// The client leaves: the unattended clock runs from now.
	c.close()
	eventually(t, 15*time.Second, func() bool { return !procutil.IsAlive(handle.PID) }, "the gate's exit after the last client left")
	assert.False(t, procutil.IsAlive(handle.BrowserPID), "the browser ends with its gate")
}

// TestStartEndsABrowserWhoseOnlyClientIsAHelper: through the real helper
// process, a connected client that marks itself a helper does not keep the
// browser, so it ends at MaxUnattended as if nobody were connected.
func TestStartEndsABrowserWhoseOnlyClientIsAHelper(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handle, err := Start(ctx, self, Config{
		Token:         NewToken(),
		Executable:    self,
		Args:          fakeBrowserArgs(),
		MaxUnattended: time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = handle.Kill() })
	c := dialWS(t, "ws"+strings.TrimPrefix(handle.URL, "http")+"/devtools/browser/"+browserIDOf(t, handle.URL), HelperHandshake())
	c.mustCall("", "Browser.getVersion", nil)
	eventually(t, 15*time.Second, func() bool { return !procutil.IsAlive(handle.PID) }, "the gate's exit with only a helper connected")
	assert.False(t, procutil.IsAlive(handle.BrowserPID), "the browser ends with its gate")
}

func TestStartRefusesBadConfig(t *testing.T) {
	t.Parallel()
	_, err := Start(context.Background(), "dagu", Config{Executable: "x"})
	assert.ErrorIs(t, err, ErrTokenRequired)
}
