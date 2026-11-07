// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/procutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireChrome skips when no Chrome is installed, except in CI, where the
// runners provide one and a missing browser is a setup failure.
func requireChrome(t *testing.T) string {
	t.Helper()
	path, err := FindBrowser("")
	if err == nil {
		return path
	}
	if os.Getenv("CI") != "" {
		t.Fatalf("Chrome is required in CI; set CHROME_PATH: %v", err)
	}
	t.Skipf("Chrome is not installed; set CHROME_PATH to run browser tests: %v", err)
	return ""
}

// TestRealChromeHasNoPort launches Chrome through the real gate helper on a
// profile of its own, headless and offline, and checks that the browser
// answers only through the gate: no DevToolsActivePort file, no listening
// TCP socket of its own, and that ending the gate ends the browser.
func TestRealChromeHasNoPort(t *testing.T) {
	chrome := requireChrome(t)
	self, err := os.Executable()
	require.NoError(t, err)
	profile := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	token := NewToken()
	handle, err := Start(ctx, self, Config{
		Token:      token,
		Executable: chrome,
		Args: ChromeArgs(LaunchOptions{
			UserDataDir: profile,
			Headless:    true,
			NoSandbox:   os.Getenv("CI") != "" || (runtime.GOOS == "linux" && os.Geteuid() == 0),
		}),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = handle.Kill() })

	status, body := get(t, handle.URL+"/json/version")
	require.Equal(t, http.StatusOK, status)
	var version map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &version))
	assert.Contains(t, version["Browser"], "/", "Chrome names itself, e.g. Chrome/157.0: %s", version["Browser"])
	assert.NotEmpty(t, version["User-Agent"])
	assert.True(t, strings.HasPrefix(version["webSocketDebuggerUrl"], "ws://127.0.0.1:"), version["webSocketDebuggerUrl"])
	assert.Contains(t, version["webSocketDebuggerUrl"], "/"+token+"/")

	// A client drives the real browser through the gate.
	c := dialWS(t, version["webSocketDebuggerUrl"], nil)
	c.mustCall("", "Target.setAutoAttach", autoAttach(false))
	page := decodeAttached(t, c.waitEvent("Target.attachedToTarget", func(m message) bool {
		return decodeAttached(t, m).TargetInfo.Type == "page"
	}))
	result := c.mustCall(page.SessionID, "Runtime.evaluate", map[string]any{"expression": "40 + 2", "returnByValue": true})
	assert.Contains(t, string(result), `"value":42`)

	// Chrome writes DevToolsActivePort only for a port server.
	_, err = os.Stat(filepath.Join(profile, "DevToolsActivePort"))
	assert.ErrorIs(t, err, os.ErrNotExist, "no DevTools port was opened")
	assertNoListeningSocket(t, handle.BrowserPID)

	// Ending the gate closes the pipe; Chrome closes itself.
	require.NoError(t, handle.Kill())
	eventually(t, 30*time.Second, func() bool { return !procutil.IsAlive(handle.BrowserPID) }, "Chrome's exit after its gate")
}

// assertNoListeningSocket checks, where a tool for it exists, that the
// browser process listens on no TCP port.
func assertNoListeningSocket(t *testing.T, pid int) {
	t.Helper()
	switch runtime.GOOS {
	case "darwin", "linux":
		lsof, err := exec.LookPath("lsof")
		if err != nil {
			t.Log("lsof is not installed; the listening-socket check is skipped")
			return
		}
		out, _ := exec.Command(lsof, "-nP", "-a", "-p", strconv.Itoa(pid), "-iTCP", "-sTCP:LISTEN").Output()
		assert.Empty(t, strings.TrimSpace(string(out)), "the browser listens on a TCP port")
	case "windows":
		out, err := exec.Command("netstat", "-ano", "-p", "TCP").Output()
		if err != nil {
			t.Log("netstat failed; the listening-socket check is skipped")
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 5 && fields[3] == "LISTENING" && fields[4] == strconv.Itoa(pid) {
				t.Errorf("the browser listens on a TCP port: %s", line)
			}
		}
	}
}
