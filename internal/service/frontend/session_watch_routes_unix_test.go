// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package frontend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/service/frontend/terminal"
)

func init() {
	openers["Terminal"] = (*routeHub).openTerminal
}

// openTerminal opens a terminal WebSocket, with a shell behind it.
func (h *routeHub) openTerminal(token string) openConnection {
	conn, _ := h.openTerminalShell(token)
	return conn
}

// openTerminalShell is openTerminal, with a function that types a command
// into the shell.
func (h *routeHub) openTerminalShell(token string) (openConnection, func(command string)) {
	h.t.Helper()
	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target := "ws" + strings.TrimPrefix(h.http.URL, "http") + "/api/v1/terminal/ws?token=" + url.QueryEscape(token)
	conn, response, err := websocket.Dial(dialCtx, target, nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	require.NoError(h.t, err)
	h.t.Cleanup(func() { _ = conn.CloseNow() })

	var (
		mu     sync.Mutex
		output strings.Builder
	)
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			_, data, err := conn.Read(context.Background())
			if err != nil {
				return
			}
			var message terminal.Message
			if json.Unmarshal(data, &message) != nil || message.Type != terminal.MessageTypeOutput {
				continue
			}
			if decoded, err := message.DecodeData(); err == nil {
				mu.Lock()
				output.Write(decoded)
				mu.Unlock()
			}
		}
	}()

	run := func(command string) {
		payload, err := json.Marshal(terminal.Message{
			Type: terminal.MessageTypeInput,
			Data: base64.StdEncoding.EncodeToString([]byte(command + "\n")),
		})
		require.NoError(h.t, err)
		writeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(h.t, conn.Write(writeCtx, websocket.MessageText, payload))
	}
	answers := 0
	alive := func() bool {
		// The shell works out the answer, so an echo of the input is not it.
		answers++
		want := fmt.Sprintf("alive-%d", answers*1000+42)
		run(fmt.Sprintf("echo alive-$((%d*1000+42))", answers))
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			seen := strings.Contains(output.String(), want)
			mu.Unlock()
			if seen {
				return true
			}
			time.Sleep(5 * time.Millisecond)
		}
		return false
	}
	require.True(h.t, alive(), "the shell did not start")
	return openConnection{closed: closed, alive: alive, hangUp: func() { _ = conn.CloseNow() }}, run
}

// The shell behind a terminal does not outlive the session: when the
// terminal is closed for it, the shell process is ended too.
func TestTerminalShellEndsWithItsOIDCSession(t *testing.T) {
	t.Parallel()
	hub := newRouteHub(t, true)
	token := hub.signIn()
	conn, run := hub.openTerminalShell(token)
	hub.armed()

	pidFile := filepath.Join(t.TempDir(), "shell.pid")
	run("echo $$ > " + pidFile)
	var pid int
	require.Eventually(t, func() bool {
		raw, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(raw)))
		return err == nil && pid > 0
	}, 10*time.Second, 10*time.Millisecond)
	require.NoError(t, syscall.Kill(pid, 0), "the shell is running")

	hub.signOut(token)
	hub.clock.advance(15 * time.Second)
	requireClosed(t, conn)

	// The hub hangs the shell up, and kills it if it does not go.
	require.Eventually(t, func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}, 10*time.Second, 20*time.Millisecond, "the shell is still running")
}
