// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package frontend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
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
	return openConnection{closed: closed, alive: alive, hangUp: func() { _ = conn.CloseNow() }}
}
