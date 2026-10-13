// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package terminal_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	persiststore "github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	terminalpkg "github.com/dagucloud/dagu/v2/internal/service/frontend/terminal"
	"github.com/stretchr/testify/require"
)

// shellTerminal is one terminal opened against the handler alone, with the
// pid of the shell behind it.
type shellTerminal struct {
	conn *websocket.Conn
	pid  int
	// cancel ends the request's context, as the hub does when it closes a
	// terminal: at shutdown, or when the terminal's OIDC session ends.
	cancel context.CancelFunc
	// served is closed when the handler has returned, cleanup included.
	served <-chan struct{}
}

func (s shellTerminal) run(t *testing.T, command string) {
	t.Helper()
	payload, err := json.Marshal(terminalpkg.Message{
		Type: terminalpkg.MessageTypeInput,
		Data: base64.StdEncoding.EncodeToString([]byte(command + "\n")),
	})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, s.conn.Write(ctx, websocket.MessageText, payload))
}

func openShellTerminal(t *testing.T) shellTerminal {
	t.Helper()
	store, err := persiststore.NewUserStore(testutil.NewMemoryBackend().Collection("users"))
	require.NoError(t, err)
	secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
	require.NoError(t, err)
	svc := authservice.New(store, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4})
	admin, err := svc.CreateUser(context.Background(), authservice.CreateUserInput{Username: "admin", Password: "password123", Role: authmodel.RoleAdmin})
	require.NoError(t, err)
	token, err := svc.GenerateToken(admin)
	require.NoError(t, err)

	manager := terminalpkg.NewManager(context.Background(), 4)
	handler := terminalpkg.NewHandler(svc, nil, nil, manager, "/bin/sh")
	requestCtx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(served)
		ctx, stop := context.WithCancel(r.Context())
		defer stop()
		context.AfterFunc(requestCtx, stop)
		handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(func() {
		cancel()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = manager.Shutdown(shutdownCtx)
		server.Close()
	})

	dialCtx, stopDial := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopDial()
	conn, response, err := websocket.Dial(dialCtx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/terminal/ws?token="+url.QueryEscape(token.Token), nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.CloseNow() })
	// Output is read and dropped, so that the shell is never held on it.
	go func() {
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	}()

	terminal := shellTerminal{conn: conn, cancel: cancel, served: served}
	pidFile := filepath.Join(t.TempDir(), "shell.pid")
	terminal.run(t, "echo $$ > "+pidFile)
	require.Eventually(t, func() bool {
		raw, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		terminal.pid, err = strconv.Atoi(strings.TrimSpace(string(raw)))
		return err == nil && terminal.pid > 0
	}, 10*time.Second, 10*time.Millisecond, "the shell did not start")
	require.NoError(t, syscall.Kill(terminal.pid, 0), "the shell is running")
	return terminal
}

func processGone(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

// However a terminal ends, the shell behind it is ended too, and the handler
// returns. The shell here is idle: it writes nothing by itself, so nothing
// but the hub ending it will make its pty readable.
func TestTerminal_AnIdleShellIsEndedWithItsTerminal(t *testing.T) {
	t.Parallel()

	for name, end := range map[string]func(*testing.T, shellTerminal){
		// The hub closes it: shutdown, or the end of its OIDC session.
		"TheHubClosesIt": func(_ *testing.T, terminal shellTerminal) { terminal.cancel() },
		// The browser goes away without a word.
		"TheClientDisconnects": func(_ *testing.T, terminal shellTerminal) { _ = terminal.conn.CloseNow() },
		// The browser closes the WebSocket properly.
		"TheClientClosesTheSocket": func(_ *testing.T, terminal shellTerminal) {
			_ = terminal.conn.Close(websocket.StatusNormalClosure, "bye")
		},
		// The browser sends the terminal's own close message.
		"TheClientSendsClose": func(t *testing.T, terminal shellTerminal) {
			payload, err := json.Marshal(terminalpkg.Message{Type: terminalpkg.MessageTypeClose})
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, terminal.conn.Write(ctx, websocket.MessageText, payload))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			terminal := openShellTerminal(t)

			end(t, terminal)

			// A shell hangs up at once; the grace before it is killed is
			// three seconds.
			require.Eventually(t, func() bool { return processGone(terminal.pid) }, 8*time.Second, 20*time.Millisecond,
				"the shell is still running")
			select {
			case <-terminal.served:
			case <-time.After(8 * time.Second):
				require.FailNow(t, "the handler did not return")
			}
		})
	}
}

// A shell that ignores the hang-up is killed after the grace.
func TestTerminal_AShellThatIgnoresTheHangUpIsKilled(t *testing.T) {
	t.Parallel()
	terminal := openShellTerminal(t)
	terminal.run(t, "trap '' HUP")
	// The trap is in place once the shell answers the next command.
	marker := filepath.Join(t.TempDir(), "trapped")
	terminal.run(t, "touch "+marker)
	require.Eventually(t, func() bool { _, err := os.Stat(marker); return err == nil }, 10*time.Second, 10*time.Millisecond)

	started := time.Now()
	terminal.cancel()
	require.Eventually(t, func() bool { return processGone(terminal.pid) }, 10*time.Second, 20*time.Millisecond,
		"the shell is still running")
	require.GreaterOrEqual(t, time.Since(started), 2*time.Second, "it was given its grace first")
	select {
	case <-terminal.served:
	case <-time.After(8 * time.Second):
		require.FailNow(t, "the handler did not return")
	}
}

// Something the shell started in the background can keep the pty open after
// the shell is gone. The terminal's cleanup does not wait for it: the shell
// is ended and the handler returns.
func TestTerminal_ABackgroundJobDoesNotHoldTheTerminalOpen(t *testing.T) {
	t.Parallel()
	terminal := openShellTerminal(t)
	pidFile := filepath.Join(t.TempDir(), "job.pid")
	// It ignores the hang-up, keeps the terminal as its output, and is
	// stopped by the test at the end.
	terminal.run(t, "(trap '' HUP; sleep 60) & echo $! > "+pidFile)
	var job int
	require.Eventually(t, func() bool {
		raw, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		job, err = strconv.Atoi(strings.TrimSpace(string(raw)))
		return err == nil && job > 0
	}, 10*time.Second, 10*time.Millisecond)
	t.Cleanup(func() { _ = syscall.Kill(job, syscall.SIGKILL) })

	terminal.cancel()
	require.Eventually(t, func() bool { return processGone(terminal.pid) }, 8*time.Second, 20*time.Millisecond,
		"the shell is still running")
	select {
	case <-terminal.served:
	case <-time.After(12 * time.Second):
		require.FailNow(t, "the handler did not return: cleanup is waiting for the background job")
	}
}
