// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package frontend

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
)

// dialTerminal opens the terminal WebSocket with a token in the query, as
// the browser does, and reports the status the handshake was answered with:
// 101 when it was upgraded.
func (h *personHub) dialTerminal(token string) int {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target := "ws" + strings.TrimPrefix(h.http.URL, "http") + "/api/v1/terminal/ws?token=" + url.QueryEscape(token)
	conn, response, err := websocket.Dial(ctx, target, nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err == nil {
		_ = conn.CloseNow()
		return http.StatusSwitchingProtocols
	}
	require.NotNil(h.t, response, err.Error())
	return response.StatusCode
}

// A person is refused the terminal before any upgrade, with or without the
// hub's administrator role on its account, and whether or not browser
// sign-in is configured: a person's hub token outlives that configuration.
// The builtin administrator is upgraded.
func TestTxePersonIsRefusedTheTerminalBeforeUpgrade(t *testing.T) {
	for _, browserOIDC := range []bool{true, false} {
		h := newPersonHub(t, browserOIDC)
		for _, u := range []*authmodel.User{h.person, h.adminP} {
			require.Equal(t, http.StatusForbidden, h.dialTerminal(h.token(u)), "%s, browser sign-in %v", u.Username, browserOIDC)
		}
		require.Equal(t, http.StatusSwitchingProtocols, h.dialTerminal(h.token(h.builtin)), "browser sign-in %v", browserOIDC)
		require.Equal(t, http.StatusUnauthorized, h.dialTerminal("not-a-token"), "browser sign-in %v", browserOIDC)
	}
}
