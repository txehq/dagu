// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// The identity checked in front of the terminal is the one the terminal
// itself authenticates: its query token, never a header sent beside it.
func TestTerminalQueryTokenOnly(t *testing.T) {
	var seen string
	h := terminalQueryTokenOnly(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = r.Header.Get("Authorization") }))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/terminal/ws?token=session-token", nil)
	req.Header.Set("Authorization", "Bearer legacy-viewer")
	h.ServeHTTP(httptest.NewRecorder(), req)
	require.Equal(t, "Bearer session-token", seen)
	require.Equal(t, "Bearer legacy-viewer", req.Header.Get("Authorization"), "the caller's request is not changed")

	req = httptest.NewRequest(http.MethodGet, "/api/v1/terminal/ws", nil)
	req.Header.Set("Authorization", "Bearer legacy-viewer")
	h.ServeHTTP(httptest.NewRecorder(), req)
	require.Empty(t, seen)
}
