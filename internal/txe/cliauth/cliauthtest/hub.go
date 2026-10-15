// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cliauthtest

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Hub is an in-process hub API at /api/v1 that answers the way the TXE
// server contract does: GET /txe/auth/cli publishes the CLI client, and every
// other route records the request and answers as Decide says.
type Hub struct {
	server *httptest.Server

	mu sync.Mutex
	// Advertise, when set, is published at GET /txe/auth/cli; when nil
	// that route answers 404.
	Advertise map[string]any
	// Decide answers a request other than the CLI client: 0 or 200 serves
	// it; 401 refuses the token (invalid_token); 403 forbids; 503 is
	// provider_unavailable. Nil serves everything.
	Decide func(r *http.Request, call int) int
	// Handle, when set, may answer a request other than the CLI client
	// itself, before Decide; it returns false to leave it to the hub.
	Handle   func(w http.ResponseWriter, r *http.Request) bool
	requests []Request
}

// Request is one request the hub received.
type Request struct {
	Method        string
	Path          string
	Authorization string
	Body          string
}

// NewHub starts a hub for the test.
func NewHub(t *testing.T) *Hub {
	t.Helper()
	h := &Hub{}
	h.server = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.server.Close)
	return h
}

// API is the hub's API root, as a CLI context names it.
func (h *Hub) API() string { return h.server.URL + "/api/v1" }

// Requests returns what the hub received, in order.
func (h *Hub) Requests() []Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Request(nil), h.requests...)
}

// Publish makes the hub publish its CLI client for provider p.
func (h *Hub) Publish(issuer, clientID, use string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Advertise = map[string]any{"contract": 1, "issuer": issuer, "client_id": clientID, "scopes": []string{"openid"}, "use": use}
}

func (h *Hub) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.requests = append(h.requests, Request{Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization"), Body: string(body)})
	call := len(h.requests)
	advertise, decide, handle := h.Advertise, h.Decide, h.Handle
	h.mu.Unlock()
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	if r.URL.Path == "/api/v1/txe/auth/cli" {
		if advertise == nil {
			WriteJSON(w, http.StatusNotFound, map[string]any{"code": "not_found", "message": "not found"})
			return
		}
		WriteJSON(w, http.StatusOK, advertise)
		return
	}
	if handle != nil && handle(w, r) {
		return
	}
	status := http.StatusOK
	if decide != nil {
		if s := decide(r, call); s != 0 {
			status = s
		}
	}
	switch status {
	case http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", `Bearer realm="dagu", error="invalid_token"`)
		WriteJSON(w, status, map[string]any{"code": "unauthorized", "message": "The token was refused. Sign in again.", "details": map[string]string{"code": "invalid_token"}})
	case http.StatusForbidden:
		WriteJSON(w, status, map[string]any{"code": "forbidden", "message": "forbidden", "details": map[string]string{"code": "forbidden"}})
	case http.StatusServiceUnavailable:
		w.Header().Set("Retry-After", "5")
		WriteJSON(w, status, map[string]any{"code": "service_unavailable", "message": "provider unavailable", "details": map[string]string{"code": "provider_unavailable"}})
	case http.StatusOK:
		if r.URL.Path == "/api/v1/txe/identity" {
			iss, sub := bearerClaims(r.Header.Get("Authorization"))
			WriteJSON(w, status, map[string]any{
				"contract": 1, "authz_mode": "off", "state": "unbound",
				"principal": map[string]any{"class": "cli", "issuer": iss, "subject": sub, "client_id": "dagu-cli"},
				"owners":    []any{}, "scope": map[string]any{"kind": "none", "unbound_reason": "no binding"},
				"platform_admin": false, "is_person": false,
			})
			return
		}
		WriteJSON(w, status, map[string]any{"ok": true, "path": r.URL.Path})
	default:
		WriteJSON(w, status, map[string]any{"code": "error", "message": http.StatusText(status)})
	}
}

// bearerClaims reads iss and sub from a bearer JWT without verifying it.
func bearerClaims(header string) (iss, sub string) {
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return "", ""
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
	}
	_ = json.Unmarshal(payload, &claims)
	return claims.Iss, claims.Sub
}
