// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	readHeaderTimeout = 10 * time.Second
	// listTimeout bounds the browser's answer to /json/list.
	listTimeout = 5 * time.Second
)

// browserVersion is what Browser.getVersion reports.
type browserVersion struct {
	ProtocolVersion string `json:"protocolVersion"`
	Product         string `json:"product"`
	Revision        string `json:"revision"`
	UserAgent       string `json:"userAgent"`
	JSVersion       string `json:"jsVersion"`
}

// gate serves the browser behind the token.
type gate struct {
	mux       *mux
	token     string
	browserID string
	version   browserVersion
	listener  net.Listener
	server    *http.Server
}

func newGate(m *mux, token, browserID string, version browserVersion) *gate {
	g := &gate{mux: m, token: token, browserID: browserID, version: version}
	g.server = &http.Server{
		Handler:           g,
		ReadHeaderTimeout: readHeaderTimeout,
		// The server's own log could name a request path, and so the token.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return g
}

// listen binds a loopback port and serves on it until close.
func (g *gate) listen() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("listen on loopback: %w", err)
	}
	g.listener = listener
	go func() { _ = g.server.Serve(listener) }()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func (g *gate) port() int {
	if g.listener == nil {
		return 0
	}
	return g.listener.Addr().(*net.TCPAddr).Port
}

func (g *gate) close() {
	_ = g.server.Close()
}

// wsBase is the websocket address of the gate.
func (g *gate) wsBase() string {
	return fmt.Sprintf("ws://127.0.0.1:%d/%s", g.port(), g.token)
}

// browserWSURL is the browser-level websocket address.
func (g *gate) browserWSURL() string {
	return g.wsBase() + "/devtools/browser/" + g.browserID
}

// ServeHTTP answers the DevTools HTTP endpoints under the token and refuses
// everything else alike.
func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	segment, rest := splitToken(r.URL.Path)
	if !g.tokenMatches(segment) {
		notFound(w)
		return
	}
	switch {
	case rest == "/json/version":
		g.serveVersion(w, r)
	case rest == "/json" || rest == "/json/list":
		g.serveList(w, r)
	case rest == "/devtools/browser/"+g.browserID:
		g.serveWebSocket(w, r, "")
	case strings.HasPrefix(rest, "/devtools/page/") && len(rest) > len("/devtools/page/"):
		g.serveWebSocket(w, r, strings.TrimPrefix(rest, "/devtools/page/"))
	default:
		notFound(w)
	}
}

// splitToken separates the first path segment from the rest of the path.
func splitToken(path string) (string, string) {
	trimmed := strings.TrimPrefix(path, "/")
	segment, rest, found := strings.Cut(trimmed, "/")
	if !found {
		return segment, ""
	}
	return segment, "/" + rest
}

// tokenMatches compares in constant time, so a wrong token learns nothing
// from how long the answer takes.
func (g *gate) tokenMatches(segment string) bool {
	return segment != "" && subtle.ConstantTimeCompare([]byte(segment), []byte(g.token)) == 1
}

// notFound is the one answer for every path that is not the browser's: the
// root, a wrong token, an unknown route.
func notFound(w http.ResponseWriter) {
	http.Error(w, "not found", http.StatusNotFound)
}

func (g *gate) serveVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		notFound(w)
		return
	}
	writeJSON(w, map[string]string{
		"Browser":              g.version.Product,
		"Protocol-Version":     g.version.ProtocolVersion,
		"User-Agent":           g.version.UserAgent,
		"V8-Version":           g.version.JSVersion,
		"WebKit-Version":       g.version.Revision,
		"webSocketDebuggerUrl": g.browserWSURL(),
	})
}

// listEntry is one target in /json/list, as Chrome lists it.
type listEntry struct {
	Description          string `json:"description"`
	ID                   string `json:"id"`
	Title                string `json:"title"`
	Type                 string `json:"type"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

func (g *gate) serveList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		notFound(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), listTimeout)
	defer cancel()
	result, err := g.mux.call(ctx, "", "Target.getTargets", map[string]any{})
	if err != nil {
		http.Error(w, "the browser did not list its targets", http.StatusBadGateway)
		return
	}
	var targets struct {
		TargetInfos []struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
			Title    string `json:"title"`
			URL      string `json:"url"`
		} `json:"targetInfos"`
	}
	if err := json.Unmarshal(result, &targets); err != nil {
		http.Error(w, "the browser did not list its targets", http.StatusBadGateway)
		return
	}
	entries := make([]listEntry, 0, len(targets.TargetInfos))
	for _, info := range targets.TargetInfos {
		if !defaultTargetFilter.matches(info.Type) {
			continue
		}
		entries = append(entries, listEntry{
			ID:                   info.TargetID,
			Title:                info.Title,
			Type:                 info.Type,
			URL:                  info.URL,
			WebSocketDebuggerURL: g.wsBase() + "/devtools/page/" + info.TargetID,
		})
	}
	writeJSON(w, entries)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_ = json.NewEncoder(w).Encode(value)
}

// serveWebSocket admits a DevTools client, on the browser when targetID is
// "" and on that target's own session otherwise.
func (g *gate) serveWebSocket(w http.ResponseWriter, r *http.Request, targetID string) {
	if !originAllowed(r.Header.Get("Origin")) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The token in the path is the credential; originAllowed has
		// already refused what a web page could send.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	// DevTools payloads carry screenshots and DOM snapshots.
	conn.SetReadLimit(-1)
	c := newClient(g.mux, conn)
	ctx := context.Background()
	if targetID != "" {
		attachCtx, cancel := context.WithTimeout(ctx, listTimeout)
		err := g.mux.attachRoot(attachCtx, c, targetID)
		cancel()
		if err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, "no such target")
			return
		}
	}
	if !g.mux.addClient(c) {
		_ = conn.Close(websocket.StatusGoingAway, "the browser is closing")
		return
	}
	c.serve(ctx)
}

// originAllowed admits a websocket without an Origin, as DevTools libraries
// send them, and one from the browser's own extensions. A web page's
// http(s) Origin is refused: the token is the credential, and a page that
// learned it would still not get in.
func originAllowed(origin string) bool {
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Scheme == "chrome-extension"
}
