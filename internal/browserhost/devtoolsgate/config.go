// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// configVersion is the version of the configuration the helper reads from
// stdin. A helper of another version refuses the configuration rather than
// guessing at it.
const configVersion = 1

// Config is what the process starting a gate hands it on stdin.
type Config struct {
	// Token is the credential in the gate's URL. It never appears on a
	// command line, in a log or in an error.
	Token string `json:"token"`
	// Executable is the browser binary.
	Executable string `json:"executable"`
	// Args are the browser's arguments without any remote-debugging flag:
	// the gate adds the pipe flags itself. ChromeArgs builds them.
	Args []string `json:"args"`
	// MaxLifetime is a hard cap on how long the gate, and so the browser,
	// runs, whether or not a client is connected. Zero means no hard cap:
	// the browser then ends by MaxUnattended alone (TXE-6201).
	MaxLifetime time.Duration `json:"max_lifetime,omitempty"`
	// MaxUnattended is how long the gate stays with no admitted client
	// before it closes the browser; the clock restarts when the last
	// client leaves. Zero means DefaultMaxUnattended. A browser with an
	// admitted client is never ended by it.
	MaxUnattended time.Duration `json:"max_unattended,omitempty"`
}

// wireConfig is the envelope on stdin.
type wireConfig struct {
	Version int    `json:"version"`
	Config  Config `json:"config"`
}

// Ready is the one line the helper prints once the browser answers and the
// gate accepts connections.
type Ready struct {
	Port             int    `json:"port"`
	BrowserID        string `json:"browser_id"`
	BrowserPID       int    `json:"browser_pid"`
	BrowserStartedAt int64  `json:"browser_started_at,omitempty"`
}

// readyLine is the envelope of the ready line, so a failure before the gate
// is ready can be told from a ready gate.
type readyLine struct {
	Ready *Ready `json:"ready,omitempty"`
	Error string `json:"error,omitempty"`
}

// ErrTokenRequired reports a configuration without a token.
var ErrTokenRequired = errors.New("devtools gate: a token is required")

// ErrDebuggingFlagInArgs reports browser arguments that choose a remote
// debugging transport themselves. Only the gate does that.
var ErrDebuggingFlagInArgs = errors.New("devtools gate: the browser arguments must not set a remote-debugging flag")

func (c Config) validate() error {
	switch {
	case c.Token == "":
		return ErrTokenRequired
	case strings.ContainsAny(c.Token, "/?#%\\ "):
		return errors.New("devtools gate: the token must be a single URL path segment")
	case c.Executable == "":
		return errors.New("devtools gate: the browser executable is required")
	case c.MaxLifetime < 0:
		return errors.New("devtools gate: the lifetime cap cannot be negative")
	case c.MaxUnattended < 0:
		return errors.New("devtools gate: the unattended cap cannot be negative")
	}
	for _, arg := range c.Args {
		if strings.HasPrefix(arg, "--remote-debugging-") {
			return ErrDebuggingFlagInArgs
		}
	}
	return nil
}

// HelperHeader on a websocket handshake, with exactly HelperValue, marks a
// permanent helper connection of the hub's own, such as the write gate that
// intercepts requests for the browser's whole life: it is admitted like any
// other client, with the same token, the same Origin rule, the same session
// ownership and the same commands, and is only left out of the attendance
// count, so a browser whose only client is a helper is unattended
// (TXE-6201). The header is read after the token and Origin checks and
// grants nothing: any token holder can attend, and declaring itself a helper
// only lets the unattended clock run against the connection's own browser.
// A header present with any other value refuses the handshake, so a
// mistyped marker neither counts nor exempts quietly.
const (
	HelperHeader = "X-Dagu-DevTools-Helper"
	HelperValue  = "attendance-exempt"
)

// HelperHandshake returns the header a permanent helper sends on its
// websocket handshake, so a consumer opts in with one call and no copy of
// the marker.
func HelperHandshake() http.Header {
	return http.Header{HelperHeader: []string{HelperValue}}
}

// NewToken returns a fresh URL-safe credential.
func NewToken() string {
	return rand.Text()
}

// BaseURL is the address of the browser behind the gate listening on port
// with token.
func BaseURL(port int, token string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/%s", port, token)
}

// TokenOf returns the token in a gate address, or "" when the address has
// none.
func TokenOf(cdpURL string) string {
	parsed, err := url.Parse(cdpURL)
	if err != nil {
		return ""
	}
	segment, _, _ := strings.Cut(strings.TrimPrefix(parsed.Path, "/"), "/")
	return segment
}
