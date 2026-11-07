// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package certproxy

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ProxyUser is the user name the browser gives the proxy with the
// credential of its Config. The credential alone is the secret.
const ProxyUser = "dagu"

// proxyRealm names the proxy in the challenge it answers an unauthenticated
// request with.
const proxyRealm = "dagu"

// proxyAuthorized reports whether r carries the proxy's credential in its
// Proxy-Authorization header. The proxy presents client certificates and
// reaches sites the way this device does, so every request a client asks
// it to carry, on the certificate port and the guard, must come from the
// browser it was started for: a process that can only reach loopback, such
// as another local account or a container sharing the network namespace,
// has no credential.
func (s *server) proxyAuthorized(r *http.Request) bool {
	scheme, encoded, ok := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(decoded, []byte(ProxyUser+":"+s.credential)) == 1
}

// challenge refuses a request without the proxy's credential before
// anything else looks at it: no host is matched, no route is chosen and
// nothing is dialed. The browser answers the challenge with the credential
// its DevTools gate holds.
func challenge(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="`+proxyRealm+`"`)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusProxyAuthRequired)
}

// setBrowser names the browser the proxy serves. Only the first name
// counts: the proxy serves one browser.
func (s *server) setBrowser(cdpURL string) bool {
	set := false
	s.browserOnce.Do(func() {
		if parsed, err := url.Parse(cdpURL); err == nil && parsed.Host != "" {
			address := parsed.Host
			s.gateAddress.Store(&address)
		}
		s.browser <- cdpURL
		set = true
	})
	return set
}

// isBrowserGate reports whether authority is the address of the DevTools
// gate of the browser the proxy serves. The browser's runtime runs inside
// the browser and opens its DevTools WebSocket there, which a manual proxy
// carrying loopback receives as a tunnel: Chrome answers no proxy challenge
// for a WebSocket, so that tunnel needs no credential. It gives a client
// nothing: the gate listens on loopback, where the client reaches it
// directly, and refuses every request without its own token.
func (s *server) isBrowserGate(authority string) bool {
	address := s.gateAddress.Load()
	return address != nil && authority == *address
}

// relayToGate splices a tunnel to the browser's DevTools gate, unread and
// direct, presenting nothing and asking the device's routes nothing.
func (s *server) relayToGate(w http.ResponseWriter, address string) {
	raw, err := net.DialTimeout("tcp", address, handshakeTimeout) //nolint:gosec // the gate's own loopback address, which the starting process named; a client names it only to match it
	if err != nil {
		http.Error(w, "the browser's DevTools gate does not answer", http.StatusBadGateway)
		return
	}
	conn, reader, ok := establish(w)
	if !ok {
		_ = raw.Close()
		return
	}
	client := conn
	if reader.Buffered() > 0 {
		client = &bufferedConn{Conn: conn, reader: reader}
	}
	s.splice(client, raw)
}

// browserRequest is what the starting process posts to name the browser.
type browserRequest struct {
	CDPURL string `json:"cdp_url"`
}

// maxBrowserRequestBytes bounds the body naming the browser.
const maxBrowserRequestBytes = 4 << 10

// serveBrowser takes the browser's DevTools address from the starting
// process. The path is under the proxy's token, which only that process
// and the record know.
func (s *server) serveBrowser(w http.ResponseWriter, r *http.Request) {
	var request browserRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBrowserRequestBytes)).Decode(&request); err != nil || request.CDPURL == "" {
		http.Error(w, "the request names no browser", http.StatusBadRequest)
		return
	}
	if !s.setBrowser(request.CDPURL) {
		http.Error(w, "the proxy already serves a browser", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
