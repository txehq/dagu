// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"encoding/json"
	"net"
	"net/url"
)

// Answers to a DevTools Fetch.authRequired challenge.
const (
	authProvide = "ProvideCredentials"
	authDefault = "Default"
	authCancel  = "CancelAuth"
)

// maxAnsweredChallenges bounds the requests the responder remembers having
// answered, so a browser left running for a day does not grow it without
// end.
const maxAnsweredChallenges = 4096

// proxyResponder gives the browser's local proxy its credential. Chrome
// sends a proxy no credential of its own accord and has none to give, so
// the proxy's challenge is answered over DevTools: on the gate's own session
// on every target, which the gate holds until interception is in place, so
// a target's first request is answered too. A client's own Fetch
// interception is on its private session and unaffected.
type proxyResponder struct {
	m    *mux
	auth ProxyAuth
	// addresses are the proxy's host:port addresses; a challenge from any
	// other origin is left to the browser.
	addresses map[string]struct{}
	// answered are the requests given the credential once. A second
	// challenge for one means the proxy refused it, and is cancelled
	// rather than answered again and again.
	answered map[string]struct{}
}

func newProxyResponder(m *mux, auth ProxyAuth) *proxyResponder {
	addresses := make(map[string]struct{}, len(auth.Addresses))
	for _, address := range auth.Addresses {
		addresses[address] = struct{}{}
	}
	return &proxyResponder{m: m, auth: auth, addresses: addresses, answered: make(map[string]struct{})}
}

// install sets the responder's hooks on its mux. It must run before the mux
// reads the pipe.
func (r *proxyResponder) install() {
	r.m.onGateAttached = r.attached
	r.m.onGateEvent = r.event
}

// attached turns on the gate's interception of t's requests, and the gate's
// auto-attach beneath it so t's own workers and frames are held and covered
// too, and keeps t paused until both are in place. m.mu is held.
func (r *proxyResponder) attached(t *target) {
	r.m.holdLocked(t)
	r.m.gateCommand(t.gateSession, "Fetch.enable", map[string]any{
		"handleAuthRequests": true,
		"patterns":           []map[string]any{{"urlPattern": "*", "requestStage": "Request"}},
	}, func(json.RawMessage, *cdpError) {
		// A target that takes no interception sends whatever it sends
		// without the credential, and the proxy refuses it.
		r.m.releaseHoldLocked(t)
	})
	if t.nestedAutoAttach {
		return
	}
	t.nestedAutoAttach = true
	r.m.holdLocked(t)
	r.m.gateCommand(t.gateSession, "Target.setAutoAttach", map[string]any{
		"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
	}, func(_ json.RawMessage, cdpErr *cdpError) {
		if cdpErr != nil {
			t.nestedAutoAttach = false
		}
		r.m.releaseHoldLocked(t)
	})
}

// event answers the interception events on the gate's sessions. m.mu is
// held.
func (r *proxyResponder) event(t *target, msg message) {
	switch msg.Method {
	case "Fetch.requestPaused":
		var params struct {
			RequestID string `json:"requestId"`
		}
		if json.Unmarshal(msg.Params, &params) != nil || params.RequestID == "" {
			return
		}
		r.m.gateCommand(t.gateSession, "Fetch.continueRequest", map[string]any{"requestId": params.RequestID}, nil)
	case "Fetch.authRequired":
		var params struct {
			RequestID     string `json:"requestId"`
			AuthChallenge struct {
				Source string `json:"source"`
				Origin string `json:"origin"`
			} `json:"authChallenge"`
		}
		if json.Unmarshal(msg.Params, &params) != nil || params.RequestID == "" {
			return
		}
		answer := map[string]any{"response": r.answer(params.RequestID, params.AuthChallenge.Source, params.AuthChallenge.Origin)}
		if answer["response"] == authProvide {
			answer["username"] = r.auth.Username
			answer["password"] = r.auth.Password
		}
		r.m.gateCommand(t.gateSession, "Fetch.continueWithAuth", map[string]any{
			"requestId":             params.RequestID,
			"authChallengeResponse": answer,
		}, nil)
	}
}

// answer decides a challenge: the credential for the first challenge of a
// request from the proxy itself, a cancel for a second one, and the
// browser's own handling for every other challenge, such as a site's.
func (r *proxyResponder) answer(requestID, source, origin string) string {
	if source != "Proxy" || !r.fromProxy(origin) {
		return authDefault
	}
	if _, again := r.answered[requestID]; again {
		delete(r.answered, requestID)
		return authCancel
	}
	if len(r.answered) >= maxAnsweredChallenges {
		clear(r.answered)
	}
	r.answered[requestID] = struct{}{}
	return authProvide
}

// fromProxy reports whether a challenge's origin, such as
// http://127.0.0.1:41234, is one of the proxy's addresses.
func (r *proxyResponder) fromProxy(origin string) bool {
	host := origin
	if parsed, err := url.Parse(origin); err == nil && parsed.Host != "" {
		host = parsed.Host
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		return false
	}
	_, ok := r.addresses[host]
	return ok
}
