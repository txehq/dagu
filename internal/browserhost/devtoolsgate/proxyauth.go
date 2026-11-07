// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
// the proxy's challenge is answered over DevTools.
//
// The answer is given at the browser level, on a session of the gate's own
// on the browser target, with Fetch interception in place before the gate
// holds any target and before it admits a client. A target created with a
// URL (Target.createTarget) starts its first request in the browser process
// before its target can be held, so an interception set up on the target
// itself comes too late for that request (TXE-6197). One at the browser
// level is in place for every request of every target, those not yet
// attached included: pages, popups opened with an address, frames of other
// sites, workers, and relies on no hold of the target. The session is the
// gate's alone: its events reach no client, and no client can address it.
// A client's own Fetch interception, on a private session or on the shared
// browser session, is a session of its own and unaffected.
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

// install sets the responder's hooks on its mux: its interception is put in
// place by mux.start before the gate's auto-attach, the targets that existed
// before it are brought under it right after, and the events of its session
// come to it. It must run before the mux reads the pipe.
func (r *proxyResponder) install() {
	r.m.beforeAttach = r.start
	r.m.afterAttach = r.coverExisting
	r.m.onGateEvent = r.event
}

// fetchPatterns intercepts every request at its start.
var fetchPatterns = []map[string]any{{"urlPattern": "*", "requestStage": "Request"}}

// start attaches the responder's own session on the browser target and
// turns on its interception there, with the proxy's challenges handled. It
// returns an error when the browser refuses either, and the gate then does
// not serve: a browser whose requests nobody answers for would fail them
// all at the proxy.
func (r *proxyResponder) start(ctx context.Context) error {
	result, err := r.m.call(ctx, "", "Target.attachToBrowserTarget", map[string]any{})
	if err != nil {
		return fmt.Errorf("turn on the proxy's answer for the browser: %w", err)
	}
	session := sessionOf(result)
	if session == "" {
		return errors.New("turn on the proxy's answer for the browser: Target.attachToBrowserTarget: no session")
	}
	r.m.mu.Lock()
	r.m.browserSession = session
	r.m.mu.Unlock()
	_, err = r.m.call(ctx, session, "Fetch.enable", map[string]any{"handleAuthRequests": true, "patterns": fetchPatterns})
	if err != nil {
		return fmt.Errorf("turn on the proxy's answer for the browser: %w", err)
	}
	return nil
}

// coverExisting brings the targets that existed before start under the
// browser-level interception. A document keeps the request loaders it was
// given when it was made, and the interception is in those made from then
// on: the browser's first page, open before the gate could speak to it,
// would send its requests past the responder (measured: a fetch from it met
// the proxy's challenge and nobody answered). Turning Fetch on and off again
// on the gate's own session of such a target makes the browser give it new
// loaders, built with the interception in place. A target that takes no
// Fetch is left as it is; one that takes it on but not off would hold its
// requests for nobody, so that ends the start.
func (r *proxyResponder) coverExisting(ctx context.Context) error {
	r.m.mu.Lock()
	sessions := make([]string, 0, len(r.m.gateSessions))
	for session := range r.m.gateSessions {
		sessions = append(sessions, session)
	}
	r.m.mu.Unlock()
	for _, session := range sessions {
		if _, err := r.m.call(ctx, session, "Fetch.enable", map[string]any{"patterns": fetchPatterns}); err != nil {
			continue
		}
		if _, err := r.m.call(ctx, session, "Fetch.disable", map[string]any{}); err != nil {
			return fmt.Errorf("turn on the proxy's answer for the browser's first targets: %w", err)
		}
	}
	return nil
}

// event answers the interception events on the gate's sessions: a paused
// request is let go on wherever it paused, and a challenge is answered on
// the responder's own session, the only one that handles them. m.mu is
// held.
func (r *proxyResponder) event(session string, msg message) {
	switch msg.Method {
	case "Fetch.requestPaused":
		var params struct {
			RequestID string `json:"requestId"`
		}
		if json.Unmarshal(msg.Params, &params) != nil || params.RequestID == "" {
			return
		}
		r.m.gateCommand(session, "Fetch.continueRequest", map[string]any{"requestId": params.RequestID}, nil)
	case "Fetch.authRequired":
		if session != r.m.browserSession {
			return
		}
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
		r.m.gateCommand(session, "Fetch.continueWithAuth", map[string]any{
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
