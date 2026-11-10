// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"sort"
	"strings"
	"sync"
)

// fakeBrowser speaks the part of the DevTools protocol the gate relies on,
// over Chrome's pipe framing, the way one browser connection would: targets,
// sessions, auto-attach with waitForDebuggerOnStart, discovery, sessions on
// the browser target, and the Fetch domain per session, at the browser level
// and on a target. Methods under "Fake." let a test drive it and read its
// state.
//
// Requests are modelled as Chrome makes them: a request pauses once on every
// session intercepting it, the browser-level ones and its target's, and
// reaches the network once every one of them continued it. There, when a
// proxy is set (Fake.proxy), a request without a credential is challenged:
// the challenge goes to the first session it paused on that handles auth,
// and a request no session answers for is refused, as a 407 nobody answers
// fails. A target created with a URL starts its navigation request as it
// is created, before any session on it exists, as the browser process does:
// only browser-level interception can see that request. And a target keeps
// the request loaders it was given when it was made: a browser-level
// interception turned on later does not reach it until Fetch is turned on
// or off on one of its own sessions, which makes the browser build its
// loaders again.
type fakeBrowser struct {
	in  *bufio.Reader
	out io.Writer

	writeMu sync.Mutex
	mu      sync.Mutex

	// exitsSlowly keeps the pipe open after Browser.close, as Chrome does
	// while it finishes writing its profile.
	exitsSlowly bool
	// refuseBrowserFetch answers Fetch.enable on a browser-target session
	// with an error, as a browser without browser-level interception would.
	refuseBrowserFetch bool

	nextTarget  int
	nextSession int
	targets     map[string]*fakeTarget
	sessions    map[string]*fakeSession
	// root is the connection's own browser session, the one a command
	// without a session id addresses: its Fetch intercepts every request,
	// as a client's browser-level Fetch.enable does over a port.
	root *fakeSession
	// autoAttach is the root auto-attach of the connection.
	autoAttach struct {
		on   bool
		wait bool
	}
	discover bool
	// resumed records the targets resumed by Runtime.runIfWaitingForDebugger
	// in order.
	resumed []string
	// requests are the paused Fetch requests by session and request id.
	requests map[string]map[string]bool
	// continues counts Fetch.continueRequest per session.
	continues map[string]int
	// inFlight are the requests made and not yet completed or refused.
	inFlight map[string]*fakeRequest
	// proxyOrigin, when set, is the proxy that challenges every request
	// reaching the network without a credential.
	proxyOrigin string
	// completed and refused record the requests that reached their site
	// and the ones the proxy refused, in order; credentials records what
	// each completed request through the proxy was given.
	completed   []string
	refused     []string
	credentials map[string]string
	// log records, in order, the commands and events that tell the setup's
	// order: the browser-session attach and its Fetch.enable, the root
	// auto-attach, a target's first request, a resume.
	log []string
	// failStart makes the browser exit before answering, as a browser
	// that cannot adopt its pipes does.
	failStart bool
	// exitMarker is a file the process form writes when it exits on EOF.
	exitMarker string
	argv       []string
	// closing is set by Browser.close: the fake exits, as Chrome does, so a
	// gate that closed the browser sees its process end and not only its
	// pipe.
	closing bool
}

type fakeTarget struct {
	id    string
	typ   string
	url   string
	title string
	// pausedBy is the auto-attached session holding the target, "" when it
	// runs.
	pausedBy string
	// loaders are the browser-level sessions whose interception the
	// target's request loaders were built with: those intercepting when the
	// target was made, or when Fetch was last turned on or off on one of
	// its sessions.
	loaders map[string]bool
}

type fakeSession struct {
	id       string
	targetID string
	// auto is set for a session the root auto-attach made.
	auto bool
	// browser is set for a session on the browser target
	// (Target.attachToBrowserTarget); its Fetch intercepts every request.
	browser    bool
	fetchOn    bool
	fetchAuth  bool
	nestedAuto bool
	nestedWait bool
}

// fakeChallenge is the authentication challenge a request meets at the
// network: a proxy's, or a site's own.
type fakeChallenge struct {
	Source string `json:"source"`
	Origin string `json:"origin"`
}

// fakeRequest is a request on its way through the interceptors to the
// network.
type fakeRequest struct {
	id        string
	targetID  string
	url       string
	challenge *fakeChallenge
	// chain are the sessions the request paused on, in order; pendingOn
	// are those that have not continued it yet.
	chain     []*fakeSession
	pendingOn map[string]bool
	// authOn is the session asked to answer the challenge, "" when none was.
	authOn string
}

func newFakeBrowser(in io.Reader, out io.Writer) *fakeBrowser {
	f := &fakeBrowser{
		in:          bufio.NewReaderSize(in, pipeReadBuffer),
		out:         out,
		targets:     make(map[string]*fakeTarget),
		sessions:    make(map[string]*fakeSession),
		requests:    make(map[string]map[string]bool),
		continues:   make(map[string]int),
		inFlight:    make(map[string]*fakeRequest),
		credentials: make(map[string]string),
		root:        &fakeSession{browser: true},
	}
	f.addTargetLocked("page", "about:blank", "blank")
	return f
}

// sessionLocked returns the session a command on sessionID addresses: the
// connection's own browser session for "".
func (f *fakeBrowser) sessionLocked(sessionID string) (*fakeSession, bool) {
	if sessionID == "" {
		return f.root, true
	}
	s, ok := f.sessions[sessionID]
	return s, ok
}

// interceptorsLocked are the sessions that may intercept requests, the
// connection's own first, then every other in order.
func (f *fakeBrowser) interceptorsLocked() []*fakeSession {
	return append([]*fakeSession{f.root}, f.sortedSessions()...)
}

func (f *fakeBrowser) addTargetLocked(typ, url, title string) *fakeTarget {
	f.nextTarget++
	t := &fakeTarget{id: fmt.Sprintf("T%d", f.nextTarget), typ: typ, url: url, title: title}
	f.targets[t.id] = t
	f.rebuildLoadersLocked(t)
	return t
}

// rebuildLoadersLocked gives t request loaders built with the browser-level
// interception in place now.
func (f *fakeBrowser) rebuildLoadersLocked(t *fakeTarget) {
	t.loaders = map[string]bool{}
	for _, s := range f.interceptorsLocked() {
		if s.browser && s.fetchOn {
			t.loaders[s.id] = true
		}
	}
}

func (f *fakeBrowser) newSessionLocked(targetID string, auto bool) *fakeSession {
	f.nextSession++
	s := &fakeSession{id: fmt.Sprintf("S%d", f.nextSession), targetID: targetID, auto: auto}
	f.sessions[s.id] = s
	return s
}

func (f *fakeBrowser) targetInfo(t *fakeTarget) map[string]any {
	return map[string]any{"targetId": t.id, "type": t.typ, "url": t.url, "title": t.title, "attached": true}
}

// serve answers commands until the pipe closes. It returns nil on EOF.
func (f *fakeBrowser) serve() error {
	if f.failStart {
		return errors.New("fake browser: failing on purpose")
	}
	for {
		data, err := f.in.ReadBytes(0)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		f.handle(data[:len(data)-1])
		f.mu.Lock()
		closing := f.closing
		f.mu.Unlock()
		if closing {
			return nil
		}
	}
}

func (f *fakeBrowser) send(value any) {
	data, err := json.Marshal(value)
	if err != nil {
		return
	}
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	_, _ = f.out.Write(append(data, 0))
}

func (f *fakeBrowser) event(sessionID, method string, params any) {
	event := map[string]any{"method": method, "params": params}
	if sessionID != "" {
		event["sessionId"] = sessionID
	}
	f.send(event)
}

func (f *fakeBrowser) reply(id json.RawMessage, sessionID string, result any) {
	reply := map[string]any{"id": id, "result": result}
	if sessionID != "" {
		reply["sessionId"] = sessionID
	}
	f.send(reply)
}

func (f *fakeBrowser) replyError(id json.RawMessage, sessionID string, code int, text string) {
	reply := map[string]any{"id": id, "error": map[string]any{"code": code, "message": text}}
	if sessionID != "" {
		reply["sessionId"] = sessionID
	}
	f.send(reply)
}

func (f *fakeBrowser) handle(data []byte) {
	var cmd struct {
		ID        json.RawMessage `json:"id"`
		Method    string          `json:"method"`
		SessionID string          `json:"sessionId"`
		Params    json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(data, &cmd); err != nil {
		return
	}
	var params map[string]any
	_ = json.Unmarshal(cmd.Params, &params)
	str := func(key string) string { v, _ := params[key].(string); return v }
	boolean := func(key string) bool { v, _ := params[key].(bool); return v }

	f.mu.Lock()
	defer f.mu.Unlock()
	switch cmd.Method {
	case "Browser.getVersion":
		f.reply(cmd.ID, cmd.SessionID, map[string]any{
			"protocolVersion": "1.3", "product": "FakeBrowser/1.0", "revision": "@fake",
			"userAgent": "FakeBrowser UA", "jsVersion": "0.0",
		})
	case "Browser.close":
		f.reply(cmd.ID, cmd.SessionID, map[string]any{})
		if f.exitsSlowly {
			return
		}
		// Chrome exits; the pipe closes with it, and so does the process.
		f.closing = true
		if closer, ok := f.out.(io.Closer); ok {
			_ = closer.Close()
		}
	case "Target.attachToBrowserTarget":
		// Only a browser-level session may ask for another.
		if s, ok := f.sessions[cmd.SessionID]; cmd.SessionID != "" && (!ok || !s.browser) {
			f.replyError(cmd.ID, cmd.SessionID, -32000, "Not allowed")
			return
		}
		s := f.newSessionLocked("", false)
		s.browser = true
		f.log = append(f.log, "Target.attachToBrowserTarget -> "+s.id)
		// Chrome announces the session before it answers, as for any
		// attach, with the browser as the target.
		f.event("", "Target.attachedToTarget", map[string]any{
			"sessionId": s.id, "waitingForDebugger": false,
			"targetInfo": map[string]any{"targetId": "B1", "type": "browser", "url": "", "title": "", "attached": true},
		})
		f.reply(cmd.ID, cmd.SessionID, map[string]any{"sessionId": s.id})
	case "Target.setAutoAttach":
		if cmd.SessionID != "" {
			if s, ok := f.sessions[cmd.SessionID]; ok {
				s.nestedAuto = boolean("autoAttach")
				s.nestedWait = boolean("waitForDebuggerOnStart")
			}
			f.reply(cmd.ID, cmd.SessionID, map[string]any{})
			return
		}
		f.log = append(f.log, "Target.setAutoAttach")
		f.autoAttach.on = boolean("autoAttach")
		f.autoAttach.wait = boolean("waitForDebuggerOnStart")
		if f.autoAttach.on {
			for _, t := range f.sortedTargets() {
				s := f.newSessionLocked(t.id, true)
				f.event("", "Target.attachedToTarget", map[string]any{
					"sessionId": s.id, "targetInfo": f.targetInfo(t), "waitingForDebugger": false,
				})
			}
		}
		f.reply(cmd.ID, "", map[string]any{})
	case "Target.setDiscoverTargets":
		f.discover = boolean("discover")
		if f.discover {
			for _, t := range f.sortedTargets() {
				f.event("", "Target.targetCreated", map[string]any{"targetInfo": f.targetInfo(t)})
			}
		}
		f.reply(cmd.ID, "", map[string]any{})
	case "Target.getTargets":
		infos := make([]map[string]any, 0, len(f.targets))
		for _, t := range f.sortedTargets() {
			infos = append(infos, f.targetInfo(t))
		}
		f.reply(cmd.ID, cmd.SessionID, map[string]any{"targetInfos": infos})
	case "Target.createTarget":
		t := f.addTargetLocked("page", str("url"), "new")
		if f.discover {
			f.event("", "Target.targetCreated", map[string]any{"targetInfo": f.targetInfo(t)})
		}
		if t.url != "" && t.url != "about:blank" {
			// The browser process starts the navigation as it creates the
			// target, before any session is attached to it.
			f.requestLocked("nav:"+t.id, t.id, t.url, f.proxyChallenge())
		}
		if f.autoAttach.on {
			s := f.newSessionLocked(t.id, true)
			if f.autoAttach.wait {
				t.pausedBy = s.id
			}
			f.event("", "Target.attachedToTarget", map[string]any{
				"sessionId": s.id, "targetInfo": f.targetInfo(t), "waitingForDebugger": f.autoAttach.wait,
			})
		}
		f.reply(cmd.ID, cmd.SessionID, map[string]any{"targetId": t.id})
	case "Target.attachToTarget":
		t, ok := f.targets[str("targetId")]
		if !ok {
			f.replyError(cmd.ID, cmd.SessionID, -32602, "No target with given id found")
			return
		}
		s := f.newSessionLocked(t.id, false)
		f.event(cmd.SessionID, "Target.attachedToTarget", map[string]any{
			"sessionId": s.id, "targetInfo": f.targetInfo(t), "waitingForDebugger": t.pausedBy != "",
		})
		f.reply(cmd.ID, cmd.SessionID, map[string]any{"sessionId": s.id})
	case "Target.detachFromTarget":
		s, ok := f.sessions[str("sessionId")]
		if !ok {
			f.replyError(cmd.ID, cmd.SessionID, -32602, "No session with given id")
			return
		}
		f.dropSessionLocked(s, cmd.SessionID)
		f.reply(cmd.ID, cmd.SessionID, map[string]any{})
	case "Target.closeTarget":
		t, ok := f.targets[str("targetId")]
		if !ok {
			f.replyError(cmd.ID, cmd.SessionID, -32602, "No target with given id found")
			return
		}
		for _, s := range f.sortedSessions() {
			if s.targetID == t.id {
				f.dropSessionLocked(s, "")
			}
		}
		delete(f.targets, t.id)
		if f.discover {
			f.event("", "Target.targetDestroyed", map[string]any{"targetId": t.id})
		}
		f.reply(cmd.ID, cmd.SessionID, map[string]any{"success": true})
	case "Runtime.runIfWaitingForDebugger":
		if s, ok := f.sessions[cmd.SessionID]; ok {
			if t, ok := f.targets[s.targetID]; ok && t.pausedBy == s.id {
				t.pausedBy = ""
				f.resumed = append(f.resumed, t.id)
				f.log = append(f.log, "resume "+t.id)
			}
		}
		f.reply(cmd.ID, cmd.SessionID, map[string]any{})
	case "Fetch.enable":
		s, ok := f.sessionLocked(cmd.SessionID)
		if !ok {
			f.replyError(cmd.ID, cmd.SessionID, -32001, "Session with given id not found.")
			return
		}
		if s.browser && f.refuseBrowserFetch {
			f.replyError(cmd.ID, cmd.SessionID, -32601, "'Fetch.enable' wasn't found")
			return
		}
		s.fetchOn = true
		s.fetchAuth = boolean("handleAuthRequests")
		if s.browser && s != f.root {
			f.log = append(f.log, fmt.Sprintf("Fetch.enable %s auth=%t", s.id, s.fetchAuth))
		}
		if t, ok := f.targets[s.targetID]; ok && !s.browser {
			f.rebuildLoadersLocked(t)
			f.log = append(f.log, "Fetch.enable "+s.id+" on "+t.id)
		}
		f.reply(cmd.ID, cmd.SessionID, map[string]any{})
	case "Fetch.disable":
		if s, ok := f.sessionLocked(cmd.SessionID); ok {
			s.fetchOn = false
			s.fetchAuth = false
			if t, ok := f.targets[s.targetID]; ok && !s.browser {
				f.rebuildLoadersLocked(t)
				f.log = append(f.log, "Fetch.disable "+s.id+" on "+t.id)
			}
		}
		f.reply(cmd.ID, cmd.SessionID, map[string]any{})
	case "Fetch.continueRequest":
		pending := f.requests[cmd.SessionID]
		requestID := str("requestId")
		if !pending[requestID] {
			f.replyError(cmd.ID, cmd.SessionID, -32602, "Invalid InterceptionId.")
			return
		}
		delete(pending, requestID)
		f.continues[cmd.SessionID]++
		f.reply(cmd.ID, cmd.SessionID, map[string]any{})
		if r, ok := f.inFlight[requestID]; ok {
			delete(r.pendingOn, cmd.SessionID)
			if len(r.pendingOn) == 0 {
				f.networkLocked(r)
			}
		}
	case "Fetch.continueWithAuth":
		var p struct {
			RequestID string `json:"requestId"`
			Response  struct {
				Response string `json:"response"`
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"authChallengeResponse"`
		}
		_ = json.Unmarshal(cmd.Params, &p)
		r, ok := f.inFlight[p.RequestID]
		if !ok || r.authOn != cmd.SessionID {
			f.replyError(cmd.ID, cmd.SessionID, -32602, "Invalid InterceptionId.")
			return
		}
		f.reply(cmd.ID, cmd.SessionID, map[string]any{})
		delete(f.inFlight, r.id)
		if p.Response.Response != authProvide {
			// The browser has no credential of its own to fall back on.
			f.refused = append(f.refused, r.id)
			return
		}
		f.credentials[r.id] = p.Response.Username + ":" + p.Response.Password
		f.completed = append(f.completed, r.id)
	case "Fake.proxy":
		f.proxyOrigin = str("origin")
		f.reply(cmd.ID, cmd.SessionID, map[string]any{})
	case "Fake.request":
		challenge := f.proxyChallenge()
		if raw, ok := params["challenge"].(map[string]any); ok {
			source, _ := raw["source"].(string)
			origin, _ := raw["origin"].(string)
			challenge = &fakeChallenge{Source: source, Origin: origin}
		}
		delivered := f.requestLocked(str("requestId"), str("targetId"), str("url"), challenge)
		f.reply(cmd.ID, cmd.SessionID, map[string]any{"delivered": delivered})
	case "Fake.createChild":
		// A child target (a worker, a frame) is attached only through the
		// sessions of its parent that asked for auto-attach, under each of
		// them, as Chrome does.
		parent, ok := f.targets[str("targetId")]
		if !ok {
			f.replyError(cmd.ID, cmd.SessionID, -32602, "No target with given id found")
			return
		}
		typ := str("type")
		if typ == "" {
			typ = "worker"
		}
		child := f.addTargetLocked(typ, "child://"+parent.id, "child")
		for _, s := range f.sortedSessions() {
			if s.targetID != parent.id || !s.nestedAuto {
				continue
			}
			cs := f.newSessionLocked(child.id, true)
			if s.nestedWait {
				child.pausedBy = cs.id
			}
			f.event(s.id, "Target.attachedToTarget", map[string]any{
				"sessionId": cs.id, "targetInfo": f.targetInfo(child), "waitingForDebugger": s.nestedWait,
			})
		}
		f.reply(cmd.ID, cmd.SessionID, map[string]any{"targetId": child.id})
	case "Fake.event":
		var raw struct {
			SessionID string          `json:"sessionId"`
			Method    string          `json:"method"`
			Params    json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(cmd.Params, &raw)
		f.event(raw.SessionID, raw.Method, raw.Params)
		f.reply(cmd.ID, cmd.SessionID, map[string]any{})
	case "Fake.state":
		f.reply(cmd.ID, cmd.SessionID, f.stateLocked())
	case "Fake.argv":
		f.reply(cmd.ID, cmd.SessionID, map[string]any{"argv": f.argv})
	default:
		if strings.HasSuffix(cmd.Method, ".enable") || strings.HasSuffix(cmd.Method, ".disable") ||
			cmd.Method == "Runtime.addBinding" || cmd.Method == "Target.activateTarget" {
			if cmd.SessionID != "" {
				if _, ok := f.sessions[cmd.SessionID]; !ok {
					f.replyError(cmd.ID, cmd.SessionID, -32001, "Session with given id not found.")
					return
				}
			}
			f.reply(cmd.ID, cmd.SessionID, map[string]any{})
			return
		}
		if cmd.Method == "Runtime.evaluate" {
			f.reply(cmd.ID, cmd.SessionID, map[string]any{"result": map[string]any{"type": "number", "value": 1}})
			return
		}
		f.replyError(cmd.ID, cmd.SessionID, -32601, fmt.Sprintf("'%s' wasn't found", cmd.Method))
	}
}

// proxyChallenge is the challenge the proxy, when one is set, makes to a
// request without a credential.
func (f *fakeBrowser) proxyChallenge() *fakeChallenge {
	if f.proxyOrigin == "" {
		return nil
	}
	return &fakeChallenge{Source: "Proxy", Origin: f.proxyOrigin}
}

// requestLocked makes a request on targetID: it pauses once on every session
// intercepting it, the browser-level ones the target's loaders were built
// with and the target's own, as Chrome chains interceptors across sessions,
// and reaches the network at once when none does. It returns how many
// sessions it paused on.
func (f *fakeBrowser) requestLocked(requestID, targetID, url string, challenge *fakeChallenge) int {
	r := &fakeRequest{id: requestID, targetID: targetID, url: url, challenge: challenge, pendingOn: map[string]bool{}}
	f.inFlight[requestID] = r
	f.log = append(f.log, "request "+requestID)
	t := f.targets[targetID]
	for _, s := range f.interceptorsLocked() {
		if !s.fetchOn {
			continue
		}
		if s.browser && (t == nil || !t.loaders[s.id]) {
			continue
		}
		if !s.browser && s.targetID != targetID {
			continue
		}
		if f.requests[s.id] == nil {
			f.requests[s.id] = make(map[string]bool)
		}
		f.requests[s.id][requestID] = true
		r.chain = append(r.chain, s)
		r.pendingOn[s.id] = true
		f.event(s.id, "Fetch.requestPaused", map[string]any{
			"requestId": requestID, "request": map[string]any{"url": url},
		})
	}
	if len(r.pendingOn) == 0 {
		f.networkLocked(r)
	}
	return len(r.pendingOn)
}

// networkLocked takes a request every interceptor continued to the network.
// A challenge there goes to the first session it paused on that handles
// auth; with none, the request is refused, as a 407 nobody answers fails.
func (f *fakeBrowser) networkLocked(r *fakeRequest) {
	if r.challenge == nil {
		delete(f.inFlight, r.id)
		f.completed = append(f.completed, r.id)
		return
	}
	for _, s := range r.chain {
		if !s.fetchAuth {
			continue
		}
		r.authOn = s.id
		f.event(s.id, "Fetch.authRequired", map[string]any{
			"requestId": r.id, "request": map[string]any{"url": r.url},
			"authChallenge": map[string]any{"source": r.challenge.Source, "origin": r.challenge.Origin, "scheme": "basic", "realm": "fake"},
		})
		return
	}
	delete(f.inFlight, r.id)
	f.refused = append(f.refused, r.id)
}

func (f *fakeBrowser) dropSessionLocked(s *fakeSession, via string) {
	delete(f.sessions, s.id)
	delete(f.requests, s.id)
	if t, ok := f.targets[s.targetID]; ok && t.pausedBy == s.id {
		t.pausedBy = ""
	}
	f.event(via, "Target.detachedFromTarget", map[string]any{"sessionId": s.id, "targetId": s.targetID})
}

func (f *fakeBrowser) sortedTargets() []*fakeTarget {
	targets := make([]*fakeTarget, 0, len(f.targets))
	for _, t := range f.targets {
		targets = append(targets, t)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].id < targets[j].id })
	return targets
}

func (f *fakeBrowser) sortedSessions() []*fakeSession {
	sessions := make([]*fakeSession, 0, len(f.sessions))
	for _, s := range f.sessions {
		sessions = append(sessions, s)
	}
	sort.Slice(sessions, func(i, j int) bool {
		if len(sessions[i].id) != len(sessions[j].id) {
			return len(sessions[i].id) < len(sessions[j].id)
		}
		return sessions[i].id < sessions[j].id
	})
	return sessions
}

// fakeState is what Fake.state reports.
type fakeState struct {
	Sessions    []fakeSessionState `json:"sessions"`
	Paused      []string           `json:"paused"`
	Resumed     []string           `json:"resumed"`
	Continues   map[string]int     `json:"continues"`
	Targets     []string           `json:"targets"`
	Completed   []string           `json:"completed"`
	Refused     []string           `json:"refused"`
	Credentials map[string]string  `json:"credentials"`
	Log         []string           `json:"log"`
}

type fakeSessionState struct {
	ID        string `json:"id"`
	TargetID  string `json:"targetId"`
	Auto      bool   `json:"auto"`
	Browser   bool   `json:"browser"`
	FetchOn   bool   `json:"fetchOn"`
	FetchAuth bool   `json:"fetchAuth"`
}

func (f *fakeBrowser) stateLocked() fakeState {
	state := fakeState{
		Continues:   map[string]int{},
		Resumed:     append([]string(nil), f.resumed...),
		Completed:   append([]string(nil), f.completed...),
		Refused:     append([]string(nil), f.refused...),
		Credentials: map[string]string{},
		Log:         append([]string(nil), f.log...),
	}
	for _, s := range f.sortedSessions() {
		state.Sessions = append(state.Sessions, fakeSessionState{ID: s.id, TargetID: s.targetID, Auto: s.auto, Browser: s.browser, FetchOn: s.fetchOn, FetchAuth: s.fetchAuth})
	}
	for _, t := range f.sortedTargets() {
		state.Targets = append(state.Targets, t.id)
		if t.pausedBy != "" {
			state.Paused = append(state.Paused, t.id)
		}
	}
	maps.Copy(state.Continues, f.continues)
	maps.Copy(state.Credentials, f.credentials)
	return state
}

// runFakeBrowserProcess is the process form: the test binary started by
// the gate as "the browser", reading fd 3 and writing fd 4 on Unix, or the
// handles named by --remote-debugging-io-pipes on Windows.
func runFakeBrowserProcess(args []string) int {
	in, out, err := fakeBrowserPipes(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake browser:", err)
		return 3
	}
	f := newFakeBrowser(in, out)
	f.argv = args
	for _, arg := range args {
		switch arg {
		case "--fail-start":
			f.failStart = true
		case "--refuse-browser-fetch":
			f.refuseBrowserFetch = true
		}
		if marker, ok := strings.CutPrefix(arg, "--exit-marker="); ok {
			f.exitMarker = marker
		}
	}
	if err := f.serve(); err != nil {
		fmt.Fprintln(os.Stderr, "fake browser:", err)
		return 3
	}
	if f.exitMarker != "" {
		_ = os.WriteFile(f.exitMarker, []byte("eof\n"), 0o600)
	}
	return 0
}
