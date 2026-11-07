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
// sessions, auto-attach with waitForDebuggerOnStart, discovery, and a
// per-session Fetch domain. Methods under "Fake." let a test drive it and
// read its state.
type fakeBrowser struct {
	in  *bufio.Reader
	out io.Writer

	writeMu sync.Mutex
	mu      sync.Mutex

	nextTarget  int
	nextSession int
	targets     map[string]*fakeTarget
	sessions    map[string]*fakeSession
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
	// failStart makes the browser exit before answering, as a browser
	// that cannot adopt its pipes does.
	failStart bool
	// exitMarker is a file the process form writes when it exits on EOF.
	exitMarker string
	argv       []string
}

type fakeTarget struct {
	id    string
	typ   string
	url   string
	title string
	// pausedBy is the auto-attached session holding the target, "" when it
	// runs.
	pausedBy string
}

type fakeSession struct {
	id       string
	targetID string
	// auto is set for a session the root auto-attach made.
	auto       bool
	fetchOn    bool
	fetchAuth  bool
	nestedAuto bool
	nestedWait bool
}

func newFakeBrowser(in io.Reader, out io.Writer) *fakeBrowser {
	f := &fakeBrowser{
		in:        bufio.NewReaderSize(in, pipeReadBuffer),
		out:       out,
		targets:   make(map[string]*fakeTarget),
		sessions:  make(map[string]*fakeSession),
		requests:  make(map[string]map[string]bool),
		continues: make(map[string]int),
	}
	f.addTargetLocked("page", "about:blank", "blank")
	return f
}

func (f *fakeBrowser) addTargetLocked(typ, url, title string) *fakeTarget {
	f.nextTarget++
	t := &fakeTarget{id: fmt.Sprintf("T%d", f.nextTarget), typ: typ, url: url, title: title}
	f.targets[t.id] = t
	return t
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
		// Chrome exits; the pipe closes with it.
		if closer, ok := f.out.(io.Closer); ok {
			_ = closer.Close()
		}
	case "Target.setAutoAttach":
		if cmd.SessionID != "" {
			if s, ok := f.sessions[cmd.SessionID]; ok {
				s.nestedAuto = boolean("autoAttach")
				s.nestedWait = boolean("waitForDebuggerOnStart")
			}
			f.reply(cmd.ID, cmd.SessionID, map[string]any{})
			return
		}
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
			}
		}
		f.reply(cmd.ID, cmd.SessionID, map[string]any{})
	case "Fetch.enable":
		s, ok := f.sessions[cmd.SessionID]
		if !ok {
			f.replyError(cmd.ID, cmd.SessionID, -32001, "Session with given id not found.")
			return
		}
		s.fetchOn = true
		s.fetchAuth = boolean("handleAuthRequests")
		f.reply(cmd.ID, cmd.SessionID, map[string]any{})
	case "Fetch.disable":
		if s, ok := f.sessions[cmd.SessionID]; ok {
			s.fetchOn = false
			s.fetchAuth = false
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
	case "Fake.request":
		// A request on a target pauses once on every session intercepting
		// it, as Chrome chains interceptors across sessions.
		delivered := 0
		for _, s := range f.sortedSessions() {
			if s.targetID == str("targetId") && s.fetchOn {
				if f.requests[s.id] == nil {
					f.requests[s.id] = make(map[string]bool)
				}
				f.requests[s.id][str("requestId")] = true
				f.event(s.id, "Fetch.requestPaused", map[string]any{
					"requestId": str("requestId"), "request": map[string]any{"url": str("url")},
				})
				delivered++
			}
		}
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
	Sessions  []fakeSessionState `json:"sessions"`
	Paused    []string           `json:"paused"`
	Resumed   []string           `json:"resumed"`
	Continues map[string]int     `json:"continues"`
	Targets   []string           `json:"targets"`
}

type fakeSessionState struct {
	ID        string `json:"id"`
	TargetID  string `json:"targetId"`
	Auto      bool   `json:"auto"`
	FetchOn   bool   `json:"fetchOn"`
	FetchAuth bool   `json:"fetchAuth"`
}

func (f *fakeBrowser) stateLocked() fakeState {
	state := fakeState{Continues: map[string]int{}, Resumed: append([]string(nil), f.resumed...)}
	for _, s := range f.sortedSessions() {
		state.Sessions = append(state.Sessions, fakeSessionState{ID: s.id, TargetID: s.targetID, Auto: s.auto, FetchOn: s.fetchOn, FetchAuth: s.fetchAuth})
	}
	for _, t := range f.sortedTargets() {
		state.Targets = append(state.Targets, t.id)
		if t.pausedBy != "" {
			state.Paused = append(state.Paused, t.id)
		}
	}
	maps.Copy(state.Continues, f.continues)
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
		if arg == "--fail-start" {
			f.failStart = true
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
