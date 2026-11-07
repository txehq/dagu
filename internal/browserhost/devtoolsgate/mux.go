// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// The pipe is one DevTools connection, and Chrome keeps auto-attach,
// discovery and sessions per connection. The multiplexer gives each
// websocket client a connection of its own on top of the pipe:
//
//   - command ids are remapped, so each client has its own id space;
//   - the gate holds the root Target.setAutoAttach itself, with
//     waitForDebuggerOnStart, so every new target is held until the clients
//     that asked to wait have seen it. For each client subscribed to
//     auto-attach the gate attaches a private session per target with
//     Target.attachToTarget, so two clients' Fetch, Page or Network state on
//     the same target never meet; a late subscriber is replayed the targets
//     that already exist;
//   - Target.setDiscoverTargets is per client, with the same replay;
//   - sessions a client attached explicitly are its own, and the gate
//     detaches them when the client goes away;
//   - events with a session id go to the client holding that session;
//     browser-level events go to every client.
//
// Commands the gate sends for itself run on the gate's own sessions, never on
// a client's.

// outQueue is how many messages may wait for the pipe before a writer blocks.
// The queue to the browser is unbounded: a client's command is never held
// under the multiplexer's lock, and a browser that stops reading is found
// by the gate's heartbeat and ended within seconds.

// cdpError is the error object of a failed DevTools command.
type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// message is a DevTools message of any kind: a command, a reply or an event.
type message struct {
	ID        json.RawMessage `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     json.RawMessage `json:"error,omitempty"`
}

// targetInfo is the part of DevTools' TargetInfo the gate reads.
type targetInfo struct {
	TargetID string `json:"targetId"`
	Type     string `json:"type"`
}

// pendingCommand is a command the gate sent to the browser and the reply it
// awaits.
type pendingCommand struct {
	// client and clientID route the reply back to the client that issued
	// the command; a gate-originated command has no client.
	client   *client
	clientID json.RawMessage
	// onReply, when set, handles the reply in place of routing it.
	onReply func(result json.RawMessage, cdpErr *cdpError)
}

// target is a target the gate's own auto-attach holds a session on.
type target struct {
	id   string
	typ  string
	info json.RawMessage
	// parent is the target this one was attached under, "" at the root.
	parent string
	// gateSession is the gate's own session on the target.
	gateSession string
	// paused is set while Chrome holds the target for the gate's
	// waitForDebuggerOnStart.
	paused bool
	// waiting are the clients that asked to wait for this target and have
	// not resumed it yet.
	waiting map[*client]struct{}
	// attaching counts the private attaches in flight for the target; the
	// target is not resumed while any is.
	attaching int
	// holds counts the gate's own setup pending on the target, such as a
	// Fetch.enable on gateSession that must be in place before the target
	// runs; the target is not resumed while any is.
	holds int
	// nestedAutoAttach is set once the gate asked for auto-attach on
	// gateSession, so the target's own children are held too.
	nestedAutoAttach bool
	// private maps a client to its private session on the target;
	// privateAttaching holds the clients whose private attach is in flight,
	// so a replay racing a live attach makes one session, not two.
	private          map[*client]string
	privateAttaching map[*client]struct{}
}

// attachRequest is a Target.attachToTarget the gate issued and whose reply
// is still to come: a private session for a client, or a client's explicit
// attach.
type attachRequest struct {
	client   *client
	explicit bool
}

// mux multiplexes clients onto the one pipe.
type mux struct {
	pipe *pipe
	// outMu guards outQueue, the messages waiting for the pipe; outSignal
	// wakes the writer.
	outMu     sync.Mutex
	outQueue  [][]byte
	outSignal chan struct{}

	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]*pendingCommand
	clients map[*client]struct{}

	// targets the gate's auto-attach holds, by target id and by the gate's
	// session id.
	targets      map[string]*target
	gateSessions map[string]*target
	// privateSessions maps a client's private session id to its target.
	privateSessions map[string]*target
	// explicitSessions maps a session a client attached itself to the client.
	explicitSessions map[string]*client
	// attaching holds, per target, the attaches in flight in request order;
	// stashed holds Target.attachedToTarget events that arrived for those
	// attaches before the replies that name their requesters.
	attaching map[string][]*attachRequest
	stashed   map[string][]message

	discoverOn  bool
	discoverers map[*client]targetFilter
	// known are the targets discovery reported, for replay to a late
	// discoverer.
	known map[string]json.RawMessage

	closed    bool
	closeOnce sync.Once
	done      chan struct{}
	// attendance, when set, is told of every admitted client that is not a
	// helper and of its leaving, under mu, so the lifetime policy's count
	// matches the registrations (attend.go).
	attendance *keeper
	// onGateEvent receives events on the gate's own sessions, for the gate's
	// own protocol use.
	onGateEvent func(t *target, m message)
	// onGateAttached runs, with mu held, once the gate's auto-attach holds a
	// new target and before any client is attached to it. Setup the gate
	// needs in place before the target runs calls holdLocked, sends its
	// commands on t.gateSession with gateCommand, and calls
	// releaseHoldLocked from the reply.
	onGateAttached func(t *target)
}

func newMux(p *pipe) *mux {
	m := &mux{
		pipe:             p,
		outSignal:        make(chan struct{}, 1),
		nextID:           1,
		pending:          make(map[uint64]*pendingCommand),
		clients:          make(map[*client]struct{}),
		targets:          make(map[string]*target),
		gateSessions:     make(map[string]*target),
		privateSessions:  make(map[string]*target),
		explicitSessions: make(map[string]*client),
		attaching:        make(map[string][]*attachRequest),
		stashed:          make(map[string][]message),
		discoverers:      make(map[*client]targetFilter),
		known:            make(map[string]json.RawMessage),
		done:             make(chan struct{}),
	}
	go m.writeLoop()
	return m
}

// run reads the pipe until the browser closes it or ctx ends, dispatching
// every message. It returns io.EOF when the browser went away.
func (m *mux) run(ctx context.Context) error {
	errs := make(chan error, 1)
	go func() {
		for {
			data, err := m.pipe.read()
			if err != nil {
				errs <- err
				return
			}
			m.handleBrowserMessage(data)
		}
	}()
	select {
	case err := <-errs:
		m.close()
		return err
	case <-ctx.Done():
		m.close()
		return ctx.Err()
	}
}

func (m *mux) writeLoop() {
	for {
		select {
		case <-m.outSignal:
		case <-m.done:
			return
		}
		for {
			m.outMu.Lock()
			if len(m.outQueue) == 0 {
				m.outMu.Unlock()
				break
			}
			data := m.outQueue[0]
			m.outQueue = m.outQueue[1:]
			m.outMu.Unlock()
			if err := m.pipe.write(data); err != nil {
				// The browser's end is gone; the read loop reports it.
				return
			}
		}
	}
}

// close ends every client. The pipe itself is closed by the browser process.
func (m *mux) close() {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		clients := make([]*client, 0, len(m.clients))
		for c := range m.clients {
			clients = append(clients, c)
		}
		m.mu.Unlock()
		for _, c := range clients {
			c.closeNow()
		}
		close(m.done)
	})
}

// enqueue hands a message to the pipe writer without waiting for it.
func (m *mux) enqueue(data []byte) {
	m.outMu.Lock()
	m.outQueue = append(m.outQueue, data)
	m.outMu.Unlock()
	select {
	case m.outSignal <- struct{}{}:
	default:
	}
}

// sendLocked sends a command to the browser on sessionID and registers how
// its reply is handled. m.mu must be held.
func (m *mux) sendLocked(sessionID, method string, params any, p *pendingCommand) (uint64, error) {
	id := m.nextID
	m.nextID++
	raw, err := marshalCommand(id, sessionID, method, params)
	if err != nil {
		return 0, err
	}
	m.pending[id] = p
	m.enqueue(raw)
	return id, nil
}

func marshalCommand(id uint64, sessionID, method string, params any) ([]byte, error) {
	command := map[string]any{"id": id, "method": method}
	if sessionID != "" {
		command["sessionId"] = sessionID
	}
	if params != nil {
		command["params"] = params
	}
	return json.Marshal(command)
}

// gateCommand sends a command for the gate itself and calls onReply with the
// outcome. m.mu must be held; onReply runs with m.mu held too.
func (m *mux) gateCommand(sessionID, method string, params any, onReply func(result json.RawMessage, cdpErr *cdpError)) {
	if m.closed {
		return
	}
	if onReply == nil {
		onReply = func(json.RawMessage, *cdpError) {}
	}
	if _, err := m.sendLocked(sessionID, method, params, &pendingCommand{onReply: onReply}); err != nil {
		onReply(nil, &cdpError{Message: err.Error()})
	}
}

// call sends a command for the gate and waits for its reply.
func (m *mux) call(ctx context.Context, sessionID, method string, params any) (json.RawMessage, error) {
	type reply struct {
		result json.RawMessage
		err    *cdpError
	}
	replies := make(chan reply, 1)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, io.EOF
	}
	m.gateCommand(sessionID, method, params, func(result json.RawMessage, cdpErr *cdpError) {
		replies <- reply{result: result, err: cdpErr}
	})
	m.mu.Unlock()
	select {
	case r := <-replies:
		if r.err != nil {
			return nil, fmt.Errorf("%s: %s", method, r.err.Message)
		}
		return r.result, nil
	case <-m.done:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// start asks the browser for the root auto-attach the gate holds. Every new
// target is then held until the gate resumes it.
func (m *mux) start(ctx context.Context) error {
	_, err := m.call(ctx, "", "Target.setAutoAttach", map[string]any{
		"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
	})
	return err
}

// handleBrowserMessage dispatches one message from the pipe.
func (m *mux) handleBrowserMessage(data []byte) {
	var msg message
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(msg.ID) > 0 {
		m.handleReplyLocked(msg)
		return
	}
	m.handleEventLocked(msg, data)
}

func (m *mux) handleReplyLocked(msg message) {
	var id uint64
	if err := json.Unmarshal(msg.ID, &id); err != nil {
		return
	}
	p, ok := m.pending[id]
	if !ok {
		return
	}
	delete(m.pending, id)
	if p.onReply != nil {
		var cdpErr *cdpError
		if len(msg.Error) > 0 {
			cdpErr = &cdpError{}
			_ = json.Unmarshal(msg.Error, cdpErr)
		}
		p.onReply(msg.Result, cdpErr)
		return
	}
	if p.client == nil {
		return
	}
	p.client.deliverReply(p.clientID, msg)
}

func (m *mux) handleEventLocked(msg message, data []byte) {
	switch msg.Method {
	case "Target.attachedToTarget":
		m.onAttachedLocked(msg)
		return
	case "Target.detachedFromTarget":
		m.onDetachedLocked(msg)
		return
	case "Target.targetCreated", "Target.targetInfoChanged", "Target.targetDestroyed", "Target.targetCrashed":
		m.onDiscoveryEventLocked(msg, data)
		return
	case "Target.receivedMessageFromTarget":
		// Only flattened sessions are supported.
		return
	}
	if msg.SessionID == "" {
		for c := range m.clients {
			c.deliver(data)
		}
		return
	}
	if t, ok := m.privateSessions[msg.SessionID]; ok {
		for c, session := range t.private {
			if session == msg.SessionID {
				c.deliver(data)
				return
			}
		}
		return
	}
	if c, ok := m.explicitSessions[msg.SessionID]; ok {
		// A page endpoint's client never named its root session, so an
		// event on it arrives without one, as it would from the browser.
		c.deliverEvent(msg.SessionID, msg.Method, msg.Params)
		return
	}
	if t, ok := m.gateSessions[msg.SessionID]; ok && m.onGateEvent != nil {
		m.onGateEvent(t, msg)
	}
}

// onAttachedLocked handles a Target.attachedToTarget event. One for a
// session the gate or a client asked for by Target.attachToTarget is kept
// until the reply names its requester; any other is the gate's auto-attach
// holding a new target.
func (m *mux) onAttachedLocked(msg message) {
	var params struct {
		SessionID          string          `json:"sessionId"`
		TargetInfo         json.RawMessage `json:"targetInfo"`
		WaitingForDebugger bool            `json:"waitingForDebugger"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return
	}
	var info targetInfo
	if err := json.Unmarshal(params.TargetInfo, &info); err != nil || info.TargetID == "" {
		return
	}
	if len(m.attaching[info.TargetID]) > 0 {
		m.stashed[info.TargetID] = append(m.stashed[info.TargetID], msg)
		return
	}
	// A client that asked for auto-attach on a session it attached itself
	// gets that session's children as its own, as the browser gives them.
	if owner, ok := m.explicitSessions[msg.SessionID]; ok && msg.SessionID != "" {
		m.explicitSessions[params.SessionID] = owner
		owner.deliverEvent(msg.SessionID, "Target.attachedToTarget", msg.Params)
		return
	}
	m.gateAttachedLocked(msg.SessionID, params.SessionID, info, params.TargetInfo, params.WaitingForDebugger)
}

// gateAttachedLocked records a target the gate's auto-attach holds, under
// the gate session parentSession ("" at the root), and attaches a private
// session for every subscribed client.
func (m *mux) gateAttachedLocked(parentSession, session string, info targetInfo, rawInfo json.RawMessage, waiting bool) {
	parent := ""
	if parentSession != "" {
		pt, ok := m.gateSessions[parentSession]
		if !ok {
			return
		}
		parent = pt.id
	}
	t := &target{
		id:               info.TargetID,
		typ:              info.Type,
		info:             rawInfo,
		parent:           parent,
		gateSession:      session,
		paused:           waiting,
		waiting:          make(map[*client]struct{}),
		private:          make(map[*client]string),
		privateAttaching: make(map[*client]struct{}),
	}
	m.targets[t.id] = t
	m.gateSessions[session] = t
	if m.onGateAttached != nil {
		m.onGateAttached(t)
	}
	for c := range m.clients {
		sub, ok := c.autoAttach[parent]
		if !ok || !sub.filter.matches(t.typ) {
			continue
		}
		m.attachPrivateLocked(c, t, sub.wait)
	}
	m.maybeResumeLocked(t)
}

// holdLocked keeps t from being resumed until releaseHoldLocked is called
// as many times. m.mu must be held.
func (m *mux) holdLocked(t *target) {
	t.holds++
}

// releaseHoldLocked lets go of one hold on t and resumes it when nothing
// else holds it. m.mu must be held, as it is in a gateCommand reply.
func (m *mux) releaseHoldLocked(t *target) {
	if t.holds > 0 {
		t.holds--
	}
	m.maybeResumeLocked(t)
}

// attachPrivateLocked attaches a private session on t for c and delivers
// Target.attachedToTarget to c once the browser names the session.
func (m *mux) attachPrivateLocked(c *client, t *target, wait bool) {
	if _, has := t.private[c]; has {
		return
	}
	if _, inFlight := t.privateAttaching[c]; inFlight {
		return
	}
	t.privateAttaching[c] = struct{}{}
	if wait && t.paused {
		t.waiting[c] = struct{}{}
	}
	t.attaching++
	m.attaching[t.id] = append(m.attaching[t.id], &attachRequest{client: c})
	m.gateCommand("", "Target.attachToTarget", map[string]any{"targetId": t.id, "flatten": true},
		func(result json.RawMessage, cdpErr *cdpError) {
			m.popAttachLocked(t.id)
			t.attaching--
			delete(t.privateAttaching, c)
			session := sessionOf(result)
			// Between the request and this reply the client may have gone
			// or unsubscribed, and the target or its parent may have been
			// detached; a session nobody wants is let go of again.
			sub, wanted := c.autoAttach[t.parent]
			parent, parentKnown := m.targets[t.parent]
			stillThere := m.targets[t.id] == t && (t.parent == "" || parentKnown)
			if cdpErr != nil || session == "" || !m.clientAlive(c) || !wanted || !sub.filter.matches(t.typ) || !stillThere {
				if session != "" {
					m.gateCommand("", "Target.detachFromTarget", map[string]any{"sessionId": session}, nil)
				}
				delete(t.waiting, c)
				m.maybeResumeLocked(t)
				return
			}
			m.dropStashedLocked(t.id, session)
			t.private[c] = session
			m.privateSessions[session] = t
			outer := ""
			if parentKnown {
				outer = parent.private[c]
			}
			c.deliverEvent(outer, "Target.attachedToTarget", map[string]any{
				"sessionId":          session,
				"targetInfo":         t.info,
				"waitingForDebugger": wait && t.paused,
			})
			m.maybeResumeLocked(t)
		})
}

func sessionOf(result json.RawMessage) string {
	var fields struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal(result, &fields)
	return fields.SessionID
}

func (m *mux) clientAlive(c *client) bool {
	_, ok := m.clients[c]
	return ok
}

// popAttachLocked removes the oldest attach in flight for targetID and
// returns it.
func (m *mux) popAttachLocked(targetID string) *attachRequest {
	queue := m.attaching[targetID]
	if len(queue) == 0 {
		return nil
	}
	request := queue[0]
	if len(queue) == 1 {
		delete(m.attaching, targetID)
	} else {
		m.attaching[targetID] = queue[1:]
	}
	return request
}

// dropStashedLocked removes the stashed attach event naming session and,
// once no attach is in flight for targetID, treats what is left as the
// gate's own auto-attach events.
func (m *mux) dropStashedLocked(targetID, session string) message {
	var found message
	stash := m.stashed[targetID]
	kept := stash[:0]
	for _, msg := range stash {
		var params struct {
			SessionID string `json:"sessionId"`
		}
		_ = json.Unmarshal(msg.Params, &params)
		if params.SessionID == session && found.Method == "" {
			found = msg
			continue
		}
		kept = append(kept, msg)
	}
	if len(kept) == 0 {
		delete(m.stashed, targetID)
	} else {
		m.stashed[targetID] = kept
	}
	if len(m.attaching[targetID]) == 0 {
		for _, msg := range kept {
			m.onAttachedLocked(msg)
		}
		delete(m.stashed, targetID)
	}
	return found
}

// maybeResumeLocked lets a held target run once every client that asked to
// wait for it has resumed it, no private attach is in flight, and the gate's
// own setup on it is done.
func (m *mux) maybeResumeLocked(t *target) {
	if !t.paused || len(t.waiting) > 0 || t.attaching > 0 || t.holds > 0 {
		return
	}
	t.paused = false
	m.gateCommand(t.gateSession, "Runtime.runIfWaitingForDebugger", map[string]any{}, nil)
}

// onDetachedLocked handles a Target.detachedFromTarget event for a gate
// session, a private session or an explicit one.
func (m *mux) onDetachedLocked(msg message) {
	var params struct {
		SessionID string `json:"sessionId"`
		TargetID  string `json:"targetId"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return
	}
	if t, ok := m.gateSessions[params.SessionID]; ok {
		m.forgetTargetLocked(t)
		return
	}
	if t, ok := m.privateSessions[params.SessionID]; ok {
		for c, session := range t.private {
			if session == params.SessionID {
				m.forgetPrivateLocked(c, t, true)
			}
		}
		return
	}
	if c, ok := m.explicitSessions[params.SessionID]; ok {
		delete(m.explicitSessions, params.SessionID)
		c.deliverEvent(msg.SessionID, "Target.detachedFromTarget", map[string]any{"sessionId": params.SessionID, "targetId": params.TargetID})
	}
}

// forgetTargetLocked drops a target the browser detached the gate from,
// telling every client holding a private session on it.
func (m *mux) forgetTargetLocked(t *target) {
	for c := range t.private {
		m.forgetPrivateLocked(c, t, true)
	}
	for c := range t.waiting {
		delete(t.waiting, c)
	}
	// A subscription to the children of a target that is gone has nothing
	// left to attach; the children's own detach events follow from the
	// browser.
	for c := range m.clients {
		delete(c.autoAttach, t.id)
	}
	delete(m.gateSessions, t.gateSession)
	delete(m.targets, t.id)
}

// forgetPrivateLocked drops c's private session on t, telling c when
// notify is set.
func (m *mux) forgetPrivateLocked(c *client, t *target, notify bool) {
	session, ok := t.private[c]
	if !ok {
		return
	}
	delete(t.private, c)
	delete(m.privateSessions, session)
	if notify {
		outer := ""
		if parent, ok := m.targets[t.parent]; ok {
			outer = parent.private[c]
		}
		c.deliverEvent(outer, "Target.detachedFromTarget", map[string]any{"sessionId": session, "targetId": t.id})
	}
}

func (m *mux) onDiscoveryEventLocked(msg message, data []byte) {
	var params struct {
		TargetInfo json.RawMessage `json:"targetInfo"`
		TargetID   string          `json:"targetId"`
	}
	_ = json.Unmarshal(msg.Params, &params)
	var info targetInfo
	switch msg.Method {
	case "Target.targetCreated", "Target.targetInfoChanged":
		if json.Unmarshal(params.TargetInfo, &info) == nil && info.TargetID != "" {
			m.known[info.TargetID] = params.TargetInfo
		}
	case "Target.targetDestroyed":
		if raw, ok := m.known[params.TargetID]; ok {
			_ = json.Unmarshal(raw, &info)
			delete(m.known, params.TargetID)
		}
	case "Target.targetCrashed":
		if raw, ok := m.known[params.TargetID]; ok {
			_ = json.Unmarshal(raw, &info)
		}
	}
	for c, filter := range m.discoverers {
		if info.Type == "" || filter.matches(info.Type) {
			c.deliver(data)
		}
	}
}

// ---- client commands ----

// errFlattenRequired is the reply to a Target command that asks for the
// legacy, unflattened protocol.
var errFlattenRequired = errors.New("the gate supports flattened sessions only: pass flatten: true")

// handleClientCommand processes one command from c.
func (m *mux) handleClientCommand(c *client, msg message) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || !m.clientAlive(c) {
		return
	}
	sessionID := msg.SessionID
	if sessionID == "" {
		sessionID = c.root
	}
	// A session is addressed only by the client it belongs to, as over a
	// port, where a session id is meaningless on another connection.
	if !m.ownsSessionLocked(c, sessionID) {
		c.deliverError(msg.ID, msg.SessionID, "Session with given id not found.")
		return
	}
	switch msg.Method {
	case "Target.setAutoAttach":
		m.setAutoAttachLocked(c, msg, sessionID)
	case "Target.setDiscoverTargets":
		m.setDiscoverTargetsLocked(c, msg)
	case "Target.attachToTarget":
		m.attachToTargetLocked(c, msg, sessionID)
	case "Target.detachFromTarget":
		m.detachFromTargetLocked(c, msg, sessionID)
	case "Runtime.runIfWaitingForDebugger":
		m.runIfWaitingLocked(c, msg, sessionID)
	default:
		m.forwardLocked(c, msg, sessionID)
	}
}

// ownsSessionLocked reports whether sessionID is the browser itself, c's
// root, a private session made for c, or a session c attached itself.
func (m *mux) ownsSessionLocked(c *client, sessionID string) bool {
	if sessionID == "" || sessionID == c.root {
		return true
	}
	if t, ok := m.privateSessions[sessionID]; ok {
		return t.private[c] == sessionID
	}
	owner, ok := m.explicitSessions[sessionID]
	return ok && owner == c
}

// forwardLocked passes a command through with a remapped id.
func (m *mux) forwardLocked(c *client, msg message, sessionID string) {
	if _, err := m.sendLocked(sessionID, msg.Method, msg.Params, &pendingCommand{client: c, clientID: msg.ID}); err != nil {
		c.deliverError(msg.ID, sessionID, err.Error())
	}
}

// scopeOfLocked returns the target whose children a command on sessionID
// means: "" for the browser, or the target of c's private or explicit
// session.
func (m *mux) scopeOfLocked(c *client, sessionID string) (string, bool) {
	if sessionID == "" {
		return "", true
	}
	if t, ok := m.privateSessions[sessionID]; ok && t.private[c] == sessionID {
		return t.id, true
	}
	return "", false
}

func (m *mux) setAutoAttachLocked(c *client, msg message, sessionID string) {
	var params struct {
		AutoAttach             bool `json:"autoAttach"`
		WaitForDebuggerOnStart bool `json:"waitForDebuggerOnStart"`
		Flatten                bool `json:"flatten"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		c.deliverError(msg.ID, sessionID, "Target.setAutoAttach: invalid parameters")
		return
	}
	if params.AutoAttach && !params.Flatten {
		c.deliverError(msg.ID, sessionID, errFlattenRequired.Error())
		return
	}
	scope, ok := m.scopeOfLocked(c, sessionID)
	if !ok {
		// A session the client attached itself: the browser keeps that
		// session's auto-attach for the client, as it would over a port.
		m.forwardLocked(c, msg, sessionID)
		return
	}
	if !params.AutoAttach {
		m.unsubscribeAutoAttachLocked(c, scope)
		c.deliverResult(msg.ID, sessionID, map[string]any{})
		return
	}
	sub := autoAttachSub{wait: params.WaitForDebuggerOnStart, filter: parseTargetFilter(msg.Params)}
	c.autoAttach[scope] = sub
	replay := func() {
		for _, t := range m.targets {
			if t.parent == scope && sub.filter.matches(t.typ) {
				m.attachPrivateLocked(c, t, sub.wait)
			}
		}
		c.deliverResult(msg.ID, sessionID, map[string]any{})
	}
	parent, nested := m.targets[scope]
	if !nested || parent.nestedAutoAttach {
		replay()
		return
	}
	// The gate's own auto-attach on the target holds its children too.
	parent.nestedAutoAttach = true
	m.gateCommand(parent.gateSession, "Target.setAutoAttach", map[string]any{
		"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
	}, func(_ json.RawMessage, cdpErr *cdpError) {
		if cdpErr != nil {
			parent.nestedAutoAttach = false
			delete(c.autoAttach, scope)
			c.deliverError(msg.ID, sessionID, "Target.setAutoAttach: "+cdpErr.Message)
			return
		}
		if m.clientAlive(c) {
			replay()
		}
	})
}

// unsubscribeAutoAttachLocked ends c's auto-attach on scope and detaches
// the private sessions it brought, as the browser does over a port.
func (m *mux) unsubscribeAutoAttachLocked(c *client, scope string) {
	delete(c.autoAttach, scope)
	for _, t := range m.targets {
		if t.parent == scope {
			m.dropPrivateLocked(c, t)
		}
	}
}

// dropPrivateLocked ends c's private session on t, lets go of c's wait on
// t, and, since c's sessions beneath t were attached through that one,
// ends c's subscription to t's children and their sessions too.
func (m *mux) dropPrivateLocked(c *client, t *target) {
	if session, ok := t.private[c]; ok {
		m.forgetPrivateLocked(c, t, false)
		m.gateCommand("", "Target.detachFromTarget", map[string]any{"sessionId": session}, nil)
	}
	if _, waiting := t.waiting[c]; waiting {
		delete(t.waiting, c)
		m.maybeResumeLocked(t)
	}
	if _, nested := c.autoAttach[t.id]; nested {
		m.unsubscribeAutoAttachLocked(c, t.id)
	}
}

func (m *mux) setDiscoverTargetsLocked(c *client, msg message) {
	var params struct {
		Discover bool `json:"discover"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		c.deliverError(msg.ID, "", "Target.setDiscoverTargets: invalid parameters")
		return
	}
	if !params.Discover {
		delete(m.discoverers, c)
		c.deliverResult(msg.ID, "", map[string]any{})
		return
	}
	filter := parseTargetFilter(msg.Params)
	replay := func() {
		m.discoverers[c] = filter
		for _, raw := range m.known {
			var info targetInfo
			if json.Unmarshal(raw, &info) == nil && filter.matches(info.Type) {
				c.deliverEvent("", "Target.targetCreated", map[string]any{"targetInfo": raw})
			}
		}
		c.deliverResult(msg.ID, "", map[string]any{})
	}
	if m.discoverOn {
		replay()
		return
	}
	m.gateCommand("", "Target.setDiscoverTargets", map[string]any{"discover": true}, func(_ json.RawMessage, cdpErr *cdpError) {
		if cdpErr != nil {
			c.deliverError(msg.ID, "", "Target.setDiscoverTargets: "+cdpErr.Message)
			return
		}
		m.discoverOn = true
		if m.clientAlive(c) {
			replay()
		}
	})
}

func (m *mux) attachToTargetLocked(c *client, msg message, sessionID string) {
	var params struct {
		TargetID string `json:"targetId"`
		Flatten  bool   `json:"flatten"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil || params.TargetID == "" {
		c.deliverError(msg.ID, sessionID, "Target.attachToTarget: invalid parameters")
		return
	}
	if !params.Flatten {
		c.deliverError(msg.ID, sessionID, errFlattenRequired.Error())
		return
	}
	m.attaching[params.TargetID] = append(m.attaching[params.TargetID], &attachRequest{client: c, explicit: true})
	m.gateCommand(sessionID, "Target.attachToTarget", map[string]any{"targetId": params.TargetID, "flatten": true},
		func(result json.RawMessage, cdpErr *cdpError) {
			m.popAttachLocked(params.TargetID)
			session := sessionOf(result)
			if cdpErr != nil || session == "" {
				if session != "" {
					m.gateCommand("", "Target.detachFromTarget", map[string]any{"sessionId": session}, nil)
				}
				if cdpErr == nil {
					cdpErr = &cdpError{Message: "Target.attachToTarget: no session"}
				}
				c.deliverError(msg.ID, sessionID, cdpErr.Message)
				return
			}
			event := m.dropStashedLocked(params.TargetID, session)
			if !m.clientAlive(c) {
				m.gateCommand("", "Target.detachFromTarget", map[string]any{"sessionId": session}, nil)
				return
			}
			m.explicitSessions[session] = c
			if event.Method != "" {
				c.deliverEvent(sessionID, event.Method, event.Params)
			}
			c.deliverResult(msg.ID, sessionID, map[string]any{"sessionId": session})
		})
}

func (m *mux) detachFromTargetLocked(c *client, msg message, sessionID string) {
	var params struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil || params.SessionID == "" {
		c.deliverError(msg.ID, sessionID, "Target.detachFromTarget: invalid parameters")
		return
	}
	if owner, ok := m.explicitSessions[params.SessionID]; ok && owner == c {
		delete(m.explicitSessions, params.SessionID)
		m.gateCommand("", "Target.detachFromTarget", map[string]any{"sessionId": params.SessionID}, func(_ json.RawMessage, cdpErr *cdpError) {
			if cdpErr != nil {
				c.deliverError(msg.ID, sessionID, cdpErr.Message)
				return
			}
			c.deliverResult(msg.ID, sessionID, map[string]any{})
		})
		return
	}
	if t, ok := m.privateSessions[params.SessionID]; ok && t.private[c] == params.SessionID {
		m.dropPrivateLocked(c, t)
		c.deliverResult(msg.ID, sessionID, map[string]any{})
		return
	}
	c.deliverError(msg.ID, sessionID, "Target.detachFromTarget: no session with the given id")
}

// runIfWaitingLocked passes a client's Runtime.runIfWaitingForDebugger on to
// its private session and counts it toward resuming the held target.
func (m *mux) runIfWaitingLocked(c *client, msg message, sessionID string) {
	m.forwardLocked(c, msg, sessionID)
	t, ok := m.privateSessions[sessionID]
	if !ok || t.private[c] != sessionID {
		return
	}
	if _, waiting := t.waiting[c]; waiting {
		delete(t.waiting, c)
		m.maybeResumeLocked(t)
	}
}

// ---- client lifecycle ----

func (m *mux) addClient(c *client) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	m.clients[c] = struct{}{}
	if m.attendance != nil && !c.helper {
		m.attendance.joined()
	}
	return true
}

// removeClient forgets c, detaches the sessions it held and lets go of the
// targets it was waiting on.
func (m *mux) removeClient(c *client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.clientAlive(c) {
		return
	}
	delete(m.clients, c)
	if m.attendance != nil && !c.helper {
		m.attendance.left()
	}
	delete(m.discoverers, c)
	for id, p := range m.pending {
		if p.client == c {
			delete(m.pending, id)
		}
	}
	for session, owner := range m.explicitSessions {
		if owner == c {
			delete(m.explicitSessions, session)
			m.gateCommand("", "Target.detachFromTarget", map[string]any{"sessionId": session}, nil)
		}
	}
	for _, t := range m.targets {
		m.dropPrivateLocked(c, t)
	}
	if c.root != "" {
		m.gateCommand("", "Target.detachFromTarget", map[string]any{"sessionId": c.root}, nil)
	}
}

// attachRoot attaches c's root session on targetID, for a client of a page
// endpoint whose commands name no session.
func (m *mux) attachRoot(ctx context.Context, c *client, targetID string) error {
	m.mu.Lock()
	m.attaching[targetID] = append(m.attaching[targetID], &attachRequest{client: c, explicit: true})
	m.mu.Unlock()
	result, err := m.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": targetID, "flatten": true})
	m.mu.Lock()
	defer m.mu.Unlock()
	m.popAttachLocked(targetID)
	session := sessionOf(result)
	m.dropStashedLocked(targetID, session)
	if err != nil {
		return err
	}
	if session == "" {
		return errors.New("Target.attachToTarget: no session")
	}
	c.root = session
	m.explicitSessions[session] = c
	return nil
}
