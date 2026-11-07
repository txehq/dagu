// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/coder/websocket"
)

// clientQueue is how many messages may wait for a client's websocket. A
// client that falls that far behind is disconnected rather than letting it
// hold up the browser's other clients.
const clientQueue = 1 << 14

// autoAttachSub is a client's Target.setAutoAttach on one scope.
type autoAttachSub struct {
	wait   bool
	filter targetFilter
}

// client is one websocket client, a virtual DevTools connection.
type client struct {
	mux  *mux
	conn *websocket.Conn
	// root is the client's own session on a page endpoint: commands without
	// a session id go there, and its replies and events come back without
	// one. It is "" for a browser endpoint.
	root string
	// autoAttach are the client's Target.setAutoAttach subscriptions by
	// scope: "" for the browser, or the target id of the parent.
	autoAttach map[string]autoAttachSub

	send      chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

func newClient(m *mux, conn *websocket.Conn) *client {
	return &client{
		mux:        m,
		conn:       conn,
		autoAttach: make(map[string]autoAttachSub),
		send:       make(chan []byte, clientQueue),
		closed:     make(chan struct{}),
	}
}

// serve reads the client's commands until the connection ends.
func (c *client) serve(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.writeLoop(ctx)
	defer c.mux.removeClient(c)
	defer c.closeNow()
	for {
		_, data, err := c.conn.Read(ctx)
		if err != nil {
			return
		}
		var msg message
		if err := json.Unmarshal(data, &msg); err != nil || len(msg.ID) == 0 || msg.Method == "" {
			continue
		}
		c.mux.handleClientCommand(c, msg)
	}
}

func (c *client) writeLoop(ctx context.Context) {
	for {
		select {
		case data := <-c.send:
			if err := c.conn.Write(ctx, websocket.MessageText, data); err != nil {
				c.closeNow()
				return
			}
		case <-c.closed:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (c *client) closeNow() {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.conn.CloseNow()
	})
}

// deliver queues raw bytes for the client.
func (c *client) deliver(data []byte) {
	select {
	case c.send <- data:
	case <-c.closed:
	default:
		c.closeNow()
	}
}

// deliverReply routes a reply the browser made to a command of the client.
// The client's own id goes back in; a reply on the client's root session
// loses its session id.
func (c *client) deliverReply(clientID json.RawMessage, msg message) {
	rewritten := map[string]any{"id": clientID}
	if msg.SessionID != "" && msg.SessionID != c.root {
		rewritten["sessionId"] = msg.SessionID
	}
	if len(msg.Error) > 0 {
		rewritten["error"] = msg.Error
	} else {
		rewritten["result"] = resultOrEmpty(msg.Result)
	}
	c.deliverJSON(rewritten)
}

func resultOrEmpty(result json.RawMessage) json.RawMessage {
	if len(result) == 0 {
		return json.RawMessage("{}")
	}
	return result
}

// deliverResult answers a command the gate handled itself.
func (c *client) deliverResult(clientID json.RawMessage, sessionID string, result any) {
	reply := map[string]any{"id": clientID, "result": result}
	if sessionID != "" && sessionID != c.root {
		reply["sessionId"] = sessionID
	}
	c.deliverJSON(reply)
}

// deliverError answers a command the gate refused.
func (c *client) deliverError(clientID json.RawMessage, sessionID, text string) {
	reply := map[string]any{"id": clientID, "error": cdpError{Code: -32000, Message: text}}
	if sessionID != "" && sessionID != c.root {
		reply["sessionId"] = sessionID
	}
	c.deliverJSON(reply)
}

// deliverEvent sends the client an event on sessionID, which is left out
// for the client's root session or the browser.
func (c *client) deliverEvent(sessionID, method string, params any) {
	event := map[string]any{"method": method, "params": params}
	if sessionID != "" && sessionID != c.root {
		event["sessionId"] = sessionID
	}
	c.deliverJSON(event)
}

func (c *client) deliverJSON(value any) {
	data, err := json.Marshal(value)
	if err != nil {
		return
	}
	c.deliver(data)
}
