// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

// fakeBrowserMarker in the arguments makes the test binary act as the
// browser the gate launches.
const fakeBrowserMarker = "fakebrowser"

// TestMain lets the test binary play two other roles: the gate helper, as
// `dagu browser devtools-gate` would, and the browser the gate launches.
func TestMain(m *testing.M) {
	if len(os.Args) >= 3 && os.Args[1] == "browser" && os.Args[2] == "devtools-gate" {
		if err := Main(context.Background(), os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if slices.Contains(os.Args, fakeBrowserMarker) {
		os.Exit(runFakeBrowserProcess(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeBrowserArgs are the browser arguments that make the test binary the
// browser, with extra flags for the fake.
func fakeBrowserArgs(extra ...string) []string {
	return append([]string{"-test.run=^$", "--", fakeBrowserMarker}, extra...)
}

// testGate is a gate over an in-process fake browser.
type testGate struct {
	t     *testing.T
	gate  *gate
	fake  *fakeBrowser
	mux   *mux
	token string
	// runErr reports how the mux ended.
	runErr chan error
}

// startTestGate runs a fake browser and a gate over pipes in this process.
func startTestGate(t *testing.T) *testGate {
	t.Helper()
	return startTestGateWith(t, nil)
}

// startTestGateWith is startTestGate with setup run on the mux and the fake
// before the mux starts, where run installs the gate's own hooks.
func startTestGateWith(t *testing.T, setup func(m *mux, f *fakeBrowser)) *testGate {
	t.Helper()
	browserRead, gateWrite, err := os.Pipe()
	require.NoError(t, err)
	gateRead, browserWrite, err := os.Pipe()
	require.NoError(t, err)
	fake := newFakeBrowser(browserRead, browserWrite)
	go func() { _ = fake.serve() }()

	m := newMux(newPipe(gateRead, gateWrite))
	if setup != nil {
		setup(m, fake)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- m.run(ctx) }()
	startCtx, cancelStart := context.WithTimeout(ctx, 10*time.Second)
	defer cancelStart()
	version, err := readVersion(startCtx, m)
	require.NoError(t, err)
	require.NoError(t, m.start(startCtx))

	token := NewToken()
	g := newGate(m, token, NewToken(), version)
	_, err = g.listen()
	require.NoError(t, err)
	t.Cleanup(func() {
		g.close()
		cancel()
		m.pipe.close()
		_ = browserRead.Close()
		_ = browserWrite.Close()
	})
	return &testGate{t: t, gate: g, fake: fake, mux: m, token: token, runErr: runErr}
}

func (tg *testGate) baseURL() string {
	return BaseURL(tg.gate.port(), tg.token)
}

// cdpConn is a test client's websocket connection with a reader that sorts
// replies from events.
type cdpConn struct {
	t      *testing.T
	conn   *websocket.Conn
	mu     sync.Mutex
	nextID int
	// replies by id.
	replies map[int]chan message
	events  chan message
	done    chan struct{}
}

// dial connects a browser-level client, or a page client when targetID is
// set.
func (tg *testGate) dial(targetID string) *cdpConn {
	tg.t.Helper()
	return dialWS(tg.t, tg.wsURL(targetID), nil)
}

func (tg *testGate) wsURL(targetID string) string {
	if targetID == "" {
		return tg.gate.browserWSURL()
	}
	return tg.gate.wsBase() + "/devtools/page/" + targetID
}

func dialWS(t *testing.T, wsURL string, header http.Header) *cdpConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, response, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: header})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	require.NoError(t, err)
	conn.SetReadLimit(-1)
	c := &cdpConn{t: t, conn: conn, replies: make(map[int]chan message), events: make(chan message, 1024), done: make(chan struct{})}
	go c.read()
	t.Cleanup(c.close)
	return c
}

func (c *cdpConn) close() {
	_ = c.conn.CloseNow()
}

func (c *cdpConn) read() {
	defer close(c.done)
	for {
		_, data, err := c.conn.Read(context.Background())
		if err != nil {
			return
		}
		var msg message
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		if len(msg.ID) > 0 {
			var id int
			_ = json.Unmarshal(msg.ID, &id)
			c.mu.Lock()
			ch := c.replies[id]
			c.mu.Unlock()
			if ch != nil {
				ch <- msg
			}
			continue
		}
		c.events <- msg
	}
}

// call sends a command and returns its result, or the browser's error.
func (c *cdpConn) call(sessionID, method string, params any) (json.RawMessage, error) {
	c.t.Helper()
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan message, 1)
	c.replies[id] = ch
	c.mu.Unlock()
	command := map[string]any{"id": id, "method": method}
	if params != nil {
		command["params"] = params
	}
	if sessionID != "" {
		command["sessionId"] = sessionID
	}
	data, err := json.Marshal(command)
	require.NoError(c.t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(c.t, c.conn.Write(ctx, websocket.MessageText, data))
	select {
	case reply := <-ch:
		if len(reply.Error) > 0 {
			var cdpErr cdpError
			_ = json.Unmarshal(reply.Error, &cdpErr)
			return nil, errors.New(cdpErr.Message)
		}
		return reply.Result, nil
	case <-ctx.Done():
		c.t.Fatalf("no reply to %s within 10s", method)
		return nil, nil
	}
}

// send sends a command without waiting for its reply, which read drops as
// nobody's. It never fails the test, so a goroutine may use it.
func (c *cdpConn) send(sessionID, method string, params any) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.mu.Unlock()
	command := map[string]any{"id": id, "method": method, "params": params}
	if sessionID != "" {
		command["sessionId"] = sessionID
	}
	data, err := json.Marshal(command)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = c.conn.Write(ctx, websocket.MessageText, data)
}

// mustCall fails the test on a protocol error.
func (c *cdpConn) mustCall(sessionID, method string, params any) json.RawMessage {
	c.t.Helper()
	result, err := c.call(sessionID, method, params)
	require.NoError(c.t, err, method)
	return result
}

// waitEvent returns the next event with method that accept allows, or
// fails after 10 seconds.
func (c *cdpConn) waitEvent(method string, accept func(message) bool) message {
	c.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case event := <-c.events:
			if event.Method == method && (accept == nil || accept(event)) {
				return event
			}
		case <-deadline:
			c.t.Fatalf("no %s event within 10s", method)
			return message{}
		}
	}
}

// noEvent asserts that no event with method arrives within wait.
func (c *cdpConn) noEvent(method string, wait time.Duration) {
	c.t.Helper()
	c.noEvents(wait, method)
}

// noEvents asserts that no event with any of methods arrives within wait,
// in one watch, so one forbidden event cannot slip by while another is
// watched for.
func (c *cdpConn) noEvents(wait time.Duration, methods ...string) {
	c.t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case event := <-c.events:
			if slices.Contains(methods, event.Method) {
				c.t.Fatalf("unexpected %s event: %s", event.Method, event.Params)
			}
		case <-deadline:
			return
		}
	}
}

// attached is the part of Target.attachedToTarget a test reads.
type attached struct {
	SessionID          string `json:"sessionId"`
	WaitingForDebugger bool   `json:"waitingForDebugger"`
	TargetInfo         struct {
		TargetID string `json:"targetId"`
		Type     string `json:"type"`
	} `json:"targetInfo"`
}

func decodeAttached(t *testing.T, event message) attached {
	t.Helper()
	var a attached
	require.NoError(t, json.Unmarshal(event.Params, &a))
	return a
}

// fakeState reads the fake browser's state through any connection.
func (tg *testGate) state(c *cdpConn) fakeState {
	tg.t.Helper()
	var state fakeState
	require.NoError(tg.t, json.Unmarshal(c.mustCall("", "Fake.state", nil), &state))
	return state
}

// eventually polls check until it passes or the wait runs out.
func eventually(t *testing.T, wait time.Duration, check func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for {
		if check() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %s", what, wait)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
