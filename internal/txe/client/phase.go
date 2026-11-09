// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"
)

// RequestPhase is how far a request to the hub got before it failed. It is
// read from the request's own connection events, so it says on which side a
// request that timed out was waiting: a request that never asked for a
// connection failed before the transport (a credential renewal, for one), one
// that was written and never answered waited on the network path or the hub.
type RequestPhase int

const (
	// PhaseNotStarted: no connection was asked for. Whatever wraps the
	// transport, such as a token renewal, failed or was still running.
	PhaseNotStarted RequestPhase = iota
	// PhaseConnecting: a connection was asked for and none was had.
	PhaseConnecting
	// PhaseConnected: a connection was had and the request was not written.
	PhaseConnected
	// PhaseRequestWritten: the request was written and no response byte came.
	PhaseRequestWritten
	// PhaseFirstByte: the first response byte came and the headers did not
	// complete.
	PhaseFirstByte
	// PhaseBody: the headers came and the body could not be read.
	PhaseBody
)

// String names the phase as an error shows it.
func (p RequestPhase) String() string {
	switch p {
	case PhaseNotStarted:
		return "before a connection was asked for"
	case PhaseConnecting:
		return "while connecting"
	case PhaseConnected:
		return "after connecting, before the request was written"
	case PhaseRequestWritten:
		return "after the request was written, before any response"
	case PhaseFirstByte:
		return "after the first response byte, before the headers completed"
	case PhaseBody:
		return "while reading the response body"
	default:
		return "at an unknown phase"
	}
}

// RequestError is a request that got no complete response. Its text is the
// transport's error followed by the phase, the kind of connection and the
// time the request ran; it names no address, header or body. Unwrap gives
// the transport's error, so errors.Is and errors.As see through it.
type RequestError struct {
	Phase RequestPhase
	// Connected says a connection was had, and Reused that it was an idle
	// one this client had used before. Both are of the last connection the
	// request had.
	Connected bool
	Reused    bool
	// Elapsed is how long the request ran, to the hundredth of a second.
	Elapsed time.Duration
	Err     error
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("%v (the request stopped %s)", e.Err, e.Describe())
}

func (e *RequestError) Unwrap() error { return e.Err }

// Describe is the phase, the kind of connection and the elapsed time, and
// nothing else.
func (e *RequestError) Describe() string {
	connection := ""
	switch {
	case !e.Connected:
	case e.Reused:
		connection = ", on a reused connection"
	default:
		connection = ", on a new connection"
	}
	return fmt.Sprintf("%s%s, after %s", e.Phase, connection, e.Elapsed)
}

// phaseTrace records one request's phase from its connection events. The
// events may come from the transport's own goroutines.
//
// A request's context also reaches any request a wrapper of the transport
// makes on its behalf first, such as a token renewal at the identity
// provider, and those fire the same hooks. So the trace counts only events
// that follow its own request asking for a connection: one to the request's
// own host and port, or to the proxy the environment names for it. Until
// then the request has not started. The address is compared here and kept
// nowhere else.
type phaseTrace struct {
	start   time.Time
	targets map[string]bool

	mu        sync.Mutex
	ours      bool
	phase     RequestPhase
	connected bool
	reused    bool
}

func newPhaseTrace(req *http.Request) *phaseTrace {
	targets := map[string]bool{canonicalAddr(req.URL): true}
	if proxy, err := http.ProxyFromEnvironment(req); err == nil && proxy != nil {
		targets[canonicalAddr(proxy)] = true
	}
	return &phaseTrace{start: time.Now(), targets: targets}
}

// canonicalAddr is the "host:port" net/http asks a connection for.
func canonicalAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// with returns ctx carrying this trace's hooks. A trace already in ctx keeps
// its hooks: httptrace calls both.
func (t *phaseTrace) with(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		// A request may ask for a connection again after one failed, so
		// each event sets the phase, and the last one is kept.
		GetConn: func(hostPort string) {
			t.mu.Lock()
			t.ours = t.targets[hostPort]
			t.mu.Unlock()
			t.set(PhaseConnecting, nil)
		},
		GotConn: func(info httptrace.GotConnInfo) { t.set(PhaseConnected, &info.Reused) },
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				t.set(PhaseRequestWritten, nil)
			}
		},
		GotFirstResponseByte: func() { t.set(PhaseFirstByte, nil) },
	})
}

// set records an event of this trace's own request. Events of another
// request are ignored.
func (t *phaseTrace) set(phase RequestPhase, reused *bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ours {
		return
	}
	t.phase = phase
	if reused != nil {
		t.connected, t.reused = true, *reused
	}
	if phase == PhaseConnecting {
		t.connected, t.reused = false, false
	}
}

// fail returns err with the phase the request had reached. at, when not
// PhaseNotStarted, is a later phase the caller knows the request reached.
func (t *phaseTrace) fail(err error, at RequestPhase) *RequestError {
	t.mu.Lock()
	defer t.mu.Unlock()
	phase := max(at, t.phase)
	return &RequestError{
		Phase: phase, Connected: t.connected, Reused: t.reused,
		Elapsed: time.Since(t.start).Round(10 * time.Millisecond), Err: err,
	}
}
