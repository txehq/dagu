// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/dagucloud/dagu/v2/internal/txe/onbehalf"
)

// RequestPhase is how far a request to the hub got before it failed. It is
// read from the request's own connection events, and from what a wrapper of
// the transport announces, so it says on which side a request that timed out
// was waiting: a request that never asked for a connection failed before the
// transport, one that stopped while a request on its behalf ran waited on
// the identity provider, one that was written and never answered waited on
// the network path or the hub.
type RequestPhase int

const (
	// PhaseNotStarted: no connection was asked for. Whatever wraps the
	// transport failed or was still running, and did not say so.
	PhaseNotStarted RequestPhase = iota
	// PhaseOnBehalf: a request made on this request's behalf, such as a
	// token renewal at the identity provider, had started and this request
	// had not asked for a connection since (onbehalf).
	PhaseOnBehalf
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
	case PhaseOnBehalf:
		return "while a request made on its behalf, such as a token renewal, ran"
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
	// Proxied says the connection was to a proxy, not to the hub. A request
	// that a transport wrapper makes on the same context without announcing
	// itself (onbehalf) reaches the same proxy, and its events cannot be
	// told apart from the hub request's: the phase may be that request's.
	Proxied bool
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
	if e.Proxied {
		connection += " to a proxy, which an earlier request on the same context may also have used"
	}
	return fmt.Sprintf("%s%s, after %s", e.Phase, connection, e.Elapsed)
}

// phaseTrace records one request's phase from its connection events, and
// from what a wrapper of the transport announces. The events may come from
// the transport's own goroutines.
//
// A request's context also reaches any request a wrapper of the transport
// makes on its behalf, such as a token renewal at the identity provider,
// before the request is sent or after the hub refused its token. Every such
// request this repository makes (transportauth, cliauth) goes through
// onbehalf.Context: it fires none of this trace's hooks, and it announces
// itself to the trace (RequestOnBehalf), which then reads as PhaseOnBehalf
// until the request's own next connection is asked for. A wrapper that
// does not announce itself fires the hooks, and the trace falls back to
// counting only events that follow its own request asking for a connection:
// one to the request's own host and port, or to the proxy the environment
// names for it. The addresses are compared here and kept nowhere else.
//
// For such an unannounced wrapper the fallback cannot separate the requests
// through a proxy: an identity provider reached through the same proxy is
// asked for by the same address. Such events are counted and the error says
// so (RequestError.Proxied) rather than claim a phase it cannot attribute.
// Nor can it separate an unannounced wrapper's request to the hub's own
// host and port.
//
// A redirect that Do follows moves the trace to the redirect's destination
// (see redirects).
type phaseTrace struct {
	start time.Time
	own   string
	proxy string

	mu        sync.Mutex
	ours      bool
	proxied   bool
	phase     RequestPhase
	connected bool
	reused    bool
}

// phaseProxy is the proxy a request is sent through. Tests replace it:
// net/http reads the environment once per process.
var phaseProxy = http.ProxyFromEnvironment

func newPhaseTrace(req *http.Request) *phaseTrace {
	t := &phaseTrace{start: time.Now()}
	t.retarget(req)
	return t
}

// retarget makes req, the request itself or a redirect it follows, the one
// whose events count. A redirect starts again: nothing of the hop before it
// is its phase.
func (t *phaseTrace) retarget(req *http.Request) {
	own, proxy := canonicalAddr(req.URL), ""
	if p, err := phaseProxy(req); err == nil && p != nil {
		if addr := canonicalAddr(p); addr != own {
			proxy = addr
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.own, t.proxy = own, proxy
	t.ours, t.proxied = false, false
	t.phase, t.connected, t.reused = PhaseNotStarted, false, false
}

// redirects returns client with a redirect policy that retargets this trace
// at each redirect it follows, and is otherwise client's own: its
// CheckRedirect, or net/http's default of at most 10 redirects.
func (t *phaseTrace) redirects(client *http.Client) *http.Client {
	policy := client.CheckRedirect
	out := *client
	out.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		var err error
		switch {
		case policy != nil:
			err = policy(req, via)
		case len(via) >= 10:
			err = errors.New("stopped after 10 redirects")
		}
		if err == nil {
			t.retarget(req)
		}
		return err
	}
	return &out
}

// canonicalAddr is the "host:port" net/http asks a connection for: the host
// in IDNA ASCII, and the scheme's default port when there is none. It does
// what net/http's own canonicalAddr does.
func canonicalAddr(u *url.URL) string {
	host := u.Hostname()
	if !isASCII(host) {
		if v, err := idna.Lookup.ToASCII(host); err == nil {
			host = v
		}
	}
	port := u.Port()
	if port == "" {
		port = schemePort(u.Scheme)
	}
	return net.JoinHostPort(host, port)
}

func schemePort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "socks5", "socks5h":
		return "1080"
	default:
		return ""
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// with returns ctx carrying this trace's hooks and this trace as the
// observer of requests made on the request's behalf. A trace already in ctx
// keeps its hooks: httptrace calls both.
func (t *phaseTrace) with(ctx context.Context) context.Context {
	ctx = onbehalf.WithObserver(ctx, t)
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		// A request may ask for a connection again after one failed, so
		// each event sets the phase, and the last one is kept.
		GetConn: func(hostPort string) {
			t.mu.Lock()
			t.proxied = t.proxy != "" && hostPort == t.proxy
			t.ours = hostPort == t.own || t.proxied
			if !t.ours {
				// Another request on the same context, such as a renewal
				// after the hub answered 401: whatever this request's last
				// attempt reached is over, and its next has not started.
				t.phase, t.connected, t.reused = PhaseNotStarted, false, false
			}
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

// RequestOnBehalf implements onbehalf.Observer: a request on this request's
// behalf has started. Whatever this request's last attempt reached is over,
// and its next attempt has not started; the request reads as PhaseOnBehalf
// until its own next connection is asked for. The request on its behalf
// fires none of this trace's hooks.
func (t *phaseTrace) RequestOnBehalf() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ours, t.proxied = false, false
	t.phase, t.connected, t.reused = PhaseOnBehalf, false, false
}

// set records an event of this trace's own request. Events of another
// request are ignored.
func (t *phaseTrace) set(phase RequestPhase, reused *bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ours {
		return
	}
	// Within one connection attempt the phase only moves forward: net/http
	// writes and reads at once, so a server that answers before a body is
	// fully written has its first byte reported before the write. A new
	// attempt (GetConn) starts again.
	if phase != PhaseConnecting && phase < t.phase {
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
		Phase: phase, Connected: t.connected, Reused: t.reused, Proxied: t.ours && t.proxied,
		Elapsed: time.Since(t.start).Round(10 * time.Millisecond), Err: err,
	}
}
