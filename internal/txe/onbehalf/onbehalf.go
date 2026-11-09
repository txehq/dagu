// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package onbehalf gives a request made on another request's behalf, such
// as a token renewal at the identity provider before a hub request is sent,
// a context of its own: the caller's deadline, cancellation and values,
// without the caller's httptrace hooks, and tells the caller's observer that
// such a request is being made (TXE-6352).
//
// A caller traces its request through httptrace hooks in the request's
// context. A renewal built on that context fires the same hooks, and the
// caller reads the renewal's connection events as its own request's. Telling
// the two apart by the address a connection is asked for fails for a
// provider at the hub's own host and port, and for two requests through one
// proxy. So a renewal drops the hooks at its source instead, and the caller
// sees only its own request's events. What the caller then cannot see, that
// a request on its behalf is running, it is told through its Observer.
package onbehalf

import (
	"context"
	"net/http/httptrace"
)

// Observer is told, through the context it was put in with WithObserver,
// that a request is about to be made on behalf of the request the context is
// for. It may be told more than once for one request, as a renewal's
// discovery, token request and key read each announce themselves, and it
// may be called from any goroutine.
type Observer interface {
	RequestOnBehalf()
}

type observerKey struct{}

// WithObserver returns ctx carrying o, which Context tells of every request
// made on the behalf of ctx's request.
func WithObserver(ctx context.Context, o Observer) context.Context {
	return context.WithValue(ctx, observerKey{}, o)
}

// Context returns ctx for a request made on behalf of the request ctx is
// for: the same deadline, cancellation and values, none of the httptrace
// hooks ctx carries, and the observer in ctx, if any, told first. A ctx with
// no hooks is returned as it is.
//
// The hooks cannot be removed by adding an empty trace: httptrace composes a
// new trace with the one already in the context, and nil hooks keep the old
// ones. So the result hides the trace from the lookup under the key
// httptrace keeps it under, which is what httptrace.ContextClientTrace and
// the transport read; see traceKey for how the key is known. The hooks that
// fire from the dialer and the resolver (ConnectStart, ConnectDone, DNSStart
// and DNSDone) are held under a second key, in net/http/internal's nettrace,
// that httptrace fills from the trace's own hooks whenever it has one of
// those four; a trace of this package's own with one such hook that does
// nothing takes that place, so none of the caller's dial hooks fire either
// (net/http/httptrace.WithClientTrace, net.Dialer.DialContext and
// net.Resolver.lookupIPAddr read these, Go 1.27). A trace added on top of
// the result, by the renewal itself or by a test, works as usual.
func Context(ctx context.Context) context.Context {
	if o, ok := ctx.Value(observerKey{}).(Observer); ok {
		o.RequestOnBehalf()
	}
	if httptrace.ContextClientTrace(ctx) == nil {
		return ctx
	}
	return httptrace.WithClientTrace(withoutTrace{ctx}, &httptrace.ClientTrace{
		ConnectStart: func(string, string) {},
	})
}

// traceKey is the key httptrace keeps a request's trace under, which the
// standard library does not export. It is learned when the package loads:
// WithClientTrace reads the trace already in the context to compose with
// it, and a context of this package's own records the key of that read, then
// checks that the trace is found under it. It is nil when that did not go as
// expected, and the trace is then recognised by its type instead.
var traceKey = learnTraceKey()

type keyRecorder struct {
	context.Context
	keys []any
}

func (r *keyRecorder) Value(key any) any {
	r.keys = append(r.keys, key)
	return nil
}

func learnTraceKey() any {
	recorder := &keyRecorder{Context: context.Background()}
	marker := &httptrace.ClientTrace{}
	ctx := httptrace.WithClientTrace(recorder, marker)
	if len(recorder.keys) != 1 {
		return nil
	}
	key := recorder.keys[0]
	if trace, _ := ctx.Value(key).(*httptrace.ClientTrace); trace != marker {
		return nil
	}
	return key
}

// withoutTrace is a context that answers every lookup from its parent except
// the one for the client trace.
type withoutTrace struct{ context.Context }

func (c withoutTrace) Value(key any) any {
	if traceKey != nil {
		if key == traceKey {
			return nil
		}
		return c.Context.Value(key)
	}
	v := c.Context.Value(key)
	if _, ok := v.(*httptrace.ClientTrace); ok {
		return nil
	}
	return v
}
