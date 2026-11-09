// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package onbehalf gives a request made on another request's behalf, such
// as a token renewal at the identity provider before a hub request is sent,
// a context of its own: the caller's deadline, cancellation and values,
// without the caller's httptrace hooks (TXE-6352).
//
// A caller traces its request through httptrace hooks in the request's
// context. A renewal built on that context fires the same hooks, and the
// caller reads the renewal's connection events as its own request's. Telling
// the two apart by the address a connection is asked for fails for a
// provider at the hub's own host and port, and for two requests through one
// proxy. So a renewal drops the hooks at its source instead, and the caller
// sees only its own request's events.
package onbehalf

import (
	"context"
	"net/http/httptrace"
)

// Context returns ctx for a request made on behalf of the request ctx is
// for: the same deadline, cancellation and values, and none of the httptrace
// hooks ctx carries. A ctx with no hooks is returned as it is.
//
// The hooks cannot be removed by adding an empty trace: httptrace composes a
// new trace with the one already in the context, and nil hooks keep the old
// ones. Nor does the standard library name the key the trace is held under.
// So the result hides any *httptrace.ClientTrace a lookup finds below it,
// which is what httptrace.ContextClientTrace and the transport read. The
// hooks that fire from the dialer (DNS and connect) are held under a second
// key, also unnamed, that httptrace fills from the trace's own hooks; a
// trace of this package's own with one hook that does nothing takes that
// place, so the caller's dial hooks do not fire either. A trace added on top
// of the result, by the renewal itself or by a test, works as usual.
func Context(ctx context.Context) context.Context {
	if httptrace.ContextClientTrace(ctx) == nil {
		return ctx
	}
	return httptrace.WithClientTrace(withoutTrace{ctx}, &httptrace.ClientTrace{
		ConnectStart: func(string, string) {},
	})
}

// withoutTrace is a context that answers every lookup from its parent except
// one that would give a client trace.
type withoutTrace struct{ context.Context }

func (c withoutTrace) Value(key any) any {
	v := c.Context.Value(key)
	if _, ok := v.(*httptrace.ClientTrace); ok {
		return nil
	}
	return v
}
