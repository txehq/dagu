// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package onbehalf_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/onbehalf"
)

// hooks counts the calls of a caller's trace: the transport's events and
// the dialer's.
type hooks struct {
	getConn, gotConn, wrote, firstByte, connectStart, connectDone, dnsStart atomic.Int32
}

func (h *hooks) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn:              func(string) { h.getConn.Add(1) },
		GotConn:              func(httptrace.GotConnInfo) { h.gotConn.Add(1) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { h.wrote.Add(1) },
		GotFirstResponseByte: func() { h.firstByte.Add(1) },
		ConnectStart:         func(string, string) { h.connectStart.Add(1) },
		ConnectDone:          func(string, string, error) { h.connectDone.Add(1) },
		DNSStart:             func(httptrace.DNSStartInfo) { h.dnsStart.Add(1) },
	}
}

func (h *hooks) total() int32 {
	return h.getConn.Load() + h.gotConn.Load() + h.wrote.Load() + h.firstByte.Load() +
		h.connectStart.Load() + h.connectDone.Load() + h.dnsStart.Load()
}

func get(t *testing.T, ctx context.Context, url string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	// A transport of its own, so no idle connection of another test's is
	// reused and the dial events fire.
	client := &http.Client{Transport: &http.Transport{}}
	resp, err := client.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	client.CloseIdleConnections()
}

// A request on the returned context fires none of the caller's hooks, the
// dialer's included; the same request on the caller's context fires them.
func TestContextDropsTheCallersHooks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	t.Cleanup(server.Close)

	var h hooks
	caller := httptrace.WithClientTrace(context.Background(), h.trace())
	get(t, onbehalf.Context(caller), server.URL)
	assert.Zero(t, h.total(), "a request on the caller's behalf fired the caller's hooks")

	// Control: the same request on the caller's own context is traced.
	get(t, caller, server.URL)
	assert.Positive(t, h.getConn.Load())
	assert.Positive(t, h.gotConn.Load())
	assert.Positive(t, h.wrote.Load())
	assert.Positive(t, h.firstByte.Load())
	assert.Positive(t, h.connectStart.Load(), "the dial hook of the caller's trace")
	assert.Positive(t, h.connectDone.Load())
}

// The reason the hooks are hidden rather than overlaid: an empty trace added
// over the caller's composes with it and the caller's hooks still fire.
func TestAnEmptyTraceWouldKeepTheCallersHooks(t *testing.T) {
	var h hooks
	caller := httptrace.WithClientTrace(context.Background(), h.trace())
	composed := httptrace.ContextClientTrace(httptrace.WithClientTrace(caller, &httptrace.ClientTrace{}))
	require.NotNil(t, composed.GetConn)
	composed.GetConn("hub.invalid:80")
	assert.Equal(t, int32(1), h.getConn.Load(), "httptrace.WithClientTrace composes; it does not replace")

	hidden := httptrace.ContextClientTrace(onbehalf.Context(caller))
	require.NotNil(t, hidden, "the result carries a trace of its own")
	assert.Nil(t, hidden.GetConn, "with none of the caller's hooks")
	assert.Nil(t, hidden.GotConn)
	assert.Nil(t, hidden.WroteRequest)
	assert.Nil(t, hidden.GotFirstResponseByte)
	assert.Nil(t, hidden.DNSStart)
	assert.Nil(t, hidden.ConnectDone)
}

type valueKey struct{}

// The deadline, the cancellation and every other value are the caller's.
func TestContextKeepsDeadlineCancellationAndValues(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	parent, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	parent = context.WithValue(parent, valueKey{}, "kept")
	var h hooks
	caller := httptrace.WithClientTrace(parent, h.trace())

	ctx := onbehalf.Context(caller)
	got, ok := ctx.Deadline()
	require.True(t, ok)
	assert.Equal(t, deadline, got)
	assert.Equal(t, "kept", ctx.Value(valueKey{}))
	assert.NoError(t, ctx.Err())

	// A child of the result is cancelled with the caller, through the
	// standard library's own propagation.
	child, childCancel := context.WithCancel(ctx)
	defer childCancel()
	cancel()
	select {
	case <-child.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the caller's cancellation did not reach the request made on its behalf")
	}
	assert.True(t, errors.Is(ctx.Err(), context.Canceled))
	assert.True(t, errors.Is(child.Err(), context.Canceled))
}

// A context with no hooks is returned as it is.
func TestContextWithoutHooksIsUnchanged(t *testing.T) {
	ctx := context.WithValue(context.Background(), valueKey{}, "x")
	assert.Equal(t, ctx, onbehalf.Context(ctx))
}

// The result can be traced anew: the renewal's own trace, or a test's, works
// on top of it, and still none of the caller's hooks fire.
func TestContextCanBeTracedAgain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	t.Cleanup(server.Close)

	var caller, own hooks
	ctx := onbehalf.Context(httptrace.WithClientTrace(context.Background(), caller.trace()))
	get(t, httptrace.WithClientTrace(ctx, own.trace()), server.URL)
	assert.Zero(t, caller.total())
	assert.Positive(t, own.getConn.Load())
	assert.Positive(t, own.connectStart.Load())
}

// The key the trace is kept under was learned from httptrace itself, and
// only that key is hidden: a client trace a caller keeps under a key of its
// own is still found.
func TestContextHidesTheTraceKeyAlone(t *testing.T) {
	require.NotNil(t, onbehalf.TraceKey(), "the key was not learned; the type fallback is in use")
	own := &httptrace.ClientTrace{}
	var h hooks
	caller := context.WithValue(httptrace.WithClientTrace(context.Background(), h.trace()), valueKey{}, own)
	ctx := onbehalf.Context(caller)
	assert.Same(t, own, ctx.Value(valueKey{}), "a trace under the caller's own key is the caller's value")
	under, _ := ctx.Value(onbehalf.TraceKey()).(*httptrace.ClientTrace)
	require.NotNil(t, under, "under httptrace's key is the package's own trace")
	assert.Nil(t, under.GetConn, "with none of the caller's hooks")
	assert.NotNil(t, under.ConnectStart, "and the one hook that takes the dial hooks' place")
}

// recorder is an Observer that counts, from any goroutine.
type recorder struct {
	mu    sync.Mutex
	calls int
}

func (r *recorder) RequestOnBehalf() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// The observer in the caller's context is told of each request made on its
// behalf, with or without a trace, and stays in the result for the next.
func TestContextTellsTheObserver(t *testing.T) {
	var r recorder
	plain := onbehalf.WithObserver(context.Background(), &r)
	assert.Equal(t, plain, onbehalf.Context(plain), "no hooks: the context is returned as it is")
	assert.Equal(t, 1, r.count())

	var h hooks
	traced := onbehalf.WithObserver(httptrace.WithClientTrace(context.Background(), h.trace()), &r)
	ctx := onbehalf.Context(traced)
	assert.Equal(t, 2, r.count())
	onbehalf.Context(ctx)
	assert.Equal(t, 3, r.count(), "a further request on the same behalf is announced too")

	assert.Equal(t, 3, r.count())
	onbehalf.Context(context.Background())
	assert.Equal(t, 3, r.count(), "no observer, nothing told")
}
