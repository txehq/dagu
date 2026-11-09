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
