// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// phaseHub answers /fast at once, holds /hold until the request is abandoned
// or the test ends, and sends half of a promised body on /short.
func phaseHub(t *testing.T) *httptest.Server {
	t.Helper()
	done := make(chan struct{})
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/fast":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/api/v1/hold":
			// The server notices that the client went away only once a
			// request body has been read.
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-done:
			}
		case "/api/v1/short":
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte(`{"ok":`))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			// Closing the connection with the body unfinished.
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(func() { close(done); hub.Close() })
	return hub
}

func phaseClient(hub *httptest.Server, rt http.RoundTripper, timeout time.Duration) *Client {
	return New(hub.URL+"/api/v1", "", &http.Client{Transport: rt, Timeout: timeout})
}

func requestError(t *testing.T, err error) *RequestError {
	t.Helper()
	require.Error(t, err)
	var re *RequestError
	require.True(t, errors.As(err, &re), "not a RequestError: %v", err)
	return re
}

// beforeTransport stands for a wrapper that holds a request before its base
// transport, as a credential renewal does: it waits for the request's end.
type beforeTransport struct{ base http.RoundTripper }

func (b beforeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, fmt.Errorf("renew this machine's access token: %w", req.Context().Err())
}

// afterTransport stands for a wrapper that has its token: it adds a header
// and sends the request on.
type afterTransport struct{ base http.RoundTripper }

func (a afterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Header.Set("Authorization", "Bearer secret-token-value")
	return a.base.RoundTrip(out)
}

func newTransport() *http.Transport { return http.DefaultTransport.(*http.Transport).Clone() }

func TestRequestPhaseNamesWhereARequestStopped(t *testing.T) {
	hub := phaseHub(t)
	ctx := context.Background()

	t.Run("a wrapper that holds the request before the transport", func(t *testing.T) {
		err := phaseClient(hub, beforeTransport{newTransport()}, 300*time.Millisecond).Do(ctx, http.MethodGet, "/fast", nil, nil, nil)
		re := requestError(t, err)
		assert.Equal(t, PhaseNotStarted, re.Phase)
		assert.False(t, re.Connected)
		assert.Contains(t, err.Error(), "renew this machine's access token: ", "the wrapper's own text is kept")
		assert.Contains(t, err.Error(), "(the request stopped before a connection was asked for, after ")
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("the request written, no answer, after a wrapper had its token", func(t *testing.T) {
		err := phaseClient(hub, afterTransport{newTransport()}, 300*time.Millisecond).Do(ctx, http.MethodGet, "/hold", nil, nil, nil)
		re := requestError(t, err)
		assert.Equal(t, PhaseRequestWritten, re.Phase)
		assert.True(t, re.Connected)
		assert.False(t, re.Reused)
		assert.Contains(t, err.Error(), "(the request stopped after the request was written, before any response, on a new connection, after ")
		assert.NotContains(t, err.Error(), "renew")
	})

	t.Run("the request written, no answer", func(t *testing.T) {
		err := phaseClient(hub, newTransport(), 300*time.Millisecond).Do(ctx, http.MethodGet, "/hold", nil, nil, nil)
		re := requestError(t, err)
		assert.Equal(t, PhaseRequestWritten, re.Phase)
		assert.GreaterOrEqual(t, re.Elapsed, 300*time.Millisecond)
		assert.Less(t, re.Elapsed, 10*time.Second)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		var nerr net.Error
		require.ErrorAs(t, err, &nerr)
		assert.True(t, nerr.Timeout(), "a client timeout is still a timeout")
	})

	t.Run("a dial that never completes", func(t *testing.T) {
		tr := newTransport()
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		err := phaseClient(hub, tr, 300*time.Millisecond).Do(ctx, http.MethodGet, "/fast", nil, nil, nil)
		re := requestError(t, err)
		assert.Equal(t, PhaseConnecting, re.Phase)
		assert.False(t, re.Connected)
		assert.Contains(t, err.Error(), "(the request stopped while connecting, after ")
	})

	t.Run("a body cut short", func(t *testing.T) {
		err := phaseClient(hub, newTransport(), 5*time.Second).Do(ctx, http.MethodGet, "/short", nil, nil, nil)
		re := requestError(t, err)
		assert.Equal(t, PhaseBody, re.Phase)
		assert.Contains(t, err.Error(), "GET /short: read response: ")
		assert.Contains(t, err.Error(), "(the request stopped while reading the response body, on a new connection, after ")
	})

	t.Run("a reused connection", func(t *testing.T) {
		client := phaseClient(hub, newTransport(), 300*time.Millisecond)
		require.NoError(t, client.Do(ctx, http.MethodGet, "/fast", nil, nil, nil))
		err := client.Do(ctx, http.MethodGet, "/hold", nil, nil, nil)
		re := requestError(t, err)
		assert.Equal(t, PhaseRequestWritten, re.Phase)
		assert.True(t, re.Reused)
		assert.Contains(t, err.Error(), "on a reused connection")
	})

	t.Run("a caller that cancels", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		time.AfterFunc(200*time.Millisecond, cancel)
		err := phaseClient(hub, newTransport(), 0).Do(cctx, http.MethodGet, "/hold", nil, nil, nil)
		re := requestError(t, err)
		assert.Equal(t, PhaseRequestWritten, re.Phase)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// nestedTransport stands for a token renewal at an identity provider: before
// sending the request on, it makes a request of its own to another server,
// on the request's context, as transportauth does.
type nestedTransport struct {
	base http.RoundTripper
	idp  string
}

func (n nestedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	renew, err := http.NewRequestWithContext(req.Context(), http.MethodPost, n.idp, strings.NewReader("grant_type=refresh_token"))
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Transport: n.base}).Do(renew)
	if err != nil {
		return nil, fmt.Errorf("renew this machine's access token: %w", err)
	}
	_ = resp.Body.Close()
	return n.base.RoundTrip(req)
}

// The request a wrapper makes first on the same context is not the hub
// request: its connection, write and wait are not counted as the hub's.
func TestRequestPhaseIgnoresARequestAWrapperMakesFirst(t *testing.T) {
	hub := phaseHub(t)
	idp := phaseHub(t)

	t.Run("the wrapper's own request stalls", func(t *testing.T) {
		err := phaseClient(hub, nestedTransport{newTransport(), idp.URL + "/api/v1/hold"}, 300*time.Millisecond).
			Do(context.Background(), http.MethodGet, "/fast", nil, nil, nil)
		re := requestError(t, err)
		assert.Equal(t, PhaseNotStarted, re.Phase, "%v", err)
		assert.False(t, re.Connected)
	})

	t.Run("the wrapper's own request answers, then the hub stalls", func(t *testing.T) {
		err := phaseClient(hub, nestedTransport{newTransport(), idp.URL + "/api/v1/fast"}, 300*time.Millisecond).
			Do(context.Background(), http.MethodGet, "/hold", nil, nil, nil)
		re := requestError(t, err)
		assert.Equal(t, PhaseRequestWritten, re.Phase, "%v", err)
		assert.True(t, re.Connected)
		assert.False(t, re.Reused, "the hub's connection is new; the identity provider's is not counted")
	})
}

// Through a proxy, a request a wrapper makes first reaches the same address
// as the hub request, so its events cannot be told apart. The error says the
// connection was to a proxy instead of claiming the phase is the hub's.
func TestRequestPhaseSaysWhenAProxyHidesWhoseEventsTheyAre(t *testing.T) {
	hub := phaseHub(t)
	idp := phaseHub(t)
	proxy, err := url.Parse(idp.URL)
	require.NoError(t, err)
	saved := phaseProxy
	phaseProxy = func(*http.Request) (*url.URL, error) { return proxy, nil }
	t.Cleanup(func() { phaseProxy = saved })

	err = phaseClient(hub, nestedTransport{newTransport(), idp.URL + "/api/v1/hold"}, 300*time.Millisecond).
		Do(context.Background(), http.MethodGet, "/fast", nil, nil, nil)
	re := requestError(t, err)
	assert.True(t, re.Proxied)
	assert.Contains(t, re.Describe(), "to a proxy, which an earlier request on the same context may also have used")

	// Negative control: without a proxy the same request is not proxied.
	phaseProxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	err = phaseClient(hub, nestedTransport{newTransport(), idp.URL + "/api/v1/hold"}, 300*time.Millisecond).
		Do(context.Background(), http.MethodGet, "/fast", nil, nil, nil)
	re = requestError(t, err)
	assert.False(t, re.Proxied)
	assert.Equal(t, PhaseNotStarted, re.Phase)
}

// A redirect Do follows is the request from then on: a stall at the
// redirect's destination, another host, is that hop's phase, not the first
// hop's answered one.
func TestRequestPhaseFollowsARedirect(t *testing.T) {
	elsewhere := phaseHub(t)
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/api/v1/hold", http.StatusFound)
	}))
	t.Cleanup(hub.Close)

	err := phaseClient(hub, newTransport(), 300*time.Millisecond).Do(context.Background(), http.MethodGet, "/fast", nil, nil, nil)
	re := requestError(t, err)
	assert.Equal(t, PhaseRequestWritten, re.Phase, "%v", err)
	assert.True(t, re.Connected)
	assert.False(t, re.Reused, "the redirect's destination is a new connection")

	// The client's own redirect policy is still the one applied.
	client := phaseClient(hub, newTransport(), time.Second)
	client.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	err = client.Do(context.Background(), http.MethodGet, "/fast", nil, nil, nil)
	var refusal *Error
	require.ErrorAs(t, err, &refusal, "the 302 itself is the answer")
	assert.Equal(t, http.StatusFound, refusal.Status)
}

func TestRequestPhaseIsPerRequest(t *testing.T) {
	hub := phaseHub(t)
	client := phaseClient(hub, newTransport(), 500*time.Millisecond)
	var wg sync.WaitGroup
	errs := make([]error, 16)
	for i := range errs {
		wg.Go(func() {
			path := "/fast"
			if i%2 == 1 {
				path = "/hold"
			}
			errs[i] = client.Do(context.Background(), http.MethodGet, path, nil, nil, nil)
		})
	}
	wg.Wait()
	for i, err := range errs {
		if i%2 == 0 {
			assert.NoError(t, err, "request %d", i)
			continue
		}
		assert.Equal(t, PhaseRequestWritten, requestError(t, err).Phase, "request %d", i)
	}
}

func TestRequestPhaseKeepsTheCallersTrace(t *testing.T) {
	hub := phaseHub(t)
	var got atomic.Int32
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { got.Add(1) },
	})
	require.NoError(t, phaseClient(hub, newTransport(), time.Second).Do(ctx, http.MethodGet, "/fast", nil, nil, nil))
	assert.Equal(t, int32(1), got.Load(), "the caller's own trace hook still runs")
}

// The phase text adds nothing a request carried: no address, credential,
// query or body. What the transport's error already says (its URL) is
// unchanged and is checked elsewhere.
func TestRequestPhaseAddsNothingTheRequestCarried(t *testing.T) {
	hub := phaseHub(t)
	client := New(hub.URL+"/api/v1", "api-key-value", &http.Client{Transport: afterTransport{newTransport()}, Timeout: 300 * time.Millisecond})
	q := map[string][]string{"q": {"query-value"}}
	err := client.Do(context.Background(), http.MethodPost, "/hold", q, map[string]string{"field": "body-value"}, nil)
	re := requestError(t, err)
	described := re.Describe()
	host := strings.TrimPrefix(hub.URL, "http://")
	hostOnly, port, _ := net.SplitHostPort(host)
	for _, leaked := range []string{host, hostOnly, port, "api-key-value", "secret-token-value", "query-value", "body-value", "Bearer"} {
		assert.NotContains(t, described, leaked)
	}
	// Negative control: the same check finds a value that is there.
	assert.Contains(t, described, "after the request was written")
}

// A refusal is a complete response: it is the *Error it was before, with no
// phase.
func TestRequestPhaseLeavesARefusalAlone(t *testing.T) {
	hub := phaseHub(t)
	err := phaseClient(hub, newTransport(), time.Second).Do(context.Background(), http.MethodGet, "/missing", nil, nil, nil)
	var refusal *Error
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, http.StatusNotFound, refusal.Status)
	var re *RequestError
	assert.False(t, errors.As(err, &re))
	assert.NotContains(t, err.Error(), "the request stopped")
}
