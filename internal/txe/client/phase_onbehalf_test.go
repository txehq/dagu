// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/onbehalf"
	"github.com/dagucloud/dagu/v2/internal/txe/onbehalf/onbehalftest"
)

// A wrapper that announces the requests it makes on the hub request's
// behalf (onbehalf.Context), as transportauth and cliauth do, fires none of
// the trace's hooks and is read as PhaseOnBehalf while it runs, whatever
// its address: the identity provider at the hub's own origin, at another,
// or behind the same proxy (TXE-6352). After it, the hub request's own
// attempt is read as before.

// behalfHub is a hub and a token endpoint. The hub refuses its first
// request to /api/v1/refuse with 401 and answers the rest; /api/v1/hold is
// never answered; /token is held or answered as the test says.
type behalfHub struct {
	server    *httptest.Server
	holdToken bool
	// closeAfter401 makes the refusal's connection a closing one.
	closeAfter401 bool
	done          chan struct{}

	mu      sync.Mutex
	refused bool
	tokens  int
}

func newBehalfHub(t *testing.T, http2 bool) *behalfHub {
	t.Helper()
	h := &behalfHub{done: make(chan struct{})}
	hold := func(r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-h.done:
		}
	}
	h.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			h.mu.Lock()
			h.tokens++
			h.mu.Unlock()
			if h.holdToken {
				hold(r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":300}`))
		case "/api/v1/hold":
			hold(r)
		case "/api/v1/refuse":
			h.mu.Lock()
			first := !h.refused
			h.refused = true
			h.mu.Unlock()
			if first {
				if h.closeAfter401 {
					w.Header().Set("Connection", "close")
				}
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"code":"unauthorized"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	if http2 {
		h.server.EnableHTTP2 = true
		h.server.StartTLS()
	} else {
		h.server.Start()
	}
	t.Cleanup(func() { close(h.done); h.server.Close() })
	return h
}

func (h *behalfHub) tokenCalls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tokens
}

// announcing stands for cliauth.BearerTransport and the machine transport:
// it renews at tokenURL on the request's behalf, before the request when
// renewFirst, or after the hub answers 401, and then sends the request on.
type announcing struct {
	base       http.RoundTripper
	tokenURL   string
	renewFirst bool
}

func (a announcing) renew(ctx context.Context) error {
	req, err := http.NewRequestWithContext(onbehalf.Context(ctx), http.MethodPost, a.tokenURL, strings.NewReader("grant_type=refresh_token"))
	if err != nil {
		return err
	}
	resp, err := a.base.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("renew the token: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

func (a announcing) RoundTrip(req *http.Request) (*http.Response, error) {
	if a.renewFirst {
		if err := a.renew(req.Context()); err != nil {
			return nil, err
		}
		return a.base.RoundTrip(req)
	}
	resp, err := a.base.RoundTrip(req.Clone(req.Context()))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err := a.renew(req.Context()); err != nil {
		return nil, err
	}
	return a.base.RoundTrip(req)
}

func TestRequestPhaseReadsAnAnnouncedRenewalAsOnBehalf(t *testing.T) {
	type where struct {
		name string
		// setup returns the hub, the base transport for both requests and
		// the token URL.
		setup func(t *testing.T, h *behalfHub) (base *http.Transport, tokenURL string)
		http2 bool
	}
	wheres := []where{
		{name: "provider at the hub's origin", setup: func(_ *testing.T, h *behalfHub) (*http.Transport, string) {
			return newTransport(), h.server.URL + "/token"
		}},
		{name: "provider at another origin", setup: func(t *testing.T, h *behalfHub) (*http.Transport, string) {
			idp := newBehalfHub(t, false)
			idp.holdToken = h.holdToken
			return newTransport(), idp.server.URL + "/token"
		}},
		{name: "both behind one proxy", setup: func(t *testing.T, h *behalfHub) (*http.Transport, string) {
			proxy := onbehalftest.NewProxy(t)
			proxyURL, err := url.Parse(proxy.URL)
			require.NoError(t, err)
			saved := phaseProxy
			phaseProxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
			t.Cleanup(func() { phaseProxy = saved })
			tr := newTransport()
			tr.Proxy = http.ProxyURL(proxyURL)
			return tr, h.server.URL + "/token"
		}},
		{name: "provider at the hub's origin, HTTP/2", http2: true, setup: func(t *testing.T, h *behalfHub) (*http.Transport, string) {
			resp, err := h.server.Client().Get(h.server.URL + "/api/v1/fast")
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, "HTTP/2.0", resp.Proto, "the fixture speaks HTTP/2")
			return h.server.Client().Transport.(*http.Transport), h.server.URL + "/token"
		}},
	}
	type when struct {
		name       string
		renewFirst bool
		closeAfter bool
		path       string
	}
	whens := []when{
		{name: "the renewal before the request stalls", renewFirst: true, path: "/fast"},
		{name: "the renewal after a 401 stalls", path: "/refuse"},
		{name: "the renewal after a 401 on a closing connection stalls", closeAfter: true, path: "/refuse"},
	}
	for _, w := range wheres {
		for _, c := range whens {
			t.Run(w.name+": "+c.name, func(t *testing.T) {
				h := newBehalfHub(t, w.http2)
				h.holdToken = true
				h.closeAfter401 = c.closeAfter
				base, tokenURL := w.setup(t, h)
				err := phaseClient(h.server, announcing{base, tokenURL, c.renewFirst}, 400*time.Millisecond).
					Do(context.Background(), http.MethodGet, c.path, nil, nil, nil)
				re := requestError(t, err)
				assert.Equal(t, PhaseOnBehalf, re.Phase, "%v", err)
				assert.False(t, re.Connected)
				assert.False(t, re.Proxied, "nothing of the renewal was counted")
				assert.Contains(t, err.Error(), "(the request stopped while a request made on its behalf, such as a token renewal, ran, after ")
				assert.Contains(t, err.Error(), "renew the token: ", "the wrapper's own text is kept")
				assert.ErrorIs(t, err, context.DeadlineExceeded)
				host := strings.TrimPrefix(strings.TrimPrefix(h.server.URL, "http://"), "https://")
				hostOnly, port, _ := net.SplitHostPort(host)
				for _, leaked := range []string{host, hostOnly, port, "/token"} {
					assert.NotContains(t, re.Describe(), leaked)
				}
			})
		}
	}
}

// Once the renewal has answered, the hub request's own attempt is read as
// before: written and unanswered, on its own connection.
func TestRequestPhaseResumesAfterAnAnnouncedRenewal(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%v", http2), func(t *testing.T) {
			h := newBehalfHub(t, http2)
			base := newTransport()
			if http2 {
				base = h.server.Client().Transport.(*http.Transport)
			}
			err := phaseClient(h.server, announcing{base, h.server.URL + "/token", true}, 400*time.Millisecond).
				Do(context.Background(), http.MethodGet, "/hold", nil, nil, nil)
			re := requestError(t, err)
			assert.Equal(t, PhaseRequestWritten, re.Phase, "%v", err)
			assert.True(t, re.Connected)
			assert.Equal(t, 1, h.tokenCalls())

			// After a 401 and a renewal, the resent request that stalls.
			h2 := newBehalfHub(t, http2)
			h2.mu.Lock()
			h2.refused = false
			h2.mu.Unlock()
			base2 := newTransport()
			if http2 {
				base2 = h2.server.Client().Transport.(*http.Transport)
			}
			client := phaseClient(h2.server, announcing{base2, h2.server.URL + "/token", false}, 400*time.Millisecond)
			require.NoError(t, client.Do(context.Background(), http.MethodGet, "/refuse", nil, nil, nil), "refused once, renewed, answered")
			err = client.Do(context.Background(), http.MethodGet, "/hold", nil, nil, nil)
			re = requestError(t, err)
			assert.Equal(t, PhaseRequestWritten, re.Phase, "%v", err)
			assert.True(t, re.Connected)
		})
	}
}
