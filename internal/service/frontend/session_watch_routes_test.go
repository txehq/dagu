// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	persiststore "github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	apiv1 "github.com/dagucloud/dagu/v2/internal/service/frontend/api/v1"
	frontendauth "github.com/dagucloud/dagu/v2/internal/service/frontend/auth"
	"github.com/dagucloud/dagu/v2/internal/service/oidcsession"
)

// routeClock is the clock of a route test. It moves only when the test moves
// it, and then fires the timers that have come due.
type routeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[*routeTimer]struct{}
}

type routeTimer struct {
	at time.Time
	c  chan time.Time
}

func newRouteClock() *routeClock {
	return &routeClock{now: time.Now(), timers: map[*routeTimer]struct{}{}}
}

func (c *routeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *routeClock) After(d time.Duration) (<-chan time.Time, func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &routeTimer{at: c.now.Add(d), c: make(chan time.Time, 1)}
	c.timers[timer] = struct{}{}
	return timer.c, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(c.timers, timer)
	}
}

// advance moves the clock and fires every timer that is due by then.
func (c *routeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for timer := range c.timers {
		if !timer.at.After(c.now) {
			delete(c.timers, timer)
			timer.c <- c.now
		}
	}
}

func (c *routeClock) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

// routeProvider is an identity provider that confirms, or does not answer.
type routeProvider struct {
	mu   sync.Mutex
	down bool
}

func (p *routeProvider) Establish(context.Context, string) (oidcsession.ClientAuth, oidcsession.Renewal, error) {
	return oidcsession.ClientAuthHeader, oidcsession.Renewal{}, nil
}

func (p *routeProvider) Refresh(context.Context, string, oidcsession.ClientAuth) (oidcsession.Renewal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.down {
		return oidcsession.Renewal{}, errors.New("the identity provider did not answer")
	}
	return oidcsession.Renewal{RefreshToken: "next-refresh-token"}, nil
}

func (p *routeProvider) Revoke(context.Context, string, oidcsession.ClientAuth) error { return nil }

func (p *routeProvider) setDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
}

// routeHub is the hub's real routes for the event stream, the MCP handler,
// the terminal and the OIDC sign-out, over a real auth service and, when
// sessions are on, a real session manager on a clock the test moves.
type routeHub struct {
	t        *testing.T
	clock    *routeClock
	provider *routeProvider
	svc      *authservice.Service
	sessions *oidcsession.Manager
	srv      *Server
	http     *httptest.Server
	alice    *authmodel.User
	admin    *authmodel.User
}

func newRouteHub(t *testing.T, sessionsOn bool) *routeHub {
	t.Helper()
	backend := testutil.NewMemoryBackend()
	users, err := persiststore.NewUserStore(backend.Collection("users"))
	require.NoError(t, err)
	secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
	require.NoError(t, err)
	svc := authservice.New(users, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4})

	hub := &routeHub{t: t, clock: newRouteClock(), provider: &routeProvider{}, svc: svc}
	ctx := testContext(t)
	hub.admin, err = svc.CreateUser(ctx, authservice.CreateUserInput{Username: "admin", Password: "password123", Role: authmodel.RoleAdmin})
	require.NoError(t, err)
	// The terminal is for administrators, so the OIDC user is one.
	hub.alice = authmodel.NewUser("alice", "", authmodel.RoleAdmin)
	hub.alice.AuthProvider = authmodel.AuthProviderOIDC
	hub.alice.OIDCIssuer, hub.alice.OIDCSubject = "https://issuer.example/realms/test", "subject-1"
	require.NoError(t, users.Create(ctx, hub.alice))

	cfg := &config.Config{}
	cfg.Server.Auth.Mode = config.AuthModeBuiltin
	cfg.Server.Terminal.MaxSessions = 2
	cfg.Core.DefaultShell = "/bin/sh"
	hub.srv = &Server{config: cfg, apiV1: &apiv1.API{}, authService: svc, sessionWatchClock: hub.clock}

	if sessionsOn {
		enc, err := crypto.NewEncryptor("a-test-key-that-is-long-enough-for-aes")
		require.NoError(t, err)
		hub.sessions, err = oidcsession.NewManager(oidcsession.Config{
			RevalidateAfter: 4 * time.Minute, RevalidateLimit: 5 * time.Minute, Now: hub.clock.Now,
		}, backend.Collection("oidc_sessions"), enc, hub.provider, nil)
		require.NoError(t, err)
		svc.SetSessionChecker(frontendauth.OIDCSessionChecker{Manager: hub.sessions})
		hub.srv.builtinOIDCCfg = &frontendauth.BuiltinOIDCConfig{AuthService: svc, Sessions: hub.sessions, LoginBasePath: "/"}
	}

	router := chi.NewMux()
	hub.srv.setupSSERoute(ctx, router, "/api/v1")
	hub.srv.setupMCPRoute(ctx, router)
	hub.srv.setupTerminalRoute(ctx, router, "/api/v1")
	if sessionsOn {
		hub.srv.setupOIDCRoutes(router, "/")
	}
	hub.http = httptest.NewServer(router)
	t.Cleanup(func() {
		hub.http.CloseClientConnections()
		hub.http.Close()
		if hub.srv.sseMultiplexer != nil {
			hub.srv.sseMultiplexer.Shutdown()
		}
		if hub.srv.appStream != nil {
			hub.srv.appStream.Shutdown()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hub.srv.terminalManager.Shutdown(shutdownCtx)
	})
	return hub
}

// signIn issues the hub token the OIDC callback would: one that carries a
// session, when sessions are on.
func (h *routeHub) signIn() string {
	h.t.Helper()
	if h.sessions == nil {
		token, err := h.svc.GenerateToken(h.alice)
		require.NoError(h.t, err)
		return token.Token
	}
	// The token is signed and verified on the real clock; the session is on
	// the test's.
	expires := time.Now().Add(time.Hour)
	session, err := h.sessions.Create(context.Background(), oidcsession.Identity{
		UserID: h.alice.ID, Issuer: h.alice.OIDCIssuer, Subject: h.alice.OIDCSubject,
	}, "provider-refresh-token", h.clock.Now().Add(time.Hour))
	require.NoError(h.t, err)
	token, err := h.svc.GenerateSessionToken(h.alice, session.ID, expires)
	require.NoError(h.t, err)
	return token.Token
}

// signOut signs the token's session out through the hub's own route.
func (h *routeHub) signOut(token string) {
	h.t.Helper()
	request, err := http.NewRequest(http.MethodPost, h.http.URL+"/oidc-logout", nil)
	require.NoError(h.t, err)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := h.http.Client().Do(request)
	require.NoError(h.t, err)
	_ = response.Body.Close()
	require.Equal(h.t, http.StatusNoContent, response.StatusCode)
}

// armed waits until the watch of the one open connection is waiting on the
// clock again: for its next check and for the limit.
func (h *routeHub) armed() {
	h.t.Helper()
	require.Eventually(h.t, func() bool { return h.clock.pending() == 2 }, 5*time.Second, time.Millisecond,
		"the watch is not waiting for its next check and its limit")
}

// openConnection is a connection a test holds open. closed is closed when
// the hub has closed it.
type openConnection struct {
	closed <-chan struct{}
	// alive, when set, reports that the connection still works, by using it.
	alive func() bool
	// hangUp ends the connection from the client's side.
	hangUp func()
}

func (c openConnection) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// openStream opens a streaming GET and reads it in the background.
func (h *routeHub) openStream(target string, header http.Header) openConnection {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, h.http.URL+target, nil)
	require.NoError(h.t, err)
	maps.Copy(request.Header, header)
	response, err := h.http.Client().Do(request) //nolint:bodyclose // closed by the reader below, when the stream ends
	require.NoError(h.t, err)
	require.Equal(h.t, http.StatusOK, response.StatusCode, target)
	require.True(h.t, strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream"), response.Header.Get("Content-Type"))

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}()
	h.t.Cleanup(cancel)
	return openConnection{closed: closed, hangUp: cancel}
}

func (h *routeHub) openEventStream(token string) openConnection {
	h.t.Helper()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	return h.openStream("/api/v1/events/stream", header)
}

// openMCPStream starts an MCP session and opens its standing stream, the GET
// a client holds open for what the server sends it.
func (h *routeHub) openMCPStream(token string) openConnection {
	h.t.Helper()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	header.Set("Accept", "application/json, text/event-stream")
	header.Set("Content-Type", "application/json")

	post := func(body string, sessionID string) (status int, mcpSession string, answer string) {
		request, err := http.NewRequest(http.MethodPost, h.http.URL+"/mcp", strings.NewReader(body))
		require.NoError(h.t, err)
		request.Header = header.Clone()
		if sessionID != "" {
			request.Header.Set("Mcp-Session-Id", sessionID)
		}
		response, err := h.http.Client().Do(request)
		require.NoError(h.t, err)
		defer func() { _ = response.Body.Close() }()
		raw, err := io.ReadAll(response.Body)
		require.NoError(h.t, err)
		return response.StatusCode, response.Header.Get("Mcp-Session-Id"), string(raw)
	}
	status, sessionID, answer := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"route-test","version":"0"}}}`, "")
	require.Equal(h.t, http.StatusOK, status, answer)
	require.NotEmpty(h.t, sessionID)
	status, _, answer = post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, sessionID)
	require.Less(h.t, status, 300, answer)

	// The two requests above were watched and are over: nothing of theirs is
	// left on the clock.
	if h.sessions != nil {
		require.Eventually(h.t, func() bool { return h.clock.pending() == 0 }, 5*time.Second, time.Millisecond)
	}

	stream := http.Header{}
	stream.Set("Authorization", "Bearer "+token)
	stream.Set("Accept", "text/event-stream")
	stream.Set("Mcp-Session-Id", sessionID)
	return h.openStream("/mcp", stream)
}

// Each connection that stays open is closed when its OIDC session ends,
// while it is open: at the next check after a sign-out, and at the session's
// limit when the provider does not confirm it. A next request refused is not
// what is shown here: the connection that was already there is closed.
func TestOpenConnectionsAreClosedWhenTheirOIDCSessionEnds(t *testing.T) {
	t.Parallel()

	for name, open := range openers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			t.Run("SignOut", func(t *testing.T) {
				t.Parallel()
				hub := newRouteHub(t, true)
				token := hub.signIn()
				conn := open(hub, token)
				hub.armed()

				// A check with the session in order leaves it open.
				hub.clock.advance(15 * time.Second)
				hub.armed()
				require.False(t, conn.isClosed())
				if conn.alive != nil {
					require.True(t, conn.alive())
				}

				hub.signOut(token)
				// Signing out closes nothing by itself; the next check does.
				hub.clock.advance(15*time.Second - time.Millisecond)
				require.Equal(t, 2, hub.clock.pending())
				require.False(t, conn.isClosed())

				hub.clock.advance(time.Millisecond)
				requireClosed(t, conn)
				assert.Zero(t, hub.clock.pending(), "the watch is over")
			})

			t.Run("ProviderOutagePastTheLimit", func(t *testing.T) {
				t.Parallel()
				hub := newRouteHub(t, true)
				token := hub.signIn()
				conn := open(hub, token)
				hub.armed()
				hub.provider.setDown(true)

				// Inside the limit it stays open, through the checks that
				// ask the provider and get nothing.
				for elapsed := time.Duration(0); elapsed < 4*time.Minute+55*time.Second; elapsed += 5 * time.Second {
					hub.clock.advance(5 * time.Second)
					hub.armed()
				}
				require.False(t, conn.isClosed(), "five seconds before the limit")
				if conn.alive != nil {
					require.True(t, conn.alive())
				}
				hub.clock.advance(5*time.Second - time.Millisecond)
				require.Eventually(t, func() bool { return hub.clock.pending() >= 1 }, 5*time.Second, time.Millisecond)
				require.False(t, conn.isClosed(), "a millisecond before the limit")

				hub.clock.advance(time.Millisecond)
				requireClosed(t, conn)
			})

			// A connection the client ends is watched no longer: nothing is
			// left on the clock, and nothing goes on asking the provider
			// for a connection that is gone.
			t.Run("ClientGoesAway", func(t *testing.T) {
				t.Parallel()
				hub := newRouteHub(t, true)
				conn := open(hub, hub.signIn())
				hub.armed()

				conn.hangUp()
				require.Eventually(t, func() bool { return hub.clock.pending() == 0 }, 10*time.Second, time.Millisecond,
					"the watch outlived its connection")
			})

			t.Run("ProviderConfirms", func(t *testing.T) {
				t.Parallel()
				hub := newRouteHub(t, true)
				conn := open(hub, hub.signIn())
				hub.armed()

				// Twenty minutes with nothing else asking for the session.
				for elapsed := time.Duration(0); elapsed < 20*time.Minute; elapsed += 15 * time.Second {
					hub.clock.advance(15 * time.Second)
					hub.armed()
				}
				require.False(t, conn.isClosed())
				if conn.alive != nil {
					require.True(t, conn.alive())
				}
			})
		})
	}
}

// Without OIDC sessions, and for a token that is not an OIDC session's when
// they are on, these connections are as they were: nothing watches them, no
// timer is set, and they stay open.
func TestOpenConnectionsAreNotWatchedWithoutAnOIDCSession(t *testing.T) {
	t.Parallel()

	for name, open := range openers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			t.Run("SessionsOff", func(t *testing.T) {
				t.Parallel()
				hub := newRouteHub(t, false)
				require.Nil(t, hub.srv.sessionWatch())
				conn := open(hub, hub.signIn())

				hub.clock.advance(24 * time.Hour)
				assert.Zero(t, hub.clock.pending())
				requireStaysOpen(t, conn)
			})

			t.Run("BuiltinUserWithSessionsOn", func(t *testing.T) {
				t.Parallel()
				hub := newRouteHub(t, true)
				token, err := hub.svc.GenerateToken(hub.admin)
				require.NoError(t, err)
				conn := open(hub, token.Token)

				hub.provider.setDown(true)
				hub.clock.advance(24 * time.Hour)
				assert.Zero(t, hub.clock.pending())
				requireStaysOpen(t, conn)
			})
		})
	}
}

func requireClosed(t *testing.T, conn openConnection) {
	t.Helper()
	select {
	case <-conn.closed:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the hub did not close the connection")
	}
}

func requireStaysOpen(t *testing.T, conn openConnection) {
	t.Helper()
	select {
	case <-conn.closed:
		require.FailNow(t, "the hub closed the connection")
	case <-time.After(300 * time.Millisecond):
	}
	if conn.alive != nil {
		require.True(t, conn.alive())
	}
}

// openers opens each kind of connection that stays open.
var openers = map[string]func(*routeHub, string) openConnection{
	"EventStream": (*routeHub).openEventStream,
	"MCPStream":   (*routeHub).openMCPStream,
}

// A handler held in a write to a client that has stopped reading does not
// see its context end. When the watch closes its request, the write is cut
// short as well, so the connection does not stay for as long as the client
// likes.
func TestAWriteToAClientThatDoesNotReadIsCutShort(t *testing.T) {
	t.Parallel()
	hub := newRouteHub(t, true)
	token := hub.signIn()

	var written atomic.Int64
	returned := make(chan struct{})
	stream := httptest.NewServer(hub.srv.sessionWatch().Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defer close(returned)
		chunk := make([]byte, 64<<10)
		// It never looks at its context: only a failed write ends it.
		for {
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	})))
	t.Cleanup(stream.Close)

	// A client that asks and then reads nothing.
	conn, err := net.Dial("tcp", strings.TrimPrefix(stream.URL, "http://"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: hub\r\nAuthorization: Bearer " + token + "\r\n\r\n"))
	require.NoError(t, err)

	// The handler fills the socket and is then held in a write.
	hub.armed()
	require.Eventually(t, func() bool {
		before := written.Load()
		time.Sleep(200 * time.Millisecond)
		return before > 0 && written.Load() == before
	}, 20*time.Second, 10*time.Millisecond, "the handler is not held in a write")

	hub.signOut(token)
	hub.clock.advance(15 * time.Second)
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the handler is still held in its write after the watch closed the request")
	}
}
