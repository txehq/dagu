// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	persiststore "github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	apiv1 "github.com/dagucloud/dagu/v2/internal/service/frontend/api/v1"
	frontendauth "github.com/dagucloud/dagu/v2/internal/service/frontend/auth"
)

// mcpHub is the hub's real MCP route in one authentication mode.
type mcpHub struct {
	t    *testing.T
	svc  *authservice.Service
	http *httptest.Server
	// opts are the options the route's authentication was built with.
	opts frontendauth.Options
}

func newMCPHub(t *testing.T, mode config.AuthMode) *mcpHub {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.Auth.Mode = mode
	cfg.Server.Auth.Basic.Username, cfg.Server.Auth.Basic.Password = "operator", "basic-password"
	hub := &mcpHub{t: t}
	srv := &Server{config: cfg, apiV1: &apiv1.API{}}
	if mode == config.AuthModeBuiltin {
		backend := testutil.NewMemoryBackend()
		users, err := persiststore.NewUserStore(backend.Collection("users"))
		require.NoError(t, err)
		keys, err := persiststore.NewAPIKeyStore(backend.Collection("api_keys"))
		require.NoError(t, err)
		secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
		require.NoError(t, err)
		hub.svc = authservice.New(users, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4},
			authservice.WithAPIKeyStore(keys))
		srv.authService = hub.svc
	}
	router := chi.NewMux()
	srv.setupMCPRoute(testContext(t), router)
	hub.opts = srv.buildStreamAuthOptions("Dagu MCP")
	hub.http = httptest.NewServer(router)
	t.Cleanup(func() {
		hub.http.CloseClientConnections()
		hub.http.Close()
	})
	return hub
}

func (h *mcpHub) user(name string, role authmodel.Role) *authmodel.User {
	h.t.Helper()
	user, err := h.svc.CreateUser(testContext(h.t), authservice.CreateUserInput{Username: name, Password: "password123", Role: role})
	require.NoError(h.t, err)
	return user
}

func (h *mcpHub) tokenOf(user *authmodel.User) string {
	h.t.Helper()
	token, err := h.svc.GenerateToken(user)
	require.NoError(h.t, err)
	return "Bearer " + token.Token
}

// mcpAnswer is what the hub answered an MCP request with. A stream that
// opened is closed again at once and reported as such.
type mcpAnswer struct {
	status  int
	session string
	stream  bool
	body    string
}

// ask sends one MCP request with the given Authorization header, on the given
// MCP session if there is one.
func (h *mcpHub) ask(method, authorization, session, body string) mcpAnswer {
	h.t.Helper()
	request, err := http.NewRequest(method, h.http.URL+"/mcp", strings.NewReader(body))
	require.NoError(h.t, err)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	request.Header.Set("Accept", "application/json, text/event-stream")
	if method == http.MethodGet {
		request.Header.Set("Accept", "text/event-stream")
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if session != "" {
		request.Header.Set("Mcp-Session-Id", session)
	}
	response, err := h.http.Client().Do(request)
	require.NoError(h.t, err)
	defer func() { _ = response.Body.Close() }()
	answer := mcpAnswer{status: response.StatusCode, session: response.Header.Get("Mcp-Session-Id")}
	if strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		answer.stream = true
		return answer
	}
	raw, err := io.ReadAll(response.Body)
	require.NoError(h.t, err)
	answer.body = string(raw)
	return answer
}

const (
	mcpInitialize  = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`
	mcpInitialized = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	mcpListTools   = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
)

// open starts an MCP session as the given caller and returns its id.
func (h *mcpHub) open(authorization string) string {
	h.t.Helper()
	initialized := h.ask(http.MethodPost, authorization, "", mcpInitialize)
	require.Equal(h.t, http.StatusOK, initialized.status, initialized.body)
	require.NotEmpty(h.t, initialized.session)
	require.Less(h.t, h.ask(http.MethodPost, authorization, initialized.session, mcpInitialized).status, 300)
	return initialized.session
}

// works reports that the caller can use the session.
func (h *mcpHub) works(authorization, session string) {
	h.t.Helper()
	listed := h.ask(http.MethodPost, authorization, session, mcpListTools)
	require.Equal(h.t, http.StatusOK, listed.status, listed.body)
	require.Contains(h.t, listed.body, `"tools"`)
}

// refused reports that the caller can do nothing with the session: not send
// a request on it, not hold its stream, not end it.
func (h *mcpHub) refused(authorization, session string, why string) {
	h.t.Helper()
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		body := ""
		if method == http.MethodPost {
			body = mcpListTools
		}
		answer := h.ask(method, authorization, session, body)
		assert.Equal(h.t, http.StatusForbidden, answer.status, "%s %s: %s", why, method, answer.body)
		assert.False(h.t, answer.stream, "%s %s: the stream was opened", why, method)
	}
}

// An MCP session belongs to the caller who created it. Another caller who
// has a credential of their own and knows the session's id can neither use
// it, nor listen on it, nor end it, and it goes on working for its owner.
func TestAnMCPSessionBelongsToTheCallerWhoCreatedIt(t *testing.T) {
	t.Parallel()
	hub := newMCPHub(t, config.AuthModeBuiltin)
	alice, bob := hub.user("alice", authmodel.RoleAdmin), hub.user("bob", authmodel.RoleViewer)
	aliceToken, bobToken := hub.tokenOf(alice), hub.tokenOf(bob)

	session := hub.open(aliceToken)
	hub.works(aliceToken, session)

	hub.refused(bobToken, session, "another user")
	hub.refused(hub.tokenOf(hub.user("carol", authmodel.RoleAdmin)), session, "another administrator")
	hub.works(aliceToken, session)

	// The session is its user's, not one token's: the same user with
	// another token, here one for a session of OIDC's, carries on with it,
	// and can hold its stream and end it.
	other, err := hub.svc.GenerateSessionToken(alice, "0123456789abcdef0123456789abcdef", time.Now().Add(time.Hour))
	require.NoError(t, err)
	again := "Bearer " + other.Token
	require.NotEqual(t, aliceToken, again)
	hub.svc.SetSessionChecker(sessionInOrder{})
	hub.works(again, session)
	stream := hub.ask(http.MethodGet, again, session, "")
	require.Equal(t, http.StatusOK, stream.status)
	require.True(t, stream.stream)
	require.Equal(t, http.StatusNoContent, hub.ask(http.MethodDelete, again, session, "").status)
	require.Equal(t, http.StatusNotFound, hub.ask(http.MethodPost, aliceToken, session, mcpListTools).status)

	// The placeholder the hub shows the MCP library is not a credential: sent
	// by a client, it is refused like any other string that is not one.
	require.Equal(t, http.StatusUnauthorized, hub.ask(http.MethodPost, mcpPlaceholderBearer, session, mcpListTools).status)
	require.Equal(t, http.StatusUnauthorized, hub.ask(http.MethodPost, mcpPlaceholderBearer, "", mcpInitialize).status)

	// A session bob opens is bob's.
	bobs := hub.open(bobToken)
	hub.works(bobToken, bobs)
	hub.refused(aliceToken, bobs, "an administrator on a viewer's session")
}

// sessionInOrder is an OIDC session check that always passes.
type sessionInOrder struct{}

func (sessionInOrder) CheckSession(context.Context, string, *authmodel.User) error { return nil }

// An API key owns the sessions it creates. The user the key belongs to is
// another caller, and so is another key of the same user.
func TestAnMCPSessionOfAnAPIKeyIsNotItsOwnersSession(t *testing.T) {
	t.Parallel()
	hub := newMCPHub(t, config.AuthModeBuiltin)
	alice := hub.user("alice", authmodel.RoleAdmin)
	aliceToken := hub.tokenOf(alice)
	key := func(name string) string {
		created, err := hub.svc.CreateAPIKey(testContext(t), authservice.CreateAPIKeyInput{
			Name: name, Role: authmodel.RoleAdmin,
			AllowedSurfaces:  []authmodel.APIKeySurface{authmodel.APIKeySurfaceMCP},
			AttributionClass: authmodel.APIKeyAttributionUserOwned, OwnerUserID: alice.ID,
		}, alice.ID)
		require.NoError(t, err)
		return "Bearer " + created.FullKey
	}
	first, second := key("first"), key("second")

	ofTheKey := hub.open(first)
	hub.works(first, ofTheKey)
	hub.refused(aliceToken, ofTheKey, "the key's owner on the key's session")
	hub.refused(second, ofTheKey, "another key of the same user")
	hub.works(first, ofTheKey)

	ofTheUser := hub.open(aliceToken)
	hub.refused(first, ofTheUser, "the user's key on the user's session")
	hub.works(aliceToken, ofTheUser)
}

// A hub that authenticates nobody has one caller, and its MCP route works as
// it did: the request carries no bearer token, and a session carries on.
// That is a hub in mode none, which gives every request its default user,
// and a hub with no mode set and nothing to authenticate with, which gives a
// request no user at all and is what the conformance suite's server is.
func TestMCPSessionsOnAHubWithoutAuthentication(t *testing.T) {
	t.Parallel()
	for name, mode := range map[string]config.AuthMode{"ModeNone": config.AuthModeNone, "NoModeSet": ""} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			hubWithoutAuthentication(t, mode)
		})
	}
}

func hubWithoutAuthentication(t *testing.T, mode config.AuthMode) {
	t.Helper()
	hub := newMCPHub(t, mode)

	session := hub.open("")
	hub.works("", session)
	stream := hub.ask(http.MethodGet, "", session, "")
	require.Equal(t, http.StatusOK, stream.status)
	require.True(t, stream.stream)
	require.Equal(t, http.StatusNoContent, hub.ask(http.MethodDelete, "", session, "").status)
}

// A hub with basic authentication has one user, who presents no bearer token
// at all. The MCP route works for them as it did.
func TestMCPSessionsOnAHubWithBasicAuthentication(t *testing.T) {
	t.Parallel()
	hub := newMCPHub(t, config.AuthModeBasic)
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("operator:basic-password"))

	require.Equal(t, http.StatusUnauthorized, hub.ask(http.MethodPost, "", "", mcpInitialize).status)
	session := hub.open(basic)
	hub.works(basic, session)
	require.Equal(t, http.StatusUnauthorized, hub.ask(http.MethodPost, "", session, mcpListTools).status)
	require.Equal(t, http.StatusNoContent, hub.ask(http.MethodDelete, basic, session, "").status)
}

// stubValidator stands for an authentication method the route has.
type stubValidator struct{}

func (stubValidator) GetUserFromToken(context.Context, string) (*authmodel.User, error) {
	return nil, errors.New("not used")
}

func (stubValidator) ValidateAPIKey(context.Context, string) (*authmodel.APIKey, error) {
	return nil, errors.New("not used")
}

// The routes the adapter is used on, by how they authenticate.
var (
	builtinRoute         = frontendauth.Options{AuthRequired: true, JWTValidator: stubValidator{}, APIKeyValidator: stubValidator{}}
	builtinRouteNoKeys   = frontendauth.Options{AuthRequired: true, JWTValidator: stubValidator{}}
	basicRoute           = frontendauth.Options{AuthRequired: true, BasicAuthEnabled: true}
	unauthenticatedRoute = frontendauth.Options{}
)

// authenticatingRoutes is every way a route can authenticate: each of hub
// tokens, API keys and basic, alone and together.
func authenticatingRoutes() map[string]frontendauth.Options {
	routes := map[string]frontendauth.Options{}
	for bits := 1; bits < 8; bits++ {
		opts, name := frontendauth.Options{AuthRequired: true}, ""
		if bits&1 != 0 {
			opts.JWTValidator, name = stubValidator{}, name+"Tokens"
		}
		if bits&2 != 0 {
			opts.APIKeyValidator, name = stubValidator{}, name+"Keys"
		}
		if bits&4 != 0 {
			opts.BasicAuthEnabled, name = true, name+"Basic"
		}
		routes[name] = opts
	}
	return routes
}

// The adapter by itself, on every kind of route that authenticates, with
// whatever is in front of it failing to say who the caller is: it refuses,
// and what is behind it is not run. That holds whether or not the route
// requires authentication.
func TestMCPSessionAdapterRefusesARequestWithNoCaller(t *testing.T) {
	t.Parallel()

	routes := authenticatingRoutes()
	require.Len(t, routes, 7)
	for route, required := range routes {
		optional := required
		optional.AuthRequired = false
		for _, opts := range []frontendauth.Options{required, optional} {
			cases := map[string]context.Context{
				"Nothing":      context.Background(),
				"NoUser":       authmodel.WithUser(context.Background(), nil),
				"UserWithNoID": authmodel.WithUser(context.Background(), &authmodel.User{Username: "nobody"}),
				// A key with no id is not its owner: the owner's name is not
				// fallen back to.
				"KeyWithNoID": authmodel.WithAPIKey(authmodel.WithUser(context.Background(), &authmodel.User{ID: "owner"}), &authmodel.APIKey{}),
			}
			if opts.APIKeyValidator == nil {
				// A key is a caller only where keys are checked.
				cases["AKeyWhereNoneAreChecked"] = authmodel.WithAPIKey(
					authmodel.WithUser(context.Background(), &authmodel.User{ID: "owner"}), &authmodel.APIKey{ID: "k1"})
			}
			for name, ctx := range cases {
				ran := false
				handler := mcpSessionUserMiddleware(opts)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))
				request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpInitialize)).WithContext(ctx)
				request.Header.Set("Authorization", "Bearer a-real-looking-token")
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)

				assert.Equal(t, http.StatusUnauthorized, recorder.Code, "%s required=%v %s", route, opts.AuthRequired, name)
				assert.False(t, ran, "%s required=%v %s", route, opts.AuthRequired, name)
			}
		}
	}

	// Even a route that authenticates nobody does not take a key for a
	// caller: nothing checked it.
	_, ok := mcpSessionOwner(authmodel.WithAPIKey(context.Background(), &authmodel.APIKey{ID: "k1"}), unauthenticatedRoute)
	assert.False(t, ok)
}

// The adapter decides that a route authenticates nobody exactly when the
// route's own authentication does. A request with no credential is sent
// through the real authentication middleware and then the adapter, built
// from the same options, for every combination of methods: it comes out the
// other end, as the default caller, only when the middleware has nothing to
// authenticate with. With any method at all it is stopped, by the middleware
// when authentication is required, and by the adapter when it is not.
func TestMCPSessionAdapterAgreesWithTheRoutesAuthentication(t *testing.T) {
	t.Parallel()

	for bits := range 16 {
		opts := frontendauth.Options{Realm: "Dagu MCP", AuthRequired: bits&8 != 0, Creds: map[string]string{"operator": "basic-password"}}
		if bits&1 != 0 {
			opts.JWTValidator = stubValidator{}
		}
		if bits&2 != 0 {
			opts.APIKeyValidator = stubValidator{}
		}
		opts.BasicAuthEnabled = bits&4 != 0
		authenticates := bits&7 != 0

		var owner string
		ran := false
		chain := frontendauth.Middleware(opts)(mcpSessionUserMiddleware(opts)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			ran = true
			owner = mcpauth.TokenInfoFromContext(r.Context()).UserID
		})))
		recorder := httptest.NewRecorder()
		chain.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpInitialize)))

		if authenticates {
			assert.False(t, ran, "%+v", opts)
			assert.Equal(t, http.StatusUnauthorized, recorder.Code, "%+v", opts)
			continue
		}
		assert.True(t, ran, "%+v", opts)
		assert.Equal(t, "default:", owner, "%+v", opts)
	}
}

// What each mode's MCP route does with a request that carries no credential,
// on the route as the server builds it. Only a hub that authenticates nobody
// serves it. A mode the configuration loader does not know never gets this
// far as itself: the loader makes it builtin (see the loader's tests), and
// the configuration's own validation refuses it.
func TestMCPRouteWithNoCredentialInEachMode(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		mode          config.AuthMode
		authenticates bool
	}{
		"Builtin": {config.AuthModeBuiltin, true},
		"Basic":   {config.AuthModeBasic, true},
		"None":    {config.AuthModeNone, false},
		// The conformance suite's server: no mode, nothing to authenticate
		// with. Its route authenticates nobody, as it did before.
		"NoModeSet": {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			hub := newMCPHub(t, tc.mode)
			require.Equal(t, tc.authenticates, hub.opts.Authenticates())

			answer := hub.ask(http.MethodPost, "", "", mcpInitialize)
			if tc.authenticates {
				assert.Equal(t, http.StatusUnauthorized, answer.status, answer.body)
				assert.Empty(t, answer.session)
				return
			}
			assert.Equal(t, http.StatusOK, answer.status, answer.body)
			assert.NotEmpty(t, answer.session)
		})
	}
}

// Who owns a session is taken from what authentication put in the context,
// with a prefix for each kind of caller, so that no two kinds share a name:
// a user whose id reads like a key's is still a user. A route that
// authenticates nobody has the one default caller, said outright.
func TestMCPSessionOwnerNames(t *testing.T) {
	t.Parallel()
	user := func(id string) context.Context {
		return authmodel.WithUser(context.Background(), &authmodel.User{ID: id})
	}
	key := func(id, ownerID string) context.Context {
		return authmodel.WithAPIKey(user(ownerID), &authmodel.APIKey{ID: id})
	}

	for _, tc := range []struct {
		ctx   context.Context
		route frontendauth.Options
		owner string
	}{
		{user("u1"), builtinRoute, "user:u1"},
		{user("u1"), builtinRouteNoKeys, "user:u1"},
		{user("apikey:k1"), builtinRoute, "user:apikey:k1"},
		{user("basic:operator"), builtinRoute, "user:basic:operator"},
		{key("k1", "u1"), builtinRoute, "apikey:k1"},
		{key("k2", "u1"), builtinRoute, "apikey:k2"},
		// A key is a caller by itself, with no user beside it.
		{authmodel.WithAPIKey(context.Background(), &authmodel.APIKey{ID: "k3"}), builtinRoute, "apikey:k3"},
		{user("operator"), basicRoute, "basic:operator"},
		// Mode none gives every request its default user.
		{user("admin"), unauthenticatedRoute, "default:admin"},
		// A hub with nothing to authenticate with gives it nobody.
		{context.Background(), unauthenticatedRoute, "default:"},
	} {
		owner, ok := mcpSessionOwner(tc.ctx, tc.route)
		require.True(t, ok, tc.owner)
		assert.Equal(t, tc.owner, owner)
	}
}

// What the adapter hands on: the caller's name for the library, and a copy of
// the request whose Authorization header is the placeholder, whatever the
// request came with, and whose query string has no token in it. The request
// it was given is left as it was.
func TestMCPSessionAdapterHandsOnNoCredential(t *testing.T) {
	t.Parallel()

	for name, authorization := range map[string]string{
		"HubToken": "Bearer a-real-hub-token", "APIKey": "Bearer dagu_a-real-key", "Basic": "Basic b3BlcmF0b3I6cGFzcw==", "None": "",
	} {
		var seen, query, uri string
		var info *mcpauth.TokenInfo
		handler := mcpSessionUserMiddleware(builtinRoute)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			seen, query, uri = r.Header.Get("Authorization"), r.URL.RawQuery, r.RequestURI
			info = mcpauth.TokenInfoFromContext(r.Context())
		}))
		// The hub takes a token from the query string too.
		const target = "/mcp?token=a-real-hub-token&workspace=ops"
		request := httptest.NewRequest(http.MethodPost, target, nil).
			WithContext(authmodel.WithUser(context.Background(), &authmodel.User{ID: "u1"}))
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)

		require.Equal(t, http.StatusOK, recorder.Code, name)
		assert.Equal(t, mcpPlaceholderBearer, seen, name)
		assert.Equal(t, authorization, request.Header.Get("Authorization"), name)
		assert.Equal(t, "workspace=ops", query, name)
		assert.Equal(t, "/mcp?workspace=ops", uri, name)
		assert.Equal(t, target, request.URL.RequestURI(), name)
		require.NotNil(t, info, name)
		assert.Equal(t, "user:u1", info.UserID, name)
		assert.Empty(t, info.Scopes, name)
		assert.Empty(t, info.Extra, name)
	}
}
