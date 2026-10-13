// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"context"
	"net/http"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/service/frontend/auth"
)

// mcpPlaceholderBearer is what the MCP library is given in place of the
// credential a request came with. It is not a credential: nothing checks it
// and it grants nothing.
const mcpPlaceholderBearer = "Bearer authenticated-by-the-hub"

// mcpSessionUserMiddleware ties an MCP session to the caller who created it.
//
// An MCP session is named by an id the client sends with each request. The
// MCP library refuses a session presented by anyone but the user who created
// it, when it knows who that was, and it learns that only from its own
// bearer-token middleware: the place it keeps it in the request's context is
// not open to anything else. The hub authenticates MCP requests itself and
// so never told it: any authenticated caller who knew another caller's
// session id could use that session, listen on its stream and end it.
//
// This middleware goes last, after the hub has authenticated the request,
// and only there: it authenticates nothing itself. It names the caller the
// hub authenticated (see mcpSessionOwner) and runs the library's middleware
// to hand that name over. The library then records it when a session is
// created and refuses the session to any other caller with 403.
//
// A request that reaches here with no caller is refused, on a route that
// authenticates: that would be a fault in what comes before, and a session
// is not created for nobody. A route that authenticates nobody at all has
// one caller, the default one, whoever asks.
//
// The library's middleware takes a bearer token and an expiry. Neither is
// used to decide anything: the token it is shown is always the placeholder,
// on a copy of the request with any token taken out of its query string, so
// the credential the request came with is not handed to the library or to
// the tools behind it; and the expiry only has to be in the future, the hub
// having checked the credential a moment ago and checking it again on every
// request.
//
// opts are the options the route's authentication was built with.
func mcpSessionUserMiddleware(opts auth.Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		bound := mcpauth.RequireBearerToken(func(ctx context.Context, _ string, _ *http.Request) (*mcpauth.TokenInfo, error) {
			owner, ok := mcpSessionOwner(ctx, opts)
			if !ok {
				// Not reached: the request was refused below.
				return nil, mcpauth.ErrInvalidToken
			}
			return &mcpauth.TokenInfo{UserID: owner, Expiration: time.Now().Add(time.Hour)}, nil
		}, nil)(next)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := mcpSessionOwner(r.Context(), opts); !ok {
				http.Error(w, "MCP needs a caller the hub has authenticated", http.StatusUnauthorized)
				return
			}
			bound.ServeHTTP(w, withoutCredential(r))
		})
	}
}

// withoutCredential returns a copy of an authenticated request that carries
// no credential: the placeholder in its Authorization header, and no token in
// its query string, which is the other place the hub takes one from.
func withoutCredential(r *http.Request) *http.Request {
	internal := r.Clone(r.Context())
	internal.Header.Set("Authorization", mcpPlaceholderBearer)
	if query := internal.URL.Query(); query.Has("token") {
		query.Del("token")
		internal.URL.RawQuery = query.Encode()
		internal.RequestURI = internal.URL.RequestURI()
	}
	return internal
}

// mcpSessionOwner names the caller a request was authenticated as, for the
// purpose of owning an MCP session. The name comes from what the hub's
// authentication put in the request's context and from nothing the request
// says about itself. Each kind of caller has a prefix of its own, so that no
// two kinds can share a name.
//
// An API key owns its sessions itself. A request made with one carries a user
// as well, the key's owner or service account, for attribution; that user
// did not make the request, and a key's sessions are not theirs.
//
// A route that authenticates nobody, because the hub's mode is none or
// because nothing was configured to authenticate with, lets every request
// through: its callers are one, the default caller. That is said here and
// not left to whether a user happens to be in the context. Whether a route
// authenticates is asked of the options its authentication middleware was
// built with, not worked out from the name of the hub's mode.
func mcpSessionOwner(ctx context.Context, opts auth.Options) (string, bool) {
	// The middleware's own account of whether it authenticates anybody.
	authenticates := opts.Authenticates()

	if apiKey, ok := authmodel.APIKeyFromContext(ctx); ok && apiKey != nil {
		// A key is a caller only where keys are checked.
		if apiKey.ID == "" || opts.APIKeyValidator == nil {
			return "", false
		}
		return "apikey:" + apiKey.ID, true
	}
	user, _ := authmodel.UserFromContext(ctx)
	if !authenticates {
		if user != nil && user.ID != "" {
			return "default:" + user.ID, true
		}
		return "default:", true
	}
	if user == nil || user.ID == "" {
		return "", false
	}
	if opts.BasicAuthEnabled && opts.JWTValidator == nil {
		return "basic:" + user.ID, true
	}
	return "user:" + user.ID, true
}
