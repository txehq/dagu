// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"context"
	"net/http"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
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
// A request that reaches here with no caller is refused. In the modes that
// authenticate, that would be a fault in what comes before; a hub that
// authenticates nobody gives every request its one default user first.
//
// The library's middleware takes a bearer token and an expiry. Neither is
// used to decide anything: the token it is shown is always the placeholder,
// on a copy of the request, so the credential the request came with is not
// handed to the library or to the tools behind it; and the expiry only has
// to be in the future, the hub having checked the credential a moment ago
// and checking it again on every request.
func mcpSessionUserMiddleware(mode config.AuthMode) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		bound := mcpauth.RequireBearerToken(func(ctx context.Context, _ string, _ *http.Request) (*mcpauth.TokenInfo, error) {
			owner, ok := mcpSessionOwner(ctx, mode)
			if !ok {
				// Not reached: the request was refused below.
				return nil, mcpauth.ErrInvalidToken
			}
			return &mcpauth.TokenInfo{UserID: owner, Expiration: time.Now().Add(time.Hour)}, nil
		}, nil)(next)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := mcpSessionOwner(r.Context(), mode); !ok {
				http.Error(w, "MCP needs a caller the hub has authenticated", http.StatusUnauthorized)
				return
			}
			internal := r.Clone(r.Context())
			internal.Header.Set("Authorization", mcpPlaceholderBearer)
			bound.ServeHTTP(w, internal)
		})
	}
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
func mcpSessionOwner(ctx context.Context, mode config.AuthMode) (string, bool) {
	if apiKey, ok := authmodel.APIKeyFromContext(ctx); ok && apiKey != nil {
		if apiKey.ID == "" {
			return "", false
		}
		return "apikey:" + apiKey.ID, true
	}
	user, ok := authmodel.UserFromContext(ctx)
	if !ok || user == nil || user.ID == "" {
		return "", false
	}
	switch mode {
	case config.AuthModeBuiltin:
		return "user:" + user.ID, true
	case config.AuthModeBasic:
		return "basic:" + user.ID, true
	case config.AuthModeNone:
		return "default:" + user.ID, true
	default:
		return "", false
	}
}
