// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"context"
	"net/http"
	"strings"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
)

// mcpPlaceholderBearer stands in for a bearer token on a request the hub
// authenticated without one. It is never checked and grants nothing.
const mcpPlaceholderBearer = "Bearer authenticated-by-the-hub"

// mcpSessionUserMiddleware ties an MCP session to the caller who created it.
//
// An MCP session is named by an id the client sends with each request. The
// MCP library refuses a session presented by anyone but the user who created
// it, when it knows who that was, and it learns that only from its own
// bearer-token middleware. The hub authenticates MCP requests itself and so
// never told it: any authenticated caller who knew another caller's session
// id could use that session, listen on its stream and end it.
//
// This middleware goes last, after the hub has authenticated the request. It
// runs the library's middleware with a verifier that verifies nothing, the
// hub having done that, and names the caller the hub authenticated: a user
// by their id, an API key by its own id, which is never a user's, not even
// the user the key belongs to. The library then records it when a session is
// created and refuses the session to any other caller with 403.
//
// The library's middleware wants a bearer token to be present. A request the
// hub authenticated another way, or did not need to authenticate, is handed
// on with a placeholder in its place.
func mcpSessionUserMiddleware(next http.Handler) http.Handler {
	bound := mcpauth.RequireBearerToken(func(ctx context.Context, _ string, _ *http.Request) (*mcpauth.TokenInfo, error) {
		owner, _ := mcpSessionOwner(ctx)
		return &mcpauth.TokenInfo{
			UserID: owner,
			// The library requires an expiry. The hub has just checked the
			// credential and checks it again on every request.
			Expiration: time.Now().Add(time.Hour),
		}, nil
	}, nil)(next)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := mcpSessionOwner(r.Context()); !ok {
			// Nobody to tie a session to. The request is as it was.
			next.ServeHTTP(w, r)
			return
		}
		if !hasBearerToken(r) {
			r = r.Clone(r.Context())
			r.Header.Set("Authorization", mcpPlaceholderBearer)
		}
		bound.ServeHTTP(w, r)
	})
}

// mcpSessionOwner names the caller a request was authenticated as, for the
// purpose of owning an MCP session.
//
// An API key owns its sessions itself. A request made with one carries a user
// as well, the key's owner or service account, for attribution; that user
// did not make the request, and a key's sessions are not theirs.
func mcpSessionOwner(ctx context.Context) (string, bool) {
	if apiKey, ok := authmodel.APIKeyFromContext(ctx); ok && apiKey != nil && apiKey.ID != "" {
		return "apikey:" + apiKey.ID, true
	}
	if user, ok := authmodel.UserFromContext(ctx); ok && user != nil && user.ID != "" {
		return "user:" + user.ID, true
	}
	return "", false
}

// hasBearerToken reports whether a request carries what the MCP library's
// middleware takes for a bearer token.
func hasBearerToken(r *http.Request) bool {
	fields := strings.Fields(r.Header.Get("Authorization"))
	return len(fields) == 2 && strings.EqualFold(fields[0], "bearer")
}
