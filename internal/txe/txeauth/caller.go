// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeauth

import (
	"context"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// Kind says what authenticated a request.
type Kind string

const (
	// KindNone is a request nothing authenticated, on a server that does not
	// require authentication.
	KindNone Kind = "none"
	// KindPlatformAdmin is the installation's builtin administrator, signed
	// in with its password, or a basic-auth credential, which the server
	// treats as an administrator.
	KindPlatformAdmin Kind = "platform_admin"
	// KindPerson is someone signed in through the browser with the identity
	// provider.
	KindPerson Kind = "person"
	// KindToken is an identity provider access token: a developer's command
	// line, or an enrolled machine.
	KindToken Kind = "token"
	// KindLegacy is any other credential the server accepted before owners
	// were enforced: a builtin user who is not the administrator, an API key,
	// or a user named by a trusted proxy.
	KindLegacy Kind = "legacy"
)

// Caller is who a request comes from.
type Caller struct {
	Kind Kind
	// Principal is the identity the provider vouched for. It is set for a
	// person and a token, and is the zero value otherwise.
	Principal authn.Principal
	// Username is the hub account the request authenticated as, for a
	// person, the platform administrator and a legacy caller. It is recorded
	// and never matched.
	Username string
}

// New reports whether the caller authenticated through the identity
// provider. Such a caller is never given a Dagu role or workspace access,
// whatever the authorization mode.
func (c Caller) New() bool {
	return c.Kind == KindPerson || c.Kind == KindToken
}

type tokenKey struct{}

// WithToken returns ctx carrying the principal of a verified provider access
// token.
func WithToken(ctx context.Context, p authn.Principal) context.Context {
	return context.WithValue(ctx, tokenKey{}, p)
}

// Token returns the principal of the verified provider access token the
// request carries, if any.
func Token(ctx context.Context) (authn.Principal, bool) {
	p, ok := ctx.Value(tokenKey{}).(authn.Principal)
	return p, ok
}

// Classify says who a request comes from. A provider token comes first: a
// request that carries one has no hub user. A hub user who signed in through
// the identity provider is a person, whatever role the hub gave the account;
// only a builtin account with the administrator role is the platform
// administrator, and an API key never is.
func Classify(ctx context.Context) Caller {
	if p, ok := Token(ctx); ok {
		return Caller{Kind: KindToken, Principal: p}
	}
	user, ok := auth.UserFromContext(ctx)
	if !ok || user == nil {
		return Caller{Kind: KindNone}
	}
	if _, apiKey := auth.APIKeyFromContext(ctx); apiKey {
		return Caller{Kind: KindLegacy, Username: user.Username}
	}
	switch user.AuthProvider {
	case auth.AuthProviderOIDC:
		if user.OIDCIssuer == "" || user.OIDCSubject == "" {
			// An account that says it came from the provider and does not
			// name the identity is nobody.
			return Caller{Kind: KindLegacy, Username: user.Username}
		}
		return Caller{
			Kind:     KindPerson,
			Username: user.Username,
			Principal: authn.Principal{
				Identity: authn.Identity{Issuer: user.OIDCIssuer, Subject: user.OIDCSubject},
				Class:    authn.ClassPerson,
			},
		}
	case "", auth.AuthProviderBuiltin:
		if user.Role == auth.RoleAdmin {
			return Caller{Kind: KindPlatformAdmin, Username: user.Username}
		}
	}
	return Caller{Kind: KindLegacy, Username: user.Username}
}
